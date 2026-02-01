const express = require('express');
const router = express.Router();

// express-rate-limit v8+ 호환 (pages.js에서 쓰는 패턴과 동일)
const erl = require("express-rate-limit");
const rateLimit = erl.rateLimit || erl;

/**
 * Comments Routes
 *
 * 이 파일은 댓글 관련 라우트를 처리합니다.
 * - 댓글 목록 조회
 * - 댓글 작성
 * - 댓글 삭제
 */

module.exports = (dependencies) => {
    const {
        pool,
        authMiddleware,
        toIsoString,
        sanitizeInput,
        logError,
        formatDateForDb,
        getCollectionPermission
	} = dependencies;

    /**
     * Abuse/DoS 방어: 공개(발행 링크) 댓글 작성 엔드포인트 전용 제한
     * - /api 전역 limiter(분당 100)만으로는 공개 댓글 작성 남용을 충분히 막기 어려움
     * - token(페이지) 단위 + IP(게스트) 또는 userId(로그인) 단위로 더 촘촘히 제한
     */
    const SHARED_COMMENT_MAX_LEN = 2000;   // 필요 시 운영 정책에 맞게 조정
    const GUEST_NAME_MAX_LEN = 32;

    const sharedCommentGuestLimiter = rateLimit({
        windowMs: 10 * 60 * 1000, // 10분
        max: 20,                  // 토큰+IP당 10분에 20회
        standardHeaders: true,
        legacyHeaders: false,
        message: { error: "댓글 작성 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요." },
        keyGenerator: (req) => {
            const token = String(req.params.token || "");
            const ip = req.clientIp || req.ip || req.connection?.remoteAddress || "unknown";
            return `guest:${token}:${ip}`;
        },
    });

    const sharedCommentUserLimiter = rateLimit({
        windowMs: 10 * 60 * 1000,
        max: 60,                  // userId+token당 10분에 60회(로그인은 조금 더 여유)
        standardHeaders: true,
        legacyHeaders: false,
        message: { error: "댓글 작성 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요." },
        keyGenerator: (req) => {
            const token = String(req.params.token || "");
            const session = dependencies.getSessionFromRequest(req);
            const userId = session?.userId;
            return userId ? `user:${userId}:${token}` : `user:unknown:${token}`;
        },
    });

    // 세션 존재 여부로 limiter 선택 (공개 엔드포인트라 authMiddleware 없음)
    const sharedCommentWriteLimiter = (req, res, next) => {
        const session = dependencies.getSessionFromRequest(req);
        if (session?.userId) return sharedCommentUserLimiter(req, res, next);
        return sharedCommentGuestLimiter(req, res, next);
    };

	// Public (published-link) comments: token 기반으로만 접근
	//  - 기존 /api/comments/:pageId 공개 허용 로직은 IDOR/권한 우회(데이터 유출) 위험
	//  - allow_comments=0 이어도 댓글이 노출되던 버그를 서버에서 강제 차단

	/**
	 * GET /api/comments/shared/:token
	 * - 공개 페이지 댓글 조회
	 * - 발행 링크 token으로 page_id를 찾아서 접근제어를 수행
	 */
	router.get('/shared/:token', async (req, res) => {
		const token = req.params.token;
		const session = dependencies.getSessionFromRequest(req);
		const userId = session ? session.userId : null;

		try {
		    const [publishRows] = await pool.execute(
			    `SELECT page_id, allow_comments
			        FROM page_publish_links
			        WHERE token = ? AND is_active = 1
			        ORDER BY created_at DESC
			        LIMIT 1`,
			    [token]
		    );

		    if (publishRows.length === 0)
			    return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });

		    const pageId = publishRows[0].page_id;
		    const allowComments = Number(publishRows[0].allow_comments) === 1;

		    // allow_comments=false이면 공개 방문자는 차단
		    if (!allowComments) {
			    // (옵션) 로그인 사용자 중 내부 권한자가 있다면 예외 허용 가능
			    if (!userId)
			        return res.status(403).json({ error: "댓글이 비활성화되었습니다." });

				// 내부 권한 확인(소유자/공유자)
			    const [pageRows] = await pool.execute(
			        `SELECT id, user_id, collection_id FROM pages WHERE id = ?`,
			        [pageId]
				);

				if (!pageRows.length)
					return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });

			    const page = pageRows[0];
			    let canReadInternal = false;
				if (page.user_id === userId) {
					canReadInternal = true;
				} else {
			        const { permission } = await getCollectionPermission(page.collection_id, userId);
			        if (permission) canReadInternal = true;
			    }

				if (!canReadInternal)
			        return res.status(403).json({ error: "댓글이 비활성화되었습니다." });
		    }

		    const [comments] = await pool.execute(
			    `SELECT c.id, c.content, c.created_at, c.user_id, c.guest_name, u.username
			        FROM comments c
			    LEFT JOIN users u ON c.user_id = u.id
			        WHERE c.page_id = ?
			        ORDER BY c.created_at ASC`,
			    [pageId]
		    );

		    res.json(comments.map(c => ({
			    id: c.id,
			    content: c.content,
			    createdAt: toIsoString(c.created_at),
			    author: c.user_id ? c.username : c.guest_name,
			    isGuest: !c.user_id,
			    isMyComment: userId ? (c.user_id === userId) : false
		    })));
		} catch (e) {
		    logError("GET /api/comments/shared/:token", e);
		    res.status(500).json({ error: "댓글 목록 조회 실패" });
		}
	});

	/**
	 * POST /api/comments/shared/:token
	 * - 공개 페이지 댓글 작성(게스트 허용)
	 */
	router.post('/shared/:token', sharedCommentWriteLimiter, async (req, res) => {
		const token = req.params.token;
		const session = dependencies.getSessionFromRequest(req);
		const userId = session ? session.userId : null;
		const { content, guestName } = req.body;

		if (!content || typeof content !== 'string' || content.trim() === '')
		    return res.status(400).json({ error: "댓글 내용을 입력해주세요." });

		const rawContent = content.trim();
        if (rawContent.length > SHARED_COMMENT_MAX_LEN) {
            return res.status(413).json({
                error: `댓글은 최대 ${SHARED_COMMENT_MAX_LEN}자까지 입력할 수 있습니다.`
            });
        }

        // 게스트만 이름 길이 제한 적용 (로그인 사용자는 guestName 무시)
        const rawGuestName = guestName ? String(guestName).trim() : 'Guest';
        if (!userId && rawGuestName.length > GUEST_NAME_MAX_LEN) {
            return res.status(400).json({
                error: `이름은 최대 ${GUEST_NAME_MAX_LEN}자까지 입력할 수 있습니다.`
            });
        }

        const sanitizedContent = sanitizeInput(rawContent);
        const sanitizedGuestName = userId ? null : sanitizeInput(rawGuestName);

		try {
		    const [publishRows] = await pool.execute(
			    `SELECT page_id, allow_comments
			        FROM page_publish_links
			        WHERE token = ? AND is_active = 1
			        ORDER BY created_at DESC
			        LIMIT 1`,
			    [token]
			);

			if (!publishRows.length)
				return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });

		    const pageId = publishRows[0].page_id;
		    const allowComments = Number(publishRows[0].allow_comments) === 1;
		    if (!allowComments && !userId)
			    return res.status(403).json({ error: "댓글을 작성할 권한이 없습니다." });

		    const nowStr = formatDateForDb(new Date());
		    await pool.execute(
			    `INSERT INTO comments (page_id, user_id, guest_name, content, created_at, updated_at)
			            VALUES (?, ?, ?, ?, ?, ?)`,
			    [pageId, userId, sanitizedGuestName, sanitizedContent, nowStr, nowStr]
		    );
		    res.status(201).json({ success: true });
		} catch (e) {
		    logError("POST /api/comments/shared/:token", e);
		    res.status(500).json({ error: "댓글 작성 실패" });
		}
	});

    // Internal comments: pageId 기반은 로그인(인증) 전용
    router.get('/:pageId', authMiddleware, async (req, res) => {
		const pageId = req.params.pageId;
        const userId = req.user.id;

        try {
            // 페이지 존재 및 권한 확인
            // - 소유자
            // - 공유받은 사용자 (컬렉션 공유)
            // - 발행된 페이지이고 댓글 허용된 경우 (공개)

            // 페이지 정보 조회
            const [pageRows] = await pool.execute(
                `SELECT p.id, p.user_id, p.collection_id,
                        c.user_id as collection_owner_id
                 FROM pages p
                 JOIN collections c ON p.collection_id = c.id
                 WHERE p.id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];
            let canRead = false;
            let isOwner = false;

            if (userId) {
                if (page.user_id === userId) {
                    canRead = true;
                    isOwner = true;
                } else {
                    // 컬렉션 권한 확인
                    const { permission } = await getCollectionPermission(page.collection_id, userId);
                    if (permission) {
                        canRead = true;
                    }
                }
            }

            if (!canRead)
                return res.status(403).json({ error: "접근 권한이 없습니다." });

            // 댓글 목록 조회
            const [comments] = await pool.execute(
                `SELECT c.id, c.content, c.created_at, c.user_id, c.guest_name,
                        u.username
                 FROM comments c
                 LEFT JOIN users u ON c.user_id = u.id
                 WHERE c.page_id = ?
                 ORDER BY c.created_at ASC`,
                [pageId]
            );

            const result = comments.map(c => ({
                id: c.id,
                content: c.content,
                createdAt: toIsoString(c.created_at),
                author: c.user_id ? c.username : c.guest_name,
                isGuest: !c.user_id,
                isMyComment: userId ? (c.user_id === userId) : false
            }));

            res.json(result);

        } catch (error) {
            logError("GET /api/comments/:pageId", error);
            res.status(500).json({ error: "댓글 목록 조회 실패" });
        }
    });

    // 댓글 작성
    router.post('/:pageId', authMiddleware, async (req, res) => {
		const pageId = req.params.pageId;
        const userId = req.user.id;
        const { content, guestName } = req.body;

        if (!content || typeof content !== 'string' || content.trim() === '') {
            return res.status(400).json({ error: "댓글 내용을 입력해주세요." });
        }

        const sanitizedContent = sanitizeInput(content.trim());
        // guestName은 비로그인 시 필수일 수도, 아닐 수도 있지만
        // 여기서는 비로그인 시 guestName이 없으면 '익명' 처리하거나 클라이언트에서 받음.
        // 블록 기반 에디터 스타일은 보통 로그인 유도하지만, 요구사항에 따라 유연하게.
        const sanitizedGuestName = guestName ? sanitizeInput(guestName.trim()) : 'Guest';

        try {
            // 권한 확인
            const [pageRows] = await pool.execute(
                `SELECT p.id, p.user_id, p.collection_id
                 FROM pages p
                 WHERE p.id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];
            let canComment = false;

            if (userId) {
                if (page.user_id === userId) {
                    canComment = true;
                } else {
                    const { permission } = await getCollectionPermission(page.collection_id, userId);
                    // READ 권한만 있어도 댓글 작성 허용
                    if (permission) {
                        canComment = true;
                    }
                }
            }

            if (!canComment)
                return res.status(403).json({ error: "댓글을 작성할 권한이 없습니다." });

            // 댓글 저장
            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
	            `INSERT INTO comments (page_id, user_id, guest_name, content, created_at, updated_at)
	                VALUES (?, ?, ?, ?, ?, ?)`,
	            [pageId, userId, null, sanitizedContent, nowStr, nowStr]
            );

            res.status(201).json({ success: true });

        } catch (error) {
            logError("POST /api/comments/:pageId", error);
            res.status(500).json({ error: "댓글 작성 실패" });
        }
    });

    // 댓글 삭제
    router.delete('/:commentId', authMiddleware, async (req, res) => {
        const commentId = req.params.commentId;
        const userId = req.user.id;

        try {
            // 댓글 확인
            const [comments] = await pool.execute(
                `SELECT c.id, c.user_id, c.page_id, p.user_id as page_owner_id
                 FROM comments c
                 JOIN pages p ON c.page_id = p.id
                 WHERE c.id = ?`,
                [commentId]
            );

            if (!comments.length) {
                return res.status(404).json({ error: "댓글을 찾을 수 없습니다." });
            }

            const comment = comments[0];

            // 삭제 권한: 댓글 작성자 또는 페이지 소유자
            if (comment.user_id !== userId && comment.page_owner_id !== userId) {
                return res.status(403).json({ error: "삭제 권한이 없습니다." });
            }

            await pool.execute(
                `DELETE FROM comments WHERE id = ?`,
                [commentId]
            );

            res.json({ success: true });

        } catch (error) {
            logError("DELETE /api/comments/:commentId", error);
            res.status(500).json({ error: "댓글 삭제 실패" });
        }
    });

    // 댓글 수정
    router.put('/:commentId', authMiddleware, async (req, res) => {
        const commentId = req.params.commentId;
        const session = dependencies.getSessionFromRequest(req);
        const userId = session ? session.userId : null;
        const { content } = req.body;

        if (!content || typeof content !== 'string' || content.trim() === '') {
            return res.status(400).json({ error: "댓글 내용을 입력해주세요." });
        }

        const sanitizedContent = sanitizeInput(content.trim());

        try {
            // 댓글 확인
            const [comments] = await pool.execute(
                `SELECT c.id, c.user_id
                 FROM comments c
                 WHERE c.id = ?`,
                [commentId]
            );

            if (!comments.length) {
                return res.status(404).json({ error: "댓글을 찾을 수 없습니다." });
            }

            const comment = comments[0];

            // 수정 권한: 댓글 작성자만 가능 (익명 댓글은 수정 불가 - 세션 기반)
            // 익명 댓글(user_id IS NULL)은 현재 로직상 세션과 연결되지 않으므로 수정 불가능이 원칙.
            // 로그인한 사용자의 댓글만 수정 허용.
            if (!userId || comment.user_id !== userId) {
                return res.status(403).json({ error: "수정 권한이 없습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `UPDATE comments
                 SET content = ?, updated_at = ?
                 WHERE id = ?`,
                [sanitizedContent, nowStr, commentId]
            );

            res.json({ success: true });

        } catch (error) {
            logError("PUT /api/comments/:commentId", error);
            res.status(500).json({ error: "댓글 수정 실패" });
        }
    });

    return router;
};
