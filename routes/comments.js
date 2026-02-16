const express = require('express');
const router = express.Router();

// express-rate-limit v8+ 호환 (pages.js에서 쓰는 패턴과 동일)
const erl = require("express-rate-limit");
const rateLimit = erl.rateLimit || erl;
const { ipKeyGenerator } = erl;

// server.js와 동일한 기본값(운영 정책에 맞게 환경변수로 조절 가능)
// - IPv6를 /56 단위로 묶어 주소 조금씩 바꾸는 우회를 방지
const RATE_LIMIT_IPV6_SUBNET = (() => {
	const n = Number(process.env.RATE_LIMIT_IPV6_SUBNET ?? 56);
	// 0~128 범위로 클램프(이상치 방어)
	if (!Number.isFinite(n)) return 56;
	return Math.max(0, Math.min(128, n));
})();

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
        pagesRepo,
        storagesRepo,
        authMiddleware,
        toIsoString,
        sanitizeInput,
        logError,
        formatDateForDb,
        getClientIpFromRequest
	} = dependencies;

    function getClientIp(req) {
        return (
            req.clientIp ||
            (typeof getClientIpFromRequest === 'function' ? getClientIpFromRequest(req) : null) ||
            req.ip ||
            req.connection?.remoteAddress ||
            req.socket?.remoteAddress ||
            'unknown'
        );
    }

    /**
     * 페이지 접근 제어(특히 encrypted + share_allowed=0)를 일관되게 적용하기 위해,
     * 댓글 엔드포인트에서도 pagesRepo.getPageByIdForUser()를 통해
     * 해당 사용자에게 이 페이지가 보이는지를 먼저 판정
     *
     * 이렇게 하면, 다른 라우트에서 사용하는 중앙 정책(pageSqlPolicy)을
     * 댓글 라우트가 우회하는 실수를 방지할 수 있음
     */
    async function loadPageForCommentsOr404(userId, pageId, res) {
        try {
            const page = await pagesRepo.getPageByIdForUser({ userId, pageId });
            if (!page) {
                // 권한이 없거나(공유 해제/차단) 페이지가 없는 경우를 동일하게 취급
                // -> ID 추측/열거(enumeration) 완화
                res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
                return null;
            }
            return page;
        } catch (e) {
            logError("loadPageForCommentsOr404", e);
            res.status(500).json({ error: "페이지 확인 실패" });
            return null;
        }
    }

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
            const rawIp = getClientIp(req);
            // 중요: IPv6 우회 방지를 위해 ipKeyGenerator로 서브넷 마스킹 적용
            const ipKey = rawIp && rawIp !== 'unknown' ? ipKeyGenerator(rawIp, RATE_LIMIT_IPV6_SUBNET) : "noip";
            return `guest:${token}:${ipKey}`;
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
		// 형식이 명백히 이상한 값은 조기 차단
		if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) {
			return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
		}
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

				// 내부 권한 확인(소유자/공유자) + 중앙 정책(pageSqlPolicy) 적용
				// - encrypted + share_allowed=0 페이지는 소유자 외에는 pagesRepo에서 NULL
				const page = await pagesRepo.getPageByIdForUser({ userId, pageId });
				if (!page) {
					return res.status(403).json({ error: "댓글이 비활성화되었습니다." });
				}
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
	router.post('/shared/:token', sharedCommentWriteLimiter, requireSameOriginForAuth, async (req, res) => {
		const token = req.params.token;
		// 토큰은 DB 스키마상 VARCHAR(64)이며(발행 링크), 일반적으로 64자 랜덤(헥스) 문자열로 발급
		// 형식이 명백히 이상한 값은 조기 차단(불필요한 DB hit/로그 노이즈 감소)
		if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) {
			return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
		}
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
			// allow_comments=0 인 경우:
			//  - 비로그인 사용자는 차단(기존 동작)
			//  - 로그인 사용자는 *반드시* 내부 권한(소유자/공유 저장소 권한)을 확인해야 함
			//    (그렇지 않으면 발행 링크만 알면 임의 계정으로도 댓글 작성이 가능해짐)
			if (!allowComments) {
				if (!userId) {
					return res.status(403).json({ error: "댓글을 작성할 권한이 없습니다." });
				}

				// 중앙 정책(pageSqlPolicy) 적용: encrypted + share_allowed=0 페이지는 소유자만
				const page = await pagesRepo.getPageByIdForUser({ userId, pageId });
				if (!page) {
					return res.status(403).json({ error: "댓글을 작성할 권한이 없습니다." });
				}
			}

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

    /**
     * Login CSRF 방지: 발행 페이지 댓글 작성 등은 CSRF 토큰이 없더라도 호출될 수 있으므로,
     * Origin/Referer + Sec-Fetch-Site 기반으로 동일 출처 요청만 허용합니다.
     */
    function requireSameOriginForAuth(req, res, next) {
        try {
            const allowedOrigins = new Set(
                String(process.env.ALLOWED_ORIGINS || dependencies.BASE_URL || "")
                    .split(",")
                    .map(s => s.trim())
                    .filter(Boolean)
                    .map(u => new URL(u).origin)
            );

            const sfs = req.headers["sec-fetch-site"];
            if (typeof sfs === "string" && sfs && sfs !== "same-origin" && sfs !== "same-site") {
                return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
            }

            const origin = req.headers.origin;
            const referer = req.headers.referer;

            let reqOrigin = null;
            if (typeof origin === "string" && origin) {
                reqOrigin = origin;
            } else if (typeof referer === "string" && referer) {
                reqOrigin = new URL(referer).origin;
            }

            if (!reqOrigin) return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
            if (!allowedOrigins.has(reqOrigin)) return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });

            return next();
        } catch (e) {
            return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
        }
    }

    // Internal comments: pageId 기반은 로그인(인증) 전용
    router.get('/:pageId', authMiddleware, async (req, res) => {
		const pageId = req.params.pageId;
        const userId = req.user.id;

        try {
            // 중앙 정책(pageSqlPolicy)을 우회하지 않도록 pagesRepo로 접근 여부 판정
            const page = await loadPageForCommentsOr404(userId, pageId, res);
            if (!page) return;

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
            // 중앙 정책(pageSqlPolicy)을 우회하지 않도록 pagesRepo로 접근 여부 판정
            const page = await loadPageForCommentsOr404(userId, pageId, res);
            if (!page) return;

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
                `SELECT c.id, c.user_id, c.page_id
                 FROM comments c
                 WHERE c.id = ?`,
                [commentId]
            );

            if (!comments.length) {
                return res.status(404).json({ error: "댓글을 찾을 수 없습니다." });
            }

            const comment = comments[0];

            // 페이지 접근 가능 여부 확인 (공유 해제/차단/암호화 정책 반영)
            const page = await loadPageForCommentsOr404(userId, comment.page_id, res);
            if (!page) return;

            // 삭제 권한: 댓글 작성자 또는 페이지 소유자
            const isAuthor = comment.user_id && Number(comment.user_id) === Number(userId);
            const isPageOwner = Number(page.user_id) === Number(userId);
            if (!isAuthor && !isPageOwner) {
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
                `SELECT c.id, c.user_id, c.page_id
                 FROM comments c
                 WHERE c.id = ?`,
                [commentId]
            );

            if (!comments.length) {
                return res.status(404).json({ error: "댓글을 찾을 수 없습니다." });
            }

            const comment = comments[0];

            // 페이지 접근 가능 여부 확인 (공유 해제/차단/암호화 정책 반영)
            const page = await loadPageForCommentsOr404(userId, comment.page_id, res);
            if (!page) return;

            // 수정 권한: 댓글 작성자만 가능 (익명 댓글은 수정 불가 - 세션 기반)
            // 익명 댓글(user_id IS NULL)은 현재 로직상 세션과 연결되지 않으므로 수정 불가능이 원칙.
            // 로그인한 사용자의 댓글만 수정 허용.
            if (!userId || !comment.user_id || Number(comment.user_id) !== Number(userId)) {
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
