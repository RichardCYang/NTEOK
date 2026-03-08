const express = require('express');
const router = express.Router();

const erl = require("express-rate-limit");
const rateLimit = erl.rateLimit || erl;
const { ipKeyGenerator } = erl;

const RATE_LIMIT_IPV6_SUBNET = (() => {
	const n = Number(process.env.RATE_LIMIT_IPV6_SUBNET ?? 56);
	if (!Number.isFinite(n)) return 56;
	return Math.max(0, Math.min(128, n));
})();


module.exports = (dependencies) => {
	const {
		pool,
		pagesRepo,
		storagesRepo,
		authMiddleware,
		csrfMiddleware,
		toIsoString,
		sanitizeInput,
		logError,
		formatDateForDb,
		getClientIpFromRequest,
		getSessionFromRequest
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

	async function loadPageForCommentsOr404(userId, pageId, res) {
		try {
			const page = await pagesRepo.getPageByIdForUser({ userId, pageId });
			if (!page) {
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

	const SHARED_COMMENT_MAX_LEN = 2000;   
	const GUEST_NAME_MAX_LEN = 32;

	const sharedCommentGuestLimiter = rateLimit({
		windowMs: 10 * 60 * 1000, 
		max: 20,                  
		standardHeaders: true,
		legacyHeaders: false,
		message: { error: "댓글 작성 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요." },
		keyGenerator: (req) => {
			const token = String(req.params.token || "");
			const rawIp = getClientIp(req);
			const ipKey = rawIp && rawIp !== 'unknown' ? ipKeyGenerator(rawIp, RATE_LIMIT_IPV6_SUBNET) : "noip";
			return `guest:${token}:${ipKey}`;
		},
	});

	const sharedCommentUserLimiter = rateLimit({
		windowMs: 10 * 60 * 1000,
		max: 60,                  
		standardHeaders: true,
		legacyHeaders: false,
		message: { error: "댓글 작성 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요." },
		keyGenerator: async (req) => {
			const token = String(req.params.token || "");
			const session = await getSessionFromRequest(req);
			const userId = session?.userId;
			return userId ? `user:${userId}:${token}` : `user:unknown:${token}`;
		},
	});

	const sharedCommentWriteLimiter = async (req, res, next) => {
		const session = await getSessionFromRequest(req);
		if (session?.userId) return sharedCommentUserLimiter(req, res, next);
		return sharedCommentGuestLimiter(req, res, next);
	};

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
			if (typeof sfs === "string" && sfs && sfs !== "same-origin" && sfs !== "same-site") return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
			const origin = req.headers.origin;
			const referer = req.headers.referer;
			let reqOrigin = null;
			if (typeof origin === "string" && origin) reqOrigin = origin;
			else if (typeof referer === "string" && referer) reqOrigin = new URL(referer).origin;
			if (!reqOrigin || !allowedOrigins.has(reqOrigin)) return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
			return next();
		} catch (e) {
			return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
		}
	}


	router.get('/shared/:token', async (req, res) => {
		const token = req.params.token;
		if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
		const tokenHash = dependencies.hashToken(token);
		const session = await getSessionFromRequest(req);
		const userId = session ? session.userId : null;
		try {
			const [publishRows] = await pool.execute(`SELECT ppl.page_id, ppl.allow_comments FROM page_publish_links ppl JOIN pages p ON p.id = ppl.page_id WHERE ppl.token = ? AND ppl.is_active = 1 AND p.deleted_at IS NULL AND p.is_encrypted = 0 AND (ppl.expires_at IS NULL OR ppl.expires_at > NOW()) ORDER BY ppl.created_at DESC LIMIT 1`, [tokenHash]);
			if (publishRows.length === 0) return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
			const pageId = publishRows[0].page_id;
			const allowComments = Number(publishRows[0].allow_comments) === 1;
			if (!allowComments) {
				if (!userId) return res.status(403).json({ error: "댓글이 비활성화되었습니다." });
				const page = await pagesRepo.getPageByIdForUser({ userId, pageId });
				if (!page) return res.status(403).json({ error: "댓글이 비활성화되었습니다." });
			}
			const [comments] = await pool.execute(`SELECT c.id, c.content, c.created_at, c.user_id, c.guest_name, u.username FROM comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.page_id = ? ORDER BY c.created_at ASC`, [pageId]);
			res.json(comments.map(c => ({ id: c.id, content: c.content, createdAt: toIsoString(c.created_at), author: c.user_id ? c.username : c.guest_name, isGuest: !c.user_id, isMyComment: userId ? (c.user_id === userId) : false })));
		} catch (e) {
			logError("GET /api/comments/shared/:token", e);
			res.status(500).json({ error: "댓글 목록 조회 실패" });
		}
	});

	router.post('/shared/:token', sharedCommentWriteLimiter, requireSameOriginForAuth, async (req, res) => {
		const token = req.params.token;
		if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
		const tokenHash = dependencies.hashToken(token);
		const session = await getSessionFromRequest(req);
		const userId = session ? session.userId : null;
		const { content, guestName } = req.body;
		if (!content || typeof content !== 'string' || content.trim() === '') return res.status(400).json({ error: "댓글 내용을 입력해주세요." });
		const rawContent = content.trim();
		if (rawContent.length > SHARED_COMMENT_MAX_LEN) return res.status(413).json({ error: `댓글은 최대 ${SHARED_COMMENT_MAX_LEN}자까지 입력할 수 있습니다.` });
		const rawGuestName = guestName ? String(guestName).trim() : 'Guest';
		if (!userId && rawGuestName.length > GUEST_NAME_MAX_LEN) return res.status(400).json({ error: `이름은 최대 ${GUEST_NAME_MAX_LEN}자까지 입력할 수 있습니다.` });
		const sanitizedContent = sanitizeInput(rawContent);
		const sanitizedGuestName = userId ? null : sanitizeInput(rawGuestName);
		try {
			const [publishRows] = await pool.execute(`SELECT ppl.page_id, ppl.allow_comments FROM page_publish_links ppl JOIN pages p ON p.id = ppl.page_id WHERE ppl.token = ? AND ppl.is_active = 1 AND p.deleted_at IS NULL AND p.is_encrypted = 0 AND (ppl.expires_at IS NULL OR ppl.expires_at > NOW()) ORDER BY ppl.created_at DESC LIMIT 1`, [tokenHash]);
			if (!publishRows.length) return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
			const pageId = publishRows[0].page_id;
			const allowComments = Number(publishRows[0].allow_comments) === 1;
			if (!allowComments) {
				if (!userId) return res.status(403).json({ error: "댓글을 작성할 권한이 없습니다." });
				const page = await pagesRepo.getPageByIdForUser({ userId, pageId });
				if (!page) return res.status(403).json({ error: "댓글을 작성할 권한이 없습니다." });
			}
			const nowStr = formatDateForDb(new Date());
			await pool.execute(`INSERT INTO comments (page_id, user_id, guest_name, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, [pageId, userId, sanitizedGuestName, sanitizedContent, nowStr, nowStr]);
			res.status(201).json({ success: true });
		} catch (e) {
			logError("POST /api/comments/shared/:token", e);
			res.status(500).json({ error: "댓글 작성 실패" });
		}
	});

	router.get('/:pageId', authMiddleware, async (req, res) => {
		const pageId = req.params.pageId;
		const userId = req.user.id;
		try {
			const page = await loadPageForCommentsOr404(userId, pageId, res);
			if (!page) return;
			const [comments] = await pool.execute(`SELECT c.id, c.content, c.created_at, c.user_id, c.guest_name, u.username FROM comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.page_id = ? ORDER BY c.created_at ASC`, [pageId]);
			res.json(comments.map(c => ({ id: c.id, content: c.content, createdAt: toIsoString(c.created_at), author: c.user_id ? c.username : c.guest_name, isGuest: !c.user_id, isMyComment: userId ? (c.user_id === userId) : false })));
		} catch (error) {
			logError("GET /api/comments/:pageId", error);
			res.status(500).json({ error: "댓글 목록 조회 실패" });
		}
	});

	router.post('/:pageId', authMiddleware, csrfMiddleware, async (req, res) => {
		const pageId = req.params.pageId;
		const userId = req.user.id;
		const { content } = req.body;
		if (!content || typeof content !== 'string' || content.trim() === '') return res.status(400).json({ error: "댓글 내용을 입력해주세요." });
		const sanitizedContent = sanitizeInput(content.trim());
		try {
			const page = await loadPageForCommentsOr404(userId, pageId, res);
			if (!page) return;
			const nowStr = formatDateForDb(new Date());
			await pool.execute(`INSERT INTO comments (page_id, user_id, guest_name, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, [pageId, userId, null, sanitizedContent, nowStr, nowStr]);
			res.status(201).json({ success: true });
		} catch (error) {
			logError("POST /api/comments/:pageId", error);
			res.status(500).json({ error: "댓글 작성 실패" });
		}
	});

	router.delete('/:commentId', authMiddleware, csrfMiddleware, async (req, res) => {
		const commentId = req.params.commentId;
		const userId = req.user.id;
		try {
			const [comments] = await pool.execute(`SELECT c.id, c.user_id, c.page_id FROM comments c WHERE c.id = ?`, [commentId]);
			if (!comments.length) return res.status(404).json({ error: "댓글을 찾을 수 없습니다." });
			const comment = comments[0];
			const page = await loadPageForCommentsOr404(userId, comment.page_id, res);
			if (!page) return;
			const isAuthor = comment.user_id && Number(comment.user_id) === Number(userId);
			const isPageOwner = Number(page.user_id) === Number(userId);
			if (!isAuthor && !isPageOwner) return res.status(403).json({ error: "삭제 권한이 없습니다." });
			await pool.execute(`DELETE FROM comments WHERE id = ?`, [commentId]);
			res.json({ success: true });
		} catch (error) {
			logError("DELETE /api/comments/:commentId", error);
			res.status(500).json({ error: "댓글 삭제 실패" });
		}
	});

	router.put('/:commentId', authMiddleware, csrfMiddleware, async (req, res) => {
		const commentId = req.params.commentId;
		const session = await getSessionFromRequest(req);
		const userId = session ? session.userId : null;
		const { content } = req.body;
		if (!content || typeof content !== 'string' || content.trim() === '') return res.status(400).json({ error: "댓글 내용을 입력해주세요." });
		const sanitizedContent = sanitizeInput(content.trim());
		try {
			const [comments] = await pool.execute(`SELECT c.id, c.user_id, c.page_id FROM comments c WHERE c.id = ?`, [commentId]);
			if (!comments.length) return res.status(404).json({ error: "댓글을 찾을 수 없습니다." });
			const comment = comments[0];
			const page = await loadPageForCommentsOr404(userId, comment.page_id, res);
			if (!page) return;
			if (!userId || !comment.user_id || Number(comment.user_id) !== Number(userId)) return res.status(403).json({ error: "수정 권한이 없습니다." });
			const nowStr = formatDateForDb(new Date());
			await pool.execute(`UPDATE comments SET content = ?, updated_at = ? WHERE id = ?`, [sanitizedContent, nowStr, commentId]);
			res.json({ success: true });
		} catch (error) {
			logError("PUT /api/comments/:commentId", error);
			res.status(500).json({ error: "댓글 수정 실패" });
		}
	});

	return router;
};
