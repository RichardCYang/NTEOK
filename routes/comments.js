const express = require('express');
const router = express.Router();
const crypto = require('crypto');

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
        getSessionFromRequest,
        COOKIE_SECURE
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
                if (await forbidPrivateEncryptedPageComments(pageId, userId, res)) return null;
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

    async function isPrivateEncryptedPageForOtherUser(pageId, userId) {
        const [rows] = await pool.execute(
            `SELECT is_encrypted, share_allowed, user_id FROM pages WHERE id = ?`,
            [pageId]
        );
        if (rows.length === 0) return false;
        const page = rows[0];
        return Number(page.is_encrypted) === 1
            && Number(page.share_allowed) === 0
            && Number(page.user_id) !== Number(userId);
    }

    async function forbidPrivateEncryptedPageComments(pageId, userId, res) {
        if (!await isPrivateEncryptedPageForOtherUser(pageId, userId)) return false;
        res.status(403).json({ error: "비공개 암호화 페이지에는 댓글을 작성할 수 없습니다." });
        return true;
    }

    router.get('/:pageId', authMiddleware, async (req, res) => {
        const pageId = req.params.pageId;
        const userId = req.user.id;
        try {
            const page = await loadPageForCommentsOr404(userId, pageId, res);
            if (!page) return;
            const [comments] = await pool.execute(`SELECT c.id, c.content, c.created_at, c.user_id, c.guest_name, u.username FROM comments c LEFT JOIN users u ON c.user_id = u.id WHERE c.page_id = ? ORDER BY c.created_at ASC`, [pageId]);
            res.json(comments.map(c => ({ id: c.id, content: c.content, createdAt: toIsoString(c.created_at), author: c.user_id ? c.username : (c.guest_name || 'Guest'), isGuest: !c.user_id, isMyComment: userId ? (c.user_id === userId) : false })));
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
