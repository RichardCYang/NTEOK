const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const dns = require("node:dns").promises;
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const ipaddr = require("ipaddr.js");
const { assertImageFileSignature } = require("../security-utils.js");

const erl = require("express-rate-limit");
const rateLimit = erl.rateLimit || erl; 
const { ipKeyGenerator } = erl;

module.exports = (dependencies) => {
    const {
		pool,
		pagesRepo,
        pageSqlPolicy,
        authMiddleware,
        toIsoString,
		sanitizeInput,
		sanitizeFilenameComponent,
        sanitizeExtension,
        sanitizeHtmlContent,
        generatePageId,
        formatDateForDb,
        wsBroadcastToStorage,
        logError,
        generatePublishToken,
        coverUpload,
        editorImageUpload,
        themeUpload,
        fileUpload,
        path,
        fs,
        yjsDocuments
	} = dependencies;

	function normalizeUploadedImageFile(fileObj, detectedExt) {
	    if (!fileObj?.path || !fileObj?.filename) throw new Error('INVALID_UPLOAD');
	    const ext = `.${String(detectedExt || '').toLowerCase()}`;
		const safeExt = sanitizeExtension(ext);
	    if (!safeExt || !['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(safeExt)) throw new Error('UNSUPPORTED_IMAGE_TYPE');
	    const dir = path.dirname(fileObj.path);
	    const rawBase = path.basename(fileObj.filename, path.extname(fileObj.filename));
	    const base = sanitizeFilenameComponent(rawBase, 80).replace(/[^a-zA-Z0-9._-]/g, '') || crypto.randomBytes(8).toString('hex');
	    let newFilename = `${base}${safeExt}`;
		let newPath = path.join(dir, newFilename);
	    if (fs.existsSync(newPath)) { const suffix = crypto.randomBytes(4).toString('hex'); newFilename = `${base}-${suffix}${safeExt}`; newPath = path.join(dir, newFilename); }
	    const resolvedDir = path.resolve(dir) + path.sep;
		const resolvedNewPath = path.resolve(newPath);
	    if (!resolvedNewPath.startsWith(resolvedDir)) throw new Error('PATH_TRAVERSAL_BLOCKED');
	    if (newPath !== fileObj.path) { fs.renameSync(fileObj.path, newPath); fileObj.path = newPath; fileObj.filename = newFilename; }
	}

	function wsPageVisibilityFromRow(row) {
		const ownerUserId = Number(row && row.user_id);
		return { ownerUserId, isEncrypted: Boolean(row && row.is_encrypted === 1), shareAllowed: Boolean(row && row.share_allowed === 1) };
	}

    const outboundProxyLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 30,
        keyGenerator: (req) => { const uid = req.user?.id ? String(req.user.id) : "anon"; const rawIp = req.clientIp || req.ip; const ipKey = rawIp ? ipKeyGenerator(rawIp, 56) : "noip"; return `outbound:${uid}:${ipKey}`; },
        handler: (req, res) => res.status(429).json({ error: "Too many requests" }),
    });

    function blockCrossSiteFetch(req, res, next) {
        const sfs = String(req.headers["sec-fetch-site"] || "").toLowerCase();
        if (sfs && !["same-origin", "same-site", "none"].includes(sfs)) return res.status(403).json({ error: "Forbidden" });
        return next();
    }

	function validateAndNormalizeIcon(raw) {
        if (!raw || typeof raw !== "string") return null;
        const icon = raw.trim();
        if (icon === "" || /[<>]/.test(icon)) return null;
        const FA_RE = /^(fa-[\w-]+)(\s+fa-[\w-]+)*$/i;
        if (FA_RE.test(icon)) return icon;
        if (icon.length <= 8 && !/\s/.test(icon) && !/["'`&]/.test(icon)) return icon;
        return null;
    }

    router.get("/covers/user", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        try {
            const userCoversDir = path.join(__dirname, '..', 'covers', String(userId));
            if (!fs.existsSync(userCoversDir)) return res.json([]);
            const files = fs.readdirSync(userCoversDir);
            const covers = files.filter(f => ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(path.extname(f).toLowerCase()))
                .map(f => { const stats = fs.statSync(path.join(userCoversDir, f)); return { path: `${userId}/${f}`, filename: f, uploadedAt: stats.birthtime.toISOString() }; })
                .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
            res.json(covers);
        } catch (error) { logError("GET /api/pages/covers/user", error); res.status(500).json({ error: "Failed" }); }
    });

    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = typeof req.query.storageId === "string" ? req.query.storageId.trim() : null;
            const rows = await pagesRepo.listPagesForUser({ userId, storageId });
            const list = rows.map((row) => ({
                id: row.id, title: row.title || "제목 없음", updatedAt: toIsoString(row.updated_at), parentId: row.parent_id,
                sortOrder: row.sort_order, storageId: row.storage_id, isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false, userId: row.user_id, icon: row.icon || null,
                coverImage: row.cover_image || null, coverPosition: row.cover_position || 50, horizontalPadding: row.horizontal_padding || null
            }));
            res.json(list);
        } catch (error) { logError("GET /api/pages", error); res.status(500).json({ error: "Failed" }); }
    });

    router.get("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
           	const row = await pagesRepo.getPageByIdForUser({ userId, pageId: id });
            if (!row) return res.status(404).json({ error: "Not found" });
            res.json({
                id: row.id, title: row.title || "제목 없음", content: sanitizeHtmlContent(row.content || "<p></p>"),
                encryptionSalt: row.encryption_salt, encryptedContent: row.encrypted_content,
                createdAt: toIsoString(row.created_at), updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id, sortOrder: row.sort_order, storageId: row.storage_id,
                isEncrypted: row.is_encrypted ? true : false, shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id, icon: row.icon || null, coverImage: row.cover_image || null,
                coverPosition: row.cover_position || 50, horizontalPadding: row.horizontal_padding || null
            });
        } catch (error) { logError("GET /api/pages/:id", error); res.status(500).json({ error: "Failed" }); }
    });

    router.post("/", authMiddleware, async (req, res) => {
        const title = sanitizeInput(String(req.body.title || "제목 없음").trim());
        const storageId = req.body.storageId;
        if (!storageId) return res.status(400).json({ error: "storageId required" });
        const userId = req.user.id;
        const now = new Date();
        const id = generatePageId(now);
        const nowStr = formatDateForDb(now);
        try {
            const [stg] = await pool.execute(`SELECT id FROM storages WHERE id = ? AND user_id = ?`, [storageId, userId]);
            if (!stg.length) return res.status(403).json({ error: "Forbidden" });
            const parentId = req.body.parentId || null;
            const sortOrder = req.body.sortOrder || 0;
            const isEncrypted = req.body.isEncrypted === true ? 1 : 0;
            const salt = req.body.encryptionSalt || null;
            const encContent = req.body.encryptedContent || null;
            const content = isEncrypted ? '' : sanitizeHtmlContent(req.body.content || "<p></p>");
            if (isEncrypted && (!salt || !encContent)) return res.status(400).json({ error: "Encryption fields missing" });
            await pool.execute(`INSERT INTO pages (id, user_id, parent_id, title, content, sort_order, created_at, updated_at, storage_id, is_encrypted, encryption_salt, encrypted_content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, userId, parentId, title, content, sortOrder, nowStr, nowStr, storageId, isEncrypted, salt, encContent]);
            res.status(201).json({ id, title, storageId, parentId, isEncrypted: !!isEncrypted, updatedAt: now.toISOString() });
        } catch (e) { logError("POST /api/pages", e); res.status(500).json({ error: "Failed" }); }
    });

    router.put("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
            const [rows] = await pool.execute(`SELECT * FROM pages WHERE id = ?`, [id]);
            if (!rows.length) return res.status(404).json({ error: "Not found" });
            const existing = rows[0];
            if (existing.user_id !== userId) return res.status(403).json({ error: "Forbidden" });
            const title = req.body.title !== undefined ? sanitizeInput(req.body.title) : existing.title;
            const isEncrypted = req.body.isEncrypted !== undefined ? (req.body.isEncrypted ? 1 : 0) : existing.is_encrypted;
            const salt = req.body.encryptionSalt || existing.encryption_salt;
            const encContent = req.body.encryptedContent || existing.encrypted_content;
            const content = isEncrypted ? '' : (req.body.content !== undefined ? sanitizeHtmlContent(req.body.content) : existing.content);
            const icon = req.body.icon !== undefined ? validateAndNormalizeIcon(req.body.icon) : existing.icon;
            const hPadding = req.body.horizontalPadding !== undefined ? req.body.horizontalPadding : existing.horizontal_padding;
            const nowStr = formatDateForDb(new Date());
            let sql = `UPDATE pages SET title=?, content=?, is_encrypted=?, encryption_salt=?, encrypted_content=?, icon=?, horizontal_padding=?, updated_at=?`;
            const params = [title, content, isEncrypted, salt, encContent, icon, hPadding, nowStr];
            if (req.body.content !== undefined) { sql += `, yjs_state=NULL`; if (yjsDocuments.has(id)) yjsDocuments.delete(id); }
            sql += ` WHERE id=?`; params.push(id);
            await pool.execute(sql, params);
            wsBroadcastToStorage(existing.storage_id, 'metadata-change', { pageId: id, field: 'title', value: title }, null, { pageVisibility: wsPageVisibilityFromRow(existing) });
            res.json({ id, title, updatedAt: new Date().toISOString() });
        } catch (e) { logError("PUT /api/pages/:id", e); res.status(500).json({ error: "Failed" }); }
    });

    router.patch("/reorder", authMiddleware, async (req, res) => {
        const { storageId, pageIds, parentId } = req.body;
        const userId = req.user.id;
        try {
            const [stg] = await pool.execute(`SELECT id FROM storages WHERE id=? AND user_id=?`, [storageId, userId]);
            if (!stg.length) return res.status(403).json({ error: "Forbidden" });
            for (let i = 0; i < pageIds.length; i++) { await pool.execute(`UPDATE pages SET sort_order=?, updated_at=NOW() WHERE id=? AND storage_id=?`, [i * 10, pageIds[i], storageId]); }
            wsBroadcastToStorage(storageId, 'pages-reordered', { parentId, pageIds }, userId);
            res.json({ ok: true });
        } catch (e) { logError("PATCH /api/pages/reorder", e); res.status(500).json({ error: "Failed" }); }
    });

    router.delete("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
            const [rows] = await pool.execute(`SELECT * FROM pages WHERE id=?`, [id]);
            if (!rows.length) return res.status(404).json({ error: "Not found" });
            if (rows[0].user_id !== userId) return res.status(403).json({ error: "Forbidden" });
            await pool.execute(`DELETE FROM pages WHERE id=?`, [id]);
            res.json({ ok: true });
        } catch (e) { logError("DELETE /api/pages/:id", e); res.status(500).json({ error: "Failed" }); }
    });

    router.get("/:id/publish", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
            const [rows] = await pool.execute(`SELECT p.id, p.user_id, p.storage_id, p.is_encrypted FROM pages p WHERE p.id=?`, [id]);
            if (!rows.length) return res.status(404).json({ error: "Not found" });
            if (rows[0].user_id !== userId) return res.status(403).json({ error: "Forbidden" });
            const [pub] = await pool.execute(`SELECT token, created_at, allow_comments FROM page_publish_links WHERE page_id=? AND is_active=1`, [id]);
            if (!pub.length) return res.json({ published: false });
            res.json({ published: true, token: pub[0].token, url: `${process.env.BASE_URL}/shared/page/${pub[0].token}`, createdAt: toIsoString(pub[0].created_at), allowComments: pub[0].allow_comments === 1 });
        } catch (e) { logError("GET /api/pages/:id/publish", e); res.status(500).json({ error: "Failed" }); }
    });

    return router;
};