const express = require('express');
const router = express.Router();

/**
 * Pages Routes
 *
 * 이 파일은 페이지 관련 라우트를 처리합니다.
 * - 페이지 목록 조회
 * - 단일 페이지 조회
 * - 페이지 생성
 * - 페이지 수정
 * - 페이지 삭제
 * - 페이지 공유 허용 설정
 */

module.exports = (dependencies) => {
    const {
        pool,
        authMiddleware,
        toIsoString,
        sanitizeInput,
        sanitizeHtmlContent,
        generatePageId,
        formatDateForDb,
        getCollectionPermission,
        broadcastToCollection,
        logError
    } = dependencies;

    /**
     * 페이지 목록 조회 (소유한 페이지 + 공유받은 컬렉션의 페이지)
     * GET /api/pages
     */
    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const collectionId =
                typeof req.query.collectionId === "string" && req.query.collectionId.trim() !== ""
                    ? req.query.collectionId.trim()
                    : null;

            let query = `
                SELECT DISTINCT p.id, p.title, p.updated_at, p.parent_id, p.sort_order, p.collection_id, p.is_encrypted, p.share_allowed, p.user_id, p.icon
                FROM pages p
                LEFT JOIN collections c ON p.collection_id = c.id
                LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                WHERE (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)
                  AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
            `;
            const params = [userId, userId, userId, userId];

            if (collectionId) {
                query += ` AND p.collection_id = ?`;
                params.push(collectionId);
            }

            query += `
                ORDER BY p.collection_id ASC, p.parent_id IS NULL DESC, p.sort_order ASC, p.updated_at DESC
            `;

            const [rows] = await pool.execute(query, params);

            const list = rows.map((row) => ({
                id: row.id,
                title: row.title || "제목 없음",
                updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id,
                sortOrder: row.sort_order,
                collectionId: row.collection_id,
                isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id,
                icon: row.icon || null
            }));

            console.log("GET /api/pages 응답 개수:", list.length);

            res.json(list);
        } catch (error) {
            logError("GET /api/pages", error);
            res.status(500).json({ error: "페이지 목록 불러오기 실패." });
        }
    });

    /**
     * 단일 페이지 조회 (소유한 페이지 또는 공유받은 컬렉션의 페이지)
     * GET /api/pages/:id
     */
    router.get("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, p.parent_id, p.sort_order, p.collection_id, p.is_encrypted, p.share_allowed, p.user_id, p.icon
                 FROM pages p
                 LEFT JOIN collections c ON p.collection_id = c.id
                 LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                 WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)`,
                [userId, id, userId, userId]
            );

            if (!rows.length) {
                console.warn("GET /api/pages/:id - 페이지 없음 또는 권한 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const row = rows[0];

            const page = {
                id: row.id,
                title: row.title || "제목 없음",
                content: row.content || "<p></p>",
                createdAt: toIsoString(row.created_at),
                updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id,
                sortOrder: row.sort_order,
                collectionId: row.collection_id,
                isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id,
                icon: row.icon || null
            };

            console.log("GET /api/pages/:id 응답:", id);

            res.json(page);
        } catch (error) {
            logError("GET /api/pages/:id", error);
            res.status(500).json({ error: "페이지 불러오기 실패." });
        }
    });

    /**
     * 새 페이지 생성
     * POST /api/pages
     * body: { title?: string, content?: string, parentId?: string, sortOrder?: number, collectionId: string, icon?: string }
     */
    router.post("/", authMiddleware, async (req, res) => {
        const rawTitle = typeof req.body.title === "string" ? req.body.title : "";
        const title = sanitizeInput(rawTitle.trim() !== "" ? rawTitle.trim() : "제목 없음");

        const now = new Date();
        const id = generatePageId(now);
        const nowStr = formatDateForDb(now);
        const rawContent = typeof req.body.content === "string" ? req.body.content : "<p></p>";
        const content = sanitizeHtmlContent(rawContent);
        const userId = req.user.id;

        const parentId =
            typeof req.body.parentId === "string" && req.body.parentId.trim() !== ""
                ? req.body.parentId.trim()
                : null;
        const sortOrder =
            typeof req.body.sortOrder === "number" && Number.isFinite(req.body.sortOrder)
                ? req.body.sortOrder
                : 0;
        const collectionId =
            typeof req.body.collectionId === "string" && req.body.collectionId.trim() !== ""
                ? req.body.collectionId.trim()
                : null;
        const icon =
            typeof req.body.icon === "string" && req.body.icon.trim() !== ""
                ? req.body.icon.trim()
                : null;

        if (!collectionId) {
            return res.status(400).json({ error: "collectionId가 필요합니다." });
        }

        try {
            const { permission } = await getCollectionPermission(collectionId, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 생성할 권한이 없습니다." });
            }

            if (parentId) {
                const [parentRows] = await pool.execute(
                    `SELECT p.id, p.collection_id
                     FROM pages p
                     LEFT JOIN collections c ON p.collection_id = c.id
                     LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                     WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)`,
                    [userId, parentId, userId, userId]
                );

                if (!parentRows.length) {
                    return res.status(400).json({ error: "부모 페이지를 찾을 수 없습니다." });
                }

                if (parentRows[0].collection_id !== collectionId) {
                    return res.status(400).json({ error: "부모 페이지와 동일한 컬렉션이어야 합니다." });
                }
            }

            await pool.execute(
                `
                INSERT INTO pages (id, user_id, parent_id, title, content, sort_order, created_at, updated_at, collection_id, icon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [id, userId, parentId, title, content, sortOrder, nowStr, nowStr, collectionId, icon]
            );

            const page = {
                id,
                title,
                content,
                parentId,
                sortOrder,
                collectionId,
                createdAt: now.toISOString(),
                updatedAt: now.toISOString(),
                icon
            };

            console.log("POST /api/pages 생성:", id);

            res.status(201).json(page);
        } catch (error) {
            logError("POST /api/pages", error);
            res.status(500).json({ error: "페이지 생성 실패." });
        }
    });

    /**
     * 페이지 수정
     * PUT /api/pages/:id
     * body: { title?: string, content?: string, isEncrypted?: boolean, icon?: string }
     */
    router.put("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        const titleFromBody = typeof req.body.title === "string" ? sanitizeInput(req.body.title.trim()) : null;
        const contentFromBody = typeof req.body.content === "string" ? sanitizeHtmlContent(req.body.content) : null;
        const isEncryptedFromBody = typeof req.body.isEncrypted === "boolean" ? req.body.isEncrypted : null;
        const iconFromBody = typeof req.body.icon === "string" ? req.body.icon.trim() : undefined;

        if (!titleFromBody && !contentFromBody && isEncryptedFromBody === null && iconFromBody === undefined) {
            return res.status(400).json({ error: "수정할 데이터 없음." });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, title, content, created_at, updated_at, parent_id, sort_order, collection_id, is_encrypted, user_id, icon
                 FROM pages
                 WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                console.warn("PUT /api/pages/:id - 페이지 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const existing = rows[0];

            const { permission } = await getCollectionPermission(existing.collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 수정할 권한이 없습니다." });
            }

            const newTitle = titleFromBody && titleFromBody !== "" ? titleFromBody : existing.title;
            const newContent = contentFromBody !== null ? contentFromBody : existing.content;
            const newIsEncrypted = isEncryptedFromBody !== null ? (isEncryptedFromBody ? 1 : 0) : existing.is_encrypted;
            const newIcon = iconFromBody !== undefined ? (iconFromBody !== "" ? iconFromBody : null) : existing.icon;
            const now = new Date();
            const nowStr = formatDateForDb(now);

            const isBecomingEncrypted = existing.is_encrypted === 0 && newIsEncrypted === 1;

            if (isBecomingEncrypted) {
                await pool.execute(
                    `UPDATE pages
                     SET title = ?, content = ?, is_encrypted = ?, icon = ?, user_id = ?, updated_at = ?
                     WHERE id = ?`,
                    [newTitle, newContent, newIsEncrypted, newIcon, userId, nowStr, id]
                );
            } else {
                await pool.execute(
                    `UPDATE pages
                     SET title = ?, content = ?, is_encrypted = ?, icon = ?, updated_at = ?
                     WHERE id = ?`,
                    [newTitle, newContent, newIsEncrypted, newIcon, nowStr, id]
                );
            }

            const page = {
                id,
                title: newTitle,
                content: newContent,
                parentId: existing.parent_id,
                sortOrder: existing.sort_order,
                collectionId: existing.collection_id,
                createdAt: toIsoString(existing.created_at),
                updatedAt: now.toISOString(),
                icon: newIcon
            };

            console.log("PUT /api/pages/:id 수정 완료:", id);

            if (titleFromBody && titleFromBody !== existing.title) {
                broadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'title',
                    value: newTitle
                }, userId);
            }

            if (iconFromBody !== undefined && newIcon !== existing.icon) {
                broadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'icon',
                    value: newIcon
                }, userId);
            }

            res.json(page);
        } catch (error) {
            logError("PUT /api/pages/:id", error);
            res.status(500).json({ error: "페이지 수정 실패." });
        }
    });

    /**
     * 페이지 삭제 (EDIT 이상 권한 필요)
     * DELETE /api/pages/:id
     */
    router.delete("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const [rows] = await pool.execute(
                `SELECT id, collection_id FROM pages WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                console.warn("DELETE /api/pages/:id - 페이지 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const page = rows[0];

            const { permission } = await getCollectionPermission(page.collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 삭제할 권한이 없습니다." });
            }

            await pool.execute(
                `DELETE FROM pages WHERE id = ?`,
                [id]
            );

            console.log("DELETE /api/pages/:id 삭제:", id);

            res.json({ ok: true, removedId: id });
        } catch (error) {
            logError("DELETE /api/pages/:id", error);
            res.status(500).json({ error: "페이지 삭제 실패." });
        }
    });

    /**
     * 페이지 공유 허용 설정 업데이트
     * PUT /api/pages/:id/share-permission
     * body: { shareAllowed: boolean }
     */
    router.put("/:id/share-permission", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { shareAllowed } = req.body;

        if (typeof shareAllowed !== "boolean") {
            return res.status(400).json({ error: "shareAllowed는 boolean 값이어야 합니다." });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, collection_id, is_encrypted, user_id FROM pages WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = rows[0];

            if (!page.is_encrypted) {
                return res.status(400).json({ error: "암호화된 페이지만 공유 허용 설정이 가능합니다." });
            }

            if (page.user_id !== userId) {
                return res.status(403).json({ error: "페이지 생성자만 공유 허용 설정을 변경할 수 있습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `UPDATE pages SET share_allowed = ?, updated_at = ? WHERE id = ?`,
                [shareAllowed ? 1 : 0, nowStr, id]
            );

            res.json({ ok: true, shareAllowed });
        } catch (error) {
            logError("PUT /api/pages/:id/share-permission", error);
            res.status(500).json({ error: "공유 허용 설정 업데이트 실패." });
        }
    });

    return router;
};
