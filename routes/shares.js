const express = require('express');
const router = express.Router();

/**
 * Shares Routes
 *
 * 이 파일은 컬렉션 공유 관련 라우트를 처리합니다.
 * - 사용자 간 직접 공유 (collection_shares)
 * - 링크 기반 공유 (share_links)
 */

module.exports = (dependencies) => {
    const {
        pool,
        authMiddleware,
        toIsoString,
        formatDateForDb,
        getCollectionPermission,
        hasEncryptedPages,
        generateShareToken,
        BASE_URL,
        logError
    } = dependencies;

    /**
     * 컬렉션을 특정 사용자에게 공유
     * POST /api/collections/:id/shares
     */
    router.post("/collections/:id/shares", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const { username, permission } = req.body;
        const ownerId = req.user.id;

        if (!username || typeof username !== 'string') {
            return res.status(400).json({ error: "사용자명을 입력해 주세요." });
        }

        if (!['READ', 'EDIT', 'ADMIN'].includes(permission)) {
            return res.status(400).json({ error: "유효하지 않은 권한입니다." });
        }

        try {
            const { isOwner } = await getCollectionPermission(collectionId, ownerId);
            if (!isOwner) {
                return res.status(403).json({ error: "컬렉션 소유자만 공유할 수 있습니다." });
            }

            const hasEncrypted = await hasEncryptedPages(collectionId);
            if (hasEncrypted) {
                return res.status(400).json({
                    error: "공유가 허용되지 않은 암호화 페이지가 포함되어 있습니다. 해당 페이지의 공유를 허용하거나 삭제한 후 다시 시도해 주세요."
                });
            }

            const [userRows] = await pool.execute(
                `SELECT id FROM users WHERE username = ?`,
                [username.trim()]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const targetUserId = userRows[0].id;

            if (targetUserId === ownerId) {
                return res.status(400).json({ error: "자기 자신에게는 공유할 수 없습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `INSERT INTO collection_shares
                 (collection_id, owner_user_id, shared_with_user_id, permission, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                 permission = VALUES(permission),
                 updated_at = VALUES(updated_at)`,
                [collectionId, ownerId, targetUserId, permission, nowStr, nowStr]
            );

            res.status(201).json({
                ok: true,
                share: {
                    collectionId,
                    username,
                    permission,
                    createdAt: now.toISOString()
                }
            });
        } catch (error) {
            logError("POST /api/collections/:id/shares", error);
            res.status(500).json({ error: "공유 생성 중 오류가 발생했습니다." });
        }
    });

    /**
     * 컬렉션 공유 목록 조회
     * GET /api/collections/:id/shares
     */
    router.get("/collections/:id/shares", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const userId = req.user.id;

        try {
            const { isOwner } = await getCollectionPermission(collectionId, userId);
            if (!isOwner) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            const [rows] = await pool.execute(
                `SELECT cs.id, u.username, cs.permission, cs.created_at, cs.updated_at
                 FROM collection_shares cs
                 JOIN users u ON cs.shared_with_user_id = u.id
                 WHERE cs.collection_id = ?
                 ORDER BY cs.created_at DESC`,
                [collectionId]
            );

            const shares = rows.map(row => ({
                id: row.id,
                username: row.username,
                permission: row.permission,
                createdAt: toIsoString(row.created_at),
                updatedAt: toIsoString(row.updated_at)
            }));

            res.json(shares);
        } catch (error) {
            logError("GET /api/collections/:id/shares", error);
            res.status(500).json({ error: "공유 목록 조회 중 오류가 발생했습니다." });
        }
    });

    /**
     * 공유 삭제
     * DELETE /api/collections/:id/shares/:shareId
     */
    router.delete("/collections/:id/shares/:shareId", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const shareId = req.params.shareId;
        const userId = req.user.id;

        try {
            const { isOwner } = await getCollectionPermission(collectionId, userId);
            if (!isOwner) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            await pool.execute(
                `DELETE FROM collection_shares WHERE id = ? AND collection_id = ?`,
                [shareId, collectionId]
            );

            res.json({ ok: true });
        } catch (error) {
            logError("DELETE /api/collections/:id/shares/:shareId", error);
            res.status(500).json({ error: "공유 삭제 중 오류가 발생했습니다." });
        }
    });

    /**
     * 공유 링크 생성
     * POST /api/collections/:id/share-links
     */
    router.post("/collections/:id/share-links", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const { permission, expiresInDays } = req.body;
        const ownerId = req.user.id;

        if (!['READ', 'EDIT'].includes(permission)) {
            return res.status(400).json({ error: "유효하지 않은 권한입니다. (ADMIN은 링크로 공유 불가)" });
        }

        try {
            const { isOwner } = await getCollectionPermission(collectionId, ownerId);
            if (!isOwner) {
                return res.status(403).json({ error: "컬렉션 소유자만 링크를 생성할 수 있습니다." });
            }

            const hasEncrypted = await hasEncryptedPages(collectionId);
            if (hasEncrypted) {
                return res.status(400).json({
                    error: "공유가 허용되지 않은 암호화 페이지가 포함되어 있습니다. 해당 페이지의 공유를 허용하거나 삭제한 후 다시 시도해 주세요."
                });
            }

            const token = generateShareToken();
            const now = new Date();
            const nowStr = formatDateForDb(now);

            let expiresAt = null;
            if (expiresInDays && typeof expiresInDays === 'number' && expiresInDays > 0) {
                const expiry = new Date(now.getTime() + expiresInDays * 24 * 60 * 60 * 1000);
                expiresAt = formatDateForDb(expiry);
            }

            await pool.execute(
                `INSERT INTO share_links
                 (token, collection_id, owner_user_id, permission, expires_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [token, collectionId, ownerId, permission, expiresAt, nowStr, nowStr]
            );

            res.status(201).json({
                ok: true,
                link: {
                    token,
                    url: `${BASE_URL}/share/${token}`,
                    permission,
                    expiresAt: expiresAt ? toIsoString(expiresAt) : null
                }
            });
        } catch (error) {
            logError("POST /api/collections/:id/share-links", error);
            res.status(500).json({ error: "링크 생성 중 오류가 발생했습니다." });
        }
    });

    /**
     * 컬렉션의 모든 공유 링크 조회
     * GET /api/collections/:id/share-links
     */
    router.get("/collections/:id/share-links", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const userId = req.user.id;

        try {
            const { isOwner } = await getCollectionPermission(collectionId, userId);
            if (!isOwner) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            const [rows] = await pool.execute(
                `SELECT id, token, permission, expires_at, is_active, created_at
                 FROM share_links
                 WHERE collection_id = ?
                 ORDER BY created_at DESC`,
                [collectionId]
            );

            const links = rows.map(row => ({
                id: row.id,
                token: row.token,
                url: `${BASE_URL}/share/${row.token}`,
                permission: row.permission,
                expiresAt: row.expires_at ? toIsoString(row.expires_at) : null,
                isActive: row.is_active ? true : false,
                createdAt: toIsoString(row.created_at)
            }));

            res.json(links);
        } catch (error) {
            logError("GET /api/collections/:id/share-links", error);
            res.status(500).json({ error: "링크 목록 조회 중 오류가 발생했습니다." });
        }
    });

    /**
     * 공유 링크 삭제
     * DELETE /api/collections/:id/share-links/:linkId
     */
    router.delete("/collections/:id/share-links/:linkId", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const linkId = req.params.linkId;
        const userId = req.user.id;

        try {
            const { isOwner } = await getCollectionPermission(collectionId, userId);
            if (!isOwner) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            await pool.execute(
                `DELETE FROM share_links WHERE id = ? AND collection_id = ?`,
                [linkId, collectionId]
            );

            res.json({ ok: true });
        } catch (error) {
            logError("DELETE /api/collections/:id/share-links/:linkId", error);
            res.status(500).json({ error: "링크 삭제 중 오류가 발생했습니다." });
        }
    });

    /**
     * 공유 링크로 컬렉션 정보 조회 (인증 불필요)
     * GET /api/share-links/:token
     */
    router.get("/share-links/:token", async (req, res) => {
        const token = req.params.token;

        try {
            const [rows] = await pool.execute(
                `SELECT sl.collection_id, sl.permission, sl.expires_at, sl.is_active,
                        c.name as collection_name
                 FROM share_links sl
                 JOIN collections c ON sl.collection_id = c.id
                 WHERE sl.token = ?`,
                [token]
            );

            if (rows.length === 0) {
                return res.status(404).json({ error: "유효하지 않은 공유 링크입니다." });
            }

            const link = rows[0];

            if (!link.is_active) {
                return res.status(403).json({ error: "비활성화된 링크입니다." });
            }

            if (link.expires_at && new Date(link.expires_at) < new Date()) {
                return res.status(403).json({ error: "만료된 링크입니다." });
            }

            res.json({
                collectionId: link.collection_id,
                collectionName: link.collection_name,
                permission: link.permission,
                expiresAt: link.expires_at ? toIsoString(link.expires_at) : null
            });
        } catch (error) {
            logError("GET /api/share-links/:token", error);
            res.status(500).json({ error: "링크 정보 조회 중 오류가 발생했습니다." });
        }
    });

    return router;
};
