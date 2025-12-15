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


    return router;
};
