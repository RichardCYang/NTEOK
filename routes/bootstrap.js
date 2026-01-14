const express = require('express');
const router = express.Router();

/**
 * Bootstrap Routes
 *
 * - 초기 로딩에 필요한 사용자/컬렉션/페이지 데이터를 한번에 제공
 */

module.exports = (dependencies) => {
    const { pool, authMiddleware, toIsoString, logError } = dependencies;

    /**
     * 부트스트랩 데이터
     * GET /api/bootstrap
     */
    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;

            const [userRows, collectionRows, pageRows] = await Promise.all([
                pool.execute(
                    `SELECT id, username FROM users WHERE id = ?`,
                    [userId]
                ),
                pool.execute(
                    `(
                        SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                               c.user_id as owner_id, c.is_encrypted,
                               c.default_encryption, c.enforce_encryption,
                               'OWNER' as permission
                        FROM collections c
                        WHERE c.user_id = ?
                    )
                    UNION ALL
                    (
                        SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                               c.user_id as owner_id, c.is_encrypted,
                               c.default_encryption, c.enforce_encryption,
                               cs.permission as permission
                        FROM collections c
                        INNER JOIN collection_shares cs ON c.id = cs.collection_id
                        WHERE cs.shared_with_user_id = ?
                    )
                    ORDER BY sort_order ASC, updated_at DESC`,
                    [userId, userId]
                ),
                pool.execute(
                    `(
                        SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                               p.collection_id, p.is_encrypted, p.share_allowed, p.user_id,
                               p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                        FROM pages p
                        INNER JOIN collections c ON p.collection_id = c.id
                        WHERE c.user_id = ?
                    )
                    UNION ALL
                    (
                        SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                               p.collection_id, p.is_encrypted, p.share_allowed, p.user_id,
                               p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                        FROM pages p
                        INNER JOIN collection_shares cs ON p.collection_id = cs.collection_id
                        WHERE cs.shared_with_user_id = ?
                          AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
                    )
                    ORDER BY collection_id ASC, parent_id IS NULL DESC, sort_order ASC, updated_at DESC`,
                    [userId, userId, userId]
                )
            ]);

            const user = userRows[0]?.[0]
                ? { id: userRows[0][0].id, username: userRows[0][0].username }
                : null;

            const collectionsRaw = collectionRows[0] || [];
            const collectionIds = collectionsRaw.map(row => row.id);
            let shareCountMap = {};

            if (collectionIds.length > 0) {
                const placeholders = collectionIds.map(() => '?').join(',');
                const [shareCounts] = await pool.execute(
                    `SELECT collection_id, COUNT(*) as share_count
                     FROM collection_shares
                     WHERE collection_id IN (${placeholders})
                     GROUP BY collection_id`,
                    collectionIds
                );

                shareCountMap = shareCounts.reduce((map, row) => {
                    map[row.collection_id] = row.share_count;
                    return map;
                }, {});
            }

            const collections = collectionsRaw.map((row) => ({
                id: row.id,
                name: row.name,
                sortOrder: row.sort_order,
                createdAt: toIsoString(row.created_at),
                updatedAt: toIsoString(row.updated_at),
                isOwner: row.owner_id === userId,
                permission: row.permission,
                isShared: (shareCountMap[row.id] || 0) > 0,
                isEncrypted: Boolean(row.is_encrypted),
                defaultEncryption: Boolean(row.default_encryption),
                enforceEncryption: Boolean(row.enforce_encryption)
            }));

            const pages = (pageRows[0] || []).map((row) => ({
                id: row.id,
                title: row.title || "제목 없음",
                updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id,
                sortOrder: row.sort_order,
                collectionId: row.collection_id,
                isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id,
                icon: row.icon || null,
                coverImage: row.cover_image || null,
                coverPosition: row.cover_position || 50,
                horizontalPadding: row.horizontal_padding || null
            }));

            res.json({ user, collections, pages });
        } catch (error) {
            logError("GET /api/bootstrap", error);
            res.status(500).json({ error: "초기 데이터 로드에 실패했습니다." });
        }
    });

    return router;
};
