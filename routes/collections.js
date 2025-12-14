const express = require('express');
const router = express.Router();

/**
 * Collections Routes
 *
 * 이 파일은 컬렉션 관련 라우트를 처리합니다.
 * - 컬렉션 목록 조회
 * - 컬렉션 생성
 * - 컬렉션 삭제
 */

module.exports = (dependencies) => {
    const {
        pool,
        authMiddleware,
        toIsoString,
        sanitizeInput,
        createCollection,
        getCollectionPermission,
        logError
    } = dependencies;

    /**
     * 컬렉션 목록 조회 (소유한 컬렉션 + 공유받은 컬렉션)
     * GET /api/collections
     */
    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;

            const [rows] = await pool.execute(
                `SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                        c.user_id as owner_id,
                        CASE
                            WHEN c.user_id = ? THEN 'OWNER'
                            ELSE cs.permission
                        END as permission,
                        (SELECT COUNT(*) FROM collection_shares WHERE collection_id = c.id) as share_count
                 FROM collections c
                 LEFT JOIN collection_shares cs ON c.id = cs.collection_id AND cs.shared_with_user_id = ?
                 WHERE c.user_id = ? OR cs.shared_with_user_id IS NOT NULL
                 ORDER BY c.sort_order ASC, c.updated_at DESC`,
                [userId, userId, userId]
            );

            const list = rows.map((row) => ({
                id: row.id,
                name: row.name,
                sortOrder: row.sort_order,
                createdAt: toIsoString(row.created_at),
                updatedAt: toIsoString(row.updated_at),
                isOwner: row.owner_id === userId,
                permission: row.permission,
                isShared: row.share_count > 0
            }));

            res.json(list);
        } catch (error) {
            logError("GET /api/collections", error);
            res.status(500).json({ error: "컬렉션 목록을 불러오지 못했습니다." });
        }
    });

    /**
     * 새 컬렉션 생성
     * POST /api/collections
     * body: { name?: string }
     */
    router.post("/", authMiddleware, async (req, res) => {
        const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
        const name = sanitizeInput(rawName !== "" ? rawName : "새 컬렉션");

        try {
            const userId = req.user.id;
            const collection = await createCollection({ userId, name });
            res.status(201).json(collection);
        } catch (error) {
            logError("POST /api/collections", error);
            res.status(500).json({ error: "컬렉션을 생성하지 못했습니다." });
        }
    });

    /**
     * 컬렉션 삭제 (소유자만 가능)
     * DELETE /api/collections/:id
     */
    router.delete("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const { isOwner } = await getCollectionPermission(id, userId);
            if (!isOwner) {
                return res.status(403).json({ error: "컬렉션 소유자만 삭제할 수 있습니다." });
            }

            await pool.execute(
                `DELETE FROM collections WHERE id = ?`,
                [id]
            );

            res.json({ ok: true, removedId: id });
        } catch (error) {
            logError("DELETE /api/collections/:id", error);
            res.status(500).json({ error: "컬렉션 삭제에 실패했습니다." });
        }
    });

    return router;
};
