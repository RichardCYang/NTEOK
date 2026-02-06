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
     *
     * 성능 최적화:
     * - UNION ALL로 쿼리 분리하여 인덱스 활용 극대화
     * - share_count는 별도 쿼리로 분리 (필요할 때만 계산)
     * - 각 쿼리가 독립적인 인덱스 사용
     */
    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.query.storageId;

            // 성능 최적화: UNION ALL로 분리하여 인덱스 활용
            // 1. 본인 소유 컬렉션 (인덱스: idx_collections_user_sort)
            // 2. 공유받은 컬렉션 (인덱스: idx_shared_with_user)
            const query = `(
                    SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                           c.user_id as owner_id, c.is_encrypted,
                           c.default_encryption, c.enforce_encryption,
                           'OWNER' as permission
                    FROM collections c
                    WHERE c.user_id = ? ${storageId ? 'AND c.storage_id = ?' : ''}
                )
                UNION ALL
                (
                    SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                           c.user_id as owner_id, c.is_encrypted,
                           c.default_encryption, c.enforce_encryption,
                           cs.permission as permission
                    FROM collections c
                    INNER JOIN collection_shares cs ON c.id = cs.collection_id
                    WHERE cs.shared_with_user_id = ? ${storageId ? 'AND c.storage_id = ?' : ''}
                )
                ORDER BY sort_order ASC, updated_at DESC`;
            
            const params = storageId 
                ? [userId, storageId, userId, storageId]
                : [userId, userId];

            const [rows] = await pool.execute(query, params);

            // share_count를 별도로 계산 (한 번의 쿼리로)
            const collectionIds = rows.map(row => row.id);
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

            const list = rows.map((row) => ({
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

            console.log("GET /api/collections 응답 개수:", list.length, "(최적화된 UNION 쿼리)");
            res.json(list);
        } catch (error) {
            logError("GET /api/collections", error);
            res.status(500).json({ error: "컬렉션 목록을 불러오지 못했습니다." });
        }
    });

    /**
     * 새 컬렉션 생성
     * POST /api/collections
     * body: { name?: string, storageId: string }
     */
    router.post("/", authMiddleware, async (req, res) => {
        const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
        const name = sanitizeInput(rawName !== "" ? rawName : "새 컬렉션");
        const storageId = req.body.storageId;

        if (!storageId) {
            return res.status(400).json({ error: "storageId가 필요합니다." });
        }

        try {
            const userId = req.user.id;
            const collection = await createCollection({ userId, name, storageId });
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

    /**
     * 컬렉션 설정 업데이트 (소유자만 가능)
     * PUT /api/collections/:id
     * body: { name?, defaultEncryption?, enforceEncryption? }
     */
    router.put("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const { isOwner } = await getCollectionPermission(id, userId);
            if (!isOwner) {
                return res.status(403).json({ error: "컬렉션 소유자만 설정을 변경할 수 있습니다." });
            }

            const updates = [];
            const values = [];

            if (typeof req.body.name === 'string') {
                const name = sanitizeInput(req.body.name.trim());
                updates.push('name = ?');
                values.push(name);
            }

            if (typeof req.body.defaultEncryption === 'boolean') {
                updates.push('default_encryption = ?');
                values.push(req.body.defaultEncryption ? 1 : 0);
            }

            if (typeof req.body.enforceEncryption === 'boolean') {
                updates.push('enforce_encryption = ?');
                values.push(req.body.enforceEncryption ? 1 : 0);
            }

            if (updates.length === 0) {
                return res.status(400).json({ error: "업데이트할 내용이 없습니다." });
            }

            updates.push('updated_at = NOW()');
            values.push(id);

            await pool.execute(
                `UPDATE collections SET ${updates.join(', ')} WHERE id = ?`,
                values
            );

            res.json({ ok: true });
        } catch (error) {
            logError("PUT /api/collections/:id", error);
            res.status(500).json({ error: "컬렉션 설정 업데이트에 실패했습니다." });
        }
    });

    /**
     * 컬렉션 암호화 키 조회
     * GET /api/collections/:id/encryption-key
     */
    router.get("/:id/encryption-key", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const userId = req.user.id;

        try {
            const { permission, isOwner } = await getCollectionPermission(collectionId, userId);
            console.log(`[컬렉션 키 조회] 사용자 ${userId}, 컬렉션 ${collectionId}, 권한: ${permission}, 소유자: ${isOwner}`);

            if (!permission) {
                console.warn(`[컬렉션 키 조회 실패] 사용자 ${userId}가 컬렉션 ${collectionId}에 대한 권한이 없음`);
                return res.status(403).json({ error: "접근 권한이 없습니다." });
            }

            if (isOwner) {
                // 소유자: collections 테이블에서 encryption_key_encrypted 조회
                const [rows] = await pool.execute(
                    `SELECT encryption_key_encrypted FROM collections WHERE id = ?`,
                    [collectionId]
                );

                if (rows.length === 0 || !rows[0].encryption_key_encrypted) {
                    return res.status(404).json({ error: "암호화 키가 설정되지 않았습니다." });
                }

                res.json({ encryptedKey: rows[0].encryption_key_encrypted });
            } else {
                // 공유받은 사용자: collection_encryption_keys 테이블에서 조회
                const [rows] = await pool.execute(
                    `SELECT encrypted_key FROM collection_encryption_keys
                     WHERE collection_id = ? AND user_id = ?`,
                    [collectionId, userId]
                );

                if (rows.length === 0) {
                    return res.status(404).json({ error: "암호화 키를 찾을 수 없습니다." });
                }

                res.json({ encryptedKey: rows[0].encrypted_key });
            }
        } catch (error) {
            logError("GET /api/collections/:id/encryption-key", error);
            res.status(500).json({ error: "암호화 키 조회에 실패했습니다." });
        }
    });

    /**
     * 컬렉션 암호화 활성화
     * POST /api/collections/:id/encrypt
     */
    router.post("/:id/encrypt", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const userId = req.user.id;
        const { encryptedKey, sharedUserKeys } = req.body;

        try {
            const { isOwner } = await getCollectionPermission(collectionId, userId);
            if (!isOwner) {
                return res.status(403).json({ error: "컬렉션 소유자만 암호화를 설정할 수 있습니다." });
            }

            // 컬렉션을 암호화 상태로 변경
            await pool.execute(
                `UPDATE collections
                 SET is_encrypted = 1, encryption_key_encrypted = ?, updated_at = NOW()
                 WHERE id = ?`,
                [encryptedKey, collectionId]
            );

            // 공유된 사용자들에게 컬렉션 키 공유
            if (sharedUserKeys && Array.isArray(sharedUserKeys)) {
                for (const { userId: sharedUserId, encryptedKey: userEncryptedKey } of sharedUserKeys) {
                    await pool.execute(
                        `INSERT INTO collection_encryption_keys (collection_id, user_id, encrypted_key, created_at, updated_at)
                         VALUES (?, ?, ?, NOW(), NOW())
                         ON DUPLICATE KEY UPDATE encrypted_key = VALUES(encrypted_key), updated_at = NOW()`,
                        [collectionId, sharedUserId, userEncryptedKey]
                    );
                }
            }

            res.json({ ok: true });
        } catch (error) {
            logError("POST /api/collections/:id/encrypt", error);
            res.status(500).json({ error: "컬렉션 암호화 설정에 실패했습니다." });
        }
    });

    /**
     * 컬렉션 키를 새 수신자에게 공유
     * POST /api/collections/:id/share-key
     */
    router.post("/:id/share-key", authMiddleware, async (req, res) => {
        const collectionId = req.params.id;
        const userId = req.user.id;
        const { sharedUserId, encryptedKey } = req.body;

        try {
            const { isOwner } = await getCollectionPermission(collectionId, userId);
            if (!isOwner) {
                return res.status(403).json({ error: "컬렉션 소유자만 키를 공유할 수 있습니다." });
            }

            // collection_encryption_keys 테이블에 추가
            await pool.execute(
                `INSERT INTO collection_encryption_keys (collection_id, user_id, encrypted_key, created_at, updated_at)
                 VALUES (?, ?, ?, NOW(), NOW())
                 ON DUPLICATE KEY UPDATE encrypted_key = VALUES(encrypted_key), updated_at = NOW()`,
                [collectionId, sharedUserId, encryptedKey]
            );

            res.json({ ok: true });
        } catch (error) {
            logError("POST /api/collections/:id/share-key", error);
            res.status(500).json({ error: "키 공유에 실패했습니다." });
        }
    });

    /**
     * 컬렉션 순서 변경
     * PATCH /api/collections/reorder
     * body: { collectionIds: string[] }
     */
    router.patch("/reorder", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        const { collectionIds } = req.body;

        if (!Array.isArray(collectionIds) || collectionIds.length === 0) {
            return res.status(400).json({ error: "collectionIds 배열이 필요합니다." });
        }

        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();

            // 모든 컬렉션이 사용자 소유인지 확인
            const placeholders = collectionIds.map(() => '?').join(',');
            const [rows] = await conn.execute(
                `SELECT id FROM collections WHERE id IN (${placeholders}) AND user_id = ?`,
                [...collectionIds, userId]
            );

            if (rows.length !== collectionIds.length) {
                await conn.rollback();
                return res.status(403).json({ error: "일부 컬렉션에 대한 권한이 없습니다." });
            }

            // 순서 업데이트 (인덱스 * 10)
            for (let i = 0; i < collectionIds.length; i++) {
                await conn.execute(
                    `UPDATE collections SET sort_order = ?, updated_at = NOW() WHERE id = ?`,
                    [i * 10, collectionIds[i]]
                );
            }

            await conn.commit();
            console.log(`[Reorder] 컬렉션 순서 변경 완료: ${collectionIds.length}개`);
            res.json({ ok: true, updated: collectionIds.length });

        } catch (error) {
            await conn.rollback();
            logError("PATCH /api/collections/reorder", error);
            res.status(500).json({ error: "순서 변경 실패" });
        } finally {
            conn.release();
        }
    });

    return router;
};
