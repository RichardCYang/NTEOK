/**
 * 저장소(Storage) 저장소
 * - DB storages 테이블 접근
 */

const crypto = require('crypto');

module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    const TRANSFER_BATCH_SIZE = (() => {
        const n = Number.parseInt(process.env.STORAGE_TRANSFER_BATCH_SIZE || "500", 10);
        if (!Number.isFinite(n)) return 500;
        return Math.max(50, Math.min(2000, n));
    })();

    function chunkArray(arr, size) {
        const out = [];
        for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
        return out;
    }

    function makeStorageId() {
        return 'stg-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
    }

    async function getNextSortOrderTx(conn, userId) {
        const [rows] = await conn.execute(
            `SELECT COALESCE(MAX(sort_order), -1) AS maxOrder FROM storages WHERE user_id = ? FOR UPDATE`,
            [userId]
        );
        return Number(rows?.[0]?.maxOrder ?? -1) + 1;
    }

    async function updatePagesInBatches(conn, sqlPrefixWhereIdIn, ids, paramsBeforeIds = []) {
        if (!Array.isArray(ids) || ids.length === 0) return;
        for (const chunk of chunkArray(ids, TRANSFER_BATCH_SIZE)) {
            const placeholders = chunk.map(() => '?').join(',');
            const sql = `${sqlPrefixWhereIdIn} (${placeholders})`;
            await conn.execute(sql, [...paramsBeforeIds, ...chunk]);
        }
    }

    return {
        /**
         * 사용자가 소유하거나 공유받은 저장소 목록 조회
         */
        async listStoragesForUser(userId) {
            const [rows] = await pool.execute(
                `SELECT s.id, s.name, s.sort_order, s.created_at, s.updated_at, s.user_id as owner_id,
                        s.is_encrypted, s.encryption_salt, s.encryption_check,
                        u.username as owner_name,
                        CASE WHEN s.user_id = ? THEN 1 ELSE 0 END as is_owner,
                        ss.permission
                 FROM storages s
                 LEFT JOIN users u ON s.user_id = u.id
                 LEFT JOIN storage_shares ss ON s.id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE s.user_id = ? OR ss.shared_with_user_id = ?
                 ORDER BY is_owner DESC, s.sort_order ASC, s.updated_at DESC`,
                [userId, userId, userId, userId]
            );
            return rows || [];
        },

        /**
         * 단일 저장소 조회 (소유 또는 공유 권한 확인)
         */
        async getStorageByIdForUser(userId, storageId) {
            const [rows] = await pool.execute(
                `SELECT s.id, s.name, s.sort_order, s.created_at, s.updated_at, s.user_id as owner_id,
                        s.is_encrypted, s.encryption_salt, s.encryption_check,
                        CASE WHEN s.user_id = ? THEN 1 ELSE 0 END as is_owner,
                        ss.permission
                 FROM storages s
                 LEFT JOIN storage_shares ss ON s.id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE s.id = ? AND (s.user_id = ? OR ss.shared_with_user_id = ?)`,
                [userId, userId, storageId, userId, userId]
            );
            return rows?.[0] || null;
        },

        /**
         * 저장소 참여자 목록 조회
         */
        async listCollaborators(storageId) {
            const [rows] = await pool.execute(
                `SELECT ss.shared_with_user_id as id, u.username, ss.permission
                 FROM storage_shares ss
                 JOIN users u ON ss.shared_with_user_id = u.id
                 WHERE ss.storage_id = ?
                 ORDER BY u.username ASC`,
                [storageId]
            );
            return rows;
        },

        /**
         * 저장소 참여자 추가
         */
        async addCollaborator({ storageId, ownerUserId, sharedWithUserId, permission, createdAt, updatedAt }) {
            await pool.execute(
                `INSERT INTO storage_shares (storage_id, owner_user_id, shared_with_user_id, permission, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE permission = ?, updated_at = ?`,
                [storageId, ownerUserId, sharedWithUserId, permission, createdAt, updatedAt, permission, updatedAt]
            );
        },

        /**
         * 저장소 참여자 삭제
         */
        async removeCollaborator(storageId, userId) {
            await pool.execute(
                `DELETE FROM storage_shares WHERE storage_id = ? AND shared_with_user_id = ?`,
                [storageId, userId]
            );
        },

        /**
         * 사용자의 저장소 권한 조회
         */
        async getPermission(userId, storageId) {
            const storage = await this.getStorageByIdForUser(userId, storageId);
            if (!storage) return null;
            if (storage.is_owner) return 'ADMIN';
            return storage.permission || null;
        },

        /**
         * 저장소 생성
         */
        async createStorage({ userId, id, name, sortOrder, createdAt, updatedAt, isEncrypted, encryptionSalt, encryptionCheck }) {
            await pool.execute(
                `INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at, is_encrypted, encryption_salt, encryption_check)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, userId, name, sortOrder, createdAt, updatedAt, isEncrypted || 0, encryptionSalt || null, encryptionCheck || null]
            );
            return { id, userId, name, sortOrder, createdAt, updatedAt, isEncrypted, encryptionSalt, encryptionCheck };
        },

        /**
         * 저장소 업데이트
         */
        async updateStorage(userId, storageId, { name, updatedAt }) {
            await pool.execute(
                `UPDATE storages SET name = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
                [name, updatedAt, storageId, userId]
            );
        },

        /**
         * 저장소 삭제
         */
        async deleteStorage(userId, storageId) {
            await pool.execute(
                `DELETE FROM storages WHERE id = ? AND user_id = ?`,
                [storageId, userId]
            );
        },

        /**
         * 데이터 유실 방지: 협업 저장소 삭제 안전화
         * 
         * 저장소(storages) 삭제 시 pages.storage_id(FK ON DELETE CASCADE) 설정으로 인해 해당 저장소의 모든 페이지가 함께 삭제될 수 있음
         * 특히 협업 저장소에서는 저장소 소유자가 아닌 다른 참여자가 생성한 페이지도 존재할 수 있는데, 소유자가 저장소를 삭제할 때 참여자의 데이터까지 영구 삭제되는 것을 방지해야 함
         * 
         * 이를 해결하기 위해 저장소를 삭제하기 전, 협업자 소유의 페이지들을 각자의 개인 저장소로 이관함
         * 또한 부모 페이지 삭제 시 연쇄 삭제되지 않도록 부모 관계(parent_id)를 해제하여 데이터를 보존함
         * 
         * @returns {Object} transferred - 사용자별 이관 정보 (개인 저장소 ID 및 이동된 페이지 목록)
         */
        async safeDeleteStoragePreservingCollaborators(ownerUserId, storageId) {
            const ownerId = Number(ownerUserId);
            const sid = String(storageId || '').trim();
            if (!Number.isFinite(ownerId) || !sid) throw new Error('Invalid args');

            const conn = await pool.getConnection();
            try {
                await conn.beginTransaction();

                // 저장소 소유 확인 + 암호화 메타 확보
                const [stRows] = await conn.execute(
                    `SELECT id, user_id, name, is_encrypted, encryption_salt, encryption_check
                       FROM storages
                      WHERE id = ? AND user_id = ?
                      FOR UPDATE`,
                    [sid, ownerId]
                );
                if (!stRows || stRows.length === 0) {
                    await conn.rollback();
                    return { ok: false, reason: 'not-found-or-forbidden' };
                }
                const storage = stRows[0];

                // 해당 저장소의 모든 페이지(휴지통 포함) 조회
                const [pageRows] = await conn.execute(
                    `SELECT id, user_id, parent_id
                       FROM pages
                      WHERE storage_id = ?`,
                    [sid]
                );

                // 협업자별 페이지 그룹화
                const byUser = new Map(); // userId -> { pageIds: Set, rows: [] }
                for (const r of (pageRows || [])) {
                    const uid = Number(r.user_id);
                    if (!Number.isFinite(uid)) continue;
                    if (uid === ownerId) continue;
                    if (!byUser.has(uid)) byUser.set(uid, { pageIds: new Set(), rows: [] });
                    byUser.get(uid).pageIds.add(String(r.id));
                    byUser.get(uid).rows.push({ id: String(r.id), parent_id: r.parent_id ? String(r.parent_id) : null });
                }

                const transferred = {};

                // 협업자 페이지가 없다면 안전하게 기존 동작(삭제) 수행
                if (byUser.size === 0) {
                    await conn.execute(`DELETE FROM storages WHERE id = ? AND user_id = ?`, [sid, ownerId]);
                    await conn.commit();
                    return { ok: true, transferred };
                }

                // 협업자별 이관 저장소 생성 + 페이지 이동
                for (const [uid, info] of byUser.entries()) {
                    const newStorageId = makeStorageId();
                    const sortOrder = await getNextSortOrderTx(conn, uid);
                    const newName = `[Recovered] ${String(storage.name || 'Storage').slice(0, 110)} (from ${ownerId})`;

                    await conn.execute(
                        `INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at, is_encrypted, encryption_salt, encryption_check)
                         VALUES (?, ?, ?, ?, NOW(), NOW(), ?, ?, ?)`,
                        [
                            newStorageId,
                            uid,
                            newName,
                            sortOrder,
                            Number(storage.is_encrypted) === 1 ? 1 : 0,
                            Number(storage.is_encrypted) === 1 ? (storage.encryption_salt || null) : null,
                            Number(storage.is_encrypted) === 1 ? (storage.encryption_check || null) : null
                        ]
                    );

                    // 경계 detach: 부모가 본인 소유 페이지 집합에 없으면 parent_id=NULL
                    const boundaryIds = [];
                    for (const row of info.rows) {
                        if (!row.parent_id) continue;
                        if (!info.pageIds.has(String(row.parent_id))) boundaryIds.push(row.id);
                    }
                    if (boundaryIds.length > 0) {
                        await updatePagesInBatches(
                            conn,
                            `UPDATE pages SET parent_id = NULL, updated_at = NOW() WHERE id IN`,
                            boundaryIds
                        );
                    }

                    // 페이지 이관: storage_id를 새 저장소로 변경
                    const pageIdsArr = Array.from(info.pageIds);
                    await updatePagesInBatches(
                        conn,
                        `UPDATE pages SET storage_id = ?, updated_at = NOW() WHERE id IN`,
                        pageIdsArr,
                        [newStorageId]
                    );

                    transferred[String(uid)] = { newStorageId, movedPages: pageIdsArr.length };
                }

                // 원래 저장소 삭제(소유자 페이지는 FK CASCADE로 정리)
                await conn.execute(`DELETE FROM storages WHERE id = ? AND user_id = ?`, [sid, ownerId]);

                await conn.commit();
                return { ok: true, transferred };
            } catch (e) {
                try { await conn.rollback(); } catch (_) {}
                throw e;
            } finally {
                try { conn.release(); } catch (_) {}
            }
        },

        /**
         * 계정 삭제(또는 대량 삭제) 전에, 사용자가 소유한 모든 저장소에서
         * 협업자 소유 페이지가 유실되지 않도록 이관 후 저장소 삭제
         */
        async safeDeleteAllOwnedStoragesPreservingCollaborators(ownerUserId) {
            const ownerId = Number(ownerUserId);
            if (!Number.isFinite(ownerId)) throw new Error('Invalid ownerUserId');

            const [rows] = await pool.execute(
                `SELECT id FROM storages WHERE user_id = ?`,
                [ownerId]
            );
            const results = [];
            for (const r of (rows || [])) {
                const storageId = r.id;
                const res = await this.safeDeleteStoragePreservingCollaborators(ownerId, storageId);
                results.push({ storageId, ...res });
                if (!res.ok) throw new Error(`safeDeleteStoragePreservingCollaborators failed: ${storageId}`);
            }
            return results;
        },

        /**
         * 다음 정렬 순서 조회
         */
        async getNextSortOrder(userId) {
            const [rows] = await pool.execute(
                `SELECT COALESCE(MAX(sort_order), -1) AS maxOrder FROM storages WHERE user_id = ?`,
                [userId]
            );
            return Number(rows[0].maxOrder) + 1;
        }
    };
};
