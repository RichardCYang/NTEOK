
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
        async listStoragesForUser(userId) {
            const [rows] = await pool.execute(
                `SELECT s.id, s.name, s.sort_order, s.created_at, s.updated_at, s.user_id as owner_id,
                        s.is_encrypted,
                        CASE WHEN s.user_id = ? THEN s.encryption_salt ELSE NULL END AS encryption_salt,
                        CASE WHEN s.user_id = ? THEN s.encryption_check ELSE NULL END AS encryption_check,
                        u.username as owner_name,
                        CASE WHEN s.user_id = ? THEN 1 ELSE 0 END as is_owner,
                        ss.permission
                 FROM storages s
                 LEFT JOIN users u ON s.user_id = u.id
                 LEFT JOIN storage_shares ss ON s.id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE s.user_id = ? OR ss.shared_with_user_id = ?
                 ORDER BY is_owner DESC, s.sort_order ASC, s.updated_at DESC`,
                [userId, userId, userId, userId, userId, userId]
            );
            return rows || [];
        },

        async getStorageByIdForUser(userId, storageId) {
            const [rows] = await pool.execute(
                `SELECT s.id, s.name, s.sort_order, s.created_at, s.updated_at, s.user_id as owner_id,
                        s.is_encrypted,
                        CASE WHEN s.user_id = ? THEN s.encryption_salt ELSE NULL END AS encryption_salt,
                        CASE WHEN s.user_id = ? THEN s.encryption_check ELSE NULL END AS encryption_check,
                        CASE WHEN s.user_id = ? THEN 1 ELSE 0 END as is_owner,
                        ss.permission
                 FROM storages s
                 LEFT JOIN storage_shares ss ON s.id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE s.id = ? AND (s.user_id = ? OR ss.shared_with_user_id = ?)`,
                [userId, userId, userId, userId, storageId, userId, userId]
            );
            return rows?.[0] || null;
        },

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

        async addCollaborator({ storageId, ownerUserId, sharedWithUserId, permission, createdAt, updatedAt }) {
            await pool.execute(
                `INSERT INTO storage_shares (storage_id, owner_user_id, shared_with_user_id, permission, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE permission = ?, updated_at = ?`,
                [storageId, ownerUserId, sharedWithUserId, permission, createdAt, updatedAt, permission, updatedAt]
            );
        },

        async removeCollaborator(storageId, userId) {
            await pool.execute(
                `DELETE FROM storage_shares WHERE storage_id = ? AND shared_with_user_id = ?`,
                [storageId, userId]
            );
        },

        async getPermission(userId, storageId) {
            const storage = await this.getStorageByIdForUser(userId, storageId);
            if (!storage) return null;
            if (storage.is_owner) return 'ADMIN';
            return storage.permission || null;
        },

        async createStorage({ userId, id, name, sortOrder, createdAt, updatedAt, isEncrypted, encryptionSalt, encryptionCheck }) {
            await pool.execute(
                `INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at, is_encrypted, encryption_salt, encryption_check)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, userId, name, sortOrder, createdAt, updatedAt, isEncrypted || 0, encryptionSalt || null, encryptionCheck || null]
            );
            return { id, userId, name, sortOrder, createdAt, updatedAt, isEncrypted, encryptionSalt, encryptionCheck };
        },

        async updateStorage(userId, storageId, { name, updatedAt }) {
            await pool.execute(
                `UPDATE storages SET name = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
                [name, updatedAt, storageId, userId]
            );
        },

        async deleteStorage(userId, storageId) {
            await pool.execute(
                `DELETE FROM storages WHERE id = ? AND user_id = ?`,
                [storageId, userId]
            );
        },

        async safeDeleteStoragePreservingCollaborators(ownerUserId, storageId) {
            const ownerId = Number(ownerUserId);
            const sid = String(storageId || '').trim();
            if (!Number.isFinite(ownerId) || !sid) throw new Error('Invalid args');

            const conn = await pool.getConnection();
            try {
                await conn.beginTransaction();

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

                const [pageRows] = await conn.execute(
                    `SELECT id, user_id, parent_id
                       FROM pages
                      WHERE storage_id = ?`,
                    [sid]
                );

                const byUser = new Map(); 
                for (const r of (pageRows || [])) {
                    const uid = Number(r.user_id);
                    if (!Number.isFinite(uid)) continue;
                    if (uid === ownerId) continue;
                    if (!byUser.has(uid)) byUser.set(uid, { pageIds: new Set(), rows: [] });
                    byUser.get(uid).pageIds.add(String(r.id));
                    byUser.get(uid).rows.push({ id: String(r.id), parent_id: r.parent_id ? String(r.parent_id) : null });
                }

                const transferred = {};

                if (byUser.size === 0) {
                    await conn.execute(`DELETE FROM storages WHERE id = ? AND user_id = ?`, [sid, ownerId]);
                    await conn.commit();
                    return { ok: true, transferred };
                }

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

                    const pageIdsArr = Array.from(info.pageIds);
                    await updatePagesInBatches(
                        conn,
                        `UPDATE pages SET storage_id = ?, updated_at = NOW() WHERE id IN`,
                        pageIdsArr,
                        [newStorageId]
                    );

                    transferred[String(uid)] = { newStorageId, movedPages: pageIdsArr.length };
                }

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

        async getNextSortOrder(userId) {
            const [rows] = await pool.execute(
                `SELECT COALESCE(MAX(sort_order), -1) AS maxOrder FROM storages WHERE user_id = ?`,
                [userId]
            );
            return Number(rows[0].maxOrder) + 1;
        }
    };
};
