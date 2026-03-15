
module.exports = ({ pool, pageSqlPolicy }) => {
    if (!pool) throw new Error("pool 필요");
    if (!pageSqlPolicy) throw new Error("pageSqlPolicy 필요");

    const SUBTREE_BATCH_SIZE = (() => {
        const n = Number.parseInt(process.env.PAGE_SUBTREE_BATCH_SIZE || "500", 10);
        if (!Number.isFinite(n)) return 500;
        return Math.max(50, Math.min(2000, n));
    })();

    function chunkArray(arr, size) {
        const out = [];
        for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
        return out;
    }

    function buildChildrenIndex(rows) {
        const map = new Map();
        for (const r of rows) {
            const p = r.parent_id || null;
            if (!map.has(p)) map.set(p, []);
            map.get(p).push(r);
        }
        return map;
    }

    function collectSubtreeIds(rows, rootId) {
        const byParent = buildChildrenIndex(rows);
        const seen = new Set();
        const order = [];
        const stack = [rootId];
        while (stack.length) {
            const id = stack.pop();
            if (seen.has(id)) continue;
            seen.add(id);
            order.push(id);
            const children = byParent.get(id) || [];
            for (const c of children) stack.push(c.id);
        }
        return order;
    }

    function splitIdsByPermission(rowsById, ids, actorUserId) {
        const allowed = [];
        const disallowed = [];
        for (const id of ids) {
            const row = rowsById.get(id);
            if (!row) continue;
            if (Number(row.user_id) === Number(actorUserId)) allowed.push(id);
            else disallowed.push(id);
        }
        return { allowed, disallowed };
    }

    async function updateByIdInBatches(sqlPrefixWhereIdIn, ids, paramsBeforeIds = []) {
        if (!Array.isArray(ids) || ids.length === 0) return;
        for (const chunk of chunkArray(ids, SUBTREE_BATCH_SIZE)) {
            const placeholders = chunk.map(() => '?').join(',');
            const sql = `${sqlPrefixWhereIdIn} (${placeholders})`;
            await pool.execute(sql, [...paramsBeforeIds, ...chunk]);
        }
    }

    async function deleteByIdInBatches(sqlPrefixWhereIdIn, ids, paramsBeforeIds = []) {
        if (!Array.isArray(ids) || ids.length === 0) return;
        for (const chunk of chunkArray(ids, SUBTREE_BATCH_SIZE)) {
            const placeholders = chunk.map(() => '?').join(',');
            const sql = `${sqlPrefixWhereIdIn} (${placeholders})`;
            await pool.execute(sql, [...paramsBeforeIds, ...chunk]);
        }
    }

    return {
        async listPagesForUser({ userId, storageId = null }) {
            if (!storageId) return [];
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const query = `
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.storage_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    INNER JOIN storages s ON p.storage_id = s.id
                    WHERE s.user_id = ?
                    AND p.storage_id = ?
                    AND p.deleted_at IS NULL
                    ${vis.sql}
                )
                UNION ALL
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.storage_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    INNER JOIN storage_shares ss ON p.storage_id = ss.storage_id
                    INNER JOIN storages s ON p.storage_id = s.id
                    WHERE ss.shared_with_user_id = ?
                    AND p.storage_id = ?
                    AND s.user_id != ?
                    AND p.deleted_at IS NULL
                    ${vis.sql}
                )
                ORDER BY parent_id IS NULL DESC, sort_order ASC, updated_at DESC
            `;
            const params = [
                userId, storageId, ...vis.params,
                userId, storageId, userId, ...vis.params
            ];
            const [rows] = await pool.execute(query, params);
            return rows || [];
        },

        async getPageByIdForUser({ userId, pageId, includeDeleted = false }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            let sql = `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.storage_id,
                        p.is_encrypted, p.share_allowed, p.user_id, p.icon, p.cover_image, p.cover_position,
                        p.horizontal_padding, p.deleted_at,
                        s.user_id AS storage_owner_id
                 FROM pages p
                 INNER JOIN storages s ON p.storage_id = s.id
                 LEFT JOIN storage_shares ss ON p.storage_id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE p.id = ? AND (ss.storage_id IS NOT NULL OR s.user_id = ?)
                 ${vis.sql}`;

            if (!includeDeleted) sql += ` AND p.deleted_at IS NULL`;

            const [rows] = await pool.execute(sql, [userId, pageId, userId, ...vis.params]);

            return rows?.[0] || null;
        },

        async listTrashedPagesForUser({ userId, storageId }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.updated_at, p.deleted_at, p.storage_id, p.user_id
                 FROM pages p
                 INNER JOIN storages s ON p.storage_id = s.id
                 LEFT JOIN storage_shares ss ON p.storage_id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE (ss.storage_id IS NOT NULL OR s.user_id = ?)
                 AND p.storage_id = ?
                 AND p.deleted_at IS NOT NULL
                 ${vis.sql}
                 ORDER BY p.deleted_at DESC`,
                [userId, userId, storageId, ...vis.params]
            );
            return rows || [];
        },

        async restorePage(pageId, userId) {
            const [rows] = await pool.execute(
                `SELECT id, user_id FROM pages WHERE id = ?`,
                [pageId]
            );
            if (!rows.length) return false;
            if (Number(rows[0].user_id) !== Number(userId)) return false;

            await pool.execute(
                `UPDATE pages SET deleted_at = NULL WHERE id = ? AND user_id = ?`,
                [pageId, userId]
            );
            return true;
        },

        async restorePageAndDescendants({ rootPageId, storageId, actorUserId }) {
            if (!rootPageId || !storageId) return;

            const [allPages] = await pool.execute(
                `SELECT id, parent_id, user_id FROM pages WHERE storage_id = ?`,
                [storageId]
            );

            const rowsById = new Map((allPages || []).map(r => [r.id, r]));
            if (!rowsById.has(rootPageId)) return;

            const subtreeIds = collectSubtreeIds(allPages || [], rootPageId);
            const { allowed: restorableIds } = splitIdsByPermission(rowsById, subtreeIds, actorUserId);

            if (!restorableIds || restorableIds.length === 0) return;

            await updateByIdInBatches(
                `UPDATE pages SET deleted_at = NULL WHERE id IN`,
                restorableIds
            );
        },

        async permanentlyDeletePageAndDescendants({ pageId, userId }) {
            const [rootRows] = await pool.execute('SELECT storage_id, user_id FROM pages WHERE id = ?', [pageId]);
            if (!rootRows.length) return;
            const storageId = rootRows[0].storage_id;

            const [allPages] = await pool.execute(
                `SELECT id, parent_id, user_id FROM pages WHERE storage_id = ?`,
                [storageId]
            );

            const subtreeIds = collectSubtreeIds(allPages || [], pageId);
            const rowsById = new Map((allPages || []).map(r => [r.id, r]));

            const { allowed: deletableIds, disallowed: keptIds } = splitIdsByPermission(rowsById, subtreeIds, userId);
            if (!deletableIds || deletableIds.length === 0) return;

            if (keptIds.length > 0) {
                const deletableSet = new Set(deletableIds);
                const keptRootIds = [];
                for (const id of keptIds) {
                    const row = rowsById.get(id);
                    if (!row) continue;
                    if (row.parent_id && deletableSet.has(row.parent_id)) keptRootIds.push(row.id);
                }
                if (keptRootIds.length > 0) {
                    await updateByIdInBatches(
                        `UPDATE pages SET parent_id = NULL, updated_at = NOW() WHERE id IN`,
                        keptRootIds
                    );
                }
            }

            await deleteByIdInBatches(
                `DELETE FROM pages WHERE id IN`,
                deletableIds
            );
        },

        async softDeletePageAndDescendants({ rootPageId, storageId, rootParentId = null, actorUserId }) {
            if (!rootPageId || !storageId) return;

            const [allPages] = await pool.execute(
                `SELECT id, parent_id, user_id FROM pages WHERE storage_id = ?`,
                [storageId]
            );

            const rowsById = new Map((allPages || []).map(r => [r.id, r]));
            if (!rowsById.has(rootPageId)) return;

            const subtreeIds = collectSubtreeIds(allPages || [], rootPageId);

            const { allowed: deletableIds, disallowed: keptIds } =
                splitIdsByPermission(rowsById, subtreeIds, actorUserId);

            if (keptIds && keptIds.length > 0) {
                const deletableSet = new Set(deletableIds || []);

                const safeParentId = (rootParentId && !deletableSet.has(rootParentId)) ? rootParentId : null;

                const keptRootIds = [];
                for (const id of keptIds) {
                    const row = rowsById.get(id);
                    if (!row) continue;
                    if (row.parent_id && deletableSet.has(row.parent_id)) keptRootIds.push(id);
                }

                if (keptRootIds.length > 0) {
                    await updateByIdInBatches(
                        `UPDATE pages SET parent_id = ?, updated_at = NOW() WHERE id IN`,
                        keptRootIds,
                        [safeParentId]
                    );
                }
            }

            if (!deletableIds || deletableIds.length === 0) return { deletedPageIds: [], keptPageIds: keptIds || [] };

            await updateByIdInBatches(
                `UPDATE pages SET deleted_at = NOW() WHERE id IN`,
                deletableIds
            );

            return { deletedPageIds: deletableIds, keptPageIds: keptIds || [] };
        },

        async listPagesForBackupExport({ userId }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.e2ee_yjs_state, p.e2ee_yjs_state_updated_at,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.storage_id,
                        p.is_encrypted, p.share_allowed, p.icon, p.cover_image, p.cover_position
                 FROM pages p
                 INNER JOIN storages s ON p.storage_id = s.id
                 WHERE s.user_id = ?
                 AND p.deleted_at IS NULL
                 ${vis.sql}
                 ORDER BY p.storage_id ASC, p.parent_id IS NULL DESC, p.sort_order ASC`,
                [userId, ...vis.params]
            );
            return rows || [];
        },

        async listFileRefsForPageIds(pageIds) {
            if (!Array.isArray(pageIds) || pageIds.length === 0) return [];
            const placeholders = pageIds.map(() => '?').join(',');
            const [rows] = await pool.execute(
                `SELECT page_id, owner_user_id, stored_filename, file_type, created_at
                 FROM page_file_refs
                 WHERE page_id IN (${placeholders})`,
                pageIds
            );
            return rows || [];
        },

        async recordUpdateHistory({ userId, storageId, pageId, action, details }) {
            const detailsStr = details ? JSON.stringify(details) : null;
            await pool.execute(
                `INSERT INTO updates_history (user_id, storage_id, page_id, action, details, created_at)
                 VALUES (?, ?, ?, ?, ?, NOW())`,
                [userId, storageId, pageId, action, detailsStr]
            );
        },

        async getUpdateHistory({ userId, storageId, limit = 50 }) {
            const vis = pageSqlPolicy.visiblePredicate({ alias: "p", viewerUserId: userId });

            const [rows] = await pool.execute(
                `SELECT h.*, u.username, p.title as page_title
                 FROM updates_history h
                 INNER JOIN users u ON h.user_id = u.id
                 INNER JOIN storages s ON h.storage_id = s.id
                 LEFT JOIN pages p ON h.page_id = p.id
                 LEFT JOIN storage_shares ss ON h.storage_id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE h.storage_id = ? AND (s.user_id = ? OR ss.storage_id IS NOT NULL)
                   AND (
                        h.page_id IS NULL
                        OR (
                            p.id IS NOT NULL
                            AND ${vis.sql}
                        )
                   )
                 ORDER BY h.created_at DESC
                 LIMIT ?`,
                [
                    userId,          
                    storageId,       
                    userId,          
                    ...vis.params,   
                    limit
                ]
            );
            return rows || [];
        }
    };
};