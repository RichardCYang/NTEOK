module.exports = ({ pool, storagesRepo }) => {
    async function resolvePageAccess({ viewerUserId, pageId, includeDeleted = false }) {
        const deletedSql = includeDeleted ? '' : 'AND p.deleted_at IS NULL';
        const [rows] = await pool.execute(
            `SELECT p.*, s.is_encrypted AS storage_is_encrypted,
                    s.user_id AS storage_owner_id
               FROM pages p
               JOIN storages s ON p.storage_id = s.id
               LEFT JOIN storage_shares ss
                 ON s.id = ss.storage_id
                AND ss.shared_with_user_id = ?
              WHERE p.id = ?
                ${deletedSql}
                AND (s.user_id = ? OR ss.shared_with_user_id IS NOT NULL)
                AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
              LIMIT 1`,
            [viewerUserId, pageId, viewerUserId, viewerUserId]
        );

        if (!rows.length) return null;
        const page = rows[0];
        const permission = await storagesRepo.getPermission(viewerUserId, page.storage_id);
        if (!permission) return null;

        return {
            page,
            permission,
            isPageOwner: Number(page.user_id) === Number(viewerUserId),
            canWrite: ['EDIT', 'ADMIN'].includes(permission)
        };
    }

    return { resolvePageAccess };
};
