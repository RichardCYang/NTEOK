const express = require('express');
const router = express.Router();


module.exports = (dependencies) => {
	const { bootstrapRepo, authMiddleware, toIsoString, logError } = dependencies;

    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;

            const { userRow, storageRows } = await bootstrapRepo.getBootstrapRows(userId);

            const user = userRow
                ? {
			        id: userRow.id,
			        username: userRow.username,
			        theme: userRow.theme || 'default',
                    stickyHeader: userRow.sticky_header === 1
                }
                : null;

            const storages = (storageRows || []).map((row) => ({
                id: row.id,
                name: row.name,
                sortOrder: row.sort_order,
                createdAt: toIsoString(row.created_at),
                updatedAt: toIsoString(row.updated_at),
                is_owner: row.is_owner,
                permission: row.permission,
                owner_name: row.owner_name,
                is_encrypted: row.is_encrypted,
                dek_version: row.dek_version
            }));

            res.json({ user, storages });
        } catch (error) {
            logError("GET /api/bootstrap", error);
            res.status(500).json({ error: "초기 데이터 로드에 실패했습니다." });
        }
    });

    return router;
};
