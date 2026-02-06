const express = require('express');
const router = express.Router();

/**
 * Bootstrap Routes
 *
 * - 초기 로딩에 필요한 사용자/컬렉션/페이지 데이터를 한번에 제공
 */

module.exports = (dependencies) => {
	const { bootstrapRepo, authMiddleware, toIsoString, logError } = dependencies;

    /**
     * 부트스트랩 데이터
     * GET /api/bootstrap
     */
    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;

            // DB 접근은 repo에서만 수행 (접근제어 SQL 정책 중앙화 포함)
            const { userRow, collectionsRaw, pageRows, shareCountMap } = await bootstrapRepo.getBootstrapRows(userId);

            const user = userRow
                ? {
			        id: userRow.id,
			        username: userRow.username,
			        theme: userRow.theme || 'default',
                    stickyHeader: userRow.sticky_header === 1
                }
                : null;

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

            const pages = (pageRows || []).map((row) => ({
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
