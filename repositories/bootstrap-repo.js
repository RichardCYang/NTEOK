/**
 * 부트스트랩 저장소 (조합자)
 * - routes/bootstrap.js 가 더 이상 pool.execute 를 직접 호출하지 않도록
 *   usersRepo / collectionsRepo / collectionSharesRepo / pagesRepo 를 조합
 */

module.exports = ({
    usersRepo,
    storagesRepo,
    collectionsRepo,
    collectionSharesRepo,
    pagesRepo
}) => {
    if (!usersRepo) throw new Error("usersRepo 필요");
    if (!storagesRepo) throw new Error("storagesRepo 필요");
    if (!collectionsRepo) throw new Error("collectionsRepo 필요");
    if (!collectionSharesRepo) throw new Error("collectionSharesRepo 필요");
    if (!pagesRepo) throw new Error("pagesRepo 필요");

    return {
        async getBootstrapRows(userId) {
            const [userRow, storageRows] = await Promise.all([
                usersRepo.getBootstrapUserById(userId),
                storagesRepo.listStoragesForUser(userId)
            ]);

            return {
                userRow,
                storageRows
            };
        },

        async getStorageData(userId, storageId) {
            const [collectionsRaw, pageRows] = await Promise.all([
                collectionsRepo.listCollectionsForStorage(userId, storageId),
                pagesRepo.listPagesForUser({ userId, storageId })
            ]);

            const collectionIds = (collectionsRaw || []).map(row => row.id);
            const shareCountMap = await collectionSharesRepo.getShareCountMapForCollectionIds(collectionIds);

            return {
                collectionsRaw,
                pageRows,
                shareCountMap
            };
        }
    };
};