/**
 * 부트스트랩 저장소 (조합자)
 * - routes/bootstrap.js 가 더 이상 pool.execute 를 직접 호출하지 않도록
 *   usersRepo / collectionsRepo / collectionSharesRepo / pagesRepo 를 조합
 */

module.exports = ({
    usersRepo,
    collectionsRepo,
    collectionSharesRepo,
    pagesRepo
}) => {
    if (!usersRepo) throw new Error("usersRepo 필요");
    if (!collectionsRepo) throw new Error("collectionsRepo 필요");
    if (!collectionSharesRepo) throw new Error("collectionSharesRepo 필요");
    if (!pagesRepo) throw new Error("pagesRepo 필요");

    return {
        async getBootstrapRows(userId) {
            const [userRow, collectionsRaw, pageRows] = await Promise.all([
                usersRepo.getBootstrapUserById(userId),
                collectionsRepo.listCollectionsForBootstrap(userId),
                pagesRepo.listPagesForUser({ userId })
            ]);

            const collectionIds = (collectionsRaw || []).map(row => row.id);
            const shareCountMap = await collectionSharesRepo.getShareCountMapForCollectionIds(collectionIds);

            return {
                userRow,
                collectionsRaw,
                pageRows,
                shareCountMap
            };
        }
    };
};