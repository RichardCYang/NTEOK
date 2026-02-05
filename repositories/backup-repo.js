/**
 * 백업 저장소 (조합자)
 * - routes/backup.js 의 /export 가 더 이상 pool.execute 를 직접 호출하지 않도록
 *   collectionsRepo / collectionSharesRepo / pagesRepo / pagePublishLinksRepo 를 조합
 */

module.exports = ({
    collectionsRepo,
    collectionSharesRepo,
    pagesRepo,
    pagePublishLinksRepo
}) => {
    if (!collectionsRepo) throw new Error("collectionsRepo 필요");
    if (!collectionSharesRepo) throw new Error("collectionSharesRepo 필요");
    if (!pagesRepo) throw new Error("pagesRepo 필요");
    if (!pagePublishLinksRepo) throw new Error("pagePublishLinksRepo 필요");

    return {
        async getExportRows(userId) {
            // 내 컬렉션
            const collections = await collectionsRepo.listCollectionsOwnedByUser(userId);
            if (!collections || collections.length === 0) {
                return {
                    collections: [],
                    shares: [],
                    pages: [],
                    publishes: []
                };
            }

            const collectionIds = collections.map(c => c.id);

            // 공유 정보 + 페이지(암호화 필드 포함)
            const [shares, pages] = await Promise.all([
                collectionSharesRepo.listSharesForCollectionIds(collectionIds),
                pagesRepo.listPagesForBackupExport({ userId })
            ]);

            // 발행 링크
            const pageIds = (pages || []).map(p => p.id);
            const publishes = await pagePublishLinksRepo.listActiveLinksForPageIds(pageIds);

            return {
                collections,
                shares,
                pages,
                publishes
            };
        }
    };
};