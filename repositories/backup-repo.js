/**
 * 백업 저장소 (조합자)
 * - 컬렉션 제거 및 저장소/페이지 구조로 업데이트
 */

module.exports = ({
    storagesRepo,
    pagesRepo,
    pagePublishLinksRepo
}) => {
    if (!storagesRepo) throw new Error("storagesRepo 필요");
    if (!pagesRepo) throw new Error("pagesRepo 필요");
    if (!pagePublishLinksRepo) throw new Error("pagePublishLinksRepo 필요");

    return {
        async getExportRows(userId) {
            // 내 저장소
            const storages = await storagesRepo.listStoragesForUser(userId);
            
            // 페이지(암호화 필드 포함)
            const pages = await pagesRepo.listPagesForBackupExport({ userId });

            // 발행 링크
            const pageIds = (pages || []).map(p => p.id);
            const publishes = pageIds.length > 0 
                ? await pagePublishLinksRepo.listActiveLinksForPageIds(pageIds)
                : [];

            return {
                storages,
                pages,
                publishes
            };
        }
    };
};
