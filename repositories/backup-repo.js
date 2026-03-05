
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
            const storages = await storagesRepo.listStoragesForUser(userId);
            
            const pages = await pagesRepo.listPagesForBackupExport({ userId });

            const pageIds = (pages || []).map(p => p.id);
            const publishes = pageIds.length > 0 
                ? await pagePublishLinksRepo.listActiveLinksForPageIds(pageIds)
                : [];

            return {
                storages,
                pages,
                publishes
            };
        },

        async listFileRefsForPageIds(pageIds) {
            return await pagesRepo.listFileRefsForPageIds(pageIds);
        }
    };
};
