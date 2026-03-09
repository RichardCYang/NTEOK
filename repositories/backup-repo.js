
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

            const safePages = (pages || []).filter(p => {
                if (Number(p.is_encrypted) === 1 && Number(p.share_allowed) === 0) return Number(p.user_id) === Number(userId);
                return true;
            });

            const pageIds = safePages.map(p => p.id);
            const publishes = pageIds.length > 0 
                ? await pagePublishLinksRepo.listActiveLinksForPageIds(pageIds)
                : [];

            return {
                storages,
                pages: safePages,
                publishes
            };
        },

        async listFileRefsForPageIds(pageIds) {
            return await pagesRepo.listFileRefsForPageIds(pageIds);
        }
    };
};
