
module.exports = ({
    storagesRepo,
    pagesRepo
}) => {
    if (!storagesRepo) throw new Error("storagesRepo 필요");
    if (!pagesRepo) throw new Error("pagesRepo 필요");

    return {
        async getExportRows(userId) {
            const storages = await storagesRepo.listStoragesForUser(userId);
            const pages = await pagesRepo.listPagesForBackupExport({ userId });

            const safePages = (pages || []).filter(p => {
                if (Number(p.is_encrypted) === 1 && Number(p.share_allowed) === 0) return Number(p.user_id) === Number(userId);
                return true;
            });

            return {
                storages,
                pages: safePages
            };
        },

        async listFileRefsForPageIds(pageIds) {
            return await pagesRepo.listFileRefsForPageIds(pageIds);
        }
    };
};
