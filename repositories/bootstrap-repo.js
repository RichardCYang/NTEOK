
module.exports = ({
    usersRepo,
    storagesRepo,
    pagesRepo
}) => {
    if (!usersRepo) throw new Error("usersRepo 필요");
    if (!storagesRepo) throw new Error("storagesRepo 필요");
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
            const pageRows = await pagesRepo.listPagesForUser({ userId, storageId });

            return {
                pageRows
            };
        }
    };
};