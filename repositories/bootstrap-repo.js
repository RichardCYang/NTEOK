/**
 * 부트스트랩 저장소 (조합자)
 * - routes/bootstrap.js 가 더 이상 pool.execute 를 직접 호출하지 않도록
 *   usersRepo / storagesRepo / pagesRepo 를 조합
 */

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