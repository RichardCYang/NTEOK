/**
 * 저장소 생성자
 * - 공유 의존성 기반으로 저장소 생성
 */

module.exports = ({ pool, pageSqlPolicy }) => {
    if (!pool) throw new Error("pool 필요");
    if (!pageSqlPolicy) throw new Error("pageSqlPolicy 필요");

    const usersRepo = require('./users-repo')({ pool });
    const storagesRepo = require('./storages-repo')({ pool });
    const pagePublishLinksRepo = require('./page-publish-links-repo')({ pool });
    const pagesRepo = require('./pages-repo')({ pool, pageSqlPolicy });

    // 조합자
    const bootstrapRepo = require('./bootstrap-repo')({
        usersRepo,
        storagesRepo,
        pagesRepo
    });

    const backupRepo = require('./backup-repo')({
        storagesRepo,
        pagesRepo,
        pagePublishLinksRepo
    });

    return {
        usersRepo,
        storagesRepo,
        pagePublishLinksRepo,
        pagesRepo,
        bootstrapRepo,
        backupRepo
    };
};
