/**
 * 저장소 생성자
 * - 공유 의존성 기반으로 저장소 생성
 */

module.exports = ({ pool, pageSqlPolicy }) => {
    if (!pool) throw new Error("pool 필요");
    if (!pageSqlPolicy) throw new Error("pageSqlPolicy 필요");

    const usersRepo = require('./users-repo')({ pool });
    const storagesRepo = require('./storages-repo')({ pool });
    const collectionsRepo = require('./collections-repo')({ pool });
    const collectionSharesRepo = require('./collection-shares-repo')({ pool });
    const pagePublishLinksRepo = require('./page-publish-links-repo')({ pool });
    const pagesRepo = require('./pages-repo')({ pool, pageSqlPolicy });

    // 조합자
    const bootstrapRepo = require('./bootstrap-repo')({
        usersRepo,
        storagesRepo,
        collectionsRepo,
        collectionSharesRepo,
        pagesRepo
    });

    const backupRepo = require('./backup-repo')({
        collectionsRepo,
        collectionSharesRepo,
        pagesRepo,
        pagePublishLinksRepo
    });

    return {
        usersRepo,
        storagesRepo,
        collectionsRepo,
        collectionSharesRepo,
        pagePublishLinksRepo,
        pagesRepo,
        bootstrapRepo,
        backupRepo
    };
};
