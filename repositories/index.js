
module.exports = ({ pool, pageSqlPolicy }) => {
    if (!pool) throw new Error("pool 필요");
    if (!pageSqlPolicy) throw new Error("pageSqlPolicy 필요");

    const usersRepo = require('./users-repo')({ pool });
    const storagesRepo = require('./storages-repo')({ pool });
    const pagePublishLinksRepo = require('./page-publish-links-repo')({ pool });
    const pagesRepo = require('./pages-repo')({ pool, pageSqlPolicy });
    const userKeysRepo = require('./user-keys-repo')({ pool });
    const storageShareKeysRepo = require('./storage-share-keys-repo')({ pool });

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
        userKeysRepo,
        storageShareKeysRepo,
        bootstrapRepo,
        backupRepo
    };
};
