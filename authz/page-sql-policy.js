function assertViewerUserId(viewerUserId) {
    if (!viewerUserId) throw new Error("페이지 인증 정책을 위한 viewerUserId 정보 필요");
}

function denyPrivateEncryptedPredicate({ alias = "p", storageAlias = null } = {}) {
    if (storageAlias) return `(${alias}.is_encrypted = 1 AND ${alias}.share_allowed = 0 AND ${alias}.user_id != ? AND ${storageAlias}.user_id != ?)`;
    return `(${alias}.is_encrypted = 1 AND ${alias}.share_allowed = 0 AND ${alias}.user_id != ?)`;
}

function visiblePredicate({ alias = "p", viewerUserId, storageAlias = null } = {}) {
    assertViewerUserId(viewerUserId);
    const pred = denyPrivateEncryptedPredicate({ alias, storageAlias });
    return {
        sql: `NOT ${pred}`,
        params: storageAlias ? [viewerUserId, viewerUserId] : [viewerUserId]
    };
}

function andVisible({ alias = "p", viewerUserId, storageAlias = null } = {}) {
    const pred = visiblePredicate({ alias, viewerUserId, storageAlias });
    return {
        sql: `AND ${pred.sql}`,
        params: pred.params
    };
}

module.exports = {
    denyPrivateEncryptedPredicate,
    visiblePredicate,
    andVisible
};
