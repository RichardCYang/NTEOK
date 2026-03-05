
function assertViewerUserId(viewerUserId) {
    if (!viewerUserId)
        throw new Error("페이지 인증 정책을 위한 viewerUserId 정보 필요");
}

function denyPrivateEncryptedPredicate({ alias = "p" } = {}) {
    return `(${alias}.is_encrypted = 1 AND ${alias}.share_allowed = 0 AND ${alias}.user_id != ?)`;
}

function visiblePredicate({ alias = "p", viewerUserId } = {}) {
    assertViewerUserId(viewerUserId);
    return {
        sql: `NOT ${denyPrivateEncryptedPredicate({ alias })}`,
        params: [viewerUserId]
    };
}

function andVisible({ alias = "p", viewerUserId } = {}) {
    const pred = visiblePredicate({ alias, viewerUserId });
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