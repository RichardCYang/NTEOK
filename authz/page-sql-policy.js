/**
 * 페이지 SQL 인증 정책 (통합된 신뢰 기원)
 *
 * 역할:
 *  - 암호화(encrypted=1) + 공유 금지(share_allowed = 0) 페이지는 오직 그 페이지의 작성자에게만 보이게 함(pages.user_id)
 *
 * SQL 프래그먼트 + 가변 인자 반환 (mysql2 호환).
 */

function assertViewerUserId(viewerUserId) {
    if (!viewerUserId)
        throw new Error("페이지 인증 정책을 위한 viewerUserId 정보 필요");
}

function denyPrivateEncryptedPredicate({ alias = "p" } = {}) {
    // index 위주로 유지: 함수 없음, 형변환 없음
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