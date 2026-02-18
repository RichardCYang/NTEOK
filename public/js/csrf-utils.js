/**
 * CSRF 토큰 유틸리티
 */

/**
 * 쿠키에서 값 읽기
 */
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null;
}

/**
 * CSRF 토큰을 쿠키에서 읽기
 */
function getCsrfToken() {
    // 보안: __Host- prefix가 붙은 쿠키를 먼저 확인
    return getCookie('__Host-nteok_csrf') || getCookie('nteok_csrf');
}

/**
 * fetch 옵션에 CSRF 토큰 헤더 추가
 */
function addCsrfHeader(options = {}) {
    const token = getCsrfToken();
    if (token) {
        options.headers = options.headers || {};
        options.headers['X-CSRF-Token'] = token;
    }
    return options;
}

// 전역으로 export
if (typeof window !== 'undefined') {
    window.csrfUtils = {
        getCookie,
        getCsrfToken,
        addCsrfHeader
    };
}
