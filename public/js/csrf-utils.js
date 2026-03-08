
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null;
}

function getCsrfToken() {
    return getCookie('__Host-nteok_csrf') || getCookie('nteok_csrf') || getCookie('__Host-nteok_preauth_csrf') || getCookie('nteok_preauth_csrf');
}

function addCsrfHeader(options = {}) {
    const token = getCsrfToken();
    if (token) {
        options.headers = options.headers || {};
        options.headers['X-CSRF-Token'] = token;
    }
    return options;
}

if (typeof window !== 'undefined') {
    window.csrfUtils = {
        getCookie,
        getCsrfToken,
        addCsrfHeader
    };
}
