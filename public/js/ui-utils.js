/**
 * UI 유틸리티 함수들
 */

/**
 * 보안 개선: CSRF 토큰이 포함된 fetch 래퍼 함수
 * POST, PUT, DELETE 요청에 자동으로 CSRF 토큰 헤더 추가
 */
export function secureFetch(url, options = {}) {
    // GET 요청이 아닌 경우 CSRF 토큰 추가
    if (!options.method || options.method.toUpperCase() !== 'GET') {
        options = window.csrfUtils.addCsrfHeader(options);
    }
    return fetch(url, options);
}

/**
 * XSS 방지: HTML 이스케이프 처리
 * 사용자 입력값을 안전하게 HTML에 삽입하기 위해 사용
 */
export function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * 에디터에 에러 메시지 표시
 */
export function showErrorInEditor(message, editor) {
    const escapedMessage = escapeHtml(message);

    if (editor) {
        editor.commands.setContent(`<p style="color: red;">${escapedMessage}</p>`, { emitUpdate: false });
    } else {
        const el = document.querySelector("#editor");
        if (el) {
            el.innerHTML = `<p style="color: red;">${escapedMessage}</p>`;
        }
    }
}

/**
 * 모든 드롭다운 메뉴 닫기
 */
export function closeAllDropdowns() {
    document.querySelectorAll("[data-dropdown-menu]").forEach(menu => {
        menu.setAttribute("hidden", "");
        const dropdown = menu.closest("[data-dropdown]");
        if (dropdown) {
            dropdown.classList.remove("open");
        }
    });
}

/**
 * 드롭다운 메뉴 열기
 */
export function openDropdown(menu, trigger) {
    menu.removeAttribute("hidden");
    const dropdown = trigger.closest("[data-dropdown]");
    if (dropdown) {
        dropdown.classList.add("open");
    }
}
