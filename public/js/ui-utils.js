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
    document.querySelectorAll(".dropdown-menu").forEach(menu => {
        menu.classList.add("hidden");
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
    menu.classList.remove("hidden");
    const dropdown = trigger ? trigger.closest("[data-dropdown]") : null;
    if (dropdown) {
        dropdown.classList.add("open");
    }
}

/**
 * Context Menu 표시
 */
export function showContextMenu(triggerBtn, menuItems) {
    const contextMenu = document.querySelector("#context-menu");
    const contextMenuContent = document.querySelector("#context-menu-content");

    if (!contextMenu || !contextMenuContent) return;

    // 메뉴 내용 설정
    contextMenuContent.innerHTML = menuItems;

    // 버튼 위치 계산
    const rect = triggerBtn.getBoundingClientRect();

    // 일단 표시하여 크기 계산
    contextMenu.style.left = '0px';
    contextMenu.style.top = '0px';
    contextMenu.classList.remove("hidden");

    const menuRect = contextMenu.getBoundingClientRect();

    // 오른쪽에 공간이 있으면 오른쪽에, 없으면 왼쪽에 표시
    let left = rect.right + 6;
    let top = rect.top;

    // 화면 오른쪽을 벗어나는 경우
    if (left + menuRect.width > window.innerWidth) {
        left = rect.left - menuRect.width - 6;
    }

    // 화면 아래를 벗어나는 경우
    if (top + menuRect.height > window.innerHeight) {
        top = window.innerHeight - menuRect.height - 10;
    }

    // 화면 위를 벗어나는 경우
    if (top < 10) {
        top = 10;
    }

    contextMenu.style.left = `${left}px`;
    contextMenu.style.top = `${top}px`;
}

/**
 * Context Menu 닫기
 */
export function closeContextMenu() {
    const contextMenu = document.querySelector("#context-menu");
    if (contextMenu) {
        contextMenu.classList.add("hidden");
    }
}
