/**
 * UI 유틸리티 함수들
 */

/**
 * 보안 개선: CSRF 토큰이 포함된 fetch 래퍼 함수
 * POST, PUT, DELETE 요청에 자동으로 CSRF 토큰 헤더 추가
 */
export function secureFetch(url, options = {}) {
	// URL 정규화 (상대경로/절대경로 모두 처리)
    let targetUrl;
    try {
        targetUrl = new URL(url, window.location.href);
    } catch (e) {
        // URL 파싱 실패는 보수적으로 차단
        throw new Error('[보안]: Invalid URL');
    }

    // same-origin 여부 판단
    const isSameOrigin = (targetUrl.origin === window.location.origin);

    // 기본 credentials 정책을 안전하게 설정
    //  - same-origin 요청은 쿠키 포함 가능
    //  - cross-origin 요청은 기본적으로 쿠키 포함 금지
    const finalOptions = { ...options };
    if (!finalOptions.credentials)
        finalOptions.credentials = isSameOrigin ? 'same-origin' : 'omit';

    // CSRF 헤더는 same-origin + state-changing 요청에만 부착
    const method = (finalOptions.method || 'GET').toUpperCase();
    const isStateChanging = !['GET', 'HEAD', 'OPTIONS'].includes(method);

    if (isSameOrigin && isStateChanging) {
        finalOptions.headers = finalOptions.headers || {};
        // csrfUtils가 headers를 덮어쓸 수 있으므로 여기서 합쳐도 되고,
        // 기존 구현 유지하려면 csrfUtils.addCsrfHeader를 사용해도 됨.
        finalOptions.headers = window.csrfUtils.addCsrfHeader({
            headers: finalOptions.headers
        }).headers;
    }

    return fetch(targetUrl.toString(), finalOptions);
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
 * XSS 방지: HTML 속성(attribute) 컨텍스트 이스케이프
 * - escapeHtml()은 텍스트 노드엔 안전하지만, attribute의 따옴표(")/' 는 별도로 이스케이프가 필요함
 * - 예: src="${userInput}" 같은 템플릿 문자열에 사용
 */
export function escapeHtmlAttr(text) {
    if (text === undefined || text === null) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

/**
 * XSS 방지용 버튼 아이콘 추가 함수
 */
export function addIcon(button, icon) {
	// 보안: innerHTML 대신 DOM API 사용 (DOM XSS 방지)
	button.textContent = "";
	const iEl = document.createElement("i");
	// icon은 서버에서 정규화되더라도 프런트에서 한 번 더 방어
	// (허용 문자 외 제거: 공백, 하이픈, 언더스코어 정도만 허용)
	const safeIcon = String(icon || "").replace(/[^a-zA-Z0-9 _-]/g, "").trim();
	iEl.className = safeIcon;
	button.appendChild(iEl);
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
        // 메뉴가 닫힐 때 트리거 ID 초기화 (다시 열 때 토글 로직을 위해)
        delete contextMenu.dataset.triggerId;
    }
}

export function syncPageUpdatedAtPadding() {
    const editorEl = document.querySelector(".editor");
    if (!editorEl) return;

    const editorStyle = window.getComputedStyle(editorEl);
    const proseEl = editorEl.querySelector(".ProseMirror");
    const proseStyle = proseEl ? window.getComputedStyle(proseEl) : null;

    const editorLeft = parseFloat(editorStyle.paddingLeft) || 0;
    const editorRight = parseFloat(editorStyle.paddingRight) || 0;
    const proseLeft = proseStyle ? parseFloat(proseStyle.paddingLeft) || 0 : 0;
    const proseRight = proseStyle ? parseFloat(proseStyle.paddingRight) || 0 : 0;

    const totalLeft = editorLeft + proseLeft;
    const totalRight = editorRight + proseRight;

    // Update Updated At Container
    const updatedAtContainer = document.querySelector("#page-updated-at-container");
    if (updatedAtContainer) {
        updatedAtContainer.style.paddingLeft = `${totalLeft}px`;
        updatedAtContainer.style.paddingRight = `${totalRight}px`;
    }

    // Update Comments Section
    const commentsContainer = document.querySelector("#page-comments-section");
    if (commentsContainer) {
        commentsContainer.style.paddingLeft = `${totalLeft}px`;
        commentsContainer.style.paddingRight = `${totalRight}px`;
    }
}

/**
 * 로딩 오버레이 표시
 */
export function showLoadingOverlay() {
    const overlay = document.querySelector('.loading-overlay');
    if (overlay) {
        overlay.classList.remove('hidden');
    }
}

/**
 * 로딩 오버레이 숨기기
 */
export function hideLoadingOverlay() {
    const overlay = document.querySelector('.loading-overlay');
    if (overlay) {
        overlay.classList.add('hidden');
    }
}

/**
 * 사이드바 열기
 */
export function openSidebar() {
    const sidebar = document.querySelector(".sidebar");
    const overlay = document.querySelector("#sidebar-overlay");

    if (sidebar) {
        sidebar.classList.add("open");
    }
    if (overlay) {
        overlay.classList.add("visible");
    }
}

/**
 * 사이드바 닫기
 */
export function closeSidebar() {
    const sidebar = document.querySelector(".sidebar");
    const overlay = document.querySelector("#sidebar-overlay");

    if (sidebar) {
        sidebar.classList.remove("open");
    }
    if (overlay) {
        overlay.classList.remove("visible");
    }
}

/**
 * 모달 표시/숨기기 토글
 * @param {string|HTMLElement} modal - 모달 셀렉터 또는 엘리먼트
 * @param {boolean} show - 표시 여부
 */
export function toggleModal(modal, show) {
    const modalEl = typeof modal === 'string' ? document.querySelector(modal) : modal;
    if (!modalEl) return;

    if (show) {
        modalEl.classList.remove('hidden');
    } else {
        modalEl.classList.add('hidden');
    }
}

/**
 * 모달 외부 클릭 시 닫기 이벤트 바인딩
 * @param {HTMLElement} modalEl - 모달 엘리먼트
 * @param {Function} closeFn - 닫기 함수
 */
export function bindModalOverlayClick(modalEl, closeFn) {
    if (!modalEl || !closeFn) return;
    const overlay = modalEl.querySelector('.modal-overlay');
    if (overlay) {
        overlay.addEventListener('click', closeFn);
    }
}
