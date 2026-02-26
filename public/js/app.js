/**
 * NTEOK 메인 애플리케이션
 * 컬렉션 제거 및 계층식 페이지 전용 버전
 */

// ==================== Imports ====================
import {
    secureFetch,
    escapeHtml,
    escapeHtmlAttr,
    showErrorInEditor,
    closeAllDropdowns,
    openDropdown,
    showContextMenu,
    closeContextMenu,
    addIcon,
    showLoadingOverlay,
    hideLoadingOverlay,
    openSidebar,
    closeSidebar,
    toggleModal,
    bindModalOverlayClick
} from './ui-utils.js';
import * as api from './api-utils.js';
import { sanitizeEditorHtml, htmlToPlainText } from './sanitize.js';
import { initEditor, bindToolbar, bindSlashKeyHandlers, updateToolbarState } from './editor.js';
import {
    initPagesManager,
    applyPagesData,
    fetchPageList,
    renderPageList,
    loadPage,
    clearCurrentPage,
    saveCurrentPage,
    toggleEditMode,
    bindModeToggle,
    bindNewPageButton
} from './pages-manager.js';
import {
    initEncryptionManager,
    showEncryptionModal,
    closeEncryptionModal,
    showDecryptionModal,
    closeDecryptionModal,
    bindEncryptionModal,
    bindDecryptionModal
} from './encryption-manager.js';
import {
    initSettingsManager,
    openSettingsModal,
    closeSettingsModal,
    saveSettings,
    loadSettings,
    bindSettingsModal,
    fetchAndDisplayCurrentUser,
    applyCurrentUser
} from './settings-manager.js';
import {
    updateTotpStatus,
    openTotpSetupModal,
    closeTotpSetupModal,
    bindTotpModals
} from './totp-manager.js';
import {
    updatePasskeyStatus,
    bindPasskeyModals
} from './passkey-manager.js';
import {
    bindAccountManagementButtons
} from './account-manager.js';
import {
    initSyncManager,
    startPageSync,
    stopPageSync,
    startStorageSync,
    stopStorageSync
} from './sync-manager.js';
import {
    initCoverManager,
    showCover,
    hideCover,
    updateCoverButtonsVisibility
} from './cover-manager.js';
import {
    initPublishManager,
    bindPublishEvents,
    checkPublishStatus,
    updatePublishButton
} from './publish-manager.js';
import {
    bindLoginLogsModal
} from './login-logs-manager.js';
import {
    initUpdatesManager
} from './updates-manager.js';
import {
    initTrashManager
} from './trash-manager.js';
import {
    initIconPicker,
    showIconPickerModal
} from './icon-manager.js';
import {
    exportPageToPDF
} from './pdf-export.js';
import {
    initSubpagesManager,
    loadAndRenderSubpages,
    handleSubpageMetadataChange,
    onEditModeChange,
    syncSubpagesPadding
} from './subpages-manager.js';
import {
    initCommentsManager,
    loadAndRenderComments
} from './comments-manager.js';
import {
    initStoragesManager
} from './storages-manager.js';

// ==================== Global State ====================
const appState = {
    editor: null,
    storages: [],
    currentStorageId: null,
    pages: [],
    currentPageId: null,
    expandedPages: new Set(),
    isWriteMode: false,
    currentPageIsEncrypted: false,
    currentUser: null,
    userSettings: {
        defaultMode: 'read',
        theme: 'default',
        language: 'ko-KR'
    },
    currentEncryptingPageId: null,
    currentDecryptingPage: null,
    fetchPageList: null
};

// 전역 변수
let colorDropdownElement = null;
let colorMenuElement = null;
let fontDropdownElement = null;
let fontMenuElement = null;

// ==================== Helper Functions ====================

/**
 * 페이지 리스트 클릭 핸들러
 */
async function handlePageListClick(event, state) {
    // 페이지 접기/펼치기 토글
    const pageToggle = event.target.closest(".page-toggle");
    if (pageToggle) {
        event.stopPropagation();
        const pageId = pageToggle.dataset.pageId;
        if (pageId) {
            if (state.expandedPages.has(pageId)) {
                state.expandedPages.delete(pageId);
            } else {
                state.expandedPages.add(pageId);
            }
            renderPageList();
        }
        return;
    }

    // 하위 페이지 추가 버튼
    const addSubpageBtn = event.target.closest(".page-add-subpage-btn");
    if (addSubpageBtn) {
        event.stopPropagation();
        const parentId = addSubpageBtn.dataset.pageId;
        const title = prompt("하위 페이지 제목을 입력하세요:", "새 하위 페이지");
        if (!title) return;

        try {
            const page = await api.post("/api/pages", {
                title: title.trim(),
                content: "<p></p>",
                parentId: parentId,
                storageId: state.currentStorageId
            });
            state.pages.push(page);
            state.expandedPages.add(parentId);
            renderPageList();
            await loadPage(page.id);
        } catch (e) {
            alert("하위 페이지 생성 실패: " + e.message);
        }
        return;
    }

    // 페이지 메뉴 토글
    const pageMenuBtn = event.target.closest(".page-menu-btn");
    if (pageMenuBtn) {
        event.stopPropagation();
        const pageId = pageMenuBtn.dataset.pageId;

        // 권한 체크: ADMIN이거나, EDIT이면서 본인 페이지인 경우만 삭제 가능
        const page = state.pages.find(p => p.id === pageId);
        const isOwner = page && state.currentUser && Number(page.userId) === Number(state.currentUser.id);
        const isAdmin = state.currentStoragePermission === 'ADMIN';
        const canDelete = isAdmin || (state.currentStoragePermission === 'EDIT' && isOwner);

        const menuItems = [
            {
                action: "set-icon",
                label: "아이콘 설정",
                icon: "fa-solid fa-icons",
                dataset: { pageId: pageId }
            }
        ];

        // 편집 권한이 있는 경우 이름 변경 추가
        const canEdit = state.currentStoragePermission === 'EDIT' || state.currentStoragePermission === 'ADMIN';
        if (canEdit) {
            menuItems.push({
                action: "rename-page",
                label: "이름 변경",
                icon: "fa-solid fa-pen",
                dataset: { pageId: pageId }
            });
        }

        if (canDelete) {
            menuItems.push({
                action: "delete-page",
                label: "페이지 삭제",
                icon: "fa-regular fa-trash-can",
                dataset: { pageId: pageId }
            });
        }
        showContextMenu(pageMenuBtn, menuItems);
        return;
    }

    // 메뉴 액션
    const menuAction = event.target.closest("#context-menu button[data-action]");
    if (menuAction) {
        const { action, pageId } = menuAction.dataset;
        if (action === "delete-page") {
            if (!confirm("이 페이지를 휴지통으로 이동하시겠습니까?")) return;
            try {
                await api.del("/api/pages/" + encodeURIComponent(pageId));
                state.pages = state.pages.filter(p => p.id !== pageId);
                if (state.currentPageId === pageId) {
                    clearCurrentPage();
                }
                renderPageList();
            } catch (e) {
                alert("삭제 실패: " + e.message);
            }
        } else if (action === "rename-page") {
            const page = state.pages.find(p => p.id === pageId);
            const newTitle = prompt("새 페이지 제목을 입력하세요:", page ? page.title : "");
            if (newTitle && newTitle.trim() && (!page || newTitle.trim() !== page.title)) {
                try {
                    await api.put("/api/pages/" + encodeURIComponent(pageId), { title: newTitle.trim() });
                    // 로컬 상태 업데이트
                    if (page) page.title = newTitle.trim();
                    // 현재 열려있는 페이지라면 제목 입력 필드도 업데이트
                    if (state.currentPageId === pageId) {
                        const titleInput = document.querySelector("#page-title-input");
                        if (titleInput) titleInput.value = newTitle.trim();
                    }
                    renderPageList();
                } catch (e) {
                    alert("이름 변경 실패: " + e.message);
                }
            }
        } else if (action === "set-icon") {
            showIconPickerModal(pageId);
        }
        closeContextMenu();
        return;
    }

    // 페이지 선택
    const li = event.target.closest("li.page-list-item");
    if (li) {
        const pageId = li.dataset.pageId;
        if (pageId && pageId !== state.currentPageId) {
            await loadPage(pageId);
        }
    }
}

/**
 * 로그아웃 버튼 바인딩
 */
function bindLogoutButton() {
    document.querySelector("#logout-btn")?.addEventListener("click", async () => {
        await api.post("/api/auth/logout");
        window.location.href = "/login";
    });
}

/**
 * 모바일 사이드바 바인딩
 */
function bindMobileSidebar() {
    const mobileMenuBtn = document.querySelector("#mobile-menu-btn");
    const overlay = document.querySelector("#sidebar-overlay");
    if (mobileMenuBtn) mobileMenuBtn.addEventListener("click", openSidebar);
    if (overlay) overlay.addEventListener("click", closeSidebar);
}

/**
 * 글로벌 이벤트 초기화
 */
function initEvent() {
    document.addEventListener("click", (event) => {
        if (!event.target.closest(".page-menu-btn, #context-menu")) {
            closeContextMenu();
        }
    });
}

function initToolbarElements() {
    const toolbar = document.querySelector(".editor-toolbar");
    if (!toolbar) return;
    colorDropdownElement = toolbar.querySelector("[data-role='color-dropdown']");
    colorMenuElement = colorDropdownElement?.querySelector("[data-color-menu]");
    fontDropdownElement = toolbar.querySelector("[data-role='font-dropdown']");
    fontMenuElement = fontDropdownElement?.querySelector("[data-font-menu]");
}

// ==================== Initialization ====================
async function init() {
    showLoadingOverlay();
    try {
        window.appState = appState;
        appState.userSettings = loadSettings();

        appState.editor = await initEditor(null);
        initToolbarElements();
        bindToolbar(appState.editor);
        bindSlashKeyHandlers(appState.editor);

        initPagesManager(appState);
        appState.fetchPageList = fetchPageList;
        initEncryptionManager(appState);
        initSettingsManager(appState);
        initSyncManager(appState);
        initCoverManager(appState);
        initPublishManager(appState);
        initSubpagesManager(appState);
        initCommentsManager(appState);
        initIconPicker(appState);
        appState.renderPageList = renderPageList;

        const storagesManager = initStoragesManager(appState, (data) => {
            if (data.permission)
                appState.currentStoragePermission = data.permission;

            if (data.isEncryptedStorage !== undefined)
                appState.currentStorageIsEncrypted = data.isEncryptedStorage;

            if (Array.isArray(data.pages))
                applyPagesData(data.pages, data.isEncryptedStorage);

            // 저장소 전환 시 UI 초기화 및 권한 적용
            clearCurrentPage();
            renderPageList();
            startStorageSync(appState.currentStorageId);

            const first = appState.pages.find(p => !p.parentId) || appState.pages[0];
            if (first)
                loadPage(first.id);
        });

        initSearch();
        initEvent();

        document.getElementById('quick-search-btn')?.addEventListener('click', () => {
            const modal = document.getElementById('quick-search-modal');
            toggleModal(modal, true);
            const input = document.getElementById('search-input');
            if (input) {
                input.value = '';
                input.focus();
                hideSearchResults();
            }
        });

        document.querySelector("#page-list")?.addEventListener("click", e => handlePageListClick(e, appState));
        document.querySelector("#context-menu")?.addEventListener("click", e => handlePageListClick(e, appState));

        bindNewPageButton();
        bindModeToggle();
        bindLogoutButton();
        bindSettingsModal();
        bindEncryptionModal();
        bindDecryptionModal();
        bindMobileSidebar();
        bindPublishEvents();
        bindTotpModals();
        bindPasskeyModals();
        bindAccountManagementButtons();
        bindLoginLogsModal();
        initUpdatesManager(appState);
        initTrashManager(appState);

        document.getElementById('switch-storage-btn')?.addEventListener('click', () => storagesManager.show());

        const bootstrap = await api.get("/api/bootstrap");
        if (bootstrap.user) applyCurrentUser(bootstrap.user);
        if (Array.isArray(bootstrap.storages)) {
            appState.storages = bootstrap.storages;
            storagesManager.show();
        }

        // 초기 저장소 동기화 시작 (이미 선택된 경우 대비)
        if (appState.currentStorageId) {
            startStorageSync(appState.currentStorageId);
        }
    } catch (error) {
        console.error('Init error:', error);
    } finally {
        hideLoadingOverlay();
    }
}

// 아이콘 선택 및 기타 기능 (기존 로직 유지)
// ... (Icon Picker, Search logic from previous app.js can be added back here if needed)

// ==================== Search System ====================
/**
 * 검색 기능 초기화
 */
function initSearch() {
    const searchInput = document.getElementById('search-input');
    const searchModal = document.getElementById('quick-search-modal');
    if (!searchInput || !searchModal) return;

    let searchTimeout = null;

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.trim();

        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(async () => {
            if (query.length === 0) {
                hideSearchResults();
            } else {
                await performSearch(query);
            }
        }, 300);
    });

    // ESC 키로 닫기
    window.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && !searchModal.classList.contains('hidden')) {
            toggleModal(searchModal, false);
        }
    });

    // 오버레이 클릭 시 닫기
    searchModal.querySelector('.modal-overlay')?.addEventListener('click', () => {
        toggleModal(searchModal, false);
    });
}

/**
 * 검색 실행
 */
async function performSearch(query) {
    const results = [];
    const queryLower = query.toLowerCase();

    for (const page of appState.pages) {
        let titleToSearch = '';
        let shouldInclude = false;

        if (page.isEncrypted) {
            // 암호화된 페이지는 제목만 검색 (내용은 서버에만 암호화된 상태로 있음)
            titleToSearch = page.title || '';
            shouldInclude = titleToSearch.toLowerCase().includes(queryLower);
        } else {
            titleToSearch = page.title || '';
            const content = page.content || '';

            // 보안: innerHTML로 사용자 콘텐츠를 파싱하지 않음 (DOM 기반 XSS 방어)
            const textContent = htmlToPlainText(content, { maxLength: 20000 });

            const fullText = titleToSearch + ' ' + textContent;
            shouldInclude = fullText.toLowerCase().includes(queryLower);
        }

        if (shouldInclude) {
            results.push({
                id: page.id,
                title: titleToSearch || '제목 없음',
                isEncrypted: page.isEncrypted,
                icon: page.icon
            });
        }
    }

    displaySearchResults(results, query);
}

/**
 * 검색 결과 표시
 */
function displaySearchResults(results, query) {
    const searchCountEl = document.getElementById('search-count');
    const searchResultsList = document.getElementById('search-results-list');
    const searchPlaceholder = document.getElementById('search-placeholder');
    const searchResultsHeader = document.getElementById('search-results-header');
    const searchModal = document.getElementById('quick-search-modal');

    if (!searchResultsList) return;

    searchPlaceholder.style.display = 'none';
    searchResultsHeader.style.display = 'block';
    searchCountEl.textContent = results.length;
    searchResultsList.innerHTML = '';

    if (results.length === 0) {
        searchResultsList.innerHTML = '<li style="padding: 32px; text-align: center; color: #9ca3af; font-size: 14px;">검색 결과가 없습니다.</li>';
    } else {
        results.forEach(result => {
            const li = document.createElement('li');
            li.className = 'search-result-item';
            li.dataset.pageId = result.id;

            const iconClass = result.isEncrypted ? 'fa-solid fa-lock' : (result.icon || 'fa-regular fa-file-lines');

            li.innerHTML = `
                <i class="${escapeHtmlAttr(iconClass)}"></i>
                <span class="search-result-title">${escapeHtml(result.title)}</span>
                <span style="font-size: 11px; color: #9ca3af;">열기</span>
            `;

            li.addEventListener('click', async () => {
                await loadPage(result.id);
                toggleModal(searchModal, false);
                clearSearchInput();
            });

            searchResultsList.appendChild(li);
        });
    }
}

/**
 * 검색 결과 숨기기
 */
function hideSearchResults() {
    const searchResultsList = document.getElementById('search-results-list');
    const searchPlaceholder = document.getElementById('search-placeholder');
    const searchResultsHeader = document.getElementById('search-results-header');

    if (searchResultsList) searchResultsList.innerHTML = '';
    if (searchPlaceholder) searchPlaceholder.style.display = 'block';
    if (searchResultsHeader) searchResultsHeader.style.display = 'none';
}

/**
 * 검색 입력 초기화
 */
function clearSearchInput() {
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.value = '';
    }
}

window.closeSidebar = closeSidebar;
window.handlePageListClick = handlePageListClick;
window.loadAndRenderSubpages = loadAndRenderSubpages;

document.addEventListener("DOMContentLoaded", init);
