/**
 * NTEOK 메인 애플리케이션
 * 컬렉션 제거 및 계층식 페이지 전용 버전
 */

// ==================== Imports ====================
import {
    secureFetch,
    escapeHtml,
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
import { sanitizeEditorHtml } from './sanitize.js';
import { initEditor, bindToolbar, bindSlashKeyHandlers, updateToolbarState } from './editor.js';
import {
    initPagesManager,
    applyPagesData,
    fetchPageList,
    renderPageList,
    loadPage,
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
    openShareModal,
    closeShareModal,
    bindShareModal,
    removeShare
} from './share-manager.js';
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
    startCollectionSync,
    stopCollectionSync
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
        const menuItems = `
            <button data-action="set-icon" data-page-id="${escapeHtml(pageId)}">
                <i class="fa-solid fa-icons"></i> 아이콘 설정
            </button>
            <button data-action="delete-page" data-page-id="${escapeHtml(pageId)}">
                <i class="fa-regular fa-trash-can"></i> 페이지 삭제
            </button>
        `;
        showContextMenu(pageMenuBtn, menuItems);
        return;
    }

    // 메뉴 액션
    const menuAction = event.target.closest("#context-menu button[data-action]");
    if (menuAction) {
        const { action, pageId } = menuAction.dataset;
        if (action === "delete-page") {
            if (!confirm("이 페이지와 모든 하위 페이지를 삭제하시겠습니까?")) return;
            try {
                await api.del("/api/pages/" + encodeURIComponent(pageId));
                state.pages = state.pages.filter(p => p.id !== pageId);
                if (state.currentPageId === pageId) state.currentPageId = null;
                renderPageList();
            } catch (e) {
                alert("삭제 실패: " + e.message);
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
        if (!event.target.closest(".collection-menu-btn, .page-menu-btn, #context-menu")) {
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

        const storagesManager = initStoragesManager(appState, (data) => {
            if (Array.isArray(data.pages)) {
                applyPagesData(data.pages);
            }
            renderPageList();
            if (appState.pages.length > 0) {
                const first = appState.pages.find(p => !p.parentId) || appState.pages[0];
                loadPage(first.id);
            }
        });

        initSearch();
        initEvent();
        
        document.querySelector("#collection-list")?.addEventListener("click", e => handlePageListClick(e, appState));
        document.querySelector("#context-menu")?.addEventListener("click", e => handlePageListClick(e, appState));

        bindNewPageButton();
        bindModeToggle();
        bindLogoutButton();
        bindSettingsModal();
        bindEncryptionModal();
        bindDecryptionModal();
        bindShareModal();
        bindMobileSidebar();
        bindPublishEvents();
        bindTotpModals();
        bindPasskeyModals();
        bindAccountManagementButtons();
        bindLoginLogsModal();

        document.getElementById('switch-storage-btn')?.addEventListener('click', () => storagesManager.show());

        const bootstrap = await api.get("/api/bootstrap");
        if (bootstrap.user) applyCurrentUser(bootstrap.user);
        if (Array.isArray(bootstrap.storages)) {
            appState.storages = bootstrap.storages;
            storagesManager.show();
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
    if (!searchInput) return;

    let searchTimeout = null;

    searchInput.addEventListener('input', (e) => {
        const query = e.target.value.trim();

        // 입력 디바운싱 (300ms)
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(async () => {
            if (query.length === 0) {
                hideSearchResults();
            } else if (query.length >= 2) {
                await performSearch(query);
            }
        }, 300);
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
            // 암호화된 페이지는 검색에서 제외 (보안상 이유)
            shouldInclude = false;
        } else {
            // 평문 페이지: 제목과 내용에서 직접 검색
            titleToSearch = page.title || '';
            const content = page.content || '';

            // HTML 태그 제거
            const tempDiv = document.createElement('div');
            tempDiv.innerHTML = content;
            const textContent = tempDiv.textContent || '';

            const fullText = titleToSearch + ' ' + textContent;
            shouldInclude = fullText.toLowerCase().includes(queryLower);
        }

        if (shouldInclude) {
            results.push({
                id: page.id,
                title: titleToSearch || '제목 없음',
                isEncrypted: page.isEncrypted
            });
        }
    }

    displaySearchResults(results, query);
}

/**
 * 검색 결과 표시
 */
function displaySearchResults(results, query) {
    const searchResultsContainer = document.getElementById('search-results');
    const searchCountEl = document.getElementById('search-count');
    const searchResultsList = document.getElementById('search-results-list');

    if (!searchResultsContainer || !searchCountEl || !searchResultsList) return;

    // 검색 결과 개수 표시
    searchCountEl.textContent = results.length;

    // 검색 결과 목록 생성
    searchResultsList.innerHTML = '';

    if (results.length === 0) {
        searchResultsList.innerHTML = '<li style="padding: 8px; color: #9ca3af; font-size: 13px;">검색 결과가 없습니다.</li>';
    } else {
        results.forEach(result => {
            const li = document.createElement('li');
            li.style.cssText = 'padding: 8px; cursor: pointer; border-radius: 4px; font-size: 13px; display: flex; align-items: center; gap: 6px;';
            li.dataset.pageId = result.id;

            // 암호화 아이콘 추가
            if (result.isEncrypted) {
                const lockIcon = document.createElement('i');
                lockIcon.className = 'fa-solid fa-lock';
                lockIcon.style.cssText = 'font-size: 10px; color: #9ca3af;';
                li.appendChild(lockIcon);
            }

            const titleSpan = document.createElement('span');
            titleSpan.textContent = result.title;
            titleSpan.style.cssText = 'overflow: hidden; text-overflow: ellipsis; white-space: nowrap;';
            li.appendChild(titleSpan);

            // 호버 효과
            li.addEventListener('mouseenter', () => {
                li.style.background = '#f3f4f6';
            });
            li.addEventListener('mouseleave', () => {
                li.style.background = '';
            });

            // 클릭 시 페이지 로드
            li.addEventListener('click', async () => {
                await loadPage(result.id);
                hideSearchResults();
                clearSearchInput();
            });

            searchResultsList.appendChild(li);
        });
    }

    // 검색 결과 영역 표시
    searchResultsContainer.style.display = 'block';
}

/**
 * 검색 결과 숨기기
 */
function hideSearchResults() {
    const searchResultsContainer = document.getElementById('search-results');
    if (searchResultsContainer) {
        searchResultsContainer.style.display = 'none';
    }
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
