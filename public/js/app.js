/**
 * NTEOK 메인 애플리케이션
 * 모듈화된 구조로 재구성
 */

// ==================== Imports ====================
import { secureFetch, escapeHtml, showErrorInEditor, closeAllDropdowns, openDropdown, showContextMenu, closeContextMenu } from './ui-utils.js';
import { initEditor, bindToolbar, bindSlashKeyHandlers, updateToolbarState } from './editor.js';
import {
    initPagesManager,
    fetchCollections,
    fetchPageList,
    renderPageList,
    loadPage,
    saveCurrentPage,
    toggleEditMode,
    bindModeToggle,
    bindNewCollectionButton
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
    removeShare,
    removeShareLink,
    copyLinkToClipboard
} from './share-manager.js';
import {
    initSettingsManager,
    openSettingsModal,
    closeSettingsModal,
    saveSettings,
    loadSettings,
    bindSettingsModal,
    fetchAndDisplayCurrentUser
} from './settings-manager.js';
import {
    updateTotpStatus,
    openTotpSetupModal,
    closeTotpSetupModal,
    bindTotpModals
} from './totp-manager.js';

// ==================== Global State ====================
const appState = {
    editor: null,
    pages: [],
    collections: [],
    currentPageId: null,
    currentCollectionId: null,
    expandedCollections: new Set(),
    isWriteMode: false,
    currentUser: null,
    userSettings: {
        defaultMode: 'read'
    },
    currentEncryptingPageId: null,
    currentDecryptingPage: null,
    fetchPageList: null
};

// 전역 변수 (드롭다운용)
let colorDropdownElement = null;
let colorMenuElement = null;
let fontDropdownElement = null;
let fontMenuElement = null;

// ==================== Helper Functions ====================

/**
 * 페이지 리스트 클릭 핸들러
 */
async function handlePageListClick(event, state) {
    // 컬렉션 메뉴 토글
    const colMenuBtn = event.target.closest(".collection-menu-btn");
    if (colMenuBtn) {
        event.stopPropagation();
        closeAllDropdowns();

        const collectionId = colMenuBtn.dataset.collectionId;
        const isOwner = colMenuBtn.dataset.isOwner === 'true';
        const permission = colMenuBtn.dataset.permission;

        let menuItems = '';
        if (isOwner) {
            menuItems = `
                <button data-action="share-collection" data-collection-id="${escapeHtml(collectionId)}">
                    <i class="fa-solid fa-share-nodes"></i>
                    컬렉션 공유
                </button>
                <button data-action="delete-collection" data-collection-id="${escapeHtml(collectionId)}">
                    <i class="fa-regular fa-trash-can"></i>
                    컬렉션 삭제
                </button>
            `;
        } else {
            menuItems = `<div style="padding: 8px; color: #6b7280; font-size: 12px;">권한: ${escapeHtml(permission || 'READ')}</div>`;
        }

        showContextMenu(colMenuBtn, menuItems);
        return;
    }

    // 컬렉션 메뉴 액션
    const colMenuAction = event.target.closest("#context-menu button[data-action^='share-collection'], #context-menu button[data-action^='delete-collection']");
    if (colMenuAction) {
        const action = colMenuAction.dataset.action;
        const colId = colMenuAction.dataset.collectionId;

        if (action === "share-collection" && colId) {
            const collection = state.collections.find(c => c.id === colId);
            if (collection && collection.isOwner !== false) {
                openShareModal(colId);
            } else {
                alert("컬렉션 소유자만 공유할 수 있습니다.");
            }
            closeContextMenu();
            return;
        }

        if (action === "delete-collection" && colId) {
            const ok = confirm("이 컬렉션과 포함된 모든 페이지를 삭제하시겠습니까?");
            if (!ok) return;
            try {
                const res = await secureFetch("/api/collections/" + encodeURIComponent(colId), {
                    method: "DELETE"
                });
                if (!res.ok) {
                    throw new Error("HTTP " + res.status + " " + res.statusText);
                }
                state.collections = state.collections.filter((c) => c.id !== colId);
                state.pages = state.pages.filter((p) => p.collectionId !== colId);
                state.expandedCollections.delete(colId);

                if (state.currentCollectionId === colId) {
                    state.currentCollectionId = state.collections[0]?.id || null;
                    state.currentPageId = null;
                }

                renderPageList();

                if (state.editor) {
                    if (state.currentCollectionId && state.pages.find((p) => p.collectionId === state.currentCollectionId)) {
                        state.editor.commands.setContent("<p>페이지를 선택하세요.</p>", { emitUpdate: false });
                    } else if (state.currentCollectionId) {
                        state.editor.commands.setContent("<p>이 컬렉션에 페이지가 없습니다.</p>", { emitUpdate: false });
                    } else {
                        state.editor.commands.setContent("<p>컬렉션을 추가해 주세요.</p>", { emitUpdate: false });
                    }
                    const titleInput = document.querySelector("#page-title-input");
                    if (titleInput) {
                        titleInput.value = "";
                    }
                }
                state.currentPageId = null;
            } catch (error) {
                console.error("컬렉션 삭제 오류:", error);
                alert("컬렉션을 삭제하지 못했습니다: " + error.message);
            } finally {
                closeContextMenu();
            }
        }
        return;
    }

    // 컬렉션에 페이지 추가
    const addBtn = event.target.closest(".collection-add-page-btn");
    if (addBtn) {
        const colId = addBtn.dataset.collectionId;
        if (!colId) return;
        state.expandedCollections.add(colId);

        let title = prompt("새 페이지 제목을 입력하세요.", "새 페이지");
        if (title === null) return;

        const plainTitle = title.trim() || "새 페이지";
        const plainContent = "<p></p>";

        try {
            const res = await secureFetch("/api/pages", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    title: plainTitle,
                    content: plainContent,
                    parentId: null,
                    collectionId: colId
                })
            });

            if (!res.ok) {
                throw new Error("HTTP " + res.status + " " + res.statusText);
            }

            const page = await res.json();
            state.pages.unshift({
                id: page.id,
                title: plainTitle,
                updatedAt: page.updatedAt,
                parentId: page.parentId || null,
                collectionId: page.collectionId || colId,
                sortOrder: typeof page.sortOrder === "number" ? page.sortOrder : 0
            });

            state.currentCollectionId = colId;
            state.currentPageId = page.id;
            renderPageList();
            await loadPage(page.id);
        } catch (error) {
            console.error("페이지 생성 오류:", error);
            alert("페이지를 생성하지 못했다: " + error.message);
        } finally {
            closeContextMenu();
        }
        return;
    }

    // 페이지 메뉴 토글
    const pageMenuBtn = event.target.closest(".page-menu-btn");
    if (pageMenuBtn) {
        event.stopPropagation();
        closeAllDropdowns();

        const pageId = pageMenuBtn.dataset.pageId;
        const isEncrypted = pageMenuBtn.dataset.isEncrypted === 'true';

        // 페이지 정보 찾기
        const page = appState.pages.find(p => p.id === pageId);
        const collection = page ? appState.collections.find(c => c.id === page.collectionId) : null;
        const isSharedCollection = collection && collection.isShared;
        const isPageOwner = page && appState.currentUser && page.userId === appState.currentUser.id;

        let menuItems = '';
        if (isEncrypted) {
            // 암호화된 페이지: 공유 컬렉션이고 페이지 소유자인 경우만 공유 허용 토글 추가
            if (isSharedCollection && isPageOwner) {
                const shareAllowed = page && page.shareAllowed;
                menuItems = `
                    <button data-action="toggle-share" data-page-id="${escapeHtml(pageId)}" data-share-allowed="${shareAllowed ? 'true' : 'false'}">
                        <i class="fa-solid fa-${shareAllowed ? 'eye-slash' : 'eye'}"></i>
                        ${shareAllowed ? '공유 비허용' : '공유 허용'}
                    </button>
                    <button data-action="delete-page" data-page-id="${escapeHtml(pageId)}">
                        <i class="fa-regular fa-trash-can"></i>
                        페이지 삭제
                    </button>
                `;
            } else {
                menuItems = `
                    <button data-action="delete-page" data-page-id="${escapeHtml(pageId)}">
                        <i class="fa-regular fa-trash-can"></i>
                        페이지 삭제
                    </button>
                `;
            }
        } else {
            menuItems = `
                <button data-action="encrypt-page" data-page-id="${escapeHtml(pageId)}">
                    <i class="fa-solid fa-lock"></i>
                    페이지 암호화
                </button>
                <button data-action="delete-page" data-page-id="${escapeHtml(pageId)}">
                    <i class="fa-regular fa-trash-can"></i>
                    페이지 삭제
                </button>
            `;
        }

        showContextMenu(pageMenuBtn, menuItems);
        return;
    }

    // 페이지 메뉴 액션
    const pageMenuAction = event.target.closest("#context-menu button[data-action^='encrypt-page'], #context-menu button[data-action^='delete-page'], #context-menu button[data-action^='toggle-share']");
    if (pageMenuAction) {
        const action = pageMenuAction.dataset.action;
        const pageId = pageMenuAction.dataset.pageId;

        if (action === "encrypt-page" && pageId) {
            showEncryptionModal(pageId);
            closeContextMenu();
            return;
        }

        if (action === "toggle-share" && pageId) {
            const currentShareAllowed = pageMenuAction.dataset.shareAllowed === 'true';
            const newShareAllowed = !currentShareAllowed;

            // API 호출
            secureFetch(`/api/pages/${encodeURIComponent(pageId)}/share-permission`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ shareAllowed: newShareAllowed })
            })
            .then(res => {
                if (!res.ok) {
                    throw new Error('HTTP ' + res.status);
                }
                return res.json();
            })
            .then(() => {
                // 상태 업데이트
                const page = appState.pages.find(p => p.id === pageId);
                if (page) {
                    page.shareAllowed = newShareAllowed;
                }
                renderPageList();
                alert(newShareAllowed ? '페이지 공유가 허용되었습니다.' : '페이지 공유가 비허용되었습니다.');
            })
            .catch(error => {
                console.error('공유 허용 설정 오류:', error);
                alert('공유 허용 설정 중 오류가 발생했습니다.');
            });

            closeContextMenu();
            return;
        }

        if (action === "delete-page" && pageId) {
            const ok = confirm("이 페이지를 삭제하시겠습니까?");
            if (!ok) return;
            try {
                const res = await secureFetch("/api/pages/" + encodeURIComponent(pageId), {
                    method: "DELETE"
                });
                if (!res.ok) {
                    throw new Error("HTTP " + res.status + " " + res.statusText);
                }
                state.pages = state.pages.filter((p) => p.id !== pageId);
                if (state.currentPageId === pageId) {
                    state.currentPageId = null;
                }
                renderPageList();

                const hasPages = state.pages.some((p) => p.collectionId === state.currentCollectionId);
                if (!hasPages && state.currentCollectionId) {
                    state.expandedCollections.delete(state.currentCollectionId);
                }
                if (state.currentCollectionId) {
                    const first = state.pages.find((p) => p.collectionId === state.currentCollectionId);
                    if (first) {
                        await loadPage(first.id);
                    } else if (state.editor) {
                        state.editor.commands.setContent("<p>이 컬렉션에 페이지가 없습니다.</p>", { emitUpdate: false });
                        const titleInput = document.querySelector("#page-title-input");
                        if (titleInput) {
                            titleInput.value = "";
                        }
                    }
                }
            } catch (error) {
                console.error("페이지 삭제 오류:", error);
                if (error.message && error.message.includes("403")) {
                    showDeletePermissionModal();
                } else {
                    alert("페이지를 삭제하지 못했습니다: " + error.message);
                }
            } finally {
                closeContextMenu();
            }
        }
        return;
    }

    // 컬렉션 선택
    const collectionHeader = event.target.closest(".collection-header");
    if (collectionHeader) {
        const container = collectionHeader.closest(".collection-item");
        const colId = container ? container.dataset.collectionId : null;
        if (colId) {
            if (state.expandedCollections.has(colId)) {
                state.expandedCollections.delete(colId);
            } else {
                state.expandedCollections.add(colId);
                state.currentCollectionId = colId;
            }
            renderPageList();
        }
        closeContextMenu();
        return;
    }

    // 페이지 선택
    const li = event.target.closest("li.page-list-item");
    if (!li) return;

    const pageId = li.dataset.pageId;
    if (!pageId || pageId === state.currentPageId) return;

    closeContextMenu();
    await loadPage(pageId);
}

/**
 * 로그아웃 버튼 바인딩
 */
function bindLogoutButton() {
    const btn = document.querySelector("#logout-btn");
    if (!btn) return;

    btn.addEventListener("click", async () => {
        try {
            const res = await secureFetch("/api/auth/logout", {
                method: "POST"
            });

            if (!res.ok) {
                throw new Error("HTTP " + res.status);
            }

            // 암호화 키 삭제
            if (typeof cryptoManager !== 'undefined') {
                cryptoManager.clearKey();
            }

            window.location.href = "/login";
        } catch (error) {
            console.error("로그아웃 오류:", error);
            alert("로그아웃 중 오류가 발생했습니다.");
        }
    });
}

/**
 * 페이지 복호화 및 로드
 */
async function decryptAndLoadPage(page, password) {
    // 암호화 키 초기화 (비밀번호 메모리에 저장)
    await cryptoManager.initializeKey(password);

    // 콘텐츠 복호화 (새 형식은 salt 포함, 구 형식은 기존 방식 사용)
    const content = await cryptoManager.decrypt(page.content, password);

    appState.currentPageId = page.id;

    const titleInput = document.querySelector("#page-title-input");
    if (titleInput) {
        titleInput.value = page.title;
    }

    if (appState.editor) {
        appState.editor.commands.setContent(content, { emitUpdate: false });
    }

    renderPageList();

    if (window.innerWidth <= 768) {
        closeSidebar();
    }

    console.log("페이지 복호화 성공");
}

/**
 * 사이드바 열기
 */
function openSidebar() {
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
function closeSidebar() {
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
 * 모바일 사이드바 바인딩
 */
function bindMobileSidebar() {
    const mobileMenuBtn = document.querySelector("#mobile-menu-btn");
    const overlay = document.querySelector("#sidebar-overlay");

    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener("click", () => {
            openSidebar();
        });
    }

    if (overlay) {
        overlay.addEventListener("click", () => {
            closeSidebar();
        });
    }
}

/**
 * 읽기 전용 경고 모달 표시
 */
function showReadonlyWarningModal() {
    const modal = document.querySelector("#readonly-warning-modal");
    if (modal) {
        modal.classList.remove("hidden");
    }
}

/**
 * 읽기 전용 경고 모달 닫기
 */
async function closeReadonlyWarningModal() {
    const modal = document.querySelector("#readonly-warning-modal");
    if (modal) {
        modal.classList.add("hidden");
    }

    if (appState.isWriteMode) {
        const modeToggleBtn = document.querySelector("#mode-toggle-btn");
        const titleInput = document.querySelector("#page-title-input");
        const toolbar = document.querySelector(".editor-toolbar");
        const iconEl = modeToggleBtn ? modeToggleBtn.querySelector("i") : null;
        const textEl = modeToggleBtn ? modeToggleBtn.querySelector("span") : null;

        appState.isWriteMode = false;

        if (appState.editor) {
            appState.editor.setEditable(false);
        }

        if (titleInput) {
            titleInput.setAttribute("readonly", "");
        }

        if (toolbar) {
            toolbar.classList.remove("visible");
        }

        if (modeToggleBtn) {
            modeToggleBtn.classList.remove("write-mode");
        }

        if (iconEl) {
            iconEl.className = "fa-solid fa-pencil";
        }

        if (textEl) {
            textEl.textContent = "쓰기모드";
        }

        if (appState.currentPageId) {
            try {
                const res = await fetch("/api/pages/" + encodeURIComponent(appState.currentPageId));
                if (!res.ok) {
                    throw new Error("HTTP " + res.status);
                }

                const page = await res.json();

                if (titleInput) {
                    titleInput.value = page.title || "";
                }

                if (appState.editor) {
                    appState.editor.commands.setContent(page.content || "<p></p>", { emitUpdate: false });
                }
            } catch (error) {
                console.error("원본 페이지 복원 오류:", error);
            }
        }
    }
}

/**
 * 읽기 전용 경고 모달 바인딩
 */
function bindReadonlyWarningModal() {
    const closeBtn = document.querySelector("#close-readonly-warning-btn");
    const confirmBtn = document.querySelector("#readonly-warning-confirm-btn");

    if (closeBtn) {
        closeBtn.addEventListener("click", closeReadonlyWarningModal);
    }

    if (confirmBtn) {
        confirmBtn.addEventListener("click", closeReadonlyWarningModal);
    }

    const modal = document.querySelector("#readonly-warning-modal");
    if (modal) {
        const overlay = modal.querySelector(".modal-overlay");
        if (overlay) {
            overlay.addEventListener("click", closeReadonlyWarningModal);
        }
    }
}

/**
 * 삭제 권한 없음 모달 표시
 */
function showDeletePermissionModal() {
    const modal = document.querySelector("#delete-permission-modal");
    if (modal) {
        modal.classList.remove("hidden");
    }
}

/**
 * 삭제 권한 없음 모달 닫기
 */
function closeDeletePermissionModal() {
    const modal = document.querySelector("#delete-permission-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
}

/**
 * 삭제 권한 없음 모달 바인딩
 */
function bindDeletePermissionModal() {
    const closeBtn = document.querySelector("#close-delete-permission-btn");
    const confirmBtn = document.querySelector("#delete-permission-confirm-btn");

    if (closeBtn) {
        closeBtn.addEventListener("click", closeDeletePermissionModal);
    }

    if (confirmBtn) {
        confirmBtn.addEventListener("click", closeDeletePermissionModal);
    }

    const modal = document.querySelector("#delete-permission-modal");
    if (modal) {
        const overlay = modal.querySelector(".modal-overlay");
        if (overlay) {
            overlay.addEventListener("click", closeDeletePermissionModal);
        }
    }
}

/**
 * 암호화 권한 없음 모달 표시
 */
function showEncryptPermissionModal() {
    const modal = document.querySelector("#encrypt-permission-modal");
    if (modal) {
        modal.classList.remove("hidden");
    }
}

/**
 * 암호화 권한 없음 모달 닫기
 */
function closeEncryptPermissionModal() {
    const modal = document.querySelector("#encrypt-permission-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    closeEncryptionModal();
}

/**
 * 암호화 권한 없음 모달 바인딩
 */
function bindEncryptPermissionModal() {
    const closeBtn = document.querySelector("#close-encrypt-permission-btn");
    const confirmBtn = document.querySelector("#encrypt-permission-confirm-btn");

    if (closeBtn) {
        closeBtn.addEventListener("click", closeEncryptPermissionModal);
    }

    if (confirmBtn) {
        confirmBtn.addEventListener("click", closeEncryptPermissionModal);
    }

    const modal = document.querySelector("#encrypt-permission-modal");
    if (modal) {
        const overlay = modal.querySelector(".modal-overlay");
        if (overlay) {
            overlay.addEventListener("click", closeEncryptPermissionModal);
        }
    }
}

/**
 * 페이지 리스트 클릭 바인딩
 */
function bindPageListClick() {
    const listEl = document.querySelector("#collection-list");
    if (!listEl) return;

    listEl.addEventListener("click", async (event) => {
        await handlePageListClick(event, appState);
    });
}

/**
 * Context Menu 클릭 바인딩
 */
function bindContextMenuClick() {
    const contextMenu = document.querySelector("#context-menu");
    if (!contextMenu) return;

    contextMenu.addEventListener("click", async (event) => {
        await handlePageListClick(event, appState);
    });
}

/**
 * 글로벌 이벤트 초기화
 */
function initEvent() {
    // 색상 드롭다운 외부 클릭 시 닫기
    document.addEventListener("click", (event) => {
        if (!colorDropdownElement || !colorMenuElement) return;
        if (colorDropdownElement.contains(event.target)) return;

        if (!colorMenuElement.hasAttribute("hidden")) {
            colorMenuElement.setAttribute("hidden", "");
            colorDropdownElement.classList.remove("open");
        }
    });

    // 폰트 드롭다운 외부 클릭 시 닫기
    document.addEventListener("click", (event) => {
        if (!fontDropdownElement || !fontMenuElement) return;
        if (fontDropdownElement.contains(event.target)) return;

        if (!fontMenuElement.hasAttribute("hidden")) {
            fontMenuElement.setAttribute("hidden", "");
            fontDropdownElement.classList.remove("open");
        }
    });

    // Context menu 외부 클릭 시 닫기
    document.addEventListener("click", (event) => {
        const isMenuBtn = event.target.closest(".collection-menu-btn, .page-menu-btn");
        const isContextMenu = event.target.closest("#context-menu");
        if (isMenuBtn || isContextMenu) {
            return;
        }
        closeContextMenu();
    });
}

/**
 * 툴바 초기화 (드롭다운 요소 캐싱)
 */
function initToolbarElements() {
    const toolbar = document.querySelector(".editor-toolbar");
    if (!toolbar) return;

    colorDropdownElement = toolbar.querySelector("[data-role='color-dropdown']");
    colorMenuElement = colorDropdownElement
        ? colorDropdownElement.querySelector("[data-color-menu]")
        : null;

    fontDropdownElement = toolbar.querySelector("[data-role='font-dropdown']");
    fontMenuElement = fontDropdownElement
        ? fontDropdownElement.querySelector("[data-font-menu]")
        : null;
}

// ==================== Initialization ====================
async function init() {
    // 설정 로드
    const loadedSettings = loadSettings();
    appState.userSettings = loadedSettings;

    // 에디터 초기화
    appState.editor = initEditor();
    initToolbarElements();
    bindToolbar(appState.editor);
    bindSlashKeyHandlers(appState.editor);

    // 페이지 관리자 초기화
    initPagesManager(appState);

    // 암호화 관리자 초기화
    appState.fetchPageList = fetchPageList;
    initEncryptionManager(appState);

    // 설정 관리자 초기화
    initSettingsManager(appState);

    // 이벤트 바인딩
    initEvent();
    bindPageListClick();
    bindContextMenuClick();
    bindNewCollectionButton();
    bindModeToggle();
    bindLogoutButton();
    bindSettingsModal();
    bindEncryptionModal();
    bindDecryptionModal();
    bindShareModal();
    bindReadonlyWarningModal();
    bindDeletePermissionModal();
    bindEncryptPermissionModal();
    bindMobileSidebar();
    bindTotpModals();

    // 데이터 로드
    await fetchAndDisplayCurrentUser();
    await fetchCollections();
    await fetchPageList();
}

// ==================== Global Window Functions ====================
// 일부 함수들은 다른 모듈이나 inline 이벤트에서 접근 필요
window.showEncryptionModal = showEncryptionModal;
window.showDecryptionModal = showDecryptionModal;
window.openShareModal = openShareModal;
window.removeShare = removeShare;
window.removeShareLink = removeShareLink;
window.copyLinkToClipboard = copyLinkToClipboard;
window.showReadonlyWarningModal = showReadonlyWarningModal;
window.showDeletePermissionModal = showDeletePermissionModal;
window.showEncryptPermissionModal = showEncryptPermissionModal;
window.closeSidebar = closeSidebar;
window.handlePageListClick = handlePageListClick;
window.decryptAndLoadPage = decryptAndLoadPage;

// ==================== Start Application ====================
document.addEventListener("DOMContentLoaded", () => {
    init();
});
