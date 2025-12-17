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
    removeShare
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
    initDuplicateLoginDetector
} from './duplicate-login-detector.js';

// ==================== Global State ====================
const appState = {
    editor: null,
    pages: [],
    collections: [],
    currentPageId: null,
    currentCollectionId: null,
    expandedCollections: new Set(),
    isWriteMode: false,
    currentPageIsEncrypted: false,  // 현재 페이지의 암호화 상태
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
        const collection = appState.collections.find(c => c.id === collectionId);

        let menuItems = '';
        if (isOwner) {
            // 공유된 컬렉션이고 아직 암호화되지 않았으면 암호화 옵션 표시
            const showEncryptOption = collection && collection.isShared && !collection.isEncrypted;

            menuItems = `
                <button data-action="share-collection" data-collection-id="${escapeHtml(collectionId)}">
                    <i class="fa-solid fa-share-nodes"></i>
                    컬렉션 공유
                </button>
                ${showEncryptOption ? `
                <button data-action="encrypt-collection" data-collection-id="${escapeHtml(collectionId)}">
                    <i class="fa-solid fa-lock"></i>
                    컬렉션 암호화
                </button>
                ` : ''}
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
    const colMenuAction = event.target.closest("#context-menu button[data-action^='share-collection'], #context-menu button[data-action^='delete-collection'], #context-menu button[data-action^='encrypt-collection']");
    if (colMenuAction) {
        const action = colMenuAction.dataset.action;
        const colId = colMenuAction.dataset.collectionId;

        if (action === "share-collection" && colId) {
            const collection = appState.collections.find(c => c.id === colId);
            if (collection && collection.isOwner !== false) {
                openShareModal(colId);
            } else {
                alert("컬렉션 소유자만 공유할 수 있습니다.");
            }
            closeContextMenu();
            return;
        }

        if (action === "encrypt-collection" && colId) {
            await handleCollectionEncryption(colId);
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
                    <button data-action="set-icon" data-page-id="${escapeHtml(pageId)}">
                        <i class="fa-solid fa-icons"></i>
                        아이콘 설정
                    </button>
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
                    <button data-action="set-icon" data-page-id="${escapeHtml(pageId)}">
                        <i class="fa-solid fa-icons"></i>
                        아이콘 설정
                    </button>
                    <button data-action="delete-page" data-page-id="${escapeHtml(pageId)}">
                        <i class="fa-regular fa-trash-can"></i>
                        페이지 삭제
                    </button>
                `;
            }
        } else {
            menuItems = `
                <button data-action="set-icon" data-page-id="${escapeHtml(pageId)}">
                    <i class="fa-solid fa-icons"></i>
                    아이콘 설정
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
    const pageMenuAction = event.target.closest("#context-menu button[data-action^='set-icon'], #context-menu button[data-action^='delete-page'], #context-menu button[data-action^='toggle-share']");
    if (pageMenuAction) {
        const action = pageMenuAction.dataset.action;
        const pageId = pageMenuAction.dataset.pageId;

        if (action === "set-icon" && pageId) {
            showIconPickerModal(pageId);
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
            if (typeof window.cryptoManager !== 'undefined') {
                window.cryptoManager.clearKey();
                window.cryptoManager.clearMasterKey();
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
    appState.currentPageIsEncrypted = false;  // 복호화 완료 - 편집 가능 상태

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

        // 읽기모드로 전환 시 커버 버튼 숨김
        updateCoverButtonsVisibility();

        if (appState.currentPageId) {
            try {
                const res = await secureFetch("/api/pages/" + encodeURIComponent(appState.currentPageId));
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

    // 실시간 동기화 관리자 초기화
    initSyncManager(appState);

    // 커버 이미지 관리자 초기화
    initCoverManager(appState);

    // 중복 로그인 감지기 초기화
    initDuplicateLoginDetector();

    // 검색 기능 초기화
    initSearch();

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
    bindIconPickerModal();
    bindMobileSidebar();
    bindTotpModals();
    bindPasskeyModals();
    bindAccountManagementButtons();
    bindPasswordReconfirmModal();
    bindMigrationModal();

    // 데이터 로드
    await fetchAndDisplayCurrentUser();
    await fetchCollections();
    await fetchPageList();

    // 마스터 키 초기화 및 마이그레이션 확인
    await initializeMasterKeyIfNeeded();
}

// ==================== Master Key Initialization ====================
// 전역 Promise resolver for password reconfirmation
let passwordReconfirmResolver = null;

/**
 * 마스터 키 초기화 필요 시 비밀번호 재확인 모달 표시
 */
async function initializeMasterKeyIfNeeded() {
    if (!window.cryptoManager) {
        console.error('cryptoManager가 초기화되지 않았습니다!');
        return;
    }

    // 이미 마스터 키가 초기화되어 있으면 마이그레이션으로 진행
    if (window.cryptoManager.isMasterKeyInitialized()) {
        await checkAndShowMigrationModal();
        return;
    }

    // 비밀번호 재확인 대기
    await showPasswordReconfirmModal();

    // 마스터 키가 초기화된 후 마이그레이션 확인
    await checkAndShowMigrationModal();
}

/**
 * 비밀번호 재확인 모달 표시 (Promise 반환)
 */
function showPasswordReconfirmModal() {
    return new Promise((resolve) => {
        // resolver 저장
        passwordReconfirmResolver = resolve;

        const modal = document.getElementById('password-reconfirm-modal');
        if (modal) {
            modal.classList.remove('hidden');
            // 포커스 설정
            setTimeout(() => {
                const passwordInput = document.getElementById('reconfirm-password');
                if (passwordInput) {
                    passwordInput.focus();
                }
            }, 100);
        }
    });
}

/**
 * 비밀번호 재확인 모달 닫기
 */
function closePasswordReconfirmModal() {
    const modal = document.getElementById('password-reconfirm-modal');
    if (modal) {
        modal.classList.add('hidden');
    }

    // 에러 메시지 초기화
    const errorEl = document.getElementById('reconfirm-error');
    if (errorEl) {
        errorEl.textContent = '';
    }

    // 비밀번호 입력 초기화
    const passwordInput = document.getElementById('reconfirm-password');
    if (passwordInput) {
        passwordInput.value = '';
    }
}

/**
 * 비밀번호 재확인 폼 바인딩
 */
function bindPasswordReconfirmModal() {
    const form = document.getElementById('password-reconfirm-form');

    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handlePasswordReconfirm();
        });
    }
}

/**
 * 비밀번호 재확인 처리
 */
async function handlePasswordReconfirm() {
    const passwordInput = document.getElementById('reconfirm-password');
    const errorEl = document.getElementById('reconfirm-error');
    const submitBtn = document.querySelector('#password-reconfirm-form button[type="submit"]');

    if (!passwordInput) return;

    const password = passwordInput.value;

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = '확인 중...';
    }

    try {
        // 서버에 비밀번호 확인 (CSRF 토큰 포함)
        const res = await secureFetch('/api/auth/verify-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ password })
        });

        if (!res.ok) {
            throw new Error('비밀번호가 올바르지 않습니다.');
        }

        const data = await res.json();

        // 마스터 키 초기화
        let masterKeySalt = data.masterKeySalt;

        if (!masterKeySalt) {
            // 신규 사용자: salt 생성
            masterKeySalt = await window.cryptoManager.initializeMasterKey(password);

            // 서버에 salt 저장 (CSRF 토큰 포함)
            await secureFetch('/api/auth/master-key-salt', {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ masterKeySalt })
            });
        } else {
            // 기존 사용자: salt로 마스터 키 초기화
            await window.cryptoManager.initializeMasterKey(password, masterKeySalt);
        }

        // 모달 닫기
        closePasswordReconfirmModal();

        // Promise resolve (마스터 키 초기화 완료 신호)
        if (passwordReconfirmResolver) {
            passwordReconfirmResolver();
            passwordReconfirmResolver = null;
        }

    } catch (error) {
        console.error('비밀번호 확인 오류:', error);
        if (errorEl) {
            errorEl.textContent = error.message || '비밀번호 확인에 실패했습니다.';
        }
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = '확인';
        }
    }
}

// ==================== Migration System ====================
/**
 * 구 형식 암호화 페이지 감지 및 마이그레이션 모달 표시
 */
async function checkAndShowMigrationModal() {
    // 구 형식 암호화 페이지 찾기 (content가 "SALT:"로 시작)
    const oldEncryptedPages = appState.pages.filter(page => {
        return page.isEncrypted && page.content && page.content.startsWith('SALT:');
    });

    if (oldEncryptedPages.length > 0) {
        console.log(`${oldEncryptedPages.length}개의 구 형식 암호화 페이지 감지됨`);
        showMigrationModal(oldEncryptedPages);
    }
}

/**
 * 마이그레이션 모달 표시
 */
function showMigrationModal(oldEncryptedPages) {
    const modal = document.getElementById('migration-modal');
    const pageCountEl = document.getElementById('migration-page-count');

    if (pageCountEl) {
        pageCountEl.textContent = oldEncryptedPages.length;
    }

    if (modal) {
        modal.classList.remove('hidden');
    }

    // 전역에 페이지 목록 저장
    window.oldEncryptedPages = oldEncryptedPages;
}

/**
 * 마이그레이션 모달 닫기
 */
function closeMigrationModal() {
    const modal = document.getElementById('migration-modal');
    if (modal) {
        modal.classList.add('hidden');
    }

    // 에러 메시지 초기화
    const errorEl = document.getElementById('migration-error');
    if (errorEl) {
        errorEl.textContent = '';
    }

    // 진행 상태 숨기기
    const progressEl = document.getElementById('migration-progress');
    if (progressEl) {
        progressEl.style.display = 'none';
    }
}

/**
 * 마이그레이션 폼 바인딩
 */
function bindMigrationModal() {
    const form = document.getElementById('migration-form');
    const skipBtn = document.getElementById('skip-migration-btn');

    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handleMigration();
        });
    }

    if (skipBtn) {
        skipBtn.addEventListener('click', () => {
            closeMigrationModal();
        });
    }
}

/**
 * 마이그레이션 실행
 */
async function handleMigration() {
    const passwordInput = document.getElementById('migration-password');
    const errorEl = document.getElementById('migration-error');
    const progressEl = document.getElementById('migration-progress');
    const progressBar = document.getElementById('migration-progress-bar');
    const currentEl = document.getElementById('migration-current');
    const totalEl = document.getElementById('migration-total');
    const submitBtn = document.querySelector('#migration-form button[type="submit"]');

    if (!passwordInput || !window.oldEncryptedPages) {
        return;
    }

    const password = passwordInput.value;
    const pages = window.oldEncryptedPages;

    // 마스터 키 초기화 확인
    if (!window.cryptoManager.isMasterKeyInitialized()) {
        if (errorEl) {
            errorEl.textContent = '마스터 키가 초기화되지 않았습니다. 다시 로그인해 주세요.';
        }
        return;
    }

    // 진행 상태 표시
    if (progressEl) {
        progressEl.style.display = 'block';
    }
    if (totalEl) {
        totalEl.textContent = pages.length;
    }
    if (submitBtn) {
        submitBtn.disabled = true;
    }

    let successCount = 0;

    try {
        for (let i = 0; i < pages.length; i++) {
            const page = pages[i];

            if (currentEl) {
                currentEl.textContent = i + 1;
            }
            if (progressBar) {
                progressBar.style.width = `${((i + 1) / pages.length) * 100}%`;
            }

            try {
                // 1. 구 형식으로 복호화
                const decryptedTitle = await window.cryptoManager.decrypt(page.title, password);
                const decryptedContent = await window.cryptoManager.decrypt(page.content, password);

                // 2. 검색 키워드 추출
                function extractSearchKeywords(title, htmlContent) {
                    const tempDiv = document.createElement('div');
                    tempDiv.innerHTML = htmlContent;
                    const textContent = tempDiv.textContent || '';
                    const fullText = title + ' ' + textContent;
                    const words = fullText
                        .toLowerCase()
                        .replace(/[^\w\sㄱ-ㅎㅏ-ㅣ가-힣]/g, ' ')
                        .split(/\s+/)
                        .filter(word => word.length >= 2);
                    return [...new Set(words)];
                }
                const searchKeywords = extractSearchKeywords(decryptedTitle, decryptedContent);

                // 3. 마스터 키로 재암호화 (내용만)
                const contentEncrypted = await window.cryptoManager.encryptWithMasterKey(decryptedContent);
                const searchIndexEncrypted = await window.cryptoManager.encryptWithMasterKey(JSON.stringify(searchKeywords));

                // 4. 서버에 저장 (CSRF 토큰 포함)
                const res = await secureFetch(`/api/pages/${encodeURIComponent(page.id)}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        title: decryptedTitle,  // 제목은 평문으로
                        content: '',  // 내용은 빈 문자열 (암호화됨)
                        contentEncrypted,
                        searchIndexEncrypted,
                        isEncrypted: true
                    })
                });

                if (!res.ok) {
                    throw new Error(`HTTP ${res.status}`);
                }

                successCount++;
                console.log(`페이지 ${page.id} 마이그레이션 완료`);

            } catch (pageError) {
                console.error(`페이지 ${page.id} 마이그레이션 실패:`, pageError);
                // 개별 페이지 실패는 계속 진행
            }
        }

        // 완료
        if (errorEl) {
            errorEl.textContent = '';
        }

        alert(`${successCount}개의 페이지가 성공적으로 변환되었습니다.`);
        closeMigrationModal();

        // 페이지 목록 새로고침
        await fetchPageList();
        renderPageList();

    } catch (error) {
        console.error('마이그레이션 오류:', error);
        if (errorEl) {
            errorEl.textContent = '마이그레이션 중 오류가 발생했습니다. 비밀번호를 확인해 주세요.';
        }
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
        }
        if (progressEl) {
            progressEl.style.display = 'none';
        }
    }
}

// ==================== Collection Encryption ====================
/**
 * 컬렉션 암호화 처리
 */
async function handleCollectionEncryption(collectionId) {
    const collection = appState.collections.find(c => c.id === collectionId);

    if (!collection || !collection.isOwner) {
        alert('컬렉션 소유자만 암호화를 설정할 수 있습니다.');
        return;
    }

    if (!collection.isShared) {
        alert('공유된 컬렉션만 암호화할 수 있습니다.');
        return;
    }

    if (collection.isEncrypted) {
        alert('이미 암호화된 컬렉션입니다.');
        return;
    }

    if (!window.cryptoManager.isMasterKeyInitialized()) {
        alert('마스터 키가 초기화되지 않았습니다. 다시 로그인해 주세요.');
        return;
    }

    const confirmed = confirm(
        `"${collection.name}" 컬렉션을 암호화하시겠습니까?\n\n` +
        '암호화 후에는:\n' +
        '- 이 컬렉션의 모든 페이지가 암호화됩니다.\n' +
        '- 공유받은 사용자도 암호화된 페이지에 접근할 수 있습니다.\n' +
        '- 암호화를 해제할 수 없습니다.'
    );

    if (!confirmed) return;

    try {
        // 1. 컬렉션 키 생성
        const collectionKey = await window.cryptoManager.generateCollectionKey();

        // 2. 컬렉션 키를 소유자의 마스터 키로 암호화
        const encryptedKey = await window.cryptoManager.encryptCollectionKey(collectionKey);

        // 3. 공유된 사용자 목록 가져오기 (TODO: 각 사용자의 공개키로 암호화 필요)
        // 현재는 소유자만 컬렉션 키를 가지고 있고,
        // 공유 사용자는 별도의 메커니즘으로 키를 받아야 함
        const sharedUserKeys = []; // 향후 구현 예정

        // 4. 서버에 암호화 설정 전송 (CSRF 토큰 포함)
        const res = await secureFetch(`/api/collections/${encodeURIComponent(collectionId)}/encrypt`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                encryptedKey,
                sharedUserKeys
            })
        });

        if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
        }

        // 5. 로컬 상태 업데이트
        collection.isEncrypted = true;

        // 6. 컬렉션 목록 다시 로드
        await fetchCollections();
        renderPageList();

        alert('컬렉션이 암호화되었습니다.');

    } catch (error) {
        console.error('컬렉션 암호화 오류:', error);
        alert('컬렉션 암호화에 실패했습니다: ' + error.message);
    }
}

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
            // 암호화된 페이지: 검색 인덱스 복호화
            if (page.searchIndexEncrypted && window.cryptoManager.isMasterKeyInitialized()) {
                try {
                    const indexJson = await window.cryptoManager.decryptWithMasterKey(page.searchIndexEncrypted);
                    const keywords = JSON.parse(indexJson);

                    // 키워드에 검색어가 포함되어 있는지 확인
                    shouldInclude = keywords.some(kw => kw.includes(queryLower));

                    // 제목은 이미 fetchPageList()에서 복호화됨
                    if (shouldInclude) {
                        titleToSearch = page.title || '제목 없음';
                    }
                } catch (error) {
                    console.error(`페이지 ${page.id} 검색 인덱스 복호화 실패:`, error);
                }
            }
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
                collectionId: page.collectionId,
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

// ==================== Icon Picker Modal ====================
const THEME_ICONS = [
    // 문서 및 파일
    'fa-solid fa-file', 'fa-solid fa-file-lines', 'fa-solid fa-file-code', 'fa-solid fa-file-pdf',
    'fa-solid fa-file-word', 'fa-solid fa-file-excel', 'fa-solid fa-file-powerpoint', 'fa-solid fa-file-image',
    'fa-solid fa-file-audio', 'fa-solid fa-file-video', 'fa-solid fa-file-zipper', 'fa-solid fa-folder',
    'fa-solid fa-folder-open', 'fa-solid fa-folder-closed', 'fa-solid fa-book', 'fa-solid fa-book-open',
    'fa-solid fa-bookmark', 'fa-solid fa-clipboard', 'fa-solid fa-clipboard-list', 'fa-solid fa-note-sticky',

    // 표시 및 강조
    'fa-solid fa-star', 'fa-solid fa-heart', 'fa-solid fa-flag', 'fa-solid fa-fire',
    'fa-solid fa-bolt', 'fa-solid fa-lightbulb', 'fa-solid fa-circle-exclamation', 'fa-solid fa-triangle-exclamation',
    'fa-solid fa-circle-check', 'fa-solid fa-circle-xmark', 'fa-solid fa-circle-info', 'fa-solid fa-circle-question',
    'fa-solid fa-bell', 'fa-solid fa-medal', 'fa-solid fa-trophy', 'fa-solid fa-award',

    // 시간 및 날짜
    'fa-solid fa-calendar', 'fa-solid fa-calendar-days', 'fa-solid fa-calendar-check', 'fa-solid fa-clock',
    'fa-solid fa-hourglass', 'fa-solid fa-stopwatch', 'fa-solid fa-business-time',

    // 커뮤니케이션
    'fa-solid fa-envelope', 'fa-solid fa-envelope-open', 'fa-solid fa-comment', 'fa-solid fa-comments',
    'fa-solid fa-message', 'fa-solid fa-phone', 'fa-solid fa-mobile', 'fa-solid fa-fax',

    // 위치 및 지도
    'fa-solid fa-location-dot', 'fa-solid fa-map', 'fa-solid fa-map-pin', 'fa-solid fa-compass',
    'fa-solid fa-globe', 'fa-solid fa-earth-americas', 'fa-solid fa-route',

    // 장소
    'fa-solid fa-home', 'fa-solid fa-building', 'fa-solid fa-shop', 'fa-solid fa-hospital',
    'fa-solid fa-school', 'fa-solid fa-graduation-cap', 'fa-solid fa-church', 'fa-solid fa-landmark',

    // 작업 및 도구
    'fa-solid fa-briefcase', 'fa-solid fa-suitcase', 'fa-solid fa-wrench', 'fa-solid fa-screwdriver-wrench',
    'fa-solid fa-hammer', 'fa-solid fa-gavel', 'fa-solid fa-toolbox', 'fa-solid fa-gear',
    'fa-solid fa-gears', 'fa-solid fa-pen', 'fa-solid fa-pencil', 'fa-solid fa-pen-to-square',

    // 보안
    'fa-solid fa-lock', 'fa-solid fa-unlock', 'fa-solid fa-key', 'fa-solid fa-shield',
    'fa-solid fa-shield-halved', 'fa-solid fa-user-shield',

    // 사용자
    'fa-solid fa-user', 'fa-solid fa-users', 'fa-solid fa-user-tie', 'fa-solid fa-user-group',
    'fa-solid fa-user-doctor', 'fa-solid fa-user-nurse', 'fa-solid fa-user-graduate',

    // 미디어
    'fa-solid fa-image', 'fa-solid fa-camera', 'fa-solid fa-video', 'fa-solid fa-film',
    'fa-solid fa-music', 'fa-solid fa-microphone', 'fa-solid fa-headphones', 'fa-solid fa-photo-film',

    // 기술
    'fa-solid fa-code', 'fa-solid fa-terminal', 'fa-solid fa-laptop', 'fa-solid fa-laptop-code',
    'fa-solid fa-desktop', 'fa-solid fa-mobile-screen', 'fa-solid fa-tablet', 'fa-solid fa-keyboard',
    'fa-solid fa-mouse', 'fa-solid fa-wifi', 'fa-solid fa-database', 'fa-solid fa-server',
    'fa-solid fa-cloud', 'fa-solid fa-microchip', 'fa-solid fa-bug',

    // 교통
    'fa-solid fa-car', 'fa-solid fa-bus', 'fa-solid fa-train', 'fa-solid fa-plane',
    'fa-solid fa-rocket', 'fa-solid fa-bicycle', 'fa-solid fa-ship', 'fa-solid fa-truck',

    // 음식
    'fa-solid fa-pizza-slice', 'fa-solid fa-burger', 'fa-solid fa-mug-hot', 'fa-solid fa-coffee',
    'fa-solid fa-wine-glass', 'fa-solid fa-beer-mug-empty', 'fa-solid fa-apple-whole', 'fa-solid fa-carrot',
    'fa-solid fa-ice-cream', 'fa-solid fa-cake-candles', 'fa-solid fa-cookie',

    // 자연
    'fa-solid fa-tree', 'fa-solid fa-leaf', 'fa-solid fa-seedling', 'fa-solid fa-sun',
    'fa-solid fa-moon', 'fa-solid fa-cloud-sun', 'fa-solid fa-cloud-rain', 'fa-solid fa-snowflake',
    'fa-solid fa-rainbow', 'fa-solid fa-umbrella', 'fa-solid fa-mountain',

    // 기타
    'fa-solid fa-gift', 'fa-solid fa-tag', 'fa-solid fa-tags', 'fa-solid fa-chart-line',
    'fa-solid fa-chart-pie', 'fa-solid fa-chart-bar', 'fa-solid fa-magnifying-glass', 'fa-solid fa-link',
    'fa-solid fa-paperclip', 'fa-solid fa-download', 'fa-solid fa-upload', 'fa-solid fa-battery-full',
    'fa-solid fa-plug', 'fa-solid fa-print', 'fa-solid fa-trash', 'fa-solid fa-box'
];

const COLOR_ICONS = [
    // 이모지 - 얼굴 및 감정
    '😀', '😃', '😄', '😁', '😆', '😅', '🤣', '😂', '🙂', '🙃',
    '😉', '😊', '😇', '🥰', '😍', '🤩', '😘', '😗', '😚', '😙',
    '😋', '😛', '😜', '🤪', '😝', '🤑', '🤗', '🤭', '🤫', '🤔',
    '🤐', '🤨', '😐', '😑', '😶', '😏', '😒', '🙄', '😬', '🤥',
    '😌', '😔', '😪', '🤤', '😴', '😷', '🤒', '🤕', '🤢', '🤮',

    // 동물
    '🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼', '🐨', '🐯',
    '🦁', '🐮', '🐷', '🐸', '🐵', '🐔', '🐧', '🐦', '🐤', '🦆',
    '🦅', '🦉', '🦇', '🐺', '🐗', '🐴', '🦄', '🐝', '🐛', '🦋',
    '🐌', '🐞', '🐜', '🦟', '🦗', '🕷', '🐢', '🐍', '🦎', '🐙',
    '🦑', '🦐', '🦀', '🐡', '🐠', '🐟', '🐬', '🐳', '🐋', '🦈',

    // 식물 및 자연
    '🌸', '🌺', '🌻', '🌷', '🌹', '🥀', '🌼', '🌿', '🍀', '🍁',
    '🍂', '🍃', '🌾', '🌱', '🌲', '🌳', '🌴', '🌵', '🌊', '🌈',

    // 음식 및 음료
    '🍎', '🍏', '🍐', '🍊', '🍋', '🍌', '🍉', '🍇', '🍓', '🍈',
    '🍒', '🍑', '🥭', '🍍', '🥥', '🥝', '🍅', '🥑', '🍆', '🥔',
    '🥕', '🌽', '🌶', '🥒', '🥬', '🥦', '🧄', '🧅', '🍄', '🥜',
    '🍞', '🥐', '🥖', '🥨', '🥯', '🧇', '🥞', '🧈', '🍕', '🍔',
    '🌭', '🥪', '🌮', '🌯', '🥙', '🧆', '🍟', '🍗', '🍖', '🦴',
    '☕', '🍵', '🧃', '🥤', '🍶', '🍺', '🍻', '🥂', '🍷', '🥃',
    '🍰', '🎂', '🧁', '🍮', '🍩', '🍪', '🍫', '🍬', '🍭', '🍡',

    // 활동 및 스포츠
    '⚽', '🏀', '🏈', '⚾', '🥎', '🎾', '🏐', '🏉', '🥏', '🎱',
    '🏓', '🏸', '🏒', '🏑', '🥍', '🏏', '🥅', '⛳', '🏹', '🎣',
    '🥊', '🥋', '🎽', '🛹', '🛼', '⛸', '🥌', '🎿', '⛷', '🏂',

    // 교통 수단
    '🚗', '🚕', '🚙', '🚌', '🚎', '🏎', '🚓', '🚑', '🚒', '🚐',
    '🚚', '🚛', '🚜', '🛴', '🚲', '🛵', '🏍', '🛺', '🚁', '🛩',
    '✈️', '🚀', '🛸', '🚂', '🚊', '🚝', '🚄', '🚅', '🚆', '🚇',
    '🚈', '🚉', '🚞', '⛴', '🛳', '⛵', '🚤', '🛶', '⚓',

    // 장소 및 건물
    '🏠', '🏡', '🏢', '🏣', '🏤', '🏥', '🏦', '🏨', '🏩', '🏪',
    '🏫', '🏬', '🏭', '🏯', '🏰', '💒', '🗼', '🗽', '⛪', '🕌',
    '🛕', '🕍', '⛩', '🕋', '⛲', '⛺', '🌁', '🌃', '🏙', '🌄',

    // 물건 및 도구
    '⌚', '📱', '💻', '⌨️', '🖥', '🖨', '🖱', '💽', '💾', '💿',
    '📀', '📷', '📹', '🎥', '📞', '☎️', '📟', '📠', '📺', '📻',
    '⏰', '⏱', '⏲', '🕰', '⏳', '⌛', '📡', '🔋', '🔌', '💡',
    '🔦', '🕯', '🪔', '🧯', '🛢', '💸', '💵', '💴', '💶', '💷',
    '🔨', '⚒', '🛠', '⛏', '🔧', '🔩', '⚙️', '⛓', '🔫', '💣',
    '🔪', '🗡', '⚔️', '🛡', '🔐', '🔑', '🗝', '🔓', '🔒', '📌',

    // 기호 및 이모지
    '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔',
    '❣️', '💕', '💞', '💓', '💗', '💖', '💘', '💝', '⭐', '🌟',
    '✨', '💫', '💥', '💢', '💦', '💨', '🔥', '☀️', '⛅', '☁️',
    '🌤', '⛈', '🌧', '⚡', '❄️', '☃️', '⛄', '🌬', '💨', '🌪',
    '🎈', '🎉', '🎊', '🎁', '🎀', '🏆', '🥇', '🥈', '🥉', '🏅'
];

let currentIconPageId = null;
let currentIconTab = 'theme'; // 'theme' or 'color'

function showIconPickerModal(pageId) {
    currentIconPageId = pageId;
    currentIconTab = 'theme'; // 기본 탭으로 시작
    const modal = document.getElementById('icon-picker-modal');

    // 탭 버튼 활성화 상태 업데이트
    updateTabButtons();

    // 아이콘 그리드 렌더링
    renderIconGrid();

    modal.classList.remove('hidden');
}

function updateTabButtons() {
    const themeTabBtn = document.getElementById('icon-tab-theme');
    const colorTabBtn = document.getElementById('icon-tab-color');

    if (currentIconTab === 'theme') {
        themeTabBtn.classList.add('active');
        colorTabBtn.classList.remove('active');
    } else {
        themeTabBtn.classList.remove('active');
        colorTabBtn.classList.add('active');
    }
}

function switchIconTab(tab) {
    currentIconTab = tab;
    updateTabButtons();
    renderIconGrid();
}

function renderIconGrid() {
    const grid = document.getElementById('icon-picker-grid');
    const page = appState.pages.find(p => p.id === currentIconPageId);
    const currentIcon = page ? page.icon : null;

    const icons = currentIconTab === 'theme' ? THEME_ICONS : COLOR_ICONS;

    // 아이콘 그리드 생성
    grid.innerHTML = '';
    icons.forEach(icon => {
        const button = document.createElement('button');
        button.className = 'icon-picker-item';

        if (currentIconTab === 'theme') {
            // Font Awesome 아이콘
            button.innerHTML = `<i class="${icon}"></i>`;
        } else {
            // 이모지
            button.textContent = icon;
            button.style.fontSize = '24px';
        }

        button.dataset.icon = icon;

        // 현재 선택된 아이콘 표시
        if (icon === currentIcon) {
            button.classList.add('selected');
        }

        button.addEventListener('click', () => {
            selectIcon(icon);
        });

        grid.appendChild(button);
    });
}

function closeIconPickerModal() {
    const modal = document.getElementById('icon-picker-modal');
    modal.classList.add('hidden');
    currentIconPageId = null;
}

async function selectIcon(iconClass) {
    if (!currentIconPageId) return;

    try {
        const res = await secureFetch(`/api/pages/${encodeURIComponent(currentIconPageId)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ icon: iconClass })
        });

        if (!res.ok) {
            throw new Error('HTTP ' + res.status);
        }

        // 상태 업데이트
        const page = appState.pages.find(p => p.id === currentIconPageId);
        if (page) {
            page.icon = iconClass;
        }

        renderPageList();
        closeIconPickerModal();
        alert('아이콘이 설정되었습니다.');
    } catch (error) {
        console.error('아이콘 설정 오류:', error);
        alert('아이콘 설정 중 오류가 발생했습니다.');
    }
}

async function removeIcon() {
    if (!currentIconPageId) return;

    try {
        const res = await secureFetch(`/api/pages/${encodeURIComponent(currentIconPageId)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ icon: '' })
        });

        if (!res.ok) {
            throw new Error('HTTP ' + res.status);
        }

        // 상태 업데이트
        const page = appState.pages.find(p => p.id === currentIconPageId);
        if (page) {
            page.icon = null;
        }

        renderPageList();
        closeIconPickerModal();
        alert('아이콘이 제거되었습니다.');
    } catch (error) {
        console.error('아이콘 제거 오류:', error);
        alert('아이콘 제거 중 오류가 발생했습니다.');
    }
}

function bindIconPickerModal() {
    const modal = document.getElementById('icon-picker-modal');
    const closeBtn = document.getElementById('close-icon-picker-btn');
    const removeBtn = document.getElementById('remove-icon-btn');
    const overlay = modal.querySelector('.modal-overlay');
    const themeTabBtn = document.getElementById('icon-tab-theme');
    const colorTabBtn = document.getElementById('icon-tab-color');

    closeBtn.addEventListener('click', closeIconPickerModal);
    overlay.addEventListener('click', closeIconPickerModal);
    removeBtn.addEventListener('click', removeIcon);
    themeTabBtn.addEventListener('click', () => switchIconTab('theme'));
    colorTabBtn.addEventListener('click', () => switchIconTab('color'));
}

// ==================== Global Window Functions ====================
// 일부 함수들은 다른 모듈이나 inline 이벤트에서 접근 필요
window.showEncryptionModal = showEncryptionModal;
window.showDecryptionModal = showDecryptionModal;
window.openShareModal = openShareModal;
window.removeShare = removeShare;
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
