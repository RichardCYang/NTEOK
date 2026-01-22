/**
 * NTEOK 메인 애플리케이션
 * 모듈화된 구조로 재구성
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
import { initEditor, bindToolbar, bindSlashKeyHandlers, updateToolbarState } from './editor.js';
import {
    initPagesManager,
    applyCollectionsData,
    applyPagesData,
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

// ==================== Global State ====================
const appState = {
    editor: null,
    pages: [],
    collections: [],
    currentPageId: null,
    currentCollectionId: null,
    expandedCollections: new Set(),
    expandedPages: new Set(),
    isWriteMode: false,
    currentPageIsEncrypted: false,  // 현재 페이지의 암호화 상태
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

        const contextMenu = document.querySelector("#context-menu");
        const isAlreadyOpen = contextMenu && !contextMenu.classList.contains("hidden") && 
                             contextMenu.dataset.triggerId === colMenuBtn.dataset.collectionId;

        closeAllDropdowns();
        closeContextMenu();

        // 이미 같은 버튼에 의해 메뉴가 열려있었다면 닫고 종료 (토글 기능)
        if (isAlreadyOpen) {
            return;
        }

        const collectionId = colMenuBtn.dataset.collectionId;
        // 메뉴가 어떤 버튼에 의해 열렸는지 식별하기 위해 ID 저장
        if (contextMenu) contextMenu.dataset.triggerId = collectionId;
        const isOwner = colMenuBtn.dataset.isOwner === 'true';
        const permission = colMenuBtn.dataset.permission;
        const collection = appState.collections.find(c => c.id === collectionId);

        let menuItems = '';
        if (isOwner) {
            // 공유된 컬렉션이고 아직 암호화되지 않았으면 암호화 옵션 표시
            const showEncryptOption = collection && collection.isShared && !collection.isEncrypted;

            menuItems = `
                <button data-action="collection-settings" data-collection-id="${escapeHtml(collectionId)}">
                    <i class="fa-solid fa-cog"></i>
                    컬렉션 설정
                </button>
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
    const colMenuAction = event.target.closest("#context-menu button[data-action^='collection-settings'], #context-menu button[data-action^='share-collection'], #context-menu button[data-action^='delete-collection'], #context-menu button[data-action^='encrypt-collection']");
    if (colMenuAction) {
        const action = colMenuAction.dataset.action;
        const colId = colMenuAction.dataset.collectionId;

        if (action === "collection-settings" && colId) {
            await showCollectionSettingsModal(colId);
            closeContextMenu();
            return;
        }

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
                await api.del("/api/collections/" + encodeURIComponent(colId));
                
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

    // 페이지에 하위 페이지 추가
    const addSubpageBtn = event.target.closest(".page-add-subpage-btn");
    if (addSubpageBtn) {
        event.stopPropagation();
        const parentPageId = addSubpageBtn.dataset.pageId;
        const colId = addSubpageBtn.dataset.collectionId;
        if (!parentPageId || !colId) return;

        const defaultTitle = (appState.translations && appState.translations['new_page']) || "새 페이지";
        const promptMsg = (appState.translations && appState.translations['new_subpage_prompt']) || "새 하위 페이지 제목을 입력하세요.";
        let title = prompt(promptMsg, defaultTitle);
        if (title === null) return;

        const plainTitle = title.trim() || defaultTitle;
        const plainContent = "<p></p>";

        try {
            const page = await api.post("/api/pages", {
                title: plainTitle,
                content: plainContent,
                parentId: parentPageId,
                collectionId: colId
            });

            state.pages.unshift({
                id: page.id,
                title: plainTitle,
                updatedAt: page.updatedAt,
                parentId: parentPageId,
                collectionId: colId,
                sortOrder: page.sortOrder || 0
            });

            // 하위 페이지 추가 시 부모 페이지 확장
            state.expandedPages.add(parentPageId);

            renderPageList();

            // 현재 페이지가 부모 페이지라면 하위 페이지 섹션 업데이트
            if (state.currentPageId === parentPageId) {
                await loadAndRenderSubpages(parentPageId);
            }

            alert("하위 페이지가 생성되었습니다.");
        } catch (error) {
            console.error("하위 페이지 생성 오류:", error);
            alert("하위 페이지를 생성하지 못했습니다: " + error.message);
        }
        return;
    }

    // 컬렉션에 페이지 추가
    const addBtn = event.target.closest(".collection-add-page-btn");
    if (addBtn) {
        const colId = addBtn.dataset.collectionId;
        if (!colId) return;
        state.expandedCollections.add(colId);

        const defaultTitle = (appState.translations && appState.translations['new_page']) || "새 페이지";
        const promptMsg = (appState.translations && appState.translations['new_page_prompt']) || "새 페이지 제목을 입력하세요.";
        let title = prompt(promptMsg, defaultTitle);
        if (title === null) return;

        const plainTitle = title.trim() || defaultTitle;
        const plainContent = "<p></p>";

        try {
            const page = await api.post("/api/pages", {
                title: plainTitle,
                content: plainContent,
                parentId: null,
                collectionId: colId
            });

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

        const contextMenu = document.querySelector("#context-menu");
        const isAlreadyOpen = contextMenu && !contextMenu.classList.contains("hidden") && 
                             contextMenu.dataset.triggerId === pageMenuBtn.dataset.pageId;

        closeAllDropdowns();
        closeContextMenu();

        // 이미 같은 버튼에 의해 메뉴가 열려있었다면 닫고 종료 (토글 기능)
        if (isAlreadyOpen) {
            return;
        }

        const pageId = pageMenuBtn.dataset.pageId;
        // 메뉴가 어떤 버튼에 의해 열렸는지 식별하기 위해 ID 저장
        if (contextMenu) contextMenu.dataset.triggerId = pageId;
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
                    <button data-action="export-pdf" data-page-id="${escapeHtml(pageId)}">
                        <i class="fa-solid fa-file-pdf"></i>
                        PDF로 내보내기
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
                    <button data-action="export-pdf" data-page-id="${escapeHtml(pageId)}">
                        <i class="fa-solid fa-file-pdf"></i>
                        PDF로 내보내기
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
                <button data-action="export-pdf" data-page-id="${escapeHtml(pageId)}">
                    <i class="fa-solid fa-file-pdf"></i>
                    PDF로 내보내기
                </button>
                <button data-action="encrypt-page" data-page-id="${escapeHtml(pageId)}">
                    <i class="fa-solid fa-lock"></i>
                    암호화 설정
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
    const pageMenuAction = event.target.closest("#context-menu button[data-action^='set-icon'], #context-menu button[data-action^='export-pdf'], #context-menu button[data-action^='encrypt-page'], #context-menu button[data-action^='delete-page'], #context-menu button[data-action^='toggle-share']");
    if (pageMenuAction) {
        const action = pageMenuAction.dataset.action;
        const pageId = pageMenuAction.dataset.pageId;

        if (action === "set-icon" && pageId) {
            showIconPickerModal(pageId);
            closeContextMenu();
            return;
        }

        if (action === "export-pdf" && pageId) {
            closeContextMenu();
            await handleExportPDF(pageId);
            return;
        }

        if (action === "encrypt-page" && pageId) {
            const page = appState.pages.find(p => p.id === pageId);
            if (page && page.isEncrypted) {
                alert('이미 암호화된 페이지입니다.');
            } else {
                showEncryptionModal(pageId);
            }
            closeContextMenu();
            return;
        }

        if (action === "toggle-share" && pageId) {
            const currentShareAllowed = pageMenuAction.dataset.shareAllowed === 'true';
            const newShareAllowed = !currentShareAllowed;

            // API 호출
            api.put(`/api/pages/${encodeURIComponent(pageId)}/share-permission`, { shareAllowed: newShareAllowed })
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
                await api.del("/api/pages/" + encodeURIComponent(pageId));
                
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
                if (error.status === 403) {
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

    // 페이지 접기/펼치기 토글 선택
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

    // 페이지 선택
    const li = event.target.closest("li.page-list-item");
    if (!li) return;

    const pageId = li.dataset.pageId;
    if (!pageId || pageId === state.currentPageId) return;

    closeContextMenu();

    // 암호화된 페이지인지 확인
    const page = state.pages.find(p => p.id === pageId);
    if (page && page.isEncrypted) {
        // 암호화된 페이지 클릭 시 복호화 모달 표시
        showDecryptionModal(page);
        return;
    }

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
            await api.post("/api/auth/logout");

            // 암호화 키 삭제
            if (typeof window.cryptoManager !== 'undefined') {
                window.cryptoManager.clearKey();
                window.cryptoManager.clearMasterKey();
                appState.decryptionKeyIsInMemory = false;
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
    toggleModal("#readonly-warning-modal", true);
}

/**
 * 읽기 전용 경고 모달 닫기
 */
async function closeReadonlyWarningModal() {
    toggleModal("#readonly-warning-modal", false);

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
            textEl.textContent = (appState.translations && appState.translations['mode_write']) || "쓰기모드";
            textEl.setAttribute('data-i18n', 'mode_write');
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

    bindModalOverlayClick(document.querySelector("#readonly-warning-modal"), closeReadonlyWarningModal);
}

/**
 * 삭제 권한 없음 모달 표시
 */
function showDeletePermissionModal() {
    toggleModal("#delete-permission-modal", true);
}

/**
 * 삭제 권한 없음 모달 닫기
 */
function closeDeletePermissionModal() {
    toggleModal("#delete-permission-modal", false);
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

    bindModalOverlayClick(document.querySelector("#delete-permission-modal"), closeDeletePermissionModal);
}

/**
 * 암호화 권한 없음 모달 표시
 */
function showEncryptPermissionModal() {
    toggleModal("#encrypt-permission-modal", true);
}

/**
 * 암호화 권한 없음 모달 닫기
 */
function closeEncryptPermissionModal() {
    toggleModal("#encrypt-permission-modal", false);
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

    bindModalOverlayClick(document.querySelector("#encrypt-permission-modal"), closeEncryptPermissionModal);
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
    showLoadingOverlay();
    try {
        // appState를 전역으로 노출 (에디터 등에서 접근 가능하도록)
        window.appState = appState;

        // 설정 로드
        const loadedSettings = loadSettings();
        appState.userSettings = loadedSettings;

        // 에디터 초기화 (Yjs 동기화 준비 전)
        appState.editor = await initEditor(null);
        const titleInput = document.querySelector("#page-title-input");
        if (titleInput) {
            titleInput.value = "시작하기 👋";
        }
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

        // 페이지 발행 관리자 초기화
        initPublishManager(appState);

        // 하위 페이지 관리자 초기화
        initSubpagesManager(appState);

        // 댓글 관리자 초기화
        initCommentsManager(appState);

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
        bindCollectionSettingsModal();
        bindReadonlyWarningModal();
        bindDeletePermissionModal();
        bindEncryptPermissionModal();
        bindIconPickerModal();
        bindMobileSidebar();
        bindPublishEvents();
        bindTotpModals();
        bindPasskeyModals();
        bindAccountManagementButtons();
        bindLoginLogsModal();

        try {
            const bootstrap = await api.get("/api/bootstrap");

            if (bootstrap.user) {
                applyCurrentUser(bootstrap.user);
            }

            if (Array.isArray(bootstrap.collections)) {
                applyCollectionsData(bootstrap.collections);
            }

            if (Array.isArray(bootstrap.pages)) {
                applyPagesData(bootstrap.pages);
            }

            if (Array.isArray(bootstrap.collections) || Array.isArray(bootstrap.pages)) {
                renderPageList();
            }

        } catch (error) {
            console.warn("Bootstrap load failed, falling back to legacy flow:", error);
        }

        // 데이터 로드 - 완전 병렬 처리로 최적화 (성능 개선)
        try {
            // 사용자 정보, 컬렉션, 페이지를 모두 병렬로 로드
            const [userResult, collectionsResult, pagesResult] = await Promise.allSettled([
                fetchAndDisplayCurrentUser(),
                fetchCollections(),
                fetchPageList()
            ]);

            // 에러 처리
            if (userResult.status === 'rejected') {
                console.error('사용자 정보 로드 실패:', userResult.reason);
                // 사용자 정보는 UI에 표시되지만 치명적이지 않음
            }

            if (collectionsResult.status === 'rejected') {
                console.error('컬렉션 로드 실패:', collectionsResult.reason);
                showErrorInEditor('컬렉션을 불러오지 못했습니다.');
            }

            if (pagesResult.status === 'rejected') {
                console.error('페이지 로드 실패:', pagesResult.reason);
                showErrorInEditor('페이지 목록을 불러오지 못했습니다.');
            }

            // 모든 데이터 로드 완료 후 UI 한 번만 렌더링 (중복 호출 방지)
            if (collectionsResult.status === 'fulfilled' || pagesResult.status === 'fulfilled') {
                renderPageList();

                // 첫 번째 페이지 자동 로드 (암호화되지 않은 경우만)
                if (appState.pages && appState.pages.length > 0) {
                    // 첫 번째 루트 페이지 찾기
                    const rootPages = appState.pages.filter(p => !p.parentId);
                    const firstPage = rootPages.length > 0 ? rootPages[0] : appState.pages[0];
                    
                    if (!firstPage.isEncrypted) {
                        loadPage(firstPage.id);
                    }
                }
            }
        } catch (error) {
            console.error('초기화 중 오류:', error);
            showErrorInEditor('데이터 로드에 실패했습니다. 페이지를 새로고침하세요.');
        }
    } finally {
        hideLoadingOverlay();
    }
}

// ==================== 마스터 키 시스템 제거됨 ====================
// 선택적 암호화 시스템으로 변경되어 마스터 키 관련 코드 제거됨

// ==================== Collection Settings ====================
let currentSettingsCollectionId = null;

/**
 * 컬렉션 설정 모달 표시
 */
async function showCollectionSettingsModal(collectionId) {
    const collection = appState.collections.find(c => c.id === collectionId);
    if (!collection) {
        alert('컬렉션을 찾을 수 없습니다.');
        return;
    }

    if (!collection.isOwner) {
        alert('컬렉션 소유자만 설정을 변경할 수 있습니다.');
        return;
    }

    currentSettingsCollectionId = collectionId;

    // 현재 설정 값 로드
    const nameInput = document.getElementById('collection-name-input');
    const defaultEncryptionCheckbox = document.getElementById('collection-default-encryption');
    const enforceEncryptionCheckbox = document.getElementById('collection-enforce-encryption');

    if (nameInput) {
        nameInput.value = collection.name || '';
    }
    if (defaultEncryptionCheckbox) {
        defaultEncryptionCheckbox.checked = collection.defaultEncryption || false;
    }
    if (enforceEncryptionCheckbox) {
        enforceEncryptionCheckbox.checked = collection.enforceEncryption || false;
    }

    // 모달 표시
    const modal = document.getElementById('collection-settings-modal');
    if (modal) {
        modal.classList.remove('hidden');
    }
}

/**
 * 컬렉션 설정 모달 닫기
 */
function closeCollectionSettingsModal() {
    const modal = document.getElementById('collection-settings-modal');
    if (modal) {
        modal.classList.add('hidden');
    }

    const errorEl = document.getElementById('collection-settings-error');
    if (errorEl) {
        errorEl.textContent = '';
    }

    currentSettingsCollectionId = null;
}

/**
 * 컬렉션 설정 저장
 */
async function saveCollectionSettings(event) {
    event.preventDefault();

    if (!currentSettingsCollectionId) {
        return;
    }

    const nameInput = document.getElementById('collection-name-input');
    const name = nameInput?.value?.trim() || '';
    const defaultEncryption = document.getElementById('collection-default-encryption')?.checked || false;
    const enforceEncryption = document.getElementById('collection-enforce-encryption')?.checked || false;
    const errorEl = document.getElementById('collection-settings-error');
    const submitBtn = event.target.querySelector('button[type="submit"]');

    // 이름 유효성 검사
    if (!name) {
        if (errorEl) {
            errorEl.textContent = '컬렉션 이름을 입력해주세요.';
        }
        return;
    }

    if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = '저장 중...';
    }

    try {
        await api.put(`/api/collections/${encodeURIComponent(currentSettingsCollectionId)}`, {
            name,
            defaultEncryption,
            enforceEncryption
        });

        // 낙관적 업데이트: 로컬 상태만 업데이트 (서버 재요청 불필요)
        const collection = appState.collections.find(c => c.id === currentSettingsCollectionId);
        if (collection) {
            collection.name = name;
            collection.defaultEncryption = defaultEncryption;
            collection.enforceEncryption = enforceEncryption;
        }

        // UI만 업데이트 (전체 재로드 없이)
        renderPageList();

        closeCollectionSettingsModal();
        alert('컬렉션 설정이 저장되었습니다.');

    } catch (error) {
        console.error('컬렉션 설정 저장 오류:', error);
        if (errorEl) {
            errorEl.textContent = error.message || '설정 저장에 실패했습니다.';
        }
    } finally {
        if (submitBtn) {
            submitBtn.disabled = false;
            submitBtn.textContent = '저장';
        }
    }
}

/**
 * 컬렉션 설정 모달 바인딩
 */
function bindCollectionSettingsModal() {
    const form = document.getElementById('collection-settings-form');
    if (form) {
        form.addEventListener('submit', saveCollectionSettings);
    }

    const closeBtn = document.getElementById('close-collection-settings-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeCollectionSettingsModal);
    }

    const cancelBtn = document.getElementById('cancel-collection-settings-btn');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeCollectionSettingsModal);
    }

    const modal = document.getElementById('collection-settings-modal');
    if (modal) {
        const overlay = modal.querySelector('.modal-overlay');
        if (overlay) {
            overlay.addEventListener('click', closeCollectionSettingsModal);
        }
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
			addIcon(button, icon);
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
        await api.put(`/api/pages/${encodeURIComponent(currentIconPageId)}`, { icon: iconClass });

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
        await api.put(`/api/pages/${encodeURIComponent(currentIconPageId)}`, { icon: '' });

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

// ==================== PDF Export Handler ====================
/**
 * PDF 내보내기 핸들러
 */
async function handleExportPDF(pageId) {
    try {
        await exportPageToPDF(pageId);
    } catch (error) {
        console.error('PDF 내보내기 실패:', error);
        alert('PDF 내보내기에 실패했습니다.');
    }
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
window.loadAndRenderSubpages = loadAndRenderSubpages;
window.handleSubpageMetadataChange = handleSubpageMetadataChange;
window.syncSubpagesPadding = syncSubpagesPadding;

// ==================== Start Application ====================
document.addEventListener("DOMContentLoaded", () => {
    init();
});