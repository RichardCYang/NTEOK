/**
 * 페이지 관리 모듈 (컬렉션 제거 버전)
 */

import { escapeHtml, showErrorInEditor, syncPageUpdatedAtPadding, closeSidebar } from './ui-utils.js';
import * as api from './api-utils.js';
import { loadAndRenderComments } from './comments-manager.js';
import { startPageSync, stopPageSync, startStorageSync, stopStorageSync, flushPendingUpdates, syncEditorFromMetadata, onLocalEditModeChanged, updateAwarenessMode } from './sync-manager.js';
import { showCover, hideCover, updateCoverButtonsVisibility } from './cover-manager.js';
import { checkPublishStatus, updatePublishButton } from './publish-manager.js';
import { loadAndRenderSubpages, onEditModeChange } from './subpages-manager.js';
import { sanitizeEditorHtml } from './sanitize.js';
import { EXAMPLE_CONTENT } from './editor.js';

// 전역 상태
let state = {
    editor: null,
    pages: [],
    currentStorageId: null,
    currentStoragePermission: null,
    currentStorageIsEncrypted: false,
    expandedPages: new Set(),
    isWriteMode: false,
    currentPageIsEncrypted: false
};

/**
 * 상태 초기화
 */
export function initPagesManager(appState) {
    state = appState;
    if (state.currentStorageIsEncrypted === undefined) state.currentStorageIsEncrypted = false;
}

/**
 * 페이지 목록 가져오기
 */
export async function fetchPageList() {
    if (!state.currentStorageId) {
        console.warn("페이지 목록 요청 중단: 선택된 저장소가 없습니다.");
        applyPagesData([]);
        renderPageList();
        return;
    }

    try {
        const url = `/api/pages?storageId=${encodeURIComponent(state.currentStorageId)}`;
        console.log(`페이지 목록 요청: GET ${url}`);
        const data = await api.get(url);
        
        applyPagesData(data);

        if (!state.pages.length) {
            if (state.editor) {
                state.editor.commands.setContent(EXAMPLE_CONTENT, { emitUpdate: false });
                const titleInput = document.querySelector("#page-title-input");
                if (titleInput) {
                    titleInput.value = "시작하기 👋";
                }
            }
        }
    } catch (error) {
        console.error("페이지 목록 요청 오류:", error);
        showErrorInEditor("페이지 목록을 불러오는 데 실패했다: " + error.message, state.editor);
    }
}

export function applyPagesData(data, isEncryptedStorage = false) {
    const pages = Array.isArray(data) ? data : [];
    state.pages.length = 0;
    state.pages.push(...pages);
    state.currentStorageIsEncrypted = !!isEncryptedStorage;
}

/**
 * 트리 구조 생성
 */
export function buildPageTree(flatPages) {
    const map = new Map();
    flatPages.forEach((p) => {
        map.set(p.id, {
            ...p,
            parentId: p.parentId || null,
            children: []
        });
    });

    const roots = [];
    map.forEach((node) => {
        if (node.parentId && map.has(node.parentId)) {
            map.get(node.parentId).children.push(node);
        } else {
            roots.push(node);
        }
    });

    const sortFn = (a, b) => {
        const aOrder = a.sortOrder || 0;
        const bOrder = b.sortOrder || 0;
        if (aOrder !== bOrder) return aOrder - bOrder;
        return new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime();
    };

    function sortNodes(nodes) {
        nodes.sort(sortFn);
        nodes.forEach(n => { if (n.children.length) sortNodes(n.children); });
    }

    sortNodes(roots);
    return roots;
}

/**
 * 페이지 목록 렌더링
 */
export function renderPageList() {
    const listEl = document.querySelector("#page-list");
    if (!listEl) return;

    listEl.innerHTML = "";

    if (!state.pages.length) {
        const empty = document.createElement("li");
        empty.className = "page-empty";
        empty.textContent = "페이지가 없습니다. 아래에서 새 페이지를 추가하세요.";
        listEl.appendChild(empty);
        return;
    }

    const fragment = document.createDocumentFragment();
    const tree = buildPageTree(state.pages);

    function renderNode(node, depth) {
        const li = document.createElement("li");
        li.className = "page-list-item";
        li.dataset.pageId = node.id;
        if (node.id === state.currentPageId) li.classList.add("active");

        const hasChildren = node.children && node.children.length > 0;
        const isExpanded = state.expandedPages.has(node.id);

        li.style.paddingLeft = (12 + depth * 16) + "px";

        const row = document.createElement("div");
        row.style.cssText = "display:flex; align-items:center; justify-content:space-between; gap:8px;";

        const titleWrap = document.createElement("div");
        titleWrap.style.cssText = "display:flex; align-items:center; gap:4px; flex:1; min-width:0;";

        const toggleSpan = document.createElement("span");
        toggleSpan.className = "page-toggle";
        if (isExpanded) toggleSpan.classList.add("expanded");
        if (hasChildren) {
            toggleSpan.innerHTML = '<i class="fa-solid fa-caret-right"></i>';
            toggleSpan.style.cursor = "pointer";
            toggleSpan.dataset.pageId = node.id;
        } else {
            toggleSpan.style.visibility = "hidden";
            toggleSpan.innerHTML = '<i class="fa-solid fa-caret-right"></i>';
        }
        titleWrap.appendChild(toggleSpan);

        const titleSpan = document.createElement("span");
        titleSpan.className = "page-list-item-title";
        
        const iconEl = (() => {
            if (node.icon) {
                if (node.icon.startsWith('fa-')) {
                    const i = document.createElement('i');
                    i.className = node.icon;
                    i.style.cssText = "margin-right:6px; color:#2d5f5d;";
                    return i;
                }
                const s = document.createElement('span');
                s.style.cssText = "margin-right:6px; font-size:16px;";
                s.textContent = node.icon;
                return s;
            }
            if (node.isEncrypted) {
                const i = document.createElement('i');
                i.className = "fa-solid fa-lock";
                i.style.cssText = "margin-right:6px; color:#2d5f5d;";
                return i;
            }
            const i = document.createElement('i');
            i.className = hasChildren ? "fa-regular fa-file-lines" : "fa-regular fa-file";
            i.style.cssText = "margin-right:6px; color:#6b7280;";
            return i;
        })();

        if (iconEl) titleSpan.appendChild(iconEl);
        titleSpan.appendChild(document.createTextNode(node.title || "제목 없음"));
        titleWrap.appendChild(titleSpan);

        const right = document.createElement("div");
        right.className = "page-menu-wrapper";
        right.style.cssText = "display:flex; align-items:center; gap:4px;";

        const canEdit = state.currentStoragePermission === 'EDIT' || state.currentStoragePermission === 'ADMIN';

        if (canEdit) {
            const addSubBtn = document.createElement("button");
            addSubBtn.className = "page-add-subpage-btn";
            addSubBtn.dataset.pageId = node.id;
            addSubBtn.innerHTML = '<i class="fa-solid fa-plus"></i>';

            const menuBtn = document.createElement("button");
            menuBtn.className = "page-menu-btn";
            menuBtn.dataset.pageId = node.id;
            menuBtn.dataset.isEncrypted = node.isEncrypted;
            menuBtn.innerHTML = '<i class="fa-solid fa-ellipsis-vertical"></i>';

            right.appendChild(addSubBtn);
            right.appendChild(menuBtn);
        }

        row.appendChild(titleWrap);
        row.appendChild(right);
        li.appendChild(row);
        fragment.appendChild(li);

        if (hasChildren && isExpanded) {
            node.children.forEach(child => renderNode(child, depth + 1));
        }
    }

    tree.forEach(node => renderNode(node, 0));
    listEl.appendChild(fragment);
    
    // 드래그 앤 드롭 (추후 저장소 단위로 재구현 필요 시 확장)
}

/**
 * 현재 페이지 상태 초기화 (저장소 전환 시 등)
 */
export function clearCurrentPage() {
    state.currentPageId = null;
    state.currentPageIsEncrypted = false;
    state.isWriteMode = false;

    stopPageSync();
    hideCover();

    if (state.editor) {
        state.editor.commands.setContent(EXAMPLE_CONTENT, { emitUpdate: false });
        state.editor.setEditable(false);
    }

    const titleInput = document.querySelector("#page-title-input");
    if (titleInput) titleInput.value = "시작하기 👋";

    const updatedAtEl = document.querySelector("#page-updated-at");
    if (updatedAtEl) updatedAtEl.textContent = "-";

    const modeToggleBtn = document.querySelector("#mode-toggle-btn");
    if (modeToggleBtn) {
        modeToggleBtn.classList.remove("write-mode");
        modeToggleBtn.style.display = 'none';
    }

    // 저장소 권한에 따라 새 페이지 버튼 표시 여부 결정
    const canEdit = state.currentStoragePermission === 'EDIT' || state.currentStoragePermission === 'ADMIN';
    const newPageBtn = document.querySelector("#new-page-btn");
    if (newPageBtn) {
        newPageBtn.style.display = canEdit ? 'flex' : 'none';
    }

    // 서브페이지 및 댓글 영역 초기화
    const subpagesContainer = document.querySelector("#subpages-container");
    if (subpagesContainer) subpagesContainer.innerHTML = "";
    
    const commentsContainer = document.querySelector("#page-comments-section");
    if (commentsContainer) {
        commentsContainer.innerHTML = "";
        commentsContainer.classList.add("hidden");
    }
    
    updatePublishButton();
}

/**
 * 페이지 로드
 */
export async function loadPage(id) {
    if (!id) {
        clearCurrentPage();
        return;
    }

    if (state.isWriteMode && state.currentPageId) {
        await saveCurrentPage();
        // 읽기 모드로 전환 로직 (생략 - app.js 등에서 통합 관리 권장)
    }

    stopPageSync();

    try {
        const page = await api.get("/api/pages/" + encodeURIComponent(id));
        state.currentPageId = page.id;

        // 부모 확장
        let curr = page.parentId;
        while (curr) {
            state.expandedPages.add(curr);
            const p = state.pages.find(x => x.id === curr);
            curr = p ? p.parentId : null;
        }

        let title = page.title || "";
        let content = page.content || "<p></p>";
        let isDecrypted = false;

        if (page.isEncrypted) {
            state.currentPageIsEncrypted = true;
            const storageKey = window.cryptoManager.getStorageKey();
            if (storageKey) {
                try {
                    // encrypted_content는 카멜케이스 변환에 따라 encryptedContent로 올 수 있음.
                    // API 응답 확인 필요하지만 보통 JSON 응답은 encryptedContent
                    const encrypted = page.encryptedContent || page.encrypted_content;
                    if (encrypted) {
                        content = await window.cryptoManager.decryptWithKey(encrypted, storageKey);
                        isDecrypted = true;
                    }
                } catch (e) {
                    console.error("Auto-decryption failed:", e);
                    content = "<p style='color:red;'>[복호화 실패] 올바르지 않은 키입니다.</p>";
                }
            } else {
                 content = "<p style='color:gray;'>[잠김] 이 페이지는 암호화되어 있습니다.</p>";
            }
        } else {
            state.currentPageIsEncrypted = false;
        }

        const titleInput = document.querySelector("#page-title-input");
        if (titleInput) titleInput.value = title;

        // 권한에 따른 UI 처리
        const canEdit = state.currentStoragePermission === 'EDIT' || state.currentStoragePermission === 'ADMIN';
        const modeToggleBtn = document.querySelector("#mode-toggle-btn");
        const newPageBtn = document.querySelector("#new-page-btn");
        
        if (modeToggleBtn) modeToggleBtn.style.display = canEdit ? 'flex' : 'none';
        if (newPageBtn) newPageBtn.style.display = canEdit ? 'flex' : 'none';

        const updatedAtEl = document.querySelector("#page-updated-at");
        if (updatedAtEl) updatedAtEl.textContent = new Date(page.updatedAt).toLocaleString();

        if (state.editor) {
            state.editor.commands.setContent(sanitizeEditorHtml(content), { emitUpdate: false });
        }

        renderPageList();

        if (page.coverImage) showCover(page.coverImage, page.coverPosition || 50);
        else hideCover();

        // 암호화된 페이지는 동기화 시 주의 필요 (평문 동기화 방지)
        // 여기서는 E2EE 환경에서는 실시간 협업(Yjs)을 비활성화하거나 암호화된 상태로 해야 함.
        // 현재 구현은 단순화를 위해 E2EE 페이지는 실시간 동기화 제외 또는 로컬 전용으로 처리
        if (!page.isEncrypted) {
            startPageSync(page.id, false);
        } else {
            // 암호화 페이지는 Yjs 동기화 중단 (서버가 평문을 알면 안되므로)
            // 추후 Yjs Webrtc Provider + Client-side Encryption 구현 필요
            stopPageSync();
        }
        
        await checkPublishStatus(page.id);
        await loadAndRenderSubpages(page.id);
        await loadAndRenderComments(page.id);

        if (window.innerWidth <= 768) closeSidebar();
    } catch (error) {
        console.error("Page load error:", error);
        showErrorInEditor("페이지 로드 실패: " + error.message, state.editor);
    }
}

/**
 * 현재 페이지 저장
 */
export async function saveCurrentPage() {
    if (!state.currentPageId || !state.editor) return true;

    const titleInput = document.querySelector("#page-title-input");
    const title = titleInput ? titleInput.value || "제목 없음" : "제목 없음";
    let content = sanitizeEditorHtml(state.editor.getHTML());

    try {
        const storageKey = window.cryptoManager.getStorageKey();
        let body = { 
            title, 
            content, 
            isEncrypted: false, 
            storageId: state.currentStorageId 
        };
        
        // 저장소 레벨 암호화 강제 적용
        if (state.currentStorageIsEncrypted) {
            if (!storageKey) {
                alert("암호화 키가 없어 저장할 수 없습니다. 저장소를 다시 열어주세요.");
                return false;
            }
            // 암호화 수행
            const encryptedContent = await window.cryptoManager.encryptWithKey(content, storageKey);
            body.isEncrypted = true;
            body.encryptedContent = encryptedContent;
            body.content = ""; // 서버에는 평문 전송 안 함 (빈 문자열)
        } else if (storageKey) {
            // (참고) 일반 저장소인데 키가 있는 경우는 없어야 함 (selectStorage에서 clear하므로)
            // 혹시라도 있다면 암호화해서 보낼 수도 있겠지만, 여기서는 저장소 속성을 따름
        } else if (state.currentPageIsEncrypted) {
            // 이미 암호화된 페이지인데 키가 없다면? (수정 불가 상태여야 함)
            alert("암호화 키가 없어 저장할 수 없습니다.");
            return false;
        }

        const page = await api.put("/api/pages/" + encodeURIComponent(state.currentPageId), body);

        state.pages = state.pages.map(p => p.id === page.id ? { ...p, title, updatedAt: page.updatedAt } : p);
        renderPageList();
        return true;
    } catch (error) {
        console.error("Save error:", error);
        alert("저장 실패: " + error.message);
        return false;
    }
}

/**
 * 편집 모드 토글
 */
export async function toggleEditMode() {
    const canEdit = state.currentStoragePermission === 'EDIT' || state.currentStoragePermission === 'ADMIN';
    if (!canEdit) {
        alert('이 저장소에 대한 편집 권한이 없습니다.');
        return;
    }

    const btn = document.querySelector("#mode-toggle-btn");
    if (!state.editor || !btn) return;

    if (state.isWriteMode) {
        await saveCurrentPage();
        state.isWriteMode = false;
        state.editor.setEditable(false);
        btn.classList.remove("write-mode");
        // UI 아이콘 업데이트 등
    } else {
        // 암호화 페이지인데 키가 없으면 편집 불가
        if (state.currentPageIsEncrypted && !window.cryptoManager.getStorageKey()) {
            alert("암호화된 페이지를 편집하려면 저장소 잠금을 해제해야 합니다.");
            return;
        }
        
        state.isWriteMode = true;
        state.editor.setEditable(true);
        btn.classList.add("write-mode");
    }
    
    updateCoverButtonsVisibility();
    updatePublishButton();
}

export function bindModeToggle() {
    const btn = document.querySelector("#mode-toggle-btn");
    if (!btn) return;

    btn.addEventListener("click", toggleEditMode);
}

/**
 * 새 페이지 버튼 바인딩
 */
export function bindNewPageButton() {
    const btn = document.querySelector("#new-page-btn");
    if (!btn) return;

    btn.addEventListener("click", async () => {
        const canEdit = state.currentStoragePermission === 'EDIT' || state.currentStoragePermission === 'ADMIN';
        if (!canEdit) {
            alert('이 저장소에 대한 편집 권한이 없습니다.');
            return;
        }

        let title = prompt("새 페이지 제목을 입력하세요:", "새 페이지");
        if (title === null) return;

        try {
            const storageKey = window.cryptoManager.getStorageKey();
            
            // 암호화 저장소 검증
            if (state.currentStorageIsEncrypted && !storageKey) {
                alert("암호화 키가 없어 페이지를 생성할 수 없습니다. 저장소를 다시 열어주세요.");
                return;
            }

            let body = {
                title: title.trim() || "새 페이지",
                content: "<p></p>",
                storageId: state.currentStorageId,
                isEncrypted: false
            };

            if (state.currentStorageIsEncrypted) {
                const encryptedContent = await window.cryptoManager.encryptWithKey("<p></p>", storageKey);
                body.isEncrypted = true;
                body.encryptedContent = encryptedContent;
                body.content = "";
            }

            const page = await api.post("/api/pages", body);

            state.pages.unshift(page);
            state.currentPageId = page.id;
            renderPageList();
            await loadPage(page.id);
        } catch (error) {
            console.error("Page create error:", error);
            alert("페이지 생성 실패: " + error.message);
        }
    });
}