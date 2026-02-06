/**
 * 페이지 관리 모듈 (컬렉션 제거 버전)
 */

import { escapeHtml, showErrorInEditor, syncPageUpdatedAtPadding, closeSidebar } from './ui-utils.js';
import * as api from './api-utils.js';
import { loadAndRenderComments } from './comments-manager.js';
import { startPageSync, stopPageSync, startCollectionSync, stopCollectionSync, flushPendingUpdates, syncEditorFromMetadata, onLocalEditModeChanged, updateAwarenessMode } from './sync-manager.js';
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
    currentPageId: null,
    expandedPages: new Set(),
    isWriteMode: false,
    currentPageIsEncrypted: false
};

/**
 * 상태 초기화
 */
export function initPagesManager(appState) {
    state = appState;
}

/**
 * 페이지 목록 가져오기
 */
export async function fetchPageList() {
    try {
        const url = state.currentStorageId 
            ? `/api/pages?storageId=${encodeURIComponent(state.currentStorageId)}`
            : "/api/pages";
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

export function applyPagesData(data) {
    const pages = Array.isArray(data) ? data : [];
    state.pages.length = 0;
    state.pages.push(...pages);
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
    const listEl = document.querySelector("#collection-list"); // index.html 구조 유지
    if (!listEl) return;

    listEl.innerHTML = "";

    if (!state.pages.length) {
        const empty = document.createElement("li");
        empty.className = "collection-empty";
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
        toggleSpan.className = "page-toggle collection-toggle";
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
 * 페이지 로드
 */
export async function loadPage(id) {
    if (!id) return;

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

        if (page.isEncrypted) {
            state.currentPageIsEncrypted = true;
            // TODO: 복호화 처리
        } else {
            state.currentPageIsEncrypted = false;
        }

        const titleInput = document.querySelector("#page-title-input");
        if (titleInput) titleInput.value = title;

        const updatedAtEl = document.querySelector("#page-updated-at");
        if (updatedAtEl) updatedAtEl.textContent = new Date(page.updatedAt).toLocaleString();

        if (state.editor) {
            state.editor.commands.setContent(sanitizeEditorHtml(content), { emitUpdate: false });
        }

        renderPageList();

        if (page.coverImage) showCover(page.coverImage, page.coverPosition || 50);
        else hideCover();

        startPageSync(page.id, page.isEncrypted || false);
        await checkPublishStatus(page.id);
        await loadAndRenderSubpages(page.id);
        if (window.loadAndRenderComments) await window.loadAndRenderComments(page.id);

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
        let body = { title, content, isEncrypted: false, storageId: state.currentStorageId };
        
        // 암호화 처리 생략 (필요 시 유지)

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
    const btn = document.querySelector("#mode-toggle-btn");
    if (!state.editor || !btn) return;

    if (state.isWriteMode) {
        await saveCurrentPage();
        state.isWriteMode = false;
        state.editor.setEditable(false);
        btn.classList.remove("write-mode");
        // UI 아이콘 업데이트 등
    } else {
        state.isWriteMode = true;
        state.editor.setEditable(true);
        btn.classList.add("write-mode");
    }
    
    updateCoverButtonsVisibility();
    updatePublishButton();
}

export function bindModeToggle() {
    document.querySelector("#mode-toggle-btn")?.addEventListener("click", toggleEditMode);
}

/**
 * 새 페이지 버튼 바인딩
 */
export function bindNewPageButton() {
    const btn = document.querySelector("#new-page-btn");
    if (!btn) return;

    btn.addEventListener("click", async () => {
        let title = prompt("새 페이지 제목을 입력하세요:", "새 페이지");
        if (title === null) return;

        try {
            const page = await api.post("/api/pages", {
                title: title.trim() || "새 페이지",
                content: "<p></p>",
                storageId: state.currentStorageId
            });

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

// 기존 fetchCollections 등 제거됨 (컬렉션이 없으므로)
export async function fetchCollections() { return []; } 
export function applyCollectionsData() {}