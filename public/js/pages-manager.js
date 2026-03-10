
import { escapeHtml, showErrorInEditor, syncPageUpdatedAtPadding, closeSidebar } from './ui-utils.js';
import * as api from './api-utils.js';
import { loadAndRenderComments } from './comments-manager.js';
import { startPageSync, stopPageSync, startStorageSync, stopStorageSync, flushPendingUpdates, syncEditorFromMetadata, onLocalEditModeChanged, updateAwarenessMode, flushE2eeState, requestImmediateSave } from './sync-manager.js';
import { showCover, hideCover, updateCoverButtonsVisibility } from './cover-manager.js';
import { checkPublishStatus, updatePublishButton } from './publish-manager.js';
import { loadAndRenderSubpages, onEditModeChange } from './subpages-manager.js';
import { sanitizeEditorHtml } from './sanitize.js';
import { EXAMPLE_CONTENT } from './editor.js';
import { flushEditorTransientNodeViews } from './editor-save-utils.js';

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

export function initPagesManager(appState) {
    state = appState;
    if (state.currentStorageIsEncrypted === undefined) state.currentStorageIsEncrypted = false;
}

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

        applyPagesData(data, state.currentStorageIsEncrypted);

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

    if (hasChildren && isExpanded) node.children.forEach(child => renderNode(child, depth + 1));
    }

    tree.forEach(node => renderNode(node, 0));
    listEl.appendChild(fragment);
}

export async function clearCurrentPage() {
    state.currentPageId = null;
    state.currentPageIsEncrypted = false;
    state.isWriteMode = false;

    await flushE2eeState();
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

    const canEdit = state.currentStoragePermission === 'EDIT' || state.currentStoragePermission === 'ADMIN';
    const newPageBtn = document.querySelector("#new-page-btn");
    if (newPageBtn) {
        newPageBtn.style.display = canEdit ? 'flex' : 'none';
    }

    const subpagesContainer = document.querySelector("#subpages-container");
    if (subpagesContainer) subpagesContainer.innerHTML = "";

    const commentsContainer = document.querySelector("#page-comments-section");
    if (commentsContainer) {
        commentsContainer.innerHTML = "";
        commentsContainer.classList.add("hidden");
    }

    updatePublishButton();
}

export async function loadPage(id) {
    if (!id) {
        await clearCurrentPage();
        return;
    }

    if (state.isWriteMode && state.currentPageId) {
        await saveCurrentPage();
    }

    await flushE2eeState();
    stopPageSync();

    try {
        const page = await api.get("/api/pages/" + encodeURIComponent(id));
        state.currentPageId = page.id;
        state.currentPageUpdatedAt = page.updatedAt || null;

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
                    const encrypted = page.encryptedContent || page.encrypted_content;
                    if (encrypted) {
                        content = await window.cryptoManager.decryptWithKey(encrypted, storageKey);
                        isDecrypted = true;
                    }
                } catch (e) {
                    console.error("자동 복호화 실패:", e);
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

        if (!page.isEncrypted) {
            startPageSync(page.id, false, false);
        } else if (state.currentStorageIsEncrypted && window.cryptoManager.getStorageKey()) {
            startPageSync(page.id, true, true);
        } else {
            stopPageSync();
        }

        await checkPublishStatus(page.id);
        await loadAndRenderSubpages(page.id);
        await loadAndRenderComments(page.id);

        if (window.innerWidth <= 768) closeSidebar();
    } catch (error) {
        console.error("페이지 로드 오류:", error);
        showErrorInEditor("페이지 로드 실패: " + error.message, state.editor);
    }
}

export async function saveCurrentPage() {
    if (!state.currentPageId || !state.editor) return true;

    await new Promise(resolve => requestAnimationFrame(() => resolve()));
    flushEditorTransientNodeViews(state.editor);
    await new Promise(resolve => requestAnimationFrame(() => resolve()));
    await Promise.resolve();

    const titleInput = document.querySelector("#page-title-input");
    const title = titleInput ? titleInput.value || "제목 없음" : "제목 없음";

    if (!state.currentStorageIsEncrypted && !state.currentPageIsEncrypted) {
        try {
            flushPendingUpdates();
            const result = await requestImmediateSave(state.currentPageId, { includeSnapshot: true, waitForAck: true });
            if (result?.ok) {
                if (result.updatedAt) {
                    state.pages = state.pages.map(p =>
                        p.id === state.currentPageId ? { ...p, title, updatedAt: result.updatedAt } : p
                    );
                    state.currentPageUpdatedAt = result.updatedAt;
                    renderPageList();
                }
                return true;
            }

            const content = sanitizeEditorHtml(state.editor.getHTML());
            const body = { title, content, storageId: state.currentStorageId };
            const page = await api.put("/api/pages/" + encodeURIComponent(state.currentPageId), body);
            if (page?.updatedAt) {
                state.pages = state.pages.map(p =>
                    p.id === state.currentPageId ? { ...p, title, updatedAt: page.updatedAt } : p
                );
                state.currentPageUpdatedAt = page.updatedAt;
                renderPageList();
            }
            return true;
        } catch (error) {
            console.error("저장 오류 (강제 저장):", error);
            return false;
        }
    }

    try {
        const storageKey = window.cryptoManager.getStorageKey();
        if (state.currentStorageIsEncrypted) {
            if (!storageKey) {
                alert("암호화 키가 없어 저장할 수 없습니다. 저장소를 다시 열어주세요.");
                return false;
            }

            try {
                await api.put("/api/pages/" + encodeURIComponent(state.currentPageId), { title });
            } catch (e) {
                console.error("메타데이터 저장 오류:", e);
            }

            const result = await requestImmediateSave(state.currentPageId, { includeSnapshot: true, waitForAck: true });
            const updatedAt = result?.updatedAt || new Date().toISOString();

            state.pages = state.pages.map(p =>
                p.id === state.currentPageId ? { ...p, title, updatedAt } : p
            );
            state.currentPageUpdatedAt = updatedAt;
            renderPageList();
            return true;
        }

        let content = sanitizeEditorHtml(state.editor.getHTML());
        let body = {
            title,
            content,
            isEncrypted: false,
            storageId: state.currentStorageId
        };

        if (state.currentPageIsEncrypted) {
            if (!storageKey) {
                alert("암호화 키가 없어 저장할 수 없습니다.");
                return false;
            }
            const encryptedContent = await window.cryptoManager.encryptWithKey(content, storageKey);
            body.isEncrypted = true;
            body.encryptedContent = encryptedContent;
            body.content = ""; 
        }

        const page = await api.put("/api/pages/" + encodeURIComponent(state.currentPageId), body);

        state.pages = state.pages.map(p => p.id === page.id ? { ...p, title, updatedAt: page.updatedAt } : p);
        state.currentPageUpdatedAt = page.updatedAt || null;
        renderPageList();
        return true;
    } catch (error) {
        console.error("저장 오류:", error);
        alert("저장 실패: " + error.message);
        return false;
    }
}

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

        flushEditorTransientNodeViews(state.editor);
        await new Promise(resolve => requestAnimationFrame(() => resolve()));
        await Promise.resolve();

        state.isWriteMode = false;
        state.editor.setEditable(false);
        btn.classList.remove("write-mode");
    } else {
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
            console.error("페이지 생성 오류:", error);
            alert("페이지 생성 실패: " + error.message);
        }
    });
}