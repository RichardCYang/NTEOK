/**
 * 페이지 및 컬렉션 관리 모듈
 */

import { secureFetch } from './ui-utils.js';
import { escapeHtml, showErrorInEditor } from './ui-utils.js';

// 전역 상태 (app.js에서 전달받음)
let state = {
    editor: null,
    pages: [],
    collections: [],
    currentPageId: null,
    currentCollectionId: null,
    expandedCollections: new Set(),
    isWriteMode: false
};

/**
 * 상태 초기화
 */
export function initPagesManager(appState) {
    state = appState;
}

/**
 * 컬렉션 목록 가져오기
 */
export async function fetchCollections() {
    try {
        console.log("컬렉션 목록 요청: GET /api/collections");
        const res = await fetch("/api/collections");
        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const data = await res.json();
        state.collections.length = 0;
        state.collections.push(...(Array.isArray(data) ? data : []));

        if (!state.currentCollectionId && state.collections.length) {
            state.currentCollectionId = state.collections[0].id;
        }

        renderPageList();
    } catch (error) {
        console.error("컬렉션 목록 요청 오류:", error);
        showErrorInEditor("컬렉션을 불러오는 데 실패했다: " + error.message, state.editor);
    }
}

/**
 * 페이지 목록 가져오기
 */
export async function fetchPageList() {
    try {
        console.log("페이지 목록 요청: GET /api/pages");
        const res = await fetch("/api/pages");
        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const data = await res.json();
        console.log("페이지 목록 응답:", data);

        state.pages.length = 0;
        state.pages.push(...(Array.isArray(data) ? data : []));

        renderPageList();

        if (!state.pages.length) {
            if (state.editor) {
                state.editor.commands.setContent("<p>새 페이지를 만들어보자.</p>", { emitUpdate: false });
            }
        }
    } catch (error) {
        console.error("페이지 목록 요청 오류:", error);
        showErrorInEditor("페이지 목록을 불러오는 데 실패했다: " + error.message, state.editor);
    }
}

/**
 * 평면 페이지 목록을 트리 구조로 변환
 */
export function buildPageTree(flatPages) {
    const map = new Map();

    flatPages.forEach((p) => {
        map.set(p.id, {
            ...p,
            parentId: p.parentId || null,
            sortOrder: typeof p.sortOrder === "number" ? p.sortOrder : 0,
            children: []
        });
    });

    const roots = [];

    map.forEach((node) => {
        if (node.parentId && map.has(node.parentId)) {
            const parent = map.get(node.parentId);
            parent.children.push(node);
        } else {
            roots.push(node);
        }
    });

    const sortFn = (a, b) => {
        const aOrder = typeof a.sortOrder === "number" ? a.sortOrder : 0;
        const bOrder = typeof b.sortOrder === "number" ? b.sortOrder : 0;
        if (aOrder !== bOrder) {
            return aOrder - bOrder;
        }
        const aTime = a.updatedAt ? new Date(a.updatedAt).getTime() : 0;
        const bTime = b.updatedAt ? new Date(b.updatedAt).getTime() : 0;
        return bTime - aTime;
    };

    function sortNodes(nodes) {
        nodes.sort(sortFn);
        nodes.forEach((n) => {
            if (n.children && n.children.length) {
                sortNodes(n.children);
            }
        });
    }

    sortNodes(roots);
    return roots;
}

/**
 * 페이지 목록 렌더링
 */
export function renderPageList() {
    const listEl = document.querySelector("#collection-list");
    if (!listEl) return;

    listEl.innerHTML = "";

    if (!state.collections.length) {
        const empty = document.createElement("li");
        empty.className = "collection-empty";
        empty.textContent = "컬렉션이 없습니다. 아래에서 새 컬렉션을 추가하세요.";
        listEl.appendChild(empty);
        return;
    }

    state.collections.forEach((collection) => {
        const item = document.createElement("li");
        item.className = "collection-item";
        item.dataset.collectionId = collection.id;

        if (collection.id === state.currentCollectionId) {
            item.classList.add("active");
        }

        const header = document.createElement("div");
        header.className = "collection-header";

        const title = document.createElement("div");
        title.className = "collection-title";

        const colPages = state.pages.filter((p) => p.collectionId === collection.id);
        const hasPages = colPages.length > 0;

        const isShared = collection.isOwner === false;
        const indicator = isShared
            ? `<span class="shared-collection-indicator">${collection.permission || 'READ'}</span>`
            : '';
        const folderIcon = isShared
            ? 'fa-solid fa-folder-open'
            : 'fa-regular fa-folder';

        if (hasPages) {
            title.innerHTML = `
                <span class="collection-toggle ${state.expandedCollections.has(collection.id) ? "expanded" : ""}">
                    <i class="fa-solid fa-caret-right"></i>
                </span>
                <i class="${folderIcon}"></i>
                <span>${escapeHtml(collection.name || "제목 없음")}${indicator}</span>
            `;
        } else {
            title.innerHTML = `
                <span class="collection-toggle" style="visibility: hidden;">
                    <i class="fa-solid fa-caret-right"></i>
                </span>
                <i class="${folderIcon}"></i>
                <span>${escapeHtml(collection.name || "제목 없음")}${indicator}</span>
            `;
        }

        const actions = document.createElement("div");
        actions.className = "collection-actions";

        const addBtn = document.createElement("button");
        addBtn.type = "button";
        addBtn.className = "collection-add-page-btn";
        addBtn.dataset.collectionId = collection.id;
        addBtn.title = "이 컬렉션에 페이지 추가";
        addBtn.innerHTML = `<i class="fa-solid fa-plus"></i>`;

        const menuBtn = document.createElement("button");
        menuBtn.type = "button";
        menuBtn.className = "collection-menu-btn";
        menuBtn.dataset.collectionId = collection.id;
        menuBtn.dataset.isOwner = collection.isOwner !== false ? 'true' : 'false';
        menuBtn.dataset.permission = collection.permission || 'WRITE';
        menuBtn.title = "컬렉션 메뉴";
        menuBtn.innerHTML = `<i class="fa-solid fa-ellipsis-vertical"></i>`;

        if (collection.permission !== 'READ') {
            actions.appendChild(addBtn);
        }
        actions.appendChild(menuBtn);

        header.appendChild(title);
        header.appendChild(actions);

        item.appendChild(header);

        const expanded = state.expandedCollections.has(collection.id);
        if (expanded && hasPages) {
            const pageList = document.createElement("ul");
            pageList.className = "page-list";

            if (!colPages.length) {
                const empty = document.createElement("div");
                empty.className = "collection-empty";
                empty.textContent = "페이지가 없습니다. 새 페이지를 추가하세요.";
                item.appendChild(empty);
            } else {
                const tree = buildPageTree(colPages);

                function renderNode(node, depth) {
                    const li = document.createElement("li");
                    li.className = "page-list-item";
                    li.dataset.pageId = node.id;

                    li.style.paddingLeft = 32 + depth * 16 + "px";

                    const row = document.createElement("div");
                    row.style.display = "flex";
                    row.style.alignItems = "center";
                    row.style.justifyContent = "space-between";
                    row.style.gap = "8px";

                    const titleWrap = document.createElement("div");
                    titleWrap.style.display = "flex";
                    titleWrap.style.flexDirection = "column";
                    titleWrap.style.gap = "2px";

                    const titleSpan = document.createElement("span");
                    titleSpan.className = "page-list-item-title";

                    if (node.isEncrypted) {
                        titleSpan.innerHTML = `<i class="fa-solid fa-lock" style="margin-right: 6px; color: #2d5f5d;"></i>${escapeHtml(node.title || "제목 없음")}`;
                    } else {
                        titleSpan.textContent = node.title || "제목 없음";
                    }

                    const dateSpan = document.createElement("span");
                    dateSpan.className = "page-list-item-date";
                    dateSpan.textContent = node.updatedAt
                        ? new Date(node.updatedAt).toLocaleString()
                        : "";

                    titleWrap.appendChild(titleSpan);
                    titleWrap.appendChild(dateSpan);

                    const pageMenuBtn = document.createElement("button");
                    pageMenuBtn.type = "button";
                    pageMenuBtn.className = "page-menu-btn";
                    pageMenuBtn.dataset.pageId = node.id;
                    pageMenuBtn.dataset.isEncrypted = node.isEncrypted ? 'true' : 'false';
                    pageMenuBtn.title = "페이지 메뉴";
                    pageMenuBtn.innerHTML = `<i class="fa-solid fa-ellipsis-vertical"></i>`;

                    const right = document.createElement("div");
                    right.className = "page-menu-wrapper";
                    right.appendChild(pageMenuBtn);

                    row.appendChild(titleWrap);
                    row.appendChild(right);

                    li.appendChild(row);

                    if (node.id === state.currentPageId) {
                        li.classList.add("active");
                    }

                    pageList.appendChild(li);

                    if (node.children && node.children.length) {
                        node.children.forEach((child) => renderNode(child, depth + 1));
                    }
                }

                tree.forEach((node) => renderNode(node, 0));
                item.appendChild(pageList);
            }
        }

        listEl.appendChild(item);
    });
}

/**
 * 페이지 로드
 */
export async function loadPage(id) {
    if (!id) return;

    // 페이지 전환 전에 쓰기모드였다면 저장하고 읽기모드로 전환
    if (state.isWriteMode && state.currentPageId) {
        await saveCurrentPage();

        const modeToggleBtn = document.querySelector("#mode-toggle-btn");
        const titleInput = document.querySelector("#page-title-input");
        const toolbar = document.querySelector(".editor-toolbar");
        const iconEl = modeToggleBtn ? modeToggleBtn.querySelector("i") : null;
        const textEl = modeToggleBtn ? modeToggleBtn.querySelector("span") : null;

        state.isWriteMode = false;
        if (state.editor) {
            state.editor.setEditable(false);
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
    }

    try {
        console.log("단일 페이지 요청: GET /api/pages/" + id);
        const res = await fetch("/api/pages/" + encodeURIComponent(id));
        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const page = await res.json();
        console.log("단일 페이지 응답:", page);

        // 암호화된 페이지인 경우 복호화 모달 표시
        if (page.isEncrypted) {
            if (page.collectionId) {
                state.currentCollectionId = page.collectionId;
                state.expandedCollections.add(page.collectionId);
            }
            // showDecryptionModal은 app.js에서 처리
            window.showDecryptionModal(page);
            return;
        }

        state.currentPageId = page.id;
        if (page.collectionId) {
            state.currentCollectionId = page.collectionId;
            state.expandedCollections.add(page.collectionId);
        }

        let title = page.title || "";
        let content = page.content || "<p></p>";

        const titleInput = document.querySelector("#page-title-input");
        if (titleInput) {
            titleInput.value = title;
        }

        if (state.editor) {
            state.editor.commands.setContent(content, { emitUpdate: false });
        }

        renderPageList();

        // 모바일에서 페이지 로드 후 사이드바 닫기
        if (window.innerWidth <= 768) {
            window.closeSidebar();
        }
    } catch (error) {
        console.error("단일 페이지 로드 오류:", error);
        showErrorInEditor("페이지를 불러오지 못했다: " + error.message, state.editor);
    }
}

/**
 * 현재 페이지 저장
 */
export async function saveCurrentPage() {
    const titleInput = document.querySelector("#page-title-input");

    if (!state.currentPageId) {
        console.warn("저장할 페이지가 없음.");
        return true;
    }
    if (!state.editor) {
        console.warn("에디터가 초기화되지 않음.");
        return true;
    }

    let title = titleInput ? titleInput.value || "제목 없음" : "제목 없음";
    let content = state.editor.getHTML();

    try {
        const res = await secureFetch("/api/pages/" + encodeURIComponent(state.currentPageId), {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                title,
                content
            })
        });

        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const page = await res.json();
        console.log("페이지 저장 응답:", page);

        const decryptedTitle = titleInput ? titleInput.value || "제목 없음" : "제목 없음";

        state.pages = state.pages.map((p) => {
            if (p.id === page.id) {
                return {
                    ...p,
                    title: decryptedTitle,
                    updatedAt: page.updatedAt,
                    parentId: page.parentId ?? p.parentId ?? null,
                    sortOrder: typeof page.sortOrder === "number" ? page.sortOrder : (typeof p.sortOrder === "number" ? p.sortOrder : 0)
                };
            }
            return p;
        });

        renderPageList();
        console.log("저장 완료.");
        return true;
    } catch (error) {
        console.error("페이지 저장 오류:", error);

        if (error.message && error.message.includes("403")) {
            window.showReadonlyWarningModal();
            return false;
        } else {
            alert("페이지 저장 실패: " + error.message);
            return false;
        }
    }
}

/**
 * 편집 모드 토글
 */
export async function toggleEditMode() {
    const modeToggleBtn = document.querySelector("#mode-toggle-btn");
    const titleInput = document.querySelector("#page-title-input");
    const toolbar = document.querySelector(".editor-toolbar");
    const iconEl = modeToggleBtn ? modeToggleBtn.querySelector("i") : null;
    const textEl = modeToggleBtn ? modeToggleBtn.querySelector("span") : null;

    if (!state.editor || !modeToggleBtn) return;

    if (state.isWriteMode) {
        const saveSuccess = await saveCurrentPage();

        if (!saveSuccess) {
            console.log("저장 실패 - 쓰기모드 유지");
            return;
        }

        state.isWriteMode = false;
        state.editor.setEditable(false);
        if (titleInput) {
            titleInput.setAttribute("readonly", "");
        }
        if (toolbar) {
            toolbar.classList.remove("visible");
        }

        modeToggleBtn.classList.remove("write-mode");
        if (iconEl) {
            iconEl.className = "fa-solid fa-pencil";
        }
        if (textEl) {
            textEl.textContent = "쓰기모드";
        }
    } else {
        state.isWriteMode = true;
        state.editor.setEditable(true);
        if (titleInput) {
            titleInput.removeAttribute("readonly");
        }
        if (toolbar) {
            toolbar.classList.add("visible");
        }

        modeToggleBtn.classList.add("write-mode");
        if (iconEl) {
            iconEl.className = "fa-solid fa-book-open";
        }
        if (textEl) {
            textEl.textContent = "읽기모드";
        }
    }
}

/**
 * 편집 모드 토글 버튼 바인딩
 */
export function bindModeToggle() {
    const btn = document.querySelector("#mode-toggle-btn");
    if (!btn) return;

    btn.addEventListener("click", () => {
        toggleEditMode();
    });
}

/**
 * 새 컬렉션 버튼 바인딩
 */
export function bindNewCollectionButton() {
    const btn = document.querySelector("#new-collection-btn");
    if (!btn) return;

    btn.addEventListener("click", async () => {
        let name = prompt("새 컬렉션 이름을 입력하세요.", "새 컬렉션");
        if (name === null) return;

        const plainName = name.trim() || "새 컬렉션";

        try {
            const res = await secureFetch("/api/collections", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ name: plainName })
            });

            if (!res.ok) {
                throw new Error("HTTP " + res.status + " " + res.statusText);
            }

            const collection = await res.json();
            collection.name = plainName;
            state.collections.push(collection);
            state.currentCollectionId = collection.id;
            state.currentPageId = null;

            renderPageList();

            if (state.editor) {
                state.editor.commands.setContent("<p>이 컬렉션에 새 페이지를 추가해 보세요.</p>", { emitUpdate: false });
            }
        } catch (error) {
            console.error("새 컬렉션 생성 오류:", error);
            alert("새 컬렉션을 생성하지 못했다: " + error.message);
        }
    });
}

/**
 * 페이지 목록 클릭 이벤트 바인딩
 * (컬렉션/페이지 선택, 메뉴 등)
 */
export function bindPageListClick() {
    const listEl = document.querySelector("#collection-list");
    if (!listEl) return;

    listEl.addEventListener("click", async (event) => {
        // 구현이 복잡하므로 app.js에서 처리하도록 이벤트를 전달
        // 또는 여기서 전체 구현 가능
        // 간단히 하기 위해 app.js에 window.handlePageListClick 함수를 만들어 처리
        if (window.handlePageListClick) {
            await window.handlePageListClick(event, state);
        }
    });
}
