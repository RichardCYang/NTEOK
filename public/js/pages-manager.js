/**
 * 페이지 및 컬렉션 관리 모듈
 */

import { escapeHtml, showErrorInEditor, syncPageUpdatedAtPadding, closeSidebar } from './ui-utils.js';
import * as api from './api-utils.js';
import { loadAndRenderComments } from './comments-manager.js';
import { startPageSync, stopPageSync, startCollectionSync, stopCollectionSync, flushPendingUpdates, syncEditorFromMetadata, onLocalEditModeChanged, updateAwarenessMode } from './sync-manager.js';
import { showCover, hideCover, updateCoverButtonsVisibility } from './cover-manager.js';
import { checkPublishStatus, updatePublishButton } from './publish-manager.js';
import { loadAndRenderSubpages, onEditModeChange } from './subpages-manager.js';
import { EXAMPLE_CONTENT } from './editor.js';

// 전역 상태 (app.js에서 전달받음)
let state = {
    editor: null,
    pages: [],
    collections: [],
    currentPageId: null,
    currentCollectionId: null,
    expandedCollections: new Set(),
    expandedPages: new Set(),
    isWriteMode: false,
    currentPageIsEncrypted: false  // 현재 페이지의 암호화 상태
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
        const data = await api.get("/api/collections");
        applyCollectionsData(data);
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
        const data = await api.get("/api/pages");
        console.log("페이지 목록 응답:", data);

        // 제목은 평문으로 저장되므로 복호화 불필요
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

/**
 * 평면 페이지 목록을 트리 구조로 변환
 */
export function applyCollectionsData(data) {
    state.collections.length = 0;
    state.collections.push(...(Array.isArray(data) ? data : []));

    if (!state.currentCollectionId && state.collections.length) {
        state.currentCollectionId = state.collections[0].id;
    }
}

export function applyPagesData(data) {
    const pages = Array.isArray(data) ? data : [];

    state.pages.length = 0;
    state.pages.push(...pages);
}

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
 *
 * 성능 최적화:
 * - 페이지를 컬렉션별로 사전 그룹화 (O(n) -> O(1) 조회)
 * - DocumentFragment 사용하여 DOM 조작 최소화
 */
export function renderPageList() {
    const listEl = document.querySelector("#collection-list");
    if (!listEl) return;

    listEl.innerHTML = "";

    if (!state.collections.length) {
        const empty = document.createElement("li");
        empty.className = "collection-empty";
        empty.textContent = (state.translations && state.translations['collection_empty']) || "컬렉션이 없습니다. 아래에서 새 컬렉션을 추가하세요.";
        listEl.appendChild(empty);
        return;
    }

    // 성능 최적화: 페이지를 컬렉션별로 사전 그룹화 (O(n) 한 번만 수행)
    const pagesByCollection = new Map();
    state.pages.forEach((page) => {
        const colId = page.collectionId;
        if (!pagesByCollection.has(colId)) {
            pagesByCollection.set(colId, []);
        }
        pagesByCollection.get(colId).push(page);
    });

    // DocumentFragment로 DOM 조작 최소화
    const fragment = document.createDocumentFragment();

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

        // O(1) 조회로 변경
        const colPages = pagesByCollection.get(collection.id) || [];
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
                <span>${escapeHtml(collection.name || ((state.translations && state.translations['untitled']) || "제목 없음"))}${indicator}</span>
            `;
        } else {
            title.innerHTML = `
                <span class="collection-toggle" style="visibility: hidden;">
                    <i class="fa-solid fa-caret-right"></i>
                </span>
                <i class="${folderIcon}"></i>
                <span>${escapeHtml(collection.name || ((state.translations && state.translations['untitled']) || "제목 없음"))}${indicator}</span>
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
            pageList.dataset.collectionId = collection.id;
            pageList.dataset.parentId = "null";

            if (!colPages.length) {
                const empty = document.createElement("div");
                empty.className = "collection-empty";
                empty.textContent = (state.translations && state.translations['page_empty']) || "페이지가 없습니다. 새 페이지를 추가하세요.";
                item.appendChild(empty);
            } else {
                const tree = buildPageTree(colPages);

                function renderNode(node, depth) {
                    const li = document.createElement("li");
                    li.className = "page-list-item";
                    li.dataset.pageId = node.id;

                    // 하위 페이지 여부 확인
                    const hasChildren = node.children && node.children.length > 0;
                    const isExpanded = state.expandedPages.has(node.id);

                    // 패딩 계산 (토글 아이콘 너비 고려)
                    li.style.paddingLeft = (12 + depth * 16) + "px";

                    const row = document.createElement("div");
                    row.style.display = "flex";
                    row.style.alignItems = "center";
                    row.style.justifyContent = "space-between";
                    row.style.gap = "8px";

                    const titleWrap = document.createElement("div");
                    titleWrap.style.display = "flex";
                    titleWrap.style.alignItems = "center";
                    titleWrap.style.gap = "4px";
                    titleWrap.style.flex = "1";
                    titleWrap.style.minWidth = "0";

                    // 접기/펼치기 토글 아이콘
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
                    titleSpan.style.overflow = "hidden";
                    titleSpan.style.textOverflow = "ellipsis";
                    titleSpan.style.whiteSpace = "nowrap";

                    // 아이콘 표시 로직 (innerHTML 사용 금지: DOM 기반으로 안전하게 렌더링)
                    const iconEl = (() => {
                        // 사용자 아이콘
                        if (node.icon) {
                            // Font Awesome class list (예: "fa-solid fa-star" 또는 "fa-star")
                            if (node.icon.startsWith('fa-')) {
                                const i = document.createElement('i');
                                i.className = node.icon;
                                i.style.marginRight = "6px";
                                i.style.color = "#2d5f5d";
                                return i;
                            }

                            // Emoji / plain text
                            const s = document.createElement('span');
                            s.style.marginRight = "6px";
                            s.style.fontSize = "16px";
                            s.textContent = node.icon;
                            return s;
                        }

                        // 암호화 페이지는 자물쇠 아이콘 표시
                        if (node.isEncrypted) {
                            const i = document.createElement('i');
                            i.className = "fa-solid fa-lock";
                            i.style.marginRight = "6px";
                            i.style.color = "#2d5f5d";
                            return i;
                        }

                        // 기본 페이지 아이콘 (하위 페이지가 있는 경우와 없는 경우 구분 가능)
                        const i = document.createElement('i');
                        i.className = hasChildren ? "fa-regular fa-file-lines" : "fa-regular fa-file";
                        i.style.marginRight = "6px";
                        i.style.color = "#6b7280";
                        return i;
                    })();

                    // 제목 (textContent 사용)
                    titleSpan.textContent = "";
                    if (iconEl) titleSpan.appendChild(iconEl);
                    titleSpan.appendChild(document.createTextNode(node.title || ((state.translations && state.translations['untitled']) || "제목 없음")));

                    titleWrap.appendChild(titleSpan);

                    // + 버튼 (하위 페이지 추가)
                    const addSubpageBtn = document.createElement("button");
                    addSubpageBtn.type = "button";
                    addSubpageBtn.className = "page-add-subpage-btn";
                    addSubpageBtn.dataset.pageId = node.id;
                    addSubpageBtn.dataset.collectionId = collection.id;
                    addSubpageBtn.title = "하위 페이지 추가";
                    addSubpageBtn.innerHTML = `<i class="fa-solid fa-plus"></i>`;

                    const pageMenuBtn = document.createElement("button");
                    pageMenuBtn.type = "button";
                    pageMenuBtn.className = "page-menu-btn";
                    pageMenuBtn.dataset.pageId = node.id;
                    pageMenuBtn.dataset.isEncrypted = node.isEncrypted ? 'true' : 'false';
                    pageMenuBtn.title = "페이지 메뉴";
                    pageMenuBtn.innerHTML = `<i class="fa-solid fa-ellipsis-vertical"></i>`;

                    const right = document.createElement("div");
                    right.className = "page-menu-wrapper";
                    right.style.display = "flex";
                    right.style.alignItems = "center";
                    right.style.gap = "4px";
                    right.appendChild(addSubpageBtn);
                    right.appendChild(pageMenuBtn);

                    row.appendChild(titleWrap);
                    row.appendChild(right);

                    li.appendChild(row);

                    if (node.id === state.currentPageId) {
                        li.classList.add("active");
                    }

                    pageList.appendChild(li);

                    // 펼쳐진 상태이고 자식이 있는 경우에만 자식 렌더링
                    if (hasChildren && isExpanded) {
                        node.children.forEach((child) => renderNode(child, depth + 1));
                    }
                }

                tree.forEach((node) => renderNode(node, 0));
                item.appendChild(pageList);

                // 페이지 드래그 앤 드롭 초기화
                initPageDragDrop(pageList, collection.id, null, collection.permission);
            }
        }

        fragment.appendChild(item);
    });

    // 한 번에 DOM에 추가 (성능 최적화)
    listEl.appendChild(fragment);

    // 컬렉션 드래그 앤 드롭 초기화
    initCollectionDragDrop();
}

/**
 * 컬렉션 드래그 앤 드롭 초기화
 */
function initCollectionDragDrop() {
    const listEl = document.querySelector("#collection-list");
    if (!listEl) return;

    // 기존 Sortable 인스턴스 제거
    if (listEl._sortable) {
        listEl._sortable.destroy();
    }

    // Sortable 초기화
    listEl._sortable = Sortable.create(listEl, {
        animation: 150,
        handle: '.collection-header',
        draggable: '.collection-item',
        ghostClass: 'sortable-ghost',
        chosenClass: 'sortable-chosen',
        dragClass: 'sortable-drag',

        // 모바일 터치 지원
        touchStartThreshold: 5,
        delay: 100,
        delayOnTouchOnly: true,

        // 공유받은 컬렉션 필터링
        filter: (evt, target) => {
            const collectionItem = target.closest('.collection-item');
            const collectionId = collectionItem?.dataset.collectionId;
            const collection = state.collections.find(c => c.id === collectionId);
            return collection && !collection.isOwner;
        },

        onEnd: async (evt) => {
            if (evt.oldIndex === evt.newIndex) return;

            const collectionItems = Array.from(listEl.querySelectorAll('.collection-item'));
            const collectionIds = collectionItems.map(item => item.dataset.collectionId);

            // 낙관적 업데이트
            const movedCollection = state.collections.splice(evt.oldIndex, 1)[0];
            state.collections.splice(evt.newIndex, 0, movedCollection);

            try {
                await api.patch('/api/collections/reorder', { collectionIds });
                console.log('컬렉션 순서 변경 완료');
            } catch (error) {
                console.error('컬렉션 순서 변경 오류:', error);
                alert(`순서 변경에 실패했습니다: ${error.message}`);

                // 롤백
                const rolledBack = state.collections.splice(evt.newIndex, 1)[0];
                state.collections.splice(evt.oldIndex, 0, rolledBack);
                renderPageList();
            }
        }
    });
}

/**
 * 페이지 드래그 앤 드롭 초기화
 */
function initPageDragDrop(pageListEl, collectionId, parentId, permission) {
    if (!pageListEl || permission === 'READ') return;

    if (pageListEl._sortable) {
        pageListEl._sortable.destroy();
    }

    pageListEl._sortable = Sortable.create(pageListEl, {
        animation: 150,
        draggable: '.page-list-item',
        handle: '.page-list-item',
        ghostClass: 'sortable-ghost',
        chosenClass: 'sortable-chosen',
        dragClass: 'sortable-drag',
        group: 'pages',

        // 모바일 터치 지원
        touchStartThreshold: 5,
        delay: 100,
        delayOnTouchOnly: true,

        onMove: (evt) => {
            const pageId = evt.dragged.dataset.pageId;
            const page = state.pages.find(p => p.id === pageId);
            const toCollectionId = evt.to.dataset.collectionId;
            const fromCollectionId = evt.from.dataset.collectionId;

            // 암호화된 페이지는 다른 컬렉션으로 이동 불가
            if (page && page.isEncrypted && fromCollectionId !== toCollectionId) {
                return false;
            }

            // 대상 컬렉션 권한 체크
            const toCollection = state.collections.find(c => c.id === toCollectionId);
            if (toCollection && toCollection.permission === 'READ') {
                return false;
            }

            return true;
        },

        onEnd: async (evt) => {
            const fromList = evt.from;
            const toList = evt.to;
            const fromCollectionId = fromList.dataset.collectionId;
            const toCollectionId = toList.dataset.collectionId;
            const fromParentId = fromList.dataset.parentId === "null" ? null : fromList.dataset.parentId;
            const toParentId = toList.dataset.parentId === "null" ? null : toList.dataset.parentId;
            const pageId = evt.item.dataset.pageId;

            // 같은 컬렉션 내 순서 변경
            if (fromCollectionId === toCollectionId && fromParentId === toParentId) {
                if (evt.oldIndex === evt.newIndex) return;

                const pageItems = Array.from(toList.querySelectorAll('.page-list-item'));
                const pageIds = pageItems.map(item => item.dataset.pageId);

                try {
                    await api.patch('/api/pages/reorder', {
                        collectionId: toCollectionId,
                        pageIds,
                        parentId: toParentId
                    });

                    console.log('페이지 순서 변경 완료');

                } catch (error) {
                    console.error('페이지 순서 변경 오류:', error);
                    alert(`순서 변경에 실패했습니다: ${error.message}`);
                    await fetchPageList();
                    renderPageList();
                }

            } else {
                // 다른 컬렉션으로 이동
                const page = state.pages.find(p => p.id === pageId);

                if (page && page.isEncrypted) {
                    alert('암호화된 페이지는 다른 컬렉션으로 이동할 수 없습니다.');
                    await fetchPageList();
                    renderPageList();
                    return;
                }

                try {
                    const newSortOrder = evt.newIndex * 10;

                    await api.patch(`/api/pages/${pageId}/move`, {
                        targetCollectionId: toCollectionId,
                        targetParentId: toParentId,
                        sortOrder: newSortOrder
                    });

                    console.log('페이지 이동 완료:', pageId, '→', toCollectionId);

                    await fetchPageList();
                    renderPageList();

                } catch (error) {
                    console.error('페이지 이동 오류:', error);
                    alert(`페이지 이동에 실패했습니다: ${error.message}`);
                    await fetchPageList();
                    renderPageList();
                }
            }
        }
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
            textEl.textContent = (state.translations && state.translations['mode_write']) || "쓰기모드";
            textEl.setAttribute('data-i18n', 'mode_write');
        }

        // 읽기모드로 전환 시 커버 버튼 숨김
        updateCoverButtonsVisibility();
    }

    stopPageSync();

    try {
        console.log("단일 페이지 요청: GET /api/pages/" + id);
        const page = await api.get("/api/pages/" + encodeURIComponent(id));
        console.log("단일 페이지 응답:", page);

        // 현재 페이지 상태 설정
        state.currentPageId = page.id;
        if (page.collectionId) {
            state.currentCollectionId = page.collectionId;
            state.expandedCollections.add(page.collectionId);
        }

        // 부모 페이지들 확장 (사이드바 트리 표시용)
        let currentParentId = page.parentId;
        while (currentParentId) {
            state.expandedPages.add(currentParentId);
            const parent = state.pages.find(p => p.id === currentParentId);
            currentParentId = parent ? parent.parentId : null;
        }

        let title = "";
        let content = "<p></p>";

        // 투명한 복호화
        if (page.isEncrypted) {
            state.currentPageIsEncrypted = true;

            // 제목은 평문으로 저장됨
            title = page.title || "";

            // 컬렉션 타입 확인
            const collection = state.collections.find(c => c.id === page.collectionId);
            const isSharedCollection = collection && (collection.isShared || !collection.isOwner);

            if (isSharedCollection && collection.isEncrypted) {
                // 암호화된 공유 컬렉션: 컬렉션 키로 복호화
                const collectionKey = await getCollectionKey(collection.id);
                content = await cryptoManager.decryptWithKey(page.encryptedContent, collectionKey);
            } else {
                // 개인 컬렉션 암호화 페이지: 복호화 필요
                throw new Error('암호화된 페이지입니다. 먼저 복호화하세요.');
            }
        } else {
            // 평문 페이지
            state.currentPageIsEncrypted = false;
            title = page.title || "";
            content = page.content || "<p></p>";
        }

        const titleInput = document.querySelector("#page-title-input");
        if (titleInput) {
            titleInput.value = title;
        }

        // 페이지 업데이트 시간 표시
        const updatedAtContainer = document.querySelector("#page-updated-at-container");
        const updatedAtEl = document.querySelector("#page-updated-at");
        if (updatedAtContainer && updatedAtEl) {
            if (page.updatedAt) {
                updatedAtEl.textContent = new Date(page.updatedAt).toLocaleString();
                updatedAtContainer.style.display = "block";
            } else {
                updatedAtContainer.style.display = "none";
            }
        }

        if (state.editor) {
            state.editor.commands.setContent(content, { emitUpdate: false });
        }

        // state.pages 배열 업데이트 (동기화 문제 해결)
        const pageIndex = state.pages.findIndex(p => p.id === page.id);
        if (pageIndex !== -1) {
            // 기존 페이지 업데이트
            state.pages[pageIndex] = {
                ...state.pages[pageIndex],
                title: title,
                content: page.isEncrypted ? undefined : content,
                isEncrypted: page.isEncrypted,
                updatedAt: page.updatedAt,
                coverImage: page.coverImage,
                coverPosition: page.coverPosition,
                horizontalPadding: page.horizontalPadding
            };
        } else {
            // 페이지가 배열에 없으면 추가 (드문 경우)
            state.pages.push({
                id: page.id,
                title: title,
                content: page.isEncrypted ? undefined : content,
                collectionId: page.collectionId,
                isEncrypted: page.isEncrypted,
                updatedAt: page.updatedAt,
                coverImage: page.coverImage,
                coverPosition: page.coverPosition,
                parentId: page.parentId,
                sortOrder: page.sortOrder,
                horizontalPadding: page.horizontalPadding
            });
        }

        renderPageList();

        // 커버 이미지 표시
        if (page.coverImage) {
            showCover(page.coverImage, page.coverPosition || 50);
        } else {
            hideCover();
        }

        // 여백 적용 (모바일에서는 기본 CSS 사용)
        const editorEl = document.querySelector('.editor');
        if (editorEl) {
            const isMobile = window.innerWidth <= 900;
            if (!isMobile && page.horizontalPadding !== null && page.horizontalPadding !== undefined) {
                editorEl.style.paddingLeft = `${page.horizontalPadding}px`;
                editorEl.style.paddingRight = `${page.horizontalPadding}px`;
            } else {
                editorEl.style.paddingLeft = '';
                editorEl.style.paddingRight = '';
            }
        }

        syncPageUpdatedAtPadding();

        // 실시간 동기화 시작 (암호화 페이지는 제외)
        startPageSync(page.id, page.isEncrypted || false);

        // 컬렉션 메타데이터 동기화 시작 (커버 이미지 등)
        if (page.collectionId) {
            startCollectionSync(page.collectionId);
        }

        // 발행 상태 확인
        await checkPublishStatus(page.id);

        // 하위 페이지 로드 및 렌더링
        await loadAndRenderSubpages(page.id);

        // 댓글 로드
        if (window.loadAndRenderComments || loadAndRenderComments) {
            // app.js에서 window에 등록했거나 import한 함수 사용
            const loader = window.loadAndRenderComments || loadAndRenderComments;
            await loader(page.id);
        }

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
 * 검색 키워드 추출 (E2EE 시스템 재설계)
 */
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

/**
 * 현재 페이지 저장 (E2EE 시스템 재설계 - 투명한 암호화)
 */
/**
 * 제목만 저장 (읽기모드 전환 시)
 */
async function savePageTitle() {
    const titleInput = document.querySelector("#page-title-input");

    if (!state.currentPageId || !titleInput) {
        return true;
    }

    const title = titleInput.value || ((state.translations && state.translations['untitled']) || "제목 없음");

    try {
        await api.patch("/api/pages/" + encodeURIComponent(state.currentPageId), { title });

        // 페이지 목록 업데이트
        state.pages = state.pages.map((p) => {
            if (p.id === state.currentPageId) {
                return { ...p, title };
            }
            return p;
        });

        renderPageList();
        return true;
    } catch (error) {
        console.error('제목 저장 실패:', error);
        return false;
    }
}

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

    const defaultTitle = (state.translations && state.translations['untitled']) || "제목 없음";
    let title = titleInput ? titleInput.value || defaultTitle : defaultTitle;
    let content = state.editor.getHTML();

    try {
        // 현재 페이지 정보 조회
        const currentPage = state.pages.find(p => p.id === state.currentPageId);
        if (!currentPage) {
            console.warn("현재 페이지를 state에서 찾을 수 없음.");
            return false;
        }

        let requestBody = {};

        // 페이지가 암호화된 상태(임시 복호화 후 수정)인 경우
        if (state.currentPageIsEncrypted) {
            // state.decryptionKeyIsInMemory 플래그로 키 존재 여부 확인
            if (!state.decryptionKeyIsInMemory) {
                throw new Error("암호화 키가 없어 저장할 수 없습니다. 페이지를 새로고침하고 다시 시도하세요.");
            }
            
            const encryptedContent = await cryptoManager.encrypt(content);
            
            requestBody = {
                title: title,
                content: '', // 원본 content는 비움
                encryptedContent: encryptedContent,
                isEncrypted: true, // 암호화 상태 유지
                // salt는 서버에서 기존 값을 유지하므로 보내지 않음
            };
            
            console.log("임시 복호화된 페이지를 다시 암호화하여 저장합니다.");

        } else {
            // 일반 평문 페이지 저장
            requestBody = {
                title,
                content,
                isEncrypted: false,
                icon: currentPage.icon || null
            };
        }

        const page = await api.put("/api/pages/" + encodeURIComponent(state.currentPageId), requestBody);

        // 저장이 성공하면 임시 암호화 키 제거 및 플래그 초기화
        if (state.currentPageIsEncrypted && state.decryptionKeyIsInMemory) {
            cryptoManager.clearKey();
            state.decryptionKeyIsInMemory = false;
            console.log("재암호화 저장 후 임시 키를 제거하고 플래그를 초기화했습니다.");
        }

        const decryptedTitle = titleInput ? titleInput.value || defaultTitle : defaultTitle;

        state.pages = state.pages.map((p) => {
            if (p.id === page.id) {
                return {
                    ...p,
                    title: decryptedTitle,
                    updatedAt: page.updatedAt,
                    parentId: page.parentId ?? p.parentId ?? null,
                    sortOrder: typeof page.sortOrder === "number" ? page.sortOrder : (typeof p.sortOrder === "number" ? p.sortOrder : 0),
                    icon: page.icon ?? p.icon ?? null
                };
            }
            return p;
        });

        renderPageList();
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
 * 공유 컬렉션 키 조회 (향후 구현 예정)
 * TODO: 마스터 키 없이 컬렉션 암호화 구현
 */
async function getCollectionKey(collectionId) {
    // 현재 마스터 키 시스템 제거로 인해 비활성화
    // 공유 컬렉션 암호화는 컬렉션별 비밀번호 방식으로 재구현 필요
    throw new Error('공유 컬렉션 암호화는 현재 지원되지 않습니다.');
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
    const addCoverBtn = document.getElementById('add-cover-btn');
    const coverContainer = document.getElementById('page-cover-container');

    if (!state.editor || !modeToggleBtn) return;

    if (state.isWriteMode) {
        // 읽기 모드로 전환 시 저장
        await saveCurrentPage();

        // 저장이 성공하면 읽기 모드로 전환
        state.isWriteMode = false;
		state.editor.setEditable(false);
        
        // 읽기 모드로 전환 시 에디터 포커스를 명시적으로 해제해야
    	// 원격 사용자에게 내 커서가 남아있는 현상을 방지할 수 있음.
        state.editor.commands?.blur?.();
        state.editor.view?.dom?.blur?.();
		updateAwarenessMode(state.isWriteMode);

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
            textEl.textContent = (state.translations && state.translations['mode_write']) || "쓰기모드";
            textEl.setAttribute('data-i18n', 'mode_write');
        }

        onLocalEditModeChanged(state.isWriteMode);
        updateCoverButtonsVisibility();
        updatePublishButton();
        onEditModeChange(false);
    } else {
        // 쓰기 모드로 전환
        // 암호화된 페이지의 경우, 복호화 키가 메모리에 있어야만 쓰기 모드 진입 가능
        if (state.currentPageIsEncrypted && !state.decryptionKeyIsInMemory) {
            alert("암호화된 페이지는 편집할 수 없습니다.\n페이지 목록에서 다시 클릭하여 비밀번호를 입력해주세요.");
            return;
        }

        state.isWriteMode = true;
        state.editor.setEditable(true);
		updateAwarenessMode(state.isWriteMode);

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
            textEl.textContent = (state.translations && state.translations['mode_read']) || "읽기모드";
            textEl.setAttribute('data-i18n', 'mode_read');
        }

		onLocalEditModeChanged(state.isWriteMode);
        updateCoverButtonsVisibility();
        updatePublishButton();
        onEditModeChange(true);
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
        const defaultName = (state.translations && state.translations['new_collection_default']) || "새 컬렉션";
        const promptMsg = (state.translations && state.translations['new_collection_prompt']) || "새 컬렉션 이름을 입력하세요.";
        let name = prompt(promptMsg, defaultName);
        if (name === null) return;

        const plainName = name.trim() || defaultName;

        try {
            const collection = await api.post("/api/collections", { name: plainName });

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
