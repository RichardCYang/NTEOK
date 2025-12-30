/**
 * 페이지 및 컬렉션 관리 모듈
 */

import { secureFetch } from './ui-utils.js';
import { escapeHtml, showErrorInEditor } from './ui-utils.js';
import { startPageSync, stopPageSync, startCollectionSync, stopCollectionSync, flushPendingUpdates, syncEditorFromMetadata, onLocalEditModeChanged, updateAwarenessMode } from './sync-manager.js';
import { showCover, hideCover, updateCoverButtonsVisibility } from './cover-manager.js';
import { checkPublishStatus, updatePublishButton } from './publish-manager.js';

// 전역 상태 (app.js에서 전달받음)
let state = {
    editor: null,
    pages: [],
    collections: [],
    currentPageId: null,
    currentCollectionId: null,
    expandedCollections: new Set(),
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

        // renderPageList()는 호출하는 쪽에서 처리 (중복 호출 방지)
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

        // 제목은 평문으로 저장되므로 복호화 불필요
        const pages = Array.isArray(data) ? data : [];

        state.pages.length = 0;
        state.pages.push(...pages);

        // renderPageList()는 호출하는 쪽에서 처리 (중복 호출 방지)

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
        empty.textContent = "컬렉션이 없습니다. 아래에서 새 컬렉션을 추가하세요.";
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
            pageList.dataset.collectionId = collection.id;
            pageList.dataset.parentId = "null";

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

                    // 아이콘 표시 로직
                    let iconHtml = '';
                    if (node.icon) {
                        // 사용자가 설정한 아이콘 표시
                        if (node.icon.startsWith('fa-')) {
                            // Font Awesome 아이콘
                            iconHtml = `<i class="${node.icon}" style="margin-right: 6px; color: #2d5f5d;"></i>`;
                        } else {
                            // 이모지
                            iconHtml = `<span style="margin-right: 6px; font-size: 16px;">${node.icon}</span>`;
                        }
                    } else if (node.isEncrypted) {
                        // 암호화 페이지는 자물쇠 아이콘 표시
                        iconHtml = `<i class="fa-solid fa-lock" style="margin-right: 6px; color: #2d5f5d;"></i>`;
                    }

                    titleSpan.innerHTML = iconHtml + escapeHtml(node.title || "제목 없음");

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
                const res = await secureFetch('/api/collections/reorder', {
                    method: 'PATCH',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ collectionIds })
                });

                if (!res.ok) {
                    const errorData = await res.json();
                    throw new Error(errorData.error || '순서 변경 실패');
                }

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
                    const res = await secureFetch('/api/pages/reorder', {
                        method: 'PATCH',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            collectionId: toCollectionId,
                            pageIds,
                            parentId: toParentId
                        })
                    });

                    if (!res.ok) {
                        const errorData = await res.json();
                        throw new Error(errorData.error || '순서 변경 실패');
                    }

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

                    const res = await secureFetch(`/api/pages/${pageId}/move`, {
                        method: 'PATCH',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            targetCollectionId: toCollectionId,
                            targetParentId: toParentId,
                            sortOrder: newSortOrder
                        })
                    });

                    if (!res.ok) {
                        const errorData = await res.json();
                        throw new Error(errorData.error || '페이지 이동 실패');
                    }

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
            textEl.textContent = "쓰기모드";
        }

        // 읽기모드로 전환 시 커버 버튼 숨김
        updateCoverButtonsVisibility();
    }

    try {
        console.log("단일 페이지 요청: GET /api/pages/" + id);
        const res = await fetch("/api/pages/" + encodeURIComponent(id));
        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const page = await res.json();
        console.log("단일 페이지 응답:", page);

        // 현재 페이지 상태 설정
        state.currentPageId = page.id;
        if (page.collectionId) {
            state.currentCollectionId = page.collectionId;
            state.expandedCollections.add(page.collectionId);
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

        // 실시간 동기화 시작 (암호화 페이지는 제외)
        startPageSync(page.id, page.isEncrypted || false);

        // 컬렉션 메타데이터 동기화 시작 (커버 이미지 등)
        if (page.collectionId) {
            startCollectionSync(page.collectionId);
        }

        // 발행 상태 확인
        await checkPublishStatus(page.id);

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

    const title = titleInput.value || "제목 없음";

    try {
        await secureFetch("/api/pages/" + encodeURIComponent(state.currentPageId), {
            method: "PATCH",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ title })
        });

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

    let title = titleInput ? titleInput.value || "제목 없음" : "제목 없음";
    let content = state.editor.getHTML();

    try {
        // 현재 페이지 정보 조회
        const currentPage = state.pages.find(p => p.id === state.currentPageId);
        if (!currentPage) {
            console.warn("현재 페이지를 state에서 찾을 수 없음.");
            return false;
        }

        // 컬렉션 정보 조회
        const collection = state.collections.find(c => c.id === currentPage.collectionId);
        const isSharedCollection = collection && (collection.isShared || !collection.isOwner);

        let requestBody = {};

        // 암호화된 페이지인 경우 수정 불가 (먼저 복호화 필요)
        if (currentPage.isEncrypted) {
            alert('암호화된 페이지는 수정할 수 없습니다. 먼저 복호화하세요.');
            return false;
        }

        // 공유 컬렉션 vs 개인 컬렉션 구분
        if (isSharedCollection) {
            if (collection.isEncrypted) {
                // 암호화된 공유 컬렉션: 컬렉션 키 사용
                const collectionKey = await getCollectionKey(collection.id);
                requestBody = {
                    title: title,  // 제목은 평문으로
                    content: '',  // 내용은 빈 문자열 (암호화됨)
                    encryptedContent: await cryptoManager.encryptWithKey(content, collectionKey),
                    isEncrypted: true,
                    icon: currentPage.icon || null  // 아이콘 유지
                };
            } else {
                // 평문 공유 컬렉션
                requestBody = {
                    title,
                    content,
                    isEncrypted: false,
                    icon: currentPage.icon || null  // 아이콘 유지
                };
            }
        } else {
            // 개인 컬렉션: 기본적으로 평문 저장 (선택적 암호화)
            requestBody = {
                title,
                content,
                isEncrypted: false,
                icon: currentPage.icon || null  // 아이콘 유지
            };
        }

        const res = await secureFetch("/api/pages/" + encodeURIComponent(state.currentPageId), {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(requestBody)
        });

        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const page = await res.json();
        const decryptedTitle = titleInput ? titleInput.value || "제목 없음" : "제목 없음";

        state.pages = state.pages.map((p) => {
            if (p.id === page.id) {
                return {
                    ...p,
                    title: decryptedTitle,
                    updatedAt: page.updatedAt,
                    parentId: page.parentId ?? p.parentId ?? null,
                    sortOrder: typeof page.sortOrder === "number" ? page.sortOrder : (typeof p.sortOrder === "number" ? p.sortOrder : 0),
                    icon: page.icon ?? p.icon ?? null  // 아이콘 업데이트
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
        // 대기 중인 업데이트를 즉시 실행 (yMetadata에 저장)
        flushPendingUpdates();

        // yMetadata → 에디터 명시적 동기화 (읽기 모드 전환 전)
        syncEditorFromMetadata();

        // 제목만 저장 (content는 Yjs 동기화에 의존)
        await savePageTitle();

        state.isWriteMode = false;
        state.editor.setEditable(false);
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
            textEl.textContent = "쓰기모드";
        }

        onLocalEditModeChanged();

        // 읽기모드 진입 시 커버 버튼 숨김
        updateCoverButtonsVisibility();
        updatePublishButton();
    } else {
        // 암호화된 페이지는 쓰기 모드 진입 차단
        if (state.currentPageIsEncrypted) {
            alert("암호화된 페이지는 편집할 수 없습니다.\n편집하려면 먼저 복호화하세요.");
            return;
        }

        // DB 로드 제거: 실시간 동기화로 이미 최신 상태

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
            textEl.textContent = "읽기모드";
        }

		onLocalEditModeChanged();

        // 쓰기모드 진입 시 커버 버튼 표시
        updateCoverButtonsVisibility();
        updatePublishButton();
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
