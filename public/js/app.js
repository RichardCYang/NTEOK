// 문단 정렬(TextAlign) 익스텐션 ESM import
import { TextAlign } from "https://esm.sh/@tiptap/extension-text-align@2.0.0-beta.209";

// 텍스트 색상(Color) / TextStyle 익스텐션 ESM import
import Color from "https://esm.sh/@tiptap/extension-color@2.0.0-beta.209";
import TextStyle from "https://esm.sh/@tiptap/extension-text-style@2.0.0-beta.209";

// 전역 Tiptap 번들에서 Editor / StarterKit 가져오기
// index.html 에서 tiptap-for-browser.min.js 우선 로딩 필요
const Editor = Tiptap.Core.Editor;
const StarterKit = Tiptap.StarterKit;

const Extension = Tiptap.Core.Extension;

const CustomEnter = Extension.create({
    name: "customEnter",
    addKeyboardShortcuts() {
        return {
            Enter: ({ editor }) => {
                // 일반 코드 블록 안에서는 줄바꿈만 수행
                if (editor.isActive("codeBlock")) {
                    return editor.commands.newlineInCode();
                }

                // 구분선(horizontalRule) 노드가 선택되어 있을 때, hr 뒤로 커서를 옮긴 다음, 그 위치에 빈 문단 <p></p>를 삽입
                if (editor.isActive("horizontalRule")) {
	                const { state } = editor;
                    const { selection } = state;

                    // selection.to = 현재 선택(구분선) 바로 뒤에 위치
                    const posAfterHr = selection.to;

                    return editor
                        .chain()
                        .focus()
                        .setTextSelection(posAfterHr)   // hr 뒤에 텍스트 커서 배치
                        .insertContent("<p></p>")       // 그 위치에 새 문단 삽입
                        .run();
                }

                // 그 외에는 StarterKit 기본 Enter 동작(문단 분리 등)에 역할 위임
	            // → false를 반환하면 다른 익스텐션(StarterKit)의 Enter 핸들러가 실행
	            return false;
            },
            "Shift-Enter": ({ editor }) => {
                // 같은 블록 안에서 줄바꿈만 하고 싶을 때 사용
                return editor.commands.setHardBreak();
            }
        };
    }
});

let editor = null;
let pages = [];
let collections = [];
let currentPageId = null;
let currentCollectionId = null;
let colorDropdownElement = null;
let colorMenuElement = null;

// 슬래시(/) 명령 블록 메뉴 관련 상태
const SLASH_ITEMS = [
    {
        id: "text",
        label: "텍스트",
        description: "기본 문단 블록",
        icon: "T",
        command(editor) {
            editor.chain().focus().setParagraph().run();
        }
    },
    {
        id: "heading1",
        label: "제목 1",
        description: "큰 제목(Heading 1)",
        icon: "H1",
        command(editor) {
            editor.chain().focus().setHeading({ level: 1 }).run();
        }
    },
    {
        id: "heading2",
        label: "제목 2",
        description: "중간 제목(Heading 2)",
        icon: "H2",
        command(editor) {
            editor.chain().focus().setHeading({ level: 2 }).run();
        }
    },
    {
        id: "bulletList",
        label: "글머리 기호 목록",
        description: "점 목록 블록",
        icon: "•",
        command(editor) {
            editor.chain().focus().toggleBulletList().run();
        }
    },
    {
        id: "orderedList",
        label: "번호 목록",
        description: "순서 있는 목록",
        icon: "1.",
        command(editor) {
            editor.chain().focus().toggleOrderedList().run();
        }
    },
    {
        id: "blockquote",
        label: "인용구",
        description: "강조된 인용 블록",
        icon: "❝",
        command(editor) {
            editor.chain().focus().toggleBlockquote().run();
        }
    },
    {
        id: "codeBlock",
        label: "코드 블록",
        description: "고정폭 코드 블록",
        icon: "</>",
        command(editor) {
            editor.chain().focus().toggleCodeBlock().run();
        }
    }
];

let slashMenuEl = null;
let slashActiveIndex = 0;
let slashState = {
    active: false,
    fromPos: null
};

function showErrorInEditor(message) {
    if (editor) {
        editor.commands.setContent(`<p style="color: red;">${message}</p>`, { emitUpdate: false });
    } else {
        const el = document.querySelector("#editor");
        if (el) {
            el.innerHTML = `<p style="color: red;">${message}</p>`;
        }
    }
}

function createSlashMenuElement() {
    if (slashMenuEl) {
        return;
    }

    slashMenuEl = document.createElement("div");
    slashMenuEl.id = "slash-menu";
    slashMenuEl.className = "slash-menu hidden";

    const listEl = document.createElement("ul");
    listEl.className = "slash-menu-list";

    SLASH_ITEMS.forEach((item, index) => {
        const li = document.createElement("li");
        li.className = "slash-menu-item";
        li.dataset.id = item.id;

        if (index === 0) {
            li.classList.add("active");
        }

        li.innerHTML = `
            <div class="slash-menu-item-icon">${item.icon}</div>
            <div class="slash-menu-item-main">
                <div class="slash-menu-item-label">${item.label}</div>
                <div class="slash-menu-item-desc">${item.description}</div>
            </div>
        `;

        listEl.appendChild(li);
    });

    slashMenuEl.appendChild(listEl);
    document.body.appendChild(slashMenuEl);

    // 클릭으로 항목 선택
    slashMenuEl.addEventListener("click", (event) => {
        const li = event.target.closest(".slash-menu-item");
        if (!li) {
            return;
        }
        const id = li.dataset.id;
        runSlashCommand(id);
    });
}

function openSlashMenu(coords, fromPos) {
    if (!slashMenuEl) {
        createSlashMenuElement();
    }

    slashState.active = true;
    slashState.fromPos = fromPos;
    slashActiveIndex = 0;

    const items = slashMenuEl.querySelectorAll(".slash-menu-item");
    items.forEach((el, index) => {
        if (index === 0) {
            el.classList.add("active");
        } else {
            el.classList.remove("active");
        }
    });

    slashMenuEl.style.left = `${coords.left}px`;
    slashMenuEl.style.top = `${coords.bottom + 4}px`;
    slashMenuEl.classList.remove("hidden");
}

function closeSlashMenu() {
    slashState.active = false;
    slashState.fromPos = null;
    if (slashMenuEl) {
        slashMenuEl.classList.add("hidden");
    }
}

function moveSlashActive(delta) {
    if (!slashMenuEl) {
        return;
    }
    const items = Array.from(slashMenuEl.querySelectorAll(".slash-menu-item"));
    if (!items.length) {
        return;
    }
    slashActiveIndex = (slashActiveIndex + delta + items.length) % items.length;
    items.forEach((el, index) => {
        if (index === slashActiveIndex) {
            el.classList.add("active");
            el.scrollIntoView({ block: "nearest" });
        } else {
            el.classList.remove("active");
        }
    });
}

function runSlashCommand(id) {
    if (!editor) {
        return;
    }
    const item = SLASH_ITEMS.find((x) => x.id === id);
    if (!item) {
        closeSlashMenu();
        return;
    }

    editor.chain().focus();

    // 슬래시 문자 하나를 제거
    if (typeof slashState.fromPos === "number") {
        editor
            .chain()
            .focus()
            .deleteRange({
                from: slashState.fromPos,
                to: slashState.fromPos + 1
            })
            .run();
    }

    item.command(editor);
    closeSlashMenu();
}

function runSlashCommandActive() {
    if (!slashMenuEl) {
        return;
    }
    const items = Array.from(slashMenuEl.querySelectorAll(".slash-menu-item"));
    if (!items.length) {
        return;
    }
    const active = items[slashActiveIndex];
    const id = active.dataset.id;
    runSlashCommand(id);
}

// 슬래시 명령용 키보드 바인딩
function bindSlashKeyHandlers() {
    document.addEventListener("keydown", (event) => {
        if (!editor) {
            return;
        }

        const target = event.target;
        const inEditor =
            target && target.closest && target.closest(".ProseMirror");

        // 에디터 안에서 "/" 입력 시 슬래시 메뉴 활성화
        if (!slashState.active && event.key === "/" && inEditor) {
            try {
                const selection = editor.state.selection;
                const pos = selection.from;
                const coords = editor.view.coordsAtPos(pos);
                openSlashMenu(coords, pos);
            } catch (e) {
                console.error("슬래시 메뉴 좌표 계산 실패:", e);
            }
            // "/" 자체는 그대로 입력되도록 기본 동작은 막지 않음
            return;
        }

        // 슬래시 메뉴가 열려 있을 때의 키 처리
        if (slashState.active) {
            if (event.key === "ArrowDown") {
                event.preventDefault();
                moveSlashActive(1);
                return;
            }
            if (event.key === "ArrowUp") {
                event.preventDefault();
                moveSlashActive(-1);
                return;
            }
            if (event.key === "Enter") {
                event.preventDefault();
                runSlashCommandActive();
                return;
            }
            if (event.key === "Escape") {
                event.preventDefault();
                closeSlashMenu();
                return;
            }
        }
    });
}

function initEditor() {
    const element = document.querySelector("#editor");

    editor = new Editor({
        element,
        extensions: [
            StarterKit,
            CustomEnter,
            TextAlign.configure({
                // 어떤 노드에 정렬 속성을 붙일지 (제목 + 문단)
                types: ["heading", "paragraph"],
                // 사용할 정렬 옵션들
                alignments: ["left", "center", "right", "justify"],
            }),
            // 텍스트 색상 기능을 위한 TextStyle / Color 익스텐션
            TextStyle,
            Color,
        ],
        content: "<p>불러오는 중...</p>",
        onSelectionUpdate() {
            updateToolbarState();
        },
        onTransaction() {
            updateToolbarState();
        },
        onCreate() {
            updateToolbarState();
        }
    });
}

function getCurrentTextAlign() {
    if (!editor) {
        return null;
    }

    // 먼저 heading에서 정렬을 찾고, 없으면 paragraph에서 찾음
    const headingAttrs = editor.getAttributes("heading");
    if (headingAttrs && headingAttrs.textAlign) {
        return headingAttrs.textAlign;
    }

    const paragraphAttrs = editor.getAttributes("paragraph");
    if (paragraphAttrs && paragraphAttrs.textAlign) {
        return paragraphAttrs.textAlign;
    }

    return null;
}

function updateToolbarState() {
    if (!editor) {
        return;
    }

    const toolbar = document.querySelector(".editor-toolbar");
    if (!toolbar) {
        return;
    }

    const buttons = toolbar.querySelectorAll("button[data-command]");
    const currentAlign = getCurrentTextAlign();  // 지금 정렬 상태 한 번만 계산

    buttons.forEach((button) => {
        const command = button.getAttribute("data-command");
        let isActive = false;

        switch (command) {
            case "bold":
                isActive = editor.isActive("bold");
                break;
            case "italic":
                isActive = editor.isActive("italic");
                break;
            case "strike":
                isActive = editor.isActive("strike");
                break;
            case "h1":
                isActive = editor.isActive("heading", { level: 1 });
                break;
            case "h2":
                isActive = editor.isActive("heading", { level: 2 });
                break;
            case "bulletList":
                isActive = editor.isActive("bulletList");
                break;
            case "orderedList":
                isActive = editor.isActive("orderedList");
                break;
            case "blockquote":
                isActive = editor.isActive("blockquote");
                break;
            case "codeBlock":
                isActive = editor.isActive("codeBlock");
                break;
            case "alignLeft":
                isActive = currentAlign === "left";
                break;
            case "alignCenter":
                isActive = currentAlign === "center";
                break;
            case "alignRight":
                isActive = currentAlign === "right";
                break;
            case "alignJustify":
                isActive = currentAlign === "justify";
                break;
            default:
                break;
        }

        if (isActive) {
            button.classList.add("active");
        } else {
            button.classList.remove("active");
        }
    });
}

function bindToolbar() {
    const toolbar = document.querySelector(".editor-toolbar");
    if (!toolbar) {
        return;
    }

    // 색상 드롭다운 / 메뉴 DOM 캐시
    colorDropdownElement = toolbar.querySelector("[data-role='color-dropdown']");
    colorMenuElement = colorDropdownElement
        ? colorDropdownElement.querySelector("[data-color-menu]")
        : null;

    toolbar.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-command]");
        if (!button || !editor) {
            return;
        }

        const command = button.getAttribute("data-command");
        const colorValue = button.getAttribute("data-color");

        // 드롭다운 열기/닫기
        if (command === "toggleColorDropdown") {
            if (!colorMenuElement || !colorDropdownElement) {
                return;
            }

            const isOpen = !colorMenuElement.hasAttribute("hidden");

            if (isOpen) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            } else {
                colorMenuElement.removeAttribute("hidden");
                colorDropdownElement.classList.add("open");
            }

            return;
        }

        // 색상 선택 (드롭다운 내부 버튼)
        if (command === "setColor" && colorValue) {
            editor.chain().focus().setColor(colorValue).run();

            // 색상 선택 후 드롭다운 닫기
            if (colorMenuElement && colorDropdownElement) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            }

            updateToolbarState();
            return;
        }

        // 색상 초기화
        if (command === "unsetColor") {
            editor.chain().focus().unsetColor().run();

            if (colorMenuElement && colorDropdownElement) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            }

            updateToolbarState();
            return;
        }

        switch (command) {
            case "bold":
                editor.chain().focus().toggleBold().run();
                break;
            case "italic":
                editor.chain().focus().toggleItalic().run();
                break;
            case "strike":
                editor.chain().focus().toggleStrike().run();
                break;
            case "h1":
                editor.chain().focus().toggleHeading({ level: 1 }).run();
                break;
            case "h2":
                editor.chain().focus().toggleHeading({ level: 2 }).run();
                break;
            case "bulletList":
                editor.chain().focus().toggleBulletList().run();
                break;
            case "orderedList":
                editor.chain().focus().toggleOrderedList().run();
                break;
            case "alignLeft":
                editor.chain().focus().setTextAlign("left").run();
                break;
            case "alignCenter":
                editor.chain().focus().setTextAlign("center").run();
                break;
            case "alignRight":
                editor.chain().focus().setTextAlign("right").run();
                break;
            case "alignJustify":
                editor.chain().focus().setTextAlign("justify").run();
                break;
            case "blockquote":
                editor.chain().focus().toggleBlockquote().run();
                break;
            case "codeBlock":
                editor.chain().focus().toggleCodeBlock().run();
                break;
            default:
                break;
        }

        updateToolbarState();
    });
}

async function fetchCollections() {
    try {
        console.log("컬렉션 목록 요청: GET /api/collections");
        const res = await fetch("/api/collections");
        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const data = await res.json();
        collections = Array.isArray(data) ? data : [];

        if (!currentCollectionId && collections.length) {
            currentCollectionId = collections[0].id;
        }

        renderPageList();
    } catch (error) {
        console.error("컬렉션 목록 요청 오류:", error);
        showErrorInEditor("컬렉션을 불러오는 데 실패했다: " + error.message);
    }
}

async function fetchPageList() {
    try {
        console.log("페이지 목록 요청: GET /api/pages");
        const res = await fetch("/api/pages");
        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const data = await res.json();
        console.log("페이지 목록 응답:", data);

        pages = Array.isArray(data) ? data : [];
        renderPageList();

        const firstInCollection = pages.find((p) => p.collectionId === currentCollectionId);

        if (firstInCollection && !currentPageId) {
            currentPageId = firstInCollection.id;
            await loadPage(currentPageId);
        } else if (!pages.length) {
            if (editor) {
                editor.commands.setContent("<p>새 페이지를 만들어보자.</p>", { emitUpdate: false });
            }
        }
    } catch (error) {
        console.error("페이지 목록 요청 오류:", error);
        showErrorInEditor("페이지 목록을 불러오는 데 실패했다: " + error.message);
    }
}

function buildPageTree(flatPages) {
    const map = new Map();

    flatPages.forEach((p) => {
        map.set(p.id, {
            ...p,
            parentId: p.parentId || null,
            sortOrder:
                typeof p.sortOrder === "number" ? p.sortOrder : 0,
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
        return bTime - aTime; // 최신순
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

function renderPageList() {
    const listEl = document.querySelector("#collection-list");
    if (!listEl) {
        return;
    }

    listEl.innerHTML = "";

    if (!collections.length) {
        const empty = document.createElement("li");
        empty.className = "collection-empty";
        empty.textContent = "컬렉션이 없습니다. 아래에서 새 컬렉션을 추가하세요.";
        listEl.appendChild(empty);
        return;
    }

    collections.forEach((collection) => {
        const item = document.createElement("li");
        item.className = "collection-item";
        item.dataset.collectionId = collection.id;

        if (collection.id === currentCollectionId) {
            item.classList.add("active");
        }

        const header = document.createElement("div");
        header.className = "collection-header";

        const title = document.createElement("div");
        title.className = "collection-title";
        title.innerHTML = `<i class="fa-regular fa-folder"></i> ${collection.name || "제목 없음"}`;

        const actions = document.createElement("div");
        actions.className = "collection-actions";

        const addBtn = document.createElement("button");
        addBtn.type = "button";
        addBtn.className = "collection-add-page-btn";
        addBtn.dataset.collectionId = collection.id;
        addBtn.title = "이 컬렉션에 페이지 추가";
        addBtn.innerHTML = `<i class="fa-solid fa-plus"></i>`;

        const meta = document.createElement("div");
        meta.className = "collection-meta";
        meta.textContent = collection.updatedAt
            ? new Date(collection.updatedAt).toLocaleDateString()
            : "";

        actions.appendChild(meta);
        actions.appendChild(addBtn);

        header.appendChild(title);
        header.appendChild(actions);

        item.appendChild(header);

        const pageList = document.createElement("ul");
        pageList.className = "page-list";

        const colPages = pages.filter((p) => p.collectionId === collection.id);
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

                // 깊이에 따른 들여쓰기
                li.style.paddingLeft = 14 + depth * 16 + "px";

                const titleSpan = document.createElement("span");
                titleSpan.className = "page-list-item-title";
                titleSpan.textContent = node.title || "제목 없음";

                const dateSpan = document.createElement("span");
                dateSpan.className = "page-list-item-date";
                dateSpan.textContent = node.updatedAt
                    ? new Date(node.updatedAt).toLocaleString()
                    : "";

                li.appendChild(titleSpan);
                li.appendChild(dateSpan);

                if (node.id === currentPageId) {
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

        listEl.appendChild(item);
    });
}

async function loadPage(id) {
    if (!id) {
        return;
    }

    try {
        console.log("단일 페이지 요청: GET /api/pages/" + id);
        const res = await fetch("/api/pages/" + encodeURIComponent(id));
        if (!res.ok) {
            throw new Error("HTTP " + res.status + " " + res.statusText);
        }

        const page = await res.json();
        console.log("단일 페이지 응답:", page);

        currentPageId = page.id;
        if (page.collectionId) {
            currentCollectionId = page.collectionId;
        }

        const titleInput = document.querySelector("#page-title-input");
        if (titleInput) {
            titleInput.value = page.title || "";
        }

        if (editor) {
            editor.commands.setContent(page.content || "<p></p>", { emitUpdate: false });
        }

        renderPageList();
    } catch (error) {
        console.error("단일 페이지 로드 오류:", error);
        showErrorInEditor("페이지를 불러오지 못했다: " + error.message);
    }
}

function bindPageListClick() {
    const listEl = document.querySelector("#collection-list");
    if (!listEl) {
        return;
    }

    listEl.addEventListener("click", async (event) => {
        const addBtn = event.target.closest(".collection-add-page-btn");
        if (addBtn) {
            const colId = addBtn.dataset.collectionId;
            if (!colId) {
                return;
            }

            const title = prompt("새 페이지 제목을 입력하세요.", "새 페이지");
            if (title === null) {
                return;
            }

            try {
                const res = await fetch("/api/pages", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        title: title.trim() || "새 페이지",
                        parentId: null,
                        collectionId: colId
                    })
                });

                if (!res.ok) {
                    throw new Error("HTTP " + res.status + " " + res.statusText);
                }

                const page = await res.json();
                pages.unshift({
                    id: page.id,
                    title: page.title,
                    updatedAt: page.updatedAt,
                    parentId: page.parentId || null,
                    collectionId: page.collectionId || colId,
                    sortOrder: typeof page.sortOrder === "number" ? page.sortOrder : 0
                });

                currentCollectionId = colId;
                currentPageId = page.id;
                renderPageList();
                await loadPage(page.id);
            } catch (error) {
                console.error("컬렉션 내 페이지 생성 오류:", error);
                alert("페이지를 생성하지 못했다: " + error.message);
            }

            return;
        }

        const collectionHeader = event.target.closest(".collection-header");
        if (collectionHeader) {
            const container = collectionHeader.closest(".collection-item");
            const colId = container ? container.dataset.collectionId : null;
            if (colId && colId !== currentCollectionId) {
                currentCollectionId = colId;
                currentPageId = null;
                renderPageList();

                const first = pages.find((p) => p.collectionId === colId);
                if (first) {
                    await loadPage(first.id);
                } else if (editor) {
                    editor.commands.setContent("<p>이 컬렉션에 페이지가 없습니다.</p>", { emitUpdate: false });
                    const titleInput = document.querySelector("#page-title-input");
                    if (titleInput) {
                        titleInput.value = "";
                    }
                }
            }
            return;
        }

        const li = event.target.closest("li.page-list-item");
        if (!li) {
            return;
        }

        const pageId = li.dataset.pageId;
        if (!pageId || pageId === currentPageId) {
            return;
        }

        await loadPage(pageId);
    });
}

function bindNewCollectionButton() {
    const btn = document.querySelector("#new-collection-btn");
    if (!btn) {
        return;
    }

    btn.addEventListener("click", async () => {
        const name = prompt("새 컬렉션 이름을 입력하세요.", "새 컬렉션");
        if (name === null) {
            return;
        }

        try {
            const res = await fetch("/api/collections", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ name })
            });

            if (!res.ok) {
                throw new Error("HTTP " + res.status + " " + res.statusText);
            }

            const collection = await res.json();
            collections.push(collection);
            currentCollectionId = collection.id;
            currentPageId = null;

            renderPageList();

            if (editor) {
                editor.commands.setContent("<p>이 컬렉션에 새 페이지를 추가해 보세요.</p>", { emitUpdate: false });
            }
        } catch (error) {
            console.error("새 컬렉션 생성 오류:", error);
            alert("새 컬렉션을 생성하지 못했다: " + error.message);
        }
    });
}

function bindSaveButton() {
    const btn = document.querySelector("#save-page-btn");
    const titleInput = document.querySelector("#page-title-input");

    if (!btn) {
        return;
    }

    btn.addEventListener("click", async () => {
        if (!currentPageId) {
            alert("저장할 페이지가 없음.");
            return;
        }
        if (!editor) {
            alert("에디터가 초기화되지 않음.");
            return;
        }

        const title = titleInput ? titleInput.value || "제목 없음" : "제목 없음";
        const content = editor.getHTML();

        try {
            const res = await fetch("/api/pages/" + encodeURIComponent(currentPageId), {
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

            pages = pages.map((p) => {
                if (p.id === page.id) {
                	return {
                        ...p,
                        title: page.title,
                        updatedAt: page.updatedAt,
                        parentId: page.parentId ?? p.parentId ?? null,
                        sortOrder:
                            typeof page.sortOrder === "number"
                                ? page.sortOrder
                                : (typeof p.sortOrder === "number" ? p.sortOrder : 0)
                    };
                }
                return p;
            });

            renderPageList();
            alert("저장 완료.");
        } catch (error) {
            console.error("페이지 저장 오류:", error);
            alert("페이지 저장 실패: " + error.message);
        }
    });

    // Ctrl+S / Cmd+S 로 저장
    document.addEventListener("keydown", (event) => {
        if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") {
            event.preventDefault();
            btn.click();
        }
    });
}

function bindDeleteButton() {
    const btn = document.querySelector("#delete-page-btn");
    if (!btn) {
        return;
    }

    btn.addEventListener("click", async () => {
        if (!currentPageId) {
            alert("삭제할 페이지 없음.");
            return;
        }

        const ok = confirm("정말 이 페이지를 삭제 하시겠습니까?");
        if (!ok) {
            return;
        }

        try {
            const res = await fetch("/api/pages/" + encodeURIComponent(currentPageId), {
                method: "DELETE"
            });

            if (!res.ok) {
                throw new Error("HTTP " + res.status + " " + res.statusText);
            }

            const result = await res.json();
            console.log("페이지 삭제 응답:", result);

            // 삭제된 노트 및 자식 노트까지 반영되도록 전체 목록 새로 로딩
            currentPageId = null;
            await fetchPageList(); // 내부에서 renderPageList + 첫 페이지 로드 처리

            if (!pages.length) {
                const titleInput = document.querySelector("#page-title-input");
                if (titleInput) {
                    titleInput.value = "";
                }
                if (editor) {
                    editor.commands.setContent("<p>새 페이지를 만들어보자.</p>", { emitUpdate: false });
                }
            }

            renderPageList();

            if (currentPageId) {
                await loadPage(currentPageId);
            } else {
                const titleInput = document.querySelector("#page-title-input");
                if (titleInput) {
                    titleInput.value = "";
                }
                if (editor) {
                    editor.commands.setContent("<p>새 페이지를 만들어보자.</p>", { emitUpdate: false });
                }
            }
        } catch (error) {
            console.error("페이지 삭제 오류:", error);
            alert("페이지 삭제 실패: " + error.message);
        }
    });
}

function bindLogoutButton() {
    const btn = document.querySelector("#logout-btn");
    if (!btn) {
        return;
    }

    btn.addEventListener("click", async () => {
        try {
            const res = await fetch("/api/auth/logout", {
                method: "POST"
            });

            if (!res.ok) {
                throw new Error("HTTP " + res.status);
            }

            window.location.href = "/login";
        } catch (error) {
            console.error("로그아웃 실패:", error);
            alert("로그아웃 중 오류가 발생했습니다.");
        }
    });
}

function initEvent() {
    document.addEventListener("click", (event) => {
    	// 글자 색상 선택 드롭다운 메뉴 바깥을 클릭하면 드롭다운 닫기 구현
        // 글자 색상 선택 드롭다운 요소가 아직 준비되지 않은 경우
        if (!colorDropdownElement || !colorMenuElement)
            return;

        // 드롭다운 내부를 클릭한 경우는 무시
        if (colorDropdownElement.contains(event.target))
            return;

        // 글자 색상 선택 드롭다운 메뉴 열려 있으면 닫기
        if (!colorMenuElement.hasAttribute("hidden")) {
            colorMenuElement.setAttribute("hidden", "");
            colorDropdownElement.classList.remove("open");
        }
    });

	document.addEventListener('click', (event) => {
		// 슬래시 메뉴 바깥을 클릭하면 슬래시 메뉴 닫기 구현
		// 슬래시 메뉴 요소가 아직 준비되지 않은 경우
		if (!slashState || !slashMenuEl)
			return;

		// 슬래시 메뉴가 안 열려 있는 경우는 무시
		if (!slashState.active)
			return;

		// 슬래시 메뉴 내부를 클릭한 경우는 무시
		if (slashMenuEl.contains(event.target))
			return;

		// 그 외 상황에서는 메뉴 닫기
		closeSlashMenu();
	});
}

function init() {
    initEditor();
	initEvent();
    bindToolbar();
    bindPageListClick();
    bindNewCollectionButton();
    bindSaveButton();
    bindDeleteButton();
    bindSlashKeyHandlers();
	bindLogoutButton();
    fetchCollections().then(() => fetchPageList());
}

document.addEventListener("DOMContentLoaded", () => {
    init();
});