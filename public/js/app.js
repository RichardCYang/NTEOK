// 문단 정렬(TextAlign) 익스텐션 ESM import
import { TextAlign } from "https://esm.sh/@tiptap/extension-text-align@2.0.0-beta.209";

// 텍스트 색상(Color) / TextStyle 익스텐션 ESM import
import Color from "https://esm.sh/@tiptap/extension-color@2.0.0-beta.209";
import TextStyle from "https://esm.sh/@tiptap/extension-text-style@2.0.0-beta.209";

// 폰트 패밀리(FontFamily) 익스텐션 ESM import
import FontFamily from "https://esm.sh/@tiptap/extension-font-family@2.0.0-beta.209";

// 전역 Tiptap 번들에서 Editor / StarterKit 가져오기
// index.html 에서 tiptap-for-browser.min.js 우선 로딩 필요
const Editor = Tiptap.Core.Editor;
const StarterKit = Tiptap.StarterKit;

const Extension = Tiptap.Core.Extension;

/**
 * 보안 개선: CSRF 토큰이 포함된 fetch 래퍼 함수
 * POST, PUT, DELETE 요청에 자동으로 CSRF 토큰 헤더 추가
 */
function secureFetch(url, options = {}) {
    // GET 요청이 아닌 경우 CSRF 토큰 추가
    if (!options.method || options.method.toUpperCase() !== 'GET') {
        options = window.csrfUtils.addCsrfHeader(options);
    }
    return fetch(url, options);
}

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
let expandedCollections = new Set();
let colorDropdownElement = null;
let colorMenuElement = null;
let fontDropdownElement = null;
let fontMenuElement = null;
let isWriteMode = false;
let currentUser = null;
let userSettings = {
    defaultMode: 'read' // 'read' or 'write'
};

// 시스템 폰트 리스트 (운영체제에 일반적으로 설치된 폰트들)
const SYSTEM_FONTS = [
    { name: "기본 폰트", value: null },
    { name: "Arial", value: "Arial, sans-serif" },
    { name: "Arial Black", value: "'Arial Black', sans-serif" },
    { name: "Comic Sans MS", value: "'Comic Sans MS', cursive" },
    { name: "Courier New", value: "'Courier New', monospace" },
    { name: "Georgia", value: "Georgia, serif" },
    { name: "Impact", value: "Impact, sans-serif" },
    { name: "Tahoma", value: "Tahoma, sans-serif" },
    { name: "Times New Roman", value: "'Times New Roman', serif" },
    { name: "Trebuchet MS", value: "'Trebuchet MS', sans-serif" },
    { name: "Verdana", value: "Verdana, sans-serif" },
    // 한글 폰트
    { name: "맑은 고딕", value: "'Malgun Gothic', sans-serif" },
    { name: "돋움", value: "Dotum, sans-serif" },
    { name: "굴림", value: "Gulim, sans-serif" },
    { name: "바탕", value: "Batang, serif" },
    { name: "궁서", value: "Gungsuh, serif" },
    // macOS 폰트
    { name: "Apple SD Gothic Neo", value: "'Apple SD Gothic Neo', sans-serif" },
    { name: "Helvetica", value: "Helvetica, sans-serif" },
    { name: "SF Pro", value: "'SF Pro Display', sans-serif" },
    // 크로스 플랫폼 폰트
    { name: "Segoe UI", value: "'Segoe UI', sans-serif" },
    { name: "Roboto", value: "Roboto, sans-serif" },
    { name: "Noto Sans", value: "'Noto Sans', sans-serif" },
    { name: "Noto Sans KR", value: "'Noto Sans KR', sans-serif" }
];

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

/**
 * XSS 방지: HTML 이스케이프 처리
 * 사용자 입력값을 안전하게 HTML에 삽입하기 위해 사용
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function showErrorInEditor(message) {
    const escapedMessage = escapeHtml(message);

    if (editor) {
        editor.commands.setContent(`<p style="color: red;">${escapedMessage}</p>`, { emitUpdate: false });
    } else {
        const el = document.querySelector("#editor");
        if (el) {
            el.innerHTML = `<p style="color: red;">${escapedMessage}</p>`;
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
        editable: false, // 기본값은 읽기모드
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
            // 폰트 패밀리 기능
            FontFamily.configure({
                types: ["textStyle"],
            }),
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

    // 폰트 드롭다운 / 메뉴 DOM 캐시
    fontDropdownElement = toolbar.querySelector("[data-role='font-dropdown']");
    fontMenuElement = fontDropdownElement
        ? fontDropdownElement.querySelector("[data-font-menu]")
        : null;

    // 폰트 드롭다운 메뉴에 폰트 옵션 동적 생성
    if (fontMenuElement) {
        fontMenuElement.innerHTML = "";
        SYSTEM_FONTS.forEach((font) => {
            const button = document.createElement("button");
            button.type = "button";
            button.className = "color-option";
            button.dataset.command = "setFont";
            if (font.value) {
                button.dataset.fontFamily = font.value;
            } else {
                button.dataset.fontFamily = "";
            }
            button.title = font.name;
            button.style.fontFamily = font.value || "inherit";
            button.textContent = font.name;
            fontMenuElement.appendChild(button);
        });
    }

    toolbar.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-command]");
        if (!button || !editor) {
            return;
        }

        const command = button.getAttribute("data-command");
        const colorValue = button.getAttribute("data-color");
        const fontFamilyValue = button.getAttribute("data-font-family");

        // 색상 드롭다운 열기/닫기
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

        // 폰트 드롭다운 열기/닫기
        if (command === "toggleFontDropdown") {
            if (!fontMenuElement || !fontDropdownElement) {
                return;
            }

            const isOpen = !fontMenuElement.hasAttribute("hidden");

            if (isOpen) {
                fontMenuElement.setAttribute("hidden", "");
                fontDropdownElement.classList.remove("open");
            } else {
                fontMenuElement.removeAttribute("hidden");
                fontDropdownElement.classList.add("open");
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

        // 폰트 선택 (드롭다운 내부 버튼)
        if (command === "setFont") {
            if (fontFamilyValue === "") {
                // 기본 폰트로 초기화
                editor.chain().focus().unsetFontFamily().run();
            } else {
                editor.chain().focus().setFontFamily(fontFamilyValue).run();
            }

            // 폰트 선택 후 드롭다운 닫기
            if (fontMenuElement && fontDropdownElement) {
                fontMenuElement.setAttribute("hidden", "");
                fontDropdownElement.classList.remove("open");
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

        // 페이지가 없으면 안내 메시지만 표시
        if (!pages.length) {
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

        // 컬렉션에 페이지가 있는지 확인
        const colPages = pages.filter((p) => p.collectionId === collection.id);
        const hasPages = colPages.length > 0;

        // 공유받은 컬렉션 표시 (isOwner가 명시적으로 false일 때만)
        const isShared = collection.isOwner === false;
        const indicator = isShared
            ? `<span class="shared-collection-indicator">${collection.permission || 'READ'}</span>`
            : '';
        const folderIcon = isShared
            ? 'fa-solid fa-folder-open'
            : 'fa-regular fa-folder';

        // 페이지가 있을 때만 화살표 표시
        // XSS 방지: collection.name을 escapeHtml로 이스케이프 처리
        if (hasPages) {
            title.innerHTML = `
                <span class="collection-toggle ${expandedCollections.has(collection.id) ? "expanded" : ""}">
                    <i class="fa-solid fa-caret-right"></i>
                </span>
                <i class="${folderIcon}"></i>
                <span>${escapeHtml(collection.name || "제목 없음")}${indicator}</span>
            `;
        } else {
            // 화살표가 없어도 동일한 너비의 공간을 차지하도록 빈 span 추가
            // XSS 방지: collection.name을 escapeHtml로 이스케이프 처리
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
        menuBtn.title = "컬렉션 메뉴";
        menuBtn.innerHTML = `<i class="fa-solid fa-ellipsis-vertical"></i>`;

        const menu = document.createElement("div");
        menu.className = "dropdown-menu collection-menu hidden";

        // 소유자만 공유 및 삭제 가능 (isOwner가 명시적으로 false가 아니면 소유자로 간주)
        if (collection.isOwner !== false) {
            menu.innerHTML = `
                <button data-action="share-collection" data-collection-id="${collection.id}">
                    <i class="fa-solid fa-share-nodes"></i>
                    컬렉션 공유
                </button>
                <button data-action="delete-collection" data-collection-id="${collection.id}">
                    <i class="fa-regular fa-trash-can"></i>
                    컬렉션 삭제
                </button>
            `;
        } else {
            menu.innerHTML = `<div style="padding: 8px; color: #6b7280; font-size: 12px;">권한: ${collection.permission || 'READ'}</div>`;
        }

        // READ 권한이면 페이지 추가 버튼 숨김 (READ가 아니면 추가 가능)
        if (collection.permission !== 'READ') {
            actions.appendChild(addBtn);
        }
        actions.appendChild(menuBtn);
        actions.appendChild(menu);

        header.appendChild(title);
        header.appendChild(actions);

        item.appendChild(header);

        const expanded = expandedCollections.has(collection.id);
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

                    // 깊이에 따른 들여쓰기 (collection-header 12px + 화살표 14px + gap 6px = 폴더 아이콘 위치)
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

                    // 암호화된 페이지는 자물쇠 아이콘 표시
                    // XSS 방지: node.title을 escapeHtml로 이스케이프 처리
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
                    pageMenuBtn.title = "페이지 메뉴";
                    pageMenuBtn.innerHTML = `<i class="fa-solid fa-ellipsis-vertical"></i>`;

                    const pageMenu = document.createElement("div");
                    pageMenu.className = "dropdown-menu page-menu hidden";

                    // 암호화된 페이지는 암호화 버튼 제거
                    if (node.isEncrypted) {
                        pageMenu.innerHTML = `
                            <button data-action="delete-page" data-page-id="${node.id}">
                                <i class="fa-regular fa-trash-can"></i>
                                페이지 삭제
                            </button>
                        `;
                    } else {
                        pageMenu.innerHTML = `
                            <button data-action="encrypt-page" data-page-id="${node.id}">
                                <i class="fa-solid fa-lock"></i>
                                페이지 암호화
                            </button>
                            <button data-action="delete-page" data-page-id="${node.id}">
                                <i class="fa-regular fa-trash-can"></i>
                                페이지 삭제
                            </button>
                        `;
                    }

                    const right = document.createElement("div");
                    right.className = "page-menu-wrapper";
                    right.appendChild(pageMenuBtn);
                    right.appendChild(pageMenu);

                    row.appendChild(titleWrap);
                    row.appendChild(right);

                    li.appendChild(row);

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
        }

        listEl.appendChild(item);
    });
}

async function loadPage(id) {
    if (!id) {
        return;
    }

    // 페이지 전환 전에 쓰기모드였다면 저장하고 읽기모드로 전환
    if (isWriteMode && currentPageId) {
        await saveCurrentPage();
        // 읽기모드로 전환
        const modeToggleBtn = document.querySelector("#mode-toggle-btn");
        const titleInput = document.querySelector("#page-title-input");
        const toolbar = document.querySelector(".editor-toolbar");
        const iconEl = modeToggleBtn ? modeToggleBtn.querySelector("i") : null;
        const textEl = modeToggleBtn ? modeToggleBtn.querySelector("span") : null;

        isWriteMode = false;
        if (editor) {
            editor.setEditable(false);
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

        // 암호화된 페이지인 경우 복호화 비밀번호 입력 요청
        if (page.isEncrypted) {
            // 암호화된 페이지는 currentPageId를 설정하지 않음
            // 복호화 성공 시 decryptAndLoadPage에서 설정
            if (page.collectionId) {
                currentCollectionId = page.collectionId;
                expandedCollections.add(page.collectionId);
            }
            showDecryptionModal(page);
            return;
        }

        currentPageId = page.id;
        if (page.collectionId) {
            currentCollectionId = page.collectionId;
            expandedCollections.add(page.collectionId);
        }

        let title = page.title || "";
        let content = page.content || "<p></p>";

        const titleInput = document.querySelector("#page-title-input");
        if (titleInput) {
            titleInput.value = title;
        }

        if (editor) {
            editor.commands.setContent(content, { emitUpdate: false });
        }

        renderPageList();

        // 모바일에서 페이지 로드 후 사이드바 닫기
        if (window.innerWidth <= 768) {
            closeSidebar();
        }
    } catch (error) {
        console.error("단일 페이지 로드 오류:", error);
        showErrorInEditor("페이지를 불러오지 못했다: " + error.message);
    }
}

function closeAllDropdowns() {
    document.querySelectorAll(".dropdown-menu").forEach((menu) => {
        menu.classList.add("hidden");
        menu.style.left = "";
        menu.style.top = "";
        menu.style.position = "";
    });
}

function openDropdown(menu, trigger) {
    if (!menu || !trigger) return;
    const rect = trigger.getBoundingClientRect();
    const left = rect.right + 6;
    const top = rect.top;
    menu.style.position = "fixed";
    menu.style.left = `${left}px`;
    menu.style.top = `${top}px`;
    menu.classList.remove("hidden");
}

function bindPageListClick() {
    const listEl = document.querySelector("#collection-list");
    if (!listEl) {
        return;
    }

    listEl.addEventListener("click", async (event) => {
        // 컬렉션 메뉴 토글
        const colMenuBtn = event.target.closest(".collection-menu-btn");
        if (colMenuBtn) {
            const container = colMenuBtn.closest(".collection-item");
            const menu = container ? container.querySelector(".collection-menu") : null;
            if (menu) {
                closeAllDropdowns();
                if (menu.classList.contains("hidden")) {
                    openDropdown(menu, colMenuBtn);
                } else {
                    closeAllDropdowns();
                }
            }
            return;
        }

        // 컬렉션 메뉴 액션
        const colMenuAction = event.target.closest(".collection-menu button");
        if (colMenuAction) {
            const action = colMenuAction.dataset.action;
            const colId = colMenuAction.dataset.collectionId;

            // 컬렉션 공유 액션
            if (action === "share-collection" && colId) {
                const collection = collections.find(c => c.id === colId);
                if (collection && collection.isOwner !== false) {
                    openShareModal(colId);
                } else {
                    alert("컬렉션 소유자만 공유할 수 있습니다.");
                }
                closeAllDropdowns();
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
                    collections = collections.filter((c) => c.id !== colId);
                    pages = pages.filter((p) => p.collectionId !== colId);
                    expandedCollections.delete(colId);

                    if (currentCollectionId === colId) {
                        currentCollectionId = collections[0]?.id || null;
                        currentPageId = null;
                    }

                    renderPageList();

                    // 에디터 초기화
                    if (editor) {
                        if (currentCollectionId && pages.find((p) => p.collectionId === currentCollectionId)) {
                            editor.commands.setContent("<p>페이지를 선택하세요.</p>", {
                                emitUpdate: false
                            });
                        } else if (currentCollectionId) {
                            editor.commands.setContent("<p>이 컬렉션에 페이지가 없습니다.</p>", {
                                emitUpdate: false
                            });
                        } else {
                            editor.commands.setContent("<p>컬렉션을 추가해 주세요.</p>", {
                                emitUpdate: false
                            });
                        }
                        const titleInput = document.querySelector("#page-title-input");
                        if (titleInput) {
                            titleInput.value = "";
                        }
                    }
                    currentPageId = null;
                } catch (error) {
                    console.error("컬렉션 삭제 오류:", error);
                    alert("컬렉션을 삭제하지 못했습니다: " + error.message);
                } finally {
                    closeAllDropdowns();
                }
            }
            return;
        }

        // 컬렉션에 페이지 추가
        const addBtn = event.target.closest(".collection-add-page-btn");
        if (addBtn) {
            const colId = addBtn.dataset.collectionId;
            if (!colId) {
                return;
            }
            expandedCollections.add(colId);

            let title = prompt("새 페이지 제목을 입력하세요.", "새 페이지");
            if (title === null) {
                return;
            }

            const plainTitle = title.trim() || "새 페이지";
            const plainContent = "<p></p>";

            try {
                const res = await secureFetch("/api/pages", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json"
                    },
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
                pages.unshift({
                    id: page.id,
                    title: plainTitle, // 복호화된 제목 저장
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
            } finally {
                closeAllDropdowns();
            }

            return;
        }

        // 페이지 메뉴 토글
        const pageMenuBtn = event.target.closest(".page-menu-btn");
        if (pageMenuBtn) {
            const item = pageMenuBtn.closest(".page-list-item");
            const menu = item ? item.querySelector(".page-menu") : null;
            if (menu) {
                closeAllDropdowns();
                if (menu.classList.contains("hidden")) {
                    openDropdown(menu, pageMenuBtn);
                } else {
                    closeAllDropdowns();
                }
            }
            return;
        }

        // 페이지 메뉴 액션
        const pageMenuAction = event.target.closest(".page-menu button");
        if (pageMenuAction) {
            const action = pageMenuAction.dataset.action;
            const pageId = pageMenuAction.dataset.pageId;
            if (action === "encrypt-page" && pageId) {
                // 페이지 암호화
                showEncryptionModal(pageId);
                closeAllDropdowns();
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
                    pages = pages.filter((p) => p.id !== pageId);
                    if (currentPageId === pageId) {
                        currentPageId = null;
                    }
                    renderPageList();
                    // 삭제 후 현재 컬렉션에 페이지가 없으면 collapse 유지
                    const hasPages = pages.some((p) => p.collectionId === currentCollectionId);
                    if (!hasPages && currentCollectionId) {
                        expandedCollections.delete(currentCollectionId);
                    }
                    if (currentCollectionId) {
                        const first = pages.find((p) => p.collectionId === currentCollectionId);
                        if (first) {
                            await loadPage(first.id);
                        } else if (editor) {
                            editor.commands.setContent("<p>이 컬렉션에 페이지가 없습니다.</p>", {
                                emitUpdate: false
                            });
                            const titleInput = document.querySelector("#page-title-input");
                            if (titleInput) {
                                titleInput.value = "";
                            }
                        }
                    }
                } catch (error) {
                    console.error("페이지 삭제 오류:", error);

                    // 403 오류(권한 없음)인 경우 커스텀 모달 표시
                    if (error.message && error.message.includes("403")) {
                        showDeletePermissionModal();
                    } else {
                        alert("페이지를 삭제하지 못했습니다: " + error.message);
                    }
                } finally {
                    closeAllDropdowns();
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
                if (expandedCollections.has(colId)) {
                    expandedCollections.delete(colId); // collapse
                } else {
                    expandedCollections.add(colId); // expand
                    currentCollectionId = colId;
                }
                renderPageList();
            }
            closeAllDropdowns();
            return;
        }

        // 페이지 선택
        const li = event.target.closest("li.page-list-item");
        if (!li) {
            return;
        }

        const pageId = li.dataset.pageId;
        if (!pageId || pageId === currentPageId) {
            return;
        }

        closeAllDropdowns();
        await loadPage(pageId);
    });
}

function bindNewCollectionButton() {
    const btn = document.querySelector("#new-collection-btn");
    if (!btn) {
        return;
    }

    btn.addEventListener("click", async () => {
        let name = prompt("새 컬렉션 이름을 입력하세요.", "새 컬렉션");
        if (name === null) {
            return;
        }

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
            collection.name = plainName; // 복호화된 이름 저장
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

async function saveCurrentPage() {
    const titleInput = document.querySelector("#page-title-input");

    if (!currentPageId) {
        console.warn("저장할 페이지가 없음.");
        return true; // 저장할 페이지가 없으면 성공으로 간주
    }
    if (!editor) {
        console.warn("에디터가 초기화되지 않음.");
        return true; // 에디터가 없으면 성공으로 간주
    }

    let title = titleInput ? titleInput.value || "제목 없음" : "제목 없음";
    let content = editor.getHTML();

    try {
        const res = await secureFetch("/api/pages/" + encodeURIComponent(currentPageId), {
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

        // 복호화된 제목으로 업데이트
        const decryptedTitle = titleInput ? titleInput.value || "제목 없음" : "제목 없음";

        pages = pages.map((p) => {
            if (p.id === page.id) {
                return {
                    ...p,
                    title: decryptedTitle,
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
        console.log("저장 완료.");
        return true; // 저장 성공
    } catch (error) {
        console.error("페이지 저장 오류:", error);

        // 403 오류(권한 없음)인 경우 커스텀 모달 표시
        if (error.message && error.message.includes("403")) {
            showReadonlyWarningModal();
            return false; // 저장 실패
        } else {
            alert("페이지 저장 실패: " + error.message);
            return false; // 저장 실패
        }
    }
}

async function toggleEditMode() {
    const modeToggleBtn = document.querySelector("#mode-toggle-btn");
    const titleInput = document.querySelector("#page-title-input");
    const toolbar = document.querySelector(".editor-toolbar");
    const iconEl = modeToggleBtn ? modeToggleBtn.querySelector("i") : null;
    const textEl = modeToggleBtn ? modeToggleBtn.querySelector("span") : null;

    if (!editor || !modeToggleBtn) {
        return;
    }

    if (isWriteMode) {
        // 쓰기모드 → 읽기모드: 저장하고 읽기 전용으로 변경
        const saveSuccess = await saveCurrentPage();

        // 저장이 실패하면 (READ 권한 등) 쓰기모드 유지
        if (!saveSuccess) {
            console.log("저장 실패 - 쓰기모드 유지");
            return;
        }

        isWriteMode = false;
        editor.setEditable(false);
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
        // 읽기모드 → 쓰기모드: 편집 가능하게 변경
        isWriteMode = true;
        editor.setEditable(true);
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

function bindModeToggle() {
    const btn = document.querySelector("#mode-toggle-btn");
    if (!btn) {
        return;
    }

    btn.addEventListener("click", () => {
        toggleEditMode();
    });
}

function bindLogoutButton() {
    const btn = document.querySelector("#logout-btn");
    if (!btn) {
        return;
    }

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
            console.error("로그아웃 실패:", error);
            alert("로그아웃 중 오류가 발생했습니다.");
        }
    });
}

async function fetchAndDisplayCurrentUser() {
    try {
        const res = await fetch("/api/auth/me");
        if (!res.ok) {
            throw new Error("HTTP " + res.status);
        }

        const user = await res.json();
        currentUser = user;

        const userAvatarEl = document.querySelector("#user-avatar");
        const userNameEl = document.querySelector("#user-name");

        if (userNameEl) {
            userNameEl.textContent = user.username || "사용자";
        }

        if (userAvatarEl) {
            // 프로필 이미지가 없으므로 사용자명의 첫 글자를 표시
            const firstLetter = (user.username || "?").charAt(0).toUpperCase();
            userAvatarEl.textContent = firstLetter;
        }
    } catch (error) {
        console.error("사용자 정보 조회 실패:", error);
        const userNameEl = document.querySelector("#user-name");
        if (userNameEl) {
            userNameEl.textContent = "사용자";
        }
        const userAvatarEl = document.querySelector("#user-avatar");
        if (userAvatarEl) {
            userAvatarEl.textContent = "?";
        }
    }
}

function openSettingsModal() {
    const modal = document.querySelector("#settings-modal");
    const usernameEl = document.querySelector("#settings-username");
    const defaultModeSelect = document.querySelector("#settings-default-mode");

    if (!modal) {
        return;
    }

    // 모바일에서 설정 열 때 사이드바 닫기
    if (window.innerWidth <= 768) {
        closeSidebar();
    }

    // 현재 사용자 정보 표시
    if (usernameEl && currentUser) {
        usernameEl.textContent = currentUser.username || "-";
    }

    // 현재 설정 값 표시
    if (defaultModeSelect) {
        defaultModeSelect.value = userSettings.defaultMode;
    }

    modal.classList.remove("hidden");
}

function closeSettingsModal() {
    const modal = document.querySelector("#settings-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
}

function saveSettings() {
    const defaultModeSelect = document.querySelector("#settings-default-mode");

    if (defaultModeSelect) {
        userSettings.defaultMode = defaultModeSelect.value;
        // localStorage에 설정 저장
        localStorage.setItem("userSettings", JSON.stringify(userSettings));
        console.log("설정 저장됨:", userSettings);
    }

    closeSettingsModal();
    alert("설정이 저장되었습니다.");
}

function loadSettings() {
    try {
        const saved = localStorage.getItem("userSettings");
        if (saved) {
            userSettings = JSON.parse(saved);
        }
    } catch (error) {
        console.error("설정 로드 실패:", error);
    }
}

function bindSettingsModal() {
    const settingsBtn = document.querySelector("#settings-btn");
    const closeBtn = document.querySelector("#close-settings-btn");
    const saveBtn = document.querySelector("#save-settings-btn");
    const overlay = document.querySelector(".modal-overlay");

    if (settingsBtn) {
        settingsBtn.addEventListener("click", () => {
            openSettingsModal();
        });
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", () => {
            closeSettingsModal();
        });
    }

    if (saveBtn) {
        saveBtn.addEventListener("click", () => {
            saveSettings();
        });
    }

    if (overlay) {
        overlay.addEventListener("click", () => {
            closeSettingsModal();
        });
    }
}

// 페이지 암호화 모달
let currentEncryptingPageId = null;

// 페이지 복호화 모달
let currentDecryptingPage = null;

function showEncryptionModal(pageId) {
    currentEncryptingPageId = pageId;
    const modal = document.querySelector("#page-encryption-modal");
    if (modal) {
        modal.classList.remove("hidden");
        const passwordInput = document.querySelector("#encryption-password");
        const confirmInput = document.querySelector("#encryption-password-confirm");
        const errorEl = document.querySelector("#encryption-error");
        if (passwordInput) passwordInput.value = "";
        if (confirmInput) confirmInput.value = "";
        if (errorEl) errorEl.textContent = "";
        if (passwordInput) passwordInput.focus();
    }
}

function closeEncryptionModal() {
    const modal = document.querySelector("#page-encryption-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    currentEncryptingPageId = null;
}

async function handleEncryption(event) {
    event.preventDefault();

    const passwordInput = document.querySelector("#encryption-password");
    const confirmInput = document.querySelector("#encryption-password-confirm");
    const errorEl = document.querySelector("#encryption-error");

    if (!passwordInput || !confirmInput || !errorEl) {
        console.error("암호화 폼 요소를 찾을 수 없습니다.");
        return;
    }

    const password = passwordInput.value.trim();
    const confirm = confirmInput.value.trim();
    errorEl.textContent = "";

    if (!password || !confirm) {
        errorEl.textContent = "비밀번호를 입력해 주세요.";
        console.log("암호화 실패: 비밀번호 미입력");
        return;
    }

    if (password !== confirm) {
        errorEl.textContent = "비밀번호가 일치하지 않습니다.";
        console.log("암호화 실패: 비밀번호 불일치");
        alert("비밀번호가 일치하지 않습니다. 다시 확인해 주세요.");
        return;
    }

    if (password.length < 4) {
        errorEl.textContent = "비밀번호는 최소 4자 이상이어야 합니다.";
        return;
    }

    if (!currentEncryptingPageId) {
        errorEl.textContent = "페이지 ID를 찾을 수 없습니다.";
        return;
    }

    try {
        // 현재 페이지 데이터 가져오기
        const res = await fetch(`/api/pages/${encodeURIComponent(currentEncryptingPageId)}`);
        if (!res.ok) {
            throw new Error("HTTP " + res.status);
        }

        const page = await res.json();

        // 암호화 키 생성
        await cryptoManager.initializeKey(password);

        // 내용만 암호화 (제목은 암호화하지 않음)
        const encryptedContent = await cryptoManager.encrypt(page.content);

        // 암호화된 데이터 저장
        const updateRes = await secureFetch(`/api/pages/${encodeURIComponent(currentEncryptingPageId)}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                title: page.title,
                content: encryptedContent,
                isEncrypted: true
            })
        });

        if (!updateRes.ok) {
            throw new Error("HTTP " + updateRes.status);
        }

        alert("페이지가 성공적으로 암호화되었습니다!");
        closeEncryptionModal();

        // 페이지 목록 새로고침
        await fetchPageList();

        // 현재 페이지 다시 로드 (복호화된 상태로)
        if (currentPageId === currentEncryptingPageId) {
            const titleInput = document.querySelector("#page-title-input");
            if (titleInput) {
                titleInput.value = page.title;
            }
            if (editor) {
                editor.commands.setContent(page.content, { emitUpdate: false });
            }
        }

        // 암호화 키 삭제
        cryptoManager.clearKey();
    } catch (error) {
        console.error("암호화 오류:", error);

        // 403 오류(권한 없음)인 경우 커스텀 모달 표시
        if (error.message && error.message.includes("403")) {
            showEncryptPermissionModal();
        } else {
            errorEl.textContent = "암호화 중 오류가 발생했습니다: " + error.message;
        }
    }
}

function bindEncryptionModal() {
    const form = document.querySelector("#encryption-form");
    const closeBtn = document.querySelector("#close-encryption-modal-btn");
    const cancelBtn = document.querySelector("#cancel-encryption-btn");

    if (form) {
        form.addEventListener("submit", handleEncryption);
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", closeEncryptionModal);
    }

    if (cancelBtn) {
        cancelBtn.addEventListener("click", closeEncryptionModal);
    }
}

// 페이지 복호화 모달 (암호화된 페이지 열 때)
function showDecryptionModal(page) {
    currentDecryptingPage = page;
    const modal = document.querySelector("#page-decryption-modal");
    if (modal) {
        modal.classList.remove("hidden");
        const passwordInput = document.querySelector("#decryption-password");
        const errorEl = document.querySelector("#decryption-error");
        if (passwordInput) passwordInput.value = "";
        if (errorEl) errorEl.textContent = "";
        if (passwordInput) passwordInput.focus();
    }
}

function closeDecryptionModal() {
    const modal = document.querySelector("#page-decryption-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    currentDecryptingPage = null;
}

async function handleDecryption(event) {
    event.preventDefault();

    const passwordInput = document.querySelector("#decryption-password");
    const errorEl = document.querySelector("#decryption-error");

    if (!passwordInput || !errorEl) {
        return;
    }

    const password = passwordInput.value.trim();
    errorEl.textContent = "";

    if (!password) {
        errorEl.textContent = "비밀번호를 입력해 주세요.";
        return;
    }

    if (!currentDecryptingPage) {
        errorEl.textContent = "페이지 정보를 찾을 수 없습니다.";
        return;
    }

    try {
        await decryptAndLoadPage(currentDecryptingPage, password);
        closeDecryptionModal();
    } catch (error) {
        console.error("복호화 처리 오류:", error);
        errorEl.textContent = "비밀번호가 올바르지 않거나 복호화에 실패했습니다.";
        cryptoManager.clearKey();
    }
}

function bindDecryptionModal() {
    const form = document.querySelector("#decryption-form");
    const closeBtn = document.querySelector("#close-decryption-modal-btn");
    const cancelBtn = document.querySelector("#cancel-decryption-btn");

    if (form) {
        form.addEventListener("submit", handleDecryption);
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", closeDecryptionModal);
    }

    if (cancelBtn) {
        cancelBtn.addEventListener("click", closeDecryptionModal);
    }
}

// ==================== 컬렉션 공유 기능 ====================

let currentSharingCollectionId = null;

function openShareModal(collectionId) {
    currentSharingCollectionId = collectionId;
    const modal = document.querySelector("#share-collection-modal");
    if (modal) {
        modal.classList.remove("hidden");
        loadShareList(collectionId);
        loadShareLinks(collectionId);
    }
}

function closeShareModal() {
    const modal = document.querySelector("#share-collection-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    currentSharingCollectionId = null;
}

async function loadShareList(collectionId) {
    try {
        const res = await fetch(`/api/collections/${encodeURIComponent(collectionId)}/shares`);
        if (!res.ok) throw new Error("HTTP " + res.status);

        const shares = await res.json();
        const listEl = document.querySelector("#share-list");

        if (!listEl) return;

        if (shares.length === 0) {
            listEl.innerHTML = '<div style="color: #6b7280; font-size: 13px;">공유 중인 사용자가 없습니다.</div>';
            return;
        }

        listEl.innerHTML = shares.map(share => `
            <div class="share-item">
                <div class="share-item-info">
                    <div class="share-item-username">${escapeHtml(share.username)}</div>
                    <div class="share-item-permission">${share.permission}</div>
                </div>
                <div class="share-item-actions">
                    <button class="danger-button remove-share-btn" data-collection-id="${escapeHtml(collectionId)}" data-share-id="${share.id}" style="padding: 4px 8px; font-size: 12px;">
                        삭제
                    </button>
                </div>
            </div>
        `).join('');

        // 삭제 버튼에 이벤트 리스너 추가
        listEl.querySelectorAll('.remove-share-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const colId = btn.dataset.collectionId;
                const shareId = btn.dataset.shareId;
                await removeShare(colId, shareId);
            });
        });
    } catch (error) {
        console.error("공유 목록 로드 오류:", error);
    }
}

async function loadShareLinks(collectionId) {
    try {
        const res = await fetch(`/api/collections/${encodeURIComponent(collectionId)}/share-links`);
        if (!res.ok) throw new Error("HTTP " + res.status);

        const links = await res.json();
        const listEl = document.querySelector("#link-list");

        if (!listEl) return;

        if (links.length === 0) {
            listEl.innerHTML = '<div style="color: #6b7280; font-size: 13px;">생성된 링크가 없습니다.</div>';
            return;
        }

        listEl.innerHTML = links.map(link => {
            const expiryText = link.expiresAt
                ? `만료: ${new Date(link.expiresAt).toLocaleString()}`
                : '무기한';

            return `
                <div class="link-item">
                    <div class="link-item-url">${escapeHtml(link.url)}</div>
                    <div class="link-item-meta">
                        <span>${link.permission} · ${expiryText}</span>
                        <div style="display: flex; gap: 6px;">
                            <button class="copy-link-btn" data-url="${escapeHtml(link.url)}" style="padding: 4px 8px; font-size: 11px; border: none; background: #2d5f5d; color: white; border-radius: 2px; cursor: pointer;">
                                복사
                            </button>
                            <button class="danger-button remove-link-btn" data-collection-id="${escapeHtml(collectionId)}" data-link-id="${link.id}" style="padding: 4px 8px; font-size: 11px;">
                                삭제
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        // 복사 버튼에 이벤트 리스너 추가
        listEl.querySelectorAll('.copy-link-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const url = btn.dataset.url;
                copyLinkToClipboard(url);
            });
        });

        // 삭제 버튼에 이벤트 리스너 추가
        listEl.querySelectorAll('.remove-link-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const colId = btn.dataset.collectionId;
                const linkId = btn.dataset.linkId;
                await removeShareLink(colId, linkId);
            });
        });
    } catch (error) {
        console.error("링크 목록 로드 오류:", error);
    }
}

async function handleShareUser(event) {
    event.preventDefault();

    const usernameInput = document.querySelector("#share-username");
    const permissionSelect = document.querySelector("#share-permission");
    const errorEl = document.querySelector("#share-error");

    if (!usernameInput || !permissionSelect || !errorEl) return;

    const username = usernameInput.value.trim();
    const permission = permissionSelect.value;

    errorEl.textContent = "";

    if (!username) {
        errorEl.textContent = "사용자명을 입력해 주세요.";
        return;
    }

    try {
        const res = await secureFetch(`/api/collections/${encodeURIComponent(currentSharingCollectionId)}/shares`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, permission })
        });

        if (!res.ok) {
            const error = await res.json();
            throw new Error(error.error || "공유 실패");
        }

        usernameInput.value = "";
        await loadShareList(currentSharingCollectionId);
        alert("공유가 완료되었습니다.");
    } catch (error) {
        console.error("공유 오류:", error);
        errorEl.textContent = error.message;
    }
}

async function handleShareLink(event) {
    event.preventDefault();

    const permissionSelect = document.querySelector("#link-permission");
    const expiresInput = document.querySelector("#link-expires");
    const errorEl = document.querySelector("#link-error");

    if (!permissionSelect || !expiresInput || !errorEl) return;

    const permission = permissionSelect.value;
    const expiresInDays = expiresInput.value ? parseInt(expiresInput.value) : null;

    errorEl.textContent = "";

    try {
        const res = await secureFetch(`/api/collections/${encodeURIComponent(currentSharingCollectionId)}/share-links`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ permission, expiresInDays })
        });

        if (!res.ok) {
            const error = await res.json();
            throw new Error(error.error || "링크 생성 실패");
        }

        expiresInput.value = "";
        await loadShareLinks(currentSharingCollectionId);
        alert("링크가 생성되었습니다.");
    } catch (error) {
        console.error("링크 생성 오류:", error);
        errorEl.textContent = error.message;
    }
}

async function removeShare(collectionId, shareId) {
    if (!confirm("이 공유를 삭제하시겠습니까?")) return;

    try {
        const res = await secureFetch(`/api/collections/${encodeURIComponent(collectionId)}/shares/${shareId}`, {
            method: "DELETE"
        });

        if (!res.ok) throw new Error("HTTP " + res.status);

        await loadShareList(collectionId);
    } catch (error) {
        console.error("공유 삭제 오류:", error);
        alert("공유 삭제 중 오류가 발생했습니다.");
    }
}

async function removeShareLink(collectionId, linkId) {
    if (!confirm("이 링크를 삭제하시겠습니까?")) return;

    try {
        const res = await secureFetch(`/api/collections/${encodeURIComponent(collectionId)}/share-links/${linkId}`, {
            method: "DELETE"
        });

        if (!res.ok) throw new Error("HTTP " + res.status);

        await loadShareLinks(collectionId);
    } catch (error) {
        console.error("링크 삭제 오류:", error);
        alert("링크 삭제 중 오류가 발생했습니다.");
    }
}

function copyLinkToClipboard(url) {
    navigator.clipboard.writeText(url).then(() => {
        alert("링크가 복사되었습니다!");
    }).catch(err => {
        console.error("복사 실패:", err);
        alert("링크 복사에 실패했습니다.");
    });
}

function bindShareModal() {
    const closeBtn = document.querySelector("#close-share-modal-btn");
    const userForm = document.querySelector("#share-user-form");
    const linkForm = document.querySelector("#share-link-form");
    const tabs = document.querySelectorAll(".share-tab");

    if (closeBtn) {
        closeBtn.addEventListener("click", closeShareModal);
    }

    if (userForm) {
        userForm.addEventListener("submit", handleShareUser);
    }

    if (linkForm) {
        linkForm.addEventListener("submit", handleShareLink);
    }

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const targetTab = tab.dataset.tab;

            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            document.querySelectorAll(".share-tab-content").forEach(content => {
                content.classList.remove("active");
            });

            const targetContent = document.querySelector(`#share-${targetTab}-tab`);
            if (targetContent) {
                targetContent.classList.add("active");
            }
        });
    });
}

// 전역 스코프에 함수 노출 (inline onclick 이벤트용)
window.removeShare = removeShare;
window.removeShareLink = removeShareLink;
window.copyLinkToClipboard = copyLinkToClipboard;

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
 * 읽기 전용 경고 모달 닫기 및 읽기 모드로 전환
 */
async function closeReadonlyWarningModal() {
    const modal = document.querySelector("#readonly-warning-modal");
    if (modal) {
        modal.classList.add("hidden");
    }

    // 저장하지 않고 읽기 모드로 강제 전환
    if (isWriteMode) {
        const modeToggleBtn = document.querySelector("#mode-toggle-btn");
        const titleInput = document.querySelector("#page-title-input");
        const toolbar = document.querySelector(".editor-toolbar");
        const iconEl = modeToggleBtn ? modeToggleBtn.querySelector("i") : null;
        const textEl = modeToggleBtn ? modeToggleBtn.querySelector("span") : null;

        // 먼저 isWriteMode를 false로 설정 (loadPage에서 저장 시도를 방지)
        isWriteMode = false;

        if (editor) {
            editor.setEditable(false);
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

        // 원본 페이지 내용으로 복원
        if (currentPageId) {
            try {
                console.log("READ-only 권한으로 수정 불가 - 원본 페이지 복원: " + currentPageId);
                const res = await fetch("/api/pages/" + encodeURIComponent(currentPageId));
                if (!res.ok) {
                    throw new Error("HTTP " + res.status);
                }

                const page = await res.json();

                // 제목과 내용을 원본으로 복원
                if (titleInput) {
                    titleInput.value = page.title || "";
                }

                if (editor) {
                    editor.commands.setContent(page.content || "<p></p>", { emitUpdate: false });
                }
            } catch (error) {
                console.error("원본 페이지 복원 오류:", error);
            }
        }
    }
}

/**
 * 읽기 전용 경고 모달 이벤트 바인딩
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

    // 오버레이 클릭 시 닫기
    const modal = document.querySelector("#readonly-warning-modal");
    if (modal) {
        const overlay = modal.querySelector(".modal-overlay");
        if (overlay) {
            overlay.addEventListener("click", closeReadonlyWarningModal);
        }
    }
}

/**
 * 삭제 권한 없음 경고 모달 표시
 */
function showDeletePermissionModal() {
    const modal = document.querySelector("#delete-permission-modal");
    if (modal) {
        modal.classList.remove("hidden");
    }
}

/**
 * 삭제 권한 없음 경고 모달 닫기
 */
function closeDeletePermissionModal() {
    const modal = document.querySelector("#delete-permission-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
}

/**
 * 삭제 권한 없음 경고 모달 이벤트 바인딩
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

    // 오버레이 클릭 시 닫기
    const modal = document.querySelector("#delete-permission-modal");
    if (modal) {
        const overlay = modal.querySelector(".modal-overlay");
        if (overlay) {
            overlay.addEventListener("click", closeDeletePermissionModal);
        }
    }
}

/**
 * 암호화 권한 없음 경고 모달 표시
 */
function showEncryptPermissionModal() {
    const modal = document.querySelector("#encrypt-permission-modal");
    if (modal) {
        modal.classList.remove("hidden");
    }
}

/**
 * 암호화 권한 없음 경고 모달 닫기
 */
function closeEncryptPermissionModal() {
    const modal = document.querySelector("#encrypt-permission-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    // 암호화 모달도 함께 닫기
    closeEncryptionModal();
}

/**
 * 암호화 권한 없음 경고 모달 이벤트 바인딩
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

    // 오버레이 클릭 시 닫기
    const modal = document.querySelector("#encrypt-permission-modal");
    if (modal) {
        const overlay = modal.querySelector(".modal-overlay");
        if (overlay) {
            overlay.addEventListener("click", closeEncryptPermissionModal);
        }
    }
}

async function decryptAndLoadPage(page, password) {
    // 암호화 키 생성
    await cryptoManager.initializeKey(password);

    // 내용만 복호화 (제목은 평문)
    const content = await cryptoManager.decrypt(page.content);

    // 복호화 성공 시 currentPageId 설정
    currentPageId = page.id;

    // UI 업데이트
    const titleInput = document.querySelector("#page-title-input");
    if (titleInput) {
        titleInput.value = page.title;
    }

    if (editor) {
        editor.commands.setContent(content, { emitUpdate: false });
    }

    renderPageList();

    // 모바일에서 페이지 로드 후 사이드바 닫기
    if (window.innerWidth <= 768) {
        closeSidebar();
    }

    // 복호화 성공 메시지
    console.log("페이지 복호화 성공");
}

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

    document.addEventListener("click", (event) => {
    	// 폰트 드롭다운 메뉴 바깥을 클릭하면 드롭다운 닫기 구현
        // 폰트 드롭다운 요소가 아직 준비되지 않은 경우
        if (!fontDropdownElement || !fontMenuElement)
            return;

        // 드롭다운 내부를 클릭한 경우는 무시
        if (fontDropdownElement.contains(event.target))
            return;

        // 폰트 드롭다운 메뉴 열려 있으면 닫기
        if (!fontMenuElement.hasAttribute("hidden")) {
            fontMenuElement.setAttribute("hidden", "");
            fontDropdownElement.classList.remove("open");
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

    document.addEventListener("click", (event) => {
        const isMenuBtn = event.target.closest(".collection-menu-btn, .page-menu-btn");
        const isMenu = event.target.closest(".dropdown-menu");
        if (isMenuBtn || isMenu) {
            return;
        }
        closeAllDropdowns();
    });
}

// ============================================================================
// TOTP 2단계 인증 관련 함수
// ============================================================================

let currentTempSessionId = null; // 로그인 시 2FA 대기용 임시 세션 ID

// TOTP 상태 확인 및 UI 업데이트
async function updateTotpStatus() {
    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch('/api/totp/status', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            }
        });

        if (!response.ok) {
            return;
        }

        const data = await response.json();
        const statusEl = document.querySelector('#totp-status');
        const setupBtn = document.querySelector('#totp-setup-btn');

        if (statusEl) {
            statusEl.textContent = data.enabled ? '활성화' : '비활성화';
            statusEl.style.color = data.enabled ? '#16a34a' : '#6b7280';
        }

        if (setupBtn) {
            setupBtn.textContent = data.enabled ? '비활성화' : '설정';
        }
    } catch (error) {
        console.error('TOTP 상태 확인 실패:', error);
    }
}

// TOTP 설정 모달 열기
async function openTotpSetupModal() {
    const statusEl = document.querySelector('#totp-status');
    const isEnabled = statusEl && statusEl.textContent === '활성화';

    const modal = document.querySelector('#totp-setup-modal');
    const step1 = document.querySelector('#totp-setup-step1');
    const step2 = document.querySelector('#totp-setup-step2');
    const disableConfirm = document.querySelector('#totp-disable-confirm');

    if (!modal) return;

    // 모든 단계 숨기기
    if (step1) step1.style.display = 'none';
    if (step2) step2.style.display = 'none';
    if (disableConfirm) disableConfirm.style.display = 'none';

    if (isEnabled) {
        // TOTP 비활성화 화면 표시
        if (disableConfirm) {
            disableConfirm.style.display = 'block';
            const passwordInput = document.querySelector('#totp-disable-password');
            const errorEl = document.querySelector('#totp-disable-error');
            if (passwordInput) passwordInput.value = '';
            if (errorEl) errorEl.textContent = '';
        }
    } else {
        // TOTP 설정 시작
        try {
            const csrfToken = getCookie('nteok_csrf');
            const response = await fetch('/api/totp/setup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                }
            });

            if (!response.ok) {
                alert('TOTP 설정을 시작할 수 없습니다.');
                return;
            }

            const data = await response.json();

            // QR 코드 표시
            const qrcodeEl = document.querySelector('#totp-qrcode');
            const secretEl = document.querySelector('#totp-secret-display');
            if (qrcodeEl) {
                qrcodeEl.innerHTML = `<img src="${data.qrCode}" alt="QR Code" style="max-width: 200px;">`;
            }
            if (secretEl) {
                secretEl.textContent = data.secret;
            }

            // Step 1 표시
            if (step1) {
                step1.style.display = 'block';
                const codeInput = document.querySelector('#totp-verify-code');
                const errorEl = document.querySelector('#totp-setup-error');
                if (codeInput) codeInput.value = '';
                if (errorEl) errorEl.textContent = '';
                if (codeInput) codeInput.focus();
            }
        } catch (error) {
            console.error('TOTP 설정 실패:', error);
            alert('TOTP 설정 중 오류가 발생했습니다.');
            return;
        }
    }

    modal.classList.remove('hidden');
}

// TOTP 설정 모달 닫기
function closeTotpSetupModal() {
    const modal = document.querySelector('#totp-setup-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

// TOTP 활성화 검증
async function verifyTotpSetup() {
    const codeInput = document.querySelector('#totp-verify-code');
    const errorEl = document.querySelector('#totp-setup-error');

    if (!codeInput || !errorEl) return;

    const code = codeInput.value.trim();
    errorEl.textContent = '';

    if (!/^\d{6}$/.test(code)) {
        errorEl.textContent = '6자리 숫자를 입력하세요.';
        return;
    }

    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch('/api/totp/verify-setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ token: code })
        });

        const data = await response.json();

        if (!response.ok) {
            errorEl.textContent = data.error || 'TOTP 활성화에 실패했습니다.';
            return;
        }

        // Step 2로 이동 (백업 코드 표시)
        const step1 = document.querySelector('#totp-setup-step1');
        const step2 = document.querySelector('#totp-setup-step2');
        const backupCodesEl = document.querySelector('#totp-backup-codes');

        if (step1) step1.style.display = 'none';
        if (step2) step2.style.display = 'block';

        if (backupCodesEl && data.backupCodes) {
            backupCodesEl.innerHTML = data.backupCodes
                .map(code => `<div>${code}</div>`)
                .join('');
        }

        updateTotpStatus();
    } catch (error) {
        console.error('TOTP 활성화 실패:', error);
        errorEl.textContent = 'TOTP 활성화 중 오류가 발생했습니다.';
    }
}

// 백업 코드 복사
function copyBackupCodes() {
    const backupCodesEl = document.querySelector('#totp-backup-codes');
    if (!backupCodesEl) return;

    const codes = Array.from(backupCodesEl.children)
        .map(div => div.textContent)
        .join('\n');

    navigator.clipboard.writeText(codes).then(() => {
        alert('백업 코드가 클립보드에 복사되었습니다.');
    }).catch(error => {
        console.error('복사 실패:', error);
        alert('복사에 실패했습니다.');
    });
}

// TOTP 비활성화
async function disableTotp() {
    const passwordInput = document.querySelector('#totp-disable-password');
    const errorEl = document.querySelector('#totp-disable-error');

    if (!passwordInput || !errorEl) return;

    const password = passwordInput.value.trim();
    errorEl.textContent = '';

    if (!password) {
        errorEl.textContent = '비밀번호를 입력하세요.';
        return;
    }

    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch('/api/totp/disable', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ password })
        });

        const data = await response.json();

        if (!response.ok) {
            errorEl.textContent = data.error || 'TOTP 비활성화에 실패했습니다.';
            return;
        }

        alert('TOTP 2단계 인증이 비활성화되었습니다.');
        closeTotpSetupModal();
        updateTotpStatus();
    } catch (error) {
        console.error('TOTP 비활성화 실패:', error);
        errorEl.textContent = 'TOTP 비활성화 중 오류가 발생했습니다.';
    }
}

// TOTP 모달 이벤트 바인딩
function bindTotpModals() {
    // TOTP 설정 버튼
    const setupBtn = document.querySelector('#totp-setup-btn');
    if (setupBtn) {
        setupBtn.addEventListener('click', () => {
            openTotpSetupModal();
        });
    }

    // TOTP 모달 닫기 버튼들
    const closeBtn = document.querySelector('#close-totp-setup-btn');
    const cancelSetupBtn = document.querySelector('#cancel-totp-setup-btn');
    const cancelDisableBtn = document.querySelector('#cancel-totp-disable-btn');
    const closeSuccessBtn = document.querySelector('#close-totp-success-btn');

    if (closeBtn) {
        closeBtn.addEventListener('click', closeTotpSetupModal);
    }
    if (cancelSetupBtn) {
        cancelSetupBtn.addEventListener('click', closeTotpSetupModal);
    }
    if (cancelDisableBtn) {
        cancelDisableBtn.addEventListener('click', closeTotpSetupModal);
    }
    if (closeSuccessBtn) {
        closeSuccessBtn.addEventListener('click', closeTotpSetupModal);
    }

    // TOTP 활성화 버튼
    const verifyBtn = document.querySelector('#verify-totp-btn');
    if (verifyBtn) {
        verifyBtn.addEventListener('click', verifyTotpSetup);
    }

    // TOTP 비활성화 버튼
    const confirmDisableBtn = document.querySelector('#confirm-totp-disable-btn');
    if (confirmDisableBtn) {
        confirmDisableBtn.addEventListener('click', disableTotp);
    }

    // 백업 코드 복사 버튼
    const copyBtn = document.querySelector('#copy-backup-codes-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyBackupCodes);
    }

    // 설정 모달이 열릴 때 TOTP 상태 업데이트
    const settingsBtn = document.querySelector('#settings-btn');
    if (settingsBtn) {
        const originalClickHandler = settingsBtn.onclick;
        settingsBtn.addEventListener('click', () => {
            updateTotpStatus();
        });
    }
}

async function init() {
    loadSettings();

    initEditor();
	initEvent();
    bindToolbar();
    bindPageListClick();
    bindNewCollectionButton();
    bindModeToggle();
    bindSlashKeyHandlers();
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

    fetchAndDisplayCurrentUser();
    fetchCollections().then(() => fetchPageList());
}

document.addEventListener("DOMContentLoaded", () => {
    init();
});