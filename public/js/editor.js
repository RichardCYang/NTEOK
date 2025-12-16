/**
 * Tiptap 에디터 모듈
 * 에디터 초기화, 툴바, 슬래시 명령 등을 관리
 */

// 문단 정렬(TextAlign) 익스텐션 ESM import
import { TextAlign } from "https://esm.sh/@tiptap/extension-text-align@2.0.0-beta.209";

// 텍스트 색상(Color) / TextStyle 익스텐션 ESM import
import Color from "https://esm.sh/@tiptap/extension-color@2.0.0-beta.209";
import TextStyle from "https://esm.sh/@tiptap/extension-text-style@2.0.0-beta.209";

// 폰트 패밀리(FontFamily) 익스텐션 ESM import
import FontFamily from "https://esm.sh/@tiptap/extension-font-family@2.0.0-beta.209";

// TaskList / TaskItem 익스텐션 ESM import
import TaskList from "https://esm.sh/@tiptap/extension-task-list@2.0.0-beta.209";
import TaskItem from "https://esm.sh/@tiptap/extension-task-item@2.0.0-beta.209";

// Table 익스텐션 ESM import
import Table from "https://esm.sh/@tiptap/extension-table@2.0.0-beta.209";
import TableRow from "https://esm.sh/@tiptap/extension-table-row@2.0.0-beta.209";
import TableHeader from "https://esm.sh/@tiptap/extension-table-header@2.0.0-beta.209";
import TableCell from "https://esm.sh/@tiptap/extension-table-cell@2.0.0-beta.209";

// Math 노드 import
import { MathBlock, MathInline } from './math-node.js';

// 전역 Tiptap 번들에서 Editor / StarterKit 가져오기
const Editor = Tiptap.Core.Editor;
const StarterKit = Tiptap.StarterKit;
const Extension = Tiptap.Core.Extension;

// 시스템 폰트 리스트
export const SYSTEM_FONTS = [
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
    { name: "맑은 고딕", value: "'Malgun Gothic', sans-serif" },
    { name: "돋움", value: "Dotum, sans-serif" },
    { name: "굴림", value: "Gulim, sans-serif" },
    { name: "바탕", value: "Batang, serif" },
    { name: "궁서", value: "Gungsuh, serif" },
    { name: "Apple SD Gothic Neo", value: "'Apple SD Gothic Neo', sans-serif" },
    { name: "Helvetica", value: "Helvetica, sans-serif" },
    { name: "SF Pro", value: "'SF Pro Display', sans-serif" },
    { name: "Segoe UI", value: "'Segoe UI', sans-serif" },
    { name: "Roboto", value: "Roboto, sans-serif" },
    { name: "Noto Sans", value: "'Noto Sans', sans-serif" },
    { name: "Noto Sans KR", value: "'Noto Sans KR', sans-serif" }
];

// 슬래시 명령 메뉴 항목들
export const SLASH_ITEMS = [
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
        id: "heading3",
        label: "제목 3",
        description: "작은 제목(Heading 3)",
        icon: "H3",
        command(editor) {
            editor.chain().focus().setHeading({ level: 3 }).run();
        }
    },
    {
        id: "heading4",
        label: "제목 4",
        description: "더 작은 제목(Heading 4)",
        icon: "H4",
        command(editor) {
            editor.chain().focus().setHeading({ level: 4 }).run();
        }
    },
    {
        id: "heading5",
        label: "제목 5",
        description: "가장 작은 제목(Heading 5)",
        icon: "H5",
        command(editor) {
            editor.chain().focus().setHeading({ level: 5 }).run();
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
        id: "taskList",
        label: "체크리스트",
        description: "완료 상태를 표시하는 목록",
        icon: "☑",
        command(editor) {
            editor.chain().focus().toggleTaskList().run();
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
        icon: "{ }",
        command(editor) {
            editor.chain().focus().toggleCodeBlock().run();
        }
    },
    {
        id: "mathBlock",
        label: "수식 블록",
        description: "LaTeX 수식 (블록)",
        icon: "∑",
        command(editor) {
            editor.chain().focus().setMathBlock('').run();
        }
    },
    {
        id: "mathInline",
        label: "인라인 수식",
        description: "$수식$ 형식으로 입력",
        icon: "$",
        command(editor) {
            editor.chain().focus().insertContent('$수식$').run();
        }
    },
    {
        id: "table",
        label: "표",
        description: "3x3 표 삽입",
        icon: "⊞",
        command(editor) {
            editor.chain().focus().insertTable({ rows: 3, cols: 3, withHeaderRow: true }).run();
        }
    }
];

// CustomEnter extension
const CustomEnter = Extension.create({
    name: "customEnter",
    addKeyboardShortcuts() {
        return {
            Enter: ({ editor }) => {
                if (editor.isActive("codeBlock")) {
                    return editor.commands.newlineInCode();
                }

                if (editor.isActive("horizontalRule")) {
                    const { state } = editor;
                    const { selection } = state;
                    const posAfterHr = selection.to;

                    return editor
                        .chain()
                        .focus()
                        .setTextSelection(posAfterHr)
                        .insertContent("<p></p>")
                        .run();
                }

                return false;
            },
            "Shift-Enter": ({ editor }) => {
                return editor.commands.setHardBreak();
            }
        };
    }
});

// 슬래시 메뉴 상태
let slashMenuEl = null;
let slashActiveIndex = 0;
let slashState = {
    active: false,
    fromPos: null
};

/**
 * 슬래시 메뉴 DOM 요소 생성
 */
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

    slashMenuEl.addEventListener("click", (event) => {
        const li = event.target.closest(".slash-menu-item");
        if (!li) return;
        const id = li.dataset.id;
        runSlashCommand(id);
    });
}

/**
 * 슬래시 메뉴 열기
 */
function openSlashMenu(coords, fromPos, editor) {
    if (!slashMenuEl) {
        createSlashMenuElement();
    }

    slashState.active = true;
    slashState.fromPos = fromPos;
    slashState.editor = editor;
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

/**
 * 슬래시 메뉴 닫기
 */
function closeSlashMenu() {
    slashState.active = false;
    slashState.fromPos = null;
    slashState.editor = null;
    if (slashMenuEl) {
        slashMenuEl.classList.add("hidden");
    }
}

/**
 * 슬래시 메뉴 항목 이동
 */
function moveSlashActive(delta) {
    if (!slashMenuEl) return;

    const items = Array.from(slashMenuEl.querySelectorAll(".slash-menu-item"));
    if (!items.length) return;

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

/**
 * 슬래시 명령 실행
 */
function runSlashCommand(id) {
    const editor = slashState.editor;
    if (!editor) return;

    const item = SLASH_ITEMS.find((x) => x.id === id);
    if (!item) {
        closeSlashMenu();
        return;
    }

    editor.chain().focus();

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

/**
 * 현재 활성화된 슬래시 명령 실행
 */
function runSlashCommandActive() {
    if (!slashMenuEl) return;

    const items = Array.from(slashMenuEl.querySelectorAll(".slash-menu-item"));
    if (!items.length) return;

    const active = items[slashActiveIndex];
    const id = active.dataset.id;
    runSlashCommand(id);
}

/**
 * 슬래시 명령 키보드 바인딩
 */
export function bindSlashKeyHandlers(editor) {
    document.addEventListener("keydown", (event) => {
        if (!editor) return;

        const target = event.target;
        const inEditor = target && target.closest && target.closest(".ProseMirror");

        // 에디터 안에서 "/" 입력 시 슬래시 메뉴 활성화
        if (!slashState.active && event.key === "/" && inEditor) {
            try {
                const selection = editor.state.selection;
                const pos = selection.from;
                const coords = editor.view.coordsAtPos(pos);
                openSlashMenu(coords, pos, editor);
            } catch (e) {
                console.error("슬래시 메뉴 좌표 계산 실패:", e);
            }
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

    // 외부 영역 클릭 시 슬래시 메뉴 닫기
    document.addEventListener("click", (event) => {
        if (slashState.active && slashMenuEl) {
            // 클릭한 요소가 슬래시 메뉴 내부가 아니면 닫기
            if (!slashMenuEl.contains(event.target)) {
                closeSlashMenu();
            }
        }
    });
}

/**
 * 에디터 초기화
 */
export function initEditor() {
    const element = document.querySelector("#editor");

    const editor = new Editor({
        element,
        editable: false,
        extensions: [
            StarterKit,
            CustomEnter,
            TextAlign.configure({
                types: ["heading", "paragraph"],
                alignments: ["left", "center", "right", "justify"],
            }),
            TextStyle,
            Color,
            FontFamily.configure({
                types: ["textStyle"],
            }),
            TaskList,
            TaskItem.configure({
                nested: true,
            }),
            Table.configure({
                resizable: true,
                lastColumnResizable: false,
                allowTableNodeSelection: true,
            }),
            TableRow,
            TableHeader.extend({
                addAttributes() {
                    return {
                        ...this.parent?.(),
                        style: {
                            default: null,
                            parseHTML: element => element.getAttribute('style'),
                            renderHTML: attributes => {
                                if (!attributes.style) {
                                    return {};
                                }
                                return { style: attributes.style };
                            },
                        },
                    };
                },
            }),
            TableCell.extend({
                addAttributes() {
                    return {
                        ...this.parent?.(),
                        style: {
                            default: null,
                            parseHTML: element => element.getAttribute('style'),
                            renderHTML: attributes => {
                                if (!attributes.style) {
                                    return {};
                                }
                                return { style: attributes.style };
                            },
                        },
                    };
                },
            }),
            MathBlock,
            MathInline,
        ],
        content: "<p>불러오는 중...</p>",
        onSelectionUpdate() {
            updateToolbarState(editor);
        },
        onTransaction() {
            updateToolbarState(editor);
            // 크기 조절 중이 아닐 때만 핸들 재생성
            if (!isResizingTable) {
                setTimeout(() => addTableResizeHandles(editor), 50);
            }
        },
        onCreate() {
            updateToolbarState(editor);
            // 에디터 생성 시 핸들 추가
            setTimeout(() => addTableResizeHandles(editor), 50);
        },
        onUpdate() {
            // 내용 업데이트 시 핸들 재생성
            setTimeout(() => addTableResizeHandles(editor), 50);
        }
    });

    return editor;
}

/**
 * 현재 텍스트 정렬 상태 가져오기
 */
function getCurrentTextAlign(editor) {
    if (!editor) return null;

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

/**
 * 툴바 상태 업데이트
 */
export function updateToolbarState(editor) {
    if (!editor) return;

    const toolbar = document.querySelector(".editor-toolbar");
    if (!toolbar) return;

    const buttons = toolbar.querySelectorAll("button[data-command]");
    const currentAlign = getCurrentTextAlign(editor);

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
            case "h3":
                isActive = editor.isActive("heading", { level: 3 });
                break;
            case "h4":
                isActive = editor.isActive("heading", { level: 4 });
                break;
            case "h5":
                isActive = editor.isActive("heading", { level: 5 });
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

/**
 * 툴바 이벤트 바인딩
 */
export function bindToolbar(editor) {
    const toolbar = document.querySelector(".editor-toolbar");
    if (!toolbar) return;

    let colorDropdownElement = toolbar.querySelector("[data-role='color-dropdown']");
    let colorMenuElement = colorDropdownElement
        ? colorDropdownElement.querySelector("[data-color-menu]")
        : null;

    let fontDropdownElement = toolbar.querySelector("[data-role='font-dropdown']");
    let fontMenuElement = fontDropdownElement
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
            button.dataset.fontFamily = font.value || "";
            button.title = font.name;
            button.style.fontFamily = font.value || "inherit";
            button.textContent = font.name;
            fontMenuElement.appendChild(button);
        });
    }

    toolbar.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-command]");
        if (!button || !editor) return;

        const command = button.getAttribute("data-command");
        const colorValue = button.getAttribute("data-color");
        const fontFamilyValue = button.getAttribute("data-font-family");

        // 색상 드롭다운 토글
        if (command === "toggleColorDropdown") {
            if (!colorMenuElement || !colorDropdownElement) return;

            const isOpen = !colorMenuElement.hasAttribute("hidden");

            if (isOpen) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            } else {
                // 버튼 위치 계산
                const buttonRect = button.getBoundingClientRect();
                colorMenuElement.style.top = `${buttonRect.bottom + 4}px`;
                colorMenuElement.style.left = `${buttonRect.left}px`;

                colorMenuElement.removeAttribute("hidden");
                colorDropdownElement.classList.add("open");
            }
            return;
        }

        // 폰트 드롭다운 토글
        if (command === "toggleFontDropdown") {
            if (!fontMenuElement || !fontDropdownElement) return;

            const isOpen = !fontMenuElement.hasAttribute("hidden");

            if (isOpen) {
                fontMenuElement.setAttribute("hidden", "");
                fontDropdownElement.classList.remove("open");
            } else {
                // 버튼 위치 계산
                const buttonRect = button.getBoundingClientRect();
                fontMenuElement.style.top = `${buttonRect.bottom + 4}px`;
                fontMenuElement.style.left = `${buttonRect.left}px`;

                fontMenuElement.removeAttribute("hidden");
                fontDropdownElement.classList.add("open");
            }
            return;
        }

        // 색상 선택
        if (command === "setColor" && colorValue) {
            editor.chain().focus().setColor(colorValue).run();

            if (colorMenuElement && colorDropdownElement) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            }

            updateToolbarState(editor);
            return;
        }

        // 색상 초기화
        if (command === "unsetColor") {
            editor.chain().focus().unsetColor().run();

            if (colorMenuElement && colorDropdownElement) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            }

            updateToolbarState(editor);
            return;
        }

        // 폰트 선택
        if (command === "setFont") {
            if (fontFamilyValue === "") {
                editor.chain().focus().unsetFontFamily().run();
            } else {
                editor.chain().focus().setFontFamily(fontFamilyValue).run();
            }

            if (fontMenuElement && fontDropdownElement) {
                fontMenuElement.setAttribute("hidden", "");
                fontDropdownElement.classList.remove("open");
            }

            updateToolbarState(editor);
            return;
        }

        // 기본 편집 명령들
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
            case "h3":
                editor.chain().focus().toggleHeading({ level: 3 }).run();
                break;
            case "h4":
                editor.chain().focus().toggleHeading({ level: 4 }).run();
                break;
            case "h5":
                editor.chain().focus().toggleHeading({ level: 5 }).run();
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

        updateToolbarState(editor);
    });
}

/**
 * 테이블 크기 조절 핸들 추가 및 관리
 */
let resizingState = {
    isResizing: false,
    resizeType: null, // 'column' or 'row'
    startX: 0,
    startY: 0,
    startWidth: 0,
    startHeight: 0,
    targetCell: null,
    targetRow: null,
    editor: null
};

// 크기 조절 중인지 확인하는 플래그
let isResizingTable = false;

/**
 * 테이블에 크기 조절 핸들 추가
 */
export function addTableResizeHandles(editor) {
    const editorElement = document.querySelector("#editor .ProseMirror");
    if (!editorElement) return;

    // 기존 핸들 컨테이너 제거
    document.querySelectorAll(".table-resize-overlay").forEach(el => el.remove());

    // 모든 테이블 찾기
    const tables = editorElement.querySelectorAll("table");
    if (tables.length === 0) return;

    // editor 인스턴스 저장
    if (editor) {
        resizingState.editor = editor;
    }

    tables.forEach((table, tableIndex) => {
        // 테이블 위치 가져오기
        const tableRect = table.getBoundingClientRect();

        // overlay 생성 (fixed position 사용)
        const overlay = document.createElement("div");
        overlay.className = "table-resize-overlay";
        overlay.style.position = "fixed";
        overlay.style.left = tableRect.left + "px";
        overlay.style.top = tableRect.top + "px";
        overlay.style.width = tableRect.width + "px";
        overlay.style.height = tableRect.height + "px";
        overlay.style.zIndex = "9999";
        overlay.style.pointerEvents = "none";

        const rows = table.querySelectorAll("tr");

        rows.forEach((row, rowIndex) => {
            const cells = row.querySelectorAll("td, th");

            cells.forEach((cell, cellIndex) => {
                const cellRect = cell.getBoundingClientRect();

                // 열 크기 조절 핸들 (마지막 열이 아닌 경우)
                if (cellIndex < cells.length - 1) {
                    const colHandle = document.createElement("div");
                    colHandle.className = "custom-resize-handle custom-resize-handle-col";
                    colHandle.dataset.cellIndex = cellIndex;
                    colHandle.dataset.rowIndex = rowIndex;
                    colHandle.dataset.tableIndex = tableIndex;

                    const left = cellRect.right - tableRect.left - 3;
                    const top = cellRect.top - tableRect.top;
                    const height = cellRect.height;

                    colHandle.style.left = left + "px";
                    colHandle.style.top = top + "px";
                    colHandle.style.height = height + "px";
                    colHandle.style.pointerEvents = "auto";

                    overlay.appendChild(colHandle);
                    colHandle.addEventListener("mousedown", startColumnResize);
                }

                // 행 크기 조절 핸들 (마지막 행이 아닌 경우)
                if (rowIndex < rows.length - 1) {
                    const rowHandle = document.createElement("div");
                    rowHandle.className = "custom-resize-handle custom-resize-handle-row";
                    rowHandle.dataset.cellIndex = cellIndex;
                    rowHandle.dataset.rowIndex = rowIndex;
                    rowHandle.dataset.tableIndex = tableIndex;

                    const left = cellRect.left - tableRect.left;
                    const top = cellRect.bottom - tableRect.top - 3;
                    const width = cellRect.width;

                    rowHandle.style.left = left + "px";
                    rowHandle.style.top = top + "px";
                    rowHandle.style.width = width + "px";
                    rowHandle.style.pointerEvents = "auto";

                    overlay.appendChild(rowHandle);
                    rowHandle.addEventListener("mousedown", startRowResize);
                }
            });
        });

        document.body.appendChild(overlay);
    });
}

// 스크롤 시 핸들 위치 업데이트
window.addEventListener("scroll", () => {
    if (resizingState.editor) {
        addTableResizeHandles(resizingState.editor);
    }
}, true);

// 창 크기 변경 시 핸들 위치 실시간 업데이트
window.addEventListener("resize", () => {
    if (resizingState.editor) {
        addTableResizeHandles(resizingState.editor);
    }
});

/**
 * 테이블 크기 초기화
 */
function resetTableSize(e) {
    e.preventDefault();
    e.stopPropagation();

    console.log("테이블 크기 초기화 시작");

    if (!resizingState.editor) {
        console.log("에디터 인스턴스 없음");
        return;
    }

    const editor = resizingState.editor;
    const editorElement = document.querySelector("#editor .ProseMirror");
    const tables = editorElement.querySelectorAll("table");

    console.log(`테이블 개수: ${tables.length}`);

    if (tables.length === 0) return;

    // 모든 테이블의 모든 셀 초기화
    const { state } = editor.view;
    const { tr } = state;
    let updated = false;

    tables.forEach(table => {
        const allCells = table.querySelectorAll("td, th");
        console.log(`셀 개수: ${allCells.length}`);

        allCells.forEach(cell => {
            const pos = editor.view.posAtDOM(cell, 0);
            if (pos === null || pos === undefined) return;

            const $pos = state.doc.resolve(pos);
            const cellNode = $pos.node($pos.depth);

            if (cellNode && (cellNode.type.name === "tableCell" || cellNode.type.name === "tableHeader")) {
                console.log(`셀 초기화 전 attrs:`, cellNode.attrs);

                // style과 colwidth 속성을 null로 설정
                const newAttrs = {
                    ...cellNode.attrs,
                    style: null,
                    colwidth: null
                };

                console.log(`셀 초기화 후 attrs:`, newAttrs);

                tr.setNodeMarkup($pos.before($pos.depth), null, newAttrs);
                updated = true;
            }
        });
    });

    console.log(`업데이트 여부: ${updated}`);

    // 트랜잭션 적용
    if (updated) {
        editor.view.dispatch(tr);
        console.log("트랜잭션 적용 완료");

        // 핸들 재생성
        setTimeout(() => {
            addTableResizeHandles(editor);
        }, 50);
    }
}

/**
 * 열 크기 조절 시작
 */
function startColumnResize(e) {
    e.preventDefault();
    e.stopPropagation();

    // 더블클릭인 경우 크기 초기화
    if (e.detail === 2) {
        console.log("더블클릭 감지 - 테이블 크기 초기화");
        resetTableSize(e);
        return;
    }

    const handle = e.target;
    const cellIndex = parseInt(handle.dataset.cellIndex);
    const rowIndex = parseInt(handle.dataset.rowIndex);

    console.log(`열 크기 조절 시작: 행${rowIndex}, 열${cellIndex}`);

    // 에디터에서 테이블 찾기
    const editorElement = document.querySelector("#editor .ProseMirror");
    const table = editorElement.querySelector("table");
    if (!table) {
        console.log("테이블을 찾을 수 없음");
        return;
    }

    const rows = table.querySelectorAll("tr");
    const row = rows[rowIndex];
    if (!row) {
        console.log("행을 찾을 수 없음");
        return;
    }

    const cells = row.querySelectorAll("td, th");
    const cell = cells[cellIndex];
    if (!cell) {
        console.log("셀을 찾을 수 없음");
        return;
    }

    console.log(`셀 찾음, 현재 너비: ${cell.offsetWidth}px`);

    isResizingTable = true; // TipTap 재렌더링 방지
    resizingState.isResizing = true;
    resizingState.resizeType = "column";
    resizingState.startX = e.pageX;
    resizingState.startWidth = cell.offsetWidth;
    resizingState.cellIndex = cellIndex;
    resizingState.table = table;

    document.addEventListener("mousemove", doColumnResize);
    document.addEventListener("mouseup", stopResize);

    document.body.style.cursor = "col-resize";
    document.body.style.userSelect = "none";

    console.log("이벤트 리스너 등록 완료, TipTap 재렌더링 중단");
}

/**
 * 열 크기 조절 중
 */
function doColumnResize(e) {
    if (!resizingState.isResizing || resizingState.resizeType !== "column") return;
    if (!resizingState.editor) return;

    const diff = e.pageX - resizingState.startX;
    const newWidth = Math.max(50, resizingState.startWidth + diff);

    const editor = resizingState.editor;
    const cellIndex = resizingState.cellIndex;
    const table = resizingState.table;

    // TipTap의 문서 모델을 업데이트
    const { state } = editor.view;
    const { tr } = state;
    let updated = false;

    // 테이블의 모든 행을 순회하며 해당 열의 셀에 width 설정
    const rows = table.querySelectorAll("tr");
    rows.forEach((row, rowIndex) => {
        const cells = row.querySelectorAll("td, th");
        const cell = cells[cellIndex];
        if (!cell) return;

        // DOM 위치에서 Prosemirror 위치 찾기
        const pos = editor.view.posAtDOM(cell, 0);
        if (pos === null || pos === undefined) return;

        // 셀 노드의 시작 위치 찾기
        const $pos = state.doc.resolve(pos);
        const cellNode = $pos.node($pos.depth);

        if (cellNode && (cellNode.type.name === "tableCell" || cellNode.type.name === "tableHeader")) {
            // colwidth 속성 업데이트와 함께 인라인 스타일도 설정
            const roundedWidth = Math.round(newWidth);
            const attrs = {
                ...cellNode.attrs,
                colwidth: [roundedWidth],
                style: `width: ${roundedWidth}px; min-width: ${roundedWidth}px;`
            };
            tr.setNodeMarkup($pos.before($pos.depth), null, attrs);
            updated = true;
        }
    });

    // 트랜잭션 적용
    if (updated) {
        editor.view.dispatch(tr);
    }
}

/**
 * 행 크기 조절 시작
 */
function startRowResize(e) {
    e.preventDefault();
    e.stopPropagation();

    // 더블클릭인 경우 크기 초기화
    if (e.detail === 2) {
        console.log("더블클릭 감지 - 테이블 크기 초기화");
        resetTableSize(e);
        return;
    }

    const handle = e.target;
    const rowIndex = parseInt(handle.dataset.rowIndex);

    // 에디터에서 테이블 찾기
    const editorElement = document.querySelector("#editor .ProseMirror");
    const table = editorElement.querySelector("table");
    if (!table) return;

    const rows = table.querySelectorAll("tr");
    const row = rows[rowIndex];
    if (!row) return;

    isResizingTable = true; // TipTap 재렌더링 방지
    resizingState.isResizing = true;
    resizingState.resizeType = "row";
    resizingState.startY = e.pageY;
    resizingState.startHeight = row.offsetHeight;
    resizingState.targetRow = row;

    document.addEventListener("mousemove", doRowResize);
    document.addEventListener("mouseup", stopResize);

    document.body.style.cursor = "row-resize";
    document.body.style.userSelect = "none";
}

/**
 * 행 크기 조절 중
 */
function doRowResize(e) {
    if (!resizingState.isResizing || resizingState.resizeType !== "row") return;
    if (!resizingState.editor) return;

    const diff = e.pageY - resizingState.startY;
    const newHeight = Math.max(30, resizingState.startHeight + diff);

    const editor = resizingState.editor;
    const targetRow = resizingState.targetRow;

    // TipTap의 문서 모델을 업데이트
    const { state } = editor.view;
    const { tr } = state;
    let updated = false;

    // 행의 모든 셀에 높이 설정
    const cells = targetRow.querySelectorAll("td, th");
    cells.forEach(cell => {
        // DOM 위치에서 Prosemirror 위치 찾기
        const pos = editor.view.posAtDOM(cell, 0);
        if (pos === null || pos === undefined) return;

        // 셀 노드의 시작 위치 찾기
        const $pos = state.doc.resolve(pos);
        const cellNode = $pos.node($pos.depth);

        if (cellNode && (cellNode.type.name === "tableCell" || cellNode.type.name === "tableHeader")) {
            // 높이 속성 업데이트 (rowspan과 colspan 유지)
            const attrs = {
                ...cellNode.attrs,
                style: `height: ${newHeight}px; min-height: ${newHeight}px;`
            };
            tr.setNodeMarkup($pos.before($pos.depth), null, attrs);
            updated = true;
        }
    });

    // 트랜잭션 적용
    if (updated) {
        editor.view.dispatch(tr);
    }
}

/**
 * 크기 조절 종료
 */
function stopResize() {
    if (resizingState.isResizing) {
        document.removeEventListener("mousemove", doColumnResize);
        document.removeEventListener("mousemove", doRowResize);
        document.removeEventListener("mouseup", stopResize);

        document.body.style.cursor = "";
        document.body.style.userSelect = "";

        resizingState.isResizing = false;
        resizingState.resizeType = null;
        resizingState.targetCell = null;
        resizingState.targetRow = null;

        console.log("크기 조절 종료, TipTap 재렌더링 재개");

        // 크기 조절 완료 후 플래그 해제 및 핸들 재생성
        setTimeout(() => {
            isResizingTable = false;
            if (resizingState.editor) {
                addTableResizeHandles(resizingState.editor);
            }
        }, 100);
    }
}
