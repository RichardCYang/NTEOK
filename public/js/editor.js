export const EXAMPLE_CONTENT = `
    <h1>NTEOK에 오신 것을 환영합니다! 👋</h1>
    <p>NTEOK은 지능형 블록 기반 협업 에디터입니다. 아래 예제를 통해 다양한 블록의 사용법을 익혀보세요.</p>

    <div data-type="callout-block" data-callout-type="info" data-content="슬래시(/) 키를 눌러 다양한 블록을 빠르게 추가할 수 있습니다!"></div>

    <h2>1. 기본 텍스트 및 서식</h2>
    <p>텍스트를 드래그하여 <strong>굵게</strong>, <em>기울임</em>, <s>취소선</s>, <code>코드</code> 등 다양한 서식을 적용할 수 있습니다. 폰트와 <span style="color: #ef4444">색상</span>도 자유롭게 변경해 보세요.</p>

    <h2>2. 목록과 작업</h2>
    <ul data-type="taskList">
        <li data-checked="true"><p>에디터 사용법 익히기</p></li>
        <li data-checked="false"><p>첫 페이지 생성하기</p></li>
        <li data-checked="false"><p>친구 초대하기</p></li>
    </ul>

    <div data-type="toggle-block" data-title="더 자세한 내용 보기 (토글)" data-is-open="true">
        <div class="toggle-content">
            <p>토글 블록을 사용하여 복잡한 내용을 숨기고 필요할 때만 펼쳐볼 수 있습니다.</p>
        </div>
    </div>

    <h2>3. 표와 수식</h2>
    <table>
        <tbody>
            <tr>
                <th style="background-color: #f3f4f6"><p>기능</p></th>
                <th style="background-color: #f3f4f6"><p>설명</p></th>
            </tr>
            <tr>
                <td><p>실시간 동기화</p></td>
                <td><p>다른 사용자와 동시에 편집 가능</p></td>
            </tr>
            <tr>
                <td><p>E2EE</p></td>
                <td><p>강력한 종단간 암호화 지원</p></td>
            </tr>
        </tbody>
    </table>

    <p>수학 수식도 지원합니다: <span data-type="math-inline" data-latex="E = mc^2"></span></p>

    <div data-type="math-block" data-latex="\\int_{a}^{b} x^2 dx = \\frac{b^3 - a^3}{3}"></div>

    <h2>4. 멀티미디어 및 링크</h2>
    <p>이 외에도 <strong>보드 뷰</strong>, <strong>이미지</strong>, <strong>YouTube</strong> 등 다양한 블록을 활용해 보세요!</p>
`;


import { secureFetch, syncPageUpdatedAtPadding, escapeHtml } from './ui-utils.js';
import { setTrustedHTML } from './sanitize.js';

function safeSetInnerHTML(element, html) {
    setTrustedHTML(element, html);
}

import { TextAlign } from "@tiptap/extension-text-align";

import Color from "@tiptap/extension-color";
import TextStyle from "@tiptap/extension-text-style";

import FontFamily from "@tiptap/extension-font-family";

import TaskList from "@tiptap/extension-task-list";
import TaskItem from "@tiptap/extension-task-item";

import Table from "@tiptap/extension-table";
import TableRow from "@tiptap/extension-table-row";
import TableHeader from "@tiptap/extension-table-header";
import TableCell from "@tiptap/extension-table-cell";

import { MathBlock, MathInline } from './math-node.js';

import { ImageWithCaption } from './image-with-caption-node.js';

import { CalloutBlock } from './callout-node.js';

import { ToggleBlock } from './toggle-node.js';

import { BoardBlock } from './board-node.js';

import { YoutubeBlock } from './youtube-node.js';

import { FileBlock } from './file-node.js';

import { CalendarBlock } from './calendar-node.js';

import { DatabaseBlock } from './database-node.js';

import { TabBlock, TabItem } from './tab-node.js';

import { BookmarkBlock } from './bookmark-node.js';

import { DragHandle } from './drag-handle-extension.js';

import { Plugin, PluginKey } from "prosemirror-state";
import { Decoration, DecorationSet } from "prosemirror-view";

const Editor = Tiptap.Core.Editor;
const StarterKit = Tiptap.StarterKit;
const Extension = Tiptap.Core.Extension;

async function handleImageUpload(editor, file) {
    const pageId = window.appState?.currentPageId;
    if (!pageId) {
        alert('페이지 ID를 찾을 수 없습니다.');
        return;
    }

    const formData = new FormData();
    formData.append('image', file);

    const response = await secureFetch(`/api/pages/${pageId}/editor-image`, {
        method: 'POST',
        body: formData
    });

    if (!response.ok) {
        throw new Error('이미지 업로드 실패');
    }

    const data = await response.json();

    editor.chain().focus().setImageWithCaption({
        src: data.url,
        alt: file.name || 'uploaded image',
        caption: ''
    }).run();
}

const Placeholder = Extension.create({
    name: 'placeholder',
    addOptions() {
        return {
            placeholder: '명령을 사용하려면 / 를 입력하세요',
            showOnlyCurrent: true,
            showOnlyWhenEditable: true,
        }
    },
    addProseMirrorPlugins() {
        return [
            new Plugin({
                key: new PluginKey('placeholder'),
                props: {
                    decorations: (state) => {
                        const { doc, selection } = state;
                        const { isEditable } = this.editor;

                        if (this.options.showOnlyWhenEditable && !isEditable) {
                            return null;
                        }

                        if (!this.editor.isFocused) {
                            return null;
                        }

                        const { $anchor } = selection;
                        const node = $anchor.parent;

                        if (node.type.isTextblock && node.content.size === 0) {
                            const pos = $anchor.before($anchor.depth);
                            const decoration = Decoration.node(pos, pos + node.nodeSize, {
                                class: 'is-empty',
                                'data-placeholder': typeof this.options.placeholder === 'function'
                                    ? this.options.placeholder({ node, pos, editor: this.editor })
                                    : this.options.placeholder,
                            });
                            return DecorationSet.create(doc, [decoration]);
                        }

                        return null;
                    },
                },
            }),
        ];
    },
});

const ImagePaste = Extension.create({
    name: 'imagePaste',
    addProseMirrorPlugins() {
        const { editor } = this;
        return [
            new Plugin({
                key: new PluginKey('imagePaste'),
                props: {
                    handlePaste: (view, event) => {
                        const items = (event.clipboardData || event.originalEvent?.clipboardData)?.items;
                        if (!items) return false;

                        let handled = false;
                        for (const item of items) {
                            if (item.type.indexOf('image') === 0) {
                                const file = item.getAsFile();
                                if (file) {
                                    event.preventDefault();
                                    handleImageUpload(editor, file).catch(err => {
                                        console.error('이미지 붙여넣기 업로드 실패:', err);
                                        alert('이미지 업로드에 실패했습니다.');
                                    });
                                    handled = true;
                                }
                            }
                        }
                        return handled;
                    }
                }
            })
        ];
    }
});

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

export const SLASH_ITEMS = [
    { id: "text", label: "텍스트", description: "기본 문단 블록", icon: "T", command(editor) { editor.chain().focus().setParagraph().run(); } },
    { id: "heading1", label: "제목 1", description: "큰 제목(Heading 1)", icon: "H1", command(editor) { editor.chain().focus().setHeading({ level: 1 }).run(); } },
    { id: "heading2", label: "제목 2", description: "중간 제목(Heading 2)", icon: "H2", command(editor) { editor.chain().focus().setHeading({ level: 2 }).run(); } },
    { id: "heading3", label: "제목 3", description: "작은 제목(Heading 3)", icon: "H3", command(editor) { editor.chain().focus().setHeading({ level: 3 }).run(); } },
    { id: "heading4", label: "제목 4", description: "더 작은 제목(Heading 4)", icon: "H4", command(editor) { editor.chain().focus().setHeading({ level: 4 }).run(); } },
    { id: "heading5", label: "제목 5", description: "가장 작은 제목(Heading 5)", icon: "H5", command(editor) { editor.chain().focus().setHeading({ level: 5 }).run(); } },
    { id: "bulletList", label: "글머리 기호 목록", description: "점 목록 블록", icon: "•", command(editor) { editor.chain().focus().toggleBulletList().run(); } },
    { id: "orderedList", label: "번호 목록", description: "순서 있는 목록", icon: "1.", command(editor) { editor.chain().focus().toggleOrderedList().run(); } },
    { id: "taskList", label: "체크리스트", description: "완료 상태를 표시하는 목록", icon: "☑", command(editor) { editor.chain().focus().toggleTaskList().run(); } },
    { id: "toggleList", label: "토글 목록", description: "내용을 접고 펼칠 수 있는 목록", icon: "▶", command(editor) { editor.chain().focus().setToggleBlock().run(); } },
    { id: "blockquote", label: "인용구", description: "강조된 인용 블록", icon: "❝", command(editor) { editor.chain().focus().toggleBlockquote().run(); } },
    { id: "codeBlock", label: "코드 블록", description: "고정폭 코드 블록", icon: "{ }", command(editor) { editor.chain().focus().toggleCodeBlock().run(); } },
    { id: "mathBlock", label: "수식 블록", description: "LaTeX 수식 (블록)", icon: "∑", command(editor) { editor.chain().focus().setMathBlock('').run(); } },
    { id: "mathInline", label: "인라인 수식", description: "$수식$ 형식으로 입력", icon: "$", command(editor) { editor.chain().focus().insertContent('$수식$').run(); } },
    { id: "table", label: "표", description: "3x3 표 삽입", icon: "⊞", command(editor) { editor.chain().focus().insertTable({ rows: 3, cols: 3, withHeaderRow: true }).run(); } },
    {
        id: "image",
        label: "이미지",
        description: "이미지 파일 업로드",
        icon: "🖼",
        command(editor) {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'image/*';
            input.onchange = async () => {
                if (input.files?.length) {
                    const file = input.files[0];
                    try {
                        await handleImageUpload(editor, file);
                    } catch (e) {
                        alert(e.message);
                    }
                }
            };
            input.click();
        }
    },
    { id: "youtube",
        label: "YouTube",
        description: "유튜브 비디오 임베드",
        icon: "▶",
        command(editor) {
            const url = prompt("YouTube 비디오 URL을 입력하세요:");
            if (!url) return;
            const match = url.match(/(?:https?:\/\/)?(?:www\.)?(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/shorts\/)([A-Za-z0-9_-]{11})/);
            if (match?.[1]) {
                editor.chain().focus().setYoutubeBlock({ src: `https://www.youtube.com/embed/${match[1]}` }).run();
            } else {
                alert("올바른 YouTube URL이 아닙니다.");
            }
        }
    },
    { id: "kanban", label: "칸반 보드", description: "작업 관리 보드", icon: "📋", command(editor) { editor.chain().focus().setBoardBlock().run(); } },
    { id: "bookmark", label: "링크 블록", description: "북마크 추출", icon: "🔗", command(editor) { editor.chain().focus().setBookmarkBlock().run(); } },
    { id: "calendar", label: "캘린더", description: "날짜 선택 캘린더", icon: "📅", command(editor) { editor.chain().focus().setCalendarBlock().run(); } },
    { id: "database", label: "데이터베이스", description: "데이터 테이블", icon: "📊", command(editor) { editor.chain().focus().setDatabaseBlock().run(); } },
    { id: "tabView", label: "탭뷰", description: "탭 형식 블록", icon: "⊟", command(editor) { editor.chain().focus().setTabBlock().run(); } }
];

const TABLE_MENU_ITEMS = [
    {
        id: "addColumnBefore",
        label: "왼쪽에 열 추가",
        icon: "←",
        command: (editor) => editor.chain().focus().addColumnBefore().run(),
        isEnabled: (editor) => editor.can().addColumnBefore()
    },
    {
        id: "addColumnAfter",
        label: "오른쪽에 열 추가",
        icon: "→",
        command: (editor) => editor.chain().focus().addColumnAfter().run(),
        isEnabled: (editor) => editor.can().addColumnAfter()
    },
    {
        id: "deleteColumn",
        label: "열 삭제",
        icon: "🗑️",
        command: (editor) => deleteColumnSafe(editor),
        isEnabled: (editor) => editor.can().deleteColumn(),
        isDanger: true
    },
    { type: "separator" },
    {
        id: "addRowBefore",
        label: "위에 행 추가",
        icon: "↑",
        command: (editor) => editor.chain().focus().addRowBefore().run(),
        isEnabled: (editor) => editor.can().addRowBefore()
    },
    {
        id: "addRowAfter",
        label: "아래에 행 추가",
        icon: "↓",
        command: (editor) => editor.chain().focus().addRowAfter().run(),
        isEnabled: (editor) => editor.can().addRowAfter()
    },
    {
        id: "deleteRow",
        label: "행 삭제",
        icon: "🗑️",
        command: (editor) => deleteRowSafe(editor),
        isEnabled: (editor) => editor.can().deleteRow(),
        isDanger: true
    },
    { type: "separator" },
    {
        id: "deleteTable",
        label: "표 삭제",
        icon: "✕",
        command: (editor) => editor.chain().focus().deleteTable().run(),
        isEnabled: (editor) => editor.can().deleteTable(),
        isDanger: true
    }
];

function deleteRowSafe(editor) {
    const { state } = editor.view;

    let rowCount = 0;
    let tableNode = null;

    state.doc.descendants((node, pos) => {
        if (node.type.name === "table") {
            const $anchor = state.selection.$anchor;
            if ($anchor.pos >= pos && $anchor.pos <= pos + node.nodeSize) {
                tableNode = node;
                rowCount = node.childCount;
                return false; 
            }
        }
    });

    if (rowCount <= 1) {
        alert("표에는 최소 1개의 행이 있어야 합니다.");
        return false;
    }

    return editor.chain().focus().deleteRow().run();
}

function deleteColumnSafe(editor) {
    const { state } = editor.view;

    let colCount = 0;

    state.doc.descendants((node, pos) => {
        if (node.type.name === "table") {
            const $anchor = state.selection.$anchor;
            if ($anchor.pos >= pos && $anchor.pos <= pos + node.nodeSize) {
                const firstRow = node.firstChild;
                if (firstRow) {
                    colCount = firstRow.childCount;
                }
                return false; 
            }
        }
    });

    if (colCount <= 1) {
        alert("표에는 최소 1개의 열이 있어야 합니다.");
        return false;
    }

    return editor.chain().focus().deleteColumn().run();
}

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

const TableKeyboardShortcuts = Extension.create({
    name: "tableKeyboardShortcuts",
    addKeyboardShortcuts() {
        return {
            "Mod-Shift-ArrowUp": ({ editor }) => {
                if (editor.isActive("table") && editor.can().addRowBefore()) {
                    return editor.chain().focus().addRowBefore().run();
                }
                return false;
            },
            "Mod-Shift-ArrowDown": ({ editor }) => {
                if (editor.isActive("table") && editor.can().addRowAfter()) {
                    return editor.chain().focus().addRowAfter().run();
                }
                return false;
            },
            "Mod-Shift-ArrowLeft": ({ editor }) => {
                if (editor.isActive("table") && editor.can().addColumnBefore()) {
                    return editor.chain().focus().addColumnBefore().run();
                }
                return false;
            },
            "Mod-Shift-ArrowRight": ({ editor }) => {
                if (editor.isActive("table") && editor.can().addColumnAfter()) {
                    return editor.chain().focus().addColumnAfter().run();
                }
                return false;
            },
            "Mod-Backspace": ({ editor }) => {
                if (editor.isActive("table") && editor.can().deleteRow()) {
                    return deleteRowSafe(editor);
                }
                return false;
            },
            "Mod-Shift-Backspace": ({ editor }) => {
                if (editor.isActive("table") && editor.can().deleteColumn()) {
                    return deleteColumnSafe(editor);
                }
                return false;
            }
        };
    }
});

let slashMenuEl = null;
let slashActiveIndex = 0;
let slashState = {
    active: false,
    ready: false,
    fromPos: null,
    filterText: '',
    filteredItems: []
};

let slashImeComposing = false;

function getNearestTextblockStart(doc, pos) {
    const $pos = doc.resolve(pos);
    for (let d = $pos.depth; d > 0; d--) {
        const node = $pos.node(d);
        if (node && node.isTextblock)
            return $pos.start(d);
    }
    return null;
}

function isSlashContextValid(editor) {
    if (!slashState.active || typeof slashState.fromPos !== 'number') return false;

    const { doc, selection } = editor.state;
    if (!selection.empty) return false;

    if (selection.from < slashState.fromPos + 1) return false;

    const selBlockStart = getNearestTextblockStart(doc, selection.from);
    const slashBlockStart = getNearestTextblockStart(doc, slashState.fromPos);
    if (selBlockStart == null || slashBlockStart == null || selBlockStart !== slashBlockStart)
        return false;

    try {
        const char = doc.textBetween(slashState.fromPos, slashState.fromPos + 1);
        if (char !== '/') return false;
    } catch {
        return false;
    }

    return true;
}

function syncSlashMenu(editor, opts = {}) {
    if (!slashState.active || slashState.fromPos === null) return;

    const { doc, selection } = editor.state;
	const composing = !!(slashImeComposing || editor?.view?.composing);
	const forceDom = !!opts.forceDom;

    if (slashState.ready && !selection.empty && !composing) {
        closeSlashMenu();
        return;
    }

    if (slashState.ready && !composing && selection.from <= slashState.fromPos) {
        closeSlashMenu();
        return;
    }

    try {
        const ch = doc.textBetween(slashState.fromPos, slashState.fromPos + 1);
        if (ch === "/") {
            slashState.ready = true;
        } else {
            if (!slashState.ready) return;
            closeSlashMenu();
            return;
        }
    } catch (e) {
        closeSlashMenu();
        return;
    }

    const text = getSlashCommandText(editor, { forceDom });
    if (text === slashState.filterText) return;
    slashState.filterText = text;
    slashState.filteredItems = filterSlashItems(text);
    renderSlashMenuItems();
}

function filterSlashItems(filterText) {
	const normalized = (filterText || '').trim().toLowerCase();
	if (!normalized) return SLASH_ITEMS;

    return SLASH_ITEMS.filter(item =>
		item.label.toLowerCase().includes(normalized) ||
		item.description.toLowerCase().includes(normalized)
    );
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
    listEl.id = "slash-menu-list";

    slashMenuEl.appendChild(listEl);
    document.body.appendChild(slashMenuEl);

    slashMenuEl.addEventListener("click", (event) => {
        const li = event.target.closest(".slash-menu-item");
        if (!li) return;
        const id = li.dataset.id;
        runSlashCommand(id);
    });
}

function renderSlashMenuItems() {
    if (!slashMenuEl) return;

    const listEl = slashMenuEl.querySelector("#slash-menu-list");
    if (!listEl) return;

    while (listEl.firstChild) listEl.removeChild(listEl.firstChild);

    const displayFilter = (slashState.filterText || '').trim();
    if (displayFilter) {
        const filterInfo = document.createElement("li");
        filterInfo.className = "slash-menu-filter-info";
        safeSetInnerHTML(filterInfo, `검색: <strong>${escapeHtml(displayFilter)}</strong>`);
        filterInfo.style.padding = "8px 16px";
        filterInfo.style.fontSize = "12px";
        filterInfo.style.color = "#999";
        filterInfo.style.borderBottom = "1px solid #eee";
        listEl.appendChild(filterInfo);
    }

    if (slashState.filteredItems.length === 0) {
        const noResults = document.createElement("li");
        noResults.className = "slash-menu-no-results";
        noResults.textContent = '검색 결과가 없습니다';
        noResults.style.padding = "16px";
        noResults.style.textAlign = "center";
        noResults.style.color = "#ccc";
        listEl.appendChild(noResults);
    } else {
        slashState.filteredItems.forEach((item, index) => {
            const li = document.createElement("li");
            li.className = "slash-menu-item";
            li.dataset.id = item.id;

            if (index === 0) {
                li.classList.add("active");
            }

            safeSetInnerHTML(li, `
                <div class="slash-menu-item-icon">${item.icon}</div>
                <div class="slash-menu-item-main">
                    <div class="slash-menu-item-label">${item.label}</div>
                    <div class="slash-menu-item-desc">${item.description}</div>
                </div>
            `);

            listEl.appendChild(li);
        });
    }

    slashActiveIndex = 0;
}

function openSlashMenu(coords, fromPos, editor) {
    if (!slashMenuEl) {
        createSlashMenuElement();
    }

    slashState.active = true;
    slashState.ready = false;
    slashState.fromPos = fromPos;
    slashState.editor = editor;
    slashState.filterText = '';
    slashState.filteredItems = filterSlashItems('');
    slashActiveIndex = 0;

    renderSlashMenuItems();

    slashMenuEl.classList.remove("hidden");
    slashMenuEl.style.visibility = "hidden"; 
    slashMenuEl.style.left = `${coords.left}px`;
    slashMenuEl.style.top = `${coords.bottom + 4}px`;

    requestAnimationFrame(() => {
        const menuHeight = slashMenuEl.offsetHeight;
        const windowHeight = window.innerHeight;
        let top = coords.bottom + 4;

        if (top + menuHeight > windowHeight) {
            top = coords.top - menuHeight - 4;
            if (top < 0) {
                top = coords.bottom + 4;
            }
        }

        slashMenuEl.style.top = `${top}px`;
        slashMenuEl.style.visibility = "visible"; 
    });
}

function closeSlashMenu() {
    slashState.active = false;
    slashState.ready = false;
    slashState.fromPos = null;
    slashState.editor = null;
    slashState.filterText = '';
    slashState.filteredItems = [];
    slashImeComposing = false;
    if (slashMenuEl) {
        slashMenuEl.classList.add("hidden");
		slashMenuEl.style.visibility = "hidden";
    }
}

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
        const selection = editor.state.selection;
        editor
            .chain()
            .focus()
            .deleteRange({
                from: slashState.fromPos,
                to: selection.from
            })
            .run();

        if (editor.state.selection.node) {
            editor.chain().insertContentAt(editor.state.selection.from, "<p></p>").focus(editor.state.selection.from).run();
        }
    }

    item.command(editor);
    closeSlashMenu();
}

function runSlashCommandActive() {
    if (!slashMenuEl) return;

    const items = Array.from(slashMenuEl.querySelectorAll(".slash-menu-item"));
    if (!items.length) return;

    const active = items[slashActiveIndex];
    const id = active.dataset.id;
    runSlashCommand(id);
}

function getSlashCommandText(editor, opts = {}) {
    if (!slashState.active || slashState.fromPos === null) return '';

    const view = editor?.view;
    const from = slashState.fromPos + 1; 
    const forceDom = !!opts.forceDom;

    if (forceDom || view?.composing || slashImeComposing) {
        try {
            const sel = view.dom.ownerDocument.getSelection();
            if (!sel || sel.rangeCount === 0) return '';
            if (!sel.focusNode || !view.dom.contains(sel.focusNode)) return '';

            const start = view.domAtPos(from);
            const range = view.dom.ownerDocument.createRange();
            range.setStart(start.node, start.offset);
            range.setEnd(sel.focusNode, sel.focusOffset);
            return range.toString();
        } catch {
            return '';
        }
    }

	const selection = editor.state.selection;
	const to = selection.from;
	if (to <= from) return '';
	return editor.state.doc.textBetween(from, to);
}


export function bindSlashKeyHandlers(editor) {
    document.addEventListener("keydown", (event) => {
        if (!editor) return;
		const composing = !!(slashImeComposing || event.isComposing || editor?.view?.composing);
        const inEditor = event.target?.closest?.(".ProseMirror");

        if (!slashState.active && event.key === "/" && inEditor) {
            try {
                const pos = editor.state.selection.from;
                openSlashMenu(editor.view.coordsAtPos(pos), pos, editor);
            } catch (e) { console.error("슬래시 메뉴 위치 계산 실패:", e); }
            return;
        }

        if (slashState.active && !composing) {
            if (event.key === "ArrowDown") { event.preventDefault(); moveSlashActive(1); return; }
            if (event.key === "ArrowUp") { event.preventDefault(); moveSlashActive(-1); return; }
            if (event.key === "Enter") { event.preventDefault(); runSlashCommandActive(); return; }
            if (event.key === "Escape") { event.preventDefault(); closeSlashMenu(); return; }
            if ((event.key === "Backspace" || event.key === "Delete") && slashState.fromPos !== null) {
                const sel = editor.state.selection;
                if (!sel.empty && sel.from <= slashState.fromPos && sel.to >= slashState.fromPos + 1) closeSlashMenu();
                else if (event.key === "Backspace" && sel.from === slashState.fromPos + 1) closeSlashMenu();
                else if (event.key === "Delete" && sel.from === slashState.fromPos) closeSlashMenu();
            }
        }
    });

    if (!bindSlashKeyHandlers.__imeBound && editor?.view?.dom) {
        bindSlashKeyHandlers.__imeBound = true;
        const dom = editor.view.dom;
        const sync = (forceDom) => { if (slashState.active) syncSlashMenu(editor, { forceDom }); };
        
        dom.addEventListener('compositionstart', () => { slashImeComposing = true; sync(true); });
        dom.addEventListener('compositionupdate', () => sync(true));
        dom.addEventListener('compositionend', () => { slashImeComposing = false; sync(false); });
        dom.addEventListener('input', () => requestAnimationFrame(() => sync(slashImeComposing)));
    }

    document.addEventListener("click", (e) => {
        if (slashState.active && slashMenuEl && !slashMenuEl.contains(e.target)) closeSlashMenu();
    });
}

export function initEditor() {
    const element = document.querySelector("#editor");

    const editor = new Editor({
        element,
        editable: false,
        extensions: [
            StarterKit,
            CustomEnter,
            TableKeyboardShortcuts,
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
            ImageWithCaption,
            CalloutBlock,
            ToggleBlock,
            BoardBlock,
            YoutubeBlock,
            BookmarkBlock,
            FileBlock,
            CalendarBlock,
            DatabaseBlock,
            TabItem,
            TabBlock,
            DragHandle,
            ImagePaste,
            Placeholder.configure({
                placeholder: '명령을 사용하려면 / 를 입력하세요',
                showOnlyCurrent: true,
                showOnlyWhenEditable: true,
            }),
        ],
        content: EXAMPLE_CONTENT,
        onSelectionUpdate() {
            updateToolbarState(editor);
            if (!isMouseDown) {
                updateBubbleMenuPosition(editor);
            }
            if (slashState.active)
            	syncSlashMenu(editor);
        },
        onTransaction({ transaction }) {
            updateToolbarState(editor);
            if (!isMouseDown) {
                updateBubbleMenuPosition(editor);
            }

            if (!isResizingTable) {
                setTimeout(() => addTableResizeHandles(editor), 50);
            }

            if (slashState.active && slashState.fromPos !== null && transaction?.docChanged) {
                try {
                    slashState.fromPos = transaction.mapping.map(slashState.fromPos, -1);
                } catch (e) {
                    closeSlashMenu();
                }
            }
        },
        onCreate() {
            updateToolbarState(editor);
            setTimeout(() => addTableResizeHandles(editor), 50);
        },
        onUpdate() {
            setTimeout(() => addTableResizeHandles(editor), 50);

			if (slashState.active)
				syncSlashMenu(editor);
            
            if (!isMouseDown) {
                updateBubbleMenuPosition(editor);
            }
        }
    });

    bindTableContextMenu(editor);

    const proseMirrorEl = document.querySelector("#editor .ProseMirror");
    if (proseMirrorEl) {
        proseMirrorEl.addEventListener("mousedown", () => {
            isMouseDown = true;
        });
        window.addEventListener("mouseup", () => {
            if (isMouseDown) {
                isMouseDown = false;
                setTimeout(() => {
                    updateBubbleMenuPosition(editor);
                }, 10);
            }
        });
    }

    const scrollHandler = () => {
        if (editor && window.appState?.isWriteMode && !isMouseDown) {
            updateBubbleMenuPosition(editor);
        }
    };

    document.querySelector(".editor")?.addEventListener("scroll", scrollHandler, { passive: true });
    document.getElementById("editor-scroll-container")?.addEventListener("scroll", scrollHandler, { passive: true });

    return editor;
}

let isMouseDown = false;

export function updateBubbleMenuPosition(editor) {
    const toolbar = document.querySelector(".editor-toolbar");
    if (!toolbar) return;

    if (!editor) return;

    const { state, view } = editor;
    const { selection } = state;

    const isFocused = editor.isFocused || (document.activeElement && toolbar.contains(document.activeElement));

    if (window.appState?.isWriteMode && isFocused && !selection.empty) {
        if (document.activeElement && document.activeElement.closest('#mode-toggle-btn')) {
            return;
        }

        try {
            let rect;
            if (selection.node) {
                const node = view.nodeDOM(selection.from);
                if (node instanceof HTMLElement) {
                    rect = node.getBoundingClientRect();
                }
            }

            if (!rect) {
                const domSelection = window.getSelection();
                if (domSelection.rangeCount > 0) {
                    const range = domSelection.getRangeAt(0);
                    rect = range.getBoundingClientRect();
                }
            }

            if (!rect || (rect.width === 0 && rect.height === 0)) {
                const startCoords = view.coordsAtPos(selection.from);
                const endCoords = view.coordsAtPos(selection.to);
                rect = {
                    left: Math.min(startCoords.left, endCoords.left),
                    right: Math.max(startCoords.right, endCoords.right),
                    top: Math.min(startCoords.top, endCoords.top),
                    bottom: Math.max(startCoords.bottom, endCoords.bottom),
                    width: Math.abs(startCoords.left - endCoords.left),
                    height: Math.abs(startCoords.top - endCoords.top)
                };
            }
            
            const left = rect.left + rect.width / 2;
            const top = rect.top;
            
            toolbar.classList.add("visible");
            
            const toolbarWidth = toolbar.offsetWidth;
            const toolbarHeight = toolbar.offsetHeight;
            
            let finalLeft = left - (toolbarWidth / 2);
            let finalTop = top - toolbarHeight - 10;
            
            if (finalLeft < 10) finalLeft = 10;
            if (finalLeft + toolbarWidth > window.innerWidth - 10) {
                finalLeft = window.innerWidth - toolbarWidth - 10;
            }
            
            if (finalTop < 10) {
                finalTop = rect.bottom + 10;
            }

            toolbar.style.left = `${finalLeft}px`;
            toolbar.style.top = `${finalTop}px`;
        } catch (e) {
            console.error("버블 메뉴 위치 계산 오류:", e);
        }
    } else {
        const isDropdownOpen = toolbar.querySelector(".toolbar-color-dropdown.open") || 
                               toolbar.querySelector(".toolbar-font-dropdown.open") ||
                               toolbar.querySelector(".toolbar-padding-dropdown.open") ||
                               !toolbar.querySelector(".toolbar-more-menu").classList.contains("hidden");
        
        if (!isDropdownOpen) {
            toolbar.classList.remove("visible");
            const moreMenu = toolbar.querySelector(".toolbar-more-menu");
            const moreBtn = toolbar.querySelector("[data-command='toggleMoreMenu']");
            if (moreMenu) moreMenu.classList.add("hidden");
            if (moreBtn) moreBtn.classList.remove("active");
        }
    }
}

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

    let paddingDropdownElement = toolbar.querySelector("[data-role='padding-dropdown']");
    let paddingMenuElement = paddingDropdownElement
        ? paddingDropdownElement.querySelector("[data-padding-menu]")
        : null;

    if (fontMenuElement) {
        while (fontMenuElement.firstChild) fontMenuElement.removeChild(fontMenuElement.firstChild);
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

    let lastFocusedBoardCard = null;

    toolbar.addEventListener("mousedown", (event) => {
        if (event.target.closest('input')) return;
        
        const button = event.target.closest("button[data-command]");
        if (button) {
            const activeCard = document.activeElement.closest('.board-card-content');
            if (activeCard) {
                lastFocusedBoardCard = activeCard;
            }
        }
        
        event.preventDefault();
    });

    toolbar.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-command]");
        if (!button || !editor) return;

        const command = button.getAttribute("data-command");
        const colorValue = button.getAttribute("data-color");
        const fontFamilyValue = button.getAttribute("data-font-family");

        const activeCard = document.activeElement.closest('.board-card-content') || lastFocusedBoardCard;
        
        if (!document.activeElement.closest('.board-card-content')) {
            lastFocusedBoardCard = null;
        }

        if (activeCard && ['bold', 'italic', 'strike', 'setColor', 'setFont', 'unsetColor', 'h1', 'h2', 'h3', 'h4', 'h5'].includes(command)) {
            if (activeCard !== document.activeElement) {
                activeCard.focus();
            }

            switch (command) {
                case "bold":
                    document.execCommand("bold", false, null);
                    break;
                case "italic":
                    document.execCommand("italic", false, null);
                    break;
                case "strike":
                    document.execCommand("strikethrough", false, null);
                    break;
                case "setColor":
                    if (colorValue) document.execCommand("foreColor", false, colorValue);
                    break;
                case "unsetColor":
                    document.execCommand("foreColor", false, "inherit"); 
                    break;
                case "setFont":
                    if (fontFamilyValue) document.execCommand("fontName", false, fontFamilyValue);
                    break;
                case "h1":
                    document.execCommand("formatBlock", false, "<h1>");
                    break;
                case "h2":
                    document.execCommand("formatBlock", false, "<h2>");
                    break;
                case "h3":
                    document.execCommand("formatBlock", false, "<h3>");
                    break;
                case "h4":
                    document.execCommand("formatBlock", false, "<h4>");
                    break;
                case "h5":
                    document.execCommand("formatBlock", false, "<h5>");
                    break;
            }
            
            if (command === "setColor" || command === "unsetColor") {
                if (colorMenuElement && colorDropdownElement) {
                    colorMenuElement.setAttribute("hidden", "");
                    colorDropdownElement.classList.remove("open");
                }
            }
            if (command === "setFont") {
                if (fontMenuElement && fontDropdownElement) {
                    fontMenuElement.setAttribute("hidden", "");
                    fontDropdownElement.classList.remove("open");
                }
            }
            return;
        }

        if (command === "toggleColorDropdown") {
            if (!colorMenuElement || !colorDropdownElement) return;

            const isOpen = !colorMenuElement.hasAttribute("hidden");

            if (isOpen) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            } else {
                const buttonRect = button.getBoundingClientRect();
                colorMenuElement.style.top = `${buttonRect.bottom + 4}px`;
                colorMenuElement.style.left = `${buttonRect.left}px`;

                colorMenuElement.removeAttribute("hidden");
                colorDropdownElement.classList.add("open");
            }
            return;
        }

        if (command === "toggleFontDropdown") {
            if (!fontMenuElement || !fontDropdownElement) return;

            const isOpen = !fontMenuElement.hasAttribute("hidden");

            if (isOpen) {
                fontMenuElement.setAttribute("hidden", "");
                fontDropdownElement.classList.remove("open");
            } else {
                const buttonRect = button.getBoundingClientRect();
                fontMenuElement.style.top = `${buttonRect.bottom + 4}px`;
                fontMenuElement.style.left = `${buttonRect.left}px`;

                fontMenuElement.removeAttribute("hidden");
                fontDropdownElement.classList.add("open");
            }
            return;
        }

        if (command === "togglePaddingDropdown") {
            if (!paddingMenuElement || !paddingDropdownElement) return;

            const isOpen = !paddingMenuElement.hasAttribute("hidden");

            if (isOpen) {
                paddingMenuElement.setAttribute("hidden", "");
                paddingDropdownElement.classList.remove("open");
            } else {
                const buttonRect = button.getBoundingClientRect();
                paddingMenuElement.style.top = `${buttonRect.bottom + 4}px`;
                paddingMenuElement.style.left = `${buttonRect.left}px`;

                updatePaddingMenuState();

                paddingMenuElement.removeAttribute("hidden");
                paddingDropdownElement.classList.add("open");
            }
            return;
        }

        if (command === "toggleMoreMenu") {
            const moreMenu = toolbar.querySelector(".toolbar-more-menu");
            if (!moreMenu) return;

            const isOpen = !moreMenu.classList.contains("hidden");
            
            if (colorMenuElement) colorMenuElement.setAttribute("hidden", "");
            if (fontMenuElement) fontMenuElement.setAttribute("hidden", "");

            if (isOpen) {
                moreMenu.classList.add("hidden");
                button.classList.remove("active");
            } else {
                const buttonRect = button.getBoundingClientRect();
                moreMenu.style.top = `${buttonRect.bottom + 8}px`;
                moreMenu.style.left = `${buttonRect.left - 80}px`; 
                moreMenu.classList.remove("hidden");
                button.classList.add("active");
            }
            return;
        }

        if (command === "setColor" && colorValue) {
            editor.chain().focus().setColor(colorValue).run();

            if (colorMenuElement && colorDropdownElement) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            }

            updateToolbarState(editor);
            return;
        }

        if (command === "unsetColor") {
            editor.chain().focus().unsetColor().run();

            if (colorMenuElement && colorDropdownElement) {
                colorMenuElement.setAttribute("hidden", "");
                colorDropdownElement.classList.remove("open");
            }

            updateToolbarState(editor);
            return;
        }

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

        if (command === "setPadding") {
            const paddingValue = button.getAttribute("data-padding");
            handlePaddingChange(paddingValue);

            if (paddingMenuElement && paddingDropdownElement) {
                paddingMenuElement.setAttribute("hidden", "");
                paddingDropdownElement.classList.remove("open");
            }
            return;
        }

        if (command === "applyCustomPadding") {
            const input = document.getElementById("padding-custom-input");
            if (input && input.value) {
                const value = parseInt(input.value);
                if (value >= 0 && value <= 300) {
                    handlePaddingChange(value.toString());
                    input.value = '';

                    if (paddingMenuElement && paddingDropdownElement) {
                        paddingMenuElement.setAttribute("hidden", "");
                        paddingDropdownElement.classList.remove("open");
                    }
                } else {
                    alert('여백은 0에서 300 사이의 값이어야 합니다.');
                }
            }
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

        const moreMenu = toolbar.querySelector(".toolbar-more-menu");
        const moreBtn = toolbar.querySelector("[data-command='toggleMoreMenu']");
        if (moreMenu && !moreMenu.classList.contains("hidden") && command !== "toggleMoreMenu") {
            moreMenu.classList.add("hidden");
            if (moreBtn) moreBtn.classList.remove("active");
        }
    });
}

let resizingState = {
    isResizing: false,
    resizeType: null, 
    startX: 0,
    startY: 0,
    startWidth: 0,
    startHeight: 0,
    targetCell: null,
    targetRow: null,
    editor: null
};

let isResizingTable = false;

export function addTableResizeHandles(editor) {
    const editorElement = document.querySelector("#editor .ProseMirror");
    if (!editorElement) return;

    document.querySelectorAll(".table-resize-overlay").forEach(el => el.remove());

    const tables = editorElement.querySelectorAll("table");
    if (tables.length === 0) return;

    if (editor) {
        resizingState.editor = editor;
    }

    tables.forEach((table, tableIndex) => {
        const tableRect = table.getBoundingClientRect();

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

window.addEventListener("scroll", () => {
    if (resizingState.editor) {
        addTableResizeHandles(resizingState.editor);
    }
}, true);

window.addEventListener("resize", () => {
    if (resizingState.editor) {
        addTableResizeHandles(resizingState.editor);
    }
});

window.addEventListener("resize", () => {
    syncPageUpdatedAtPadding();
});

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

    if (updated) {
        editor.view.dispatch(tr);
        console.log("트랜잭션 적용 완료");

        setTimeout(() => {
            addTableResizeHandles(editor);
        }, 50);
    }
}

function startColumnResize(e) {
    e.preventDefault();
    e.stopPropagation();

    if (e.detail === 2) {
        console.log("더블클릭 감지 - 테이블 크기 초기화");
        resetTableSize(e);
        return;
    }

    const handle = e.target;
    const cellIndex = parseInt(handle.dataset.cellIndex);
    const rowIndex = parseInt(handle.dataset.rowIndex);

    console.log(`열 크기 조절 시작: 행${rowIndex}, 열${cellIndex}`);

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

    isResizingTable = true; 
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

function doColumnResize(e) {
    if (!resizingState.isResizing || resizingState.resizeType !== "column") return;
    if (!resizingState.editor) return;

    const diff = e.pageX - resizingState.startX;
    const newWidth = Math.max(50, resizingState.startWidth + diff);

    const editor = resizingState.editor;
    const cellIndex = resizingState.cellIndex;
    const table = resizingState.table;

    const { state } = editor.view;
    const { tr } = state;
    let updated = false;

    const rows = table.querySelectorAll("tr");
    rows.forEach((row, rowIndex) => {
        const cells = row.querySelectorAll("td, th");
        const cell = cells[cellIndex];
        if (!cell) return;

        const pos = editor.view.posAtDOM(cell, 0);
        if (pos === null || pos === undefined) return;

        const $pos = state.doc.resolve(pos);
        const cellNode = $pos.node($pos.depth);

        if (cellNode && (cellNode.type.name === "tableCell" || cellNode.type.name === "tableHeader")) {
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

    if (updated) {
        editor.view.dispatch(tr);
    }
}

function startRowResize(e) {
    e.preventDefault();
    e.stopPropagation();

    if (e.detail === 2) {
        console.log("더블클릭 감지 - 테이블 크기 초기화");
        resetTableSize(e);
        return;
    }

    const handle = e.target;
    const rowIndex = parseInt(handle.dataset.rowIndex);

    const editorElement = document.querySelector("#editor .ProseMirror");
    const table = editorElement.querySelector("table");
    if (!table) return;

    const rows = table.querySelectorAll("tr");
    const row = rows[rowIndex];
    if (!row) return;

    isResizingTable = true; 
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

function doRowResize(e) {
    if (!resizingState.isResizing || resizingState.resizeType !== "row") return;
    if (!resizingState.editor) return;

    const diff = e.pageY - resizingState.startY;
    const newHeight = Math.max(30, resizingState.startHeight + diff);

    const editor = resizingState.editor;
    const targetRow = resizingState.targetRow;

    const { state } = editor.view;
    const { tr } = state;
    let updated = false;

    const cells = targetRow.querySelectorAll("td, th");
    cells.forEach(cell => {
        const pos = editor.view.posAtDOM(cell, 0);
        if (pos === null || pos === undefined) return;

        const $pos = state.doc.resolve(pos);
        const cellNode = $pos.node($pos.depth);

        if (cellNode && (cellNode.type.name === "tableCell" || cellNode.type.name === "tableHeader")) {
            const attrs = {
                ...cellNode.attrs,
                style: `height: ${newHeight}px; min-height: ${newHeight}px;`
            };
            tr.setNodeMarkup($pos.before($pos.depth), null, attrs);
            updated = true;
        }
    });

    if (updated) {
        editor.view.dispatch(tr);
    }
}

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

        setTimeout(() => {
            isResizingTable = false;
            if (resizingState.editor) {
                addTableResizeHandles(resizingState.editor);
            }
        }, 100);
    }
}

function hideTableContextMenu() {
    const menuEl = document.getElementById("context-menu");
    if (menuEl) {
        menuEl.classList.add("hidden");
    }
}

function showTableContextMenu(x, y, editor) {
    const menuEl = document.getElementById("context-menu");
    const contentEl = document.getElementById("context-menu-content");

    if (!menuEl || !contentEl) {
        console.error("컨텍스트 메뉴 요소를 찾을 수 없습니다.");
        return;
    }

    while (contentEl.firstChild) contentEl.removeChild(contentEl.firstChild);
    TABLE_MENU_ITEMS.forEach(item => {
        if (item.type === "separator") {
            const separator = document.createElement("div");
            separator.className = "context-menu-separator";
            contentEl.appendChild(separator);
            return;
        }

        const button = document.createElement("button");
        button.className = "context-menu-item";
        if (item.isDanger) {
            button.classList.add("danger");
        }

        const enabled = item.isEnabled(editor);
        if (!enabled) {
            button.disabled = true;
        }

        safeSetInnerHTML(button, `
            <span class="context-menu-icon">${item.icon}</span>
            <span>${item.label}</span>
        `);

        button.addEventListener("click", (e) => {
            e.stopPropagation();
            if (enabled) {
                item.command(editor);
                hideTableContextMenu();
            }
        });

        contentEl.appendChild(button);
    });

    menuEl.classList.remove("hidden");
    menuEl.style.left = `${x}px`;
    menuEl.style.top = `${y}px`;

    requestAnimationFrame(() => {
        const rect = menuEl.getBoundingClientRect();
        if (rect.right > window.innerWidth) {
            menuEl.style.left = `${x - rect.width}px`;
        }
        if (rect.bottom > window.innerHeight) {
            menuEl.style.top = `${y - rect.height}px`;
        }
    });
}

export function bindTableContextMenu(editor) {
    const editorElement = document.querySelector("#editor .ProseMirror");
    if (!editorElement) return;

    editorElement.addEventListener("contextmenu", (event) => {
        const target = event.target.closest("td, th");
        if (!target) return;

        if (!editor.isEditable) return;

        event.preventDefault();
        event.stopPropagation();

        try {
            const pos = editor.view.posAtDOM(target, 0);
            editor.chain().focus().setTextSelection(pos).run();
        } catch (error) {
            console.error("셀 포커스 설정 오류:", error);
        }

        showTableContextMenu(event.clientX, event.clientY, editor);
    });

    document.addEventListener("click", () => {
        hideTableContextMenu();
    });
}

async function handlePaddingChange(paddingValue) {
    const state = window.appState;
    if (!state || !state.currentPageId) return;

    const editorEl = document.querySelector('.editor');
    const padding = paddingValue === 'default' ? null : parseInt(paddingValue);

    if (editorEl) {
        const isMobile = window.innerWidth <= 900;
        if (padding === null || isMobile) {
            editorEl.style.paddingLeft = '';
            editorEl.style.paddingRight = '';
        } else {
            editorEl.style.paddingLeft = `${padding}px`;
            editorEl.style.paddingRight = `${padding}px`;
        }
    }

    syncPageUpdatedAtPadding();

    try {
        const res = await secureFetch(`/api/pages/${state.currentPageId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ horizontalPadding: padding })
        });

        if (!res.ok) throw new Error('여백 저장 실패');

        const page = state.pages.find(p => p.id === state.currentPageId);
        if (page) page.horizontalPadding = padding;

        console.log('여백 저장 완료:', padding === null ? '기본값' : `${padding}px`);
    } catch (error) {
        console.error('여백 저장 오류:', error);
        alert('여백 설정을 저장하는데 실패했습니다.');
    }
}

function updatePaddingMenuState() {
    const state = window.appState;
    if (!state || !state.currentPageId) return;

    const page = state.pages.find(p => p.id === state.currentPageId);
    const currentPadding = page?.horizontalPadding;

    document.querySelectorAll('.padding-option').forEach(option => {
        option.classList.remove('active');
    });

    if (currentPadding === null || currentPadding === undefined) {
        document.querySelector('.padding-option[data-padding="default"]')?.classList.add('active');
    } else {
        const matchingOption = document.querySelector(`.padding-option[data-padding="${currentPadding}"]`);
        if (matchingOption) {
            matchingOption.classList.add('active');
        }
    }
}
