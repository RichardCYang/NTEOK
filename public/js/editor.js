// 예제 콘텐츠
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
    <div data-type="bookmark-container" data-title="유용한 링크" data-icon="🔖">
        <div data-type="bookmark-block" data-url="https://github.com/nteok" data-title="NTEOK GitHub" data-description="프로젝트 소스 코드를 확인하세요." data-thumbnail=""></div>
    </div>

    <p>이 외에도 <strong>보드 뷰</strong>, <strong>이미지</strong>, <strong>YouTube</strong> 등 다양한 블록을 활용해 보세요!</p>
`;

/**
 * Tiptap 에디터 모듈
 * 에디터 초기화, 툴바, 슬래시 명령 등을 관리
 */

// UI Utils import
import { secureFetch, syncPageUpdatedAtPadding } from './ui-utils.js';

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

// ImageWithCaption 노드 import
import { ImageWithCaption } from './image-with-caption-node.js';

// BookmarkBlock 노드 import
import { BookmarkBlock, BookmarkContainerBlock } from './bookmark-node.js';

// CalloutBlock 노드 import
import { CalloutBlock } from './callout-node.js';

// ToggleBlock 노드 import
import { ToggleBlock } from './toggle-node.js';

// BoardBlock 노드 import
import { BoardBlock } from './board-node.js';

// YoutubeBlock 노드 import
import { YoutubeBlock } from './youtube-node.js';

// FileBlock 노드 import
import { FileBlock } from './file-node.js';

// DragHandle extension import
import { DragHandle } from './drag-handle-extension.js';

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
        id: "toggleList",
        label: "토글 목록",
        description: "내용을 접고 펼칠 수 있는 목록",
        icon: "▶",
        command(editor) {
            editor.chain().focus().setToggleBlock().run();
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
    },
    {
        id: "image",
        label: "이미지",
        description: "이미지 파일 업로드",
        icon: "🖼",
        command(editor) {
            // 파일 선택 다이얼로그 생성
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'image/jpeg,image/jpg,image/png,image/gif,image/webp';

            input.onchange = async (e) => {
                const file = e.target.files[0];
                if (!file) return;

                // 파일 크기 체크 (5MB)
                if (file.size > 5 * 1024 * 1024) {
                    alert('이미지 파일 크기는 5MB 이하여야 합니다.');
                    return;
                }

                // 이미지 타입 체크
                if (!file.type.match(/^image\/(jpeg|jpg|png|gif|webp)$/)) {
                    alert('jpg, png, gif, webp 형식의 이미지만 업로드 가능합니다.');
                    return;
                }

                try {
                    // 페이지 ID 가져오기
                    const pageId = window.appState?.currentPageId;
                    if (!pageId) {
                        alert('페이지 ID를 찾을 수 없습니다.');
                        return;
                    }

                    // FormData 생성
                    const formData = new FormData();
                    formData.append('image', file);

                    // 서버에 업로드 (secureFetch 사용)
                    const response = await secureFetch(`/api/pages/${pageId}/editor-image`, {
                        method: 'POST',
                        body: formData
                    });

                    if (!response.ok) {
                        throw new Error('이미지 업로드 실패');
                    }

                    const data = await response.json();

                    // 에디터에 이미지 삽입
                    editor.chain().focus().setImageWithCaption({
                        src: data.url,
                        alt: file.name,
                        caption: ''
                    }).run();

                } catch (error) {
                    console.error('이미지 업로드 오류:', error);
                    alert('이미지 업로드에 실패했습니다.');
                }
            };

            input.click();
        }
    },
    {
        id: "file",
        label: "파일",
        description: "파일 첨부 (50MB 제한)",
        icon: "📎",
        command(editor) {
            // 빈 파일 블록 삽입 (Placeholder 상태로 렌더링됨)
            editor.chain().focus().setFileBlock().run();
        }
    },
    {
        id: "bookmark",
        label: "북마크",
        description: "웹 페이지 링크 카드들",
        icon: "🔖",
        command(editor) {
            editor.chain().focus().setBookmarkContainer().run();
        }
    },
    {
        id: "callout",
        label: "콜아웃",
        description: "정보, 경고, 에러, 성공 메시지 블록",
        icon: "ℹ️",
        command(editor) {
            editor.chain().focus().setCallout('info', '').run();
        }
    },
    {
        id: "board",
        label: "보드 뷰",
        description: "칸반 보드 (할 일 관리)",
        icon: "📋",
        command(editor) {
            editor.chain().focus().setBoardBlock().run();
        }
    },
    {
        id: "youtube",
        label: "YouTube",
        description: "YouTube 동영상 임베드",
        icon: "▶",
        command(editor) {
            const url = window.prompt("YouTube 동영상 URL을 입력하세요:");
            if (!url) return;

            // YouTube ID 추출 정규식
            const regExp = /^.*(youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=|&v=)([^#&?]*).*/;
            const match = url.match(regExp);

            if (match && match[2].length === 11) {
                const embedUrl = `https://www.youtube.com/embed/${match[2]}`;
                editor.chain().focus().setYoutubeBlock({ src: embedUrl }).run();
            } else {
                alert("올바른 YouTube URL이 아닙니다.");
            }
        }
    }
];

// 테이블 컨텍스트 메뉴 항목들
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

/**
 * 안전하게 행 삭제 (최소 1행 유지)
 */
function deleteRowSafe(editor) {
    const { state } = editor.view;

    // 테이블의 전체 행 수 확인
    let rowCount = 0;
    let tableNode = null;

    state.doc.descendants((node, pos) => {
        if (node.type.name === "table") {
            // 현재 선택된 위치가 이 테이블 안에 있는지 확인
            const $anchor = state.selection.$anchor;
            if ($anchor.pos >= pos && $anchor.pos <= pos + node.nodeSize) {
                tableNode = node;
                rowCount = node.childCount;
                return false; // 테이블을 찾았으므로 더 이상 순회하지 않음
            }
        }
    });

    // 마지막 행인 경우 삭제 방지
    if (rowCount <= 1) {
        alert("표에는 최소 1개의 행이 있어야 합니다.");
        return false;
    }

    return editor.chain().focus().deleteRow().run();
}

/**
 * 안전하게 열 삭제 (최소 1열 유지)
 */
function deleteColumnSafe(editor) {
    const { state } = editor.view;

    // 테이블의 전체 열 수 확인
    let colCount = 0;

    state.doc.descendants((node, pos) => {
        if (node.type.name === "table") {
            // 현재 선택된 위치가 이 테이블 안에 있는지 확인
            const $anchor = state.selection.$anchor;
            if ($anchor.pos >= pos && $anchor.pos <= pos + node.nodeSize) {
                const firstRow = node.firstChild;
                if (firstRow) {
                    colCount = firstRow.childCount;
                }
                return false; // 테이블을 찾았으므로 더 이상 순회하지 않음
            }
        }
    });

    // 마지막 열인 경우 삭제 방지
    if (colCount <= 1) {
        alert("표에는 최소 1개의 열이 있어야 합니다.");
        return false;
    }

    return editor.chain().focus().deleteColumn().run();
}

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

// 테이블 키보드 단축키 확장
const TableKeyboardShortcuts = Extension.create({
    name: "tableKeyboardShortcuts",
    addKeyboardShortcuts() {
        return {
            // Ctrl+Shift+↑: 위에 행 추가
            "Mod-Shift-ArrowUp": ({ editor }) => {
                if (editor.isActive("table") && editor.can().addRowBefore()) {
                    return editor.chain().focus().addRowBefore().run();
                }
                return false;
            },
            // Ctrl+Shift+↓: 아래에 행 추가
            "Mod-Shift-ArrowDown": ({ editor }) => {
                if (editor.isActive("table") && editor.can().addRowAfter()) {
                    return editor.chain().focus().addRowAfter().run();
                }
                return false;
            },
            // Ctrl+Shift+←: 왼쪽에 열 추가
            "Mod-Shift-ArrowLeft": ({ editor }) => {
                if (editor.isActive("table") && editor.can().addColumnBefore()) {
                    return editor.chain().focus().addColumnBefore().run();
                }
                return false;
            },
            // Ctrl+Shift+→: 오른쪽에 열 추가
            "Mod-Shift-ArrowRight": ({ editor }) => {
                if (editor.isActive("table") && editor.can().addColumnAfter()) {
                    return editor.chain().focus().addColumnAfter().run();
                }
                return false;
            },
            // Ctrl+Backspace: 행 삭제
            "Mod-Backspace": ({ editor }) => {
                if (editor.isActive("table") && editor.can().deleteRow()) {
                    return deleteRowSafe(editor);
                }
                return false;
            },
            // Ctrl+Shift+Backspace: 열 삭제
            "Mod-Shift-Backspace": ({ editor }) => {
                if (editor.isActive("table") && editor.can().deleteColumn()) {
                    return deleteColumnSafe(editor);
                }
                return false;
            }
        };
    }
});

// 슬래시 메뉴 상태
let slashMenuEl = null;
let slashActiveIndex = 0;
let slashState = {
    active: false,
    ready: false,
    fromPos: null,
    filterText: '',
    filteredItems: []
};

// 일부 브라우저/IME 조합에서는 ProseMirror의 view.composing 플래그가
// compositionupdate 타이밍에 false로 유지되는 경우가 있어(특히 Windows + 일부 Chromium 계열)
// slash 필터 텍스트를 state.doc에서 읽으면 마지막에 스페이스(조합 확정)를 치기 전까지
// 검색어가 갱신되지 않는 현상이 발생할 수 있음 -> composition 이벤트로 IME 조합 상태를 직접 트래킹해서, 필요 시 DOM 기준으로 검색어를 추출
let slashImeComposing = false;

/**
 * 현재 pos가 속한 가장 가까운 textblock(문단/제목/테이블 셀 내 문단 등)의 시작 포지션을 반환
 * - slash 명령은 "같은 textblock 안"에서만 유효해야 하므로 context 검증에 사용
 */
function getNearestTextblockStart(doc, pos) {
    const $pos = doc.resolve(pos);
    for (let d = $pos.depth; d > 0; d--) {
        const node = $pos.node(d);
        if (node && node.isTextblock)
            return $pos.start(d);
    }
    return null;
}

/**
 * slash 메뉴가 계속 열려있어야 하는 컨텍스트인지 검증
 * - 슬래시가 실제로 존재해야 함
 * - 커서는 슬래시 뒤에 있어야 함
 * - 커서/슬래시가 같은 textblock에 있어야 함
 * - 범위 선택(드래그 선택 등) 상태면 닫음
 */
function isSlashContextValid(editor) {
    if (!slashState.active || typeof slashState.fromPos !== 'number') return false;

    const { doc, selection } = editor.state;
    if (!selection.empty) return false;

    // 커서가 슬래시 앞(또는 동일 위치)으로 이동하면 더 이상 slash 명령 컨텍스트가 아님
    if (selection.from < slashState.fromPos + 1) return false;

    // 동일 textblock 안에서만 유효
    const selBlockStart = getNearestTextblockStart(doc, selection.from);
    const slashBlockStart = getNearestTextblockStart(doc, slashState.fromPos);
    if (selBlockStart == null || slashBlockStart == null || selBlockStart !== slashBlockStart)
        return false;

    // fromPos 위치의 문자가 정말 "/"인지 확인
    try {
        const char = doc.textBetween(slashState.fromPos, slashState.fromPos + 1);
        if (char !== '/') return false;
    } catch {
        return false;
    }

    return true;
}

/**
 * slash 메뉴 상태를 에디터 상태(doc/selection)에 맞게 동기화
 * - keydown에서 열린 직후에는 doc에 '/'가 아직 없을 수 있으므로(ready=false) 그 전엔 닫지 않음
 * - '/'가 실제로 doc에 들어온 이후(ready=true)부터는 엄격하게 컨텍스트 검증
 */
function syncSlashMenu(editor, opts = {}) {
    if (!slashState.active || slashState.fromPos === null) return;

    const { doc, selection } = editor.state;
	const composing = !!(slashImeComposing || editor?.view?.composing);
	const forceDom = !!opts.forceDom;

    // 범위 선택이면 slash 컨텍스트가 아님
	// IME(한글/일본어/중국어 등) 조합 중에는 ProseMirror 상태(selection/doc)가
	// 실제 화면(DOM)과 잠시 불일치할 수 있어, 이 타이밍에 닫아버리면
	// 초성만 남고 입력이 끊기는 현상이 생길 수 있음.
	// keydown에서 메뉴를 연 직후에는 아직 '/'가 doc에 반영되기 전 프레임이 있을 수 있음.
	// (특히 input 이벤트가 먼저 들어오면 selection.from이 fromPos와 같아져서 즉시 닫히는 버그 발생)
	// => '/'가 실제로 doc에 들어온 이후(ready=true)부터만 엄격하게 닫기 조건을 적용한다. (slashState.ready 조건 추가)
    if (slashState.ready && !selection.empty && !composing) {
        closeSlashMenu();
        return;
    }

    // 커서가 '/' 이전(또는 같은 위치)으로 오면 닫기
    if (slashState.ready && !composing && selection.from <= slashState.fromPos) {
        closeSlashMenu();
        return;
    }

    // keydown 직후 첫 업데이트에서 '/'가 실제로 삽입되었는지 확인 -> ready 전환
    try {
        const ch = doc.textBetween(slashState.fromPos, slashState.fromPos + 1);
        if (ch === "/") {
            slashState.ready = true;
        } else {
            // 아직 '/'가 doc에 없으면(삽입 전 프레임) 닫지 말고 대기
            if (!slashState.ready) return;
            // ready인데 '/'가 아니라면(삭제/치환됨) 닫기
            closeSlashMenu();
            return;
        }
    } catch (e) {
        closeSlashMenu();
        return;
    }

    // 필터 텍스트/목록 업데이트
    const text = getSlashCommandText(editor, { forceDom });
    if (text === slashState.filterText) return;
    slashState.filterText = text;
    slashState.filteredItems = filterSlashItems(text);
    renderSlashMenuItems();
}

/**
 * 슬래시 메뉴 필터링 함수
 */
function filterSlashItems(filterText) {
	const normalized = (filterText || '').trim().toLowerCase();
	if (!normalized) return SLASH_ITEMS;

    return SLASH_ITEMS.filter(item =>
		item.label.toLowerCase().includes(normalized) ||
		item.description.toLowerCase().includes(normalized)
    );
}

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

/**
 * 슬래시 메뉴 항목 렌더링
 */
function renderSlashMenuItems() {
    if (!slashMenuEl) return;

    const listEl = slashMenuEl.querySelector("#slash-menu-list");
    if (!listEl) return;

    // 기존 항목 제거
    listEl.innerHTML = "";

    // 필터 텍스트가 있으면 검색 결과 표시
    const displayFilter = (slashState.filterText || '').trim();
    if (displayFilter) {
        const filterInfo = document.createElement("li");
        filterInfo.className = "slash-menu-filter-info";
        filterInfo.innerHTML = `검색: <strong>${escapeHtml(displayFilter)}</strong>`;
        filterInfo.style.padding = "8px 16px";
        filterInfo.style.fontSize = "12px";
        filterInfo.style.color = "#999";
        filterInfo.style.borderBottom = "1px solid #eee";
        listEl.appendChild(filterInfo);
    }

    // 필터링된 항목 렌더링
    if (slashState.filteredItems.length === 0) {
        const noResults = document.createElement("li");
        noResults.className = "slash-menu-no-results";
        noResults.innerHTML = '검색 결과가 없습니다';
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

            li.innerHTML = `
                <div class="slash-menu-item-icon">${item.icon}</div>
                <div class="slash-menu-item-main">
                    <div class="slash-menu-item-label">${item.label}</div>
                    <div class="slash-menu-item-desc">${item.description}</div>
                </div>
            `;

            listEl.appendChild(li);
        });
    }

    slashActiveIndex = 0;
}

/**
 * HTML 이스케이프 함수
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

/**
 * 슬래시 메뉴 열기
 */
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

    // 메뉴 항목 렌더링
    renderSlashMenuItems();

    // 임시로 메뉴를 보여서 실제 높이를 계산
    slashMenuEl.classList.remove("hidden");
    slashMenuEl.style.visibility = "hidden"; // 화면에 나타나지 않게 함
    slashMenuEl.style.left = `${coords.left}px`;
    slashMenuEl.style.top = `${coords.bottom + 4}px`;

    // 다음 프레임에서 높이를 계산하고 위치 조정
    requestAnimationFrame(() => {
        const menuHeight = slashMenuEl.offsetHeight;
        const windowHeight = window.innerHeight;
        let top = coords.bottom + 4;

        // 메뉴가 화면 아래로 나갈 경우, 커서 위쪽에 표시
        if (top + menuHeight > windowHeight) {
            top = coords.top - menuHeight - 4;
            // 메뉴가 화면 위로 나가지 않도록 조정
            if (top < 0) {
                top = coords.bottom + 4;
            }
        }

        slashMenuEl.style.top = `${top}px`;
        slashMenuEl.style.visibility = "visible"; // 계산 후 표시
    });
}

/**
 * 슬래시 메뉴 닫기
 */
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
		// 열기(open)에서 visibility를 쓰기 때문에 닫을 때도 명시적으로 숨김
		slashMenuEl.style.visibility = "hidden";
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
        // "/" 부터 현재 커서까지의 텍스트 모두 삭제
        const selection = editor.state.selection;
        editor
            .chain()
            .focus()
            .deleteRange({
                from: slashState.fromPos,
                to: selection.from
            })
            .run();

        // [버그 수정] deleteRange 실행 후 빈 문단이 제거되어 바로 아래의 블록(표, 콜아웃 등)이 
        // NodeSelection 상태로 선택되는 현상 방지.
        // 이 상태에서 명령을 실행하면 아래 블록이 교체되어 사라지므로, 
        // 강제로 빈 문단을 삽입하여 새 블록이 해당 위치에 추가되도록 함.
        if (editor.state.selection.node) {
            editor.chain().insertContentAt(editor.state.selection.from, "<p></p>").focus(editor.state.selection.from).run();
        }
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
 * 슬래시 메뉴 텍스트 추출 (fromPos부터 현재 커서까지)
 */
function getSlashCommandText(editor, opts = {}) {
    if (!slashState.active || slashState.fromPos === null) return '';

    const view = editor?.view;
    const from = slashState.fromPos + 1; // "/" 다음 위치부터
    const forceDom = !!opts.forceDom;

    // IME 조합 중에는 state.doc/state.selection이 즉시 반영되지 않아
    // textBetween 결과가 "ㄱ" 처럼 초성만 나오거나 아예 갱신이 멈출 수 있음.
    // 이때는 DOM selection 기준으로 범위를 잘라 실제 화면에 보이는 텍스트를 사용.
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

/**
 * 슬래시 명령 키보드 바인딩
 */
export function bindSlashKeyHandlers(editor) {
    document.addEventListener("keydown", (event) => {
        if (!editor) return;

        // IME 조합(한글/일본어/중국어 등) 중에는 Enter/Arrow 등이
        // 조합 확정/후보 선택에 쓰일 수 있으므로 slash 메뉴 단축키로 가로채면
        // 조합이 깨져 초성만 남고 입력이 멈추는 현상이 발생할 수 있음.
		const imeComp = (typeof slashImeComposing !== 'undefined') && slashImeComposing;
		const composing = !!(imeComp || event.isComposing || editor?.view?.composing || event.key === 'Process' || event.keyCode === 229);

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
			// IME 조합 중엔 메뉴 내 키바인딩을 적용하지 않고, 입력 자체를 우선.
			// (필터링은 composition 이벤트에서 DOM 기준으로 동기화)
			if (composing)
			    return;

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

            // '/' 자체가 삭제되는 케이스면 즉시 닫기 (onUpdate 타이밍 꼬임 방지)
            if ((event.key === "Backspace" || event.key === "Delete") && slashState.fromPos !== null) {
                const sel = editor.state.selection;
                if (!sel.empty) {
                    // 선택 범위가 '/'를 포함하면 닫기
                    if (sel.from <= slashState.fromPos && sel.to >= slashState.fromPos + 1) {
                        closeSlashMenu();
                    }
                    return;
                }
                // 커서가 '/' 바로 뒤에서 Backspace -> '/' 삭제
                if (event.key === "Backspace" && sel.from === slashState.fromPos + 1) {
                    closeSlashMenu();
                    return;
                }
                // 커서가 '/' 바로 앞에서 Delete -> '/' 삭제
                if (event.key === "Delete" && sel.from === slashState.fromPos) {
                    closeSlashMenu();
                    return;
                }
            }

            // "/" 다음 문자가 입력/삭제되면 메뉴 필터링 업데이트
            // 실제 입력은 에디터의 기본 동작에 맡기고,
            // 다음 업데이트에서 필터링 적용
            if (event.key === "Backspace" || (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey)) {
                // 기본 동작 허용 (preventDefault 하지 않음)
                // onUpdate에서 필터링 처리
                return;
            }
        }
    });

    // IME 조합 중에는 editor.onUpdate가 즉시 호출되지 않는 경우가 있어
    // composition/input 이벤트에서 필터 텍스트를 DOM 기준으로 동기화한다.
    // (bindSlashKeyHandlers가 여러 번 호출될 수 있으므로 한 번만 바인딩)
    if (!bindSlashKeyHandlers.__imeBound && editor?.view?.dom) {
        bindSlashKeyHandlers.__imeBound = true;
        const dom = editor.view.dom;
        const syncDom = () => {
            if (slashState.active) syncSlashMenu(editor, { forceDom: true });
        };
        const onCompStart = () => {
            slashImeComposing = true;
            syncDom();
        };
        const onCompEnd = () => {
            slashImeComposing = false;
            // 조합 확정 후에는 state.doc에도 반영되므로 일반 동기화로 정리
            if (slashState.active) syncSlashMenu(editor);
        };

        dom.addEventListener('compositionstart', onCompStart);
        dom.addEventListener('compositionupdate', syncDom);
        dom.addEventListener('compositionend', onCompEnd);
        // 일부 환경에서는 compositionupdate만으로는 즉시 반영이 안 되는 경우가 있어 input도 보조로 사용
        dom.addEventListener('input', () => {
            if (!slashState.active) return;
            // input이 ProseMirror transaction 반영보다 먼저 들어오는 환경이 있어서 1프레임 지연
            requestAnimationFrame(() => {
                if (!slashState.active) return;
                if (slashImeComposing) syncSlashMenu(editor, { forceDom: true });
                else syncSlashMenu(editor);
            });
        });
    }

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
            BookmarkContainerBlock,
            BookmarkBlock,
            CalloutBlock,
            ToggleBlock,
            BoardBlock,
            YoutubeBlock,
            FileBlock,
            DragHandle,
        ],
        content: EXAMPLE_CONTENT,
        onSelectionUpdate() {
            updateToolbarState(editor);
            // 문서 변경 없이 커서만 이동해도(←/→ 클릭 이동) 메뉴 컨텍스트가 깨지면 닫혀야 함
            if (slashState.active)
            	syncSlashMenu(editor);
        },
        onTransaction({ transaction }) {
            updateToolbarState(editor);

            // 크기 조절 중이 아닐 때만 핸들 재생성
            if (!isResizingTable) {
                setTimeout(() => addTableResizeHandles(editor), 50);
            }

            // doc이 바뀌면 fromPos가 틀어질 수 있어 mapping 보정(삽입 경계 왼쪽에 붙도록 assoc=-1)
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
            // 에디터 생성 시 핸들 추가
            setTimeout(() => addTableResizeHandles(editor), 50);
        },
        onUpdate() {
            // 내용 업데이트 시 핸들 재생성
            setTimeout(() => addTableResizeHandles(editor), 50);

			// 슬래시 메뉴 동기화(삭제/이동/필터 등)
			if (slashState.active)
				syncSlashMenu(editor);
        }
    });

    // 테이블 컨텍스트 메뉴 바인딩
    bindTableContextMenu(editor);

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

    let paddingDropdownElement = toolbar.querySelector("[data-role='padding-dropdown']");
    let paddingMenuElement = paddingDropdownElement
        ? paddingDropdownElement.querySelector("[data-padding-menu]")
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

    // 보드 카드 포커스 추적을 위한 변수
    let lastFocusedBoardCard = null;

    // 툴바 버튼 클릭 시 포커스 해제 방지
    toolbar.addEventListener("mousedown", (event) => {
        const button = event.target.closest("button[data-command]");
        if (button) {
            // 보드 카드 내부 편집 중이라면 포커스 이동 방지
            const activeCard = document.activeElement.closest('.board-card-content');
            if (activeCard) {
                lastFocusedBoardCard = activeCard;
                event.preventDefault();
            }
        }
    });

    toolbar.addEventListener("click", (event) => {
        const button = event.target.closest("button[data-command]");
        if (!button || !editor) return;

        const command = button.getAttribute("data-command");
        const colorValue = button.getAttribute("data-color");
        const fontFamilyValue = button.getAttribute("data-font-family");

        // 보드 카드 내부 편집 중인지 확인 (현재 포커스 또는 마지막 포커스된 카드)
        const activeCard = document.activeElement.closest('.board-card-content') || lastFocusedBoardCard;
        
        // 보드 카드 내부가 아니면 추적 변수 초기화
        if (!document.activeElement.closest('.board-card-content')) {
            lastFocusedBoardCard = null;
        }

        if (activeCard && ['bold', 'italic', 'strike', 'setColor', 'setFont', 'unsetColor', 'h1', 'h2', 'h3', 'h4', 'h5'].includes(command)) {
            // 보드 카드 내부 편집 중이면 브라우저 기본 execCommand 사용
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
            
            // 드롭다운 닫기 처리
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

        // 여백 드롭다운 토글
        if (command === "togglePaddingDropdown") {
            if (!paddingMenuElement || !paddingDropdownElement) return;

            const isOpen = !paddingMenuElement.hasAttribute("hidden");

            if (isOpen) {
                paddingMenuElement.setAttribute("hidden", "");
                paddingDropdownElement.classList.remove("open");
            } else {
                // 버튼 위치 계산
                const buttonRect = button.getBoundingClientRect();
                paddingMenuElement.style.top = `${buttonRect.bottom + 4}px`;
                paddingMenuElement.style.left = `${buttonRect.left}px`;

                // 현재 여백 값 표시
                updatePaddingMenuState();

                paddingMenuElement.removeAttribute("hidden");
                paddingDropdownElement.classList.add("open");
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

        // 여백 설정
        if (command === "setPadding") {
            const paddingValue = button.getAttribute("data-padding");
            handlePaddingChange(paddingValue);

            if (paddingMenuElement && paddingDropdownElement) {
                paddingMenuElement.setAttribute("hidden", "");
                paddingDropdownElement.classList.remove("open");
            }
            return;
        }

        // 커스텀 여백 적용
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

window.addEventListener("resize", () => {
    syncPageUpdatedAtPadding();
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

/**
 * 테이블 컨텍스트 메뉴 숨기기
 */
function hideTableContextMenu() {
    const menuEl = document.getElementById("context-menu");
    if (menuEl) {
        menuEl.classList.add("hidden");
    }
}

/**
 * 테이블 컨텍스트 메뉴 표시
 */
function showTableContextMenu(x, y, editor) {
    const menuEl = document.getElementById("context-menu");
    const contentEl = document.getElementById("context-menu-content");

    if (!menuEl || !contentEl) {
        console.error("컨텍스트 메뉴 요소를 찾을 수 없습니다.");
        return;
    }

    // 메뉴 내용 생성
    contentEl.innerHTML = "";
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

        // 명령 실행 가능 여부 확인
        const enabled = item.isEnabled(editor);
        if (!enabled) {
            button.disabled = true;
        }

        button.innerHTML = `
            <span class="context-menu-icon">${item.icon}</span>
            <span>${item.label}</span>
        `;

        button.addEventListener("click", (e) => {
            e.stopPropagation();
            if (enabled) {
                item.command(editor);
                hideTableContextMenu();
            }
        });

        contentEl.appendChild(button);
    });

    // 위치 설정
    menuEl.classList.remove("hidden");
    menuEl.style.left = `${x}px`;
    menuEl.style.top = `${y}px`;

    // 다음 프레임에서 위치 조정 (화면 밖으로 나가지 않도록)
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

/**
 * 테이블 컨텍스트 메뉴 이벤트 바인딩
 */
export function bindTableContextMenu(editor) {
    const editorElement = document.querySelector("#editor .ProseMirror");
    if (!editorElement) return;

    // 우클릭 이벤트 리스너
    editorElement.addEventListener("contextmenu", (event) => {
        // 테이블 셀 클릭 여부 확인
        const target = event.target.closest("td, th");
        if (!target) return;

        // 읽기 모드에서는 메뉴 표시하지 않음
        if (!editor.isEditable) return;

        // 기본 컨텍스트 메뉴 방지
        event.preventDefault();
        event.stopPropagation();

        // 셀에 포커스 설정
        try {
            const pos = editor.view.posAtDOM(target, 0);
            editor.chain().focus().setTextSelection(pos).run();
        } catch (error) {
            console.error("셀 포커스 설정 오류:", error);
        }

        // 컨텍스트 메뉴 표시
        showTableContextMenu(event.clientX, event.clientY, editor);
    });

    // 다른 곳 클릭 시 메뉴 닫기
    document.addEventListener("click", () => {
        hideTableContextMenu();
    });
}

// 여백 변경 처리
async function handlePaddingChange(paddingValue) {
    const state = window.appState;
    if (!state || !state.currentPageId) return;

    const editorEl = document.querySelector('.editor');
    const padding = paddingValue === 'default' ? null : parseInt(paddingValue);

    // UI 즉시 업데이트 (모바일에서는 기본 CSS 사용)
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

    // 서버에 저장
    try {
        const csrfToken = window.csrfUtils?.getCsrfToken();
        const res = await fetch(`/api/pages/${state.currentPageId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'include',
            body: JSON.stringify({ horizontalPadding: padding })
        });

        if (!res.ok) throw new Error('여백 저장 실패');

        // 로컬 상태 업데이트
        const page = state.pages.find(p => p.id === state.currentPageId);
        if (page) page.horizontalPadding = padding;

        console.log('여백 저장 완료:', padding === null ? '기본값' : `${padding}px`);
    } catch (error) {
        console.error('여백 저장 오류:', error);
        alert('여백 설정을 저장하는데 실패했습니다.');
    }
}

// 메뉴 상태 업데이트
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
