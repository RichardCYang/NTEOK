/**
 * Tiptap File Block Node Extension
 * Notion 스타일의 파일 첨부 블록 (Placeholder & Upload)
 */

import { secureFetch } from './ui-utils.js';
import { sanitizeHttpHref } from './url-utils.js';

const Node = Tiptap.Core.Node;

export const FileBlock = Node.create({
    name: 'fileBlock',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            src: {
                default: null
            },
            filename: {
                default: null
            },
            size: {
                default: 0
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="file-block"]',
                getAttrs: (element) => {
                    return {
                        src: element.getAttribute('data-src'),
                        filename: element.getAttribute('data-filename'),
                        size: parseInt(element.getAttribute('data-size') || '0', 10)
                    };
                }
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        return [
            'div',
            {
                ...HTMLAttributes,
                'data-type': 'file-block',
                'data-src': node.attrs.src,
                'data-filename': node.attrs.filename,
                'data-size': node.attrs.size,
                'class': 'file-block-wrapper'
            }
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'file-block-wrapper';
            wrapper.contentEditable = 'false';

            // 파일 업로드 처리 함수
            const handleUpload = async (file) => {
                if (!file) return;

                if (file.size > 50 * 1024 * 1024) {
                    alert('파일 크기는 50MB 이하여야 합니다.');
                    return;
                }

                const placeholderText = wrapper.querySelector('.file-placeholder-text');
                if (placeholderText) placeholderText.textContent = '업로드 중...';

                try {
                    const pageId = window.appState?.currentPageId;
                    if (!pageId) throw new Error('페이지 ID 없음');

                    const formData = new FormData();
                    formData.append('file', file);

                    const response = await secureFetch(`/api/pages/${pageId}/file`, {
                        method: 'POST',
                        body: formData
                    });

                    if (!response.ok) {
                         const err = await response.json();
                         throw new Error(err.error || '업로드 실패');
                    }

                    const data = await response.json();

                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        const tr = editor.view.state.tr;
                        tr.setNodeMarkup(pos, null, {
                            src: data.url,
                            filename: data.filename,
                            size: data.size
                        });
                        editor.view.dispatch(tr);
                    }

                } catch (error) {
                    console.error('파일 업로드 오류:', error);
                    alert('업로드 실패: ' + error.message);
                    if (placeholderText) placeholderText.textContent = '업로드 실패. 다시 시도하세요.';
                }
            };

            const triggerFileUpload = () => {
                const input = document.createElement('input');
                input.type = 'file';

                input.onchange = (e) => {
                    const file = e.target.files[0];
                    handleUpload(file);
                };

                input.click();
            };

            // 드래그 앤 드롭 이벤트 설정 (데스크탑 환경 권장)
            const setupDragAndDrop = (target) => {
                // 터치 환경이 아닌 경우(데스크탑 등)에만 활성화하거나,
                // 일반적인 드래그 앤 드롭은 모바일에서 무시되므로 기본 적용 가능

                target.addEventListener('dragover', (e) => {
                    if (!editor.isEditable) return;
                    e.preventDefault();
                    e.stopPropagation();
                    target.classList.add('drag-over');
                });

                target.addEventListener('dragleave', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    target.classList.remove('drag-over');
                });

                target.addEventListener('drop', (e) => {
                    if (!editor.isEditable) return;
                    e.preventDefault();
                    e.stopPropagation();
                    target.classList.remove('drag-over');

                    const files = e.dataTransfer.files;
                    if (files && files.length > 0) {
                        handleUpload(files[0]);
                    }
                });
            };

            const render = () => {
                wrapper.innerHTML = '';

                // 무채색 클립 아이콘 SVG
                const clipIconSvg = `
                    <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"></path>
                    </svg>
                `;

                if (!node.attrs.src) {
                    // 1. Placeholder State (Embed Form Style)
                    const placeholder = document.createElement('div');
                    placeholder.className = 'file-placeholder';

                    const leftPart = document.createElement('div');
                    leftPart.className = 'file-placeholder-left';

                    const icon = document.createElement('span');
                    icon.className = 'file-placeholder-icon';
                    icon.innerHTML = clipIconSvg;

                    const text = document.createElement('span');
                    text.className = 'file-placeholder-text';
                    text.textContent = '파일을 추가하세요 (또는 드래그)';

                    leftPart.appendChild(icon);
                    leftPart.appendChild(text);

                    const rightPart = document.createElement('div');
                    rightPart.className = 'file-placeholder-right edit-only';

                    const uploadBtn = document.createElement('button');
                    uploadBtn.className = 'file-upload-btn';
                    uploadBtn.innerHTML = '&#43;'; // Plus sign (+)
                    uploadBtn.title = '파일 업로드';

                    uploadBtn.onclick = (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        triggerFileUpload();
                    };

                    placeholder.onclick = (e) => {
                         if (editor.isEditable) triggerFileUpload();
                    };

                    // 데스크탑 환경을 위한 드래그 앤 드롭 설정
                    setupDragAndDrop(placeholder);

                    rightPart.appendChild(uploadBtn);

                    placeholder.appendChild(leftPart);
                    placeholder.appendChild(rightPart);
                    wrapper.appendChild(placeholder);

                } else {
                    // 2. Filled State (File Card Style)
                    const container = document.createElement('div');
                    container.className = 'file-block';

                    const content = document.createElement('div');
                    content.className = 'file-block-content';

                    const icon = document.createElement('span');
                    icon.className = 'file-icon';
                    icon.innerHTML = clipIconSvg;

                    const info = document.createElement('div');
                    info.className = 'file-info';

                    const name = document.createElement('div');
                    name.className = 'file-name';
                    name.textContent = node.attrs.filename || 'Unknown File';

                    const size = document.createElement('div');
                    size.className = 'file-size';
                    size.textContent = formatBytes(node.attrs.size);

                    info.appendChild(name);
                    info.appendChild(size);

                    content.appendChild(icon);
                    content.appendChild(info);
                    container.appendChild(content);

                    const rightPart = document.createElement('div');
                    rightPart.className = 'file-block-right edit-only';

                    const deleteBtn = document.createElement('button');
                    deleteBtn.className = 'file-delete-btn';
                    deleteBtn.innerHTML = '&times;';
                    deleteBtn.title = '파일 삭제';

                    deleteBtn.onclick = async (e) => {
                        e.preventDefault();
                        e.stopPropagation();

                        const fileUrl = node.attrs.src;
                        if (!fileUrl) return;

                        if (confirm('첨부된 파일을 삭제하시겠습니까? (다른 곳에서 사용 중이지 않다면 서버에서도 영구 삭제됩니다)')) {
                            try {
                                const pageId = window.appState?.currentPageId;
                                if (!pageId) throw new Error('페이지 ID 없음');

                                // 서버에 파일 정리 요청
                                await secureFetch(`/api/pages/${pageId}/file-cleanup`, {
                                    method: 'DELETE',
                                    headers: { 'Content-Type': 'application/json' },
                                    body: JSON.stringify({ fileUrl })
                                });

                                // 에디터 노드 속성 초기화
                                if (typeof getPos === 'function') {
                                    const pos = getPos();
                                    const tr = editor.view.state.tr;
                                    tr.setNodeMarkup(pos, null, {
                                        src: null,
                                        filename: null,
                                        size: 0
                                    });
                                    editor.view.dispatch(tr);
                                }
                            } catch (error) {
                                console.error('파일 삭제 처리 오류:', error);
                                alert('파일 삭제 처리 중 오류가 발생했습니다.');
                            }
                        }
                    };

                    rightPart.appendChild(deleteBtn);
                    container.appendChild(rightPart);

                    container.onclick = (e) => {
                        if (e.target.closest('.file-delete-btn')) return;
                        e.preventDefault();

						if (node.attrs.src) {
							// allowRelative=true로 내부 경로 허용, addHttpsIfMissing=false로 스킴 자동추가 방지
							const safe = sanitizeHttpHref(node.attrs.src, {
							    allowRelative: true,
							    addHttpsIfMissing: false
							});

							// file-block는 내부 첨부만 허용
							if (safe && safe.startsWith('/paperclip/')) {
							    window.open(safe, '_blank', 'noopener,noreferrer');
							} else {
							    console.warn('[Blocked unsafe file src]', node.attrs.src);
							}
						}
                    };

                    // 이미 파일이 있는 경우에도 드래그 앤 드롭으로 교체 가능하게 설정
                    setupDragAndDrop(container);

                    wrapper.appendChild(container);
                }
            };

            render();

            return {
                dom: wrapper,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) return false;
                    if (updatedNode.attrs.src !== node.attrs.src ||
                        updatedNode.attrs.filename !== node.attrs.filename ||
                        updatedNode.attrs.size !== node.attrs.size) {
                        node = updatedNode;
                        render();
                    }
                    return true;
                }
            };
        };
    },

    addCommands() {
        return {
            setFileBlock: (options) => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        src: options?.src || null,
                        filename: options?.filename || null,
                        size: options?.size || 0
                    }
                });
            }
        };
    }
});

/**
 * 파일 크기 포맷팅 유틸리티
 */
function formatBytes(bytes, decimals = 1) {
    if (bytes === 0) return '0 B';

    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];

    const i = Math.floor(Math.log(bytes) / Math.log(k));

    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}