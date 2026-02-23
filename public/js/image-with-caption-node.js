/**
 * Tiptap Image with Caption Node Extension
 * 캡션 기능이 있는 이미지 노드
 */

// 보안: 협업(WebSocket/Yjs) 업데이트는 서버 저장 전에 다른 클라이언트로 즉시 전파될 수 있으므로,
// NodeView에서 사용하는 URL(src)은 렌더링 시점에도 반드시 검증해야 함
import { sanitizeHttpHref } from './url-utils.js';

const Node = Tiptap.Core.Node;

function sanitizeImageSrc(raw) {
    if (typeof raw !== 'string') return null;
    const v = raw.trim();
    if (!v) return null;

    // protocol-relative URL(//evil.com) 차단
    if (v.startsWith('//')) return null;

    // data:, javascript:, file: 등 위험 스킴 차단 + 제어문자 차단
    const safe = sanitizeHttpHref(v, {
        allowRelative: true,
        addHttpsIfMissing: false,
        maxLen: 2048
    });

    if (!safe) return null;
    if (safe.startsWith('#')) return null; // 이미지에 fragment-only는 무의미

    // 절대 URL은 same-origin만 허용 (외부 오리진 차단)
    if (/^https?:/i.test(safe)) {
        try {
            const u = new URL(safe);
            if (u.origin !== window.location.origin) return null;
            return u.toString();
        } catch {
            return null;
        }
    }

    // 상대경로는 필요한 범위만 허용 (정책에 맞게 확장 가능)
    if (safe.startsWith('/')) {
        const ok =
            safe.startsWith('/imgs/') ||
            safe.startsWith('/covers/') ||
            safe.startsWith('/api/pages/proxy/image');
        return ok ? safe : null;
    }

    return null;
}

export const ImageWithCaption = Node.create({
    name: 'imageWithCaption',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            src: {
                default: null
            },
            alt: {
                default: ''
            },
            caption: {
                default: ''
            },
            width: {
                default: '100%'
            },
            align: {
                default: 'center'
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'figure[data-type="image-with-caption"]',
                getAttrs: (element) => {
                    // data-* 속성에서 먼저 읽기 (DB에서 로드한 경우)
                    const dataSrc = element.getAttribute('data-src');
                    const dataAlt = element.getAttribute('data-alt');
                    const dataCaption = element.getAttribute('data-caption');
                    const dataWidth = element.getAttribute('data-width');
                    const dataAlign = element.getAttribute('data-align');

                    if (dataSrc) {
                        const safeDataSrc = sanitizeImageSrc(dataSrc);
                        if (safeDataSrc) {
                            return {
                                src: safeDataSrc,
                                alt: dataAlt || '',
                                caption: dataCaption || '',
                                width: dataWidth || '100%',
                                align: dataAlign || 'center'
                            };
                        }
                    }

                    // DOM 구조에서 읽기 (NodeView에서 생성된 경우)
                    const img = element.querySelector('img');
                    const captionDiv = element.querySelector('.image-caption');
                    const captionInput = element.querySelector('.image-caption-input');

                    const safeImgSrc = sanitizeImageSrc(img?.getAttribute('src') || '');
                    return {
                        src: safeImgSrc,
                        alt: img?.getAttribute('alt') || '',
                        caption: captionDiv?.textContent || captionInput?.value || '',
                        width: element.style.width || '100%',
                        align: element.getAttribute('data-align') || 'center'
                    };
                }
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        const safeSrc = sanitizeImageSrc(node.attrs.src || '') || '';
        return [
            'figure',
            {
                ...HTMLAttributes,
                'data-type': 'image-with-caption',
                'data-src': safeSrc,
                'data-alt': node.attrs.alt || '',
                'data-caption': node.attrs.caption || '',
                'data-width': node.attrs.width || '100%',
                'data-align': node.attrs.align || 'center',
                'class': 'image-with-caption',
                'style': `width: ${node.attrs.width || '100%'};`
            },
            [
                'div',
                { 'class': 'image-container' },
                [
                    'img',
                    {
                        'src': safeSrc,
                        'alt': node.attrs.alt || '',
                        'class': 'caption-image'
                    }
                ]
            ],
            [
                'div',
                { 'class': 'image-caption-container' },
                [
                    'div',
                    { 'class': 'image-caption' },
                    node.attrs.caption || ''
                ]
            ]
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            // 전체 wrapper (figure)
            const figure = document.createElement('figure');
            figure.className = 'image-with-caption-wrapper';
            figure.contentEditable = 'false';
            figure.style.width = node.attrs.width || '100%';
            figure.setAttribute('data-align', node.attrs.align || 'center');

            let currentCaption = node.attrs.caption || '';
            let currentAlign = node.attrs.align || 'center';

            // 이미지 컨테이너 (resize handle 포함)
            const imageContainer = document.createElement('div');
            imageContainer.className = 'image-container';
            imageContainer.style.position = 'relative';

            // 정렬 메뉴 (쓰기모드에서만 표시)
            const alignMenu = document.createElement('div');
            alignMenu.className = 'image-align-menu';
            alignMenu.style.display = editor.isEditable ? 'flex' : 'none';

            // 정렬 아이콘 SVG 생성 함수
            const createAlignIcon = (align) => {
                const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.setAttribute('width', '16');
                svg.setAttribute('height', '16');
                svg.setAttribute('viewBox', '0 0 16 16');
                svg.setAttribute('fill', 'currentColor');

                if (align === 'left') {
                    // 왼쪽 정렬: 짧은 막대들이 왼쪽 정렬
                    svg.innerHTML = `
                        <rect x="2" y="3" width="12" height="2" rx="1"/>
                        <rect x="2" y="7" width="8" height="2" rx="1"/>
                        <rect x="2" y="11" width="10" height="2" rx="1"/>
                    `;
                } else if (align === 'center') {
                    // 가운데 정렬: 짧은 막대들이 가운데 정렬
                    svg.innerHTML = `
                        <rect x="2" y="3" width="12" height="2" rx="1"/>
                        <rect x="4" y="7" width="8" height="2" rx="1"/>
                        <rect x="3" y="11" width="10" height="2" rx="1"/>
                    `;
                } else if (align === 'right') {
                    // 오른쪽 정렬: 짧은 막대들이 오른쪽 정렬
                    svg.innerHTML = `
                        <rect x="2" y="3" width="12" height="2" rx="1"/>
                        <rect x="6" y="7" width="8" height="2" rx="1"/>
                        <rect x="4" y="11" width="10" height="2" rx="1"/>
                    `;
                }

                return svg;
            };

            // 정렬 버튼 생성 함수
            const createAlignButton = (align, title) => {
                const button = document.createElement('button');
                button.className = 'align-button';
                button.type = 'button';
                button.title = title;
                button.setAttribute('data-align', align);

                // SVG 아이콘 추가
                button.appendChild(createAlignIcon(align));

                if (currentAlign === align) {
                    button.classList.add('active');
                }

                button.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();

                    console.log('[ImageAlign] 정렬 버튼 클릭:', align);

                    currentAlign = align;
                    figure.setAttribute('data-align', align);

                    // 모든 버튼의 active 클래스 제거
                    alignMenu.querySelectorAll('.align-button').forEach(btn => {
                        btn.classList.remove('active');
                    });
                    // 현재 버튼에 active 클래스 추가
                    button.classList.add('active');

                    // 에디터에 저장
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        try {
                            const tr = editor.view.state.tr;
                            const currentNode = editor.view.state.doc.nodeAt(pos);

                            if (currentNode && currentNode.type.name === this.name) {
                                console.log('[ImageAlign] 현재 노드:', currentNode);
                                console.log('[ImageAlign] 새 정렬:', align);

                                tr.setNodeMarkup(pos, null, {
                                    src: currentNode.attrs.src,
                                    alt: currentNode.attrs.alt,
                                    caption: currentNode.attrs.caption,
                                    width: currentNode.attrs.width,
                                    align: align
                                });
                                editor.view.dispatch(tr);

                                console.log('[ImageAlign] 정렬 저장 완료');
                            }
                        } catch (error) {
                            console.error('[ImageWithCaption] 정렬 저장 실패:', error);
                        }
                    }
                });

                return button;
            };

            // 정렬 버튼 추가
            alignMenu.appendChild(createAlignButton('left', '왼쪽 정렬'));
            alignMenu.appendChild(createAlignButton('center', '가운데 정렬'));
            alignMenu.appendChild(createAlignButton('right', '오른쪽 정렬'));

            imageContainer.appendChild(alignMenu);

            // 이미지
            const img = document.createElement('img');
            img.src = sanitizeImageSrc(node.attrs.src || '') || '';
            img.alt = node.attrs.alt || '';
            img.className = 'caption-image';

            imageContainer.appendChild(img);

            // Resize handle (쓰기모드에서만 표시)
            const resizeHandle = document.createElement('div');
            resizeHandle.className = 'image-resize-handle';
            resizeHandle.style.display = editor.isEditable ? 'block' : 'none';
            imageContainer.appendChild(resizeHandle);

            // 캡션 컨테이너
            const captionContainer = document.createElement('div');
            captionContainer.className = 'image-caption-container';

            // 항상 input 사용 (readonly로 읽기/쓰기 모드 제어)
            const captionElement = document.createElement('input');
            captionElement.type = 'text';
            captionElement.className = 'image-caption-input';
            captionElement.placeholder = '캡션을 입력하세요...';
            captionElement.value = currentCaption;
            captionElement.readOnly = !editor.isEditable;

            let captionSaveTimeout = null;

            // 캡션 입력 이벤트
            captionElement.oninput = (e) => {
                e.stopPropagation();

                // 입력이 멈춘 후 500ms 후 자동 저장
                if (captionSaveTimeout) {
                    clearTimeout(captionSaveTimeout);
                }

                captionSaveTimeout = setTimeout(() => {
                    currentCaption = captionElement.value;

                    // 에디터에 자동 저장
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        try {
                            const tr = editor.view.state.tr;
                            const currentNode = editor.view.state.doc.nodeAt(pos);
                            
                            if (currentNode && currentNode.type.name === this.name) {
                                tr.setNodeMarkup(pos, null, {
                                    src: currentNode.attrs.src,
                                    alt: currentNode.attrs.alt,
                                    caption: currentCaption,
                                    width: figure.style.width || currentNode.attrs.width,
                                    align: currentAlign
                                });
                                editor.view.dispatch(tr);
                            }
                        } catch (error) {
                            console.error('[ImageWithCaption] 캡션 자동 저장 실패:', error);
                        }
                    }
                }, 500);
            };

            // 키보드 이벤트 전파 차단
            captionElement.onkeydown = (e) => {
                e.stopPropagation();

                if (e.key === 'Enter') {
                    e.preventDefault();
                    captionElement.blur();
                }
            };

            captionElement.onkeyup = (e) => {
                e.stopPropagation();
            };

            captionElement.onkeypress = (e) => {
                e.stopPropagation();
            };

            captionContainer.appendChild(captionElement);

            // 모두 조립
            figure.appendChild(imageContainer);
            figure.appendChild(captionContainer);

            // Resize 기능
            let isResizing = false;
            let startX = 0;
            let startWidth = 0;

            const onResizeStart = (e) => {
                e.preventDefault();
                e.stopPropagation();

                isResizing = true;
                startX = e.clientX;

                // 현재 width를 px로 가져오기
                const currentWidth = figure.offsetWidth;
                startWidth = currentWidth;

                document.addEventListener('mousemove', onResizeMove);
                document.addEventListener('mouseup', onResizeEnd);

                figure.style.userSelect = 'none';
            };

            const onResizeMove = (e) => {
                if (!isResizing) return;

                const deltaX = e.clientX - startX;
                let newWidth = startWidth + deltaX * 2; // 양쪽으로 확장되므로 2배

                // 실제 문서 작업 영역의 최대 너비 가져오기
                const editorElement = document.querySelector('#editor .ProseMirror');
                const maxWidth = editorElement ? editorElement.offsetWidth : 800;

                // 최소/최대 크기 제한
                const minWidth = 200;
                newWidth = Math.max(minWidth, Math.min(newWidth, maxWidth));

                // width 업데이트
                figure.style.width = `${newWidth}px`;
            };

            const onResizeEnd = () => {
                if (!isResizing) return;

                isResizing = false;
                document.removeEventListener('mousemove', onResizeMove);
                document.removeEventListener('mouseup', onResizeEnd);

                figure.style.userSelect = '';

                // 최종 width를 노드 속성에 저장
                const finalWidth = figure.style.width;

                if (typeof getPos === 'function') {
                    const pos = getPos();
                    try {
                        const tr = editor.view.state.tr;
                        const currentNode = tr.doc.nodeAt(pos);
                        
                        if (currentNode && currentNode.type.name === this.name) {
                            tr.setNodeMarkup(pos, null, {
                                src: currentNode.attrs.src,
                                alt: currentNode.attrs.alt,
                                caption: currentNode.attrs.caption,
                                width: finalWidth,
                                align: currentAlign
                            });
                            editor.view.dispatch(tr);
                        }
                    } catch (error) {
                        console.error('[ImageWithCaption] width 저장 실패:', error);
                    }
                }
            };

            resizeHandle.addEventListener('mousedown', onResizeStart);

            // 에디터 상태 변경 감지 (editable 변경 시 readOnly 업데이트)
            let lastEditableState = editor.isEditable;

            const updateReadOnly = () => {
                const currentEditableState = editor.isEditable;
                if (currentEditableState !== lastEditableState) {
                    lastEditableState = currentEditableState;
                    captionElement.readOnly = !currentEditableState;
                    resizeHandle.style.display = currentEditableState ? 'block' : 'none';
                    alignMenu.style.display = currentEditableState ? 'flex' : 'none';
                }
            };

            // 주기적으로 에디터 상태 체크 (100ms)
            const stateCheckInterval = setInterval(updateReadOnly, 100);

            return {
                dom: figure,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) {
                        return false;
                    }

                    // 이미지 src가 변경되었으면 업데이트 (상대 경로 vs 절대 경로 고려)
                    const normalizeUrl = (url) => {
                        try { return new URL(url, window.location.origin).href; }
                        catch { return url; }
                    };

                    const updatedSafe = sanitizeImageSrc(updatedNode.attrs.src || '') || '';
                    const updatedSrc = normalizeUrl(updatedSafe);
                    const currentSrc = normalizeUrl(img.src);

                    if (updatedSrc !== currentSrc) {
                        img.src = updatedSafe;
                        img.alt = updatedNode.attrs.alt || '';
                    }

                    // 캡션이 외부에서 변경되었으면 업데이트 (포커스 중이 아닐 때만)
                    if (updatedNode.attrs.caption !== currentCaption && document.activeElement !== captionElement) {
                        currentCaption = updatedNode.attrs.caption || '';
                        captionElement.value = currentCaption;
                    }

                    // width가 변경되었으면 업데이트 (resize 중이 아닐 때만)
                    if (!isResizing && updatedNode.attrs.width && updatedNode.attrs.width !== figure.style.width) {
                        figure.style.width = updatedNode.attrs.width;
                    }

                    // align이 변경되었으면 업데이트
                    if (updatedNode.attrs.align !== currentAlign) {
                        currentAlign = updatedNode.attrs.align || 'center';
                        figure.setAttribute('data-align', currentAlign);

                        // 정렬 버튼 active 상태 업데이트
                        alignMenu.querySelectorAll('.align-button').forEach(btn => {
                            if (btn.getAttribute('data-align') === currentAlign) {
                                btn.classList.add('active');
                            } else {
                                btn.classList.remove('active');
                            }
                        });
                    }

                    return true;
                },
                destroy: () => {
                    // 노드가 파괴될 때 타임아웃 정리
                    if (captionSaveTimeout) {
                        clearTimeout(captionSaveTimeout);
                    }
                    // interval 정리
                    clearInterval(stateCheckInterval);
                    // resize 이벤트 리스너 제거
                    resizeHandle.removeEventListener('mousedown', onResizeStart);
                    document.removeEventListener('mousemove', onResizeMove);
                    document.removeEventListener('mouseup', onResizeEnd);
                },
                stopEvent: (event) => {
                    // 쓰기모드에서 캡션 입력 필드와 정렬 메뉴 내부의 이벤트는 내부에서 처리
                    if (editor.isEditable) {
                        return captionContainer.contains(event.target) || alignMenu.contains(event.target);
                    }
                    return false;
                },
                ignoreMutation: () => {
                    // 모든 DOM 변경 무시
                    return true;
                }
            };
        };
    },

    addCommands() {
        return {
            setImageWithCaption: (options) => ({ commands }) => {
                const safeSrc = sanitizeImageSrc(options?.src || '');
                if (!safeSrc) return false;
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        src: safeSrc,
                        alt: options.alt || '',
                        caption: options.caption || '',
                        width: options.width || '100%',
                        align: options.align || 'center'
                    }
                });
            }
        };
    }
});
