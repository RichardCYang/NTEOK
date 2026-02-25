/**
 * Tiptap YouTube Node Extension
 * 유튜브 동영상 임베드 노드
 */

const Node = Tiptap.Core.Node;

// 보안: YouTube embed URL allowlist + 정규화 (Defense-in-Depth)
const _YT_ALLOWED_HOSTS = new Set([
    'youtube.com',
    'www.youtube.com',
    'm.youtube.com',
    'youtu.be',
    'youtube-nocookie.com',
    'www.youtube-nocookie.com'
]);

function _parseStartSeconds(urlObj) {
    const raw = urlObj.searchParams.get('start') || urlObj.searchParams.get('t') || '';
    if (!raw) return null;
    if (/^\d+$/.test(raw)) {
        const n = parseInt(raw, 10);
        return Number.isFinite(n) && n > 0 && n < 24 * 60 * 60 ? n : null;
    }
    const m = String(raw).toLowerCase().match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
    if (!m) return null;
    const h = m[1] ? parseInt(m[1], 10) : 0;
    const mm = m[2] ? parseInt(m[2], 10) : 0;
    const s = m[3] ? parseInt(m[3], 10) : 0;
    const total = h * 3600 + mm * 60 + s;
    return Number.isFinite(total) && total > 0 && total < 24 * 60 * 60 ? total : null;
}

function normalizeYouTubeEmbedUrl(value) {
    if (typeof value !== 'string') return null;
    const v = value.trim();
    if (!v) return null;
    let u;
    try { u = new URL(v); } catch { return null; }
    if (!(u.protocol === 'http:' || u.protocol === 'https:')) return null;
    const host = u.hostname.toLowerCase();
    if (!_YT_ALLOWED_HOSTS.has(host)) return null;
    let videoId = null;
    if (host === 'youtu.be') videoId = u.pathname.split('/').filter(Boolean)[0] || null;
    else if (u.pathname.startsWith('/embed/')) videoId = u.pathname.split('/').filter(Boolean)[1] || null;
    else if (u.pathname === '/watch') videoId = u.searchParams.get('v');
    else if (u.pathname.startsWith('/shorts/')) videoId = u.pathname.split('/').filter(Boolean)[1] || null;
    if (!videoId || !/^[A-Za-z0-9_-]{11}$/.test(videoId)) return null;
    const out = new URL(`https://www.youtube-nocookie.com/embed/${videoId}`);
    const start = _parseStartSeconds(u);
    if (start) out.searchParams.set('start', String(start));
    return out.toString();
}

export const YoutubeBlock = Node.create({
    name: 'youtubeBlock',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            src: {
                default: null
            },
            width: {
                default: '100%'
            },
            align: {
                default: 'center'
            },
            caption: {
                default: ''
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="youtube"]',
                getAttrs: (element) => {
                	const normalized = normalizeYouTubeEmbedUrl(element.getAttribute('data-src') || '');
                    return {
                        src: normalized,
                        width: element.getAttribute('data-width') || '100%',
                        align: element.getAttribute('data-align') || 'center',
                        caption: element.getAttribute('data-caption') || ''
                    };
                }
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
    	const safeSrc = normalizeYouTubeEmbedUrl(node.attrs.src || '') || 'about:blank';
        return [
            'div',
            {
                'data-type': 'youtube',
                'data-src': safeSrc,
                'data-width': node.attrs.width || '100%',
                'data-align': node.attrs.align || 'center',
                'data-caption': node.attrs.caption || '',
                'class': 'youtube-block-wrapper',
                'style': `width: ${node.attrs.width || '100%'};`
            },
            [
                'div',
                { 'class': 'youtube-container' },
                [
                    'iframe',
                    {
                        'src': safeSrc,
                        'frameborder': '0',
                        'allowfullscreen': 'true',
                        'allow': 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture',
                        'sandbox': 'allow-scripts allow-same-origin allow-presentation allow-popups',
                        'referrerpolicy': 'strict-origin-when-cross-origin'
                    }
                ]
            ],
            [
                'div',
                { 'class': 'youtube-caption' },
                node.attrs.caption || ''
            ]
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            // 전체 wrapper
            const wrapper = document.createElement('div');
            wrapper.className = 'youtube-block-wrapper';
            wrapper.contentEditable = 'false';
            wrapper.style.width = node.attrs.width || '100%';
            wrapper.setAttribute('data-align', node.attrs.align || 'center');

            let currentWidth = node.attrs.width || '100%';
            let currentAlign = node.attrs.align || 'center';
            let currentCaption = node.attrs.caption || '';

            // 유튜브 컨테이너
            const container = document.createElement('div');
            container.className = 'youtube-container';
            container.style.position = 'relative';
            container.style.paddingBottom = '56.25%'; // 16:9 비율
            container.style.height = '0';
            container.style.overflow = 'hidden';
            container.style.backgroundColor = '#000'; // 로딩 전 배경

            // Iframe
            const safeSrc = normalizeYouTubeEmbedUrl(node.attrs.src || '');
            const iframe = document.createElement('iframe');
            iframe.src = safeSrc || 'about:blank';
            iframe.style.position = 'absolute';
            iframe.style.top = '0';
            iframe.style.left = '0';
            iframe.style.width = '100%';
            iframe.style.height = '100%';
            iframe.frameBorder = '0';
            iframe.allow = 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture';
            iframe.allowFullscreen = true;
            iframe.sandbox = 'allow-scripts allow-same-origin allow-presentation allow-popups';
            iframe.referrerPolicy = 'strict-origin-when-cross-origin';

            // 드래그/리사이즈 중 iframe 이벤트 방지용 오버레이
            const overlay = document.createElement('div');
            overlay.style.position = 'absolute';
            overlay.style.top = '0';
            overlay.style.left = '0';
            overlay.style.width = '100%';
            overlay.style.height = '100%';
            overlay.style.zIndex = '1';
            overlay.style.display = editor.isEditable ? 'block' : 'none'; // 쓰기 모드에서만 클릭 방지 (재생을 원하면 읽기 모드로)
            // 더블 클릭시 재생 가능하게 하거나, 별도 버튼을 둘 수도 있음.
            // 여기서는 쓰기 모드에서 오버레이를 두어 선택이 용이하게 함.

            container.appendChild(iframe);
            container.appendChild(overlay);

            // 정렬 메뉴 (쓰기모드에서만)
            const alignMenu = document.createElement('div');
            alignMenu.className = 'image-align-menu'; // 기존 CSS 재사용
            alignMenu.style.display = editor.isEditable ? 'flex' : 'none';

            // 정렬 아이콘 SVG 생성 함수 (ImageWithCaption과 동일)
            const createAlignIcon = (align) => {
                const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.setAttribute('width', '16');
                svg.setAttribute('height', '16');
                svg.setAttribute('viewBox', '0 0 16 16');
                svg.setAttribute('fill', 'currentColor');

                if (align === 'left') {
                    svg.innerHTML = `<rect x="2" y="3" width="12" height="2" rx="1"/><rect x="2" y="7" width="8" height="2" rx="1"/><rect x="2" y="11" width="10" height="2" rx="1"/>`;
                } else if (align === 'center') {
                    svg.innerHTML = `<rect x="2" y="3" width="12" height="2" rx="1"/><rect x="4" y="7" width="8" height="2" rx="1"/><rect x="3" y="11" width="10" height="2" rx="1"/>`;
                } else if (align === 'right') {
                    svg.innerHTML = `<rect x="2" y="3" width="12" height="2" rx="1"/><rect x="6" y="7" width="8" height="2" rx="1"/><rect x="4" y="11" width="10" height="2" rx="1"/>`;
                }
                return svg;
            };

            const createAlignButton = (align, title) => {
                const button = document.createElement('button');
                button.className = 'align-button';
                button.type = 'button';
                button.title = title;
                button.setAttribute('data-align', align);
                button.appendChild(createAlignIcon(align));
                if (currentAlign === align) button.classList.add('active');

                button.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        const tr = editor.view.state.tr;
                        const currentNode = editor.view.state.doc.nodeAt(pos);

                        if (currentNode && currentNode.type.name === this.name) {
                            currentAlign = align;
                            wrapper.setAttribute('data-align', align);

                            alignMenu.querySelectorAll('.align-button').forEach(btn => btn.classList.remove('active'));
                            button.classList.add('active');

                            tr.setNodeMarkup(pos, null, { 
                                ...currentNode.attrs, 
                                align: align 
                            });
                            editor.view.dispatch(tr);
                        }
                    }
                });
                return button;
            };

            alignMenu.appendChild(createAlignButton('left', '왼쪽 정렬'));
            alignMenu.appendChild(createAlignButton('center', '가운데 정렬'));
            alignMenu.appendChild(createAlignButton('right', '오른쪽 정렬'));

            container.appendChild(alignMenu);

            // Resize Handle (쓰기모드에서만)
            const resizeHandle = document.createElement('div');
            resizeHandle.className = 'image-resize-handle'; // 기존 CSS 재사용
            resizeHandle.style.display = editor.isEditable ? 'block' : 'none';
            container.appendChild(resizeHandle);

            // 캡션 영역
            const captionContainer = document.createElement('div');
            captionContainer.className = 'image-caption-container'; // 기존 CSS 재사용

            const captionInput = document.createElement('input');
            captionInput.type = 'text';
            captionInput.className = 'image-caption-input';
            captionInput.placeholder = '동영상 설명을 입력하세요...';
            captionInput.value = currentCaption;
            captionInput.readOnly = !editor.isEditable;

            let captionSaveTimeout = null;
            captionInput.oninput = (e) => {
                e.stopPropagation();
                if (captionSaveTimeout) clearTimeout(captionSaveTimeout);
                captionSaveTimeout = setTimeout(() => {
                    currentCaption = captionInput.value;
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        const tr = editor.view.state.tr;
                        const currentNode = editor.view.state.doc.nodeAt(pos);

                        if (currentNode && currentNode.type.name === this.name) {
                            tr.setNodeMarkup(pos, null, { 
                                ...currentNode.attrs, 
                                caption: currentCaption 
                            });
                            editor.view.dispatch(tr);
                        }
                    }
                }, 500);
            };

            // 키보드 이벤트 차단 (엔터 등)
            captionInput.onkeydown = (e) => {
                e.stopPropagation();
                if (e.key === 'Enter') {
                    e.preventDefault();
                    captionInput.blur();
                }
            };

            captionContainer.appendChild(captionInput);

            wrapper.appendChild(container);
            wrapper.appendChild(captionContainer);

            // 리사이즈 로직
            let isResizing = false;
            let startX = 0;
            let startWidth = 0;

            const onResizeStart = (e) => {
                e.preventDefault();
                e.stopPropagation();
                isResizing = true;
                startX = e.clientX;
                startWidth = wrapper.offsetWidth;
                document.addEventListener('mousemove', onResizeMove);
                document.addEventListener('mouseup', onResizeEnd);
            };

            const onResizeMove = (e) => {
                if (!isResizing) return;
                const deltaX = e.clientX - startX;
                let newWidth = startWidth + deltaX * 2;
                const editorElement = document.querySelector('#editor .ProseMirror');
                const maxWidth = editorElement ? editorElement.offsetWidth : 800;
                newWidth = Math.max(200, Math.min(newWidth, maxWidth));
                wrapper.style.width = `${newWidth}px`;
            };

            const onResizeEnd = () => {
                if (!isResizing) return;
                isResizing = false;
                document.removeEventListener('mousemove', onResizeMove);
                document.removeEventListener('mouseup', onResizeEnd);

                if (typeof getPos === 'function') {
                    const pos = getPos();
                    const tr = editor.view.state.tr;
                    const currentNode = editor.view.state.doc.nodeAt(pos);

                    if (currentNode && currentNode.type.name === this.name) {
                        tr.setNodeMarkup(pos, null, { 
                            ...currentNode.attrs, 
                            width: wrapper.style.width 
                        });
                        editor.view.dispatch(tr);
                    }
                }
            };

            resizeHandle.addEventListener('mousedown', onResizeStart);

            // 에디터 모드 변경 감지
            let lastEditableState = editor.isEditable;
            const stateCheckInterval = setInterval(() => {
                if (editor.isEditable !== lastEditableState) {
                    lastEditableState = editor.isEditable;
                    resizeHandle.style.display = lastEditableState ? 'block' : 'none';
                    alignMenu.style.display = lastEditableState ? 'flex' : 'none';
                    overlay.style.display = lastEditableState ? 'block' : 'none';
                    captionInput.readOnly = !lastEditableState;
                }
            }, 100);

            return {
                dom: wrapper,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) return false;

                    if (updatedNode.attrs.src !== iframe.src) {
                        iframe.src = updatedNode.attrs.src;
                    }

                    if (updatedNode.attrs.caption !== currentCaption && document.activeElement !== captionInput) {
                        currentCaption = updatedNode.attrs.caption || '';
                        captionInput.value = currentCaption;
                    }

                    if (!isResizing && updatedNode.attrs.width && updatedNode.attrs.width !== wrapper.style.width) {
                        wrapper.style.width = updatedNode.attrs.width;
                    }

                    if (updatedNode.attrs.align !== currentAlign) {
                        currentAlign = updatedNode.attrs.align || 'center';
                        wrapper.setAttribute('data-align', currentAlign);

                        alignMenu.querySelectorAll('.align-button').forEach(btn => {
                             if (btn.getAttribute('data-align') === currentAlign) btn.classList.add('active');
                             else btn.classList.remove('active');
                        });
                    }

                    return true;
                },
                destroy: () => {
                    clearInterval(stateCheckInterval);
                    if (captionSaveTimeout) clearTimeout(captionSaveTimeout);
                    resizeHandle.removeEventListener('mousedown', onResizeStart);
                    document.removeEventListener('mousemove', onResizeMove);
                    document.removeEventListener('mouseup', onResizeEnd);
                },
                stopEvent: (event) => {
                    if (editor.isEditable) {
                        return captionContainer.contains(event.target) || alignMenu.contains(event.target);
                    }
                    return false;
                },
                ignoreMutation: () => true
            };
        };
    },

    addCommands() {
        return {
            setYoutubeBlock: (options) => ({ commands }) => {
                const normalized = normalizeYouTubeEmbedUrl(options?.src || '');
                if (!normalized) return false;
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        src: normalized,
                        caption: options.caption || ''
                    }
                });
            }
        };
    }
});
