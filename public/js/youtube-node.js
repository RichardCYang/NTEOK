/**
 * Tiptap YouTube Node Extension
 * 유튜브 동영상 임베드 노드
 */

const Node = Tiptap.Core.Node;

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
                    return {
                        src: element.getAttribute('data-src'),
                        width: element.getAttribute('data-width') || '100%',
                        align: element.getAttribute('data-align') || 'center',
                        caption: element.getAttribute('data-caption') || ''
                    };
                }
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        return [
            'div',
            {
                'data-type': 'youtube',
                'data-src': node.attrs.src,
                'data-width': node.attrs.width || '100%',
                'data-align': node.attrs.align || 'center',
                'data-caption': node.attrs.caption || '',
                'class': 'youtube-block-wrapper',
                'style': `width: ${node.attrs.width || '100%'}; margin: 0 auto;`
            },
            [
                'div',
                { 'class': 'youtube-container' },
                [
                    'iframe',
                    {
                        'src': node.attrs.src,
                        'frameborder': '0',
                        'allowfullscreen': 'true',
                        'allow': 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture'
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

            // 정렬에 따른 마진 설정
            if (node.attrs.align === 'center') wrapper.style.margin = '0 auto';
            else if (node.attrs.align === 'right') wrapper.style.marginLeft = 'auto';
            else wrapper.style.margin = '0';

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
            const iframe = document.createElement('iframe');
            iframe.src = node.attrs.src;
            iframe.style.position = 'absolute';
            iframe.style.top = '0';
            iframe.style.left = '0';
            iframe.style.width = '100%';
            iframe.style.height = '100%';
            iframe.frameBorder = '0';
            iframe.allow = 'accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture';
            iframe.allowFullscreen = true;
            
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
                button.appendChild(createAlignIcon(align));
                if (currentAlign === align) button.classList.add('active');

                button.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    currentAlign = align;
                    wrapper.setAttribute('data-align', align);
                    
                    if (align === 'center') wrapper.style.margin = '0 auto';
                    else if (align === 'right') wrapper.style.marginLeft = 'auto';
                    else wrapper.style.margin = '0';

                    alignMenu.querySelectorAll('.align-button').forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');

                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        const tr = editor.view.state.tr;
                        tr.setNodeMarkup(pos, null, { ...node.attrs, align: align });
                        editor.view.dispatch(tr);
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
                        tr.setNodeMarkup(pos, null, { ...node.attrs, caption: currentCaption });
                        editor.view.dispatch(tr);
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
                    tr.setNodeMarkup(pos, null, { ...node.attrs, width: wrapper.style.width });
                    editor.view.dispatch(tr);
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
                        if (currentAlign === 'center') wrapper.style.margin = '0 auto';
                        else if (currentAlign === 'right') wrapper.style.marginLeft = 'auto';
                        else wrapper.style.margin = '0';
                        
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
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        src: options.src,
                        caption: options.caption || ''
                    }
                });
            }
        };
    }
});
