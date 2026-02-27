/**
 * Tiptap Bookmark Node Extension
 * 링크 블록 (북마크) 노드
 */

const Node = Tiptap.Core.Node;

export const BookmarkBlock = Node.create({
    name: 'bookmarkBlock',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            url: {
                default: null
            },
            title: {
                default: null
            },
            favicon: {
                default: null
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="bookmark"]',
                getAttrs: (element) => ({
                    url: element.getAttribute('data-url'),
                    title: element.getAttribute('data-title'),
                    favicon: element.getAttribute('data-favicon')
                })
            }
        ];
    },

    renderHTML({ node }) {
        return [
            'div',
            {
                'data-type': 'bookmark',
                'data-url': node.attrs.url || '',
                'data-title': node.attrs.title || '',
                'data-favicon': node.attrs.favicon || '',
                'class': 'bookmark-block'
            }
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            const container = document.createElement('div');
            container.className = 'bookmark-block-container';
            container.contentEditable = 'false';

            const render = () => {
                container.innerHTML = '';

                if (!node.attrs.url) {
                    // 빈 상태: URL 입력창 표시
                    const inputWrapper = document.createElement('div');
                    inputWrapper.className = 'bookmark-input-wrapper';

                    const input = document.createElement('input');
                    input.type = 'text';
                    input.placeholder = '링크를 입력하거나 붙여넣으세요...';
                    input.className = 'bookmark-url-input';

                    const button = document.createElement('button');
                    button.textContent = '추가';
                    button.className = 'bookmark-add-btn';

                    const handleAdd = async () => {
                        const url = input.value.trim();
                        if (!url) return;

                        // 간단한 URL 형식 검사
                        if (!url.startsWith('http://') && !url.startsWith('https://')) {
                             alert('http:// 또는 https:// 로 시작하는 올바른 URL을 입력하세요.');
                             return;
                        }

                        input.disabled = true;
                        button.disabled = true;
                        button.textContent = '가져오는 중...';

                        try {
                            const headers = {};
                            if (window.csrfUtils) {
                                headers['X-CSRF-Token'] = window.csrfUtils.getCsrfToken();
                            }

                            const response = await fetch(`/api/pages/fetch-metadata?url=${encodeURIComponent(url)}`, {
                                headers: headers
                            });
                            
                            if (!response.ok) {
                                const errData = await response.json().catch(() => ({}));
                                throw new Error(errData.error || '메타데이터를 가져올 수 없습니다.');
                            }

                            const data = await response.json();

                            if (typeof getPos === 'function') {
                                editor.view.dispatch(editor.view.state.tr.setNodeMarkup(getPos(), null, {
                                    url: data.url,
                                    title: data.title,
                                    favicon: data.favicon
                                }));
                            }
                        } catch (error) {
                            alert('오류: ' + error.message);
                            input.disabled = false;
                            button.disabled = false;
                            button.textContent = '추가';
                            input.focus();
                        }
                    };

                    input.addEventListener('keydown', (e) => {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            handleAdd();
                        }
                    });

                    button.addEventListener('click', (e) => {
                        e.preventDefault();
                        handleAdd();
                    });

                    inputWrapper.appendChild(input);
                    inputWrapper.appendChild(button);
                    container.appendChild(inputWrapper);
                    
                    if (editor.isEditable) {
                        setTimeout(() => input.focus(), 10);
                    }
                } else {
                    // 채워진 상태: 컴팩트한 북마크 링크 표시
                    const card = document.createElement('a');
                    card.href = node.attrs.url;
                    card.target = '_blank';
                    card.rel = 'noopener noreferrer';
                    card.className = 'bookmark-compact-link';

                    // 파비콘/아이콘 영역
                    if (node.attrs.favicon) {
                        const icon = document.createElement('img');
                        icon.src = node.attrs.favicon;
                        icon.className = 'bookmark-compact-favicon';
                        icon.alt = '';
                        icon.onerror = () => {
                            // 이미지 로드 실패 시 아이콘으로 교체
                            const fallbackIcon = document.createElement('i');
                            fallbackIcon.className = 'fa-solid fa-link bookmark-compact-icon';
                            if (card.contains(icon)) {
                                card.replaceChild(fallbackIcon, icon);
                            }
                        };
                        card.appendChild(icon);
                    } else {
                        const icon = document.createElement('i');
                        icon.className = 'fa-solid fa-link bookmark-compact-icon';
                        card.appendChild(icon);
                    }

                    // 제목 영역
                    const title = document.createElement('span');
                    title.className = 'bookmark-compact-title';
                    title.textContent = node.attrs.title || node.attrs.url;
                    card.appendChild(title);

                    container.appendChild(card);
                    
                    // 삭제 버튼 (편집 모드에서만)
                    if (editor.isEditable) {
                        const removeBtn = document.createElement('button');
                        removeBtn.className = 'bookmark-remove-btn';
                        removeBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
                        removeBtn.title = '링크 삭제';
                        removeBtn.onclick = (e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            if (typeof getPos === 'function') {
                                editor.view.dispatch(editor.view.state.tr.delete(getPos(), getPos() + node.nodeSize));
                            }
                        };
                        container.appendChild(removeBtn);
                    }
                }
            };

            render();

            return {
                dom: container,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) return false;
                    
                    if (updatedNode.attrs.url !== node.attrs.url || 
                        updatedNode.attrs.title !== node.attrs.title ||
                        updatedNode.attrs.favicon !== node.attrs.favicon) {
                        
                        // 속성 업데이트
                        node.attrs.url = updatedNode.attrs.url;
                        node.attrs.title = updatedNode.attrs.title;
                        node.attrs.favicon = updatedNode.attrs.favicon;
                        render();
                    }
                    return true;
                },
                stopEvent: (event) => {
                    const isInput = event.target.closest('input');
                    const isButton = event.target.closest('button');
                    return isInput || isButton;
                },
                ignoreMutation: () => true
            };
        };
    },

    addCommands() {
        return {
            setBookmarkBlock: () => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        url: null,
                        title: null,
                        favicon: null
                    }
                });
            }
        };
    }
});
