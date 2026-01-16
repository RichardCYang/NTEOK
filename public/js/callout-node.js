/**
 * Tiptap Callout Node Extension
 * 정보, 경고, 에러, 성공 메시지를 표시하는 콜아웃 블록
 */

const Node = Tiptap.Core.Node;

// 콜아웃 타입 정의 (파스텔톤 테마)
const CALLOUT_TYPES = {
    info: {
        icon: 'ℹ️',
        label: '정보',
        bgColor: '#f1f5f9',
        borderColor: '#e2e8f0',
        iconColor: '#3182ce'
    },
    warning: {
        icon: '⚠️',
        label: '경고',
        bgColor: '#fffbeb',
        borderColor: '#fef3c7',
        iconColor: '#dd6b20'
    },
    error: {
        icon: '❌',
        label: '에러',
        bgColor: '#fef2f2',
        borderColor: '#fee2e2',
        iconColor: '#e53e3e'
    },
    success: {
        icon: '✅',
        label: '성공',
        bgColor: '#f0fdf4',
        borderColor: '#dcfce7',
        iconColor: '#38a169'
    }
};

export const CalloutBlock = Node.create({
    name: 'calloutBlock',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            type: {
                default: 'info',
                parseHTML: element => element.getAttribute('data-callout-type') || 'info',
                renderHTML: attributes => {
                    return { 'data-callout-type': attributes.type };
                }
            },
            content: {
                default: '',
                parseHTML: element => element.getAttribute('data-content') || '',
                renderHTML: attributes => {
                    return { 'data-content': attributes.content };
                }
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="callout-block"]'
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        return [
            'div',
            {
                ...HTMLAttributes,
                'data-type': 'callout-block',
                'class': 'callout-block',
                'data-callout-type': node.attrs.type,
                'data-content': node.attrs.content
            }
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            // 전체 컨테이너 생성
            const wrapper = document.createElement('div');
            wrapper.className = 'callout-block-wrapper';
            wrapper.setAttribute('data-callout-type', node.attrs.type);
            wrapper.contentEditable = 'false';

            let currentType = node.attrs.type || 'info';
            let currentContent = node.attrs.content || '';
            let isEditingContent = false;
            let typePopup = null;
            let lastEditableState = editor.isEditable;

            // 메인 콘텐츠 레이아웃 (아이콘 + 텍스트)
            const mainContainer = document.createElement('div');
            mainContainer.className = 'callout-header';

            // 아이콘 영역
            const icon = document.createElement('span');
            icon.className = 'callout-icon';
            icon.textContent = CALLOUT_TYPES[currentType].icon;

            // 텍스트 내용 영역
            const contentContainer = document.createElement('div');
            contentContainer.className = 'callout-content';

            const textarea = document.createElement('textarea');
            textarea.className = 'callout-content-textarea';
            textarea.placeholder = '내용을 입력하세요...';
            textarea.value = currentContent;
            textarea.rows = 1;

            contentContainer.appendChild(textarea);
            mainContainer.appendChild(icon);
            mainContainer.appendChild(contentContainer);

            // 타입 선택 버튼 (우측 상단 위치)
            const typeSelector = document.createElement('button');
            typeSelector.className = 'callout-type-selector';
            typeSelector.textContent = CALLOUT_TYPES[currentType].label;
            typeSelector.type = 'button';

            wrapper.appendChild(mainContainer);
            wrapper.appendChild(typeSelector);

            // 텍스트 영역 높이 자동 조절
            const adjustTextareaHeight = () => {
                textarea.style.height = 'auto';
                textarea.style.height = textarea.scrollHeight + 'px';
            };

            // 초기 높이 설정
            setTimeout(adjustTextareaHeight, 0);

            // ------------------------------------------------------------
            // 내용 편집 관련 로직
            // ------------------------------------------------------------
            const setupContentInteraction = () => {
                if (editor.isEditable) {
                    textarea.readOnly = false;
                    textarea.style.cursor = 'text';

                    textarea.onfocus = () => {
                        isEditingContent = true;
                    };

                    textarea.oninput = (e) => {
                        e.stopPropagation();
                        adjustTextareaHeight();
                        currentContent = textarea.value;
                    };

                    textarea.onkeydown = (e) => {
                        e.stopPropagation();
                    };

                    textarea.onblur = () => {
                        isEditingContent = false;
                        currentContent = textarea.value;

                        if (typeof getPos === 'function') {
                            const pos = getPos();
                            try {
                                const tr = editor.view.state.tr;
                                tr.setNodeMarkup(pos, null, {
                                    type: currentType,
                                    content: currentContent
                                });
                                editor.view.dispatch(tr);
                            } catch (error) {
                                console.error('[CalloutBlock] 내용 저장 실패:', error);
                            }
                        }
                    };
                } else {
                    isEditingContent = false;
                    textarea.readOnly = true;
                    textarea.style.cursor = 'default';
                    textarea.onfocus = null;
                    textarea.oninput = null;
                    textarea.onkeydown = null;
                    textarea.onblur = null;
                }
            };

            // ------------------------------------------------------------
            // 타입 선택 팝업 관련 로직
            // ------------------------------------------------------------
            const closeTypePopup = () => {
                if (typePopup && typePopup.parentNode) {
                    typePopup.parentNode.removeChild(typePopup);
                    typePopup = null;
                }
            };

            const changeCalloutType = (newType) => {
                currentType = newType;
                wrapper.setAttribute('data-callout-type', newType);
                icon.textContent = CALLOUT_TYPES[newType].icon;
                typeSelector.textContent = CALLOUT_TYPES[newType].label;

                if (typeof getPos === 'function') {
                    const pos = getPos();
                    try {
                        const tr = editor.view.state.tr;
                        tr.setNodeMarkup(pos, null, {
                            type: currentType,
                            content: currentContent
                        });
                        editor.view.dispatch(tr);
                    } catch (error) {
                        console.error('[CalloutBlock] 타입 변경 저장 실패:', error);
                    }
                }
            };

            const createTypePopup = () => {
                const popup = document.createElement('div');
                popup.className = 'callout-type-popup';

                Object.keys(CALLOUT_TYPES).forEach(typeKey => {
                    const typeInfo = CALLOUT_TYPES[typeKey];
                    const option = document.createElement('div');
                    option.className = 'callout-type-option';
                    if (typeKey === currentType) {
                        option.style.backgroundColor = '#f7fafc';
                    }

                    const optionIcon = document.createElement('span');
                    optionIcon.textContent = typeInfo.icon;
                    optionIcon.style.fontSize = '16px';

                    const optionLabel = document.createElement('span');
                    optionLabel.textContent = typeInfo.label;
                    optionLabel.style.flex = '1';

                    option.appendChild(optionIcon);
                    option.appendChild(optionLabel);

                    option.onclick = (e) => {
                        e.stopPropagation();
                        changeCalloutType(typeKey);
                        closeTypePopup();
                    };

                    popup.appendChild(option);
                });

                return popup;
            };

            const openTypePopup = () => {
                if (typePopup) {
                    closeTypePopup();
                    return;
                }

                typePopup = createTypePopup();
                const rect = typeSelector.getBoundingClientRect();
                typePopup.style.position = 'absolute';
                typePopup.style.top = (rect.bottom + 5) + 'px';
                typePopup.style.right = '8px';

                document.body.appendChild(typePopup);

                setTimeout(() => {
                    const closeHandler = (e) => {
                        if (typePopup && !typePopup.contains(e.target) && e.target !== typeSelector) {
                            closeTypePopup();
                            document.removeEventListener('click', closeHandler);
                        }
                    };
                    document.addEventListener('click', closeHandler);
                }, 0);
            };

            const setupTypeSelectorInteraction = () => {
                if (editor.isEditable) {
                    typeSelector.style.display = 'block';
                    typeSelector.onclick = (e) => {
                        e.stopPropagation();
                        openTypePopup();
                    };
                } else {
                    typeSelector.style.display = 'none';
                    typeSelector.onclick = null;
                }
            };

            // ------------------------------------------------------------
            // 에디터 상태 변경 감지
            // ------------------------------------------------------------
            const modeCheckHandler = () => {
                if (editor.isEditable !== lastEditableState) {
                    lastEditableState = editor.isEditable;
                    setupContentInteraction();
                    setupTypeSelectorInteraction();
                }
            };

            editor.on('transaction', modeCheckHandler);

            wrapper.onmouseenter = () => {
                if (editor.isEditable !== lastEditableState) {
                    lastEditableState = editor.isEditable;
                    setupContentInteraction();
                    setupTypeSelectorInteraction();
                }
            };

            // 초기 설정 실행
            setupContentInteraction();
            setupTypeSelectorInteraction();

            return {
                dom: wrapper,

                update(updatedNode) {
                    // 노드 존재 여부 및 타입 일치 확인 (에러 방지 강화)
                    if (!updatedNode || !updatedNode.type || !this.node || !this.node.type) {
                        return false;
                    }

                    if (updatedNode.type.name !== this.node.type.name) {
                        return false;
                    }

                    if (updatedNode.attrs && updatedNode.attrs.type !== currentType) {
                        currentType = updatedNode.attrs.type;
                        wrapper.setAttribute('data-callout-type', currentType);
                        icon.textContent = CALLOUT_TYPES[currentType].icon;
                        typeSelector.textContent = CALLOUT_TYPES[currentType].label;
                    }

                    if (updatedNode.attrs && updatedNode.attrs.content !== currentContent) {
                        if (!isEditingContent) {
                            currentContent = updatedNode.attrs.content;
                            textarea.value = currentContent;
                            adjustTextareaHeight();
                        }
                    }

                    return true;
                },

                destroy() {
                    closeTypePopup();
                    editor.off('transaction', modeCheckHandler);

                    if (isEditingContent) {
                        currentContent = textarea.value;
                        if (typeof getPos === 'function') {
                            const pos = getPos();
                            try {
                                const tr = editor.view.state.tr;
                                tr.setNodeMarkup(pos, null, {
                                    type: currentType,
                                    content: currentContent
                                });
                                editor.view.dispatch(tr);
                            } catch (error) {
                                console.error('[CalloutBlock] 종료 시 저장 실패:', error);
                            }
                        }
                    }
                },

                stopEvent(event) {
                    const target = event.target;
                    return (
                        target === textarea ||
                        target === typeSelector ||
                        (typePopup && typePopup.contains(target))
                    );
                },

                ignoreMutation() {
                    return true;
                }
            };
        };
    },

    addCommands() {
        return {
            setCallout: (type = 'info', content = '') => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: { type, content }
                });
            }
        };
    }
});