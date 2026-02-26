/**
 * Tiptap Tab View Node Extension
 * 탭 형식으로 블록 콘텐츠를 정리하는 레이아웃 블록
 *
 * 구조:
 *   TabBlock  (group: 'block', content: 'tabItem+')
 *     └─ TabItem  (group: 'tabItem', content: 'block+', 탭 하나의 패널)
 *
 * 각 TabItem은 contentDOM을 가지므로 내부에 슬래시 메뉴 포함 모든 블록을 삽입할 수 있다.
 * 탭 전환은 각 TabItem의 isActive 속성을 업데이트하여 CSS show/hide로 처리.
 */

const Node = Tiptap.Core.Node;

// ─────────────────────────────────────────────────────────────
// TabItem: 개별 탭 패널 (block+를 자식으로 가짐)
// ─────────────────────────────────────────────────────────────
export const TabItem = Node.create({
    name: 'tabItem',

    // 'block'이 아닌 별도 그룹 → tabBlock의 content: 'tabItem+' 에서만 사용
    group: 'tabItem',

    content: 'block+',

    defining: true,

    addAttributes() {
        return {
            label: {
                default: '탭',
                parseHTML: el => el.getAttribute('data-label') || '탭',
                renderHTML: attrs => ({ 'data-label': attrs.label })
            },
            isActive: {
                default: false,
                parseHTML: el => el.getAttribute('data-is-active') === 'true',
                renderHTML: attrs => ({ 'data-is-active': String(attrs.isActive) })
            }
        };
    },

    parseHTML() {
        return [{
            tag: 'div[data-type="tab-item"]',
            contentElement: '.tab-panel-content'
        }];
    },

    renderHTML({ node }) {
        return [
            'div',
            {
                'data-type': 'tab-item',
                'data-label': node.attrs.label,
                'data-is-active': String(node.attrs.isActive)
            },
            ['div', { class: 'tab-panel-content' }, 0]
        ];
    },

    addNodeView() {
        return ({ node }) => {
            const panel = document.createElement('div');
            panel.className = 'tab-panel' + (node.attrs.isActive ? ' active' : '');

            const content = document.createElement('div');
            content.className = 'tab-panel-content';
            panel.appendChild(content);

            return {
                dom: panel,
                contentDOM: content,

                update(updatedNode) {
                    if (updatedNode.type.name !== 'tabItem') return false;
                    panel.className = 'tab-panel' + (updatedNode.attrs.isActive ? ' active' : '');
                    return true;
                },

                ignoreMutation(mutation) {
                    // content 내부 변경은 ProseMirror가 처리
                    if (content.contains(mutation.target) || mutation.target === content) return false;
                    return true;
                }
            };
        };
    }
});

// ─────────────────────────────────────────────────────────────
// TabBlock: 탭 컨테이너 (헤더 + TabItem 패널들)
// ─────────────────────────────────────────────────────────────
export const TabBlock = Node.create({
    name: 'tabBlock',

    group: 'block',

    content: 'tabItem+',

    defining: true,

    parseHTML() {
        return [{ tag: 'div[data-type="tab-block"]', contentElement: '.tab-panels' }];
    },

    renderHTML() {
        return [
            'div',
            { 'data-type': 'tab-block', class: 'tab-block' },
            ['div', { class: 'tab-panels' }, 0]
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            let currentNode = node;
            let isEditingLabel = false;

            // ──────────────────────────────
            // DOM 구성
            // ──────────────────────────────
            const wrapper = document.createElement('div');
            wrapper.className = 'tab-block-wrapper';

            // 탭 헤더 바 (contentEditable 차단 → ProseMirror가 직접 편집하지 않음)
            const tabHeader = document.createElement('div');
            tabHeader.className = 'tab-header';
            tabHeader.contentEditable = 'false';

            const tabList = document.createElement('div');
            tabList.className = 'tab-list';

            const addTabBtn = document.createElement('button');
            addTabBtn.className = 'tab-add-btn';
            addTabBtn.type = 'button';
            addTabBtn.title = '탭 추가';
            addTabBtn.textContent = '+';
            addTabBtn.style.display = 'flex'; // 초기 표시 (편집 모드에서 생성되므로 기본 표시)

            tabHeader.appendChild(tabList);
            tabHeader.appendChild(addTabBtn);

            // 탭 패널 컨테이너 → contentDOM (ProseMirror가 tabItem NodeView들을 여기에 렌더링)
            const panelsContainer = document.createElement('div');
            panelsContainer.className = 'tab-panels';

            wrapper.appendChild(tabHeader);
            wrapper.appendChild(panelsContainer);

            // ──────────────────────────────
            // 헬퍼: 현재 활성 탭 인덱스
            // ──────────────────────────────
            const getActiveIndex = (n) => {
                let activeIdx = 0;
                n.forEach((child, _, idx) => {
                    if (child.attrs.isActive) activeIdx = idx;
                });
                return activeIdx;
            };

            // ──────────────────────────────
            // 탭 헤더 렌더링
            // ──────────────────────────────
            const renderHeader = (n) => {
                if (isEditingLabel) return;
                tabList.innerHTML = '';
                const activeIdx = getActiveIndex(n);

                n.forEach((child, _, idx) => {
                    const tabBtn = document.createElement('div');
                    tabBtn.className = 'tab-btn' + (idx === activeIdx ? ' active' : '');

                    // 탭 레이블 (기본은 읽기 전용, 더블클릭 시 이름 편집)
                    const tabLabel = document.createElement('span');
                    tabLabel.className = 'tab-label';
                    tabLabel.textContent = child.attrs.label;
                    tabLabel.contentEditable = 'false'; // 기본은 편집 불가 → 싱글클릭이 tabBtn.onclick으로 전달됨
                    tabLabel.spellcheck = false;

                    // 더블클릭 → 이름 편집 모드 진입
                    tabLabel.ondblclick = (e) => {
                        if (!editor.isEditable) return;
                        e.stopPropagation();
                        isEditingLabel = true;
                        tabLabel.contentEditable = 'true';
                        tabLabel.focus();
                        // 텍스트 전체 선택
                        const range = document.createRange();
                        range.selectNodeContents(tabLabel);
                        const sel = window.getSelection();
                        sel.removeAllRanges();
                        sel.addRange(range);
                    };

                    tabLabel.onblur = () => {
                        tabLabel.contentEditable = 'false';
                        isEditingLabel = false;
                        const newLabel = tabLabel.textContent.trim() || `탭 ${idx + 1}`;
                        tabLabel.textContent = newLabel;
                        if (newLabel === child.attrs.label || typeof getPos !== 'function') return;
                        let childOffset = 0;
                        currentNode.forEach((c, o, i) => { if (i === idx) childOffset = o; });
                        try {
                            editor.view.dispatch(
                                editor.view.state.tr.setNodeMarkup(getPos() + 1 + childOffset, null, {
                                    ...currentNode.child(idx).attrs,
                                    label: newLabel
                                })
                            );
                        } catch (e) {
                            console.error('[TabBlock] 레이블 저장 실패:', e);
                        }
                    };

                    tabLabel.onkeydown = (e) => {
                        e.stopPropagation();
                        if (e.key === 'Enter') { e.preventDefault(); tabLabel.blur(); }
                        if (e.key === 'Escape') { e.preventDefault(); tabLabel.textContent = child.attrs.label; tabLabel.blur(); }
                    };

                    // 탭 삭제 버튼 (탭이 2개 이상 + 편집 모드일 때만 표시)
                    const deleteBtn = document.createElement('button');
                    deleteBtn.className = 'tab-delete-btn';
                    deleteBtn.type = 'button';
                    deleteBtn.title = '탭 삭제';
                    deleteBtn.textContent = '×';
                    deleteBtn.style.display = (editor.isEditable && n.childCount > 1) ? '' : 'none';

                    deleteBtn.onclick = (e) => {
                        e.stopPropagation();
                        if (typeof getPos !== 'function' || currentNode.childCount <= 1) return;
                        const blockPos = getPos();
                        const activeIdx = getActiveIndex(currentNode);
                        const tr = editor.view.state.tr;

                        // 각 자식의 offset, size 수집
                        const children = [];
                        currentNode.forEach((c, o) => children.push({ node: c, offset: o, size: c.nodeSize }));

                        const { offset: tOff, size: tSize } = children[idx];

                        // 삭제되는 탭이 활성 탭이면 인접 탭을 활성화
                        if (idx === activeIdx) {
                            const newIdx = idx > 0 ? idx - 1 : 1;
                            tr.setNodeMarkup(blockPos + 1 + children[newIdx].offset, null, {
                                ...children[newIdx].node.attrs,
                                isActive: true
                            });
                        }

                        tr.delete(blockPos + 1 + tOff, blockPos + 1 + tOff + tSize);
                        editor.view.dispatch(tr);
                    };

                    // 탭 버튼 클릭 → 탭 전환
                    tabBtn.onclick = (e) => {
                        if (deleteBtn.contains(e.target)) return; // deleteBtn은 자체 핸들러 처리
                        if (isEditingLabel) return;               // 이름 편집 중이면 무시
                        if (idx === getActiveIndex(currentNode) || typeof getPos !== 'function') return;
                        const blockPos = getPos();
                        const tr = editor.view.state.tr;
                        currentNode.forEach((c, o, i) => {
                            tr.setNodeMarkup(blockPos + 1 + o, null, { ...c.attrs, isActive: i === idx });
                        });
                        editor.view.dispatch(tr);
                    };

                    tabBtn.appendChild(tabLabel);
                    tabBtn.appendChild(deleteBtn);
                    tabList.appendChild(tabBtn);
                });

                addTabBtn.style.display = editor.isEditable ? 'flex' : 'none';
            };

            // ──────────────────────────────
            // 탭 추가
            // ──────────────────────────────
            addTabBtn.onclick = (e) => {
                e.stopPropagation();
                if (typeof getPos !== 'function') return;
                const blockPos = getPos();
                const newLabel = `탭 ${currentNode.childCount + 1}`;
                const schema = editor.schema;
                const newTabItem = schema.nodes.tabItem.create(
                    { label: newLabel, isActive: true },
                    [schema.nodes.paragraph.create()]
                );
                // setNodeMarkup은 노드 크기를 변경하지 않으므로 insertPos는 그대로 유효
                const insertPos = blockPos + 1 + currentNode.content.size;
                const tr = editor.view.state.tr;
                // 기존 탭 모두 비활성화
                currentNode.forEach((c, o) => {
                    tr.setNodeMarkup(blockPos + 1 + o, null, { ...c.attrs, isActive: false });
                });
                tr.insert(insertPos, newTabItem);
                editor.view.dispatch(tr);
            };

            // ──────────────────────────────
            // 에디터 모드(읽기↔편집) 변경 감지
            // ──────────────────────────────
            let lastEditable = editor.isEditable;
            const modeCheckHandler = () => {
                if (editor.isEditable !== lastEditable) {
                    lastEditable = editor.isEditable;
                    renderHeader(currentNode);
                }
            };
            editor.on('transaction', modeCheckHandler);

            // 초기 헤더 렌더링
            renderHeader(node);

            return {
                dom: wrapper,
                contentDOM: panelsContainer,

                update(updatedNode) {
                    if (updatedNode.type.name !== 'tabBlock') return false;
                    currentNode = updatedNode;
                    renderHeader(updatedNode);
                    return true;
                },

                destroy() {
                    editor.off('transaction', modeCheckHandler);
                },

                // tabHeader 영역의 이벤트만 ProseMirror에서 차단
                // panelsContainer(contentDOM) 영역은 통과 → ProseMirror가 정상 처리
                stopEvent(event) {
                    return tabHeader.contains(event.target);
                },

                ignoreMutation(mutation) {
                    if (tabHeader.contains(mutation.target)) return true;
                    return false;
                }
            };
        };
    },

    addCommands() {
        return {
            setTabBlock: () => ({ commands }) => {
                return commands.insertContent({
                    type: 'tabBlock',
                    content: [
                        {
                            type: 'tabItem',
                            attrs: { label: '탭 1', isActive: true },
                            content: [{ type: 'paragraph' }]
                        },
                        {
                            type: 'tabItem',
                            attrs: { label: '탭 2', isActive: false },
                            content: [{ type: 'paragraph' }]
                        }
                    ]
                });
            }
        };
    }
});
