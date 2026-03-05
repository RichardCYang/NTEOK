
const Node = Tiptap.Core.Node;

export const TabItem = Node.create({
    name: 'tabItem',

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
                    if (content.contains(mutation.target) || mutation.target === content) return false;
                    return true;
                }
            };
        };
    }
});

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

            const wrapper = document.createElement('div');
            wrapper.className = 'tab-block-wrapper';

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
            addTabBtn.style.display = 'flex'; 

            tabHeader.appendChild(tabList);
            tabHeader.appendChild(addTabBtn);

            const panelsContainer = document.createElement('div');
            panelsContainer.className = 'tab-panels';

            wrapper.appendChild(tabHeader);
            wrapper.appendChild(panelsContainer);

            const getActiveIndex = (n) => {
                let activeIdx = 0;
                n.forEach((child, _, idx) => {
                    if (child.attrs.isActive) activeIdx = idx;
                });
                return activeIdx;
            };

            const renderHeader = (n) => {
                if (isEditingLabel) return;
                tabList.innerHTML = '';
                const activeIdx = getActiveIndex(n);

                n.forEach((child, _, idx) => {
                    const tabBtn = document.createElement('div');
                    tabBtn.className = 'tab-btn' + (idx === activeIdx ? ' active' : '');

                    const tabLabel = document.createElement('span');
                    tabLabel.className = 'tab-label';
                    tabLabel.textContent = child.attrs.label;
                    tabLabel.contentEditable = 'false'; 
                    tabLabel.spellcheck = false;

                    tabLabel.ondblclick = (e) => {
                        if (!editor.isEditable) return;
                        e.stopPropagation();
                        isEditingLabel = true;
                        tabLabel.contentEditable = 'true';
                        tabLabel.focus();
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

                        const children = [];
                        currentNode.forEach((c, o) => children.push({ node: c, offset: o, size: c.nodeSize }));

                        const { offset: tOff, size: tSize } = children[idx];

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

                    tabBtn.onclick = (e) => {
                        if (deleteBtn.contains(e.target)) return; 
                        if (isEditingLabel) return;               
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
                const insertPos = blockPos + 1 + currentNode.content.size;
                const tr = editor.view.state.tr;
                currentNode.forEach((c, o) => {
                    tr.setNodeMarkup(blockPos + 1 + o, null, { ...c.attrs, isActive: false });
                });
                tr.insert(insertPos, newTabItem);
                editor.view.dispatch(tr);
            };

            let lastEditable = editor.isEditable;
            const modeCheckHandler = () => {
                if (editor.isEditable !== lastEditable) {
                    lastEditable = editor.isEditable;
                    renderHeader(currentNode);
                }
            };
            editor.on('transaction', modeCheckHandler);

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
