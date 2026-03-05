
const Node = Tiptap.Core.Node;

export const ToggleBlock = Node.create({
    name: 'toggleBlock',

    group: 'block',

    content: 'block+', 

    defining: true, 

    addAttributes() {
        return {
            title: {
                default: '',
                parseHTML: element => element.getAttribute('data-title') || '',
                renderHTML: attributes => {
                    return { 'data-title': attributes.title };
                }
            },
            isOpen: {
                default: true, 
                parseHTML: element => element.getAttribute('data-is-open') === 'true',
                renderHTML: attributes => {
                    return { 'data-is-open': attributes.isOpen };
                }
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="toggle-block"]',
                getAttrs: element => ({
                    title: element.getAttribute('data-title'),
                    isOpen: element.getAttribute('data-is-open') === 'true'
                }),
                contentElement: '.toggle-content'
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        return [
            'div',
            {
                'data-type': 'toggle-block',
                'class': 'toggle-block',
                'data-title': node.attrs.title,
                'data-is-open': node.attrs.isOpen
            },
            ['div', { class: 'toggle-header', contenteditable: 'false' },
                ['span', { class: 'toggle-btn' }, node.attrs.isOpen ? '▼' : '▶'],
                ['div', { class: 'toggle-title' }, node.attrs.title]
            ],
            ['div', { class: 'toggle-content', style: node.attrs.isOpen ? '' : 'display: none;' }, 0]
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'toggle-block-wrapper';
            wrapper.setAttribute('data-is-open', node.attrs.isOpen);

            const header = document.createElement('div');
            header.className = 'toggle-header';
            header.contentEditable = 'false'; 

            const toggleBtn = document.createElement('button');
            toggleBtn.className = 'toggle-btn';
            toggleBtn.type = 'button';
            toggleBtn.innerHTML = node.attrs.isOpen ? '▼' : '▶';
            if (node.attrs.isOpen) toggleBtn.classList.add('open');

            const title = document.createElement('div');
            title.className = 'toggle-title';
            title.textContent = node.attrs.title || '토글 목록';
            title.spellcheck = false;
            title.contentEditable = editor.isEditable ? 'true' : 'false';
            
            if (!node.attrs.title && editor.isEditable) {
                title.classList.add('empty');
            }

            header.appendChild(toggleBtn);
            header.appendChild(title);

            const contentContainer = document.createElement('div');
            contentContainer.className = 'toggle-content';
            
            if (!node.attrs.isOpen) {
                contentContainer.style.display = 'none';
            }

            wrapper.appendChild(header);
            wrapper.appendChild(contentContainer);


            const toggleOpen = () => {
                const isOpen = !wrapper.getAttribute('data-is-open') || wrapper.getAttribute('data-is-open') === 'false';
                const newState = !isOpen ? false : true; 

                if (newState) {
                    contentContainer.style.display = 'block';
                    toggleBtn.innerHTML = '▼';
                    toggleBtn.classList.add('open');
                } else {
                    contentContainer.style.display = 'none';
                    toggleBtn.innerHTML = '▶';
                    toggleBtn.classList.remove('open');
                }
                wrapper.setAttribute('data-is-open', newState);

                if (typeof getPos === 'function') {
                    const pos = getPos();
                    editor.view.dispatch(
                        editor.view.state.tr.setNodeMarkup(pos, null, {
                            ...node.attrs,
                            isOpen: newState
                        })
                    );
                }
            };

            toggleBtn.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                toggleOpen();
            };

            title.onfocus = () => {
                title.classList.add('focused');
                if (title.classList.contains('empty')) {
                    title.textContent = '';
                    title.classList.remove('empty');
                }
            };

            title.onblur = () => {
                title.classList.remove('focused');
                const text = title.textContent.trim();
                
                if (!text) {
                    title.textContent = '토글 목록';
                    title.classList.add('empty');
                }

                if (typeof getPos === 'function') {
                    const titleToSave = text === '토글 목록' && title.classList.contains('empty') ? '' : text;
                    
                    if (titleToSave !== node.attrs.title) {
                        editor.view.dispatch(
                            editor.view.state.tr.setNodeMarkup(getPos(), null, {
                                ...node.attrs,
                                title: titleToSave
                            })
                        );
                    }
                }
            };

            title.onkeydown = (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (wrapper.getAttribute('data-is-open') !== 'true') {
                        toggleOpen();
                    }
                    
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        editor.commands.focus(pos + node.nodeSize - 2); 
                        
                        const tr = editor.state.tr;
                        
                        const resolvePos = editor.state.doc.resolve(pos + 1);
                        
                        editor.commands.focus(pos + 2); 
                    }
                }
            };
            
            
            return {
                dom: wrapper,
                contentDOM: contentContainer, 

                update(updatedNode) {
                    if (updatedNode.type !== node.type) return false;

                    if (updatedNode.attrs.isOpen !== (wrapper.getAttribute('data-is-open') === 'true')) {
                        const isOpen = updatedNode.attrs.isOpen;
                        if (isOpen) {
                            contentContainer.style.display = 'block';
                            toggleBtn.innerHTML = '▼';
                            toggleBtn.classList.add('open');
                        } else {
                            contentContainer.style.display = 'none';
                            toggleBtn.innerHTML = '▶';
                            toggleBtn.classList.remove('open');
                        }
                        wrapper.setAttribute('data-is-open', isOpen);
                    }

                    if (updatedNode.attrs.title !== title.textContent && document.activeElement !== title) {
                        title.textContent = updatedNode.attrs.title || '토글 목록';
                        if (!updatedNode.attrs.title) title.classList.add('empty');
                        else title.classList.remove('empty');
                    }

                    node = updatedNode; 
                    return true;
                },

                stopEvent(event) {
                    const target = event.target;
                    if (target === title || target === toggleBtn) {
                        return true; 
                    }
                    return false;
                },
                
                ignoreMutation(mutation) {
                    if (!contentContainer.contains(mutation.target)) {
                        return true;
                    }
                    return false;
                }
            };
        };
    },

    addCommands() {
        return {
            setToggleBlock: (title = '', isOpen = true) => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: { title, isOpen },
                    content: [
                        {
                            type: 'paragraph',
                            content: []
                        }
                    ]
                });
            }
        };
    }
});