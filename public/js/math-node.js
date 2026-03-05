
const Node = Tiptap.Core.Node;

export const MathBlock = Node.create({
    name: 'mathBlock',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            latex: {
                default: '',
                parseHTML: element => element.getAttribute('data-latex') || '',
                renderHTML: attributes => {
                    if (!attributes.latex) {
                        return {};
                    }
                    return {
                        'data-latex': attributes.latex
                    };
                }
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="math-block"]'
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        return [
            'div',
            {
                ...HTMLAttributes,
                'data-type': 'math-block',
                'class': 'math-block',
                'data-latex': node.attrs.latex || ''
            }
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'math-block-wrapper';
            wrapper.contentEditable = 'false';

            let isEditing = false;
            let currentLatex = node.attrs.latex || '';
            let autoSaveTimeout = null; 

            const showRendered = () => {
                if (autoSaveTimeout) {
                    clearTimeout(autoSaveTimeout);
                    autoSaveTimeout = null;
                }

                wrapper.innerHTML = '';

                const rendered = document.createElement('div');
                rendered.className = 'math-rendered';

                try {
                    if (window.katex && currentLatex) {
                        window.katex.render(currentLatex, rendered, {
                            displayMode: true,
                            throwOnError: false,
                            errorColor: '#cc0000'
                        });
                    } else {
                        rendered.textContent = currentLatex || '수식을 입력하려면 클릭하세요';
                    }
                } catch (error) {
                    rendered.textContent = '수식 렌더링 오류: ' + error.message;
                }

                rendered.onclick = () => {
                    if (!isEditing) {
                        if (editor.isEditable) {
                            showEditor();
                        }
                    }
                };

                wrapper.appendChild(rendered);
            };

            const showEditor = () => {
                isEditing = true;

                if (autoSaveTimeout) {
                    clearTimeout(autoSaveTimeout);
                    autoSaveTimeout = null;
                }

                wrapper.innerHTML = '';

                const editorContainer = document.createElement('div');
                editorContainer.className = 'math-editor-container';

                const textarea = document.createElement('textarea');
                textarea.className = 'math-input';
                textarea.placeholder = 'LaTeX 수식을 입력하세요 (예: x = \\frac{-b \\pm \\sqrt{b^2-4ac}}{2a})';
                textarea.value = currentLatex;
                textarea.rows = 5;

                textarea.oninput = (e) => {
                    e.stopPropagation();

                    if (autoSaveTimeout) {
                        clearTimeout(autoSaveTimeout);
                    }

                    autoSaveTimeout = setTimeout(() => {
                        currentLatex = textarea.value;

                        if (typeof getPos === 'function') {
                            const pos = getPos();
                            try {
                                const tr = editor.view.state.tr;
                                tr.setNodeMarkup(pos, null, { latex: currentLatex });
                                editor.view.dispatch(tr);
                            } catch (error) {
                                console.error('[MathBlock] 자동 저장 실패:', error);
                            }
                        }
                    }, 500);
                };

                const buttonContainer = document.createElement('div');
                buttonContainer.className = 'math-button-container';

                const saveButton = document.createElement('button');
                saveButton.textContent = '저장';
                saveButton.className = 'math-save-button';
                saveButton.onclick = () => {
                    currentLatex = textarea.value;
                    saveAndClose();
                };

                const cancelButton = document.createElement('button');
                cancelButton.textContent = '취소';
                cancelButton.className = 'math-cancel-button';
                cancelButton.onclick = () => {
                    isEditing = false;
                    showRendered();
                };

                buttonContainer.appendChild(saveButton);
                buttonContainer.appendChild(cancelButton);

                editorContainer.appendChild(textarea);
                editorContainer.appendChild(buttonContainer);
                wrapper.appendChild(editorContainer);

                const focusTextarea = () => {
                    textarea.focus();
                    textarea.selectionStart = textarea.value.length;
                    textarea.selectionEnd = textarea.value.length;

                    setTimeout(() => {
                        if (document.activeElement !== textarea) {
                            console.warn('[MathBlock] 포커스 실패, activeElement:', document.activeElement);
                        }
                    }, 100);
                };

                requestAnimationFrame(() => {
                    focusTextarea();
                });

                editorContainer.onclick = (e) => {
                    if (e.target === editorContainer) {
                        focusTextarea();
                    }
                };

                textarea.onkeydown = (e) => {
                    e.stopPropagation(); 

                    if (e.key === 'Enter' && e.ctrlKey) {
                        e.preventDefault();
                        currentLatex = textarea.value;
                        saveAndClose();
                    }
                    if (e.key === 'Escape') {
                        e.preventDefault();
                        isEditing = false;
                        showRendered();
                    }
                };

                textarea.onkeyup = (e) => {
                    e.stopPropagation(); 
                };

                textarea.onkeypress = (e) => {
                    e.stopPropagation(); 
                };

                textarea.onblur = () => {
                    setTimeout(() => {
                        if (isEditing) {
                            currentLatex = textarea.value;
                            saveAndClose();
                        }
                    }, 200);
                };
            };

            const saveAndClose = () => {
                isEditing = false;

                if (typeof getPos === 'function') {
                    const pos = getPos();

                    try {
                        const tr = editor.view.state.tr;
                        const newNode = editor.view.state.schema.nodes.mathBlock.create({
                            latex: currentLatex
                        });

                        tr.replaceWith(pos, pos + node.nodeSize, newNode);
                        editor.view.dispatch(tr);

                        showRendered();
                    } catch (error) {
                        console.error('노드 교체 실패:', error);
                        showRendered();
                    }
                } else {
                    showRendered();
                }
            };

            showRendered();

            return {
                dom: wrapper,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) {
                        return false;
                    }

                    if (!isEditing) {
                        if (updatedNode.attrs.latex !== undefined) {
                            currentLatex = updatedNode.attrs.latex;
                            showRendered();
                        }
                    }
                    return true;
                },
                destroy: () => {
                    if (isEditing && wrapper.querySelector('.math-input')) {
                        const textarea = wrapper.querySelector('.math-input');
                        if (textarea && textarea.value !== currentLatex) {
                            currentLatex = textarea.value;

                            if (typeof getPos === 'function') {
                                const pos = getPos();
                                try {
                                    editor.view.dispatch(
                                        editor.view.state.tr.setNodeMarkup(pos, null, {
                                            latex: currentLatex
                                        })
                                    );
                                } catch (error) {
                                    console.error('destroy에서 노드 업데이트 실패:', error);
                                }
                            }
                        }
                    }
                },
                stopEvent: () => {
                    return true;
                },
                ignoreMutation: () => {
                    return true;
                }
            };
        };
    },

    addCommands() {
        return {
            setMathBlock: (latex = '') => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: { latex }
                });
            }
        };
    }
});

const { InputRule } = Tiptap.Core;

export const MathInline = Node.create({
    name: 'mathInline',

    group: 'inline',

    inline: true,

    atom: true,

    addAttributes() {
        return {
            latex: {
                default: '',
                parseHTML: element => element.getAttribute('data-latex') || '',
                renderHTML: attributes => {
                    if (!attributes.latex) {
                        return {};
                    }
                    return {
                        'data-latex': attributes.latex
                    };
                }
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'span[data-type="math-inline"]'
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        return [
            'span',
            {
                ...HTMLAttributes,
                'data-type': 'math-inline',
                'class': 'math-inline',
                'data-latex': node.attrs.latex || ''
            },
            node.attrs.latex || ''
        ];
    },

    addInputRules() {
        return [
            new InputRule({
                find: /\$([^\$\n]+)\$$/,
                handler: ({ state, range, match, commands }) => {
                    const latex = match[1];

                    if (latex) {
                        commands.insertContentAt(range, {
                            type: this.name,
                            attrs: { latex }
                        });
                    }
                }
            })
        ];
    },

    addNodeView() {
        return ({ node }) => {
            const dom = document.createElement('span');
            dom.className = 'math-inline-view';
            dom.contentEditable = 'false';

            const latex = node.attrs.latex || '';

            try {
                if (window.katex && latex) {
                    window.katex.render(latex, dom, {
                        displayMode: false,
                        throwOnError: false,
                        errorColor: '#cc0000'
                    });
                } else {
                    dom.textContent = latex || '$수식$';
                }
            } catch (error) {
                dom.textContent = latex || '오류';
            }

            dom.onmousedown = (e) => {
                e.preventDefault();
            };

            return {
                dom,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) {
                        return false;
                    }
                    const newLatex = updatedNode.attrs.latex || '';
                    try {
                        if (window.katex && newLatex) {
                            dom.innerHTML = '';
                            window.katex.render(newLatex, dom, {
                                displayMode: false,
                                throwOnError: false,
                                errorColor: '#cc0000'
                            });
                        } else {
                            dom.textContent = newLatex || '$수식$';
                        }
                    } catch (error) {
                        dom.textContent = newLatex || '오류';
                    }
                    return true;
                }
            };
        };
    },

    addCommands() {
        return {
            setMathInline: (latex = '') => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: { latex }
                });
            }
        };
    }
});
