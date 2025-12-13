/**
 * Tiptap Math Node Extension
 * LaTeX 수식을 렌더링하는 커스텀 노드
 */

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
                'class': 'math-block'
            }
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            // 전체 wrapper
            const wrapper = document.createElement('div');
            wrapper.className = 'math-block-wrapper';
            wrapper.contentEditable = 'false';

            let isEditing = false;
            let currentLatex = node.attrs.latex || '';

            // 렌더링된 수식을 표시하는 함수
            const showRendered = () => {
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
                    if (!isEditing && editor.isEditable) {
                        showEditor();
                    }
                };

                wrapper.appendChild(rendered);
            };

            // 편집기를 표시하는 함수
            const showEditor = () => {
                isEditing = true;
                wrapper.innerHTML = '';

                const editorContainer = document.createElement('div');
                editorContainer.className = 'math-editor-container';

                const textarea = document.createElement('textarea');
                textarea.className = 'math-input';
                textarea.placeholder = 'LaTeX 수식을 입력하세요 (예: x = \\frac{-b \\pm \\sqrt{b^2-4ac}}{2a})';
                textarea.value = currentLatex;
                textarea.rows = 5;

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

                // textarea에 포커스 - 더 강력한 포커스 처리
                const focusTextarea = () => {
                    textarea.focus();
                    textarea.selectionStart = textarea.value.length;
                    textarea.selectionEnd = textarea.value.length;
                };

                // 즉시 포커스 시도
                requestAnimationFrame(() => {
                    focusTextarea();
                });

                // editorContainer 클릭 시에도 포커스 보장
                editorContainer.onclick = (e) => {
                    if (e.target === editorContainer) {
                        focusTextarea();
                    }
                };

                // 모든 키보드 이벤트를 textarea 내부에서만 처리 (슬래시 메뉴 등 차단)
                textarea.onkeydown = (e) => {
                    e.stopPropagation(); // 에디터로 이벤트 전파 차단

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
                    e.stopPropagation(); // 에디터로 이벤트 전파 차단
                };

                textarea.onkeypress = (e) => {
                    e.stopPropagation(); // 에디터로 이벤트 전파 차단
                };

                // textarea가 포커스를 잃을 때 자동 저장
                textarea.onblur = () => {
                    // 약간의 지연을 두어 버튼 클릭이 먼저 처리되도록 함
                    setTimeout(() => {
                        if (isEditing) {
                            currentLatex = textarea.value;
                            saveAndClose();
                        }
                    }, 200);
                };
            };

            // 저장하고 렌더링 모드로 전환
            const saveAndClose = () => {
                // 편집 모드 종료
                isEditing = false;

                // 에디터에 저장 - 트랜잭션으로 노드 교체
                if (typeof getPos === 'function') {
                    const pos = getPos();

                    try {
                        const tr = editor.view.state.tr;
                        const newNode = editor.view.state.schema.nodes.mathBlock.create({
                            latex: currentLatex
                        });

                        tr.replaceWith(pos, pos + node.nodeSize, newNode);
                        editor.view.dispatch(tr);

                        // 트랜잭션 후 렌더링 모드로 전환
                        showRendered();
                    } catch (error) {
                        console.error('노드 교체 실패:', error);
                        // 실패하면 직접 렌더링
                        showRendered();
                    }
                } else {
                    // getPos가 없으면 직접 렌더링만 수행
                    showRendered();
                }
            };

            // 초기 렌더링
            showRendered();

            return {
                dom: wrapper,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) {
                        return false;
                    }
                    // 편집 중이 아닐 때만 업데이트
                    if (!isEditing) {
                        // updatedNode.attrs.latex가 정의되어 있을 때만 업데이트
                        if (updatedNode.attrs.latex !== undefined) {
                            currentLatex = updatedNode.attrs.latex;
                            showRendered();
                        }
                    }
                    return true;
                },
                destroy: () => {
                    // 노드가 파괴될 때 (읽기 모드로 전환 시) 편집 중이면 저장
                    if (isEditing && wrapper.querySelector('.math-input')) {
                        const textarea = wrapper.querySelector('.math-input');
                        if (textarea && textarea.value !== currentLatex) {
                            currentLatex = textarea.value;

                            // 노드 속성 업데이트
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
                    // 모든 이벤트를 내부에서 처리
                    return true;
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
                'class': 'math-inline'
            },
            node.attrs.latex || ''
        ];
    },

    addInputRules() {
        return [
            // $...$ 패턴을 인라인 수식으로 변환
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
            // 단순한 렌더링 전용 뷰
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

            // 클릭 시 커서 캡처 방지
            dom.onmousedown = (e) => {
                e.preventDefault();
            };

            return {
                dom,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) {
                        return false;
                    }
                    // 내용 변경 시 재렌더링
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
