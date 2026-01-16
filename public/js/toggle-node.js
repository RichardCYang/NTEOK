/**
 * Tiptap Toggle List Node Extension
 * 접고 펼칠 수 있는 토글 리스트 블록 (제목 + 내용)
 * 내용 영역에 다른 블록(슬래시 메뉴 포함)을 중첩할 수 있도록 구현
 */

const Node = Tiptap.Core.Node;

export const ToggleBlock = Node.create({
    name: 'toggleBlock',

    group: 'block',

    // atom: true를 제거하고 content 정의를 추가하여 중첩 블록 허용
    content: 'block+', // 최소 1개의 블록이 있어야 함

    defining: true, // 블록의 내용을 유지하려는 성질

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
                default: true, // 생성 시 기본적으로 열려있도록 설정
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
                // HTML 파싱 시 .toggle-content 내부의 내용을 자식 노드로 인식
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
            // 헤더 영역 (제목) - renderHTML은 직렬화용이므로 단순 구조만 반환
            ['div', { class: 'toggle-header', contenteditable: 'false' },
                ['span', { class: 'toggle-btn' }, node.attrs.isOpen ? '▼' : '▶'],
                ['div', { class: 'toggle-title' }, node.attrs.title]
            ],
            // 내용 영역 (자식 노드들이 들어갈 구멍: 0)
            ['div', { class: 'toggle-content', style: node.attrs.isOpen ? '' : 'display: none;' }, 0]
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            // 전체 wrapper
            const wrapper = document.createElement('div');
            wrapper.className = 'toggle-block-wrapper';
            wrapper.setAttribute('data-is-open', node.attrs.isOpen);

            // 헤더 생성
            const header = document.createElement('div');
            header.className = 'toggle-header';
            header.contentEditable = 'false'; // 헤더 자체는 편집 불가 (내부 타이틀은 별도 처리)

            // 토글 버튼 (화살표)
            const toggleBtn = document.createElement('button');
            toggleBtn.className = 'toggle-btn';
            toggleBtn.type = 'button';
            toggleBtn.innerHTML = node.attrs.isOpen ? '▼' : '▶';
            if (node.attrs.isOpen) toggleBtn.classList.add('open');

            // 제목 입력 필드
            const title = document.createElement('div');
            title.className = 'toggle-title';
            title.textContent = node.attrs.title || '토글 목록';
            title.spellcheck = false;
            title.contentEditable = editor.isEditable ? 'true' : 'false';
            
            // 제목 플레이스홀더 처리
            if (!node.attrs.title && editor.isEditable) {
                title.classList.add('empty');
            }

            header.appendChild(toggleBtn);
            header.appendChild(title);

            // 내용 컨테이너 (contentDOM이 들어갈 곳)
            const contentContainer = document.createElement('div');
            contentContainer.className = 'toggle-content';
            
            // 초기 상태 반영
            if (!node.attrs.isOpen) {
                contentContainer.style.display = 'none';
            }

            wrapper.appendChild(header);
            wrapper.appendChild(contentContainer);

            // ============================================================
            // 이벤트 핸들러
            // ============================================================

            // 토글 상태 변경 함수
            const toggleOpen = () => {
                const isOpen = !wrapper.getAttribute('data-is-open') || wrapper.getAttribute('data-is-open') === 'false';
                const newState = !isOpen ? false : true; // 문자열 파싱 주의

                // DOM 업데이트
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

                // ProseMirror 상태 업데이트
                if (typeof getPos === 'function') {
                    const pos = getPos();
                    // 트랜잭션으로 상태 저장
                    editor.view.dispatch(
                        editor.view.state.tr.setNodeMarkup(pos, null, {
                            ...node.attrs,
                            isOpen: newState
                        })
                    );
                }
            };

            // 버튼 클릭 시 토글
            toggleBtn.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                toggleOpen();
            };

            // 제목 편집 이벤트
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
                
                // 비어있으면 기본 텍스트 표시 (시각적으로만)
                if (!text) {
                    title.textContent = '토글 목록';
                    title.classList.add('empty');
                }

                // 변경사항 저장
                if (typeof getPos === 'function') {
                    // 실제 저장할 때는 기본 텍스트가 아닌 빈 문자열이나 입력된 값 저장
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

            // 제목 입력 중 엔터 키 처리 -> 내용 영역으로 포커스 이동
            title.onkeydown = (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    // 토글이 닫혀있으면 열기
                    if (wrapper.getAttribute('data-is-open') !== 'true') {
                        toggleOpen();
                    }
                    
                    // 내용 영역의 첫 번째 블록으로 포커스 이동 시도
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        // 현재 노드 위치 + 1 (contentDOM 진입) 등 계산 필요하지만
                        // TipTap의 commands를 사용하는 것이 안전
                        // 여기서는 간단히 다음 틱에 에디터 포커스를 맞추도록 유도
                        editor.commands.focus(pos + node.nodeSize - 2); // 대략적인 끝 위치? 정확하지 않을 수 있음
                        
                        // 더 정확한 방법: NodeSelection이나 TextSelection을 사용하여 내부로 이동
                        const tr = editor.state.tr;
                        // 컨텐츠 시작 위치: pos + 1 (개작 괄호) + 헤더 크기? 
                        // NodeView 구조상 정확한 내부 위치 계산은 getPos() + 1 (Node start)
                        // 하지만 contentDOM이 있으므로 ProseMirror가 관리하는 자식 노드 시작점은 getPos() + 1
                        
                        // 자식이 있다면 첫 자식의 시작점으로
                        const resolvePos = editor.state.doc.resolve(pos + 1);
                        // nodeAt(pos).content.size > 0
                        
                        editor.commands.focus(pos + 2); // 대략적으로 내부 진입
                    }
                }
            };
            
            // 제목 영역 이벤트 전파 차단 (TipTap이 편집을 가로채지 않도록)
            // contentDOM 내부의 이벤트는 차단하면 안 됨!
            
            return {
                dom: wrapper,
                contentDOM: contentContainer, // 이 부분이 중요: 자식 노드들이 렌더링될 위치

                update(updatedNode) {
                    if (updatedNode.type !== node.type) return false;

                    // 속성 업데이트 반영
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

                    node = updatedNode; // 내부 노드 참조 갱신
                    return true;
                },

                stopEvent(event) {
                    const target = event.target;
                    // 제목 입력 필드나 토글 버튼에서의 이벤트는 에디터가 처리하지 않도록 차단
                    // 단, contentDOM 내부(contentContainer의 자식들)의 이벤트는 통과시켜야 함
                    if (target === title || target === toggleBtn) {
                        // 제목에서 Enter, ArrowDown 등은 에디터 동작과 연동하고 싶을 수 있으나
                        // 여기서는 간단히 제목 편집을 위해 차단하고 필요한 키만 수동 처리
                        return true; 
                    }
                    return false;
                },
                
                ignoreMutation(mutation) {
                    // contentDOM 내부의 변경은 ProseMirror가 처리해야 함
                    // wrapper나 header의 변경은 무시
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