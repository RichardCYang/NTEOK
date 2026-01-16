/**
 * Tiptap Board View Extension
 * 칸반 보드 블록
 */

import { addIcon } from './ui-utils.js';

const Node = Tiptap.Core.Node;

// 아이콘 선택용 기본 아이콘 목록
const BOARD_THEME_ICONS = [
    'fa-solid fa-star', 'fa-solid fa-heart', 'fa-solid fa-flag', 'fa-solid fa-bookmark',
    'fa-solid fa-circle-check', 'fa-solid fa-circle-info', 'fa-solid fa-circle-exclamation', 'fa-solid fa-circle-xmark',
    'fa-solid fa-lightbulb', 'fa-solid fa-fire', 'fa-solid fa-bolt', 'fa-solid fa-bell',
    'fa-solid fa-user', 'fa-solid fa-users', 'fa-solid fa-calendar', 'fa-solid fa-clock',
    'fa-solid fa-tag', 'fa-solid fa-tags', 'fa-solid fa-trophy', 'fa-solid fa-gift'
];

const BOARD_EMOJI_ICONS = [
    '⭐', '❤️', '🚩', '🔖', '✅', 'ℹ️', '⚠️', '❌',
    '💡', '🔥', '⚡', '🔔', '👤', '👥', '📅', '⏰',
    '🏷️', '🎯', '🏆', '🎁'
];

export const BoardBlock = Node.create({
    name: 'boardBlock',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            columns: {
                default: [
                    { id: 'todo', title: '할 일', cards: [] },
                    { id: 'doing', title: '진행 중', cards: [] },
                    { id: 'done', title: '완료', cards: [] }
                ],
                parseHTML: element => {
                    const data = element.getAttribute('data-columns');
                    try {
                        return data ? JSON.parse(data) : null;
                    } catch (e) {
                        return null;
                    }
                },
                renderHTML: attributes => {
                    return {
                        'data-columns': JSON.stringify(attributes.columns)
                    };
                }
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="board-block"]'
            }
        ];
    },

    renderHTML({ HTMLAttributes }) {
        return ['div', { ...HTMLAttributes, 'data-type': 'board-block', class: 'board-block' }];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            const container = document.createElement('div');
            container.className = 'board-container';
            container.contentEditable = 'false';

            // 상태 관리
            let columns = JSON.parse(JSON.stringify(node.attrs.columns)); // 깊은 복사
            let draggedCardId = null;
            let draggedFromColId = null;
            let lastIsEditable = editor.isEditable; // 편집 모드 상태 추적

            // 데이터 저장 함수
            const saveData = () => {
                if (typeof getPos === 'function') {
                    const pos = getPos();
                    try {
                        // 불필요한 트랜잭션 방지를 위해 현재 데이터와 비교
                        const currentAttrs = editor.state.doc.nodeAt(pos).attrs;
                        if (JSON.stringify(currentAttrs.columns) === JSON.stringify(columns)) {
                            return;
                        }

                        const tr = editor.view.state.tr;
                        tr.setNodeMarkup(pos, null, { columns });
                        editor.view.dispatch(tr);
                    } catch (error) {
                        console.error('[BoardBlock] 데이터 저장 실패:', error);
                    }
                }
            };

            // 아이콘 선택 팝업 생성 함수
            const showIconPickerPopup = (targetEl, onSelect) => {
                if (!editor.isEditable) return;

                // 기존 팝업 제거
                const existingPopup = document.querySelector('.board-icon-picker-popup');
                if (existingPopup) existingPopup.remove();

                const popup = document.createElement('div');
                popup.className = 'board-icon-picker-popup';
                popup.style.cssText = `
                    position: absolute;
                    background: var(--primary-color, white);
                    border: 1px solid var(--border-color, #ccc);
                    border-radius: 8px;
                    padding: 8px;
                    z-index: 10000;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    max-width: 250px;
                `;

                // 탭 버튼
                const tabContainer = document.createElement('div');
                tabContainer.style.cssText = 'display: flex; gap: 4px; margin-bottom: 8px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px;';

                const themeTab = document.createElement('button');
                themeTab.textContent = '테마';
                themeTab.style.cssText = 'flex: 1; padding: 4px; border: none; background: var(--secondary-color); cursor: pointer; border-radius: 4px; font-size: 11px; color: var(--font-color);';

                const emojiTab = document.createElement('button');
                emojiTab.textContent = '이모지';
                emojiTab.style.cssText = 'flex: 1; padding: 4px; border: none; background: transparent; cursor: pointer; border-radius: 4px; font-size: 11px; color: var(--font-color);';

                tabContainer.appendChild(themeTab);
                tabContainer.appendChild(emojiTab);
                popup.appendChild(tabContainer);

                const grid = document.createElement('div');
                grid.style.cssText = 'display: grid; grid-template-columns: repeat(5, 1fr); gap: 4px; max-height: 150px; overflow-y: auto;';

                const renderGrid = (tab) => {
                    grid.innerHTML = '';
                    const icons = tab === 'theme' ? BOARD_THEME_ICONS : BOARD_EMOJI_ICONS;
                    
                    themeTab.style.background = tab === 'theme' ? 'var(--secondary-color)' : 'transparent';
                    emojiTab.style.background = tab === 'emoji' ? 'var(--secondary-color)' : 'transparent';

                    icons.forEach(iconValue => {
                        const btn = document.createElement('button');
                        btn.style.cssText = 'padding: 6px; border: 1px solid var(--border-color); background: var(--primary-color); cursor: pointer; border-radius: 4px; font-size: 14px; display: flex; align-items: center; justify-content: center; color: var(--font-color);';
                        
                        if (tab === 'theme') {
                            addIcon(btn, iconValue);
                        } else {
                            btn.textContent = iconValue;
                        }

                        btn.onclick = (e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            onSelect(iconValue);
                            popup.remove();
                        };
                        grid.appendChild(btn);
                    });
                };

                renderGrid('theme');
                themeTab.onclick = (e) => { e.stopPropagation(); renderGrid('theme'); };
                emojiTab.onclick = (e) => { e.stopPropagation(); renderGrid('emoji'); };

                // 삭제 버튼 추가
                const removeBtn = document.createElement('button');
                removeBtn.textContent = '아이콘 삭제';
                removeBtn.style.cssText = 'width: 100%; margin-top: 8px; padding: 4px; border: none; background: var(--secondary-color); color: var(--danger-color, #ef4444); cursor: pointer; border-radius: 4px; font-size: 11px;';
                removeBtn.onclick = (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    onSelect(null);
                    popup.remove();
                };
                popup.appendChild(grid);
                popup.appendChild(removeBtn);

                document.body.appendChild(popup);
                const rect = targetEl.getBoundingClientRect();
                popup.style.left = `${rect.left}px`;
                popup.style.top = `${rect.bottom + 5}px`;

                // 외부 클릭 시 닫기
                const closePopup = (e) => {
                    if (!popup.contains(e.target) && !targetEl.contains(e.target)) {
                        popup.remove();
                        document.removeEventListener('mousedown', closePopup);
                    }
                };
                document.addEventListener('mousedown', closePopup);
            };

            // 렌더링 함수
            const render = () => {
                lastIsEditable = editor.isEditable; // 현재 상태 저장
                container.innerHTML = '';

                // 컬럼 컨테이너
                const columnsWrapper = document.createElement('div');
                columnsWrapper.className = 'board-columns-wrapper';

                columns.forEach(column => {
                    const colEl = document.createElement('div');
                    colEl.className = 'board-column';
                    colEl.dataset.colId = column.id;

                    // 헤더
                    const header = document.createElement('div');
                    header.className = 'board-column-header';

                    const titleInput = document.createElement('input');
                    titleInput.className = 'board-column-title';
                    titleInput.value = column.title;
                    titleInput.placeholder = '컬럼 제목';
                    
                    if (editor.isEditable) {
                        titleInput.onchange = (e) => {
                            column.title = e.target.value;
                            saveData();
                        };
                    } else {
                        titleInput.readOnly = true;
                    }

                    // 컬럼 삭제 버튼 (옵션)
                    const deleteColBtn = document.createElement('button');
                    deleteColBtn.className = 'board-column-delete-btn';
                    deleteColBtn.innerHTML = '×';
                    deleteColBtn.title = '컬럼 삭제';
                    if (editor.isEditable) {
                        deleteColBtn.onclick = () => {
                            if (confirm('이 컬럼과 포함된 모든 카드를 삭제하시겠습니까?')) {
                                columns = columns.filter(c => c.id !== column.id);
                                saveData();
                                render(); // 전체 다시 렌더링
                            }
                        };
                    } else {
                        deleteColBtn.style.display = 'none';
                    }

                    header.appendChild(titleInput);
                    header.appendChild(deleteColBtn);
                    colEl.appendChild(header);

                    // 카드 리스트
                    const cardList = document.createElement('div');
                    cardList.className = 'board-card-list';
                    cardList.dataset.colId = column.id;

                    // 드래그 앤 드롭 이벤트 (리스트 영역)
                    if (editor.isEditable) {
                        cardList.ondragover = (e) => {
                            e.preventDefault();
                            cardList.classList.add('drag-over');
                        };
                        cardList.ondragleave = () => {
                            cardList.classList.remove('drag-over');
                        };
                        cardList.ondrop = (e) => {
                            e.preventDefault();
                            cardList.classList.remove('drag-over');
                            if (!draggedCardId || !draggedFromColId) return;

                            const toColId = column.id;
                            
                            // 원본 찾기 및 제거
                            const fromCol = columns.find(c => c.id === draggedFromColId);
                            const cardIndex = fromCol.cards.findIndex(c => c.id === draggedCardId);
                            if (cardIndex === -1) return;
                            const [card] = fromCol.cards.splice(cardIndex, 1);

                            // 대상 컬럼에 추가
                            const toCol = columns.find(c => c.id === toColId);
                            toCol.cards.push(card);

                            draggedCardId = null;
                            draggedFromColId = null;
                            saveData();
                            render();
                        };
                    }

                    column.cards.forEach(card => {
                        const cardEl = document.createElement('div');
                        cardEl.className = 'board-card';
                        cardEl.draggable = editor.isEditable;
                        cardEl.dataset.cardId = card.id;

                        if (editor.isEditable) {
                            cardEl.ondragstart = (e) => {
                                // 팝업이 열려있으면 닫기
                                const existingPopup = document.querySelector('.board-icon-picker-popup');
                                if (existingPopup) existingPopup.remove();

                                draggedCardId = card.id;
                                draggedFromColId = column.id;
                                e.dataTransfer.effectAllowed = 'move';
                                setTimeout(() => cardEl.classList.add('dragging'), 0);
                            };
                            cardEl.ondragend = () => {
                                cardEl.classList.remove('dragging');
                                draggedCardId = null;
                                draggedFromColId = null;
                            };
                        }

                        // 카드 상단 영역 (아이콘 + 삭제 버튼)
                        const cardHeader = document.createElement('div');
                        cardHeader.className = 'board-card-header';
                        cardHeader.style.display = 'flex';
                        cardHeader.style.justifyContent = 'space-between';
                        cardHeader.style.alignItems = 'flex-start';
                        cardHeader.style.marginBottom = '4px';

                        // 아이콘 영역
                        const iconBtn = document.createElement('div');
                        iconBtn.className = 'board-card-icon-btn';
                        iconBtn.style.cursor = editor.isEditable ? 'pointer' : 'default';
                        iconBtn.style.fontSize = '16px';
                        iconBtn.style.minWidth = '20px';
                        iconBtn.style.minHeight = '20px';
                        iconBtn.style.display = 'flex';
                        iconBtn.style.alignItems = 'center';

                        const renderIcon = () => {
                            iconBtn.innerHTML = '';
                            if (card.icon) {
                                if (card.icon.startsWith('fa-')) {
                                    const i = document.createElement('i');
                                    i.className = card.icon;
                                    iconBtn.appendChild(i);
                                } else {
                                    iconBtn.textContent = card.icon;
                                }
                            } else if (editor.isEditable) {
                                // 아이콘이 없지만 편집 모드일 때 투명한 아이콘 또는 플러스 표시 가능
                                iconBtn.innerHTML = '<i class="fa-regular fa-face-smile" style="opacity: 0.3;"></i>';
                            }
                        };
                        renderIcon();

                        if (editor.isEditable) {
                            iconBtn.onclick = (e) => {
                                e.stopPropagation();
                                showIconPickerPopup(iconBtn, (newIcon) => {
                                    card.icon = newIcon;
                                    renderIcon();
                                    saveData();
                                });
                            };
                        }

                        // 카드 삭제 버튼
                        const deleteCardBtn = document.createElement('button');
                        deleteCardBtn.className = 'board-card-delete-btn';
                        deleteCardBtn.innerHTML = '×';
                        if (editor.isEditable) {
                            deleteCardBtn.onclick = (e) => {
                                e.stopPropagation(); // 카드 드래그 방지
                                if (confirm('이 카드를 삭제하시겠습니까?')) {
                                    column.cards = column.cards.filter(c => c.id !== card.id);
                                    saveData();
                                    render();
                                }
                            };
                        } else {
                            deleteCardBtn.style.display = 'none';
                        }

                        cardHeader.appendChild(iconBtn);
                        cardHeader.appendChild(deleteCardBtn);
                        cardEl.appendChild(cardHeader);

                        const cardContent = document.createElement('div');
                        cardContent.className = 'board-card-content';
                        cardContent.contentEditable = editor.isEditable ? 'true' : 'false'; // 텍스트 편집 가능하게
                        cardContent.textContent = card.content;

                        // 카드 내용 수정 시 저장
                        if (editor.isEditable) {
                            cardContent.onblur = () => {
                                const newContent = cardContent.textContent;
                                if (newContent !== card.content) {
                                    card.content = newContent;
                                    saveData();
                                }
                            };
                            // Enter 키 방지 (줄바꿈 허용 여부에 따라 다름, 여기선 허용)
                            cardContent.onkeydown = (e) => {
                                e.stopPropagation(); // 에디터의 이벤트 간섭 방지
                            };
                        }

                        cardEl.appendChild(cardContent);
                        cardList.appendChild(cardEl);
                    });

                    colEl.appendChild(cardList);

                    // 카드 추가 버튼
                    if (editor.isEditable) {
                        const addCardBtn = document.createElement('button');
                        addCardBtn.className = 'board-add-card-btn';
                        addCardBtn.textContent = '+ 카드 추가';
                        addCardBtn.onclick = () => {
                            const newCard = {
                                id: 'card-' + Date.now() + Math.random().toString(36).substr(2, 9),
                                content: '새 카드',
                                icon: null
                            };
                            column.cards.push(newCard);
                            saveData();
                            render();
                        };
                        colEl.appendChild(addCardBtn);
                    }

                    columnsWrapper.appendChild(colEl);
                });

                // 컬럼 추가 버튼
                if (editor.isEditable) {
                    const addColBtn = document.createElement('button');
                    addColBtn.className = 'board-add-column-btn';
                    addColBtn.textContent = '+ 컬럼 추가';
                    addColBtn.onclick = () => {
                        const newCol = {
                            id: 'col-' + Date.now(),
                            title: '새 컬럼',
                            cards: []
                        };
                        columns.push(newCol);
                        saveData();
                        render();
                    };
                    columnsWrapper.appendChild(addColBtn);
                }

                container.appendChild(columnsWrapper);
            };

            // 초기 렌더링
            render();

            // 편집 모드 변경 감지 로직
            const checkEditable = () => {
                if (editor.isEditable !== lastIsEditable) {
                    render();
                }
            };

            // 1. Transaction 이벤트 리스너 (상태 변경 감지 보조)
            editor.on('transaction', checkEditable);

            // 2. MutationObserver (contenteditable 속성 변경 감지 - 확실한 방법)
            const observer = new MutationObserver((mutations) => {
                checkEditable();
            });
            
            if (editor.view && editor.view.dom) {
                observer.observe(editor.view.dom, { 
                    attributes: true, 
                    attributeFilter: ['contenteditable'] 
                });
            }

            return {
                dom: container,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== node.type.name) return false;
                    
                    const isEditableChanged = editor.isEditable !== lastIsEditable;
                    const isDataChanged = JSON.stringify(updatedNode.attrs.columns) !== JSON.stringify(columns);

                    if (isDataChanged || isEditableChanged) {
                        if (isDataChanged) {
                            columns = JSON.parse(JSON.stringify(updatedNode.attrs.columns));
                        }
                        render();
                    }
                    return true;
                },
                stopEvent: (event) => {
                    // 드래그 앤 드롭, 입력 이벤트 등이 에디터로 전파되지 않도록 차단
                    // contentEditable 영역 내의 이벤트는 허용해야 함
                    const target = event.target;
                    // 카드 내용 입력 중이거나 input 태그 등에서는 이벤트 전파 막기
                    if (target.classList.contains('board-card-content') || target.tagName === 'INPUT' || target.tagName === 'BUTTON' || target.closest('.board-icon-picker-popup')) {
                        return true;
                    }
                    return false;
                },
                ignoreMutation: (mutation) => {
                    // DOM 내부 변경은 ProseMirror가 무시하고 우리가 직접 관리
                    // 단, selection 변경 등은 허용해야 할 수도 있음
                    return !container.contains(mutation.target) || mutation.target === container;
                },
                destroy: () => {
                    editor.off('transaction', checkEditable);
                    observer.disconnect();
                }
            };
        };
    },

    addCommands() {
        return {
            setBoardBlock: () => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        columns: [
                            { id: 'todo', title: '할 일', cards: [] },
                            { id: 'doing', title: '진행 중', cards: [] },
                            { id: 'done', title: '완료', cards: [] }
                        ]
                    }
                });
            }
        };
    }
});
