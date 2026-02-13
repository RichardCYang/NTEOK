/**
 * Tiptap Calendar Node Extension
 * 날짜 선택 및 표시, 메모가 가능한 캘린더 블록
 */

const Node = Tiptap.Core.Node;

export const CalendarBlock = Node.create({
    name: 'calendarBlock',

    group: 'block',

    // 다시 atom: true로 설정 (BoardBlock과 동일한 방식)
    atom: true,

    addAttributes() {
        return {
            selectedDate: {
                default: new Date().toISOString().split('T')[0],
                parseHTML: element => element.getAttribute('data-selected-date'),
                renderHTML: attributes => {
                    return { 'data-selected-date': attributes.selectedDate };
                }
            },
            memos: {
                default: {},
                parseHTML: element => {
                    const memos = element.getAttribute('data-memos');
                    try {
                        return memos ? JSON.parse(memos) : {};
                    } catch (e) {
                        return {};
                    }
                },
                renderHTML: attributes => {
                    return { 'data-memos': JSON.stringify(attributes.memos) };
                }
            },
            width: {
                default: '100%',
                parseHTML: element => element.getAttribute('data-width') || '100%',
                renderHTML: attributes => {
                    return { 'data-width': attributes.width };
                }
            },
            align: {
                default: 'center',
                parseHTML: element => element.getAttribute('data-align') || 'center',
                renderHTML: attributes => {
                    return { 'data-align': attributes.align };
                }
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="calendar-block"]'
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        return [
            'div',
            {
                ...HTMLAttributes,
                'data-type': 'calendar-block',
                'class': 'calendar-block',
                'style': `width: ${node.attrs.width};`
            }
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'calendar-block-wrapper';
            wrapper.contentEditable = 'false';
            wrapper.style.width = node.attrs.width || '100%';
            wrapper.setAttribute('data-align', node.attrs.align || 'center');

            let selectedDateStr = node.attrs.selectedDate || new Date().toISOString().split('T')[0];
            let memos = { ...node.attrs.memos };
            let currentAlign = node.attrs.align || 'center';
            let currentViewDate = new Date(selectedDateStr);
            currentViewDate.setDate(1);

            let memoTimeout = null;

            // Alignment Menu
            const alignMenu = document.createElement('div');
            alignMenu.className = 'calendar-align-menu';
            alignMenu.style.display = editor.isEditable ? 'flex' : 'none';

            const createAlignIcon = (align) => {
                const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
                svg.setAttribute('width', '16');
                svg.setAttribute('height', '16');
                svg.setAttribute('viewBox', '0 0 16 16');
                svg.setAttribute('fill', 'currentColor');
                if (align === 'left') {
                    svg.innerHTML = '<rect x="2" y="3" width="12" height="2" rx="1"/><rect x="2" y="7" width="8" height="2" rx="1"/><rect x="2" y="11" width="10" height="2" rx="1"/>';
                } else if (align === 'center') {
                    svg.innerHTML = '<rect x="2" y="3" width="12" height="2" rx="1"/><rect x="4" y="7" width="8" height="2" rx="1"/><rect x="3" y="11" width="10" height="2" rx="1"/>';
                } else if (align === 'right') {
                    svg.innerHTML = '<rect x="2" y="3" width="12" height="2" rx="1"/><rect x="6" y="7" width="8" height="2" rx="1"/><rect x="4" y="11" width="10" height="2" rx="1"/>';
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
                button.onclick = (e) => {
                    e.preventDefault(); e.stopPropagation();
                    currentAlign = align;
                    wrapper.setAttribute('data-align', align);
                    alignMenu.querySelectorAll('.align-button').forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        editor.view.dispatch(editor.view.state.tr.setNodeMarkup(pos, null, { ...node.attrs, align }));
                    }
                };
                return button;
            };

            alignMenu.appendChild(createAlignButton('left', '왼쪽 정렬'));
            alignMenu.appendChild(createAlignButton('center', '가운데 정렬'));
            alignMenu.appendChild(createAlignButton('right', '오른쪽 정렬'));
            wrapper.appendChild(alignMenu);

            const renderCalendar = () => {
                // 입력 중일 때는 전체 재렌더링 차단 (포커스 유지 핵심)
                if (document.activeElement && document.activeElement.classList.contains('calendar-day-memo') && wrapper.contains(document.activeElement)) {
                    return;
                }

                Array.from(wrapper.childNodes).forEach(child => {
                    if (child !== alignMenu && !child.classList?.contains('calendar-resize-handle')) {
                        wrapper.removeChild(child);
                    }
                });

                const header = document.createElement('div');
                header.className = 'calendar-header';
                const title = document.createElement('div');
                title.className = 'calendar-title';
                const monthNames = ["1월", "2월", "3월", "4월", "5월", "6월", "7월", "8월", "9월", "10월", "11월", "12월"];
                title.textContent = `${currentViewDate.getFullYear()}년 ${monthNames[currentViewDate.getMonth()]}`;
                const nav = document.createElement('div');
                nav.className = 'calendar-nav';
                const prevBtn = document.createElement('button');
                prevBtn.className = 'calendar-nav-btn';
                prevBtn.innerHTML = '<i class="fa-solid fa-chevron-left"></i>';
                prevBtn.onclick = (e) => {
                    e.stopPropagation(); e.preventDefault();
                    currentViewDate.setMonth(currentViewDate.getMonth() - 1);
                    renderCalendar();
                };
                const nextBtn = document.createElement('button');
                nextBtn.className = 'calendar-nav-btn';
                nextBtn.innerHTML = '<i class="fa-solid fa-chevron-right"></i>';
                nextBtn.onclick = (e) => {
                    e.stopPropagation(); e.preventDefault();
                    currentViewDate.setMonth(currentViewDate.getMonth() + 1);
                    renderCalendar();
                };
                nav.appendChild(prevBtn);
                nav.appendChild(nextBtn);
                header.appendChild(title);
                header.appendChild(nav);
                wrapper.appendChild(header);

                const grid = document.createElement('div');
                grid.className = 'calendar-grid';
                ['일', '월', '화', '수', '목', '금', '토'].forEach(day => {
                    const label = document.createElement('div');
                    label.className = 'calendar-day-label';
                    label.textContent = day;
                    grid.appendChild(label);
                });

                const firstDayOfMonth = new Date(currentViewDate.getFullYear(), currentViewDate.getMonth(), 1).getDay();
                const lastDateOfMonth = new Date(currentViewDate.getFullYear(), currentViewDate.getMonth() + 1, 0).getDate();
                const lastDateOfPrevMonth = new Date(currentViewDate.getFullYear(), currentViewDate.getMonth(), 0).getDate();

                for (let i = firstDayOfMonth - 1; i >= 0; i--) {
                    const day = document.createElement('div');
                    day.className = 'calendar-day other-month';
                    const num = document.createElement('div');
                    num.className = 'calendar-day-number';
                    num.textContent = lastDateOfPrevMonth - i;
                    day.appendChild(num);
                    grid.appendChild(day);
                }

                const today = new Date();
                const todayStr = `${today.getFullYear()}-${String(today.getMonth() + 1).padStart(2, '0')}-${String(today.getDate()).padStart(2, '0')}`;

                for (let i = 1; i <= lastDateOfMonth; i++) {
                    const day = document.createElement('div');
                    day.className = 'calendar-day';
                    const dateStr = `${currentViewDate.getFullYear()}-${String(currentViewDate.getMonth() + 1).padStart(2, '0')}-${String(i).padStart(2, '0')}`;
                    
                    if (dateStr === selectedDateStr) day.classList.add('selected');
                    if (dateStr === todayStr) day.classList.add('today');

                    const num = document.createElement('div');
                    num.className = 'calendar-day-number';
                    num.textContent = i;
                    num.onclick = (e) => {
                        e.stopPropagation();
                        if (editor.isEditable) {
                            selectedDateStr = dateStr;
                            if (typeof getPos === 'function') {
                                const pos = getPos();
                                editor.view.dispatch(editor.view.state.tr.setNodeMarkup(pos, null, { ...node.attrs, selectedDate: dateStr }));
                            }
                        }
                    };
                    day.appendChild(num);

                    // BoardBlock 방식: div + contentEditable 사용
                    const memoArea = document.createElement('div');
                    memoArea.className = 'calendar-day-memo';
                    memoArea.contentEditable = editor.isEditable ? 'true' : 'false';
                    memoArea.innerText = memos[dateStr] || '';
                    memoArea.setAttribute('data-placeholder', '메모...');
                    
                    // 이벤트 차단 (에디터가 포커스를 가로채지 못하게 함)
                    const stopEvents = (e) => e.stopPropagation();
                    memoArea.onmousedown = stopEvents;
                    memoArea.onclick = stopEvents;
                    memoArea.onkeydown = stopEvents;
                    memoArea.onkeyup = stopEvents;
                    memoArea.onkeypress = stopEvents;

                    memoArea.onblur = () => {
                        const newText = memoArea.innerText;
                        if (newText !== (memos[dateStr] || '')) {
                            memos[dateStr] = newText;
                            if (typeof getPos === 'function') {
                                const pos = getPos();
                                editor.view.dispatch(editor.view.state.tr.setNodeMarkup(pos, null, { ...node.attrs, memos }));
                            }
                        }
                    };

                    day.appendChild(memoArea);
                    grid.appendChild(day);
                }
                wrapper.appendChild(grid);

                const footer = document.createElement('div');
                footer.className = 'calendar-footer';
                const selectedDateDisplay = document.createElement('div');
                selectedDateDisplay.className = 'calendar-selected-date';
                const d = new Date(selectedDateStr);
                selectedDateDisplay.textContent = `${d.getFullYear()}년 ${d.getMonth() + 1}월 ${d.getDate()}일`;
                const todayBtn = document.createElement('button');
                todayBtn.className = 'calendar-today-btn';
                todayBtn.textContent = '오늘';
                todayBtn.onclick = (e) => {
                    e.stopPropagation(); e.preventDefault();
                    if (editor.isEditable) {
                        selectedDateStr = todayStr;
                        currentViewDate = new Date(today);
                        currentViewDate.setDate(1);
                        if (typeof getPos === 'function') {
                            const pos = getPos();
                            editor.view.dispatch(editor.view.state.tr.setNodeMarkup(pos, null, { ...node.attrs, selectedDate: todayStr }));
                        }
                        renderCalendar();
                    }
                };
                footer.appendChild(selectedDateDisplay);
                footer.appendChild(todayBtn);
                wrapper.appendChild(footer);
            };

            const resizeHandle = document.createElement('div');
            resizeHandle.className = 'calendar-resize-handle';
            resizeHandle.style.display = editor.isEditable ? 'block' : 'none';
            wrapper.appendChild(resizeHandle);

            let isResizing = false;
            let startX = 0;
            let startWidth = 0;

            const onResizeStart = (e) => {
                e.preventDefault(); e.stopPropagation();
                isResizing = true; startX = e.clientX;
                startWidth = wrapper.offsetWidth;
                document.addEventListener('mousemove', onResizeMove);
                document.addEventListener('mouseup', onResizeEnd);
                wrapper.style.userSelect = 'none';
            };
            const onResizeMove = (e) => {
                if (!isResizing) return;
                const deltaX = e.clientX - startX;
                let newWidth = startWidth + deltaX * 2;
                const editorElement = document.querySelector('#editor .ProseMirror');
                const maxWidth = editorElement ? editorElement.offsetWidth : 1000;
                newWidth = Math.max(300, Math.min(newWidth, maxWidth));
                wrapper.style.width = `${newWidth}px`;
            };
            const onResizeEnd = () => {
                if (!isResizing) return;
                isResizing = false;
                document.removeEventListener('mousemove', onResizeMove);
                document.removeEventListener('mouseup', onResizeEnd);
                wrapper.style.userSelect = '';
                if (typeof getPos === 'function') {
                    const pos = getPos();
                    editor.view.dispatch(editor.view.state.tr.setNodeMarkup(pos, null, { ...node.attrs, width: wrapper.style.width }));
                }
            };
            resizeHandle.addEventListener('mousedown', onResizeStart);

            renderCalendar();

            return {
                dom: wrapper,
                update(updatedNode) {
                    if (updatedNode.type.name !== node.type.name) return false;
                    
                    const oldSelected = selectedDateStr;
                    selectedDateStr = updatedNode.attrs.selectedDate;
                    memos = { ...updatedNode.attrs.memos };
                    
                    if (selectedDateStr !== oldSelected) {
                        renderCalendar();
                    }
                    
                    if (updatedNode.attrs.align !== currentAlign) {
                        currentAlign = updatedNode.attrs.align;
                        wrapper.setAttribute('data-align', currentAlign);
                        alignMenu.querySelectorAll('.align-button').forEach(btn => {
                            btn.classList.toggle('active', btn.getAttribute('data-align') === currentAlign);
                        });
                    }
                    if (!isResizing && updatedNode.attrs.width !== wrapper.style.width) {
                        wrapper.style.width = updatedNode.attrs.width;
                    }
                    return true;
                },
                selectNode() { wrapper.classList.add('ProseMirror-selectednode'); },
                deselectNode() { wrapper.classList.remove('ProseMirror-selectednode'); },
                ignoreMutation(mutation) {
                    // 메모 영역 내부의 DOM 변화는 에디터가 무시하도록 설정 (우리가 직접 관리)
                    return mutation.target.classList.contains('calendar-day-memo') || mutation.target.parentNode?.classList.contains('calendar-day-memo');
                },
                stopEvent(event) {
                    const target = event.target;
                    // 메모 영역이나 정렬 메뉴에서의 모든 이벤트는 에디터가 가로채지 못하게 함
                    const isInternalInteraction = target.classList.contains('calendar-day-memo') || 
                                                 target.closest('.calendar-align-menu') || 
                                                 target.closest('.calendar-nav');
                    if (isInternalInteraction) return true;
                    return false;
                }
            };
        };
    },

    addCommands() {
        return {
            setCalendarBlock: (attributes) => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: attributes
                });
            }
        };
    }
});
