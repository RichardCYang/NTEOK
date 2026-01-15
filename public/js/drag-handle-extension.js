import { Extension } from "https://esm.sh/@tiptap/core@2.0.0-beta.209";
import { Plugin, PluginKey } from "https://esm.sh/prosemirror-state@1.4.3";
import { showContextMenu, closeContextMenu } from './ui-utils.js';

// 핸들 요소 생성을 위한 유틸리티
function createHandleElement() {
    const handle = document.createElement('div');
    handle.className = 'block-handle';
    handle.contentEditable = 'false';
    // 6-dot grid icon (Notion style), thinner and stylish
    handle.innerHTML = `
        <svg viewBox="0 0 10 16" width="10" height="16" fill="currentColor" style="display: block;">
            <circle cx="2" cy="2" r="1.5" />
            <circle cx="8" cy="2" r="1.5" />
            <circle cx="2" cy="8" r="1.5" />
            <circle cx="8" cy="8" r="1.5" />
            <circle cx="2" cy="14" r="1.5" />
            <circle cx="8" cy="14" r="1.5" />
        </svg>
    `;
    handle.style.position = 'absolute';
    handle.style.cursor = 'grab';
    handle.style.opacity = '0'; // 초기에는 숨김
    handle.style.transition = 'opacity 0.2s, top 0.1s';
    handle.style.zIndex = '50';
    return handle;
}

// 드래그 고스트 이미지 생성
function createGhostImage(text) {
    const ghost = document.createElement('div');
    ghost.className = 'drag-ghost';
    ghost.textContent = text.substring(0, 30) + (text.length > 30 ? '...' : '');
    ghost.style.position = 'fixed';
    ghost.style.pointerEvents = 'none';
    ghost.style.background = 'white';
    ghost.style.border = '1px solid #ccc';
    ghost.style.padding = '8px';
    ghost.style.borderRadius = '4px';
    ghost.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)';
    ghost.style.zIndex = '10000';
    ghost.style.maxWidth = '200px';
    ghost.style.whiteSpace = 'nowrap';
    ghost.style.overflow = 'hidden';
    ghost.style.opacity = '0.9';
    return ghost;
}

export const DragHandle = Extension.create({
    name: 'dragHandle',

    addProseMirrorPlugins() {
        return [
            new Plugin({
                key: new PluginKey('dragHandle'),
                view: (editorView) => {
                    const handle = createHandleElement();
                    
                    if (editorView.dom.parentNode) {
                        editorView.dom.parentNode.appendChild(handle);
                    }

                    let currentBlockPos = null;
                    let currentBlockNode = null;
                    
                    // 상태 변수
                    let isMouseDown = false;
                    let isDragging = false;
                    let dragStartCoords = null;
                    let ghostEl = null;
                    let dropIndicator = null;
                    let dropTargetPos = null;

                    // 마우스 오버 핸들러 (데스크탑)
                    const onMouseMove = (e) => {
                        // 읽기 모드이면 핸들 숨김
                        if (!editorView.editable) {
                            handle.style.opacity = '0';
                            return;
                        }

                        if (isMouseDown) return; // 드래그/클릭 동작 중에는 핸들 위치 고정

                        const view = editorView;
                        // 좌표로 pos 찾기
                        const pos = view.posAtCoords({ left: e.clientX, top: e.clientY });
                        if (!pos) return;

                        // 해당 pos의 가장 깊은 block 노드 찾기
                        let $pos = view.state.doc.resolve(pos.pos);
                        let depth = $pos.depth;
                        let node = $pos.node(depth);
                        
                        // depth 1까지 올라가서 최상위 블록 찾기
                        while (depth > 1) {
                            $pos = view.state.doc.resolve($pos.before(depth));
                            depth = $pos.depth;
                            node = $pos.node(depth);
                        }

                        let targetPos = null;
                        let targetNode = null;
                        
                        // depth 1: 일반 블록
                        if (depth === 1) {
                            targetPos = $pos.before(1);
                            targetNode = node;
                        } 
                        // depth 0: 루트 레벨 Atom 노드 (YouTube, Image 등) 처리
                        else if (depth === 0) {
                            const nodeAfter = $pos.nodeAfter;
                            const nodeBefore = $pos.nodeBefore;
                            
                            // nodeAfter 확인
                            if (nodeAfter && nodeAfter.isBlock) {
                                const dom = view.nodeDOM($pos.pos);
                                if (dom && dom.nodeType === 1) {
                                    const rect = dom.getBoundingClientRect();
                                    // 마우스 Y 좌표가 해당 블록 범위 내에 있는지 확인
                                    if (e.clientY >= rect.top && e.clientY <= rect.bottom) {
                                        targetPos = $pos.pos;
                                        targetNode = nodeAfter;
                                    }
                                }
                            }
                            
                            // nodeAfter가 아니면 nodeBefore 확인
                            if (!targetNode && nodeBefore && nodeBefore.isBlock) {
                                const p = $pos.pos - nodeBefore.nodeSize;
                                const dom = view.nodeDOM(p);
                                if (dom && dom.nodeType === 1) {
                                    const rect = dom.getBoundingClientRect();
                                    if (e.clientY >= rect.top && e.clientY <= rect.bottom) {
                                        targetPos = p;
                                        targetNode = nodeBefore;
                                    }
                                }
                            }
                        }

                        if (!targetNode || targetPos === null) return;

                        const domNode = view.nodeDOM(targetPos);

                        if (domNode && domNode.nodeType === 1) {
                            // 블록 위치 가져오기
                            const rect = domNode.getBoundingClientRect();
                            const parentRect = view.dom.parentNode.getBoundingClientRect();
                            
                            // 마우스가 블록 범위(또는 근처)에 있는지 이중 확인
                            if (e.clientY < rect.top - 20 || e.clientY > rect.bottom + 20) {
                                return;
                            }

                            // 스크롤 오프셋을 고려하여 절대 위치 계산 (scrollTop 추가)
                            handle.style.top = (rect.top - parentRect.top + view.dom.parentNode.scrollTop) + 'px';
                            // main.css에 의하면 .editor padding-left가 120px임.
                            // 핸들을 에디터 콘텐츠 시작점(rect.left)보다 왼쪽에 배치.
                            handle.style.left = (rect.left - parentRect.left - 24 + view.dom.parentNode.scrollLeft) + 'px'; // 얇아졌으므로 위치 살짝 조정
                            
                            handle.style.opacity = '1';
                            
                            currentBlockPos = targetPos;
                            currentBlockNode = targetNode;
                        }
                    };

                    // 드래그/클릭 시작 처리
                    const startInteraction = (e) => {
                        // 읽기 모드이면 불가
                        if (!editorView.editable) return;
                        if (!currentBlockNode) return;
                        
                        isMouseDown = true;
                        isDragging = false;
                        dragStartCoords = { x: e.clientX, y: e.clientY };
                        
                        // 전역 이벤트 리스너 등록
                        document.addEventListener('mousemove', onGlobalMouseMove);
                        document.addEventListener('mouseup', onGlobalMouseUp);
                        document.addEventListener('touchmove', onGlobalTouchMove, { passive: false });
                        document.addEventListener('touchend', onGlobalMouseUp);
                    };

                    const initDragVisuals = () => {
                        if (ghostEl) return; // 이미 생성됨

                        // 고스트 이미지 생성
                        ghostEl = createGhostImage(currentBlockNode.textContent || '블록');
                        document.body.appendChild(ghostEl);

                        // 드롭 인디케이터 생성
                        dropIndicator = document.createElement('div');
                        dropIndicator.className = 'drop-indicator';
                        dropIndicator.style.position = 'absolute';
                        dropIndicator.style.height = '4px';
                        dropIndicator.style.background = '#0ea5e9'; // sky-500
                        dropIndicator.style.borderRadius = '2px';
                        dropIndicator.style.pointerEvents = 'none';
                        dropIndicator.style.zIndex = '40';
                        dropIndicator.style.display = 'none';
                        if (editorView.dom.parentNode) {
                            editorView.dom.parentNode.appendChild(dropIndicator);
                        }

                        handle.style.cursor = 'grabbing';
                    };

                    const moveGhost = (x, y) => {
                        if (ghostEl) {
                            ghostEl.style.left = (x + 10) + 'px';
                            ghostEl.style.top = (y + 10) + 'px';
                        }
                    };

                    const updateDropIndicator = (x, y) => {
                        const pos = editorView.posAtCoords({ left: x, top: y });
                        if (!pos) return;

                        // 타겟 블록 찾기
                        let $pos = editorView.state.doc.resolve(pos.pos);
                        let depth = $pos.depth;
                        while (depth > 1) {
                            $pos = editorView.state.doc.resolve($pos.before(depth));
                            depth = $pos.depth;
                        }
                        if (depth !== 1) return;

                        const targetBlockPos = $pos.before(1);
                        const targetNode = editorView.state.doc.nodeAt(targetBlockPos);
                        const domNode = editorView.nodeDOM(targetBlockPos);

                        if (domNode && domNode.nodeType === 1) {
                            const rect = domNode.getBoundingClientRect();
                            const parentRect = editorView.dom.parentNode.getBoundingClientRect();
                            const middleY = rect.top + rect.height / 2;

                            // 위쪽 절반이면 블록 위로, 아래쪽 절반이면 블록 아래로
                            // 스크롤 오프셋 반영
                            const scrollTop = editorView.dom.parentNode.scrollTop;
                            const scrollLeft = editorView.dom.parentNode.scrollLeft;
                            
                            if (y < middleY) {
                                dropTargetPos = targetBlockPos; // 위로 이동 (현재 블록 자리)
                                dropIndicator.style.top = (rect.top - parentRect.top - 2 + scrollTop) + 'px';
                            } else {
                                dropTargetPos = targetBlockPos + targetNode.nodeSize; // 아래로 이동 (다음 블록 자리)
                                dropIndicator.style.top = (rect.bottom - parentRect.top - 2 + scrollTop) + 'px';
                            }
                            
                            dropIndicator.style.left = (rect.left - parentRect.left + scrollLeft) + 'px';
                            dropIndicator.style.width = rect.width + 'px';
                            dropIndicator.style.display = 'block';
                        }
                    };

                    const onGlobalMouseMove = (e) => {
                        if (!isMouseDown) return;

                        // 드래그 여부 판단 (5px 이상 이동 시)
                        if (!isDragging) {
                            const dx = e.clientX - dragStartCoords.x;
                            const dy = e.clientY - dragStartCoords.y;
                            if (Math.sqrt(dx * dx + dy * dy) > 5) {
                                isDragging = true;
                                initDragVisuals();
                            }
                        }

                        if (isDragging) {
                            e.preventDefault();
                            moveGhost(e.clientX, e.clientY);
                            updateDropIndicator(e.clientX, e.clientY);
                        }
                    };

                    const onGlobalTouchMove = (e) => {
                        if (!isMouseDown) return;
                        
                        const touch = e.touches[0];

                        // 드래그 여부 판단
                        if (!isDragging) {
                            const dx = touch.clientX - dragStartCoords.x;
                            const dy = touch.clientY - dragStartCoords.y;
                            if (Math.sqrt(dx * dx + dy * dy) > 5) {
                                isDragging = true;
                                initDragVisuals();
                            }
                        }

                        if (isDragging) {
                            e.preventDefault(); // 스크롤 방지
                            moveGhost(touch.clientX, touch.clientY);
                            updateDropIndicator(touch.clientX, touch.clientY);
                        }
                    };

                    const onGlobalMouseUp = (e) => {
                        if (!isMouseDown) return;
                        
                        isMouseDown = false;
                        handle.style.cursor = 'grab';

                        document.removeEventListener('mousemove', onGlobalMouseMove);
                        document.removeEventListener('mouseup', onGlobalMouseUp);
                        document.removeEventListener('touchmove', onGlobalTouchMove);
                        document.removeEventListener('touchend', onGlobalMouseUp);

                        if (isDragging) {
                            // 드래그 종료 -> 이동 실행
                            
                            // 정리
                            if (ghostEl) ghostEl.remove();
                            if (dropIndicator) dropIndicator.remove();
                            ghostEl = null;
                            dropIndicator = null;

                            // 이동 실행
                            if (dropTargetPos !== null && currentBlockPos !== null) {
                                const from = currentBlockPos;
                                const to = dropTargetPos;
                                const node = currentBlockNode;
                                
                                // 같은 위치면 무시
                                if (from === to || from + node.nodeSize === to) {}
                                else {
                                    const tr = editorView.state.tr;
                                    const nodeToMove = editorView.state.doc.nodeAt(from);
                                    if (nodeToMove) {
                                        // 새 위치 보정
                                        let insertPos = to;
                                        if (to > from) {
                                            insertPos -= nodeToMove.nodeSize;
                                        }
                                        
                                        tr.delete(from, from + nodeToMove.nodeSize);
                                        tr.insert(insertPos, nodeToMove);
                                        
                                        editorView.dispatch(tr);
                                    }
                                }
                            }
                            
                            // 드래그 후 클릭 이벤트 발생 방지 (캡처링 단계에서 차단)
                            const preventClick = (clickEvent) => {
                                clickEvent.preventDefault();
                                clickEvent.stopPropagation();
                                window.removeEventListener('click', preventClick, true);
                            };
                            window.addEventListener('click', preventClick, true);
                            
                            // 안전장치: 짧은 시간 후 리스너 제거 (이벤트가 안 올 경우 대비)
                            setTimeout(() => {
                                window.removeEventListener('click', preventClick, true);
                            }, 100);
                            
                            isDragging = false;
                        } 
                        // isDragging이 false인 경우:
                        // 아무 것도 하지 않음. 브라우저가 handle에 대해 'click' 이벤트를 발생시킬 것임.
                        // 아래 'click' 리스너에서 메뉴를 염.
                    };

                    // 핸들 이벤트 바인딩
                    handle.addEventListener('mousedown', (e) => {
                        if (!editorView.editable) return;
                        if (e.button !== 0) return; // 좌클릭만
                        // e.preventDefault(); // 제거: 네이티브 클릭 이벤트 허용
                        startInteraction(e);
                    });
                    
                    handle.addEventListener('touchstart', (e) => {
                        if (!editorView.editable) return;
                        e.preventDefault(); // 터치는 스크롤 방지를 위해 preventDefault 필요할 수 있음
                        // 터치 후 탭은 'click' 이벤트를 발생시키지 않을 수 있으므로,
                        // 터치는 별도 로직이 필요할 수 있지만, 
                        // startInteraction에서 touchmove/touchend를 처리하므로
                        // mouseup 로직과 유사하게 동작함.
                        // 단, 모바일에서 'click' 이벤트가 지연 발생하거나 preventDefault로 인해 안 생길 수 있음.
                        // 모바일은 click 리스너에 의존하기보다, touchend에서 처리하는게 나을 수 있음.
                        // 하지만 일단 PC 클릭 복구가 우선.
                        
                        const touch = e.touches[0];
                        startInteraction({ 
                            clientX: touch.clientX, 
                            clientY: touch.clientY 
                        });
                    }, { passive: false });

                    // 클릭 (메뉴) 이벤트 바인딩
                    handle.addEventListener('click', (e) => {
                        if (!editorView.editable) return;
                        
                        // 드래그 후에는 상단의 capture listener에 의해 이 이벤트가 도달하지 않아야 함.
                        // 도달했다는 것은 드래그가 아닌 순수 클릭이라는 뜻.
                        
                        e.stopPropagation();
                        // e.preventDefault(); 
                        showHandleMenu(handle);
                    });

                    // 핸들 메뉴 표시 함수
                    const showHandleMenu = (trigger) => {
                        if (!editorView.editable) return;
                        if (!currentBlockNode || currentBlockPos === null) return;

                        const menuItems = `
                            <button data-action="block-move-up">
                                <i class="fa-solid fa-arrow-up"></i> 위로 이동
                            </button>
                            <button data-action="block-move-down">
                                <i class="fa-solid fa-arrow-down"></i> 아래로 이동
                            </button>
                            <button data-action="block-delete" class="danger">
                                <i class="fa-solid fa-trash-can"></i> 삭제
                            </button>
                        `;

                        showContextMenu(trigger, menuItems);

                        const contextMenu = document.getElementById('context-menu');
                        
                        const handleMenuClick = (e) => {
                            const btn = e.target.closest('button');
                            if (!btn) return;
                            const action = btn.dataset.action;
                            
                            if (action === 'block-move-up') {
                                moveBlockUp();
                                closeContextMenu();
                            } else if (action === 'block-move-down') {
                                moveBlockDown();
                                closeContextMenu();
                            } else if (action === 'block-delete') {
                                deleteBlock();
                                closeContextMenu();
                            }
                        };
                        
                        contextMenu.onclick = handleMenuClick;
                    };

                    // 블록 이동 유틸리티
                    const moveBlockUp = () => {
                        if (currentBlockPos === null) return;
                        const $pos = editorView.state.doc.resolve(currentBlockPos);
                        
                        const index = $pos.index(0); 
                        if (index === 0) return; 

                        const prevNode = editorView.state.doc.child(index - 1);
                        const node = editorView.state.doc.child(index);
                        
                        const tr = editorView.state.tr;
                        const from = currentBlockPos;
                        const to = from - prevNode.nodeSize;
                        
                        tr.delete(from, from + node.nodeSize);
                        tr.insert(to, node);
                        editorView.dispatch(tr);
                    };

                    const moveBlockDown = () => {
                        if (currentBlockPos === null) return;
                        const $pos = editorView.state.doc.resolve(currentBlockPos);
                        const index = $pos.index(0);
                        const docSize = editorView.state.doc.content.childCount;
                        
                        if (index >= docSize - 1) return; 

                        const nextNode = editorView.state.doc.child(index + 1);
                        const node = editorView.state.doc.child(index);
                        
                        const tr = editorView.state.tr;
                        const from = currentBlockPos;
                        
                        tr.delete(from, from + node.nodeSize);
                        tr.insert(from + nextNode.nodeSize, node); 
                        editorView.dispatch(tr);
                    };

                    const deleteBlock = () => {
                        if (currentBlockPos === null) return;
                        const node = currentBlockNode;
                        const tr = editorView.state.tr;
                        tr.delete(currentBlockPos, currentBlockPos + node.nodeSize);
                        editorView.dispatch(tr);
                        handle.style.opacity = '0';
                    };

                    // 에디터 마우스 이동 리스너 등록
                    if (editorView.dom.parentNode) {
                        editorView.dom.parentNode.addEventListener('mousemove', onMouseMove);
                    }
                    
                    editorView.dom.addEventListener('click', (e) => {
                         onMouseMove({ clientX: e.clientX, clientY: e.clientY });
                    });

                    // 스크롤 시 핸들 숨김 처리 (위치 불일치 방지)
                    const onScroll = () => {
                        if (handle.style.opacity !== '0') {
                            handle.style.opacity = '0';
                        }
                    };
                    window.addEventListener('scroll', onScroll, true);

                    return {
                        destroy() {
                            handle.remove();
                            if (dropIndicator) dropIndicator.remove();
                            if (editorView.dom.parentNode) {
                                editorView.dom.parentNode.removeEventListener('mousemove', onMouseMove);
                            }
                            window.removeEventListener('scroll', onScroll, true);
                        }
                    };
                }
            })
        ];
    }
});