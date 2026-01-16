import { Extension } from "https://esm.sh/@tiptap/core@2.0.0-beta.209";
import { Plugin, PluginKey } from "https://esm.sh/prosemirror-state@1.4.3";
import { showContextMenu, closeContextMenu } from './ui-utils.js';

// 핸들 요소 생성을 위한 유틸리티
function createHandleElement() {
    const handle = document.createElement('div');
    handle.className = 'block-handle';
    handle.contentEditable = 'false';
    // 6-dot grid icon, thinner and stylish
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

                        // 핸들 자체 위에 있을 때는 위치 업데이트 하지 않음 (스냅/깜빡임 방지)
                        if (e.target === handle || handle.contains(e.target)) {
                            return;
                        }

                        if (isMouseDown) return; // 드래그/클릭 동작 중에는 핸들 위치 고정

                        const view = editorView;
                        // 좌표로 pos 찾기
                        const pos = view.posAtCoords({ left: e.clientX, top: e.clientY });
                        if (!pos) return;

                        let $pos = view.state.doc.resolve(pos.pos);
                        
                        let targetPos = null;
                        let targetNode = null;

                        // Helper: 마우스가 특정 노드의 DOM 영역 안에 있는지 확인
                        const isMouseOverNode = (nodePos, node) => {
                             if (!node || !node.isBlock) return false;
                             const dom = view.nodeDOM(nodePos);
                             if (dom && dom.nodeType === 1) {
                                 const rect = dom.getBoundingClientRect();
                                 return e.clientY >= rect.top && e.clientY <= rect.bottom;
                             }
                             return false;
                        };

                        // 1. Leaf / Atom Block Check (Callout, Board 등)
                        // $pos가 블록 바로 앞/뒤에 있는 경우 (Atom 노드 등)
                        const nodeAfter = $pos.nodeAfter;
                        if (isMouseOverNode($pos.pos, nodeAfter)) {
                            targetPos = $pos.pos;
                            targetNode = nodeAfter;
                        } else {
                            const nodeBefore = $pos.nodeBefore;
                            if (nodeBefore && isMouseOverNode($pos.pos - nodeBefore.nodeSize, nodeBefore)) {
                                targetPos = $pos.pos - nodeBefore.nodeSize;
                                targetNode = nodeBefore;
                            }
                        }
                        
                        // 2. Container Hierarchy Check (Table, ToggleList 등 중첩 구조)
                        if (!targetNode) {
                            // 깊은 곳에서부터 위로 올라가며 "컨테이너의 직계 자식"인 블록을 찾음
                            for (let d = $pos.depth; d >= 0; d--) {
                                const node = $pos.node(d);
                                
                                // d=0은 doc의 자식 (루트 레벨)
                                if (d === 0) {
                                    // 이미 Leaf Check에서 걸리지 않았다면 여기서 처리될 수도 있음
                                    // 하지만 $pos가 깊이 들어가있지 않은 경우(depth=0)를 위해 필요
                                    // (Leaf Check는 nodeAfter/Before만 보므로)
                                    // 그러나 depth loop에서는 $pos가 가리키는 노드의 조상만 본다.
                                    // 루트 레벨 블록 선택은 보통 Leaf Check나 이 루프의 d=1(doc의 자식)에서 걸림?
                                    // 아니, $pos.node(0)은 doc이다. doc 자체를 선택하진 않음.
                                    // $pos.node(d)가 'node'이고, $pos.node(d-1)이 'parent'
                                    // d=0이면 parent가 없다.
                                    break; 
                                }

                                const parent = $pos.node(d - 1);
                                
                                // 컨테이너(doc, toggleBlock, blockquote 등)의 직계 자식이면 선택
                                if (parent.type.name === 'doc' || parent.type.name === 'toggleBlock' || parent.type.name === 'blockquote') {
                                    targetPos = $pos.before(d);
                                    targetNode = node;
                                    break;
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

                            // 스크롤 오프셋을 고려하여 절대 위치 계산
                            handle.style.top = (rect.top - parentRect.top + view.dom.parentNode.scrollTop) + 'px';
                            // main.css에 의하면 .editor padding-left가 120px임.
                            // 핸들을 에디터 콘텐츠 시작점(rect.left)보다 왼쪽에 배치.
                            handle.style.left = (rect.left - parentRect.left - 24 + view.dom.parentNode.scrollLeft) + 'px';
                            
                            handle.style.opacity = '1';
                            
                            currentBlockPos = targetPos;
                            currentBlockNode = targetNode;
                        }
                    };

                    // 드래그/클릭 시작 처리
                    const startInteraction = (e) => {
                        if (!editorView.editable) return;
                        if (!currentBlockNode) return;
                        
                        isMouseDown = true;
                        isDragging = false;
                        dragStartCoords = { x: e.clientX, y: e.clientY };
                        
                        document.addEventListener('mousemove', onGlobalMouseMove);
                        document.addEventListener('mouseup', onGlobalMouseUp);
                        document.addEventListener('touchmove', onGlobalTouchMove, { passive: false });
                        document.addEventListener('touchend', onGlobalMouseUp);
                    };

                    const initDragVisuals = () => {
                        if (ghostEl) return; 

                        ghostEl = createGhostImage(currentBlockNode.textContent || '블록');
                        document.body.appendChild(ghostEl);

                        dropIndicator = document.createElement('div');
                        dropIndicator.className = 'drop-indicator';
                        dropIndicator.style.position = 'absolute';
                        dropIndicator.style.height = '4px';
                        dropIndicator.style.background = '#0ea5e9';
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

                        let $pos = editorView.state.doc.resolve(pos.pos);
                        
                        let targetBlockPos = null;
                        let targetNode = null;
                        
                        // 드롭 타겟 찾기 (onMouseMove와 유사 로직)
                        // 1. Leaf check
                        const nodeAfter = $pos.nodeAfter;
                        // 마우스 위치 체크는 생략 (드롭은 근처면 됨)
                        if (nodeAfter && nodeAfter.isBlock) targetBlockPos = $pos.pos;
                        else {
                            const nodeBefore = $pos.nodeBefore;
                            if (nodeBefore && nodeBefore.isBlock) targetBlockPos = $pos.pos - nodeBefore.nodeSize;
                        }

                        // 2. Loop check
                        if (targetBlockPos === null) {
                            for (let d = $pos.depth; d >= 0; d--) {
                                if (d === 0) break;
                                const node = $pos.node(d);
                                const parent = $pos.node(d - 1);
                                if (parent.type.name === 'doc' || parent.type.name === 'toggleBlock' || parent.type.name === 'blockquote') {
                                    targetBlockPos = $pos.before(d);
                                    targetNode = node;
                                    break;
                                }
                            }
                        } else {
                            targetNode = editorView.state.doc.nodeAt(targetBlockPos);
                        }

                        if (targetBlockPos === null || !targetNode) return;

                        const domNode = editorView.nodeDOM(targetBlockPos);

                        if (domNode && domNode.nodeType === 1) {
                            const rect = domNode.getBoundingClientRect();
                            const parentRect = editorView.dom.parentNode.getBoundingClientRect();
                            const middleY = rect.top + rect.height / 2;

                            const scrollTop = editorView.dom.parentNode.scrollTop;
                            const scrollLeft = editorView.dom.parentNode.scrollLeft;
                            
                            if (y < middleY) {
                                dropTargetPos = targetBlockPos;
                                dropIndicator.style.top = (rect.top - parentRect.top - 2 + scrollTop) + 'px';
                            } else {
                                dropTargetPos = targetBlockPos + targetNode.nodeSize;
                                dropIndicator.style.top = (rect.bottom - parentRect.top - 2 + scrollTop) + 'px';
                            }
                            
                            dropIndicator.style.left = (rect.left - parentRect.left + scrollLeft) + 'px';
                            dropIndicator.style.width = rect.width + 'px';
                            dropIndicator.style.display = 'block';
                        }
                    };

                    const onGlobalMouseMove = (e) => {
                        if (!isMouseDown) return;

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

                        if (!isDragging) {
                            const dx = touch.clientX - dragStartCoords.x;
                            const dy = touch.clientY - dragStartCoords.y;
                            if (Math.sqrt(dx * dx + dy * dy) > 5) {
                                isDragging = true;
                                initDragVisuals();
                            }
                        }

                        if (isDragging) {
                            e.preventDefault();
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
                            if (ghostEl) ghostEl.remove();
                            if (dropIndicator) dropIndicator.remove();
                            ghostEl = null;
                            dropIndicator = null;

                            if (dropTargetPos !== null && currentBlockPos !== null) {
                                const from = currentBlockPos;
                                const to = dropTargetPos;
                                const node = currentBlockNode;
                                
                                if (from !== to && from + node.nodeSize !== to) {
                                    const tr = editorView.state.tr;
                                    const nodeToMove = editorView.state.doc.nodeAt(from);
                                    if (nodeToMove) {
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
                            
                            const preventClick = (clickEvent) => {
                                clickEvent.preventDefault();
                                clickEvent.stopPropagation();
                                window.removeEventListener('click', preventClick, true);
                            };
                            window.addEventListener('click', preventClick, true);
                            
                            setTimeout(() => {
                                window.removeEventListener('click', preventClick, true);
                            }, 100);
                            
                            isDragging = false;
                        } 
                    };

                    handle.addEventListener('mousedown', (e) => {
                        if (!editorView.editable) return;
                        if (e.button !== 0) return;
                        startInteraction(e);
                    });
                    
                    handle.addEventListener('touchstart', (e) => {
                        if (!editorView.editable) return;
                        e.preventDefault(); 
                        const touch = e.touches[0];
                        startInteraction({ 
                            clientX: touch.clientX, 
                            clientY: touch.clientY 
                        });
                    }, { passive: false });

                    handle.addEventListener('click', (e) => {
                        if (!editorView.editable) return;
                        e.stopPropagation();
                        showHandleMenu(handle);
                    });

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

                    const moveBlockUp = () => {
                        if (currentBlockPos === null) return;
                        const $pos = editorView.state.doc.resolve(currentBlockPos);
                        const index = $pos.index(); 
                        if (index === 0) return;

                        const parent = $pos.parent;
                        const prevNode = parent.child(index - 1);
                        const node = parent.child(index);
                        
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
                        const index = $pos.index();
                        const parent = $pos.parent;
                        if (index >= parent.childCount - 1) return;

                        const nextNode = parent.child(index + 1);
                        const node = parent.child(index);
                        
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

                    if (editorView.dom.parentNode) {
                        editorView.dom.parentNode.addEventListener('mousemove', onMouseMove);
                    }
                    
                    editorView.dom.addEventListener('click', (e) => {
                         onMouseMove({ clientX: e.clientX, clientY: e.clientY });
                    });

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