import { Extension } from "@tiptap/core";
import { Plugin, PluginKey } from "prosemirror-state";
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

                    // 마우스 오버 핸들러 (데스크탑) - Throttle 적용하여 성능 최적화 및 오류 빈도 감소
                    let lastMouseMoveTime = 0;
                    const onMouseMove = (e) => {
                        const now = Date.now();
                        if (now - lastMouseMoveTime < 50) return; // 50ms 디바운스/쓰로틀
                        lastMouseMoveTime = now;

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
                        // 좌표로 pos 찾기 (예외 처리 추가: 커스텀 노드 등에서 내부 오류 발생 가능)
                        let pos;
                        try {
                            pos = view.posAtCoords({ left: e.clientX, top: e.clientY });
                        } catch (err) {
                            // 특정 TypeError(nodeName)는 ProseMirror 내부 이슈이므로 무시하여 콘솔 노이즈 제거
                            if (!(err instanceof TypeError && err.message.includes('nodeName'))) {
                                console.warn('[DragHandle] posAtCoords error:', err);
                            }
                            return;
                        }
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
                        // Atom 노드이거나 텍스트가 없는 특수 블록인 경우 우선 선택
                        if (nodeAfter && nodeAfter.isBlock && (nodeAfter.isAtom || nodeAfter.type.name === 'horizontalRule' || nodeAfter.type.name === 'boardBlock')) {
                            if (isMouseOverNode($pos.pos, nodeAfter)) {
                                targetPos = $pos.pos;
                                targetNode = nodeAfter;
                            }
                        } else {
                            const nodeBefore = $pos.nodeBefore;
                            if (nodeBefore && nodeBefore.isBlock && (nodeBefore.isAtom || nodeBefore.type.name === 'horizontalRule' || nodeBefore.type.name === 'boardBlock')) {
                                if (isMouseOverNode($pos.pos - nodeBefore.nodeSize, nodeBefore)) {
                                    targetPos = $pos.pos - nodeBefore.nodeSize;
                                    targetNode = nodeBefore;
                                }
                            }
                        }
                        
                        // 2. Container Hierarchy Check (Table, ToggleList, TaskList 등 중첩 구조)
                        if (!targetNode) {
                            // 이동 가능한 블록의 부모가 될 수 있는 컨테이너 타입 정의
                            const containerTypes = ['doc', 'toggleBlock', 'blockquote', 'taskList', 'bulletList', 'orderedList', 'boardBlock'];
                            // 개별적으로 핸들이 붙어야 하는 리스트 아이템 타입
                            const listItemTypes = ['taskItem', 'listItem'];
                            
                            // 깊은 곳에서부터 위로 올라가며 "컨테이너의 직계 자식"인 블록을 찾음
                            for (let d = $pos.depth; d >= 0; d--) {
                                const node = $pos.node(d);
                                if (d === 0) break; 

                                const parent = $pos.node(d - 1);
                                
                                // [수정] 현재 노드가 리스트 아이템이거나, 부모가 컨테이너인 경우 타겟으로 설정
                                // 이를 통해 리스트 전체가 아닌 개별 항목에 핸들이 표시됨
                                if (listItemTypes.includes(node.type.name) || containerTypes.includes(parent.type.name)) {
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

                            // 기본 왼쪽 오프셋 (핸들 너비 및 간격)
                            let xOffset = 24;

                            // [수정] TaskList 아이템인 경우 체크박스 레이블 너비만큼 핸들을 더 왼쪽으로 이동
                            // li 요소 내부에 label(체크박스 영역)이 있는지 확인하여 오프셋 계산
                            if (domNode.nodeName === 'LI' && domNode.querySelector('label')) {
                                const label = domNode.querySelector('label');
                                xOffset += label.offsetWidth;
                            }

                            // 스크롤 오프셋을 고려하여 절대 위치 계산
                            handle.style.top = (rect.top - parentRect.top + view.dom.parentNode.scrollTop) + 'px';
                            // 계산된 xOffset을 적용하여 핸들을 항상 블록의 가장 왼쪽(체크박스 포함)에 배치
                            handle.style.left = (rect.left - parentRect.left - xOffset + view.dom.parentNode.scrollLeft) + 'px';
                            
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
                        let pos;
                        try {
                            pos = editorView.posAtCoords({ left: x, top: y });
                        } catch (err) {
                            // nodeName 에러는 ProseMirror 내부 이슈이므로 로깅 생략
                            return;
                        }
                        if (!pos) return;

                        let $pos = editorView.state.doc.resolve(pos.pos);
                        
                        let targetBlockPos = null;
                        let targetNode = null;
                        
                        // 드롭 타겟 찾기 (onMouseMove와 유사 로직)
                        // 1. Leaf check (Atom 노드 우선)
                        const nodeAfter = $pos.nodeAfter;
                        if (nodeAfter && nodeAfter.isBlock && (nodeAfter.isAtom || nodeAfter.type.name === 'boardBlock')) {
                            targetBlockPos = $pos.pos;
                        } else {
                            const nodeBefore = $pos.nodeBefore;
                            if (nodeBefore && nodeBefore.isBlock && (nodeBefore.isAtom || nodeBefore.type.name === 'boardBlock')) {
                                targetBlockPos = $pos.pos - nodeBefore.nodeSize;
                            }
                        }

                        // 2. Loop check (컨테이너 계층 탐색)
                        if (targetBlockPos === null) {
                            const containerTypes = ['doc', 'toggleBlock', 'blockquote', 'taskList', 'bulletList', 'orderedList', 'boardBlock'];
                            const listItemTypes = ['taskItem', 'listItem'];

                            for (let d = $pos.depth; d >= 0; d--) {
                                if (d === 0) break;
                                const node = $pos.node(d);
                                const parent = $pos.node(d - 1);
                                
                                // 리스트 아이템이거나 컨테이너의 직계 자식인 경우 드롭 타겟으로 설정
                                if (listItemTypes.includes(node.type.name) || containerTypes.includes(parent.type.name)) {
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

                        const menuItems = [
                            { action: "block-move-up", label: "위로 이동", icon: "fa-solid fa-arrow-up" },
                            { action: "block-move-down", label: "아래로 이동", icon: "fa-solid fa-arrow-down" },
                            { action: "block-delete", label: "삭제", icon: "fa-solid fa-trash-can", className: "danger" }
                        ];

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