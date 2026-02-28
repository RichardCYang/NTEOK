/**
 * Tiptap Database Block Extension
 * 데이터베이스(테이블 뷰) 블록 (열/행 드래그 크기 조절 기능 포함)
 */

import { addIcon } from './ui-utils.js';
import DOMPurify from 'dompurify';

const Node = Tiptap.Core.Node;

// 보안: XSS 방어
const DB_CELL_PURIFY_CONFIG = {
    USE_PROFILES: { html: true },
    ALLOWED_TAGS: ['br', 'span', 'strong', 'b', 'em', 'i', 'u', 's', 'code', 'a'],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
};

function sanitizeCellHtml(html) {
    return DOMPurify.sanitize(String(html ?? ''), DB_CELL_PURIFY_CONFIG);
}

export const DatabaseBlock = Node.create({
    name: 'databaseBlock',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            title: {
                default: '데이터베이스',
                parseHTML: element => element.getAttribute('data-title'),
                renderHTML: attributes => ({ 'data-title': attributes.title })
            },
            columns: {
                default: [
                    { id: 'col-1', title: '이름', type: 'text', width: '200px' },
                    { id: 'col-2', title: '태그', type: 'text', width: '150px' }
                ],
                parseHTML: element => {
                    const data = element.getAttribute('data-columns');
                    try { return data ? JSON.parse(data) : null; } catch (e) { return null; }
                },
                renderHTML: attributes => ({ 'data-columns': JSON.stringify(attributes.columns) })
            },
            rows: {
                default: [
                    { id: 'row-1', values: { 'col-1': '', 'col-2': '' }, height: 'auto' }
                ],
                parseHTML: element => {
                    const data = element.getAttribute('data-rows');
                    try { return data ? JSON.parse(data) : null; } catch (e) { return null; }
                },
                renderHTML: attributes => ({ 'data-rows': JSON.stringify(attributes.rows) })
            }
        };
    },

    parseHTML() {
        return [{ tag: 'div[data-type="database-block"]' }];
    },

    renderHTML({ HTMLAttributes }) {
        return ['div', { ...HTMLAttributes, 'data-type': 'database-block', class: 'database-block' }];
    },

    addNodeView() {
        return ({ node, editor, getPos, updateAttributes }) => {
            const container = document.createElement('div');
            container.className = 'database-container';
            container.contentEditable = 'false';

            // updateAttributes 타이밍 오류 방지 guard: 함수가 아닌 경우 조용히 무시
            const updateAttrs = (newAttrs) => {
                if (typeof updateAttributes === 'function') updateAttributes(newAttrs);
            };

            let { title, columns, rows } = node.attrs;
            let lastIsEditable = editor.isEditable;
            let cancelActiveResize = null; // 활성 리사이즈 정리 함수

            const render = () => {
                // render() 재호출 시 이전 리사이즈 이벤트 리스너 먼저 정리
                if (cancelActiveResize) { cancelActiveResize(); cancelActiveResize = null; }
                lastIsEditable = editor.isEditable;
                container.innerHTML = '';
                
                // 헤더 영역
                const header = document.createElement('div');
                header.className = 'database-header';
                const titleInput = document.createElement('input');
                titleInput.className = 'database-title-input';
                titleInput.value = title;
                titleInput.placeholder = '데이터베이스 제목';
                titleInput.readOnly = !editor.isEditable;
                titleInput.onchange = (e) => {
                    title = e.target.value;
                    updateAttrs({ title });
                };
                header.appendChild(titleInput);
                container.appendChild(header);

                // 테이블 영역
                const tableWrapper = document.createElement('div');
                tableWrapper.className = 'database-table-wrapper';
                const table = document.createElement('table');
                table.className = 'database-table';

                // ---- Column sizing via <colgroup> (tbody/thead 모두 동일하게 반영) ----
                const colgroup = document.createElement('colgroup');
                const colEls = [];
                columns.forEach((col) => {
                    const colEl = document.createElement('col');
                    colEl.style.width = col.width;
                    colEls.push(colEl);
                    colgroup.appendChild(colEl);
                });
                if (editor.isEditable) {
                    const utilCol = document.createElement('col');
                    utilCol.style.width = '40px';
                    colgroup.appendChild(utilCol);
                }
                table.appendChild(colgroup);

                // ---- Drag resize helpers (Pointer Events) ----
                const startColResize = (e, colIndex, handleEl) => {
                    if (typeof e.button === 'number' && e.button !== 0) return;
                    e.preventDefault(); e.stopPropagation();
                    
                    const startX = e.clientX;
                    // 실제 렌더링된 셀의 너비를 기준으로 시작 (정밀도 향상)
                    const cellEl = handleEl.parentElement;
                    const startWidth = cellEl.offsetWidth;
                    
                    // 드래그 중 테이블 전체 너비를 픽셀로 고정 (1:1 매칭 필수)
                    const tableEl = table;
                    const startTableWidth = tableEl.offsetWidth;
                    tableEl.style.width = startTableWidth + 'px';
                    tableEl.style.minWidth = startTableWidth + 'px';
                    
                    handleEl?.setPointerCapture?.(e.pointerId);
                    document.body.classList.add('db-resizing', 'db-resizing-col');
                    
                    const onMove = (moveEvent) => {
                        moveEvent.preventDefault?.();
                        const delta = moveEvent.clientX - startX;
                        const newWidth = Math.max(50, startWidth + delta);
                        const px = Math.round(newWidth) + 'px';
                        
                        colEls[colIndex].style.width = px;
                        columns[colIndex].width = px;
                        
                        // 테이블 전체 너비도 함께 조절하여 경계선이 마우스를 정확히 따라오게 함
                        const totalDelta = newWidth - startWidth;
                        tableEl.style.width = (startTableWidth + totalDelta) + 'px';
                        tableEl.style.minWidth = (startTableWidth + totalDelta) + 'px';
                    };
                    const cleanup = () => {
                        window.removeEventListener('pointermove', onMove);
                        window.removeEventListener('pointerup', onUp);
                        document.body.classList.remove('db-resizing', 'db-resizing-col', 'db-resizing-row');
                        cancelActiveResize = null;
                    };
                    const onUp = () => { cleanup(); updateAttrs({ columns: [...columns] }); };
                    cancelActiveResize = cleanup;
                    window.addEventListener('pointermove', onMove, { passive: false });
                    window.addEventListener('pointerup', onUp, { once: true });
                };

                const startRowResize = (e, trEl, rowObj, handleEl) => {
                    if (typeof e.button === 'number' && e.button !== 0) return;
                    e.preventDefault(); e.stopPropagation();

                    const startY = e.clientY;
                    const startHeight = trEl.offsetHeight; // offsetHeight가 더 안정적임

                    handleEl?.setPointerCapture?.(e.pointerId);
                    document.body.classList.add('db-resizing', 'db-resizing-row');

                    const onMove = (moveEvent) => {
                        moveEvent.preventDefault?.();
                        const delta = moveEvent.clientY - startY;
                        const px = Math.round(Math.max(36, startHeight + delta)) + 'px';
                        trEl.style.height = px;
                        // <td>들에도 높이를 직접 설정해야 height:100% 기반의 셀이 늘어남
                        trEl.querySelectorAll('td').forEach(td => { td.style.height = px; });
                        rowObj.height = px;
                    };
                    const cleanup = () => {
                        window.removeEventListener('pointermove', onMove);
                        window.removeEventListener('pointerup', onUp);
                        document.body.classList.remove('db-resizing', 'db-resizing-col', 'db-resizing-row');
                        cancelActiveResize = null;
                    };
                    const onUp = () => { cleanup(); updateAttrs({ rows: [...rows] }); };
                    cancelActiveResize = cleanup;
                    window.addEventListener('pointermove', onMove, { passive: false });
                    window.addEventListener('pointerup', onUp, { once: true });
                };

                const makeColResizer = (colIndex) => {
                    const resizer = document.createElement('div');
                    resizer.className = 'database-col-resizer';
                    resizer.onpointerdown = (e) => startColResize(e, colIndex, resizer);
                    return resizer;
                };

                const makeRowResizer = (trEl, rowObj) => {
                    const resizer = document.createElement('div');
                    resizer.className = 'database-row-resizer';
                    resizer.onpointerdown = (e) => startRowResize(e, trEl, rowObj, resizer);
                    return resizer;
                };
                
                // THead
                const thead = document.createElement('thead');
                const headerRow = document.createElement('tr');
                
                columns.forEach((col, index) => {
                    const th = document.createElement('th');
                    
                    const thContent = document.createElement('div');
                    thContent.className = 'database-th-content';
                    
                    const colTitle = document.createElement('input');
                    colTitle.className = 'database-col-title';
                    colTitle.value = col.title;
                    colTitle.readOnly = !editor.isEditable;
                    colTitle.onchange = (e) => {
                        col.title = e.target.value;
                        updateAttrs({ columns: [...columns] });
                    };
                    
                    thContent.appendChild(colTitle);
                    
                    if (editor.isEditable && columns.length > 1) {
                        const delColBtn = document.createElement('button');
                        delColBtn.className = 'database-del-col-btn';
                        delColBtn.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
                        delColBtn.onclick = (e) => {
                            e.stopPropagation();
                            if (confirm('이 열을 삭제하시겠습니까?')) {
                                columns.splice(index, 1);
                                rows.forEach(row => { delete row.values[col.id]; });
                                updateAttrs({ columns: [...columns], rows: [...rows] });
                                render();
                            }
                        };
                        thContent.appendChild(delColBtn);
                    }
                    
                    th.appendChild(thContent);

                    // [열 크기 조절 핸들]
                    if (editor.isEditable) {
                        th.appendChild(makeColResizer(index));
                    }

                    headerRow.appendChild(th);
                });
                
                // [열 추가 버튼]
                if (editor.isEditable) {
                    const thAddCol = document.createElement('th');
                    thAddCol.className = 'database-add-col-th';
                    const addColBtn = document.createElement('button');
                    addColBtn.className = 'database-add-col-btn';
                    addColBtn.innerHTML = '<i class="fa-solid fa-plus"></i>';
                    addColBtn.onclick = (e) => {
                        e.stopPropagation();
                        const newColId = 'col-' + Date.now();
                        columns.push({ id: newColId, title: '새 열', type: 'text', width: '150px' });
                        rows.forEach(row => { row.values[newColId] = ''; });
                        updateAttrs({ columns: [...columns], rows: [...rows] });
                        render();
                    };
                    thAddCol.appendChild(addColBtn);
                    headerRow.appendChild(thAddCol);
                }
                
                thead.appendChild(headerRow);
                table.appendChild(thead);
                
                // TBody
                const tbody = document.createElement('tbody');
                rows.forEach((row, rowIndex) => {
                    const tr = document.createElement('tr');
                    const rowHeightPx = (row.height && row.height !== 'auto') ? row.height : null;
                    if (rowHeightPx) {
                        tr.style.height = rowHeightPx;
                    }

                    columns.forEach((col, colIndex) => {
                        const td = document.createElement('td');
                        if (rowHeightPx) { td.style.height = rowHeightPx; }
                        const cell = document.createElement('div');
                        cell.className = 'database-cell';
                        cell.contentEditable = editor.isEditable ? 'true' : 'false';
                        cell.innerHTML = sanitizeCellHtml(row.values[col.id]);
                        cell.onblur = () => {
                            const newValue = sanitizeCellHtml(cell.innerHTML);
                            if (row.values[col.id] !== newValue) {
                                row.values[col.id] = newValue;
                                updateAttrs({ rows: [...rows] });
                            }
                        };
                        cell.onkeydown = (e) => {
                            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); cell.blur(); return; }
                            e.stopPropagation();
                        };
                        td.appendChild(cell);

                        if (editor.isEditable) {
                            td.appendChild(makeColResizer(colIndex));
                            td.appendChild(makeRowResizer(tr, row));
                        }

                        tr.appendChild(td);
                    });
                    
                    if (editor.isEditable) {
                        const tdDelRow = document.createElement('td');
                        tdDelRow.className = 'database-del-row-td';
                        if (rowHeightPx) { tdDelRow.style.height = rowHeightPx; }
                        const delRowBtn = document.createElement('button');
                        delRowBtn.className = 'database-del-row-btn';
                        delRowBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
                        delRowBtn.onclick = (e) => {
                            e.stopPropagation();
                            if (rows.length > 1) {
                                rows.splice(rowIndex, 1);
                                updateAttrs({ rows: [...rows] });
                                render();
                            }
                        };
                        tdDelRow.appendChild(delRowBtn);

                        // [행 높이 조절 핸들]
                        tdDelRow.appendChild(makeRowResizer(tr, row));

                        tr.appendChild(tdDelRow);
                    }
                    tbody.appendChild(tr);
                });
                
                table.appendChild(tbody);
                tableWrapper.appendChild(table);
                container.appendChild(tableWrapper);
                
                if (editor.isEditable) {
                    const addRowBtn = document.createElement('button');
                    addRowBtn.className = 'database-add-row-btn';
                    addRowBtn.innerHTML = '<i class="fa-solid fa-plus"></i> 새 행 추가';
                    addRowBtn.onclick = (e) => {
                        e.stopPropagation();
                        const newValues = {};
                        columns.forEach(col => { newValues[col.id] = ''; });
                        rows.push({ id: 'row-' + Date.now(), values: newValues, height: 'auto' });
                        updateAttrs({ rows: [...rows] });
                        render();
                    };
                    container.appendChild(addRowBtn);
                }
            };

            const checkEditable = () => { if (editor.isEditable !== lastIsEditable) render(); };
            editor.on('transaction', checkEditable);
            const observer = new MutationObserver(() => checkEditable());
            if (editor.view && editor.view.dom) {
                observer.observe(editor.view.dom, { attributes: true, attributeFilter: ['contenteditable'] });
            }

            render();

            return {
                dom: container,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== node.type.name) return false;
                    const isDataChanged = JSON.stringify(updatedNode.attrs) !== JSON.stringify({ title, columns, rows });
                    if (isDataChanged) {
                        title = updatedNode.attrs.title;
                        columns = updatedNode.attrs.columns;
                        rows = updatedNode.attrs.rows;
                        render();
                    }
                    return true;
                },
                stopEvent: (event) => {
                    const target = event.target;
                    return target.closest('.database-container') !== null && 
                           (target.tagName === 'INPUT' || target.contentEditable === 'true' || target.tagName === 'BUTTON' || target.closest('button') || target.classList.contains('database-col-resizer') || target.classList.contains('database-row-resizer'));
                },
                ignoreMutation: () => true,
                destroy: () => {
                    editor.off('transaction', checkEditable);
                    observer.disconnect();
                }
            };
        };
    },

    addCommands() {
        return {
            setDatabaseBlock: () => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        title: '새 데이터베이스',
                        columns: [
                            { id: 'col-1', title: '이름', type: 'text', width: '200px' },
                            { id: 'col-2', title: '태그', type: 'text', width: '150px' }
                        ],
                        rows: [
                            { id: 'row-1', values: { 'col-1': '', 'col-2': '' }, height: 'auto' }
                        ]
                    }
                });
            }
        };
    }
});
