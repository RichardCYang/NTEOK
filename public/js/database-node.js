
import { addIcon } from './ui-utils.js';
import { safeJsonClone, safeJsonParse } from './safe-json.js';
import { sanitizeStructuredRichHtml } from './sanitize.js';

const Node = Tiptap.Core.Node;

function sanitizeCellHtml(html) {
    return sanitizeStructuredRichHtml(html);
}

function cloneDatabaseColumns(columns) {
    const cloned = safeJsonClone(columns, []);
    if (!Array.isArray(cloned) || cloned.length === 0) return [
        { id: 'col-1', title: '이름', type: 'text', width: '200px' },
        { id: 'col-2', title: '태그', type: 'text', width: '150px' }
    ];
    return cloned.map((col, index) => ({
        id: (typeof col?.id === 'string' && col.id.trim()) ? col.id : `col-${index + 1}`,
        title: typeof col?.title === 'string' ? col.title : '',
        type: 'text',
        width: (typeof col?.width === 'string' && col.width.trim()) ? col.width : '150px'
    }));
}

function cloneDatabaseRows(rows, columns) {
    const cloned = safeJsonClone(rows, []);
    const safeColumns = cloneDatabaseColumns(columns);
    if (!Array.isArray(cloned) || cloned.length === 0) {
        const values = {};
        safeColumns.forEach((col) => { values[col.id] = ''; });
        return [{ id: 'row-1', values, height: 'auto' }];
    }
    return cloned.map((row, index) => {
        const rawValues = (row && typeof row.values === 'object' && row.values) ? row.values : {};
        const values = {};
        safeColumns.forEach((col) => {
            values[col.id] = sanitizeCellHtml(rawValues[col.id]);
        });
        return {
            id: (typeof row?.id === 'string' && row.id.trim()) ? row.id : `row-${index + 1}`,
            values,
            height: (typeof row?.height === 'string' && row.height.trim()) ? row.height : 'auto'
        };
    });
}

function cloneDatabaseState(attrs = {}) {
    const columns = cloneDatabaseColumns(attrs.columns);
    const rows = cloneDatabaseRows(attrs.rows, columns);
    return {
        title: typeof attrs.title === 'string' ? attrs.title : '데이터베이스',
        columns,
        rows
    };
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
                    const parsed = safeJsonParse(data, null);
                    return Array.isArray(parsed) ? parsed : null;
                },
                renderHTML: attributes => ({ 'data-columns': JSON.stringify(cloneDatabaseColumns(attributes.columns)) })
            },
            rows: {
                default: [
                    { id: 'row-1', values: { 'col-1': '', 'col-2': '' }, height: 'auto' }
                ],
                parseHTML: element => {
                    const data = element.getAttribute('data-rows');
                    const parsed = safeJsonParse(data, null);
                    return Array.isArray(parsed) ? parsed : null;
                },
                renderHTML: attributes => ({ 'data-rows': JSON.stringify(safeJsonClone(attributes.rows ?? [], [])) })
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

            let { title, columns, rows } = cloneDatabaseState(node.attrs);
            let lastIsEditable = editor.isEditable;
            let cancelActiveResize = null;
            let activeCellRefs = [];
            let commitTimer = null;

            const buildSnapshotFromDom = () => {
                const titleEl = container.querySelector('.database-title-input');
                if (titleEl) title = titleEl.value;

                const colTitleEls = Array.from(container.querySelectorAll('.database-col-title'));
                colTitleEls.forEach((el, index) => {
                    if (columns[index]) columns[index].title = el.value;
                });

                flushDirtyCells();
            };

            const buildAttrsSnapshot = () => cloneDatabaseState({ title, columns, rows });

            const commitToDocument = ({ syncDom = true } = {}) => {
                if (syncDom) buildSnapshotFromDom();
                const nextAttrs = buildAttrsSnapshot();

                try {
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        const currentNode = editor.state.doc.nodeAt(pos);
                        if (!currentNode) return false;

                        const currentJson = JSON.stringify(currentNode.attrs);
                        const nextJson = JSON.stringify(nextAttrs);
                        if (currentJson === nextJson) return false;

                        const tr = editor.view.state.tr;
                        tr.setNodeMarkup(pos, null, {
                            ...currentNode.attrs,
                            ...nextAttrs
                        });
                        editor.view.dispatch(tr);
                        return true;
                    }

                    if (typeof updateAttributes === 'function') {
                        updateAttributes(nextAttrs);
                        return true;
                    }
                } catch (error) {
                    console.error('[DatabaseBlock] 데이터 저장 실패:', error);
                }

                return false;
            };

            const scheduleCommit = (delay = 120) => {
                if (commitTimer) clearTimeout(commitTimer);
                commitTimer = setTimeout(() => {
                    commitTimer = null;
                    commitToDocument();
                }, delay);
            };

            const flushScheduledCommit = () => {
                if (commitTimer) {
                    clearTimeout(commitTimer);
                    commitTimer = null;
                }
                const changed = commitToDocument();
                if (changed) {
                    try {
                        document.dispatchEvent(new CustomEvent('nteok:database-block-committed'));
                    } catch (_) {}
                }
                return changed;
            };

            const flushDirtyCells = () => {
                let changed = false;
                for (const ref of activeCellRefs) {
                    if (!ref.el || !ref.el.isConnected) continue;
                    const newValue = sanitizeCellHtml(ref.el.innerHTML);
                    if (ref.row.values[ref.colId] !== newValue) {
                        ref.row.values[ref.colId] = newValue;
                        changed = true;
                    }
                }
                return changed;
            };

            const render = () => {
                if (cancelActiveResize) { cancelActiveResize(); cancelActiveResize = null; }
                flushDirtyCells();
                activeCellRefs = [];
                lastIsEditable = editor.isEditable;
                container.innerHTML = '';
                
                const header = document.createElement('div');
                header.className = 'database-header';
                const titleInput = document.createElement('input');
                titleInput.className = 'database-title-input';
                titleInput.value = title;
                titleInput.placeholder = '데이터베이스 제목';
                titleInput.readOnly = !editor.isEditable;
                titleInput.oninput = () => {
                    title = titleInput.value;
                    scheduleCommit();
                };
                titleInput.onchange = () => flushScheduledCommit();
                header.appendChild(titleInput);
                container.appendChild(header);

                const tableWrapper = document.createElement('div');
                tableWrapper.className = 'database-table-wrapper';
                const table = document.createElement('table');
                table.className = 'database-table';

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

                const startColResize = (e, colIndex, handleEl) => {
                    if (typeof e.button === 'number' && e.button !== 0) return;
                    e.preventDefault(); e.stopPropagation();
                    
                    const startX = e.clientX;
                    const cellEl = handleEl.parentElement;
                    const startWidth = cellEl.offsetWidth;
                    
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
                    const onUp = () => { cleanup(); flushScheduledCommit(); };
                    cancelActiveResize = cleanup;
                    window.addEventListener('pointermove', onMove, { passive: false });
                    window.addEventListener('pointerup', onUp, { once: true });
                };

                const startRowResize = (e, trEl, rowObj, handleEl) => {
                    if (typeof e.button === 'number' && e.button !== 0) return;
                    e.preventDefault(); e.stopPropagation();

                    const startY = e.clientY;
                    const startHeight = trEl.offsetHeight; 

                    handleEl?.setPointerCapture?.(e.pointerId);
                    document.body.classList.add('db-resizing', 'db-resizing-row');

                    const onMove = (moveEvent) => {
                        moveEvent.preventDefault?.();
                        const delta = moveEvent.clientY - startY;
                        const px = Math.round(Math.max(36, startHeight + delta)) + 'px';
                        trEl.style.height = px;
                        trEl.querySelectorAll('td').forEach(td => { td.style.height = px; });
                        rowObj.height = px;
                    };
                    const cleanup = () => {
                        window.removeEventListener('pointermove', onMove);
                        window.removeEventListener('pointerup', onUp);
                        document.body.classList.remove('db-resizing', 'db-resizing-col', 'db-resizing-row');
                        cancelActiveResize = null;
                    };
                    const onUp = () => { cleanup(); flushScheduledCommit(); };
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
                    colTitle.oninput = () => {
                        col.title = colTitle.value;
                        scheduleCommit();
                    };
                    colTitle.onchange = () => flushScheduledCommit();
                    
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
                                commitToDocument({ syncDom: false });
                                render();
                            }
                        };
                        thContent.appendChild(delColBtn);
                    }
                    
                    th.appendChild(thContent);

                    if (editor.isEditable) {
                        th.appendChild(makeColResizer(index));
                    }

                    headerRow.appendChild(th);
                });
                
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
                        commitToDocument({ syncDom: false });
                        render();
                    };
                    thAddCol.appendChild(addColBtn);
                    headerRow.appendChild(thAddCol);
                }
                
                thead.appendChild(headerRow);
                table.appendChild(thead);
                
                const tbody = document.createElement('tbody');
                rows.forEach((row, rowIndex) => {
                    const tr = document.createElement('tr');
                    const rowHeightPx = (row.height && row.height !== 'auto') ? row.height : null;
                    if (rowHeightPx) tr.style.height = rowHeightPx;

                    columns.forEach((col, colIndex) => {
                        const td = document.createElement('td');
                        if (rowHeightPx) td.style.height = rowHeightPx;
                        const cell = document.createElement('div');
                        cell.className = 'database-cell';
                        cell.contentEditable = editor.isEditable ? 'true' : 'false';
                        cell.innerHTML = sanitizeCellHtml(row.values[col.id]);
                        cell.oninput = () => scheduleCommit();
                        cell.onblur = () => flushScheduledCommit();
                        cell.onkeydown = (e) => {
                            if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); cell.blur(); return; }
                            e.stopPropagation();
                        };
                        if (editor.isEditable) activeCellRefs.push({ el: cell, row, colId: col.id });
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
                        if (rowHeightPx) tdDelRow.style.height = rowHeightPx;
                        const delRowBtn = document.createElement('button');
                        delRowBtn.className = 'database-del-row-btn';
                        delRowBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
                        delRowBtn.onclick = (e) => {
                            e.stopPropagation();
                            if (rows.length > 1) {
                                rows.splice(rowIndex, 1);
                                commitToDocument({ syncDom: false });
                                render();
                            }
                        };
                        tdDelRow.appendChild(delRowBtn);

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
                        commitToDocument({ syncDom: false });
                        render();
                    };
                    container.appendChild(addRowBtn);
                }
            };

            const checkEditable = () => { if (editor.isEditable !== lastIsEditable) render(); };
            editor.on('transaction', checkEditable);
            const observer = new MutationObserver(() => checkEditable());
            const handleExternalFlush = () => flushScheduledCommit();
            if (editor.view && editor.view.dom) {
                observer.observe(editor.view.dom, { attributes: true, attributeFilter: ['contenteditable'] });
            }
            document.addEventListener('nteok:flush-nodeviews', handleExternalFlush);

            render();

            return {
                dom: container,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== node.type.name) return false;
                    const incoming = cloneDatabaseState(updatedNode.attrs);
                    const incomingJson = JSON.stringify(incoming);
                    const currentJson = JSON.stringify(buildAttrsSnapshot());
                    if (incomingJson !== currentJson) {
                        title = incoming.title;
                        columns = incoming.columns;
                        rows = incoming.rows;
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
                    flushScheduledCommit();
                    document.removeEventListener('nteok:flush-nodeviews', handleExternalFlush);
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
