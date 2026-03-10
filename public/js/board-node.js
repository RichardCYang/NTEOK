
import { addIcon } from './ui-utils.js';
import * as DOMPurifyModule from '../lib/dompurify/dompurify.js';
import { safeJsonClone, safeJsonParse } from './safe-json.js';

function createPurifier() {
    let m = DOMPurifyModule;
    if (m.default) m = m.default;
    if (typeof m === 'function' && !m.sanitize) return m(window);
    return m;
}
const DOMPurify = createPurifier();

const Node = Tiptap.Core.Node;

const BOARD_CARD_PURIFY_CONFIG = {
    USE_PROFILES: { html: true },
    ALLOWED_TAGS: [
        'br','p','div','span',
        'strong','b','em','i','u','s',
        'code','pre','ul','ol','li','blockquote',
        'a'
    ],
    ALLOWED_ATTR: ['href','target','rel'],
    FORBID_TAGS: ['style','script','svg','math'],
};

function sanitizeBoardCardHtml(html) {
    const clean = DOMPurify.sanitize(String(html ?? ''), BOARD_CARD_PURIFY_CONFIG);

    const tmp = document.createElement('div');
    tmp.innerHTML = clean;
    tmp.querySelectorAll('a').forEach((a) => {
        const target = (a.getAttribute('target') || '').toLowerCase();
        if (target === '_blank') {
            const rel = new Set((a.getAttribute('rel') || '').split(/\s+/).filter(Boolean).map((s) => s.toLowerCase()));
            rel.add('noopener');
            rel.add('noreferrer');
            a.setAttribute('rel', Array.from(rel).join(' '));
        }
    });
    return tmp.innerHTML;
}

function sanitizeBoardColumns(columns) {
    if (!Array.isArray(columns)) return columns;
    for (const col of columns) {
        if (!col || typeof col !== 'object') continue;
        if (!Array.isArray(col.cards)) col.cards = [];
        for (const card of col.cards) {
            if (!card || typeof card !== 'object') continue;
            card.content = sanitizeBoardCardHtml(card.content);
        }
    }
    return columns;
}

const BOARD_THEME_ICONS = [
    'fa-solid fa-star', 'fa-solid fa-heart', 'fa-solid fa-flag',
    'fa-solid fa-circle-check', 'fa-solid fa-circle-info', 'fa-solid fa-circle-exclamation', 'fa-solid fa-circle-xmark',
    'fa-solid fa-lightbulb', 'fa-solid fa-fire', 'fa-solid fa-bolt', 'fa-solid fa-bell',
    'fa-solid fa-user', 'fa-solid fa-users', 'fa-solid fa-calendar', 'fa-solid fa-clock',
    'fa-solid fa-tag', 'fa-solid fa-tags', 'fa-solid fa-trophy', 'fa-solid fa-gift'
];

const BOARD_EMOJI_ICONS = [
    '⭐', '❤️', '🚩', '✅', 'ℹ️', '⚠️', '❌',
    '💡', '🔥', '⚡', '🔔', '👤', '👥', '📅', '⏰',
    '🏷️', '🎯', '🏆', '🎁'
];

const BOARD_CARD_COLORS = [
    { name: '기본', value: 'default', bg: 'var(--primary-color)' },
    { name: '노랑', value: 'yellow', bg: 'var(--board-card-yellow)' },
    { name: '파랑', value: 'blue', bg: 'var(--board-card-blue)' },
    { name: '초록', value: 'green', bg: 'var(--board-card-green)' },
    { name: '분홍', value: 'pink', bg: 'var(--board-card-pink)' },
    { name: '보라', value: 'purple', bg: 'var(--board-card-purple)' },
    { name: '주황', value: 'orange', bg: 'var(--board-card-orange)' }
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
                    let data = element.getAttribute('data-columns');
                    if (!data) return null;
                    const div = document.createElement('div');
                    div.innerHTML = data;
                    data = div.textContent;
                    const parsed = safeJsonParse(data, null);
                    return parsed ? sanitizeBoardColumns(parsed) : null;
                },
                renderHTML: attributes => {
                    const safeColumns = sanitizeBoardColumns(safeJsonClone(attributes.columns ?? [], []));
                    const json = JSON.stringify(safeColumns);
                    const div = document.createElement('div');
                    div.textContent = json;
                    return { 'data-columns': div.innerHTML };
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

            let columns = sanitizeBoardColumns(safeJsonClone(node.attrs.columns, []));
            let draggedCardId = null;
            let draggedFromColId = null;
            let lastIsEditable = editor.isEditable;
            let saveTimer = null;
            let cardDomRefs = [];
            let isComposing = false;
            let pendingFlushAfterComposition = false;
            let lastCommittedColumnsJson = JSON.stringify(columns);
            let pendingDocumentSyncJson = null;

            const buildColumnsSnapshot = (inputColumns = columns) =>
                sanitizeBoardColumns(safeJsonClone(inputColumns ?? [], []));

            const buildColumnsJson = (inputColumns = columns) =>
                JSON.stringify(buildColumnsSnapshot(inputColumns));

            const getDocumentSnapshotState = () => {
                const docColumns = readColumnsFromDocument();
                return {
                    docColumns,
                    docJson: docColumns ? JSON.stringify(docColumns) : null,
                    localJson: buildColumnsJson(),
                };
            };

            const hasDocumentDrift = (snapshot = getDocumentSnapshotState()) =>
                snapshot.docJson !== null && snapshot.docJson !== snapshot.localJson;

            const hasPendingLocalColumns = () => {
                const snapshot = getDocumentSnapshotState();
                return !!saveTimer ||
                    pendingFlushAfterComposition ||
                    !!pendingDocumentSyncJson ||
                    hasDocumentDrift(snapshot);
            };

            const readColumnsFromDocument = () => {
                if (typeof getPos !== 'function') return null;

                try {
                    const pos = getPos();
                    const currentNode = editor.state.doc.nodeAt(pos);
                    if (!currentNode || currentNode.type.name !== node.type.name) return null;
                    return buildColumnsSnapshot(currentNode.attrs.columns);
                } catch (_) {
                    return null;
                }
            };

            const syncCardDomToState = (card, cardContent, { writeBackToDom = false } = {}) => {
                let raw = String(cardContent?.innerHTML ?? '');
                const tmp = document.createElement('div');
                tmp.innerHTML = raw;
                if (!tmp.textContent.trim() && !tmp.querySelector('br')) raw = '';

                const sanitized = sanitizeBoardCardHtml(raw);

                if (writeBackToDom && !isComposing && sanitized !== raw) cardContent.innerHTML = sanitized;

                if (sanitized !== card.content) {
                    card.content = sanitized;
                    return true;
                }
                return false;
            };

            const findLiveCard = (refCard, refColumn) => {
                if (!refCard) return null;
                const col = refColumn
                    ? columns.find(c => c.id === refColumn.id)
                    : columns.find(c => c.cards.some(cd => cd.id === refCard.id));
                if (!col) return null;
                return col.cards.find(cd => cd.id === refCard.id) || null;
            };

            const syncAllCardDomToState = ({ writeBackToDom = false } = {}) => {
                let changed = false;

                cardDomRefs.forEach(({ el, card, cardEl, column }) => {
                    if (!el || !cardEl || !cardEl.isConnected || !card) return;
                    if (syncCardDomToState(card, el, { writeBackToDom })) changed = true;
                    const live = findLiveCard(card, column);
                    if (live && live !== card && live.content !== card.content) {
                        live.content = card.content;
                        changed = true;
                    }
                });

                return changed;
            };

            const commitColumns = ({ syncDom = false, writeBackToDom = false } = {}) => {
                if (typeof getPos !== 'function') return false;

                if (syncDom) {
                    if (isComposing) {
                        pendingFlushAfterComposition = true;
                        return false;
                    }
                    syncAllCardDomToState({ writeBackToDom });
                }

                const normalizedColumns = buildColumnsSnapshot();
                const normalizedJson = JSON.stringify(normalizedColumns);
                const pos = getPos();

                try {
                    const currentNode = editor.state.doc.nodeAt(pos);
                    const currentAttrs = currentNode?.attrs || {};
                    const currentJson = JSON.stringify(buildColumnsSnapshot(currentAttrs.columns));

                    columns = normalizedColumns;
                    lastCommittedColumnsJson = normalizedJson;

                    if (currentJson === normalizedJson) {
                        pendingDocumentSyncJson = null;
                        return false;
                    }

                    pendingDocumentSyncJson = normalizedJson;

                    const tr = editor.view.state.tr;
                    tr.setNodeMarkup(pos, null, { ...currentAttrs, columns: normalizedColumns });
                    editor.view.dispatch(tr);
                    return true;
                } catch (error) {
                    pendingDocumentSyncJson = null;
                    console.error('[BoardBlock] 데이터 저장 실패:', error);
                    return false;
                }
            };

            const scheduleSaveData = () => {
                if (isComposing) {
                    pendingFlushAfterComposition = true;
                    return;
                }
                if (saveTimer) clearTimeout(saveTimer);
                saveTimer = setTimeout(() => {
                    saveTimer = null;
                    commitColumns({ syncDom: true, writeBackToDom: false });
                }, 150);
            };

            const flushScheduledSaveData = () => {
                if (saveTimer) {
                    clearTimeout(saveTimer);
                    saveTimer = null;
                }
                return commitColumns({ syncDom: true, writeBackToDom: true });
            };

            const flushCardDomRefs = ({ writeBackToDom = true } = {}) => {
                if (isComposing) {
                    pendingFlushAfterComposition = true;
                    return false;
                }

                const changed = syncAllCardDomToState({ writeBackToDom });
                if (changed || saveTimer) return flushScheduledSaveData();
                return false;
            };

            const showIconPickerPopup = (targetEl, onSelect) => {
                if (!editor.isEditable) return;

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

                        if (tab === 'theme') addIcon(btn, iconValue);
                        else btn.textContent = iconValue;

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

                const closePopup = (e) => {
                    if (!popup.contains(e.target) && !targetEl.contains(e.target)) {
                        popup.remove();
                        document.removeEventListener('mousedown', closePopup);
                    }
                };
                document.addEventListener('mousedown', closePopup);
            };

            const showColorPickerPopup = (targetEl, onSelect) => {
                if (!editor.isEditable) return;

                const existingPopup = document.querySelector('.board-color-picker-popup');
                if (existingPopup) existingPopup.remove();

                const popup = document.createElement('div');
                popup.className = 'board-color-picker-popup';
                popup.style.cssText = `
                    position: absolute;
                    background: var(--primary-color, white);
                    border: 1px solid var(--border-color, #ccc);
                    border-radius: 8px;
                    padding: 8px;
                    z-index: 10000;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    display: grid;
                    grid-template-columns: repeat(4, 1fr);
                    gap: 8px;
                `;

                BOARD_CARD_COLORS.forEach(color => {
                    const btn = document.createElement('button');
                    btn.title = color.name;
                    btn.style.cssText = `
                        width: 24px;
                        height: 24px;
                        border-radius: 50%;
                        border: 1px solid var(--border-color);
                        background-color: ${color.bg === 'var(--primary-color)' ? 'white' : color.bg};
                        cursor: pointer;
                        padding: 0;
                    `;

                    if (color.value === 'default') {
                        btn.innerHTML = '<i class="fa-solid fa-ban" style="font-size: 10px; color: #999;"></i>';
                        btn.style.display = 'flex';
                        btn.style.alignItems = 'center';
                        btn.style.justifyContent = 'center';
                    }

                    btn.onclick = (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        onSelect(color.value);
                        popup.remove();
                    };
                    popup.appendChild(btn);
                });

                document.body.appendChild(popup);
                const rect = targetEl.getBoundingClientRect();
                popup.style.left = `${rect.left}px`;
                popup.style.top = `${rect.bottom + 5}px`;

                const closePopup = (e) => {
                    if (!popup.contains(e.target) && !targetEl.contains(e.target)) {
                        popup.remove();
                        document.removeEventListener('mousedown', closePopup);
                    }
                };
                document.addEventListener('mousedown', closePopup);
            };

            const render = ({ flushDom = true } = {}) => {
                if (flushDom && cardDomRefs.length > 0) {
                    flushCardDomRefs();
                }
                lastIsEditable = editor.isEditable;
                cardDomRefs = [];
                container.innerHTML = '';

                const columnsWrapper = document.createElement('div');
                columnsWrapper.className = 'board-columns-wrapper';

                columns.forEach(column => {
                    const colEl = document.createElement('div');
                    colEl.className = 'board-column';
                    colEl.dataset.colId = column.id;

                    const header = document.createElement('div');
                    header.className = 'board-column-header';

                    const titleInput = document.createElement('input');
                    titleInput.className = 'board-column-title';
                    titleInput.value = column.title;
                    titleInput.placeholder = '컬럼 제목';

                    if (editor.isEditable) {
                        titleInput.onchange = (e) => {
                            column.title = e.target.value;
                            flushScheduledSaveData();
                        };
                    } else {
                        titleInput.readOnly = true;
                    }

                    const deleteColBtn = document.createElement('button');
                    deleteColBtn.className = 'board-column-delete-btn';
                    deleteColBtn.innerHTML = '×';
                    deleteColBtn.title = '컬럼 삭제';
                    if (editor.isEditable) {
                        deleteColBtn.onclick = () => {
                            if (confirm('이 컬럼과 포함된 모든 카드를 삭제하시겠습니까?')) {
                                columns = columns.filter(c => c.id !== column.id);
                                flushScheduledSaveData();
                                render();
                            }
                        };
                    } else {
                        deleteColBtn.style.display = 'none';
                    }

                    header.appendChild(titleInput);
                    header.appendChild(deleteColBtn);
                    colEl.appendChild(header);

                    const cardList = document.createElement('div');
                    cardList.className = 'board-card-list';
                    cardList.dataset.colId = column.id;

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
                            const fromCol = columns.find(c => c.id === draggedFromColId);
                            const cardIndex = fromCol.cards.findIndex(c => c.id === draggedCardId);
                            if (cardIndex === -1) return;
                            const [card] = fromCol.cards.splice(cardIndex, 1);

                            const toCol = columns.find(c => c.id === toColId);
                            toCol.cards.push(card);

                            draggedCardId = null;
                            draggedFromColId = null;
                            flushScheduledSaveData();
                            render();
                        };
                    }

                    column.cards.forEach(card => {
                        const cardEl = document.createElement('div');
                        cardEl.className = `board-card ${card.color ? 'color-' + card.color : ''}`;
                        cardEl.dataset.cardId = card.id;
                        cardEl.draggable = false;

                        if (editor.isEditable) {
                            cardEl.ondragstart = (e) => {
                                const existingPopup = document.querySelector('.board-icon-picker-popup') || document.querySelector('.board-color-picker-popup');
                                if (existingPopup) existingPopup.remove();

                                draggedCardId = card.id;
                                draggedFromColId = column.id;
                                e.dataTransfer.effectAllowed = 'move';
                                e.dataTransfer.setData('text/plain', card.id);

                                setTimeout(() => cardEl.classList.add('dragging'), 0);
                            };
                            cardEl.ondragend = () => {
                                cardEl.classList.remove('dragging');
                                draggedCardId = null;
                                draggedFromColId = null;
                            };
                        }

                        const cardHeader = document.createElement('div');
                        cardHeader.className = 'board-card-header';

                        const hasIcon = !!card.icon;
                        if (!editor.isEditable && !hasIcon) cardHeader.style.display = 'none';
                        else cardHeader.style.display = 'flex';

                        if (editor.isEditable) {
                            cardHeader.onmouseenter = () => { cardEl.draggable = true; };
                            cardHeader.onmouseleave = () => { cardEl.draggable = false; };
                        }

                        cardHeader.style.justifyContent = 'space-between';
                        cardHeader.style.alignItems = 'flex-start';
                        cardHeader.style.marginBottom = '4px';

                        const cardHeaderLeft = document.createElement('div');
                        cardHeaderLeft.style.display = 'flex';
                        cardHeaderLeft.style.gap = '4px';
                        cardHeaderLeft.style.alignItems = 'center';

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
                                } else iconBtn.textContent = card.icon;
                            } else if (editor.isEditable) iconBtn.innerHTML = '<i class="fa-regular fa-face-smile" style="opacity: 0.3;"></i>';
                        };
                        renderIcon();

                        if (editor.isEditable) {
                            iconBtn.onclick = (e) => {
                                e.stopPropagation();
                                showIconPickerPopup(iconBtn, (newIcon) => {
                                    card.icon = newIcon;
                                    renderIcon();
                                    flushScheduledSaveData();
                                });
                            };
                        }

                        const colorBtn = document.createElement('div');
                        colorBtn.className = 'board-card-color-btn';
                        colorBtn.innerHTML = '<i class="fa-solid fa-palette" style="font-size: 12px; opacity: 0.5;"></i>';
                        colorBtn.style.cursor = editor.isEditable ? 'pointer' : 'default';
                        colorBtn.style.display = editor.isEditable ? 'flex' : 'none';
                        colorBtn.style.alignItems = 'center';
                        colorBtn.style.justifyContent = 'center';
                        colorBtn.style.width = '20px';
                        colorBtn.style.height = '20px';
                        colorBtn.style.borderRadius = '3px';

                        if (editor.isEditable) {
                            colorBtn.onclick = (e) => {
                                e.stopPropagation();
                                showColorPickerPopup(colorBtn, (newColor) => {
                                    card.color = newColor;
                                    flushScheduledSaveData();
                                    render();
                                });
                            };
                        }

                        cardHeaderLeft.appendChild(iconBtn);
                        cardHeaderLeft.appendChild(colorBtn);
                        cardHeader.appendChild(cardHeaderLeft);

                        const deleteCardBtn = document.createElement('button');
                        deleteCardBtn.className = 'board-card-delete-btn';
                        deleteCardBtn.innerHTML = '×';
                        if (editor.isEditable) {
                            deleteCardBtn.onclick = (e) => {
                                e.stopPropagation();
                                if (confirm('이 카드를 삭제하시겠습니까?')) {
                                    column.cards = column.cards.filter(c => c.id !== card.id);
                                    flushScheduledSaveData();
                                    render();
                                }
                            };
                        } else deleteCardBtn.style.display = 'none';

                        cardHeader.appendChild(deleteCardBtn);
                        cardEl.appendChild(cardHeader);

                        const cardContent = document.createElement('div');
                        cardContent.className = 'board-card-content';
                        cardContent.contentEditable = editor.isEditable ? 'true' : 'false';

                        const safeInitial = sanitizeBoardCardHtml(card.content);
                        if (safeInitial !== card.content) card.content = safeInitial;
                        cardContent.innerHTML = safeInitial;

                        if (editor.isEditable) {
                            cardContent.onfocus = () => {
                                const toolbar = document.querySelector('.editor-toolbar');
                                if (toolbar) toolbar.classList.add('visible');
                            };

                            cardContent.oncompositionstart = () => {
                                isComposing = true;
                            };

                            cardContent.oncompositionend = () => {
                                isComposing = false;
                                queueMicrotask(() => {
                                    const changed = syncCardDomToState(card, cardContent, { writeBackToDom: true });
                                    if (pendingFlushAfterComposition) {
                                        pendingFlushAfterComposition = false;
                                        flushScheduledSaveData();
                                    } else if (changed) scheduleSaveData();
                                });
                            };

                            cardContent.oninput = (e) => {
                                if (e?.isComposing || isComposing) {
                                    pendingFlushAfterComposition = true;
                                    return;
                                }
                                if (syncCardDomToState(card, cardContent, { writeBackToDom: false })) scheduleSaveData();
                            };

                            cardContent.onblur = () => {
                                queueMicrotask(() => {
                                    const changed = syncCardDomToState(card, cardContent, { writeBackToDom: true });
                                    if (isComposing) {
                                        pendingFlushAfterComposition = true;
                                        return;
                                    }
                                    if (changed || pendingFlushAfterComposition || saveTimer) {
                                        pendingFlushAfterComposition = false;
                                        flushScheduledSaveData();
                                    }
                                });
                            };

                            cardContent.onkeydown = (e) => {
                                if (e.ctrlKey || e.metaKey) {
                                    if (['b', 'i', 'u', 's'].includes(e.key.toLowerCase())) return;
                                }
                                e.stopPropagation();
                            };
                        }

                        cardDomRefs.push({ el: cardContent, cardEl, card, column });
                        cardEl.appendChild(cardContent);
                        cardList.appendChild(cardEl);
                    });

                    colEl.appendChild(cardList);

                    if (editor.isEditable) {
                        const addCardBtn = document.createElement('button');
                        addCardBtn.className = 'board-add-card-btn';
                        addCardBtn.textContent = '+ 카드 추가';
                        addCardBtn.onclick = () => {
                            const newCard = {
                                id: 'card-' + Date.now() + Math.random().toString(36).substr(2, 9),
                                content: '새 카드',
                                icon: null,
                                color: 'default'
                            };
                            column.cards.push(newCard);
                            flushScheduledSaveData();
                            render();
                        };
                        colEl.appendChild(addCardBtn);
                    }

                    columnsWrapper.appendChild(colEl);
                });

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
                        flushScheduledSaveData();
                        render();
                    };
                    columnsWrapper.appendChild(addColBtn);
                }

                container.appendChild(columnsWrapper);
            };

            render({ flushDom: false });

            const checkEditable = () => {
                const nextIsEditable = editor.isEditable;
                if (nextIsEditable === lastIsEditable) return;

                const wasEditable = lastIsEditable;
                lastIsEditable = nextIsEditable;

                if (wasEditable) {
                    if (isComposing) isComposing = false;
                    pendingFlushAfterComposition = false;
                    flushCardDomRefs({ writeBackToDom: true });
                }

                const { docColumns, docJson, localJson } = getDocumentSnapshotState();
                const canAdoptDocumentSnapshot =
                    !!docColumns &&
                    (
                        !hasPendingLocalColumns() ||
                        docJson === localJson ||
                        (!!pendingDocumentSyncJson && docJson === pendingDocumentSyncJson)
                    );

                if (canAdoptDocumentSnapshot && docJson !== localJson) columns = docColumns;
                if (canAdoptDocumentSnapshot && docJson) {
                    lastCommittedColumnsJson = docJson;
                    if (pendingDocumentSyncJson === docJson) pendingDocumentSyncJson = null;
                }

                render({ flushDom: false });
            };

            editor.on('transaction', checkEditable);

            const observer = new MutationObserver((mutations) => {
                checkEditable();
            });

            const handleExternalFlush = () => {
                if (isComposing) isComposing = false;
                pendingFlushAfterComposition = false;
                flushCardDomRefs();
            };

            if (editor.view && editor.view.dom) {
                observer.observe(editor.view.dom, {
                    attributes: true,
                    attributeFilter: ['contenteditable']
                });
            }

            document.addEventListener('nteok:flush-nodeviews', handleExternalFlush);

            return {
                dom: container,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== node.type.name) return false;

                    if (!isComposing) syncAllCardDomToState({ writeBackToDom: false });

                    const isEditableChanged = editor.isEditable !== lastIsEditable;
                    const nextColumns = buildColumnsSnapshot(updatedNode.attrs.columns);
                    const nextJson = JSON.stringify(nextColumns);
                    const snapshotState = getDocumentSnapshotState();
                    const { docJson, localJson } = snapshotState;
                    const hasPendingLocalChanges =
                        !!saveTimer ||
                        pendingFlushAfterComposition ||
                        !!pendingDocumentSyncJson ||
                        hasDocumentDrift(snapshotState);
                    const isIncomingCommittedEcho = !!pendingDocumentSyncJson && nextJson === pendingDocumentSyncJson;
                    const isIncomingStaleComparedToLocal = nextJson !== localJson;
                    const isIncomingStaleComparedToDocument = docJson !== null && nextJson !== docJson;
                    const shouldIgnoreIncoming =
                        (!!pendingDocumentSyncJson &&
                            localJson === pendingDocumentSyncJson &&
                            nextJson !== pendingDocumentSyncJson) ||
                        (hasPendingLocalChanges && isIncomingStaleComparedToLocal && isIncomingStaleComparedToDocument);

                    if (isIncomingCommittedEcho) pendingDocumentSyncJson = null;

                    if (shouldIgnoreIncoming) {
                        if (isEditableChanged) render({ flushDom: false });
                        return true;
                    }

                    if (!hasPendingLocalChanges || nextJson === localJson || isIncomingCommittedEcho || nextJson === lastCommittedColumnsJson) {
                        if (nextJson !== localJson) columns = nextColumns;
                        if (nextJson !== localJson || isEditableChanged) render({ flushDom: false });
                    } else if (isEditableChanged) render({ flushDom: false });

                    return true;
                },
                stopEvent: (event) => {
                    const target = event.target;
                    if (!(target instanceof HTMLElement)) return false;
                    if (
                        target.classList.contains('board-card-content') ||
                        target.tagName === 'INPUT' ||
                        target.tagName === 'BUTTON' ||
                        target.closest('.board-icon-picker-popup') ||
                        target.closest('.board-color-picker-popup')
                    ) return true;
                    return false;
                },
                ignoreMutation: () => true,
                destroy: () => {
                    if (isComposing) {
                        isComposing = false;
                        syncAllCardDomToState({ writeBackToDom: false });
                    }
                    flushCardDomRefs();
                    document.removeEventListener('nteok:flush-nodeviews', handleExternalFlush);
                    if (saveTimer) {
                        clearTimeout(saveTimer);
                        saveTimer = null;
                    }
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
