/**
 * Tiptap Bookmark Node Extension
 * URL에서 메타데이터를 추출하여 북마크 카드를 표시하는 커스텀 노드
 */

import { secureFetch, addIcon } from './ui-utils.js';
import { sanitizeHttpHref } from './url-utils.js';

const Node = Tiptap.Core.Node;

// 아이콘 선택용 기본 아이콘 목록
const BOOKMARK_THEME_ICONS = [
    'fa-solid fa-bookmark', 'fa-solid fa-star', 'fa-solid fa-heart', 'fa-solid fa-flag',
    'fa-solid fa-book', 'fa-solid fa-book-open', 'fa-solid fa-link', 'fa-solid fa-folder',
    'fa-solid fa-tag', 'fa-solid fa-tags', 'fa-solid fa-circle-check', 'fa-solid fa-lightbulb',
    'fa-solid fa-fire', 'fa-solid fa-bell', 'fa-solid fa-gift', 'fa-solid fa-trophy'
];

const BOOKMARK_EMOJI_ICONS = [
    '🔖', '⭐', '❤️', '🚩', '📚', '📖', '🔗', '📁',
    '🏷️', '🎯', '✅', '💡', '🔥', '📢', '🎁', '🏆'
];

export const BookmarkBlock = Node.create({
    name: 'bookmarkBlock',

    group: 'bookmarkItem',

    atom: true,

    addAttributes() {
        return {
            url: {
                default: '',
                parseHTML: element => {
                    const raw = element.getAttribute('data-url') || '';
                    return sanitizeHttpHref(raw, { allowRelative: false }) || '';
                },
                renderHTML: attributes => {
                    const safe = sanitizeHttpHref(attributes.url, { allowRelative: false }) || '';
                    return { 'data-url': safe };
                }
            },
            title: {
                default: '',
                parseHTML: element => element.getAttribute('data-title') || '',
                renderHTML: attributes => {
                    return { 'data-title': attributes.title };
                }
            },
            description: {
                default: '',
                parseHTML: element => element.getAttribute('data-description') || '',
                renderHTML: attributes => {
                    return { 'data-description': attributes.description };
                }
            },
            thumbnail: {
                default: '',
                parseHTML: element => {
                    const raw = element.getAttribute('data-thumbnail') || '';
                    return sanitizeHttpHref(raw, { allowRelative: false }) || '';
                },
                renderHTML: attributes => {
                    const safe = sanitizeHttpHref(attributes.thumbnail, { allowRelative: false }) || '';
                    return { 'data-thumbnail': safe };
                }
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="bookmark-block"]'
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        const safeUrl = sanitizeHttpHref(node.attrs.url, { allowRelative: false }) || '';
        const safeThumbnail = sanitizeHttpHref(node.attrs.thumbnail, { allowRelative: false }) || '';
        // Tiptap의 HTMLAttributes와 커스텀 속성을 병합하여 반환
        return [
            'div',
            {
                ...HTMLAttributes,
                'data-type': 'bookmark-block',
                'class': 'bookmark-block',
                // 아래 속성들은 HTMLAttributes에 이미 포함되어 있을 수 있지만, 
                // 명시적으로 한 번 더 확인하여 저장 보장
                'data-url': safeUrl,
                'data-title': node.attrs.title || '',
                'data-description': node.attrs.description || '',
                'data-thumbnail': safeThumbnail
            }
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            // 전체 wrapper
            const wrapper = document.createElement('div');
            wrapper.className = 'bookmark-block-wrapper';
            wrapper.contentEditable = 'false';

            let isEditing = false;
            const rawInitialUrl = node.attrs.url || '';
            // href로 사용 가능한 안전 URL만 보존
            let currentUrl = sanitizeHttpHref(rawInitialUrl, { allowRelative: false }) || '';
            let currentMetadata = {
                title: node.attrs.title || '',
                description: node.attrs.description || '',
                thumbnail: node.attrs.thumbnail || ''
            };

            // 북마크 카드 렌더링 함수
            const showBookmarkCard = () => {
                wrapper.innerHTML = '';

                if (!currentUrl) {
                    // URL이 없으면 입력 폼 표시
                    showEditForm();
                    return;
                }

                // 북마크 카드 컨테이너
                const card = document.createElement('a');
                card.className = 'bookmark-card';
                // 혹시라도 currentUrl이 비어있으면 링크를 무력화
                if (currentUrl) {
                    card.href = currentUrl;
                } else {
                    card.href = '#';
                    card.addEventListener('click', (e) => e.preventDefault());
                }
                card.target = '_blank';
                card.rel = 'noopener noreferrer';

                // 왼쪽: 텍스트 정보
                const textContainer = document.createElement('div');
                textContainer.className = 'bookmark-text';

                const titleElement = document.createElement('div');
                titleElement.className = 'bookmark-title';
                titleElement.textContent = currentMetadata.title || currentUrl;

                const descElement = document.createElement('div');
                descElement.className = 'bookmark-description';
                descElement.textContent = currentMetadata.description || '';

                const urlContainer = document.createElement('div');
                urlContainer.className = 'bookmark-url';
                urlContainer.textContent = currentUrl;

                textContainer.appendChild(titleElement);
                if (currentMetadata.description) {
                    textContainer.appendChild(descElement);
                }
                textContainer.appendChild(urlContainer);

                card.appendChild(textContainer);

                // 오른쪽: 썸네일
                const thumbnailContainer = document.createElement('div');
                thumbnailContainer.className = 'bookmark-thumbnail';

                if (currentMetadata.thumbnail) {
                    const thumbnail = document.createElement('img');

                    // 프록시 URL 사용 (CSP 정책 우회)
                    const proxyUrl = `/api/pages/proxy/image?url=${encodeURIComponent(currentMetadata.thumbnail)}`;
                    thumbnail.src = proxyUrl;
                    thumbnail.alt = currentMetadata.title || '';

                    thumbnail.onload = () => {
                        thumbnailContainer.classList.remove('error');
                    };

                    thumbnail.onerror = () => {
                        // 이미지 로드 실패 시 에러 상태로 표시
                        console.warn('[BookmarkBlock] 썸네일 로드 실패:', proxyUrl);
                        thumbnailContainer.classList.add('error');
                        thumbnail.style.display = 'none';
                    };

                    thumbnailContainer.appendChild(thumbnail);
                } else {
                    // 썸네일 URL이 없을 때
                    thumbnailContainer.classList.add('error');
                }

                // 에러 메시지 (항상 준비되어 있음)
                const errorMessage = document.createElement('div');
                errorMessage.className = 'bookmark-thumbnail-error';
                errorMessage.textContent = '이미지 없음';
                thumbnailContainer.appendChild(errorMessage);

                card.appendChild(thumbnailContainer);

                wrapper.appendChild(card);

                // 쓰기 모드에서만 편집 버튼 표시
                if (editor.isEditable) {
                    const editButton = document.createElement('button');
                    editButton.className = 'bookmark-edit-button';
                    editButton.textContent = '수정';
                    editButton.type = 'button';
                    editButton.onclick = (e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        showEditForm();
                    };
                    wrapper.appendChild(editButton);
                }
            };

            // URL 입력 폼 표시 함수
            const showEditForm = () => {
                isEditing = true;
                wrapper.innerHTML = '';

                const formContainer = document.createElement('div');
                formContainer.className = 'bookmark-edit-form';

                const input = document.createElement('input');
                input.type = 'url';
                input.className = 'bookmark-url-input';
                input.placeholder = 'URL을 입력하세요 (예: https://example.com)';
				// 편집 시에는 원문을 최대한 보존(단, 저장 시 sanitize)
				input.value = node.attrs.url || currentUrl;

                const buttonContainer = document.createElement('div');
                buttonContainer.className = 'bookmark-button-container';

                const saveButton = document.createElement('button');
                saveButton.textContent = '저장';
                saveButton.type = 'button';
                saveButton.className = 'bookmark-save-button';
                saveButton.onclick = async () => {
                    await fetchAndSaveMetadata(input.value);
                };

                const cancelButton = document.createElement('button');
                cancelButton.textContent = '취소';
                cancelButton.type = 'button';
                cancelButton.className = 'bookmark-cancel-button';
                cancelButton.onclick = () => {
                    isEditing = false;
                    if (currentUrl) {
                        showBookmarkCard();
                    } else {
                        // URL이 없으면 노드 삭제
                        deleteNode();
                    }
                };

                buttonContainer.appendChild(saveButton);
                buttonContainer.appendChild(cancelButton);

                formContainer.appendChild(input);
                formContainer.appendChild(buttonContainer);
                wrapper.appendChild(formContainer);

                // 입력 필드에 포커스
                setTimeout(() => input.focus(), 0);

                // Enter 키로 저장
                input.onkeydown = (e) => {
                    e.stopPropagation();
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        saveButton.click();
                    }
                    if (e.key === 'Escape') {
                        e.preventDefault();
                        cancelButton.click();
                    }
                };
            };

            // 메타데이터 가져오고 저장하는 함수
            const fetchAndSaveMetadata = async (url) => {
                if (!url) {
                    alert('URL을 입력해주세요.');
                    return;
                }

                // http/https allowlist 검증 (+ 스킴 누락 시 https:// 보정)
                const safeUrl = sanitizeHttpHref(url, { allowRelative: false });
                if (!safeUrl) {
                    alert('http/https URL만 허용됩니다.');
                    return;
                }

                // 로딩 표시
                wrapper.innerHTML = '<div class="bookmark-loading">메타데이터를 가져오는 중...</div>';

                try {
                    // 페이지 ID 가져오기
                    const pageId = window.appState?.currentPageId;
                    if (!pageId) {
                        alert('페이지 ID를 찾을 수 없습니다.');
                        showEditForm();
                        return;
                    }

                    // 메타데이터 API 호출
                    const response = await secureFetch(`/api/pages/${pageId}/bookmark-metadata`, {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ 'url':safeUrl })
                    });

                    if (!response.ok) {
                        let errorMessage = '메타데이터를 가져올 수 없습니다.';
                        try {
                            const errorData = await response.json();
                            if (errorData.error) {
                                errorMessage = errorData.error;
                            }
                        } catch (e) {
                            // JSON 파싱 실패 무시
                        }
                        throw new Error(errorMessage);
                    }

                    const data = await response.json();

                    if (!data.success) {
                        throw new Error(data.error || '메타데이터 추출 실패');
                    }

                    // 메타데이터 업데이트
                    currentUrl = safeUrl;
                    currentMetadata = {
                        title: data.metadata.title || safeUrl,
                        description: data.metadata.description || '',
                        thumbnail: data.metadata.thumbnail || ''
                    };

            // 에디터에 저장 (ProseMirror 트랜잭션 사용)
                    if (typeof getPos === 'function') {
                        const pos = getPos();
                        try {
                            const tr = editor.view.state.tr;
                            // 노드의 속성을 새 메타데이터로 업데이트
                            tr.setNodeMarkup(pos, null, {
                                url: currentUrl,
                                title: currentMetadata.title,
                                description: currentMetadata.description,
                                thumbnail: currentMetadata.thumbnail
                            });
                            editor.view.dispatch(tr);
                        } catch (error) {
                            console.error('[BookmarkBlock] 저장 실패:', error);
                        }
                    }

                    isEditing = false;
                    showBookmarkCard();

                } catch (error) {
                    console.error('[BookmarkBlock] 메타데이터 가져오기 실패:', error);
                    alert(error.message || '메타데이터를 가져오는데 실패했습니다.');
                    showEditForm();
                }
            };

            // 노드 삭제 함수
            const deleteNode = () => {
                if (typeof getPos === 'function') {
                    const pos = getPos();
                    try {
                        const tr = editor.view.state.tr;
                        tr.delete(pos, pos + node.nodeSize);
                        editor.view.dispatch(tr);
                    } catch (error) {
                        console.error('[BookmarkBlock] 노드 삭제 실패:', error);
                    }
                }
            };

            // 초기 렌더링
            if (currentUrl) {
                showBookmarkCard();
            } else {
                showEditForm();
            }

            // 편집 모드 변경 감지 로직
            let lastIsEditable = editor.isEditable;
            const checkEditable = () => {
                if (editor.isEditable !== lastIsEditable) {
                    lastIsEditable = editor.isEditable;
                    // 편집 중이 아닐 때만 카드 다시 렌더링 (수정 버튼 표시 여부 업데이트)
                    if (!isEditing) {
                        showBookmarkCard();
                    }
                }
            };

            // 1. Transaction 이벤트 리스너 (상태 변경 감지)
            editor.on('transaction', checkEditable);

            // 2. MutationObserver (contenteditable 속성 변경 감지)
            const observer = new MutationObserver(() => {
                checkEditable();
            });

            if (editor.view && editor.view.dom) {
                observer.observe(editor.view.dom, {
                    attributes: true,
                    attributeFilter: ['contenteditable']
                });
            }

            return {
                dom: wrapper,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) {
                        return false;
                    }

                    // 편집 중이 아닐 때만 업데이트
                    if (!isEditing) {
                        const newUrl = updatedNode.attrs.url || '';
                        const safe = sanitizeHttpHref(newUrl, { allowRelative: false }) || '';
                        const newMetadata = {
                            title: updatedNode.attrs.title || '',
                            description: updatedNode.attrs.description || '',
                            thumbnail: updatedNode.attrs.thumbnail || ''
                        };

                        // 데이터가 실제로 변경되었을 때만 다시 렌더링
                        if (currentUrl !== safe ||
                            currentMetadata.title !== newMetadata.title ||
                            currentMetadata.description !== newMetadata.description ||
                            currentMetadata.thumbnail !== newMetadata.thumbnail) {
                            currentUrl = safe;
                            currentMetadata = newMetadata;
                            showBookmarkCard();
                        }
                    }
                    return true;
                },
                stopEvent: () => true,
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
            setBookmarkBlock: (url = '') => ({ commands }) => {
                const safeUrl = sanitizeHttpHref(url, { allowRelative: false }) || '';
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        url: safeUrl,
                        title: '',
                        description: '',
                        thumbnail: ''
                    }
                });
            }
        };
    }
});

/**
 * 북마크 컨테이너 노드
 * 여러 개의 북마크 카드를 담을 수 있는 부모 컨테이너
 */
export const BookmarkContainerBlock = Node.create({
    name: 'bookmarkContainer',

    group: 'block',

    content: 'bookmarkItem*',

    addAttributes() {
        return {
            id: {
                default: () => 'bookmark-container-' + Math.random().toString(36).substr(2, 9),
                parseHTML: element => element.getAttribute('data-id') || '',
                renderHTML: attributes => {
                    return { 'data-id': attributes.id };
                }
            },
            title: {
                default: '',
                parseHTML: element => element.getAttribute('data-title') || '',
                renderHTML: attributes => {
                    return { 'data-title': attributes.title };
                }
            },
            icon: {
                default: '🔖',
                parseHTML: element => element.getAttribute('data-icon') || '🔖',
                renderHTML: attributes => {
                    return { 'data-icon': attributes.icon };
                }
            },
            layout: {
                default: 'grid',
                parseHTML: element => element.getAttribute('data-layout') || 'grid',
                renderHTML: attributes => {
                    return { 'data-layout': attributes.layout };
                }
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="bookmark-container"]'
            }
        ];
    },

    renderHTML({ node, HTMLAttributes }) {
        return [
            'div',
            {
                ...HTMLAttributes,
                'data-type': 'bookmark-container',
                'class': 'bookmark-container',
                'data-title': node.attrs.title || '',
                'data-icon': node.attrs.icon || '🔖',
                'data-layout': node.attrs.layout || 'grid'
            },
            0  // 자식 노드 렌더링 위치
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            const wrapper = document.createElement('div');
            wrapper.className = 'bookmark-container-wrapper';
            wrapper.contentEditable = 'false';  // wrapper는 편집 불가

            // 헤더 섹션
            const header = document.createElement('div');
            header.className = 'bookmark-container-header';
            header.style.display = 'flex';
            header.style.alignItems = 'center';
            header.style.gap = '8px';
            header.contentEditable = 'false';

            const icon = document.createElement('span');
            icon.className = 'bookmark-container-icon';
            if (node.attrs.icon && node.attrs.icon.includes('fa-')) {
                addIcon(icon, node.attrs.icon);
            } else {
                icon.textContent = node.attrs.icon;
            }
            icon.contentEditable = 'false';  // 아이콘은 항상 편집 불가
            icon.style.marginRight = '6px';

            // 아이콘 선택 팝업 생성 함수
            const showIconPickerPopup = () => {
                // 쓰기 모드가 아니면 팝업을 표시하지 않음
                if (!editor.isEditable) {
                    return;
                }

                // 기존 팝업 제거
                const existingPopup = document.querySelector('.bookmark-icon-picker-popup');
                if (existingPopup) {
                    existingPopup.remove();
                }

                // 팝업 생성
                const popup = document.createElement('div');
                popup.className = 'bookmark-icon-picker-popup';
                popup.style.cssText = `
                    position: absolute;
                    background: white;
                    border: 1px solid #ccc;
                    border-radius: 8px;
                    padding: 8px;
                    z-index: 10000;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    max-width: 320px;
                `;

                // 탭 버튼
                const tabContainer = document.createElement('div');
                tabContainer.style.cssText = 'display: flex; gap: 4px; margin-bottom: 8px; border-bottom: 1px solid #eee; padding-bottom: 8px;';

                const themeTab = document.createElement('button');
                themeTab.textContent = '테마 아이콘';
                themeTab.style.cssText = `
                    flex: 1;
                    padding: 6px 10px;
                    border: none;
                    background: #f0f0f0;
                    cursor: pointer;
                    border-radius: 4px;
                    font-size: 12px;
                `;

                const emojiTab = document.createElement('button');
                emojiTab.textContent = '이모지';
                emojiTab.style.cssText = `
                    flex: 1;
                    padding: 6px 10px;
                    border: none;
                    background: white;
                    cursor: pointer;
                    border-radius: 4px;
                    font-size: 12px;
                `;

                tabContainer.appendChild(themeTab);
                tabContainer.appendChild(emojiTab);
                popup.appendChild(tabContainer);

                // 아이콘 그리드
                const grid = document.createElement('div');
                grid.style.cssText = 'display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; max-height: 200px; overflow-y: auto;';

                let currentTab = 'theme';

                const renderGrid = (tab) => {
                    grid.innerHTML = '';
                    currentTab = tab;
                    const icons = tab === 'theme' ? BOOKMARK_THEME_ICONS : BOOKMARK_EMOJI_ICONS;

                    if (tab === 'theme') {
                        themeTab.style.background = '#f0f0f0';
                        emojiTab.style.background = 'white';
                    } else {
                        themeTab.style.background = 'white';
                        emojiTab.style.background = '#f0f0f0';
                    }

                    icons.forEach(iconValue => {
                        const btn = document.createElement('button');
                        btn.style.cssText = `
                            padding: 8px;
                            border: 1px solid #ddd;
                            background: white;
                            cursor: pointer;
                            border-radius: 4px;
                            font-size: 18px;
                            transition: all 0.2s;
                        `;
                        btn.title = iconValue;

                        if (tab === 'theme') {
							addIcon(btn, iconValue);
                        } else {
                            btn.textContent = iconValue;
                        }

                        btn.onmouseover = () => {
                            btn.style.background = '#f5f5f5';
                            btn.style.borderColor = '#999';
                        };
                        btn.onmouseout = () => {
                            btn.style.background = 'white';
                            btn.style.borderColor = '#ddd';
                        };

                        btn.onclick = (e) => {
                            e.preventDefault();
                            e.stopPropagation();

                            if (typeof getPos === 'function') {
                                const pos = getPos();
                                // 현재 노드의 최신 정보 가져오기
                                const currentNode = editor.view.state.doc.nodeAt(pos);
                                if (currentNode) {
                                    const newAttrs = {
                                        ...currentNode.attrs,
                                        icon: iconValue
                                    };
                                    const tr = editor.view.state.tr;
                                    tr.setNodeMarkup(pos, null, newAttrs);
                                    editor.view.dispatch(tr);
                                }
                            }
                            popup.remove();
                        };

                        grid.appendChild(btn);
                    });
                };

                renderGrid('theme');

                themeTab.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    renderGrid('theme');
                });

                emojiTab.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    renderGrid('emoji');
                });

                popup.appendChild(grid);

                // 팝업 위치 설정
                document.body.appendChild(popup);
                const iconRect = icon.getBoundingClientRect();
                popup.style.left = (iconRect.left - 10) + 'px';
                popup.style.top = (iconRect.bottom + 10) + 'px';

                // 외부 클릭 시 팝업 닫기
                const closePopup = (e) => {
                    if (!popup.contains(e.target) && !icon.contains(e.target)) {
                        popup.remove();
                        document.removeEventListener('click', closePopup);
                    }
                };
                document.addEventListener('click', closePopup);
            };

            // 아이콘 클릭 핸들러 - mousedown 사용 (포커스 전에 처리)
            icon.onmousedown = (e) => {
                e.preventDefault();
                e.stopPropagation();
                showIconPickerPopup();
            };

            // 아이콘 스타일 업데이트 함수
            const setupIconInteraction = () => {
                if (editor.isEditable) {
                    icon.style.cursor = 'pointer';
                    icon.title = '클릭해서 아이콘 변경';
                } else {
                    icon.style.cursor = 'default';
                    icon.title = '';
                }
            };

            const title = document.createElement('div');
            title.className = 'bookmark-container-title';
            title.textContent = node.attrs.title || '북마크 컬렉션';
            title.spellcheck = false;
            title.style.flex = '1';

            let isEditingTitle = false;

            // 제목 편집 상태 설정 함수
            const setupTitleInteraction = () => {
                if (editor.isEditable) {
                    // 쓰기 모드: 상호작용 활성화
                    title.setAttribute('contenteditable', 'plaintext-only');
                    title.setAttribute('spellcheck', 'false');
                    title.style.cursor = 'text';
                    title.style.padding = '4px 6px';
                    title.style.borderRadius = '4px';
                    title.style.transition = 'background-color 0.2s';
                    title.style.pointerEvents = 'auto';
                    title.style.userSelect = 'text';
                    title.style.webkitUserSelect = 'text';
                    title.style.mozUserSelect = 'text';

                    // 마우스 오버 시 배경색 변경
                    title.onmouseenter = () => {
                        if (!isEditingTitle) {
                            title.style.backgroundColor = '#f0f0f0';
                        }
                    };
                    title.onmouseleave = () => {
                        if (!isEditingTitle) {
                            title.style.backgroundColor = 'transparent';
                        }
                    };

                    // 포커스 시 편집 모드 표시
                    title.onfocus = () => {
                        isEditingTitle = true;
                        title.style.backgroundColor = '#fff8f0';
                        title.style.border = '1px solid #ddd';
                    };

                    // blur 시 저장
                    title.onblur = () => {
                        if (!isEditingTitle) return;
                        isEditingTitle = false;
                        const newTitle = title.textContent?.trim() || '';
                        title.textContent = newTitle || '북마크 컬렉션';
                        title.style.backgroundColor = 'transparent';
                        title.style.border = 'none';

                        if (typeof getPos === 'function') {
                            const pos = getPos();
                            const currentNode = editor.view.state.doc.nodeAt(pos);
                            if (currentNode) {
                                const newAttrs = {
                                    ...currentNode.attrs,
                                    title: newTitle
                                };
                                const tr = editor.view.state.tr;
                                tr.setNodeMarkup(pos, null, newAttrs);
                                editor.view.dispatch(tr);
                            }
                        }
                    };

                    // keydown 이벤트 처리
                    title.onkeydown = (e) => {
                        e.stopPropagation();

                        if (e.key === 'Enter') {
                            e.preventDefault();
                            title.blur();
                        } else if (e.key === 'Escape') {
                            e.preventDefault();
                            isEditingTitle = false;
                            title.textContent = node.attrs.title || '북마크 컬렉션';
                            title.style.backgroundColor = 'transparent';
                            title.style.border = 'none';
                            title.blur();
                        }
                    };

                    // input 이벤트도 전파 막기
                    title.oninput = (e) => {
                        e.stopPropagation();
                    };

                    // mousedown 이벤트는 제거 (contentEditable이 자연스럽게 처리)
                    title.onmousedown = null;
                } else {
                    // 읽기 모드: 상호작용 비활성화
                    title.contentEditable = 'false';
                    title.style.cursor = 'default';
                    title.style.padding = '0';
                    title.style.borderRadius = '0';
                    title.style.backgroundColor = 'transparent';
                    title.style.border = 'none';
                    title.style.pointerEvents = 'none';
                    title.onmouseenter = null;
                    title.onmouseleave = null;
                    title.onmousedown = null;
                    title.onfocus = null;
                    title.onblur = null;
                    title.onkeydown = null;
                    title.oninput = null;
                }
            };

            // icon과 title을 header에 직접 추가
            header.appendChild(icon);
            header.appendChild(title);

            // 레이아웃 전환 버튼 생성
            const layoutControls = document.createElement('div');
            layoutControls.className = 'bookmark-layout-controls';
            layoutControls.style.display = 'flex';
            layoutControls.style.gap = '4px';

            const gridBtn = document.createElement('button');
            gridBtn.className = 'bookmark-layout-btn';
            gridBtn.type = 'button';
            gridBtn.title = 'Grid 보기';
            addIcon(gridBtn, 'fa-solid fa-grip');
            
            const listBtn = document.createElement('button');
            listBtn.className = 'bookmark-layout-btn';
            listBtn.type = 'button';
            listBtn.title = 'List 보기';
            addIcon(listBtn, 'fa-solid fa-list');

            const updateLayoutButtons = (currentLayout) => {
                gridBtn.classList.toggle('active', currentLayout === 'grid');
                listBtn.classList.toggle('active', currentLayout === 'list');
            };

            const setLayout = (newLayout) => {
                if (typeof getPos === 'function') {
                    const pos = getPos();
                    const currentNode = editor.view.state.doc.nodeAt(pos);
                    if (currentNode) {
                        const tr = editor.view.state.tr;
                        tr.setNodeMarkup(pos, null, {
                            ...currentNode.attrs,
                            layout: newLayout
                        });
                        editor.view.dispatch(tr);
                    }
                }
            };

            gridBtn.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                setLayout('grid');
            };

            listBtn.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                setLayout('list');
            };

            layoutControls.appendChild(gridBtn);
            layoutControls.appendChild(listBtn);
            header.appendChild(layoutControls);

            updateLayoutButtons(node.attrs.layout || 'grid');

            // DOM에 추가된 후에 설정
            setupIconInteraction();
            setupTitleInteraction();

            // 컨테이너 내용 래퍼
            const contentWrapper = document.createElement('div');
            contentWrapper.className = 'bookmark-container-content';
            contentWrapper.setAttribute('data-layout', node.attrs.layout || 'grid');

            wrapper.appendChild(header);
            wrapper.appendChild(contentWrapper);
            
            // 북마크 추가 버튼 생성
            const addButton = document.createElement('button');
            addButton.className = 'bookmark-add-button';
            addButton.textContent = '+ 북마크 추가';
            addButton.type = 'button';

            addButton.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();

                // 새 북마크 블록 추가
                const pos = getPos();
                if (typeof pos === 'number') {
                    const tr = editor.view.state.tr;
                    // 컨테이너의 마지막에 새 북마크 블록 삽입
                    const insertPos = pos + node.nodeSize - 1;
                    tr.insert(insertPos, editor.view.state.schema.nodes.bookmarkBlock.create({
                        url: '',
                        title: '',
                        description: '',
                        thumbnail: ''
                    }));
                    editor.view.dispatch(tr);
                }
            };

            wrapper.appendChild(addButton);

            // UI 업데이트 함수 (항상 업데이트)
            const updateUI = () => {
                try {
                    setupIconInteraction();
                    setupTitleInteraction();

                    // 쓰기 모드(!editor.isEditable)에서만 버튼 표시
                    const newDisplay = editor.isEditable ? 'inline-block' : 'none';
                    addButton.style.display = newDisplay;
                    layoutControls.style.display = editor.isEditable ? 'flex' : 'none';
                } catch (error) {
                    console.error('[BookmarkContainer] updateUI 에러:', error);
                }
            };

            // 초기 상태로 UI 설정
            updateUI();

            // 편집 모드 변경 감지 로직
            let lastIsEditable = editor.isEditable;
            const checkEditable = () => {
                if (editor.isEditable !== lastIsEditable) {
                    lastIsEditable = editor.isEditable;
                    updateUI();
                }
            };

            // 1. Transaction 이벤트 리스너 (상태 변경 감지)
            editor.on('transaction', checkEditable);

            // 2. MutationObserver (contenteditable 속성 변경 감지 - 가장 확실한 방법)
            const observer = new MutationObserver(() => {
                checkEditable();
            });

            if (editor.view && editor.view.dom) {
                observer.observe(editor.view.dom, {
                    attributes: true,
                    attributeFilter: ['contenteditable']
                });
            }

            return {
                dom: wrapper,
                contentDOM: contentWrapper,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) {
                        return false;
                    }

                    // 편집 중이 아닐 때만 제목과 아이콘 업데이트
                    if (!isEditingTitle) {
                        title.textContent = updatedNode.attrs.title || '북마크 컬렉션';
                        if (updatedNode.attrs.icon && updatedNode.attrs.icon.includes('fa-')) {
                            addIcon(icon, updatedNode.attrs.icon);
                        } else {
                            icon.textContent = updatedNode.attrs.icon;
                        }
                    }

                    // 레이아웃 업데이트
                    const newLayout = updatedNode.attrs.layout || 'grid';
                    contentWrapper.setAttribute('data-layout', newLayout);
                    updateLayoutButtons(newLayout);

                    updateUI();
                    return true;
                },
                stopEvent: (event) => {
                    // title이나 icon에서 발생한 이벤트는 Tiptap이 가로채지 않도록
                    const target = event.target;

                    // title 요소 자체이거나 title의 자식 요소인지 확인
                    if (target === title || title.contains(target)) {
                        return true;
                    }

                    // icon 요소인지 확인
                    if (target === icon || icon.contains(target)) {
                        return true;
                    }

                    return false;
                },
                ignoreMutation: (mutation) => {
                    // title 내부의 변경은 허용
                    if (title.contains(mutation.target) || mutation.target === title) {
                        return true;
                    }
                    return false;
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
            setBookmarkContainer: () => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    content: [
                        {
                            type: 'bookmarkBlock',
                            attrs: {
                                url: '',
                                title: '',
                                description: '',
                                thumbnail: ''
                            }
                        }
                    ]
                });
            }
        };
    }
});
