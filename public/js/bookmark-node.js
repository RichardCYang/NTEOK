import { sanitizeHttpHref } from "./url-utils.js";
import { secureFetch } from "./ui-utils.js";

const Node = Tiptap.Core.Node;

async function fetchTransientFaviconObjectUrl(opaqueId) {
    if (typeof opaqueId !== 'string' || !/^[a-f0-9]{32}$/i.test(opaqueId)) return null;

    const response = await secureFetch('/api/pages/proxy-favicon', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: opaqueId })
    });

    if (!response.ok) return null;
    const blob = await response.blob();
    return URL.createObjectURL(blob);
}

function getRenderableFaviconSrc(persisted, transient) {
    if (typeof transient === 'string' && transient.startsWith('blob:')) return transient;
    return sanitizeBookmarkImageUrl(persisted);
}

function sanitizeBookmarkImageUrl(value) {
    if (typeof value !== 'string') return null;
    const v = value.trim();
    if (!v) return null;
    if (/[\u0000-\u001F\u007F]/.test(v)) return null;
    if (v.startsWith('//') || v.startsWith('#')) return null;
    if (v.startsWith('/')) return v;
    try {
        const u = new URL(v, window.location.origin);
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
        if (u.username || u.password) return null;
        if (u.origin !== window.location.origin) return null;
        return u.toString();
    } catch {
        return null;
    }
}

function isTransientProxyFavicon(value) {
    return /^\/api\/pages\/proxy-favicon(?:\?|$)/i.test(String(value || '').trim());
}

function buildGeneratedBookmarkFaviconUrlFromPageUrl(rawUrl) {
    try {
        const u = new URL(String(rawUrl), window.location.origin);
        return `/api/pages/bookmark-favicon/${encodeURIComponent(u.hostname.toLowerCase())}.svg`;
    } catch {
        return null;
    }
}

export const BookmarkBlock = Node.create({
    name: 'bookmarkBlock',

    group: 'block',

    atom: true,

    addAttributes() {
        return {
            url: {
                default: null
            },
            title: {
                default: null
            },
            favicon: {
                default: null
            }
        };
    },

    parseHTML() {
        return [
            {
                tag: 'div[data-type="bookmark"]',
                getAttrs: (element) => ({
                    url: element.getAttribute('data-url'),
                    title: element.getAttribute('data-title'),
                    favicon: sanitizeBookmarkImageUrl(element.getAttribute('data-favicon'))
                })
            }
        ];
    },

    renderHTML({ node }) {
        return [
            'div',
            {
                'data-type': 'bookmark',
                'data-url': node.attrs.url || '',
                'data-title': node.attrs.title || '',
                'data-favicon': sanitizeBookmarkImageUrl(node.attrs.favicon) || '',
                'class': 'bookmark-block'
            }
        ];
    },

    addNodeView() {
        return ({ node, editor, getPos }) => {
            const container = document.createElement('div');
            container.className = 'bookmark-block-container';
            container.contentEditable = 'false';
            let transientFavicon = null;
            let transientObjectUrl = null;

            const render = () => {
                container.innerHTML = '';

                if (!node.attrs.url) {
                    const inputWrapper = document.createElement('div');
                    inputWrapper.className = 'bookmark-input-wrapper';

                    const input = document.createElement('input');
                    input.type = 'text';
                    input.placeholder = '링크를 입력하거나 붙여넣으세요...';
                    input.className = 'bookmark-url-input';

                    const button = document.createElement('button');
                    button.textContent = '추가';
                    button.className = 'bookmark-add-btn';

                    const handleAdd = async () => {
                        let url = input.value.trim();
                        if (!url) return;
                        if (!/^https?:\/\//i.test(url)) url = 'https://' + url;

                        input.disabled = true;
                        button.disabled = true;
                        button.textContent = '가져오는 중...';

                        try {
                            const response = await secureFetch('/api/pages/fetch-metadata', {
                                method: 'POST',
                                body: JSON.stringify({ url })
                            });
                            
                            if (!response.ok) {
                                const errData = await response.json().catch(() => ({}));
                                throw new Error(errData.error || '메타데이터를 가져올 수 없습니다.');
                            }

                            const data = await response.json();

if (typeof getPos === 'function') {
    if (transientObjectUrl) {
        URL.revokeObjectURL(transientObjectUrl);
        transientObjectUrl = null;
    }

    transientObjectUrl = await fetchTransientFaviconObjectUrl(data.faviconOpaqueId).catch(() => null);
    transientFavicon = transientObjectUrl || null;

    const rawFavicon = sanitizeBookmarkImageUrl(data.favicon);
    const persistedFavicon = rawFavicon
        || buildGeneratedBookmarkFaviconUrlFromPageUrl(data.url)
        || null;

    editor.view.dispatch(editor.view.state.tr.setNodeMarkup(getPos(), null, {
        url: data.url,
        title: data.title,
        favicon: persistedFavicon
    }));
}
                        } catch (error) {
                            alert('오류: ' + error.message);
                            input.disabled = false;
                            button.disabled = false;
                            button.textContent = '추가';
                            input.focus();
                        }
                    };

                    input.addEventListener('keydown', (e) => {
                        if (e.key === 'Enter') {
                            e.preventDefault();
                            handleAdd();
                        }
                    });

                    button.addEventListener('click', (e) => {
                        e.preventDefault();
                        handleAdd();
                    });

                    inputWrapper.appendChild(input);
                    inputWrapper.appendChild(button);
                    container.appendChild(inputWrapper);
                    
                    if (editor.isEditable) {
                        setTimeout(() => input.focus(), 10);
                    }
                } else {
                    const card = document.createElement('a');
                    const safeHref = sanitizeHttpHref(node.attrs.url, {
                        allowRelative: false,
                        addHttpsIfMissing: false,
                        maxLen: 2048
                    });

                    card.href = safeHref || "about:blank";
                    if (!safeHref) {
                        card.setAttribute("aria-disabled", "true");
                        card.classList.add("bookmark-card--invalid");
                        card.addEventListener("click", (e) => e.preventDefault());
                    }
                    card.target = '_blank';
                    card.rel = 'noopener noreferrer';
                    card.className = 'bookmark-compact-link';

                    const safeFavicon = getRenderableFaviconSrc(node.attrs.favicon, transientFavicon);
                    if (safeFavicon) {
                        const icon = document.createElement('img');
                        icon.src = safeFavicon;
                        icon.className = 'bookmark-compact-favicon';
                        icon.alt = '';
                        icon.onerror = () => {
                            const fallbackIcon = document.createElement('i');
                            fallbackIcon.className = 'fa-solid fa-link bookmark-compact-icon';
                            if (card.contains(icon)) {
                                card.replaceChild(fallbackIcon, icon);
                            }
                        };
                        card.appendChild(icon);
                    } else {
                        const icon = document.createElement('i');
                        icon.className = 'fa-solid fa-link bookmark-compact-icon';
                        card.appendChild(icon);
                    }

                    const title = document.createElement('span');
                    title.className = 'bookmark-compact-title';
                    title.textContent = node.attrs.title || safeHref || "북마크";
                    card.appendChild(title);

                    container.appendChild(card);
                    
                    if (editor.isEditable) {
                        const removeBtn = document.createElement('button');
                        removeBtn.className = 'bookmark-remove-btn';
                        removeBtn.innerHTML = '<i class="fa-solid fa-xmark"></i>';
                        removeBtn.title = '링크 삭제';
                        removeBtn.onclick = (e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            if (typeof getPos === 'function') {
                                editor.view.dispatch(editor.view.state.tr.delete(getPos(), getPos() + node.nodeSize));
                            }
                        };
                        container.appendChild(removeBtn);
                    }
                }
            };

            render();

            return {
                dom: container,
                update: (updatedNode) => {
                    if (updatedNode.type.name !== this.name) return false;
                    
                    if (updatedNode.attrs.url !== node.attrs.url || 
                        updatedNode.attrs.title !== node.attrs.title ||
                        updatedNode.attrs.favicon !== node.attrs.favicon) {
                        
                        node.attrs.url = updatedNode.attrs.url;
                        node.attrs.title = updatedNode.attrs.title;
                        node.attrs.favicon = updatedNode.attrs.favicon;
                        render();
                    }
                    return true;
                },
                destroy: () => {
                    if (transientObjectUrl) {
                        URL.revokeObjectURL(transientObjectUrl);
                        transientObjectUrl = null;
                    }
                },
                stopEvent: (event) => {
                    const isInput = event.target.closest('input');
                    const isButton = event.target.closest('button');
                    return isInput || isButton;
                },
                ignoreMutation: () => true
            };
        };
    },

    addCommands() {
        return {
            setBookmarkBlock: () => ({ commands }) => {
                return commands.insertContent({
                    type: this.name,
                    attrs: {
                        url: null,
                        title: null,
                        favicon: null
                    }
                });
            }
        };
    }
});
