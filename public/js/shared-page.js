import { sanitizeHttpHref } from './url-utils.js';
import { escapeHtml, addIcon, secureFetch } from './ui-utils.js';
import { loadAndRenderComments, initCommentsManager } from './comments-manager.js';
import DOMPurify from 'dompurify';


const _CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
function _isSafeHttpUrlOrRelative(value) {
    if (typeof value !== 'string') return false;
    const v = value.trim();
    if (!v) return false;
    if (_CONTROL_CHARS_RE.test(v)) return false;
    if (v.startsWith('/') || v.startsWith('#')) return true;
    try {
        const u = new URL(v);
        return u.protocol === 'http:' || u.protocol === 'https:';
    } catch {
        return false;
    }
}

const _purifier = (typeof DOMPurify === 'function' && !DOMPurify.sanitize)
    ? DOMPurify(window)
    : DOMPurify;

if (typeof _purifier?.addHook === 'function') {
    _purifier.addHook('uponSanitizeAttribute', (_node, hookEvent) => {
        const name = String(hookEvent?.attrName || '').toLowerCase();
        if (name === 'data-url' || name === 'data-thumbnail') {
            if (!_isSafeHttpUrlOrRelative(String(hookEvent.attrValue || ''))) {
                hookEvent.keepAttr = false;
                hookEvent.forceKeepAttr = false;
            }
        }
    });

    _purifier.addHook('afterSanitizeAttributes', (node) => {
        if (String(node.tagName).toLowerCase() === 'a') {
            const target = String(node.getAttribute('target') || '').trim().toLowerCase();
            if (target === '_blank') {
                const rel = (node.getAttribute('rel') || '').toLowerCase();
                const set = new Set(rel.split(/\s+/).filter(Boolean));
                set.add('noopener');
                set.add('noreferrer');
                node.setAttribute('rel', Array.from(set).join(' '));
            }
        }
    });
}

function sanitizeSharedHtml(html) {
    const input = (typeof html === 'string') ? html : '';
    return _purifier.sanitize(input, {
        ALLOWED_TAGS: [
            'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'blockquote',
            'a', 'span', 'div',
            'hr',
            'table', 'thead', 'tbody', 'tr', 'th', 'td',
            'img', 'figure',
            'label', 'input'
        ],
        ALLOWED_ATTR: [
            'style', 'class', 'href', 'target', 'rel', 'data-type', 'data-latex',
            'colspan', 'rowspan', 'colwidth',
            'src', 'alt', 'data-src', 'data-alt', 'data-caption', 'data-width', 'data-align',
            'data-id', 'data-icon',
            'data-url', 'data-title', 'data-favicon',
            'data-checked', 'type', 'checked', 'data-callout-type', 'data-content',
            'data-columns', 'data-is-open'
        ],
        ALLOW_DATA_ATTR: true,
        ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
    });
}

function buildSafeCoverUrl(ref) {
    if (typeof ref !== 'string') return null;
    const s = ref.trim();
    const parts = s.split('/');
    if (parts.length !== 2) return null;
    const [scope, filename] = parts;
    if (!(scope === 'default' || /^\d{1,12}$/.test(scope))) return null;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(filename)) return null;
    if (filename.includes('..')) return null;
    if (!/\.(?:jpe?g|png|gif|webp)$/i.test(filename)) return null;
    return `/covers/${encodeURIComponent(scope)}/${encodeURIComponent(filename)}`;
}

function renderCheckboxes(container) {
    container.querySelectorAll('ul[data-type="taskList"]').forEach((ul) => {
        ul.querySelectorAll('li').forEach((li) => {
            const isChecked = li.getAttribute('data-checked') === 'true';

            if (li.querySelector('input[type="checkbox"]')) {
                const checkbox = li.querySelector('input[type="checkbox"]');
                checkbox.checked = isChecked;
                return;
            }

            const content = li.innerHTML;

            li.innerHTML = '';

            const label = document.createElement('label');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = isChecked;
            checkbox.disabled = true; 

            label.appendChild(checkbox);
            li.appendChild(label);

            const contentDiv = document.createElement('div');
            contentDiv.innerHTML = sanitizeSharedHtml(content);
            li.appendChild(contentDiv);
        });
    });
}

function renderBookmarks(container) {
    container.querySelectorAll('div[data-type="bookmark"]').forEach((el) => {
        const url = el.getAttribute('data-url');
        const title = el.getAttribute('data-title');
        const favicon = el.getAttribute('data-favicon');

        if (!url) return;

        el.innerHTML = '';
        el.className = 'bookmark-block';

        const containerInner = document.createElement('div');
        containerInner.className = 'bookmark-block-container';

        const card = document.createElement('a');
        card.href = url;
        card.target = '_blank';
        card.rel = 'noopener noreferrer';
        card.className = 'bookmark-compact-link';

        if (favicon) {
            const icon = document.createElement('img');
            icon.src = favicon;
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

        const titleEl = document.createElement('span');
        titleEl.className = 'bookmark-compact-title';
        titleEl.textContent = title || url;
        card.appendChild(titleEl);

        containerInner.appendChild(card);
        el.appendChild(containerInner);
    });
}

(async () => {
    try {
        const token = window.location.pathname.split('/').pop();
        if (!token) {
            throw new Error('토큰이 없습니다.');
        }

        const response = await secureFetch(`/api/shared/page/${encodeURIComponent(token)}`);
        if (!response.ok) {
            throw new Error('페이지를 찾을 수 없습니다.');
        }

        const data = await response.json();

        document.title = `${data.title || '제목 없음'} - NTEOK`;
        document.getElementById('page-title-text').textContent = data.title || '제목 없음';

        if (data.icon) {
            const iconEl = document.getElementById('page-icon');
            if (data.icon.includes('fa-')) {
                addIcon(iconEl, data.icon);
            } else {
                iconEl.textContent = data.icon;
            }
            iconEl.style.display = 'inline';
        }

        if (data.coverImage) {
            const coverEl = document.getElementById('page-cover');
            const coverUrl = buildSafeCoverUrl(data.coverImage);
            if (coverUrl) {
                coverEl.style.backgroundImage = `url("${coverUrl}")`;
                if (data.coverPosition) {
                    coverEl.style.backgroundPositionY = `${data.coverPosition}%`;
                }
                coverEl.style.display = 'block';
            }
        }

        const editorEl = document.getElementById('page-editor');
        editorEl.innerHTML = sanitizeSharedHtml(data.content || '<p></p>');
        editorEl.classList.remove('shared-page-loading');

        renderCheckboxes(editorEl);

        renderBookmarks(editorEl);

        if (window.katex) {
            editorEl.querySelectorAll('[data-type="math-block"]').forEach((el) => {
                try {
                    const latex = el.getAttribute('data-latex') || el.textContent;
                    if (latex) {
                        el.innerHTML = '';
                        window.katex.render(latex, el, {
                            displayMode: true,
                            throwOnError: false
                        });
                    }
                } catch (err) {
                    console.error('[MathBlock] KaTeX 렌더링 오류:', err);
                }
            });

            editorEl.querySelectorAll('[data-type="math-inline"]').forEach((el) => {
                try {
                    const latex = el.getAttribute('data-latex') || el.textContent;
                    if (latex) {
                        el.innerHTML = '';
                        window.katex.render(latex, el, {
                            displayMode: false,
                            throwOnError: false
                        });
                    }
                } catch (err) {
                    console.error('[MathInline] KaTeX 렌더링 오류:', err);
                }
            });

            document.querySelectorAll('.katex-block, .katex-inline').forEach((el) => {
                try {
                    const isDisplay = el.classList.contains('katex-block');
                    const latex = el.dataset.latex || el.textContent;
                    el.innerHTML = '';
                    window.katex.render(latex, el, { displayMode: isDisplay, throwOnError: false });
                } catch (err) {
                    console.error('KaTeX 렌더링 오류:', err);
                }
            });
        }

        initCommentsManager({ currentUser: null });
        loadAndRenderComments(data.id, 'page-comments-section', token);
    } catch (error) {
        console.error('페이지 로드 오류:', error);
        const editorEl = document.getElementById('page-editor');

        const msg = (error && typeof error.message === 'string' && error.message)
            ? error.message
            : '페이지를 불러올 수 없습니다.';

        editorEl.textContent = '';

        const wrap = document.createElement('div');
        wrap.className = 'shared-page-error';
        const box = document.createElement('div');
        box.className = 'shared-page-error-message';

        const iconP = document.createElement('p');
        const iconI = document.createElement('i');
        iconI.className = 'fa-solid fa-exclamation-circle';
        iconP.appendChild(iconI);

        const msgP = document.createElement('p');
        msgP.textContent = msg;

        const linkP = document.createElement('p');
        linkP.style.fontSize = '13px';
        linkP.style.marginTop = '16px';
        linkP.style.color = '#6b7280';

        const a = document.createElement('a');
        a.href = '/';
        a.textContent = '홈으로 돌아가기';
        a.style.color = '#2d5f5d';
        a.style.textDecoration = 'underline';
        linkP.appendChild(a);

        box.appendChild(iconP);
        box.appendChild(msgP);
        box.appendChild(linkP);
        wrap.appendChild(box);
        editorEl.appendChild(wrap);

        editorEl.classList.remove('shared-page-loading');
    }
})();
