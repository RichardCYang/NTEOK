import * as DOMPurifyModule from '../lib/dompurify/dompurify.js';
const _DOMPurify = DOMPurifyModule.default || DOMPurifyModule;
const DOMPurify = (typeof _DOMPurify === 'function' && !_DOMPurify.sanitize) ? _DOMPurify(window) : _DOMPurify;

import { sanitizeHttpHref } from './url-utils.js';
import { sanitizeBlockAlign, sanitizeCssLength } from './node-attr-sanitizers.js';

const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;

function sanitizeNavHref(value, { allowRelative = true } = {}) {
    const safe = sanitizeHttpHref(value, {
        allowRelative,
        addHttpsIfMissing: false,
        maxLen: 2048
    });
    if (!safe || safe.startsWith('//')) return null;
    return safe;
}

function sanitizeLocalAssetSrc(raw) {
    const safe = sanitizeNavHref(raw, { allowRelative: true });
    if (!safe || safe.startsWith('#') || safe.startsWith('//')) return null;
    if (/^(https?:)/i.test(safe)) {
        try {
            const u = new URL(safe, window.location.origin);
            if (u.origin !== window.location.origin) return null;
            return /^\/(?:imgs|covers|paperclip)\//.test(u.pathname) ? u.pathname : null;
        } catch {
            return null;
        }
    }
    return /^\/(?:imgs|covers|paperclip)\//.test(safe) ? safe : null;
}

let hooksInstalled = false;

if (!hooksInstalled) {
    hooksInstalled = true;

    DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
        const name = String(data?.attrName || '').toLowerCase();
        const raw = String(data?.attrValue || '');

        if (name === 'src') {
            const safe = sanitizeLocalAssetSrc(raw);
            if (!safe) {
                data.keepAttr = false;
                data.forceKeepAttr = false;
                return;
            }
            data.attrValue = safe;
        }

        if (name === 'href') {
            const safe = sanitizeNavHref(raw, { allowRelative: true });
            if (!safe) {
                data.keepAttr = false;
                data.forceKeepAttr = false;
                return;
            }
            data.attrValue = safe;
        }

        if (name === 'data-width') {
            data.attrValue = sanitizeCssLength(raw, '100%');
            return;
        }

        if (name === 'data-align') {
            data.attrValue = sanitizeBlockAlign(raw, 'center');
            return;
        }

        if (name === 'data-columns') {
            data.attrValue = raw;
            data.keepAttr = true;
            data.forceKeepAttr = true;
            return;
        }

        if (name === 'data-url' || name === 'data-thumbnail') {
            const safe = sanitizeNavHref(raw, { allowRelative: false });
            if (!safe) {
                data.keepAttr = false;
                data.forceKeepAttr = false;
                return;
            }
            data.attrValue = safe;
        }

        if (name === 'data-src') {
            const nodeType = String(node?.getAttribute?.('data-type') || '').toLowerCase();

            if (nodeType === 'file-block') {
                const m = raw.match(/^\/paperclip\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/);
                if (!m) {
                    data.keepAttr = false;
                    data.forceKeepAttr = false;
                    return;
                }
            }

            const safe = sanitizeNavHref(raw, { allowRelative: true });
            if (!safe) {
                data.keepAttr = false;
                data.forceKeepAttr = false;
                return;
            }
            data.attrValue = safe;
        }
    });

    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
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

export const EDITOR_PURIFY_CONFIG = {
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
        'style', 'class', 'href', 'target', 'rel', 'data-type', 'data-latex', 'colspan', 'rowspan', 'colwidth',
        'src', 'alt', 'data-src', 'data-alt', 'data-caption', 'data-width', 'data-align', 'data-url', 'data-title',
        'data-description', 'data-thumbnail', 'data-id', 'data-icon', 'data-checked', 'type', 'checked',
        'data-callout-type', 'data-content', 'data-columns', 'data-rows', 'data-is-open', 'data-selected-date', 'data-memos'
    ],
    ALLOW_DATA_ATTR: true,
    ALLOWED_URI_REGEXP: /^(?:(?:(?:ht)tps?|mailto|tel):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
};

export function sanitizeEditorHtml(html) {
    if (!html || typeof html !== 'string') return html;
    return DOMPurify.sanitize(html, EDITOR_PURIFY_CONFIG);
}

export function htmlToPlainText(html, { maxLength = 0 } = {}) {
    if (!html || typeof html !== 'string') return '';
    const HARD_LIMIT = 2000000; 
    const input = html.length > HARD_LIMIT ? html.slice(0, HARD_LIMIT) : html;
    try {
        const parser = new DOMParser();
        const doc = parser.parseFromString(input, 'text/html');
        let out = (doc.body && doc.body.textContent) ? doc.body.textContent : '';
        out = out.replace(/\s+/g, ' ').trim();
        if (maxLength > 0 && out.length > maxLength) return out.slice(0, maxLength);
        return out;
    } catch {
        let out = input.replace(/<[^>]*>/g, ' ');
        out = out.replace(/\s+/g, ' ').trim();
        if (maxLength > 0 && out.length > maxLength) return out.slice(0, maxLength);
        return out;
    }
}