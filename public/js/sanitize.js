import DOMPurify from 'dompurify';

const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
function isSafeHttpUrlOrRelative(value) {
	if (typeof value !== 'string') return false;
	const v = value.trim();
	if (!v) return false;
	if (CONTROL_CHARS_RE.test(v)) return false;
	if (v.startsWith('//')) return false;	
	if (v.startsWith('/') || v.startsWith('#')) return true;
	try {
		const u = new URL(v);
		return u.protocol === 'http:' || u.protocol === 'https:';
	} catch {
		return false;
	}
}

if (!DOMPurify.__nteokSecurityHooksInstalled) {
	DOMPurify.__nteokSecurityHooksInstalled = true;

	DOMPurify.addHook('uponSanitizeAttribute', (node, data) => {
		const name = String(data?.attrName || '').toLowerCase();

		if (name === 'data-src') {
			const nodeType = String(node?.getAttribute?.('data-type') || '').toLowerCase();
			const raw = String(data?.attrValue || '');

			if (!isSafeHttpUrlOrRelative(raw)) {
				data.keepAttr = false;
				data.forceKeepAttr = false;
				return;
			}

			if (nodeType === 'file-block' && !raw.startsWith('/paperclip/')) {
				data.keepAttr = false;
				data.forceKeepAttr = false;
			}
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
		'p','br','strong','em','u','s','code','pre',
		'h1','h2','h3','h4','h5','h6',
		'ul','ol','li','blockquote',
		'a','span','div','hr',
		'table','thead','tbody','tr','th','td',
		'img','figure',
		'label','input'
	],
	ALLOWED_ATTR: [
		'style','class','href','target','rel','data-type','data-latex','colspan','rowspan','colwidth',
		'src','alt','data-src','data-alt','data-caption','data-width','data-align','data-url','data-title',
		'data-description','data-thumbnail','data-id','data-icon','data-checked','type','checked',
		'data-callout-type','data-content','data-columns','data-is-open','data-selected-date','data-memos'
	],
	ALLOW_DATA_ATTR: true,
	ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
};

export function sanitizeEditorHtml(html) {
	if (!html || typeof html !== 'string') return html;
	return DOMPurify.sanitize(html, EDITOR_PURIFY_CONFIG);
}

export function htmlToPlainText(html, { maxLength = 0 } = {}) {
	if (!html || typeof html !== 'string') return '';

	const HARD_LIMIT = 2_000_000; 
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