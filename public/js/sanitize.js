import DOMPurify from 'dompurify';

// DOMPurify는 기본적으로 href/src 같은 URI 속성만 프로토콜 검증을 수행
// 이 앱은 data-src/data-url 같은 data-*를 실제 URL sink로 승격시키므로 data-*도 별도 검증 필요
const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
function isSafeHttpUrlOrRelative(value) {
	if (typeof value !== 'string') return false;
	const v = value.trim();
	if (!v) return false;
	if (CONTROL_CHARS_RE.test(v)) return false;
	if (v.startsWith('//')) return false;	// protocol-relative 차단
	if (v.startsWith('/') || v.startsWith('#')) return true;
	try {
		const u = new URL(v);
		return u.protocol === 'http:' || u.protocol === 'https:';
	} catch {
		return false;
	}
}

// 훅은 1회만 설치 (중복 설치 방지)
if (!DOMPurify.__nteokSecurityHooksInstalled) {
	DOMPurify.__nteokSecurityHooksInstalled = true;

	// data-src/data-url 등 data-* 속성 검증
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

			// file-block는 내부 첨부만 허용
			if (nodeType === 'file-block' && !raw.startsWith('/paperclip/')) {
				data.keepAttr = false;
				data.forceKeepAttr = false;
			}
		}
	});

	// Reverse Tabnabbing 방어: target="_blank"인 경우 rel="noopener noreferrer" 강제
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

// 서버(server.js)의 sanitizeHtmlContent 정책과 최대한 유사하게 유지하는 것이 중요
// 암호화 콘텐츠는 서버에서 정화할 수 없으므로 클라이언트가 최후의 방어
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
	// javascript:, data: 등을 차단하기 위한 안전한 URI 패턴
	ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
};

export function sanitizeEditorHtml(html) {
	if (!html || typeof html !== 'string') return html;
	return DOMPurify.sanitize(html, EDITOR_PURIFY_CONFIG);
}