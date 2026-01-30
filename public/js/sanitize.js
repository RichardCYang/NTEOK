import DOMPurify from 'dompurify';

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
		'data-callout-type','data-content','data-columns','data-is-open'
	],
	ALLOW_DATA_ATTR: true,
	// javascript:, data: 등을 차단하기 위한 안전한 URI 패턴
	ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
};

export function sanitizeEditorHtml(html) {
	if (!html || typeof html !== 'string') return html;
	return DOMPurify.sanitize(html, EDITOR_PURIFY_CONFIG);
}