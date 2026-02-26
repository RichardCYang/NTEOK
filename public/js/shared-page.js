import { sanitizeHttpHref } from './url-utils.js';
import { escapeHtml, addIcon, secureFetch } from './ui-utils.js';
import { loadAndRenderComments, initCommentsManager } from './comments-manager.js';
import DOMPurify from 'dompurify';

/**
 * 공개 페이지 스크립트
 */

// 보안: 공유(공개) 페이지는 외부 사용자가 만든 HTML을 표시하므로, 방어적으로 한 번 더 정화
// - 서버에서도 정화하지만(저장 시), 공개 뷰어에서 innerHTML을 사용하므로 클라이언트에서도 추가 정화(Defense in Depth)
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

// DOMPurify 훅: data-url / data-thumbnail에 javascript: 등 위험 스킴이 들어가는 것을 추가로 차단
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

    // Reverse Tabnabbing 방어: target="_blank"인 경우 rel="noopener noreferrer" 강제
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

/**
 * 체크박스(to-do list) 렌더링 함수
 * @param {HTMLElement} container - 렌더링 대상 컨테이너
 */
function renderCheckboxes(container) {
    // taskList 타입의 ul 요소를 모두 찾아서 처리
    container.querySelectorAll('ul[data-type="taskList"]').forEach((ul) => {
        // 각 li 항목 처리
        ul.querySelectorAll('li').forEach((li) => {
            const isChecked = li.getAttribute('data-checked') === 'true';

            // 이미 렌더링된 경우 건너뛰기
            if (li.querySelector('input[type="checkbox"]')) {
                const checkbox = li.querySelector('input[type="checkbox"]');
                checkbox.checked = isChecked;
                return;
            }

            // 기존 내용 백업
            const content = li.innerHTML;

            // li 내용 재구성
            li.innerHTML = '';

            // label과 checkbox 생성
            const label = document.createElement('label');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = isChecked;
            checkbox.disabled = true; // 공개 페이지에서는 체크박스 비활성화

            label.appendChild(checkbox);
            li.appendChild(label);

            // 콘텐츠 div 생성
            const contentDiv = document.createElement('div');
            contentDiv.innerHTML = sanitizeSharedHtml(content);
            li.appendChild(contentDiv);
        });
    });
}

(async () => {
    try {
        // URL에서 토큰 추출
        const token = window.location.pathname.split('/').pop();
        if (!token) {
            throw new Error('토큰이 없습니다.');
        }

        // 페이지 데이터 로드
        const response = await secureFetch(`/api/shared/page/${encodeURIComponent(token)}`);
        if (!response.ok) {
            throw new Error('페이지를 찾을 수 없습니다.');
        }

        const data = await response.json();

        // 제목 설정
        document.title = `${data.title || '제목 없음'} - NTEOK`;
        document.getElementById('page-title-text').textContent = data.title || '제목 없음';

        // 아이콘 표시
        if (data.icon) {
            const iconEl = document.getElementById('page-icon');
            if (data.icon.includes('fa-')) {
                addIcon(iconEl, data.icon);
            } else {
                iconEl.textContent = data.icon;
            }
            iconEl.style.display = 'inline';
        }

        // 커버 이미지 표시
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

        // 콘텐츠 표시
        const editorEl = document.getElementById('page-editor');
        editorEl.innerHTML = sanitizeSharedHtml(data.content || '<p></p>');
        editorEl.classList.remove('shared-page-loading');

        // 체크박스 렌더링
        renderCheckboxes(editorEl);

        // KaTeX 수식 렌더링
        if (window.katex) {
            // 수식 블록 렌더링
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

            // 인라인 수식 렌더링 (혹시 있을 경우)
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

            // 레거시: 이전 형식 지원 (.katex-block, .katex-inline)
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

        // 댓글 시스템 초기화 (게스트 모드)
        initCommentsManager({ currentUser: null });
        // 보안: 댓글 로드 -> 공개 댓글은 pageId가 아니라 발행 링크 token으로 접근
        loadAndRenderComments(data.id, 'page-comments-section', token);
    } catch (error) {
        console.error('페이지 로드 오류:', error);
        const editorEl = document.getElementById('page-editor');

        // 보안: error.message는 (직/간접적으로) 사용자 제어 문자열이 섞일 수 있으므로
        // innerHTML로 주입하면 DOM XSS/HTML Injection Sink가 됨
        // 안전한 방식: DOM API + textContent 사용
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
