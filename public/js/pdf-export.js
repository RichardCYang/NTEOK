/**
 * PDF 내보내기 모듈
 * jsPDF와 html2canvas를 직접 사용하여 고품질 PDF 생성
 */

import { secureFetch, escapeHtml, escapeHtmlAttr, addIcon } from './ui-utils.js';
import DOMPurify from 'dompurify';

// ------------------------------------------------------------
// Security fix: Board(Kanban) block XSS hardening in PDF export
// ------------------------------------------------------------
// pdf-export.js는 data-columns(JSON)에서 파싱한 card.content를 innerHTML로 주입합니다.
// export 시점에도 allow-list 기반 정화가 없으면 저장형/DOM XSS가 발생할 수 있습니다.
const BOARD_CARD_PURIFY_CONFIG = {
    USE_PROFILES: { html: true },
    ALLOWED_TAGS: [
        'br', 'p', 'div', 'span',
        'strong', 'b', 'em', 'i', 'u', 's',
        'code', 'pre', 'ul', 'ol', 'li', 'blockquote',
        'a'
    ],
    ALLOWED_ATTR: ['href', 'target', 'rel'],
    FORBID_TAGS: ['style', 'script', 'svg', 'math'],
};

/**
 * 보안(CVE-2026-22787): HTML 문자열을 DOM에 직접 부착할 때 XSS 위험 방어
 * - PDF export 시 문자열 소스 사용을 지양하고 항상 HTMLElement를 사용하도록 유도
 * - 부득이하게 문자열을 다룰 경우 RETURN_DOM_FRAGMENT 옵션으로 정화 후 부착
 */
const MAIN_CONTENT_PURIFY_CONFIG = {
    USE_PROFILES: { html: true },
    RETURN_DOM_FRAGMENT: true,
    FORBID_TAGS: ['style', 'script', 'iframe', 'object', 'embed', 'link'],
    FORBID_ATTR: ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus'], // 주요 이벤트 핸들러 명시적 차단
};

function ensureElementSource(source) {
    if (typeof source === 'string') {
        throw new Error('[SECURITY] PDF export source must be an HTMLElement, not a string (XSS risk).');
    }
    if (!source || source.nodeType !== 1) {
        throw new Error('[SECURITY] Invalid PDF export source. Expected HTMLElement.');
    }
    return source;
}

function buildSafeCloneForExport(element) {
    const clone = element.cloneNode(true);
    // 보안: script, iframe, object 등 잠재적 위험 태그 제거
    clone.querySelectorAll('script, iframe, object, embed, link[rel="import"], style').forEach(n => n.remove());
    // 보안: 모든 인라인 이벤트 핸들러 제거
    clone.querySelectorAll('*').forEach((node) => {
        [...node.attributes].forEach((attr) => {
            if (/^on/i.test(attr.name)) node.removeAttribute(attr.name);
        });
    });
    return clone;
}

function sanitizeBoardCardHtmlForPdf(html) {
    const clean = DOMPurify.sanitize(String(html ?? ''), BOARD_CARD_PURIFY_CONFIG);

    // target=_blank tabnabbing 방어
    const tmp = document.createElement('div');
    tmp.innerHTML = clean;
    tmp.querySelectorAll('a').forEach((a) => {
        const target = (a.getAttribute('target') || '').toLowerCase();
        if (target === '_blank') {
            const rel = new Set(
                (a.getAttribute('rel') || '')
                    .split(/\s+/)
                    .filter(Boolean)
                    .map(s => s.toLowerCase())
            );
            rel.add('noopener');
            rel.add('noreferrer');
            a.setAttribute('rel', Array.from(rel).join(' '));
        }
    });
    return tmp.innerHTML;
}

// card.color는 class attribute로 들어가므로 허용값 allow-list로 제한
const BOARD_ALLOWED_COLORS = new Set(['default', 'yellow', 'blue', 'green', 'pink', 'purple', 'orange']);
function normalizeBoardColor(value) {
    const c = String(value || '').toLowerCase().trim();
    return BOARD_ALLOWED_COLORS.has(c) ? c : '';
}

/**
 * 라이브러리 로드 대기 (jsPDF, html2canvas)
 */
async function waitForLibraries() {
    const check = () => {
        return typeof window.jspdf !== 'undefined' && typeof window.html2canvas !== 'undefined';
    };

    if (check()) return true;

    const maxWaitTime = 5000;
    const checkInterval = 100;
    let elapsedTime = 0;

    while (elapsedTime < maxWaitTime) {
        if (check()) return true;
        await new Promise(resolve => setTimeout(resolve, checkInterval));
        elapsedTime += checkInterval;
    }

    return check();
}

/**
 * 페이지를 PDF로 내보내기
 * @param {string} pageId - 내보낼 페이지 ID
 */
export async function exportPageToPDF(pageId) {
    let pdfContainer = null;
    let overlay = null;
    try {
        // 라이브러리 로드 확인
        const isLoaded = await waitForLibraries();
        if (!isLoaded) {
            alert('PDF 생성 라이브러리(jsPDF, html2canvas)를 로드할 수 없습니다. 페이지를 새로고침 후 다시 시도해주세요.');
            return;
        }

        // 페이지 데이터 가져오기
        const pageData = await fetchPageData(pageId);
        if (!pageData) {
            alert('페이지를 불러올 수 없습니다.');
            return;
        }

        // 암호화된 페이지 확인
        if (pageData.isEncrypted && !pageData.content) {
            alert('암호화된 페이지는 복호화 후 내보낼 수 있습니다.');
            return;
        }

        // 로딩 오버레이 표시
        overlay = createLoadingOverlay();
        document.body.appendChild(overlay);

        // 스크롤을 최상단으로 이동
        window.scrollTo(0, 0);

        // PDF용 임시 컨테이너 생성
        pdfContainer = createPDFContainer(pageData);
        document.body.insertBefore(pdfContainer, document.body.firstChild);

        // 커스텀 블록 렌더링 (KaTeX, 북마크, Callout 등)
        await renderCustomBlocks(pdfContainer);

        // 레이아웃/스타일 계산 대기
        await new Promise(resolve => setTimeout(resolve, 1000));

        // PDF 생성 시작
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF({
            orientation: 'p',
            unit: 'mm',
            format: 'a4',
            compress: true
        });

        // A4 규격 설정 (mm)
        const pageWidth = 210;
        const pageHeight = 297;
        
        // 캔버스 캡처 옵션
        const canvasOptions = {
            scale: 2, // 고해상도 캡처
            useCORS: true,
            logging: false,
            allowTaint: true,
            backgroundColor: '#ffffff',
            width: pdfContainer.offsetWidth,
            height: pdfContainer.offsetHeight
        };

        // html2canvas로 컨테이너 캡처
        const canvas = await window.html2canvas(pdfContainer, canvasOptions);
        const imgData = canvas.toDataURL('image/jpeg', 0.95);
        
        // 캔버스 크기를 PDF mm 단위로 변환
        // pdfContainer 너비(850px)를 210mm에 맞춤
        const imgWidth = pageWidth;
        const imgHeight = (canvas.height * imgWidth) / canvas.width;
        
        let heightLeft = imgHeight;
        let position = 0;

        // 첫 페이지 추가
        doc.addImage(imgData, 'JPEG', 0, position, imgWidth, imgHeight, undefined, 'FAST');
        heightLeft -= pageHeight;

        // 남은 내용이 있으면 새 페이지 추가
        while (heightLeft > 0) {
            position = heightLeft - imgHeight;
            doc.addPage();
            doc.addImage(imgData, 'JPEG', 0, position, imgWidth, imgHeight, undefined, 'FAST');
            heightLeft -= pageHeight;
        }

        // PDF 저장
        doc.save(`${sanitizeFileName(pageData.title)}.pdf`);

        console.log('[PDF Export] PDF 생성 및 다운로드 완료');
    } catch (error) {
        console.error('PDF 내보내기 오류:', error);
        alert('PDF 내보내기 중 오류가 발생했습니다: ' + error.message);
    } finally {
        // 리소스 정리
        if (pdfContainer && pdfContainer.parentNode) {
            pdfContainer.parentNode.removeChild(pdfContainer);
        }
        if (overlay && overlay.parentNode) {
            overlay.parentNode.removeChild(overlay);
        }
    }
}

/**
 * 페이지 데이터 가져오기
 */
async function fetchPageData(pageId) {
    const res = await secureFetch(`/api/pages/${encodeURIComponent(pageId)}`);
    if (!res.ok) {
        throw new Error('페이지 데이터를 불러올 수 없습니다.');
    }
    return await res.json();
}

/**
 * PDF용 컨테이너 생성
 */
function createPDFContainer(pageData) {
    const container = document.createElement('div');
    container.id = 'pdf-export-container';

    // PDF 캡처 안정화 스타일
    const styleEl = document.createElement('style');
    styleEl.textContent = `
        #pdf-export-container {
            box-sizing: border-box;
            width: 850px !important;
        }
        #pdf-export-container * {
            box-sizing: border-box !important;
        }
        #pdf-export-container pre, #pdf-export-container code {
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            word-break: break-word;
        }
        #pdf-export-container pre {
            background: #f6f8fa;
            border: 1px solid #e5e7eb;
            padding: 12px;
            border-radius: 6px;
            margin: 20px 0;
        }
        #pdf-export-container .tableWrapper {
            margin: 24px 0;
            width: 100% !important;
            overflow: visible;
        }
        #pdf-export-container table {
            border-collapse: separate;
            border-spacing: 0;
            table-layout: fixed;
            width: 100%;
            margin: 24px 0;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
        }
        #pdf-export-container col {
            display: table-column;
        }
        #pdf-export-container th, #pdf-export-container td {
            border-right: 1px solid #e5e7eb !important;
            border-bottom: 1px solid #e5e7eb !important;
            padding: 10px 14px !important;
            vertical-align: top !important;
            word-wrap: break-word;
            overflow-wrap: break-word;
            word-break: normal;
            background-color: #ffffff;
            line-height: 1.7 !important;
        }
        #pdf-export-container th {
            font-weight: 600 !important;
            text-align: left;
            background-color: #f8fafc !important;
            color: #1e293b !important;
            font-size: 0.95em !important;
        }
        #pdf-export-container thead th {
            border-bottom: 1px solid #e5e7eb !important;
        }
        #pdf-export-container td > *:first-child, #pdf-export-container th > *:first-child {
            margin-top: 0 !important;
        }
        #pdf-export-container td > *:last-child, #pdf-export-container th > *:last-child {
            margin-bottom: 0 !important;
        }
        #pdf-export-container td:last-child,
        #pdf-export-container th:last-child {
            border-right: none !important;
        }
        #pdf-export-container tr:last-child td,
        #pdf-export-container tr:last-child th {
            border-bottom: none !important;
        }
        #pdf-export-container [data-type="callout-block"],
        #pdf-export-container [data-type="bookmark-block"],
        #pdf-export-container [data-type="bookmark-container"],
        #pdf-export-container figure {
            margin: 20px 0;
        }
        #pdf-export-container h1, #pdf-export-container h2, #pdf-export-container h3 {
            margin-top: 30px;
            margin-bottom: 15px;
        }
        #pdf-export-container h1:first-child,
        #pdf-export-container h2:first-child,
        #pdf-export-container h3:first-child {
            margin-top: 0;
        }
        #pdf-export-container td p, #pdf-export-container th p {
            margin: 0 !important;
            min-height: 1.2em;
        }
        #pdf-export-container p {
            margin: 10px 0;
        }
        #pdf-export-container img {
            max-width: 100%;
            height: auto;
        }
        #pdf-export-container .board-container {
            margin: 20px 0;
        }
        #pdf-export-container .board-columns-wrapper {
            display: flex;
            gap: 12px;
            align-items: flex-start;
            flex-wrap: wrap;
            width: 100%;
        }
        #pdf-export-container .board-column {
            flex: 1 1 200px;
            min-width: 200px;
            background-color: #f8fafc;
            border-radius: 6px;
            display: flex;
            flex-direction: column;
            border: 1px solid #e2e8f0;
        }
        #pdf-export-container .board-column-header {
            padding: 10px;
            font-weight: 600;
            font-size: 14px;
            border-bottom: 1px solid #e2e8f0;
            background-color: #f1f5f9;
            border-top-left-radius: 6px;
            border-top-right-radius: 6px;
        }
        #pdf-export-container .board-card-list {
            padding: 10px;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        #pdf-export-container .board-card {
            background-color: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 4px;
            padding: 12px;
            box-shadow: 0 1px 2px rgba(0, 0, 0, 0.05);
            display: flex;
            flex-direction: column;
            justify-content: center;
            min-height: 40px;
        }
        #pdf-export-container .board-card.color-yellow { background-color: #fff9c4; border-color: #f0e68c; }
        #pdf-export-container .board-card.color-blue { background-color: #e3f2fd; border-color: #add8e6; }
        #pdf-export-container .board-card.color-green { background-color: #e8f5e9; border-color: #90ee90; }
        #pdf-export-container .board-card.color-pink { background-color: #fce4ec; border-color: #ffb6c1; }
        #pdf-export-container .board-card.color-purple { background-color: #f3e5f5; border-color: #d8bfd8; }
        #pdf-export-container .board-card.color-orange { background-color: #fff3e0; border-color: #ffcc80; }
        #pdf-export-container .board-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 6px;
        }
        #pdf-export-container .board-card-content {
            font-size: 14px;
            line-height: 1.5;
            color: #333;
            white-space: pre-wrap;
            word-break: break-word;
        }
        #pdf-export-container .board-card-content p {
            margin: 0 !important;
        }
        #pdf-export-container .board-card-content > *:first-child {
            margin-top: 0 !important;
        }
        #pdf-export-container .board-card-content > *:last-child {
            margin-bottom: 0 !important;
        }
    `;
    container.appendChild(styleEl);

    container.style.cssText = `
        position: absolute;
        left: -9999px;
        top: 0;
        width: 850px;
        background: white;
        padding: 60px 80px;
        font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif;
        font-size: 16px;
        line-height: 1.7;
        color: #333;
        visibility: visible;
    `;

    // 커버 이미지
    if (pageData.coverImage) {
        const coverUrl = `/imgs/${pageData.coverImage}`;
        const coverPosition = pageData.coverPosition || 50;
        const coverDiv = document.createElement('div');
        coverDiv.className = 'pdf-cover-image';
        coverDiv.style.cssText = `
            width: calc(100% + 160px);
            height: 250px;
            margin: -60px -80px 40px -80px;
            overflow: hidden;
            position: relative;
        `;
        const coverImg = document.createElement('img');
        coverImg.src = coverUrl;
        coverImg.setAttribute('crossorigin', 'anonymous');
        coverImg.style.cssText = `
            width: 100%;
            height: 100%;
            object-fit: cover;
            object-position: center ${coverPosition}%;
            display: block;
        `;
        coverDiv.appendChild(coverImg);
        container.appendChild(coverDiv);
    }

    // 제목 및 아이콘
    const titleH1 = document.createElement('h1');
    titleH1.style.cssText = `
        font-size: 32px;
        font-weight: 700;
        margin: 0 0 20px 0;
        word-wrap: break-word;
        display: flex;
        align-items: center;
    `;
    if (pageData.icon) {
        const iconSpan = document.createElement('span');
        iconSpan.style.cssText = 'font-size: 32px; margin-right: 12px;';
        iconSpan.textContent = pageData.icon;
        titleH1.appendChild(iconSpan);
    }
    titleH1.appendChild(document.createTextNode(pageData.title));
    container.appendChild(titleH1);

    // 메타데이터
    const metadataDiv = document.createElement('div');
    metadataDiv.style.cssText = `
        font-size: 13px;
        color: #666;
        margin-bottom: 40px;
        padding-bottom: 15px;
        border-bottom: 1px solid #eee;
    `;
    const createdDiv = document.createElement('div');
    createdDiv.textContent = `생성: ${new Date(pageData.createdAt).toLocaleString('ko-KR')}`;
    const updatedDiv = document.createElement('div');
    updatedDiv.textContent = `수정: ${new Date(pageData.updatedAt).toLocaleString('ko-KR')}`;
    metadataDiv.appendChild(createdDiv);
    metadataDiv.appendChild(updatedDiv);
    container.appendChild(metadataDiv);

    // 콘텐츠
    const contentDiv = document.createElement('div');
    contentDiv.className = 'pdf-content';
    contentDiv.style.cssText = `
        font-size: 16px;
        line-height: 1.7;
    `;

    let processedContent = pageData.content || '<p>내용이 없습니다.</p>';
    processedContent = processedContent.replace(/<td><p><\/p><\/td>/g, '<td><p>&nbsp;</p></td>')
                                     .replace(/<th><p><\/p><\/th>/g, '<th><p>&nbsp;</p></th>')
                                     .replace(/<td><\/td>/g, '<td><p>&nbsp;</p></td>')
                                     .replace(/<th><\/th>/g, '<th><p>&nbsp;</p></th>');

    // 보안: RETURN_DOM_FRAGMENT로 정화하여 부착
    const cleanFrag = DOMPurify.sanitize(processedContent, MAIN_CONTENT_PURIFY_CONFIG);
    contentDiv.appendChild(cleanFrag);
    container.appendChild(contentDiv);

    return container;
}

/**
 * 커스텀 블록 렌더링
 */
async function renderCustomBlocks(container) {
    // KaTeX 수식 렌더링
    const mathBlocks = container.querySelectorAll('[data-type="math-block"]');
    mathBlocks.forEach((el) => {
        const latex = el.getAttribute('data-latex') || '';
        if (latex && window.katex) {
            try {
                window.katex.render(latex, el, { displayMode: true, throwOnError: false });
            } catch (e) { console.error(e); }
        }
    });

    const mathInlines = container.querySelectorAll('[data-type="math-inline"]');
    mathInlines.forEach((el) => {
        const latex = el.getAttribute('data-latex') || '';
        if (latex && window.katex) {
            try {
                window.katex.render(latex, el, { displayMode: false, throwOnError: false });
            } catch (e) { console.error(e); }
        }
    });

    // 북마크 블록
    const bookmarks = container.querySelectorAll('[data-type="bookmark-block"]');
    bookmarks.forEach((el) => {
        const url = el.getAttribute('data-url') || '';
        const title = el.getAttribute('data-title') || url;
        const description = el.getAttribute('data-description') || '';
        const thumbnail = el.getAttribute('data-thumbnail') || '';

        let thumbnailHTML = '';
        if (thumbnail) {
            thumbnailHTML = `<img src="${escapeHtmlAttr(getProxiedImageUrl(thumbnail))}" crossorigin="anonymous" style="width: 80px; height: 80px; object-fit: cover; border-radius: 4px; margin-left: 12px;">`;
        }

        el.innerHTML = `
            <div style="border: 1px solid #ddd; border-radius: 8px; padding: 12px; margin: 10px 0; display: flex; align-items: center; background: #f9f9f9;">
                <div style="flex: 1; min-width: 0;">
                    <div style="font-weight: 600; margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(title)}</div>
                    <div style="font-size: 12px; color: #666; margin-bottom: 4px; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;">${escapeHtml(description)}</div>
                    <div style="font-size: 11px; color: #999; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(url)}</div>
                </div>
                ${thumbnailHTML}
            </div>
        `;
    });

    // Callout 블록
    const callouts = container.querySelectorAll('[data-type="callout-block"]');
    callouts.forEach((el) => {
        const type = el.getAttribute('data-callout-type') || 'info';
        const content = el.getAttribute('data-content') || '';
        const colors = {
            info: { bg: '#f1f5f9', border: '#e2e8f0', icon: 'ℹ️' },
            warning: { bg: '#fffbeb', border: '#fef3c7', icon: '⚠️' },
            error: { bg: '#fef2f2', border: '#fee2e2', icon: '❌' },
            success: { bg: '#f0fdf4', border: '#dcfce7', icon: '✅' }
        };
        const style = colors[type] || colors.info;

        el.innerHTML = `
            <div style="background: ${style.bg}; border: 1px solid ${style.border}; border-radius: 6px; padding: 16px; margin: 12px 0; display: flex; gap: 12px;">
                <div style="font-size: 20px;">${style.icon}</div>
                <div style="white-space: pre-wrap; font-size: 15px; color: #2d3748; flex: 1;">${escapeHtml(content)}</div>
            </div>
        `;
    });

    // Board (Kanban) 블록
    const boards = container.querySelectorAll('[data-type="board-block"]');
    boards.forEach((el) => {
        const dataStr = el.getAttribute('data-columns');
        let columns = [];
        try {
            columns = JSON.parse(dataStr || '[]');
        } catch (e) {
            console.error('[PDF Export] Board 데이터 파싱 실패:', e);
            return;
        }

        let columnsHTML = '';
        columns.forEach(column => {
            let cardsHTML = '';
            (column.cards || []).forEach(card => {
                let cardHeaderHTML = '';
                if (card.icon) {
                    let cardIconHTML = '';
                    if (card.icon.startsWith('fa-')) {
                        cardIconHTML = `<i class="${escapeHtmlAttr(card.icon)}" style="font-size: 14px; color: #666; margin-right: 4px;"></i>`;
                    } else {
                        cardIconHTML = `<span style="font-size: 14px; margin-right: 4px;">${escapeHtml(card.icon)}</span>`;
                    }
                    cardHeaderHTML = `
                        <div class="board-card-header">
                            <div style="display: flex; align-items: center;">
                                ${cardIconHTML}
                            </div>
                        </div>
                    `;
                }

                const safeColor = normalizeBoardColor(card.color);
                const colorClass = safeColor ? `color-${safeColor}` : '';
                const safeCardContent = sanitizeBoardCardHtmlForPdf(card.content || '');

                cardsHTML += `
                    <div class="board-card ${colorClass}">
                        ${cardHeaderHTML}
                        <div class="board-card-content">${safeCardContent}</div>
                    </div>
                `;
            });

            columnsHTML += `
                <div class="board-column">
                    <div class="board-column-header">
                        <div class="board-column-title">${escapeHtml(column.title)}</div>
                    </div>
                    <div class="board-card-list">
                        ${cardsHTML}
                    </div>
                </div>
            `;
        });

        el.innerHTML = `
            <div class="board-container">
                <div class="board-columns-wrapper">
                    ${columnsHTML}
                </div>
            </div>
        `;
    });

    // 체크리스트
    const taskLists = container.querySelectorAll('ul[data-type="taskList"]');
    taskLists.forEach((ul) => {
        ul.style.listStyle = 'none';
        ul.style.paddingLeft = '0';
        ul.querySelectorAll('li').forEach(li => {
            const checkbox = li.querySelector('input[type="checkbox"]');
            const isChecked = checkbox ? checkbox.checked : false;
            const text = li.textContent.trim();
            li.innerHTML = `
                <div style="display: flex; align-items: flex-start; margin-bottom: 4px;">
                    <div style="width: 18px; height: 18px; border: 1px solid #ccc; border-radius: 3px; margin-right: 8px; flex-shrink: 0; display: flex; align-items: center; justify-content: center; background: ${isChecked ? '#22c55e' : 'white'};">
                        ${isChecked ? '<span style="color: white; font-size: 12px;">✓</span>' : ''}
                    </div>
                    <span style="${isChecked ? 'text-decoration: line-through; color: #999;' : ''}">${escapeHtml(text)}</span>
                </div>
            `;
        });
    });

    // 테이블 컬럼 너비 동기화 (TipTap 전용 처리)
    const tables = container.querySelectorAll('table');
    tables.forEach(table => {
        const colgroup = table.querySelector('colgroup');
        if (!colgroup) return;

        const firstRowCells = table.querySelectorAll('tr:first-child > td, tr:first-child > th');
        const cols = colgroup.querySelectorAll('col');
        
        let colIndex = 0;
        let hasCustomWidth = false;
        let totalCustomWidth = 0;

        firstRowCells.forEach(cell => {
            const colwidth = cell.getAttribute('data-colwidth');
            const colspan = parseInt(cell.getAttribute('colspan') || '1');
            
            if (colwidth) {
                hasCustomWidth = true;
                const widths = colwidth.split(',').map(w => parseInt(w));
                for (let i = 0; i < widths.length && (colIndex + i) < cols.length; i++) {
                    if (widths[i]) {
                        cols[colIndex + i].style.width = `${widths[i]}px`;
                        totalCustomWidth += widths[i];
                    }
                }
            }
            colIndex += colspan;
        });

        // 사용자가 직접 너비를 지정한 경우에만 fixed 레이아웃 적용
        const availableWidth = 850 - 160; // 850px (container) - 160px (padding) = 690px

        if (hasCustomWidth) {
            table.style.tableLayout = 'fixed';
            if (totalCustomWidth > availableWidth) {
                // 너비가 가용 범위를 초과하면 비율에 맞춰 각 컬럼 너비 축소 (왜곡 방지)
                const ratio = availableWidth / totalCustomWidth;
                let adjustedTotal = 0;
                cols.forEach((col, idx) => {
                    const currentW = parseInt(col.style.width);
                    if (currentW) {
                        const newW = Math.floor(currentW * ratio);
                        col.style.width = `${newW}px`;
                        adjustedTotal += newW;
                    }
                });
                table.style.width = `${adjustedTotal}px`;
            } else {
                table.style.width = `${totalCustomWidth}px`;
            }
        } else {
            // 커스텀 너비가 없는 경우에도 fixed 레이아웃으로 균등 배분 유도
            table.style.tableLayout = 'fixed';
            table.style.width = '100%';
        }
    });

    // 외부 이미지 프록시 처리 및 모든 이미지 로딩 대기
    const images = container.querySelectorAll('img');
    const promises = Array.from(images).map(img => {
        const src = img.getAttribute('src');
        if (src && (src.startsWith('http') || src.startsWith('//'))) {
            img.src = getProxiedImageUrl(src);
        }
        img.setAttribute('crossorigin', 'anonymous');
        return new Promise(resolve => {
            if (img.complete) resolve();
            else {
                img.onload = resolve;
                img.onerror = resolve;
            }
        });
    });

    await Promise.all(promises);
    if (document.fonts && document.fonts.ready) {
        await document.fonts.ready;
    }
}

function getProxiedImageUrl(url) {
    if (!url || url.startsWith('/api/pages/proxy/image') || url.startsWith('data:') || url.startsWith('blob:')) return url;
    return `/api/pages/proxy/image?url=${encodeURIComponent(url)}`;
}

/**
 * 파일명 정리
 */
function sanitizeFileName(filename) {
    return filename
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, '')
        .replace(/\s+/g, '_')
        .substring(0, 200) || 'NTEOK_Export';
}

/**
 * 로딩 오버레이 생성
 */
function createLoadingOverlay() {
    const overlay = document.createElement('div');
    overlay.style.cssText = `
        position: fixed; top: 0; left: 0; width: 100%; height: 100%;
        background: rgba(0,0,0,0.8); z-index: 10000;
        display: flex; align-items: center; justify-content: center;
        flex-direction: column; color: white; font-family: sans-serif;
    `;
    overlay.innerHTML = `
        <div style="font-size: 40px; margin-bottom: 20px;"><i class="fa-solid fa-file-pdf"></i></div>
        <div style="font-size: 18px; font-weight: 600;">PDF 생성 중...</div>
        <div style="font-size: 14px; margin-top: 10px; opacity: 0.8;">문서가 길 경우 시간이 걸릴 수 있습니다.</div>
    `;
    return overlay;
}

// 전역 등록
window.exportPageToPDF = exportPageToPDF;