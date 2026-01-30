/**
 * PDF 내보내기 모듈
 * html2pdf.js를 사용하여 페이지를 PDF로 변환
 */

import { secureFetch, escapeHtml, escapeHtmlAttr, addIcon } from './ui-utils.js';

/**
 * html2pdf 라이브러리 로드 대기
 */
async function waitForHtml2Pdf() {
    // 이미 로드되어 있으면 즉시 반환
    if (typeof window.html2pdf !== 'undefined') {
        return true;
    }

    // 최대 5초 대기
    const maxWaitTime = 5000;
    const checkInterval = 100;
    let elapsedTime = 0;

    while (elapsedTime < maxWaitTime) {
        if (typeof window.html2pdf !== 'undefined') {
            return true;
        }
        await new Promise(resolve => setTimeout(resolve, checkInterval));
        elapsedTime += checkInterval;
    }

    return false;
}

/**
 * 페이지를 PDF로 내보내기
 * @param {string} pageId - 내보낼 페이지 ID
 */
export async function exportPageToPDF(pageId) {
	let pdfContainer = null;
	let overlay = null;
    try {
        // html2pdf 라이브러리 로드 확인
        const isLoaded = await waitForHtml2Pdf();
        if (!isLoaded) {
            alert('PDF 라이브러리를 로드할 수 없습니다. 페이지를 새로고침 후 다시 시도해주세요.');
            return;
        }

        // 페이지 데이터 가져오기
        const pageData = await fetchPageData(pageId);
        if (!pageData) {
            alert('페이지를 불러올 수 없습니다.');
            return;
        }

		console.log('[PDF Export] 페이지 데이터:', {
			title: pageData.title,
			hasContent: !!pageData.content,
			contentLength: pageData.content?.length || 0,
			isEncrypted: pageData.isEncrypted
		});

        // 암호화된 페이지 확인
        if (pageData.isEncrypted && !pageData.content) {
            alert('암호화된 페이지는 복호화 후 내보낼 수 있습니다.');
            return;
        }

		// 로딩 오버레이 표시
		overlay = createLoadingOverlay();
		document.body.appendChild(overlay);

        // 커버 이미지 유효성 검사
		if (pageData.coverImage) {
			const isValid = await validateImage(`/imgs/${pageData.coverImage}`);
			if (!isValid) {
				console.warn('[PDF Export] 커버 이미지 로드 실패, 제거:', pageData.coverImage);
				pageData.coverImage = null; // 이미지 제거
			}
		}

		// 스크롤을 최상단으로 이동 (html2canvas가 정확히 캡처하도록)
		window.scrollTo(0, 0);

		// PDF용 임시 컨테이너 생성
        pdfContainer = createPDFContainer(pageData);
		document.body.insertBefore(pdfContainer, document.body.firstChild);

		console.log('[PDF Export] 컨테이너 생성 완료, 크기:', {
			width: pdfContainer.offsetWidth,
			height: pdfContainer.offsetHeight,
			scrollWidth: pdfContainer.scrollWidth,
			scrollHeight: pdfContainer.scrollHeight
		});

        // 커스텀 블록 렌더링 (KaTeX, 북마크, Callout 등)
		console.log('[PDF Export] 커스텀 블록 렌더링 시작');
		await renderCustomBlocks(pdfContainer);
		console.log('[PDF Export] 커스텀 블록 렌더링 완료');

		// 레이아웃/스타일 계산이 끝난 뒤 캡처되도록 충분히 대기
		await new Promise(resolve => setTimeout(resolve, 1000));

		// 캔버스 크기 제한(브라우저별)로 인해 빈 PDF가 생성되는 경우를 방지하기 위해 scale을 안전하게 조정
		const preferredScale = 2;
		const safeScale = computeSafeCanvasScale(pdfContainer, preferredScale);
		if (safeScale < preferredScale) {
			const { width, height } = getElementPxSize(pdfContainer);
			console.warn(`[PDF Export] scale 조정: ${preferredScale} -> ${safeScale.toFixed(2)} (px=${width}x${height})`);
		}

		console.log('[PDF Export] PDF 생성 시작, scale:', safeScale);

		// PDF 생성 옵션 설정
        const options = {
            margin: 0,
            filename: `${sanitizeFileName(pageData.title)}.pdf`,
            image: {
                type: 'jpeg',
                quality: 0.98
            },
            html2canvas: {
                scale: safeScale,
                useCORS: true,
				logging: false,
				allowTaint: true,
                letterRendering: true,
                backgroundColor: '#ffffff',
				width: pdfContainer.offsetWidth,
				height: pdfContainer.offsetHeight
            },
            jsPDF: {
                unit: 'mm',
                format: 'a4',
                orientation: 'portrait',
                compress: true
            },
            pagebreak: {
                mode: ['css', 'legacy'],
				avoid: ['table', 'pre', '[data-type="callout-block"]', '[data-type="bookmark-block"]', 'figure', 'img']
            }
        };

        // PDF 생성 및 다운로드
        await window.html2pdf()
            .set(options)
            .from(pdfContainer)
            .save();

		console.log('[PDF Export] PDF 생성 완료');
    } catch (error) {
        console.error('PDF 내보내기 오류:', error);
        alert('PDF 내보내기 중 오류가 발생했습니다: ' + error.message);
    } finally {
        // 임시 컨테이너 제거 (에러가 나도 항상 정리)
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
 * 이미지 유효성 검사
 */
async function validateImage(url) {
	return new Promise((resolve) => {
		const img = new Image();
		img.onload = () => resolve(true);
		img.onerror = () => resolve(false);
		img.src = url;

		// 5초 타임아웃
		setTimeout(() => resolve(false), 5000);
	});
}

/**
 * PDF용 컨테이너 생성
 */
function createPDFContainer(pageData) {
    const container = document.createElement('div');
	container.id = 'pdf-export-container';

	// PDF 캡처 안정화 스타일 (가로 스크롤/과도한 scrollWidth 방지)
    const inlineStyle = `
        <style>
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
                page-break-inside: avoid;
                margin: 20px 0;
            }
            #pdf-export-container table {
                width: 100%;
                border-collapse: collapse;
                page-break-inside: avoid;
                margin: 20px 0;
            }
            #pdf-export-container th, #pdf-export-container td {
                border: 1px solid #e5e7eb;
                padding: 6px 8px;
                vertical-align: top;
            }
            #pdf-export-container [data-type="callout-block"],
            #pdf-export-container [data-type="bookmark-block"],
            #pdf-export-container [data-type="bookmark-container"],
            #pdf-export-container figure {
                page-break-inside: avoid;
                margin: 20px 0;
            }
            #pdf-export-container h1, #pdf-export-container h2, #pdf-export-container h3 {
                page-break-after: avoid;
                margin-top: 30px;
                margin-bottom: 15px;
            }
            #pdf-export-container h1:first-child,
            #pdf-export-container h2:first-child,
            #pdf-export-container h3:first-child {
                margin-top: 0;
            }
            #pdf-export-container p {
                margin: 10px 0;
            }
            /* 페이지 분할 시 균등한 여백 */
            @media print {
                #pdf-export-container * {
                    orphans: 3;
                    widows: 3;
                }
            }
        </style>
    `;

	container.style.cssText = `
        /*
         * A4 용지 크기에 맞춘 컨테이너
         * A4 = 210mm width = 794px (96dpi 기준)
         * 좌우 여백 1:1 완벽 정렬
         * 최종 조정: padding-left 33px, padding-right 45px
         */
        position: relative;
        width: 716px;
        background: white;
        padding: 40px 45px 40px 33px;
        font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif;
        font-size: 14px;
        line-height: 1.6;
        color: #333;
        visibility: visible;
        pointer-events: none;
        overflow: visible;
        box-sizing: content-box;
        margin: 0;
    `;

    // 커버 이미지 (img 태그로 변경하여 onerror 처리 가능하도록)
    let coverHTML = '';
    if (pageData.coverImage) {
        const coverUrl = `/imgs/${pageData.coverImage}`;
        const coverPosition = pageData.coverPosition || 50;
        coverHTML = `
            <div class="pdf-cover-image" style="
                width: calc(100% + 80px);
                height: 300px;
                margin: -40px -40px 30px -40px;
                overflow: hidden;
                position: relative;
            ">
                <img
                    src="${escapeHtmlAttr(coverUrl)}"
                    crossorigin="anonymous"
                    referrerpolicy="no-referrer"
                    onerror="this.style.display='none'"
                    style="
                        width: 100%;
                        height: 100%;
                        object-fit: cover;
                        object-position: center ${coverPosition}%;
                        display: block;
                    "
                />
            </div>
        `;
    }

    // 제목 및 아이콘
    const icon = pageData.icon ? `<span style="font-size: 32px; margin-right: 10px;">${pageData.icon}</span>` : '';
    const title = `<h1 style="
        font-size: 28px;
        font-weight: 700;
        margin: 0 0 20px 0;
        word-wrap: break-word;
    ">${icon}${escapeHtml(pageData.title)}</h1>`;

    // 메타데이터
    const metadata = `
        <div style="
            font-size: 12px;
            color: #666;
            margin-bottom: 30px;
            padding-bottom: 15px;
            border-bottom: 1px solid #ddd;
        ">
            <div>생성: ${new Date(pageData.createdAt).toLocaleString('ko-KR')}</div>
            <div>수정: ${new Date(pageData.updatedAt).toLocaleString('ko-KR')}</div>
        </div>
    `;

    // 콘텐츠
    const content = `
        <div class="pdf-content" style="
            font-size: 14px;
            line-height: 1.8;
        ">
            ${pageData.content || '<p>내용이 없습니다.</p>'}
        </div>
    `;

    container.innerHTML = inlineStyle + coverHTML + title + metadata + content;
    return container;
}

/**
 * 모든 이미지 로딩 대기
 */
async function waitForImages(container) {
    const images = container.querySelectorAll('img');
    const imagePromises = Array.from(images).map((img, index) => {
        return new Promise((resolve) => {
            if (img.complete) {
                if (img.naturalWidth === 0) {
                    // 이미지 로드 실패 - 숨김 처리
                    console.warn(`[PDF Export] 이미지 로드 실패 (인덱스 ${index}):`, img.src);
                    img.style.display = 'none';
                }
                resolve();
            } else {
                img.onload = () => {
                    console.log(`[PDF Export] 이미지 로드 성공 (인덱스 ${index}):`, img.src);
                    resolve();
                };
                img.onerror = () => {
                    console.warn(`[PDF Export] 이미지 로드 실패 (인덱스 ${index}):`, img.src);
                    img.style.display = 'none';
                    resolve();
                };
            }
        });
    });

    await Promise.all(imagePromises);
    const visibleImages = Array.from(images).filter(img => img.style.display !== 'none').length;
    console.log(`[PDF Export] 이미지 로딩 완료: 총 ${images.length}개 중 ${visibleImages}개 성공`);
}

/**
 * 커스텀 블록 렌더링
 */
async function renderCustomBlocks(container) {
    try {
		// KaTeX 수식 렌더링
		console.log('[PDF Export] KaTeX 렌더링 시작');
		await renderMathBlocks(container);
		console.log('[PDF Export] KaTeX 렌더링 완료');
	} catch (error) {
		console.error('[PDF Export] KaTeX 렌더링 오류:', error);
	}

	try {
		// 북마크 블록 정리
		console.log('[PDF Export] 북마크 렌더링 시작');
		renderBookmarkBlocks(container);
		console.log('[PDF Export] 북마크 렌더링 완료');
	} catch (error) {
		console.error('[PDF Export] 북마크 렌더링 오류:', error);
	}

	try {
		// Callout 블록 정리
		console.log('[PDF Export] Callout 렌더링 시작');
		renderCalloutBlocks(container);
		console.log('[PDF Export] Callout 렌더링 완료');
	} catch (error) {
		console.error('[PDF Export] Callout 렌더링 오류:', error);
	}

	try {
		// 체크리스트 렌더링
		console.log('[PDF Export] 체크리스트 렌더링 시작');
		renderTaskLists(container);
		console.log('[PDF Export] 체크리스트 렌더링 완료');
	} catch (error) {
		console.error('[PDF Export] 체크리스트 렌더링 오류:', error);
	}

	try {
		// 이미지 캡션 렌더링
		console.log('[PDF Export] 이미지 캡션 렌더링 시작');
		renderImageCaptions(container);
		console.log('[PDF Export] 이미지 캡션 렌더링 완료');
	} catch (error) {
		console.error('[PDF Export] 이미지 캡션 렌더링 오류:', error);
	}

	try {
		// 외부 이미지(src)가 있으면 프록시로 치환하여 CORS/taint 이슈를 회피
		console.log('[PDF Export] 이미지 프록시 처리 시작');
		rewriteExternalImagesForPdf(container);
		console.log('[PDF Export] 이미지 프록시 처리 완료');
	} catch (error) {
		console.error('[PDF Export] 이미지 프록시 처리 오류:', error);
	}

	try {
		// 모든 이미지 로딩 대기
		console.log('[PDF Export] 이미지 로딩 대기 시작');
		await waitForImages(container);
		console.log('[PDF Export] 이미지 로딩 대기 완료');
	} catch (error) {
		console.error('[PDF Export] 이미지 로딩 대기 오류:', error);
	}

	try {
		// 웹폰트 로딩이 끝난 뒤 캡처되도록 대기 (지원 브라우저에서만)
		console.log('[PDF Export] 웹폰트 로딩 대기 시작');
		if (document.fonts && document.fonts.ready) {
			await document.fonts.ready;
		}
		console.log('[PDF Export] 웹폰트 로딩 대기 완료');
	} catch (error) {
		console.error('[PDF Export] 웹폰트 로딩 대기 오류:', error);
	}
}

/**
 * KaTeX 수식 렌더링
 */
async function renderMathBlocks(container) {
    // Math Block 렌더링
    const mathBlocks = container.querySelectorAll('[data-type="math-block"]');
    mathBlocks.forEach((el) => {
        const latex = el.getAttribute('data-latex') || '';
        if (latex && window.katex) {
            try {
                el.innerHTML = '';
                window.katex.render(latex, el, {
                    displayMode: true,
                    throwOnError: false,
                    output: 'html'
                });
            } catch (error) {
	            // 보안: innerHTML에 사용자 입력(latex)을 직접 삽입하지 않는다 (DOM XSS 방지)
	            const errSpan = document.createElement('span');
	            errSpan.style.color = 'red';
	            errSpan.textContent = `수식 렌더링 오류: ${latex}`;
	            el.replaceChildren(errSpan);
            }
        }
    });

    // Math Inline 렌더링
    const mathInlines = container.querySelectorAll('[data-type="math-inline"]');
    mathInlines.forEach((el) => {
        const latex = el.getAttribute('data-latex') || '';
        if (latex && window.katex) {
            try {
                el.innerHTML = '';
                window.katex.render(latex, el, {
                    displayMode: false,
                    throwOnError: false,
                    output: 'html'
                });
            } catch (error) {
                el.innerHTML = `<span style="color: red;">수식 오류</span>`;
            }
        }
    });

    // KaTeX가 렌더링될 시간 대기
    await new Promise(resolve => setTimeout(resolve, 500));
}

/**
 * 북마크 블록 정리
 */
function renderBookmarkBlocks(container) {
    const bookmarks = container.querySelectorAll('[data-type="bookmark-block"]');
    bookmarks.forEach((el) => {
        const url = el.getAttribute('data-url') || '';
        const title = el.getAttribute('data-title') || url;
        const description = el.getAttribute('data-description') || '';
        const thumbnail = el.getAttribute('data-thumbnail') || '';

        let thumbnailHTML = '';
        if (thumbnail) {
            // 북마크 썸네일은 외부 URL인 경우가 많아 canvas taint 원인이 됨.
            // 기존 앱 UI처럼 프록시 경유로 로드하여 same-origin 으로 만든다.
            const proxied = getProxiedImageUrl(thumbnail);
            thumbnailHTML = `
                <img
					src="${escapeHtmlAttr(proxied)}"
					alt="${escapeHtmlAttr(title)}"
                    crossorigin="anonymous"
                    referrerpolicy="no-referrer"
                    style="
                        width: 80px;
                        height: 80px;
                        flex-shrink: 0;
                        margin-left: 12px;
                        object-fit: cover;
                        object-position: center;
                        border-radius: 4px;
                        display: block;
                    "
                />
            `;
        }

        el.innerHTML = `
            <div style="
                border: 1px solid #ddd;
                border-radius: 8px;
                padding: 12px;
                margin: 8px 0;
                display: flex;
                align-items: center;
                background: #f9f9f9;
            ">
                <div style="flex: 1;">
                    <div style="font-weight: 600; margin-bottom: 4px;">${escapeHtml(title)}</div>
                    <div style="font-size: 12px; color: #666; margin-bottom: 4px;">${escapeHtml(description)}</div>
                    <div style="font-size: 11px; color: #999;">${escapeHtml(url)}</div>
                </div>
                ${thumbnailHTML}
            </div>
        `;
    });

    // 북마크 컨테이너 처리
    const bookmarkContainers = container.querySelectorAll('[data-type="bookmark-container"]');
    bookmarkContainers.forEach((el) => {
        const icon = el.getAttribute('data-icon') || '🔖';
        const title = el.getAttribute('data-title') || '북마크';

        // 헤더 추가
        const header = document.createElement('div');
        header.style.cssText = `
            font-weight: 700;
            font-size: 16px;
            margin: 20px 0 10px 0;
            padding-bottom: 8px;
            border-bottom: 2px solid #333;
        `;

        // 보안: innerHTML 금지 -> data-icon / data-title은 사용자 콘텐츠에서 오므로, 엔티티(&lt; 등)가 실제 태그로 승격되어
        // DOM XSS로 이어질 수 있음 (textContent / createElement 사용)
        const iconEl = document.createElement('span');
        iconEl.style.marginRight = '6px';
        if (icon && icon.includes('fa-')) {
            // FontAwesome 클래스도 기존 앱처럼 지원(내부적으로 class를 정화)
            addIcon(iconEl, icon);
        } else {
            iconEl.textContent = icon;
        }

        const titleEl = document.createElement('span');
        titleEl.textContent = title;

        header.appendChild(iconEl);
        header.appendChild(titleEl);

        el.insertBefore(header, el.firstChild);
    });
}

function getElementPxSize(el) {
    const rect = el.getBoundingClientRect();
    const width = Math.ceil(rect.width || el.scrollWidth || 0);
    const height = Math.ceil(el.scrollHeight || rect.height || 0);
    return { width, height };
}

/**
 * html2canvas/html2pdf는 내부적으로 canvas를 생성한 뒤 이미지로 변환합니다.
 * 브라우저별 canvas 최대 크기(가로/세로 및 면적)를 초과하면 결과가 빈 캔버스/빈 PDF로 나올 수 있습니다.
 * (특히 긴 문서 + 높은 scale 조합에서 자주 발생)
 * 참고: Chrome/Firefox 계열: 한 변 최대 32767px, 면적 268,435,456px^2 수준 제한(환경별 차이 있음)
 */
function computeSafeCanvasScale(el, preferredScale = 2) {
    const { width, height } = getElementPxSize(el);

    // 매우 보수적인 상한선(대부분 브라우저에서 안전)
    const MAX_DIMENSION = 16384;        // px
    const MAX_AREA = 268435456;         // px^2 (16384^2)

    if (!width || !height) return preferredScale;

    const byDimension = Math.min(MAX_DIMENSION / width, MAX_DIMENSION / height);
    const byArea = Math.sqrt(MAX_AREA / (width * height));

    const safeScale = Math.min(preferredScale, byDimension, byArea);

    // html2canvas는 0보다 큰 실수 scale을 허용. 너무 작아지는 것을 막기 위해 하한을 둔다.
    return Math.max(0.05, safeScale);
}

function nextFrame() {
    return new Promise(resolve => requestAnimationFrame(() => resolve()));
}

function getProxiedImageUrl(url) {
    if (!url) return url;
    if (url.startsWith('/api/pages/proxy/image') || url.startsWith('data:') || url.startsWith('blob:')) return url;
    if (url.startsWith('http://') || url.startsWith('https://')) {
        return `/api/pages/proxy/image?url=${encodeURIComponent(url)}`;
    }
    return url;
}

function rewriteExternalImagesForPdf(container) {
    const imgs = container.querySelectorAll('img');
    imgs.forEach(img => {
        const src = img.getAttribute('src') || '';
        const proxied = getProxiedImageUrl(src);
        if (proxied && proxied !== src) img.setAttribute('src', proxied);
        img.setAttribute('crossorigin', 'anonymous');
        img.setAttribute('referrerpolicy', 'no-referrer');
    });
}

/**
 * Callout 블록 정리
 */
function renderCalloutBlocks(container) {
    const callouts = container.querySelectorAll('[data-type="callout-block"]');
    callouts.forEach((el) => {
        const type = el.getAttribute('data-callout-type') || 'info';
        const title = el.getAttribute('data-title') || '';
        const content = el.getAttribute('data-content') || '';

        const colors = {
            info: { bg: '#f1f5f9', border: '#e2e8f0', icon: 'ℹ️' },
            warning: { bg: '#fffbeb', border: '#fef3c7', icon: '⚠️' },
            error: { bg: '#fef2f2', border: '#fee2e2', icon: '❌' },
            success: { bg: '#f0fdf4', border: '#dcfce7', icon: '✅' }
        };
        const style = colors[type] || colors.info;

        el.innerHTML = `
            <div style="
                background: ${style.bg};
                border: 1px solid ${style.border};
                border-radius: 4px;
                padding: 16px;
                margin: 12px 0;
                display: flex;
                align-items: flex-start;
                gap: 12px;
            ">
                <div style="font-size: 20px; flex-shrink: 0; line-height: 1;">${style.icon}</div>
                <div style="
                    white-space: pre-wrap;
                    color: #2d3748;
                    font-size: 15px;
                    line-height: 1.6;
                    flex: 1;
                ">${escapeHtml(content)}</div>
            </div>
        `;
    });
}

/**
 * 체크리스트 렌더링
 */
function renderTaskLists(container) {
    const taskLists = container.querySelectorAll('ul[data-type="taskList"]');
    taskLists.forEach((ul) => {
        ul.style.cssText = 'list-style: none; padding-left: 0;';

        const items = ul.querySelectorAll('li');
        items.forEach((li) => {
            const checkbox = li.querySelector('input[type="checkbox"]');
            if (checkbox) {
                const isChecked = checkbox.checked;
                const text = li.textContent || '';

                li.innerHTML = `
                    <span style="
                        display: inline-block;
                        width: 16px;
                        height: 16px;
                        border: 1px solid #999;
                        border-radius: 3px;
                        margin-right: 8px;
                        text-align: center;
                        line-height: 16px;
                        font-size: 12px;
                        vertical-align: middle;
                        background: ${isChecked ? '#22c55e' : 'white'};
                        color: white;
                    ">${isChecked ? '✓' : ''}</span>
                    <span style="${isChecked ? 'text-decoration: line-through; color: #999;' : ''}">${escapeHtml(text)}</span>
                `;
            }
        });
    });
}

/**
 * 이미지 캡션 렌더링
 */
function renderImageCaptions(container) {
    const figures = container.querySelectorAll('figure[data-type="image-with-caption"]');
    figures.forEach((figure) => {
        const img = figure.querySelector('img');
        const caption = figure.querySelector('figcaption');

        if (img) {
            img.style.cssText = 'max-width: 100%; height: auto; display: block;';
        }
        if (caption) {
            caption.style.cssText = 'font-size: 12px; color: #666; margin-top: 6px; text-align: center;';
        }
    });
}

/**
 * 파일명 정리 (특수문자 제거)
 */
function sanitizeFileName(filename) {
    return filename
        .replace(/[<>:"/\\|?*\x00-\x1F]/g, '') // 금지 문자 제거
        .replace(/\s+/g, '_') // 공백을 언더스코어로
        .substring(0, 200) // 길이 제한
        || 'NTEOK_페이지';
}

/**
 * 로딩 오버레이 생성
 */
function createLoadingOverlay() {
	const overlay = document.createElement('div');
	overlay.style.cssText = `
		position: fixed;
		top: 0;
		left: 0;
		width: 100%;
		height: 100%;
		background: #000;
		z-index: 10000;
		display: flex;
		align-items: center;
		justify-content: center;
		flex-direction: column;
		color: white;
		font-family: 'Malgun Gothic', 'Apple SD Gothic Neo', sans-serif;
	`;

	overlay.innerHTML = `
		<div style="font-size: 24px; margin-bottom: 20px;">
			<i class="fa-solid fa-file-pdf" style="font-size: 48px; margin-bottom: 10px;"></i>
		</div>
		<div style="font-size: 18px; font-weight: 600; margin-bottom: 10px;">PDF 생성 중...</div>
		<div style="font-size: 14px; color: rgba(255,255,255,0.8);">잠시만 기다려주세요</div>
	`;

	return overlay;
}

// 전역으로 export
window.exportPageToPDF = exportPageToPDF;
