/**
 * 하위 페이지 관리 모듈
 * 하위 페이지 카드 그리드 렌더링
 */

import { secureFetch, escapeHtml, escapeHtmlAttr } from './ui-utils.js';

let state = null;

/**
 * 모듈 초기화
 */
export function initSubpagesManager(appState) {
    state = appState;
}

/**
 * 하위 페이지 목록 가져오기 및 렌더링
 * @param {string} pageId - 현재 페이지 ID
 */
export async function loadAndRenderSubpages(pageId) {
    if (!pageId) {
        hideSubpagesSection();
        return;
    }

    try {
        // state.pages에서 하위 페이지 필터링
        const subpages = getSubpagesFromState(pageId);

        if (subpages.length === 0) {
            hideSubpagesSection();
        } else {
            renderSubpages(subpages, pageId);
            showSubpagesSection();

            // 현재 페이지의 여백과 동기화
            const currentPage = state.pages.find(p => p.id === pageId);
            if (currentPage && currentPage.horizontalPadding !== undefined) {
                syncSubpagesPadding(currentPage.horizontalPadding);
            }
        }
    } catch (error) {
        console.error('하위 페이지 로드 오류:', error);
        hideSubpagesSection();
    }
}

/**
 * state.pages에서 하위 페이지 필터링
 */
function getSubpagesFromState(parentId) {
    if (!state || !state.pages) return [];

    return state.pages
        .filter(page => page.parentId === parentId)
        .sort((a, b) => {
            // sortOrder 우선, 같으면 updatedAt 기준 내림차순
            if (a.sortOrder !== b.sortOrder) {
                return (a.sortOrder || 0) - (b.sortOrder || 0);
            }
            return new Date(b.updatedAt) - new Date(a.updatedAt);
        })
        .map(page => ({
            id: page.id,
            title: page.title || "제목 없음",
            icon: page.icon || null,
            coverImage: page.coverImage || null,
            content: page.content || "",
            isEncrypted: page.isEncrypted || false,
            updatedAt: page.updatedAt
        }));
}

/**
 * 하위 페이지 카드 그리드 렌더링
 */
function renderSubpages(subpages, parentId) {
    const gridEl = document.getElementById('subpages-grid');
    if (!gridEl) return;

    // 기존 카드 제거
    gridEl.innerHTML = '';

    // 카드 생성 및 추가
    subpages.forEach(subpage => {
        const card = createSubpageCard(subpage);
        gridEl.appendChild(card);
    });
}

/**
 * 하위 페이지 리스트 아이템 생성
 */
function createSubpageCard(subpage) {
    const item = document.createElement('div');
    item.className = 'subpage-card';
    if (subpage.isEncrypted) {
        item.classList.add('encrypted');
    }
    item.dataset.pageId = subpage.id;

    // 아이콘 렌더링
    const iconHtml = renderIcon(subpage.icon, subpage.isEncrypted);

    // 콘텐츠 미리보기 생성
    const preview = generatePreview(subpage.content, subpage.isEncrypted);

    // 리스트 아이템 HTML 구성
    item.innerHTML = `
        <div class="subpage-card-icon">${iconHtml}</div>
        <div class="subpage-card-content">
            <div class="subpage-card-title">${escapeHtml(subpage.title)}</div>
            ${preview ? `<div class="subpage-card-preview">${preview}</div>` : ''}
        </div>
        ${subpage.isEncrypted ? `
            <div class="subpage-card-encrypted-badge">
                <i class="fa-solid fa-lock"></i>
                <span>암호화됨</span>
            </div>
        ` : ''}
    `;

    // 클릭 이벤트: 페이지 로드
    item.addEventListener('click', async () => {
        // 현재 페이지가 아닌 경우만 로드
        if (state && state.currentPageId !== subpage.id) {
            const { loadPage } = await import('./pages-manager.js');
            await loadPage(subpage.id);
        }
    });

    return item;
}

/**
 * 아이콘 렌더링
 */
function renderIcon(icon, isEncrypted) {
    if (icon) {
        // Font Awesome 아이콘
        if (icon.startsWith('fa-')) {
            return `<i class="${escapeHtmlAttr(icon)}"></i>`;
        }
        // 이모지
        return escapeHtml(icon);
    }

    // 기본 아이콘
    if (isEncrypted) {
        return '<i class="fa-solid fa-lock"></i>';
    }
    return '<i class="fa-solid fa-file-lines"></i>';
}

/**
 * 콘텐츠 미리보기 생성 (한 줄로 짧게)
 */
function generatePreview(htmlContent, isEncrypted) {
    if (isEncrypted) {
        return '';
    }

    if (!htmlContent || htmlContent === '<p></p>') {
        return '';
    }

    // HTML 태그 제거
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = htmlContent;
    const textContent = tempDiv.textContent || tempDiv.innerText || '';

    // 첫 80자로 제한 (한 줄로 표시)
    const preview = textContent.trim().substring(0, 80);
    return preview ? escapeHtml(preview) + (textContent.length > 80 ? '...' : '') : '';
}

/**
 * 하위 페이지 섹션 표시
 */
function showSubpagesSection() {
    const section = document.getElementById('subpages-section');
    if (section) {
        section.style.display = 'block';
    }
}

/**
 * 하위 페이지 섹션 숨김
 */
function hideSubpagesSection() {
    const section = document.getElementById('subpages-section');
    if (section) {
        section.style.display = 'none';
    }
}

/**
 * WebSocket 메타데이터 변경 이벤트 처리
 */
export function handleSubpageMetadataChange(data) {
    // 현재 페이지의 하위 페이지가 변경된 경우 다시 렌더링
    if (!state || !state.currentPageId) return;

    const subpages = getSubpagesFromState(state.currentPageId);
    const affectedSubpage = subpages.find(sp => sp.id === data.pageId);

    if (affectedSubpage) {
        // 메타데이터 업데이트 후 다시 렌더링
        loadAndRenderSubpages(state.currentPageId);
    }
}

/**
 * 편집 모드 변경 시 호출
 * (현재는 하위 페이지 섹션에서 특별히 처리할 것이 없음)
 */
export function onEditModeChange(isWriteMode) {
    // 하위 페이지는 사이드바의 + 버튼으로 추가하므로
    // 편집 모드 변경 시 특별히 처리할 것 없음
}

/**
 * 하위 페이지 섹션의 여백을 에디터와 동기화
 */
export function syncSubpagesPadding(horizontalPadding) {
    const section = document.getElementById('subpages-section');
    if (!section) return;

    const isMobile = window.innerWidth <= 900;

    if (horizontalPadding === null || isMobile) {
        // 기본 CSS 값 사용
        section.style.paddingLeft = '';
        section.style.paddingRight = '';
    } else {
        // 동적 패딩 적용
        section.style.paddingLeft = `${horizontalPadding}px`;
        section.style.paddingRight = `${horizontalPadding}px`;
    }
}
