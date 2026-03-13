
import { secureFetch, escapeHtml, escapeHtmlAttr } from './ui-utils.js';
import { htmlToPlainText } from './sanitize.js';

let state = null;

export function initSubpagesManager(appState) {
    state = appState;
}

export async function loadAndRenderSubpages(pageId) {
    if (!pageId) {
        hideSubpagesSection();
        return;
    }

    try {
        const subpages = getSubpagesFromState(pageId);

        if (subpages.length === 0) {
            hideSubpagesSection();
        } else {
            renderSubpages(subpages, pageId);
            showSubpagesSection();

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

function getSubpagesFromState(parentId) {
    if (!state || !state.pages) return [];

    return state.pages
        .filter(page => page.parentId === parentId)
        .sort((a, b) => {
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

function renderSubpages(subpages, parentId) {
    const gridEl = document.getElementById('subpages-grid');
    if (!gridEl) return;

    gridEl.innerHTML = '';

    subpages.forEach(subpage => {
        const card = createSubpageCard(subpage);
        gridEl.appendChild(card);
    });
}

function createSubpageCard(subpage) {
    const item = document.createElement('div');
    item.className = 'subpage-card';
    if (subpage.isEncrypted) item.classList.add('encrypted');
    item.dataset.pageId = subpage.id;

    const iconContainer = document.createElement('div');
    iconContainer.className = 'subpage-card-icon';
    iconContainer.appendChild(renderIconElement(subpage.icon, subpage.isEncrypted));
    item.appendChild(iconContainer);

    const contentContainer = document.createElement('div');
    contentContainer.className = 'subpage-card-content';

    const titleDiv = document.createElement('div');
    titleDiv.className = 'subpage-card-title';
    titleDiv.textContent = subpage.title || "제목 없음";
    contentContainer.appendChild(titleDiv);

    const previewText = generatePreviewText(subpage.content, subpage.isEncrypted);
    if (previewText) {
        const previewDiv = document.createElement('div');
        previewDiv.className = 'subpage-card-preview';
        previewDiv.textContent = previewText;
        contentContainer.appendChild(previewDiv);
    }
    item.appendChild(contentContainer);

    if (subpage.isEncrypted) {
        const badge = document.createElement('div');
        badge.className = 'subpage-card-encrypted-badge';
        const lockIcon = document.createElement('i');
        lockIcon.className = 'fa-solid fa-lock';
        badge.appendChild(lockIcon);
        const textSpan = document.createElement('span');
        textSpan.textContent = ' 암호화됨';
        badge.appendChild(textSpan);
        item.appendChild(badge);
    }

    item.addEventListener('click', async () => {
        if (state && state.currentPageId !== subpage.id) {
            const { loadPage } = await import('./pages-manager.js');
            await loadPage(subpage.id);
        }
    });

    return item;
}

function renderIconElement(icon, isEncrypted) {
    if (icon && String(icon).startsWith('fa-')) {
        const i = document.createElement('i');
        i.className = String(icon).replace(/[^a-zA-Z0-9 _-]/g, '').trim();
        return i;
    }
    if (icon) {
        const span = document.createElement('span');
        span.textContent = String(icon);
        return span;
    }
    const i = document.createElement('i');
    i.className = isEncrypted ? 'fa-solid fa-lock' : 'fa-solid fa-file-lines';
    return i;
}

function generatePreviewText(htmlContent, isEncrypted) {
    if (isEncrypted) return '';
    if (!htmlContent || htmlContent === '<p></p>') return '';

    const textContent = htmlToPlainText(htmlContent, { maxLength: 5000 });
    const preview = textContent.trim().substring(0, 80);
    return preview ? preview + (textContent.length > 80 ? '...' : '') : '';
}

function showSubpagesSection() {
    const section = document.getElementById('subpages-section');
    if (section) {
        section.style.display = 'block';
    }
}

function hideSubpagesSection() {
    const section = document.getElementById('subpages-section');
    if (section) {
        section.style.display = 'none';
    }
}

export function handleSubpageMetadataChange(data) {
    if (!state || !state.currentPageId) return;

    const subpages = getSubpagesFromState(state.currentPageId);
    const affectedSubpage = subpages.find(sp => sp.id === data.pageId);

    if (affectedSubpage) {
        loadAndRenderSubpages(state.currentPageId);
    }
}

export function onEditModeChange(isWriteMode) {
}

export function syncSubpagesPadding(horizontalPadding) {
    const section = document.getElementById('subpages-section');
    if (!section) return;

    const isMobile = window.innerWidth <= 900;

    if (horizontalPadding === null || isMobile) {
        section.style.paddingLeft = '';
        section.style.paddingRight = '';
    } else {
        section.style.paddingLeft = `${horizontalPadding}px`;
        section.style.paddingRight = `${horizontalPadding}px`;
    }
}
