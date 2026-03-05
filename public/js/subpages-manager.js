
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
    if (subpage.isEncrypted) {
        item.classList.add('encrypted');
    }
    item.dataset.pageId = subpage.id;

    const iconHtml = renderIcon(subpage.icon, subpage.isEncrypted);

    const preview = generatePreview(subpage.content, subpage.isEncrypted);

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

    item.addEventListener('click', async () => {
        if (state && state.currentPageId !== subpage.id) {
            const { loadPage } = await import('./pages-manager.js');
            await loadPage(subpage.id);
        }
    });

    return item;
}

function renderIcon(icon, isEncrypted) {
    if (icon) {
        if (icon.startsWith('fa-')) {
            return `<i class="${escapeHtmlAttr(icon)}"></i>`;
        }
        return escapeHtml(icon);
    }

    if (isEncrypted) {
        return '<i class="fa-solid fa-lock"></i>';
    }
    return '<i class="fa-solid fa-file-lines"></i>';
}

function generatePreview(htmlContent, isEncrypted) {
    if (isEncrypted) {
        return '';
    }

    if (!htmlContent || htmlContent === '<p></p>') {
        return '';
    }

    const textContent = htmlToPlainText(htmlContent, { maxLength: 5000 });

    const preview = textContent.trim().substring(0, 80);
    return preview ? escapeHtml(preview) + (textContent.length > 80 ? '...' : '') : '';
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
