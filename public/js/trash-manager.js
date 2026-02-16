/**
 * 휴지통 매니저
 */
import { get, post, del } from './api-utils.js';
import { toggleModal, escapeHtml } from './ui-utils.js';
import { fetchPageList } from './pages-manager.js';

let appState = null;

export function initTrashManager(state) {
    appState = state;
    const showTrashBtn = document.getElementById('show-trash-btn');
    const closeTrashBtn = document.getElementById('close-trash-modal-btn');
    const trashModal = document.getElementById('trash-modal');

    if (showTrashBtn) {
        showTrashBtn.addEventListener('click', () => {
            openTrashModal();
        });
    }

    if (closeTrashBtn) {
        closeTrashBtn.addEventListener('click', () => {
            toggleModal(trashModal, false);
        });
    }
}

export async function openTrashModal() {
    const trashModal = document.getElementById('trash-modal');
    const trashList = document.getElementById('trash-list');
    
    toggleModal(trashModal, true);
    
    trashList.innerHTML = `<div style="padding: 40px; text-align: center; color: #9ca3af;" data-i18n="loading">불러오는 중...</div>`;

    try {
        const storageId = appState ? appState.currentStorageId : null;
        if (!storageId) {
            trashList.innerHTML = `<div style="padding: 40px; text-align: center; color: #9ca3af;">저장소가 선택되지 않았습니다.</div>`;
            return;
        }

        const pages = await get(`/api/pages/trash?storageId=${encodeURIComponent(storageId)}`);
        renderTrashList(pages);
    } catch (error) {
        console.error('Failed to fetch trash list:', error);
        trashList.innerHTML = `<div style="padding: 40px; text-align: center; color: #ef4444;">정보를 불러오는데 실패했습니다.</div>`;
    }
}

function renderTrashList(pages) {
    const trashList = document.getElementById('trash-list');
    
    if (!pages || pages.length === 0) {
        trashList.innerHTML = `<div style="padding: 40px; text-align: center; color: #9ca3af;" data-i18n="trash_empty">휴지통이 비어 있습니다.</div>`;
        return;
    }

    trashList.innerHTML = '';
    
    pages.forEach(page => {
        const item = document.createElement('div');
        item.className = 'trash-item';
        item.style = 'display: flex; align-items: center; justify-content: space-between; padding: 12px 16px; border-bottom: 1px solid #f3f4f6;';
        
        const info = document.createElement('div');
        info.style = 'display: flex; flex-direction: column; gap: 2px;';
        info.innerHTML = `
            <div style="font-weight: 500; color: #1f2937;">${escapeHtml(page.title)}</div>
            <div style="font-size: 12px; color: #9ca3af;">삭제됨: ${formatTime(page.deletedAt)}</div>
        `;
        
        const actions = document.createElement('div');
        actions.style = 'display: flex; gap: 8px;';
        
        const restoreBtn = document.createElement('button');
        restoreBtn.className = 'trash-action-btn';
        restoreBtn.style = 'background: #f3f4f6; border: none; padding: 4px 10px; border-radius: 4px; font-size: 12px; cursor: pointer; color: #4b5563; transition: background 0.2s;';
        restoreBtn.innerText = '복구';
        restoreBtn.dataset.i18n = 'trash_restore';
        restoreBtn.addEventListener('mouseenter', () => restoreBtn.style.background = '#e5e7eb');
        restoreBtn.addEventListener('mouseleave', () => restoreBtn.style.background = '#f3f4f6');
        restoreBtn.addEventListener('click', () => restorePage(page.id));
        
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'trash-action-btn';
        deleteBtn.style = 'background: #fee2e2; border: none; padding: 4px 10px; border-radius: 4px; font-size: 12px; cursor: pointer; color: #dc2626; transition: background 0.2s;';
        deleteBtn.innerText = '영구 삭제';
        deleteBtn.dataset.i18n = 'trash_permanent_delete';
        deleteBtn.addEventListener('mouseenter', () => deleteBtn.style.background = '#fecaca');
        deleteBtn.addEventListener('mouseleave', () => deleteBtn.style.background = '#fee2e2');
        deleteBtn.addEventListener('click', () => permanentlyDeletePage(page.id));
        
        actions.appendChild(restoreBtn);
        actions.appendChild(deleteBtn);
        
        item.appendChild(info);
        item.appendChild(actions);
        trashList.appendChild(item);
    });

    // 전역 번역 적용 함수가 있다면 호출 (예: window.applyTranslations)
    if (window.i18n && typeof window.i18n.applyTranslations === 'function') {
        window.i18n.applyTranslations(trashList);
    }
}

async function restorePage(pageId) {
    try {
        await post(`/api/pages/${pageId}/restore`);
        await openTrashModal(); // 목록 새로고침
        if (typeof fetchPageList === 'function') {
            await fetchPageList(); // 사이드바 새로고침
        }
    } catch (error) {
        console.error('Failed to restore page:', error);
        alert('페이지 복구에 실패했습니다.');
    }
}

async function permanentlyDeletePage(pageId) {
    if (!confirm('이 페이지를 영구적으로 삭제하시겠습니까? 이 작업은 되돌릴 수 없습니다.')) {
        return;
    }

    try {
        await del(`/api/pages/${pageId}/permanent`);
        await openTrashModal(); // 목록 새로고침
    } catch (error) {
        console.error('Failed to permanently delete page:', error);
        alert('페이지 삭제에 실패했습니다.');
    }
}

function formatTime(isoString) {
    const date = new Date(isoString);
    return date.toLocaleDateString('ko-KR', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
