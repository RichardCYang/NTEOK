/**
 * 업데이트 히스토리 매니저
 */
import { get } from './api-utils.js';
import { toggleModal, escapeHtml } from './ui-utils.js';
import { loadPage } from './pages-manager.js';

let appState = null;

export function initUpdatesManager(state) {
    appState = state;
    const showUpdatesBtn = document.getElementById('show-updates-btn');
    const closeUpdatesBtn = document.getElementById('close-updates-history-btn');
    const updatesModal = document.getElementById('updates-history-modal');

    if (showUpdatesBtn) {
        showUpdatesBtn.addEventListener('click', () => {
            openUpdatesModal();
        });
    }

    if (closeUpdatesBtn) {
        closeUpdatesBtn.addEventListener('click', () => {
            toggleModal(updatesModal, false);
        });
    }
}

export async function openUpdatesModal() {
    const updatesModal = document.getElementById('updates-history-modal');
    const updatesList = document.getElementById('updates-history-list');
    
    toggleModal(updatesModal, true);
    
    updatesList.innerHTML = '<div style="padding: 40px; text-align: center; color: #9ca3af;">업데이트 정보를 불러오는 중...</div>';

    try {
        const storageId = appState ? appState.currentStorageId : null;
        if (!storageId) {
            updatesList.innerHTML = '<div style="padding: 40px; text-align: center; color: #9ca3af;">저장소가 선택되지 않았습니다.</div>';
            return;
        }

        const history = await get(`/api/pages/history?storageId=${encodeURIComponent(storageId)}`);
        renderUpdatesHistory(history);
    } catch (error) {
        console.error('Failed to fetch updates history:', error);
        updatesList.innerHTML = '<div style="padding: 40px; text-align: center; color: #ef4444;">업데이트 정보를 불러오는데 실패했습니다.</div>';
    }
}

function renderUpdatesHistory(history) {
    const updatesList = document.getElementById('updates-history-list');
    
    if (!history || history.length === 0) {
        updatesList.innerHTML = '<div style="padding: 40px; text-align: center; color: #9ca3af;">최근 업데이트 내역이 없습니다.</div>';
        return;
    }

    updatesList.innerHTML = '';
    
    history.forEach(item => {
        const updateItem = document.createElement('div');
        updateItem.className = 'update-item';
        
        const icon = getActionIcon(item.action);
        const message = getActionMessage(item);
        const time = formatTime(item.createdAt);
        
        updateItem.innerHTML = `
            <div class="update-icon">${icon}</div>
            <div class="update-content">
                <div class="update-header">
                    <span class="update-user">${escapeHtml(item.username)}</span>
                    <span class="update-time">${time}</span>
                </div>
                <div class="update-message">${message}</div>
                ${renderDetails(item)}
            </div>
        `;
        
        updatesList.appendChild(updateItem);
    });

    // 페이지 링크 클릭 이벤트 바인딩
    updatesList.querySelectorAll('.update-page-link').forEach(link => {
        link.addEventListener('click', (e) => {
            const pageId = e.target.dataset.pageId;
            if (pageId) {
                toggleModal(document.getElementById('updates-history-modal'), false);
                loadPage(pageId);
            }
        });
    });
}

function getActionIcon(action) {
    switch (action) {
        case 'CREATE_PAGE': return '<i class="fa-solid fa-file-circle-plus" style="color: #16a34a;"></i>';
        case 'UPDATE_PAGE': return '<i class="fa-solid fa-file-pen" style="color: #2563eb;"></i>';
        case 'DELETE_PAGE': return '<i class="fa-solid fa-file-circle-xmark" style="color: #dc2626;"></i>';
        case 'REORDER_PAGES': return '<i class="fa-solid fa-sort" style="color: #7c3aed;"></i>';
        case 'UPDATE_COVER': return '<i class="fa-solid fa-image" style="color: #ea580c;"></i>';
        case 'DELETE_COVER': return '<i class="fa-solid fa-image-slash" style="color: #9ca3af;"></i>';
        case 'RESTORE_PAGE': return '<i class="fa-solid fa-rotate-left" style="color: #10b981;"></i>';
        case 'PERMANENT_DELETE_PAGE': return '<i class="fa-solid fa-trash-can" style="color: #dc2626;"></i>';
        default: return '<i class="fa-solid fa-clock-rotate-left"></i>';
    }
}

function getActionMessage(item) {
    const action = item.action;
    const pageTitle = item.pageTitle || (item.details && item.details.title) || '제목 없음';
    
    // 삭제된 페이지는 링크를 걸지 않음
    const isDeleted = action === 'DELETE_PAGE' || action === 'PERMANENT_DELETE_PAGE';
    const pageLink = (item.pageId && !isDeleted) 
        ? `<span class="update-page-link" data-page-id="${item.pageId}">${escapeHtml(pageTitle)}</span>` 
        : `<span style="font-weight: 600;">${escapeHtml(pageTitle)}</span>`;

    switch (action) {
        case 'CREATE_PAGE': return `${pageLink} 페이지를 생성했습니다.`;
        case 'UPDATE_PAGE': return `${pageLink} 문서를 수정했습니다.`;
        case 'DELETE_PAGE': return `${pageLink} 페이지를 휴지통으로 이동했습니다.`;
        case 'RESTORE_PAGE': return `${pageLink} 페이지를 복구했습니다.`;
        case 'PERMANENT_DELETE_PAGE': return `${pageLink} 페이지를 영구 삭제했습니다.`;
        case 'REORDER_PAGES': return `페이지 순서를 변경했습니다.`;
        case 'UPDATE_COVER': return `${pageLink} 페이지의 커버를 변경했습니다.`;
        case 'DELETE_COVER': return `${pageLink} 페이지의 커버를 제거했습니다.`;
        default: return `알 수 없는 작업을 수행했습니다. (${action})`;
    }
}

function renderDetails(item) {
    if (item.action === 'UPDATE_PAGE' && item.details && item.details.title && item.pageTitle && item.details.title !== item.pageTitle) {
        return `<div class="update-details">제목 변경: ${escapeHtml(item.details.title)}</div>`;
    }
    return '';
}

function formatTime(isoString) {
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return '방금 전';
    if (diffMins < 60) return `${diffMins}분 전`;
    if (diffHours < 24) return `${diffHours}시간 전`;
    if (diffDays < 7) return `${diffDays}일 전`;
    
    return date.toLocaleDateString('ko-KR', { year: 'numeric', month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}
