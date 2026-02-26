/**
 * 아이콘 선택기 관리 모듈
 */

import { toggleModal, addIcon } from './ui-utils.js';
import * as api from './api-utils.js';

// 아이콘 목록 정의
const THEME_ICONS = [
    'fa-solid fa-star', 'fa-solid fa-heart', 'fa-solid fa-flag', 'fa-solid fa-bookmark',
    'fa-solid fa-circle-check', 'fa-solid fa-circle-info', 'fa-solid fa-circle-exclamation', 'fa-solid fa-circle-xmark',
    'fa-solid fa-lightbulb', 'fa-solid fa-fire', 'fa-solid fa-bolt', 'fa-solid fa-bell',
    'fa-solid fa-user', 'fa-solid fa-users', 'fa-solid fa-calendar', 'fa-solid fa-clock',
    'fa-solid fa-tag', 'fa-solid fa-tags', 'fa-solid fa-trophy', 'fa-solid fa-gift',
    'fa-solid fa-house', 'fa-solid fa-magnifying-glass', 'fa-solid fa-gear', 'fa-solid fa-trash-can',
    'fa-solid fa-file', 'fa-solid fa-file-lines', 'fa-solid fa-folder', 'fa-solid fa-folder-open',
    'fa-solid fa-image', 'fa-solid fa-video', 'fa-solid fa-music', 'fa-solid fa-link',
    'fa-solid fa-code', 'fa-solid fa-terminal', 'fa-solid fa-database', 'fa-solid fa-server',
    'fa-solid fa-mobile-screen', 'fa-solid fa-laptop', 'fa-solid fa-desktop', 'fa-solid fa-print',
    'fa-solid fa-paper-plane', 'fa-solid fa-inbox', 'fa-solid fa-envelope', 'fa-solid fa-comment'
];

const COLOR_ICONS = [
    '⭐', '❤️', '🚩', '🔖', '✅', 'ℹ️', '⚠️', '❌',
    '💡', '🔥', '⚡', '🔔', '👤', '👥', '📅', '⏰',
    '🏷️', '🎯', '🏆', '🎁', '🏠', '🔍', '⚙️', '🗑️',
    '📄', '📃', '📁', '📂', '🖼️', '🎬', '🎵', '🔗',
    '💻', '📱', '🖥️', '⌨️', '🖱️', '🔋', '📡', '☁️',
    '🍎', '🍋', '🍇', '🍉', '🍓', '🍔', '🍕', '☕',
    '✈️', '🚗', '🚲', '🚀', '🏀', '⚽', '🎮', '🎨'
];

let state = {
    currentPageId: null,
    currentTab: 'theme', // 'theme' | 'color'
    appState: null
};

/**
 * 아이콘 선택기 초기화
 */
export function initIconPicker(appState) {
    state.appState = appState;
    
    const modal = document.getElementById('icon-picker-modal');
    if (!modal) return;

    // 닫기 버튼
    document.getElementById('close-icon-picker-btn')?.addEventListener('click', () => {
        toggleModal(modal, false);
    });

    // 오버레이 클릭 시 닫기
    modal.querySelector('.modal-overlay')?.addEventListener('click', () => {
        toggleModal(modal, false);
    });

    // 탭 전환
    document.getElementById('icon-tab-theme')?.addEventListener('click', () => {
        switchTab('theme');
    });

    document.getElementById('icon-tab-color')?.addEventListener('click', () => {
        switchTab('color');
    });

    // 아이콘 제거 버튼
    document.getElementById('remove-icon-btn')?.addEventListener('click', () => {
        selectIcon(null);
    });
}

/**
 * 아이콘 선택 모달 표시
 */
export function showIconPickerModal(pageId) {
    state.currentPageId = pageId;
    const modal = document.getElementById('icon-picker-modal');
    if (!modal) return;

    switchTab('theme'); // 기본 탭으로 시작
    toggleModal(modal, true);
}

/**
 * 탭 전환
 */
function switchTab(tab) {
    state.currentTab = tab;
    
    // UI 업데이트
    const themeBtn = document.getElementById('icon-tab-theme');
    const colorBtn = document.getElementById('icon-tab-color');
    
    if (tab === 'theme') {
        themeBtn?.classList.add('active');
        colorBtn?.classList.remove('active');
    } else {
        themeBtn?.classList.remove('active');
        colorBtn?.classList.add('active');
    }
    
    renderIconGrid();
}

/**
 * 아이콘 그리드 렌더링
 */
function renderIconGrid() {
    const grid = document.getElementById('icon-picker-grid');
    if (!grid) return;

    grid.innerHTML = '';
    const icons = state.currentTab === 'theme' ? THEME_ICONS : COLOR_ICONS;

    icons.forEach(iconValue => {
        const btn = document.createElement('button');
        btn.className = 'icon-picker-item';
        btn.type = 'button';
        btn.title = iconValue;

        if (state.currentTab === 'theme') {
            addIcon(btn, iconValue);
        } else {
            btn.textContent = iconValue;
        }

        btn.addEventListener('click', () => {
            selectIcon(iconValue);
        });

        grid.appendChild(btn);
    });
}

/**
 * 아이콘 선택 처리
 */
async function selectIcon(iconValue) {
    if (!state.currentPageId) return;

    try {
        await api.put(`/api/pages/${encodeURIComponent(state.currentPageId)}`, {
            icon: iconValue
        });

        // 로컬 상태 업데이트
        if (state.appState && state.appState.pages) {
            const page = state.appState.pages.find(p => p.id === state.currentPageId);
            if (page) {
                page.icon = iconValue;
            }
        }

        // UI 갱신 (전역 renderPageList가 app.js에 있으므로 window를 통해 호출하거나 fetchPageList 호출)
        if (typeof window.renderPageList === 'function') {
            window.renderPageList();
        } else if (state.appState && typeof state.appState.renderPageList === 'function') {
            state.appState.renderPageList();
        } else {
            // 차선책: 새로고침 또는 목록 다시 가져오기
            if (state.appState && typeof state.appState.fetchPageList === 'function') {
                await state.appState.fetchPageList();
            }
        }

        // 모달 닫기
        toggleModal('#icon-picker-modal', false);
    } catch (error) {
        console.error('Failed to set icon:', error);
        alert('아이콘 설정 실패: ' + error.message);
    }
}
