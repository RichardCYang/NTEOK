
import { toggleModal, addIcon } from './ui-utils.js';
import * as api from './api-utils.js';

const THEME_ICONS = [
    'fa-solid fa-star', 'fa-solid fa-heart', 'fa-solid fa-flag',
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
    '⭐', '❤️', '🚩', '✅', 'ℹ️', '⚠️', '❌',
    '💡', '🔥', '⚡', '🔔', '👤', '👥', '📅', '⏰',
    '🏷️', '🎯', '🏆', '🎁', '🏠', '🔍', '⚙️', '🗑️',
    '📄', '📃', '📁', '📂', '🖼️', '🎬', '🎵', '🔗',
    '💻', '📱', '🖥️', '⌨️', '🖱️', '🔋', '📡', '☁️',
    '🍎', '🍋', '🍇', '🍉', '🍓', '🍔', '🍕', '☕',
    '✈️', '🚗', '🚲', '🚀', '🏀', '⚽', '🎮', '🎨'
];

let state = {
    currentPageId: null,
    currentTab: 'theme', 
    appState: null
};

export function initIconPicker(appState) {
    state.appState = appState;
    
    const modal = document.getElementById('icon-picker-modal');
    if (!modal) return;

    document.getElementById('close-icon-picker-btn')?.addEventListener('click', () => {
        toggleModal(modal, false);
    });

    modal.querySelector('.modal-overlay')?.addEventListener('click', () => {
        toggleModal(modal, false);
    });

    document.getElementById('icon-tab-theme')?.addEventListener('click', () => {
        switchTab('theme');
    });

    document.getElementById('icon-tab-color')?.addEventListener('click', () => {
        switchTab('color');
    });

    document.getElementById('remove-icon-btn')?.addEventListener('click', () => {
        selectIcon(null);
    });
}

export function showIconPickerModal(pageId) {
    state.currentPageId = pageId;
    const modal = document.getElementById('icon-picker-modal');
    if (!modal) return;

    switchTab('theme'); 
    toggleModal(modal, true);
}

function switchTab(tab) {
    state.currentTab = tab;
    
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

async function selectIcon(iconValue) {
    if (!state.currentPageId) return;

    try {
        await api.put(`/api/pages/${encodeURIComponent(state.currentPageId)}`, {
            icon: iconValue
        });

        if (state.appState && state.appState.pages) {
            const page = state.appState.pages.find(p => p.id === state.currentPageId);
            if (page) {
                page.icon = iconValue;
            }
        }

        if (typeof window.renderPageList === 'function') {
            window.renderPageList();
        } else if (state.appState && typeof state.appState.renderPageList === 'function') {
            state.appState.renderPageList();
        } else {
            if (state.appState && typeof state.appState.fetchPageList === 'function') {
                await state.appState.fetchPageList();
            }
        }

        toggleModal('#icon-picker-modal', false);
    } catch (error) {
        console.error('Failed to set icon:', error);
        alert('아이콘 설정 실패: ' + error.message);
    }
}
