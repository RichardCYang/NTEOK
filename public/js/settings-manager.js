
import { hideParentModalForChild, restoreParentModalFromChild } from './modal-parent-manager.js';
import { 
    escapeHtml, 
    showLoadingOverlay, 
    hideLoadingOverlay, 
    toggleModal, 
    bindModalOverlayClick,
    closeSidebar
} from './ui-utils.js';
import * as api from './api-utils.js';

let cachedCountries = null;
let cachedSecuritySettings = null;

let state = {
    currentUser: null,
    userSettings: {
        defaultMode: 'read',
        theme: 'default',
        language: 'ko-KR', 
        stickyHeader: false 
    },
    translations: {}, 
    availableCountries: [],
    allowedLoginCountries: []
};

function applyTheme(themeName) {
    const themeLink = document.querySelector('#theme-link');
    if (themeLink) {
        themeLink.href = `/themes/${themeName}.css`;
    } else {
        const newThemeLink = document.createElement('link');
        newThemeLink.id = 'theme-link';
        newThemeLink.rel = 'stylesheet';
        newThemeLink.href = `/themes/${themeName}.css`;
        document.head.appendChild(newThemeLink);
    }
    state.userSettings.theme = themeName;
    localStorage.setItem("userSettings", JSON.stringify(state.userSettings));
}

export function applyStickyHeader(isEnabled) {
    const editorArea = document.querySelector('.editor-area');
    if (!editorArea) return;

    if (isEnabled) {
        editorArea.classList.add('sticky-header-enabled');
    } else {
        editorArea.classList.remove('sticky-header-enabled');
    }
    state.userSettings.stickyHeader = isEnabled;
    localStorage.setItem("userSettings", JSON.stringify(state.userSettings));
}

export async function loadLanguage(lang) {
    try {
        const response = await fetch(`/languages/${lang}.json`);
        if (!response.ok) {
            throw new Error(`Failed to load language: ${lang}`);
        }
        const translations = await response.json();
        state.translations = translations;
        state.userSettings.language = lang;

        localStorage.setItem("userSettings", JSON.stringify(state.userSettings));

        applyTranslations();
        console.log(`Language loaded: ${lang}`);
    } catch (error) {
        console.error("Language load error:", error);
        if (lang !== 'ko-KR') {
            console.log("Falling back to ko-KR");
            loadLanguage('ko-KR');
        }
    }
}

function applyTranslations() {
    const translations = state.translations;
    if (!translations) return;

    const elements = document.querySelectorAll('[data-i18n]');
    elements.forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (translations[key]) {
            el.textContent = translations[key];
        }
    });

    const placeholders = document.querySelectorAll('[data-i18n-placeholder]');
    placeholders.forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (translations[key]) {
            el.placeholder = translations[key];
        }
    });

    updateModeToggleText();
}

function updateModeToggleText() {
    const modeBtn = document.querySelector('#mode-toggle-btn');
    if (!modeBtn) return;

    const span = modeBtn.querySelector('span');
    const translations = state.translations || {};
    
    if (span) {
        const isReadMode = span.textContent.includes(translations['mode_read'] || '읽기모드') ||
                           span.textContent.includes('읽기모드');
    }

    const currentTitle = modeBtn.getAttribute('title');
    if (currentTitle) {
        const isWriteModeIcon = modeBtn.querySelector('i')?.classList.contains('fa-pencil');
        if (isWriteModeIcon) {
            modeBtn.setAttribute('title', translations['mode_toggle_write'] || '쓰기 모드');
        } else {
            modeBtn.setAttribute('title', translations['mode_toggle_read'] || '읽기 모드');
        }
    }
}


export function initSettingsManager(appState) {
    state = appState;

    if (!state.userSettings) {
        state.userSettings = {
            defaultMode: 'read',
            theme: 'default',
            language: 'ko-KR'
        };
    }

    loadSettings();
    applyTheme(state.userSettings.theme);
    applyStickyHeader(state.userSettings.stickyHeader || false);

    const lang = state.userSettings.language || 'ko-KR';
    loadLanguage(lang);
}

export async function openSettingsModal() {
    const modal = document.querySelector("#settings-modal");
    const usernameEl = document.querySelector("#settings-username");
    const defaultModeSelect = document.querySelector("#settings-default-mode");
    const themeSelect = document.querySelector("#settings-theme-select");
    const languageSelect = document.querySelector("#settings-language-select");

    if (!modal) return;

    if (window.innerWidth <= 768 && window.closeSidebar) {
        window.closeSidebar();
    }

    if (usernameEl && state.currentUser) {
        usernameEl.textContent = state.currentUser.username || "-";
    }

    if (defaultModeSelect) {
        defaultModeSelect.value = state.userSettings.defaultMode;
    }

    const stickyHeaderCheckbox = document.querySelector("#settings-sticky-header");
    if (stickyHeaderCheckbox) {
        stickyHeaderCheckbox.checked = state.userSettings.stickyHeader || false;
    }

    if (languageSelect) {
        languageSelect.value = state.userSettings.language || 'ko-KR';
        languageSelect.onchange = (e) => {
             const newLang = e.target.value;
             loadLanguage(newLang);
        };
    }

    if (themeSelect) {
        try {
            const themes = await api.get('/api/themes');

            themeSelect.innerHTML = '';
            themes.forEach(theme => {
                const option = document.createElement('option');
                option.value = theme.id ?? theme.name;
                option.textContent = theme.name ?? theme.id;
                themeSelect.appendChild(option);
            });

            const desired = state.userSettings.theme || 'default';
            const has = Array.from(themeSelect.options).some(o => o.value === desired);
            themeSelect.value = has ? desired : 'default';
        } catch (error) {
            console.error('테마 목록 로드 실패:', error);
        }
    }

    toggleModal("#settings-modal", true);
}

export function closeSettingsModal() {
    toggleModal("#settings-modal", false);
}

export async function saveSettings() {
    const defaultModeSelect = document.querySelector("#settings-default-mode");
    const themeSelect = document.querySelector("#settings-theme-select");
    const languageSelect = document.querySelector("#settings-language-select");

    const newSettings = { ...state.userSettings };

    if (defaultModeSelect) {
        newSettings.defaultMode = defaultModeSelect.value;
    }

    const stickyHeaderCheckbox = document.querySelector("#settings-sticky-header");
    if (stickyHeaderCheckbox) {
        newSettings.stickyHeader = stickyHeaderCheckbox.checked;
        
        try {
            await api.put('/api/auth/settings', { stickyHeader: newSettings.stickyHeader });
        } catch (error) {
            console.error('서버 설정 저장 실패:', error);
        }
        
        applyStickyHeader(newSettings.stickyHeader);
    }

    if (languageSelect) {
        newSettings.language = languageSelect.value;
    }

    if (themeSelect) {
        const themeName = themeSelect.value;
        newSettings.theme = themeName;

        try {
            await api.post('/api/themes/set', { theme: themeName });
        } catch (error) {
            console.error('서버 테마 저장 실패:', error);
        }

        applyTheme(themeName);
    }

    state.userSettings = newSettings;
    localStorage.setItem("userSettings", JSON.stringify(state.userSettings));
    console.log("설정 저장됨:", state.userSettings);

    closeSettingsModal();
    alert("설정이 저장되었습니다.");
}

export function loadSettings() {
    try {
        const saved = localStorage.getItem("userSettings");
        if (saved) {
            const loaded = JSON.parse(saved);
            state.userSettings = { ...state.userSettings, ...loaded };
        }
    } catch (error) {
        console.error("설정 로드 실패:", error);
    }
    return state.userSettings;
}

export function bindSettingsModal() {
    const settingsBtn = document.querySelector("#settings-btn");
    const closeBtn = document.querySelector("#close-settings-btn");
    const saveBtn = document.querySelector("#save-settings-btn");
    const overlay = document.querySelector(".modal-overlay");
    const exportBackupBtn = document.querySelector("#export-backup-btn");
    const importBackupBtn = document.querySelector("#import-backup-btn");
    const importBackupInput = document.querySelector("#import-backup-input");
    const themeSelect = document.querySelector("#settings-theme-select");

    if (settingsBtn) {
        settingsBtn.addEventListener("click", () => {
            openSettingsModal();
        });
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", () => {
            closeSettingsModal();
        });
    }

    if (saveBtn) {
        saveBtn.addEventListener("click", () => {
            saveSettings();
        });
    }

    if (overlay) {
        overlay.addEventListener("click", () => {
            closeSettingsModal();
        });
    }

    if (themeSelect) {
        themeSelect.addEventListener('change', (e) => {
            applyTheme(e.target.value);
        });
    }

    if (exportBackupBtn) {
        exportBackupBtn.addEventListener("click", async () => {
            await exportBackup();
        });
    }

    if (importBackupBtn) {
        importBackupBtn.addEventListener("click", () => {
            importBackupInput.click();
        });
    }

    if (importBackupInput) {
        importBackupInput.addEventListener("change", async (e) => {
            const file = e.target.files[0];
            if (file) {
                await importBackup(file);
                importBackupInput.value = '';
            }
        });
    }

    const countryWhitelistToggle = document.querySelector('#country-whitelist-toggle');
    if (countryWhitelistToggle) {
        countryWhitelistToggle.addEventListener('change', (e) => {
            updateCountryWhitelistUI(e.target.checked, state.allowedLoginCountries || []);
        });
    }

    const manageCountryBtn = document.querySelector('#manage-country-whitelist-btn');
    if (manageCountryBtn) {
        manageCountryBtn.addEventListener('click', openCountryWhitelistModal);
    }

    const closeCountryModal = document.querySelector('#close-country-whitelist-modal');
    const cancelCountryBtn = document.querySelector('#cancel-country-whitelist');
    if (closeCountryModal) {
        closeCountryModal.addEventListener('click', closeCountryWhitelistModal);
    }
    if (cancelCountryBtn) {
        cancelCountryBtn.addEventListener('click', closeCountryWhitelistModal);
    }

    const saveCountryBtn = document.querySelector('#save-country-whitelist');
    if (saveCountryBtn) {
        saveCountryBtn.addEventListener('click', saveCountryWhitelist);
    }

    const countrySearchInput = document.querySelector('#country-search-input');
    if (countrySearchInput) {
        countrySearchInput.addEventListener('input', (e) => {
            filterCountries(e.target.value);
        });
    }

    const selectAllBtn = document.querySelector('#select-all-countries');
    const clearAllBtn = document.querySelector('#clear-all-countries');
    if (selectAllBtn) {
        selectAllBtn.addEventListener('click', () => {
            const checkboxes = document.querySelectorAll('#country-list-container input[type="checkbox"]');
            checkboxes.forEach(cb => cb.checked = true);
            updateSelectedCountriesSummary();
        });
    }
    if (clearAllBtn) {
        clearAllBtn.addEventListener('click', () => {
            const checkboxes = document.querySelectorAll('#country-list-container input[type="checkbox"]');
            checkboxes.forEach(cb => cb.checked = false);
            updateSelectedCountriesSummary();
        });
    }

    const openSecuritySettingsBtn = document.querySelector('#open-security-settings-btn');
    const backToSettingsBtn = document.querySelector('#back-to-settings-btn');
    const closeSecuritySettingsBtn = document.querySelector('#close-security-settings-btn');
    const saveSecuritySettingsBtn = document.querySelector('#save-security-settings-btn');
    const securityOverlay = document.querySelector('#security-settings-modal .modal-overlay');

    if (openSecuritySettingsBtn) {
        openSecuritySettingsBtn.addEventListener('click', () => {
            openSecuritySettingsModal();
        });
    }

    if (backToSettingsBtn) {
        backToSettingsBtn.addEventListener('click', () => {
            backToMainSettings();
        });
    }

    if (closeSecuritySettingsBtn) {
        closeSecuritySettingsBtn.addEventListener('click', () => {
            closeSecuritySettingsModal();
        });
    }

    if (saveSecuritySettingsBtn) {
        saveSecuritySettingsBtn.addEventListener('click', () => {
            saveSecuritySettings();
        });
    }

    if (securityOverlay) {
        securityOverlay.addEventListener('click', () => {
            closeSecuritySettingsModal();
        });
    }
}

export function applyCurrentUser(user) {
    if (!user) {
        return;
    }

    state.currentUser = user;

    const userNameEl = document.querySelector("#user-name");
    const userAvatarEl = document.querySelector("#user-avatar");

    if (userNameEl) {
        userNameEl.textContent = user.username || "Unknown";
    }

    if (userAvatarEl) {
        userAvatarEl.textContent = user.username ? user.username[0].toUpperCase() : "?";
    }

    if (user.theme) {
        applyTheme(user.theme);
    }

    if (user.stickyHeader !== undefined) {
        state.userSettings.stickyHeader = user.stickyHeader;
        applyStickyHeader(user.stickyHeader);
    }
}

export async function fetchAndDisplayCurrentUser() {
    try {
        const user = await api.get("/api/auth/me");
        applyCurrentUser(user);
        return;
    } catch (error) {
        console.error("사용자 정보 불러오기 실패:", error);
        const userNameEl = document.querySelector("#user-name");
        const userAvatarEl = document.querySelector("#user-avatar");

        if (userNameEl) {
            userNameEl.textContent = "로그인 필요";
        }

        if (userAvatarEl) {
            userAvatarEl.textContent = "?";
        }
    }
}

async function exportBackup() {
    try {
        try {
            const pageId = window?.appState?.currentPageId;
            if (pageId) {
                const { requestImmediateSave } = await import('./sync-manager.js');
                await requestImmediateSave(pageId, { includeSnapshot: true, waitForAck: true });
            }
        } catch (e) {
            console.warn('[백업 내보내기] 저장 선반영 실패(continue):', e?.message || e);
        }

        alert('백업 생성 중입니다. 데이터 양에 따라 시간이 걸릴 수 있습니다.');

        const { secureFetch } = await import('./ui-utils.js');
        const response = await secureFetch('/api/backup/export');

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || '백업 내보내기 실패');
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;

        const now = new Date();
        const dateStr = now.toISOString().slice(0, 19).replace(/[-:T]/g, '').replace(/(\d{8})(\d{6})/, '$1_$2');
        a.download = `NTEOK_Backup_${dateStr}.zip`;

        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        console.log('백업 내보내기 완료');
        alert('백업이 성공적으로 내보내졌습니다.');
    } catch (error) {
        console.error('백업 내보내기 실패:', error);
        alert(`백업 내보내기에 실패했습니다: ${error.message}`);
    }
}

async function importBackup(file) {
    if (!file || !file.name.endsWith('.zip')) {
        alert('ZIP 파일만 선택할 수 있습니다.');
        return;
    }

    const confirmed = confirm(
        '백업을 불러오면 현재 데이터와 병합됩니다.\n' +
        '계속하시겠습니까?'
    );

    if (!confirmed) {
        return;
    }

    try {
        const formData = new FormData();
        formData.append('backup', file);

        alert('백업 불러오기 중입니다. 데이터 양에 따라 시간이 걸릴 수 있습니다.');

        const { secureFetch } = await import('./ui-utils.js');
        const response = await secureFetch('/api/backup/import', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || '백업 불러오기 실패');
        }

        const result = await response.json();
        console.log('백업 불러오기 완료:', result);

        alert(
            `백업 불러오기가 완료되었습니다!\n\n` +
            `저장소: ${result.storagesCount}개\n` +
            `페이지: ${result.pagesCount}개\n` +
            `이미지: ${result.imagesCount}개\n\n` +
            `페이지를 새로고침합니다.`
        );

        window.location.reload();
    } catch (error) {
        console.error('백업 불러오기 실패:', error);
        alert(`백업 불러오기에 실패했습니다: ${error.message}`);
    }
}

export async function openSecuritySettingsModal() {
    const modal = document.querySelector("#security-settings-modal");
    if (!modal) return;

    toggleModal("#security-settings-modal", true);
    hideParentModalForChild('#settings-modal', modal);

    try {
        let data;
        if (cachedSecuritySettings) {
            data = cachedSecuritySettings;
        } else {
            data = await api.get('/api/auth/security-settings');
            cachedSecuritySettings = data;
        }

        const blockDuplicateLoginToggle = document.querySelector('#block-duplicate-login-toggle');
        const countryWhitelistToggle = document.querySelector('#country-whitelist-toggle');

        if (blockDuplicateLoginToggle) {
            blockDuplicateLoginToggle.checked = data.blockDuplicateLogin;
        }

        if (countryWhitelistToggle) {
            countryWhitelistToggle.checked = data.countryWhitelistEnabled;
            state.allowedLoginCountries = data.allowedLoginCountries || [];
        }
    } catch (error) {
        console.error('보안 설정 로드 실패:', error);
        closeSecuritySettingsModal();
        restoreParentModalFromChild(modal);
        alert('보안 설정을 불러오는데 실패했습니다.');
    }
}

function closeSecuritySettingsModal() {
    const modal = document.querySelector("#security-settings-modal");
    if (modal) {
        toggleModal("#security-settings-modal", false);
        restoreParentModalFromChild(modal);
    }
}

function backToMainSettings() {
    closeSecuritySettingsModal();
    openSettingsModal();
}

async function saveSecuritySettings() {
    try {
        const blockDuplicateLoginToggle = document.querySelector('#block-duplicate-login-toggle');
        const countryWhitelistToggle = document.querySelector('#country-whitelist-toggle');

        const payload = {
            blockDuplicateLogin: blockDuplicateLoginToggle?.checked || false,
            countryWhitelistEnabled: countryWhitelistToggle?.checked || false,
            allowedLoginCountries: state.allowedLoginCountries || []
        };

        await api.put('/api/auth/security-settings', payload);

        cachedSecuritySettings = payload;

        console.log('보안 설정 저장됨:', payload);
        closeSecuritySettingsModal();
        alert('보안 설정이 저장되었습니다.');
    } catch (error) {
        console.error('보안 설정 저장 실패:', error);
        alert(`보안 설정 저장에 실패했습니다: ${error.message}`);
    }
}

function updateSelectedCountriesSummary() {
    const summary = document.querySelector('#selected-countries-summary');
    if (!summary) return;

    const checkboxes = document.querySelectorAll('#country-list-container input[type="checkbox"]:checked');
    const selectedCount = checkboxes.length;

    if (selectedCount === 0) {
        summary.innerHTML = '<span style="color: #e74c3c;">선택된 국가가 없습니다. (모든 국가 차단)</span>';
    } else {
        const countryNames = Array.from(checkboxes).map(cb => {
            const label = cb.closest('label');
            return label?.querySelector('span')?.textContent || '';
        }).filter(name => name);

        summary.innerHTML = `
            <div style="margin-bottom: 4px;"><strong>${selectedCount}개 국가 선택됨</strong></div>
            <div style="color: #888; font-size: 12px; max-height: 60px; overflow-y: auto;">${escapeHtml(countryNames.join(', '))}</div>
        `;
    }
}

export async function openCountryWhitelistModal() {
    const modal = document.querySelector('#country-whitelist-modal');
    if (!modal) return;

    try {
        let countriesData, settingsData;

        if (!cachedCountries) {
            countriesData = await api.get('/api/auth/countries');
            cachedCountries = countriesData;
        }
        countriesData = cachedCountries;

        settingsData = await api.get('/api/auth/security-settings');
        cachedSecuritySettings = settingsData;

        state.availableCountries = countriesData.countries;
        state.allowedLoginCountries = settingsData.allowedLoginCountries || [];

        renderCountryList(state.availableCountries, state.allowedLoginCountries);

        updateSelectedCountriesSummary();

        toggleModal('#country-whitelist-modal', true);
    } catch (error) {
        console.error('국가 화이트리스트 모달 열기 실패:', error);
        alert('국가 목록을 불러오는데 실패했습니다.');
    }
}

function renderCountryList(countries, selectedCountries) {
    const container = document.querySelector('#country-list-container');
    if (!container) return;

    container.innerHTML = '';

    countries.forEach(country => {
        const isChecked = selectedCountries.includes(country.code);

        const label = document.createElement('label');
        label.style.display = 'flex';
        label.style.alignItems = 'center';
        label.style.padding = '8px';
        label.style.cursor = 'pointer';
        label.style.borderRadius = '4px';
        label.dataset.countryCode = country.code;
        label.dataset.countryName = country.name;

        label.innerHTML = `
            <input type="checkbox"
                   value="${escapeHtmlAttr(country.code)}"
                   ${isChecked ? 'checked' : ''}
                   style="margin-right: 8px;">
            <span>${escapeHtml(country.name)} (${escapeHtml(country.code)})</span>
        `;

        const checkbox = label.querySelector('input[type="checkbox"]');
        checkbox.addEventListener('change', () => {
            updateSelectedCountriesSummary();
        });

        label.addEventListener('mouseenter', () => {
            label.style.backgroundColor = '#f5f5f5';
        });
        label.addEventListener('mouseleave', () => {
            label.style.backgroundColor = '';
        });

        container.appendChild(label);
    });
}

async function saveCountryWhitelist() {
    const checkboxes = document.querySelectorAll('#country-list-container input[type="checkbox"]:checked');
    const selectedCountries = Array.from(checkboxes).map(cb => cb.value);

    state.allowedLoginCountries = selectedCountries;

    closeCountryWhitelistModal();

    alert(`${selectedCountries.length}개 국가가 선택되었습니다. "설정 저장" 버튼을 클릭하여 저장하세요.`);
}

function closeCountryWhitelistModal() {
    toggleModal('#country-whitelist-modal', false);
}

function filterCountries(searchTerm) {
    const labels = document.querySelectorAll('#country-list-container label');
    const term = searchTerm.toLowerCase();

    labels.forEach(label => {
        const countryName = label.dataset.countryName.toLowerCase();
        const countryCode = label.dataset.countryCode.toLowerCase();

        if (countryName.includes(term) || countryCode.includes(term)) {
            label.style.display = 'flex';
        } else {
            label.style.display = 'none';
        }
    });
}
