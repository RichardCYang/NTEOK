/**
 * 설정 관리 모듈
 */

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

// 캐시 변수 (성능 최적화)
let cachedCountries = null;
let cachedSecuritySettings = null;

// 전역 상태
let state = {
    currentUser: null,
    userSettings: {
        defaultMode: 'read',
        theme: 'default',
        language: 'ko-KR', // 기본 언어: 한국어
        stickyHeader: false // 기본값: 고정 없음 (스크롤됨)
    },
    translations: {}, // 로드된 번역 데이터
    availableCountries: [],
    allowedLoginCountries: []
};

/**
 * 테마 적용
 * @param {string} themeName - 적용할 테마 이름 (e.g., 'default', 'dark')
 */
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

/**
 * 고정 헤더 설정 적용
 * @param {boolean} isEnabled - 고정 여부
 */
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

/**
 * 언어 로드 및 적용
 * @param {string} lang - 언어 코드 (e.g., 'ko-KR', 'en', 'ja-JP')
 */
export async function loadLanguage(lang) {
    try {
        const response = await fetch(`/languages/${lang}.json`);
        if (!response.ok) {
            throw new Error(`Failed to load language: ${lang}`);
        }
        const translations = await response.json();
        state.translations = translations;
        state.userSettings.language = lang;

        // 설정 저장 (언어 변경 즉시 저장)
        localStorage.setItem("userSettings", JSON.stringify(state.userSettings));

        applyTranslations();
        console.log(`Language loaded: ${lang}`);
    } catch (error) {
        console.error("Language load error:", error);
        // 실패 시 기본 언어로 폴백하거나 에러 처리
        if (lang !== 'ko-KR') {
            console.log("Falling back to ko-KR");
            loadLanguage('ko-KR');
        }
    }
}

/**
 * 번역 적용
 */
function applyTranslations() {
    const translations = state.translations;
    if (!translations) return;

    // 텍스트 콘텐츠 번역 (data-i18n)
    const elements = document.querySelectorAll('[data-i18n]');
    elements.forEach(el => {
        const key = el.getAttribute('data-i18n');
        if (translations[key]) {
            el.textContent = translations[key];
        }
    });

    // 플레이스홀더 번역 (data-i18n-placeholder)
    const placeholders = document.querySelectorAll('[data-i18n-placeholder]');
    placeholders.forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        if (translations[key]) {
            el.placeholder = translations[key];
        }
    });

    // 모드 토글 버튼 텍스트 업데이트 (동적 상태라 별도 처리 필요할 수 있음)
    updateModeToggleText();
}

/**
 * 모드 토글 버튼 텍스트 업데이트 헬퍼
 */
function updateModeToggleText() {
    const modeBtn = document.querySelector('#mode-toggle-btn');
    if (!modeBtn) return;

    const span = modeBtn.querySelector('span');
    const translations = state.translations || {};
    
    // index.html 디자인에 따라 span이 없을 수 있음 (아이콘만 있는 경우)
    if (span) {
        const isReadMode = span.textContent.includes(translations['mode_read'] || '읽기모드') ||
                           span.textContent.includes('읽기모드');
        // 필요한 경우 여기서 span 텍스트 업데이트 로직 추가
    }

    // title 속성 번역 (항상 존재함)
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


/**
 * 상태 초기화
 */
export function initSettingsManager(appState) {
    state = appState;

    // appState에 없는 경우 초기값 설정 (기존 코드 호환성)
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

    // 언어 로드
    const lang = state.userSettings.language || 'ko-KR';
    loadLanguage(lang);
}

/**
 * 설정 모달 열기
 */
export async function openSettingsModal() {
    const modal = document.querySelector("#settings-modal");
    const usernameEl = document.querySelector("#settings-username");
    const defaultModeSelect = document.querySelector("#settings-default-mode");
    const themeSelect = document.querySelector("#settings-theme-select");
    const languageSelect = document.querySelector("#settings-language-select");

    if (!modal) return;

    // 모바일에서 설정 열 때 사이드바 닫기
    if (window.innerWidth <= 768 && window.closeSidebar) {
        window.closeSidebar();
    }

    // 현재 사용자 정보 표시
    if (usernameEl && state.currentUser) {
        usernameEl.textContent = state.currentUser.username || "-";
    }

    // 현재 설정 값 표시
    if (defaultModeSelect) {
        defaultModeSelect.value = state.userSettings.defaultMode;
    }

    const stickyHeaderCheckbox = document.querySelector("#settings-sticky-header");
    if (stickyHeaderCheckbox) {
        stickyHeaderCheckbox.checked = state.userSettings.stickyHeader || false;
    }

    if (languageSelect) {
        languageSelect.value = state.userSettings.language || 'ko-KR';
        // 이벤트 리스너 중복 방지 (간단하게 처리)
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
                // value에는 실제 파일을 가리키는 id를 사용
                option.value = theme.id ?? theme.name;
                option.textContent = theme.name ?? theme.id;
                themeSelect.appendChild(option);
            });

            // 저장된 값이 목록에 없으면 안전하게 default로 폴백
            const desired = state.userSettings.theme || 'default';
            const has = Array.from(themeSelect.options).some(o => o.value === desired);
            themeSelect.value = has ? desired : 'default';
        } catch (error) {
            console.error('테마 목록 로드 실패:', error);
        }
    }

    toggleModal("#settings-modal", true);
}

/**
 * 설정 모달 닫기
 */
export function closeSettingsModal() {
    toggleModal("#settings-modal", false);
}

/**
 * 설정 저장
 */
export async function saveSettings() {
    const defaultModeSelect = document.querySelector("#settings-default-mode");
    const themeSelect = document.querySelector("#settings-theme-select");
    const languageSelect = document.querySelector("#settings-language-select");

    const newSettings = { ...state.userSettings };

    // 로컬 설정 저장
    if (defaultModeSelect) {
        newSettings.defaultMode = defaultModeSelect.value;
    }

    const stickyHeaderCheckbox = document.querySelector("#settings-sticky-header");
    if (stickyHeaderCheckbox) {
        newSettings.stickyHeader = stickyHeaderCheckbox.checked;
        
        // 서버에 일반 설정 저장 시도
        try {
            await api.put('/api/auth/settings', { stickyHeader: newSettings.stickyHeader });
        } catch (error) {
            console.error('서버 설정 저장 실패:', error);
        }
        
        applyStickyHeader(newSettings.stickyHeader);
    }

    if (languageSelect) {
        newSettings.language = languageSelect.value;
        // 이미 onchange에서 저장했지만, 여기서도 명시적으로 업데이트
    }

    if (themeSelect) {
        const themeName = themeSelect.value;
        newSettings.theme = themeName;

        // 서버에 테마 저장 시도
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

/**
 * 설정 로드
 */
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

/**
 * 설정 모달 이벤트 바인딩
 */
export function bindSettingsModal() {
    const settingsBtn = document.querySelector("#settings-btn");
    const closeBtn = document.querySelector("#close-settings-btn");
    const saveBtn = document.querySelector("#save-settings-btn");
    const overlay = document.querySelector(".modal-overlay");
    const exportBackupBtn = document.querySelector("#export-backup-btn");
    const importBackupBtn = document.querySelector("#import-backup-btn");
    const importBackupInput = document.querySelector("#import-backup-input");
    const themeSelect = document.querySelector("#settings-theme-select");
    const themeUploadBtn = document.querySelector("#theme-upload-btn");
    const themeUploadInput = document.querySelector("#theme-upload-input");

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

    if (themeUploadBtn) {
        themeUploadBtn.addEventListener('click', () => {
            themeUploadInput.click();
        });
    }

    if (themeUploadInput) {
        themeUploadInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (file) {
                await uploadTheme(file);
                themeUploadInput.value = ''; // Reset input
            }
        });
    }

    // 백업 내보내기 버튼
    if (exportBackupBtn) {
        exportBackupBtn.addEventListener("click", async () => {
            await exportBackup();
        });
    }

    // 백업 불러오기 버튼
    if (importBackupBtn) {
        importBackupBtn.addEventListener("click", () => {
            importBackupInput.click();
        });
    }

    // 파일 선택 시 백업 불러오기
    if (importBackupInput) {
        importBackupInput.addEventListener("change", async (e) => {
            const file = e.target.files[0];
            if (file) {
                await importBackup(file);
                // 입력 초기화
                importBackupInput.value = '';
            }
        });
    }

    // 국가 화이트리스트 토글
    const countryWhitelistToggle = document.querySelector('#country-whitelist-toggle');
    if (countryWhitelistToggle) {
        countryWhitelistToggle.addEventListener('change', (e) => {
            updateCountryWhitelistUI(e.target.checked, state.allowedLoginCountries || []);
        });
    }

    // 국가 화이트리스트 관리 버튼
    const manageCountryBtn = document.querySelector('#manage-country-whitelist-btn');
    if (manageCountryBtn) {
        manageCountryBtn.addEventListener('click', openCountryWhitelistModal);
    }

    // 국가 화이트리스트 모달 닫기
    const closeCountryModal = document.querySelector('#close-country-whitelist-modal');
    const cancelCountryBtn = document.querySelector('#cancel-country-whitelist');
    if (closeCountryModal) {
        closeCountryModal.addEventListener('click', closeCountryWhitelistModal);
    }
    if (cancelCountryBtn) {
        cancelCountryBtn.addEventListener('click', closeCountryWhitelistModal);
    }

    // 국가 화이트리스트 저장
    const saveCountryBtn = document.querySelector('#save-country-whitelist');
    if (saveCountryBtn) {
        saveCountryBtn.addEventListener('click', saveCountryWhitelist);
    }

    // 국가 검색
    const countrySearchInput = document.querySelector('#country-search-input');
    if (countrySearchInput) {
        countrySearchInput.addEventListener('input', (e) => {
            filterCountries(e.target.value);
        });
    }

    // 모두 선택/해제
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

    // 보안 설정 모달 버튼
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

/**
 * 현재 사용자 정보 가져오기 및 표시
 */
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

    // 서버에서 받은 테마 적용
    if (user.theme) {
        applyTheme(user.theme);
    }

    // 서버에서 받은 고정 헤더 설정 적용
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

/**
 * 백업 내보내기
 */
async function exportBackup() {
    try {
        // 내보내기 시작 알림
        alert('백업 생성 중입니다. 데이터 양에 따라 시간이 걸릴 수 있습니다.');

        // Blob 데이터 처리를 위해 직접 secureFetch 사용 (api.get은 json 기대)
        const { secureFetch } = await import('./ui-utils.js');
        const response = await secureFetch('/api/backup/export');

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || '백업 내보내기 실패');
        }

        // Blob으로 파일 다운로드
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;

        // 파일명: NTEOK_Backup_YYYYMMDD_HHMMSS.zip
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

/**
 * 백업 불러오기
 */
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
        // FormData로 파일 전송
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
            `컬렉션: ${result.collectionsCount}개\n` +
            `페이지: ${result.pagesCount}개\n` +
            `이미지: ${result.imagesCount}개\n\n` +
            `페이지를 새로고침합니다.`
        );

        // 페이지 새로고침하여 새 데이터 반영
        window.location.reload();
    } catch (error) {
        console.error('백업 불러오기 실패:', error);
        alert(`백업 불러오기에 실패했습니다: ${error.message}`);
    }
}

/**
 * 테마 파일 업로드
 */
async function uploadTheme(file) {
    if (!file || !file.name.endsWith('.css')) {
        alert('CSS 파일만 선택할 수 있습니다.');
        return;
    }

    try {
        const formData = new FormData();
        formData.append('themeFile', file);

        const { secureFetch } = await import('./ui-utils.js');
        const response = await secureFetch('/api/themes/upload', {
            method: 'POST',
            body: formData
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || '테마 업로드 실패');
        }

        const result = await response.json();
        console.log('테마 업로드 완료:', result);

        // 다시 테마 목록을 불러와서 UI에 반영
        await openSettingsModal();

        alert(`테마 '${(result.theme && result.theme.name) ? result.theme.name : '업로드한 테마'}'이(가) 성공적으로 업로드되었습니다.`);
    } catch (error) {
        console.error('테마 업로드 실패:', error);
        alert(`테마 업로드에 실패했습니다: ${error.message}`);
    }
}

/**
 * 보안 설정 모달 열기
 */
export async function openSecuritySettingsModal() {
    const modal = document.querySelector("#security-settings-modal");
    if (!modal) return;

    toggleModal("#security-settings-modal", true);
    hideParentModalForChild('#settings-modal', modal);

    try {
        // 보안 설정 로드 (캐싱 적용)
        let data;
        if (cachedSecuritySettings) {
            // 캐시된 데이터 사용
            data = cachedSecuritySettings;
        } else {
            // 최초 로드 시에만 API 호출
            data = await api.get('/api/auth/security-settings');
            cachedSecuritySettings = data;
        }

        // UI에 값 설정
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

/**
 * 보안 설정 모달 닫기
 */
function closeSecuritySettingsModal() {
    const modal = document.querySelector("#security-settings-modal");
    if (modal) {
        toggleModal("#security-settings-modal", false);
        restoreParentModalFromChild(modal);
    }
}

/**
 * 보안 설정에서 메인 설정으로 돌아가기
 */
function backToMainSettings() {
    closeSecuritySettingsModal();
    openSettingsModal();
}

/**
 * 보안 설정 저장
 */
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

        // 캐시 무효화 (최신 데이터 반영)
        cachedSecuritySettings = payload;

        console.log('보안 설정 저장됨:', payload);
        closeSecuritySettingsModal();
        alert('보안 설정이 저장되었습니다.');
    } catch (error) {
        console.error('보안 설정 저장 실패:', error);
        alert(`보안 설정 저장에 실패했습니다: ${error.message}`);
    }
}

/**
 * 선택된 국가 요약 업데이트 (허용 국가 관리 모달 내부)
 */
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
            <div style="color: #888; font-size: 12px; max-height: 60px; overflow-y: auto;">${countryNames.join(', ')}</div>
        `;
    }
}

/**
 * 국가 화이트리스트 관리 모달 열기
 */
export async function openCountryWhitelistModal() {
    const modal = document.querySelector('#country-whitelist-modal');
    if (!modal) return;

    try {
        // 국가 목록 및 현재 설정 로드 (캐싱 적용)
        let countriesData, settingsData;

        // 국가 목록은 정적이므로 캐시 사용
        if (!cachedCountries) {
            countriesData = await api.get('/api/auth/countries');
            cachedCountries = countriesData;
        }
        countriesData = cachedCountries;

        // 보안 설정은 변경될 수 있으므로 항상 최신 데이터 로드
        settingsData = await api.get('/api/auth/security-settings');
        cachedSecuritySettings = settingsData;

        // 전역 상태에 저장
        state.availableCountries = countriesData.countries;
        state.allowedLoginCountries = settingsData.allowedLoginCountries || [];

        // UI 렌더링
        renderCountryList(state.availableCountries, state.allowedLoginCountries);

        // 초기 선택 요약 업데이트
        updateSelectedCountriesSummary();

        toggleModal('#country-whitelist-modal', true);
    } catch (error) {
        console.error('국가 화이트리스트 모달 열기 실패:', error);
        alert('국가 목록을 불러오는데 실패했습니다.');
    }
}

/**
 * 국가 목록 렌더링
 */
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
                   value="${country.code}"
                   ${isChecked ? 'checked' : ''}
                   style="margin-right: 8px;">
            <span>${country.name} (${country.code})</span>
        `;

        // 체크박스 변경 시 요약 업데이트
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

/**
 * 국가 화이트리스트 저장
 */
async function saveCountryWhitelist() {
    const checkboxes = document.querySelectorAll('#country-list-container input[type="checkbox"]:checked');
    const selectedCountries = Array.from(checkboxes).map(cb => cb.value);

    // 전역 상태에 저장
    state.allowedLoginCountries = selectedCountries;

    // 모달 닫기
    closeCountryWhitelistModal();

    alert(`${selectedCountries.length}개 국가가 선택되었습니다. "설정 저장" 버튼을 클릭하여 저장하세요.`);
}

/**
 * 국가 화이트리스트 모달 닫기
 */
function closeCountryWhitelistModal() {
    toggleModal('#country-whitelist-modal', false);
}

/**
 * 국가 검색 필터링
 */
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
