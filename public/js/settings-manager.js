/**
 * 설정 관리 모듈
 */

import { hideParentModalForChild, restoreParentModalFromChild } from './modal-parent-manager.js';

// 캐시 변수 (성능 최적화)
let cachedCountries = null;
let cachedSecuritySettings = null;

// 전역 상태
let state = {
    currentUser: null,
    userSettings: {
        defaultMode: 'read'
    },
    availableCountries: [],
    allowedLoginCountries: []
};

/**
 * 상태 초기화
 */
export function initSettingsManager(appState) {
    state = appState;
}

/**
 * 설정 모달 열기
 */
export async function openSettingsModal() {
    const modal = document.querySelector("#settings-modal");
    const usernameEl = document.querySelector("#settings-username");
    const defaultModeSelect = document.querySelector("#settings-default-mode");

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

    modal.classList.remove("hidden");
}

/**
 * 설정 모달 닫기
 */
export function closeSettingsModal() {
    const modal = document.querySelector("#settings-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
}

/**
 * 설정 저장
 */
export async function saveSettings() {
    const defaultModeSelect = document.querySelector("#settings-default-mode");

    // 로컬 설정 저장
    if (defaultModeSelect) {
        state.userSettings.defaultMode = defaultModeSelect.value;
        localStorage.setItem("userSettings", JSON.stringify(state.userSettings));
        console.log("설정 저장됨:", state.userSettings);
    }

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
export async function fetchAndDisplayCurrentUser() {
    try {
        const res = await fetch("/api/auth/me");
        if (!res.ok) {
            throw new Error("HTTP " + res.status);
        }

        const user = await res.json();
        state.currentUser = user;

        const userNameEl = document.querySelector("#user-name");
        const userAvatarEl = document.querySelector("#user-avatar");

        if (userNameEl) {
            userNameEl.textContent = user.username || "사용자";
        }

        if (userAvatarEl) {
            userAvatarEl.textContent = user.username ? user.username[0].toUpperCase() : "?";
        }
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
        const { secureFetch } = await import('./ui-utils.js');

        // 내보내기 시작 알림
        alert('백업 생성 중입니다. 데이터 양에 따라 시간이 걸릴 수 있습니다.');

        const response = await secureFetch('/api/backup/export', {
            method: 'GET'
        });

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
        const { secureFetch } = await import('./ui-utils.js');

        // FormData로 파일 전송
        const formData = new FormData();
        formData.append('backup', file);

        alert('백업 불러오기 중입니다. 데이터 양에 따라 시간이 걸릴 수 있습니다.');

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
 * 보안 설정 모달 열기
 */
export async function openSecuritySettingsModal() {
    const modal = document.querySelector("#security-settings-modal");
    if (!modal) return;

    modal.classList.remove('hidden');
    hideParentModalForChild('#settings-modal', modal);

    try {
        const { secureFetch } = await import('./ui-utils.js');

        // ?? ?? ?? (?? ??)
        let data;
        if (cachedSecuritySettings) {
            // ??? ??? ??
            data = cachedSecuritySettings;
        } else {
            // ?? ?? ??? API ??
            const response = await secureFetch('/api/auth/security-settings');
            if (!response.ok) {
                throw new Error('?? ?? ?? ??');
            }
            data = await response.json();
            cachedSecuritySettings = data;
        }

        // UI ????
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
        console.error('?? ?? ?? ??:', error);
        closeSecuritySettingsModal();
        restoreParentModalFromChild(modal);
        alert('?? ??? ????? ??????.');
    }
}

/**
 * 보안 설정 모달 닫기
 */
function closeSecuritySettingsModal() {
    const modal = document.querySelector("#security-settings-modal");
    if (modal) {
        modal.classList.add('hidden');
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
        const { secureFetch } = await import('./ui-utils.js');

        const blockDuplicateLoginToggle = document.querySelector('#block-duplicate-login-toggle');
        const countryWhitelistToggle = document.querySelector('#country-whitelist-toggle');

        const payload = {
            blockDuplicateLogin: blockDuplicateLoginToggle?.checked || false,
            countryWhitelistEnabled: countryWhitelistToggle?.checked || false,
            allowedLoginCountries: state.allowedLoginCountries || []
        };

        const response = await secureFetch('/api/auth/security-settings', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || '보안 설정 저장 실패');
        }

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
        const { secureFetch } = await import('./ui-utils.js');

        // 국가 목록 및 현재 설정 로드 (캐싱 적용)
        let countriesData, settingsData;

        // 국가 목록은 정적이므로 캐시 사용
        if (!cachedCountries) {
            const countriesRes = await secureFetch('/api/auth/countries');
            if (!countriesRes.ok) {
                throw new Error('국가 목록 로드 실패');
            }
            cachedCountries = await countriesRes.json();
        }
        countriesData = cachedCountries;

        // 보안 설정은 변경될 수 있으므로 항상 최신 데이터 로드
        const settingsRes = await secureFetch('/api/auth/security-settings');
        if (!settingsRes.ok) {
            throw new Error('보안 설정 로드 실패');
        }
        settingsData = await settingsRes.json();
        cachedSecuritySettings = settingsData;

        // 전역 상태에 저장
        state.availableCountries = countriesData.countries;
        state.allowedLoginCountries = settingsData.allowedLoginCountries || [];

        // UI 렌더링
        renderCountryList(state.availableCountries, state.allowedLoginCountries);

        // 초기 선택 요약 업데이트
        updateSelectedCountriesSummary();

        modal.classList.remove('hidden');
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
    const modal = document.querySelector('#country-whitelist-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
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
