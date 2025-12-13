/**
 * 설정 관리 모듈
 */

// 전역 상태
let state = {
    currentUser: null,
    userSettings: {
        defaultMode: 'read'
    }
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
export function openSettingsModal() {
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
export function saveSettings() {
    const defaultModeSelect = document.querySelector("#settings-default-mode");

    if (defaultModeSelect) {
        state.userSettings.defaultMode = defaultModeSelect.value;
        // localStorage에 설정 저장
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
