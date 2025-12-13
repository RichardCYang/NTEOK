/**
 * 페이지 암호화/복호화 관리 모듈
 */

import { secureFetch } from './ui-utils.js';

// 전역 상태
let state = {
    currentEncryptingPageId: null,
    currentDecryptingPage: null,
    editor: null,
    currentPageId: null,
    fetchPageList: null
};

/**
 * 상태 초기화
 */
export function initEncryptionManager(appState) {
    state = appState;
}

/**
 * 암호화 모달 표시
 */
export function showEncryptionModal(pageId) {
    state.currentEncryptingPageId = pageId;
    const modal = document.querySelector("#page-encryption-modal");
    if (modal) {
        modal.classList.remove("hidden");
        const passwordInput = document.querySelector("#encryption-password");
        const confirmInput = document.querySelector("#encryption-password-confirm");
        const errorEl = document.querySelector("#encryption-error");
        if (passwordInput) passwordInput.value = "";
        if (confirmInput) confirmInput.value = "";
        if (errorEl) errorEl.textContent = "";
        if (passwordInput) passwordInput.focus();
    }
}

/**
 * 암호화 모달 닫기
 */
export function closeEncryptionModal() {
    const modal = document.querySelector("#page-encryption-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    state.currentEncryptingPageId = null;
}

/**
 * 페이지 암호화 처리
 */
export async function handleEncryption(event) {
    event.preventDefault();

    const passwordInput = document.querySelector("#encryption-password");
    const confirmInput = document.querySelector("#encryption-password-confirm");
    const errorEl = document.querySelector("#encryption-error");

    if (!passwordInput || !confirmInput || !errorEl) {
        console.error("암호화 폼 요소를 찾을 수 없습니다.");
        return;
    }

    const password = passwordInput.value.trim();
    const confirm = confirmInput.value.trim();
    errorEl.textContent = "";

    if (!password || !confirm) {
        errorEl.textContent = "비밀번호를 입력해 주세요.";
        return;
    }

    if (password !== confirm) {
        errorEl.textContent = "비밀번호가 일치하지 않습니다.";
        alert("비밀번호가 일치하지 않습니다. 다시 확인해 주세요.");
        return;
    }

    if (password.length < 4) {
        errorEl.textContent = "비밀번호는 최소 4자 이상이어야 합니다.";
        return;
    }

    if (!state.currentEncryptingPageId) {
        errorEl.textContent = "페이지 ID를 찾을 수 없습니다.";
        return;
    }

    try {
        // 1. 현재 페이지 가져오기
        const res = await fetch(`/api/pages/${encodeURIComponent(state.currentEncryptingPageId)}`);
        if (!res.ok) {
            throw new Error("HTTP " + res.status);
        }

        const page = await res.json();

        // 2. 암호화 키 초기화 (새 salt 생성)
        await cryptoManager.initializeKey(password);

        // 3. 콘텐츠 암호화 (salt 포함)
        const encryptedContent = await cryptoManager.encrypt(page.content);

        // 4. 암호화된 콘텐츠 저장
        const updateRes = await secureFetch(`/api/pages/${encodeURIComponent(state.currentEncryptingPageId)}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                title: page.title,
                content: encryptedContent,
                isEncrypted: true
            })
        });

        if (!updateRes.ok) {
            throw new Error("HTTP " + updateRes.status);
        }

        alert("페이지가 성공적으로 암호화되었습니다!");
        closeEncryptionModal();

        if (state.fetchPageList) {
            await state.fetchPageList();
        }

        if (state.currentPageId === state.currentEncryptingPageId) {
            const titleInput = document.querySelector("#page-title-input");
            if (titleInput) {
                titleInput.value = page.title;
            }
            if (state.editor) {
                state.editor.commands.setContent(page.content, { emitUpdate: false });
            }
        }

        cryptoManager.clearKey();
    } catch (error) {
        console.error("암호화 오류:", error);

        if (error.message && error.message.includes("403")) {
            window.showEncryptPermissionModal();
        } else {
            errorEl.textContent = "암호화 중 오류가 발생했습니다: " + error.message;
        }
    }
}

/**
 * 복호화 모달 표시
 */
export function showDecryptionModal(page) {
    state.currentDecryptingPage = page;
    const modal = document.querySelector("#page-decryption-modal");
    if (modal) {
        modal.classList.remove("hidden");
        const passwordInput = document.querySelector("#decryption-password");
        const errorEl = document.querySelector("#decryption-error");
        if (passwordInput) passwordInput.value = "";
        if (errorEl) errorEl.textContent = "";
        if (passwordInput) passwordInput.focus();
    }
}

/**
 * 복호화 모달 닫기
 */
export function closeDecryptionModal() {
    const modal = document.querySelector("#page-decryption-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    state.currentDecryptingPage = null;
}

/**
 * 페이지 복호화 처리
 */
export async function handleDecryption(event) {
    event.preventDefault();

    const passwordInput = document.querySelector("#decryption-password");
    const errorEl = document.querySelector("#decryption-error");

    if (!passwordInput || !errorEl) {
        return;
    }

    const password = passwordInput.value.trim();
    errorEl.textContent = "";

    if (!password) {
        errorEl.textContent = "비밀번호를 입력해 주세요.";
        return;
    }

    if (!state.currentDecryptingPage) {
        errorEl.textContent = "페이지 정보를 찾을 수 없습니다.";
        return;
    }

    try {
        if (window.decryptAndLoadPage) {
            await window.decryptAndLoadPage(state.currentDecryptingPage, password);
        }
        closeDecryptionModal();
    } catch (error) {
        console.error("복호화 처리 오류:", error);
        errorEl.textContent = "비밀번호가 올바르지 않거나 복호화에 실패했습니다.";
        cryptoManager.clearKey();
    }
}

/**
 * 암호화 모달 이벤트 바인딩
 */
export function bindEncryptionModal() {
    const form = document.querySelector("#encryption-form");
    const closeBtn = document.querySelector("#close-encryption-modal-btn");
    const cancelBtn = document.querySelector("#cancel-encryption-btn");

    if (form) {
        form.addEventListener("submit", handleEncryption);
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", closeEncryptionModal);
    }

    if (cancelBtn) {
        cancelBtn.addEventListener("click", closeEncryptionModal);
    }
}

/**
 * 복호화 모달 이벤트 바인딩
 */
export function bindDecryptionModal() {
    const form = document.querySelector("#decryption-form");
    const closeBtn = document.querySelector("#close-decryption-modal-btn");
    const cancelBtn = document.querySelector("#cancel-decryption-btn");

    if (form) {
        form.addEventListener("submit", handleDecryption);
    }

    if (closeBtn) {
        closeBtn.addEventListener("click", closeDecryptionModal);
    }

    if (cancelBtn) {
        cancelBtn.addEventListener("click", closeDecryptionModal);
    }
}
