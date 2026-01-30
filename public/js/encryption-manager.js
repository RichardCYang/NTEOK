/**
 * 페이지 암호화/복호화 관리 모듈
 */

import { secureFetch } from './ui-utils.js';
import { loadPage, renderPageList, fetchPageList } from './pages-manager.js';
import { sanitizeEditorHtml } from './sanitize.js';
import { stopPageSync } from './sync-manager.js';

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
        const saltBase64 = await cryptoManager.initializeKey(password);

        // 3. 콘텐츠 암호화
        const encryptedData = await cryptoManager.encrypt(page.content);

        // 4. 암호화된 콘텐츠 저장
        const updateRes = await secureFetch(`/api/pages/${encodeURIComponent(state.currentEncryptingPageId)}`, {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                title: page.title,
                content: '',
                encryptionSalt: saltBase64,
                encryptedContent: encryptedData,
                isEncrypted: true
            })
        });

        if (!updateRes.ok) {
            throw new Error("HTTP " + updateRes.status);
        }

        alert("페이지가 성공적으로 암호화되었습니다!");
        closeEncryptionModal();

        // 암호화 완료 - 쓰기 모드 차단
        if (state.currentPageId === state.currentEncryptingPageId) {
            state.currentPageIsEncrypted = true;
        }

        await fetchPageList();
        renderPageList();

        if (state.currentPageId === state.currentEncryptingPageId) {
            const titleInput = document.querySelector("#page-title-input");
            if (titleInput) {
                titleInput.value = page.title;
            }
            if (state.editor) {
                state.editor.commands.setContent(page.content, { emitUpdate: false });
            }

            // 암호화 후 쓰기 모드 비활성화
            if (state.isWriteMode) {
                const modeToggleBtn = document.querySelector("#mode-toggle-btn");
                const toolbar = document.querySelector(".editor-toolbar");
                const iconEl = modeToggleBtn ? modeToggleBtn.querySelector("i") : null;
                const textEl = modeToggleBtn ? modeToggleBtn.querySelector("span") : null;

                state.isWriteMode = false;
                if (state.editor) {
                    state.editor.setEditable(false);
                }
                if (titleInput) {
                    titleInput.setAttribute("readonly", "");
                }
                if (toolbar) {
                    toolbar.classList.remove("visible");
                }
                if (modeToggleBtn) {
                    modeToggleBtn.classList.remove("write-mode");
                }
                if (iconEl) {
                    iconEl.className = "fa-solid fa-pencil";
                }
                if (textEl) {
                    textEl.textContent = "쓰기모드";
                }
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
 * 페이지 임시 복호화 처리 (메모리에서만 복호화, DB는 암호화 상태 유지)
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
        const page = state.currentDecryptingPage;

        // 이전 페이지의 실시간 동기화 중지 (중요!)
        stopPageSync();

        // 페이지 데이터 가져오기 (encryptionSalt, encryptedContent)
        const res = await fetch(`/api/pages/${encodeURIComponent(page.id)}`);
        if (!res.ok) {
            throw new Error("페이지를 불러올 수 없습니다.");
        }

        const pageData = await res.json();

        if (!pageData.encryptionSalt || !pageData.encryptedContent) {
            throw new Error("암호화 데이터가 없습니다.");
        }

        // 비밀번호로 키 생성 (기존 salt 사용)
        await cryptoManager.initializeKey(password, pageData.encryptionSalt);
        state.decryptionKeyIsInMemory = true; // 키가 메모리에 있음을 표시

        // 콘텐츠 복호화 (메모리에서만)
		const decryptedContentRaw = await cryptoManager.decrypt(pageData.encryptedContent);

		// 보안: 암호화 콘텐츠는 서버에서 정화할 수 없으므로, 클라이언트에서 반드시 정화
		const decryptedContent = sanitizeEditorHtml(decryptedContentRaw);

		closeDecryptionModal();

        // 에디터에 복호화된 콘텐츠를 표시하고 읽기 모드로 유지
        state.currentPageId = page.id;
        state.currentPageIsEncrypted = true; // 저장 시 재암호화를 위해 상태 유지

        const titleInput = document.querySelector("#page-title-input");
        const modeToggleBtn = document.querySelector("#mode-toggle-btn");
        const toolbar = document.querySelector(".editor-toolbar");

        if (titleInput) {
            titleInput.value = pageData.title;
            titleInput.setAttribute("readonly", ""); // 읽기 모드이므로 제목도 읽기 전용
        }

        if (state.editor) {
            state.editor.commands.setContent(decryptedContent, { emitUpdate: false });
            // 복호화 직후에는 읽기 모드를 유지해야 하므로 편집 불가능 상태로 설정
            state.editor.setEditable(false);
        }

        // UI는 읽기 모드로 유지
        state.isWriteMode = false;
        if (toolbar) {
            toolbar.classList.remove("visible");
        }
        if (modeToggleBtn) {
            modeToggleBtn.classList.remove("write-mode");
            const iconEl = modeToggleBtn.querySelector("i");
            const textEl = modeToggleBtn.querySelector("span");
            if (iconEl) iconEl.className = "fa-solid fa-pencil";
            if (textEl) textEl.textContent = "쓰기모드";
        }

        // 페이지 목록 갱신 (선택 표시)
        renderPageList();

        // cryptoManager.clearKey(); // 저장 시 재암호화를 위해 키를 유지
    } catch (error) {
        console.error("임시 복호화 오류:", error);
        errorEl.textContent = "비밀번호가 올바르지 않거나 복호화에 실패했습니다.";
        cryptoManager.clearKey(); // 오류 발생 시 키 삭제
        state.decryptionKeyIsInMemory = false; // 오류 발생 시 플래그 초기화
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
