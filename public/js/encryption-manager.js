
import { secureFetch } from './ui-utils.js';
import { loadPage, renderPageList, fetchPageList } from './pages-manager.js';
import { sanitizeEditorHtml } from './sanitize.js';
import { stopPageSync, flushPendingUpdates } from './sync-manager.js';

let state = {
    currentEncryptingPageId: null,
    currentDecryptingPage: null,
    editor: null,
    currentPageId: null,
    fetchPageList: null
};

export function initEncryptionManager(appState) {
    state = appState;
}

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

export function closeEncryptionModal() {
    const modal = document.querySelector("#page-encryption-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    state.currentEncryptingPageId = null;
}

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

    const wasActivePage = state.currentPageId === state.currentEncryptingPageId;

    let localTitle = null;
    let localContent = null;
    if (wasActivePage) {
        try { flushPendingUpdates(); } catch (_) {}

        try {
            const titleInput = document.querySelector("#page-title-input");
            localTitle = titleInput ? titleInput.value : null;
        } catch (_) {}

        try {
            if (state.editor && typeof state.editor.getHTML === "function") {
                localContent = state.editor.getHTML();
            }
        } catch (_) {}

        try { stopPageSync(); } catch (_) {}

        state.currentPageId = state.currentEncryptingPageId;
    }

    try {
        let page = null;
        let plainTitle = localTitle;
        let plainContent = localContent;

        if (plainTitle == null || plainContent == null) {
            const res = await secureFetch(`/api/pages/${encodeURIComponent(state.currentEncryptingPageId)}`);
            if (!res.ok) throw new Error("HTTP " + res.status);
            page = await res.json();

            if (plainTitle == null) plainTitle = page.title;
            if (plainContent == null) plainContent = page.content;
        }

        const saltBase64 = await cryptoManager.initializeKey(password);

        const safePlainContent = sanitizeEditorHtml(plainContent || "<p></p>");
        const encryptedData = await cryptoManager.encrypt(safePlainContent);

        const updateRes = await secureFetch(`/api/pages/${encodeURIComponent(state.currentEncryptingPageId)}`, {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                ...(plainTitle != null ? { title: plainTitle } : {}),
                content: "",
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

        if (wasActivePage) {
            state.currentPageIsEncrypted = true;
        }

        await fetchPageList();
        renderPageList();

        if (wasActivePage) {
            const titleInput = document.querySelector("#page-title-input");
            if (titleInput) {
                titleInput.value = (plainTitle != null ? plainTitle : (page ? page.title : ''));
            }
            if (state.editor) {
                state.editor.commands.setContent(safePlainContent, { emitUpdate: false });
            }

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

export function closeDecryptionModal() {
    const modal = document.querySelector("#page-decryption-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    state.currentDecryptingPage = null;
}

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

        stopPageSync();

        const res = await secureFetch(`/api/pages/${encodeURIComponent(page.id)}`);
        if (!res.ok) {
            throw new Error("페이지를 불러올 수 없습니다.");
        }

        const pageData = await res.json();

        if (!pageData.encryptionSalt || !pageData.encryptedContent) {
            throw new Error("암호화 데이터가 없습니다.");
        }

        await cryptoManager.initializeKey(password, pageData.encryptionSalt);
        state.decryptionKeyIsInMemory = true; 

		const decryptedContentRaw = await cryptoManager.decrypt(pageData.encryptedContent);

		const decryptedContent = sanitizeEditorHtml(decryptedContentRaw);

		closeDecryptionModal();

        state.currentPageId = page.id;
        state.currentPageIsEncrypted = true; 

        const titleInput = document.querySelector("#page-title-input");
        const modeToggleBtn = document.querySelector("#mode-toggle-btn");
        const toolbar = document.querySelector(".editor-toolbar");

        if (titleInput) {
            titleInput.value = pageData.title;
            titleInput.setAttribute("readonly", ""); 
        }

        if (state.editor) {
            state.editor.commands.setContent(decryptedContent, { emitUpdate: false });
            state.editor.setEditable(false);
        }

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

        renderPageList();

    } catch (error) {
        console.error("임시 복호화 오류:", error);
        errorEl.textContent = "비밀번호가 올바르지 않거나 복호화에 실패했습니다.";
        cryptoManager.clearKey(); 
        state.decryptionKeyIsInMemory = false; 
    }
}

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
