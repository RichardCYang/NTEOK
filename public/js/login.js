let currentTempSessionId = null;
let availableMethods = [];

// SimpleWebAuthn 동적 import
let SimpleWebAuthnBrowser = null;

async function loadSimpleWebAuthn() {
    if (SimpleWebAuthnBrowser) return SimpleWebAuthnBrowser;

    try {
        SimpleWebAuthnBrowser = await import('https://cdn.jsdelivr.net/npm/@simplewebauthn/browser@10.0.0/+esm');
        return SimpleWebAuthnBrowser;
    } catch (error) {
        console.error('SimpleWebAuthn 로드 실패:', error);
        throw new Error('SimpleWebAuthn 라이브러리를 로드할 수 없습니다.');
    }
}

async function handleLogin(event) {
    event.preventDefault();

    const usernameInput = document.querySelector("#username");
    const passwordInput = document.querySelector("#password");
    const errorEl = document.querySelector("#login-error");

    if (!usernameInput || !passwordInput || !errorEl) {
        return;
    }

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    errorEl.textContent = "";

    if (!username || !password) {
        errorEl.textContent = "아이디와 비밀번호를 모두 입력해 주세요.";
        return;
    }

    try {
        // 보안: CSRF 토큰 추가 (일관성 유지)
        const options = window.csrfUtils.addCsrfHeader({
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        const res = await fetch("/api/auth/login", options);

        if (!res.ok) {
            let message = "로그인에 실패했습니다.";
            try {
                const data = await res.json();
                if (data && data.error) {
                    message = data.error;
                }
            } catch (_) {
                // ignore
            }
            errorEl.textContent = message;
            return;
        }

        const data = await res.json();

        // 2FA 검증 필요
        if (data.requires2FA && data.tempSessionId) {
            currentTempSessionId = data.tempSessionId;
            availableMethods = data.availableMethods || [];

            // 사용 가능한 2FA 방법이 1개면 바로 해당 방법으로, 2개 이상이면 선택 화면
            if (availableMethods.length === 1) {
                if (availableMethods[0] === 'passkey') {
                    await startPasskeyAuth();
                } else {
                    showTotpVerifyModal();
                }
            } else if (availableMethods.length >= 2) {
                show2FAMethodSelectModal();
            } else {
                errorEl.textContent = "2단계 인증 설정에 오류가 있습니다.";
            }
            return;
        }

        // 로그인 성공 → 메인 페이지로 이동
        if (data.ok) {
            window.location.href = "/";
        }
    } catch (error) {
        console.error("로그인 요청 오류:", error);
        errorEl.textContent = "서버와 통신 중 오류가 발생했습니다.";
    }
}

function showTotpVerifyModal() {
    const modal = document.querySelector("#totp-verify-modal");
    if (modal) {
        modal.classList.remove("hidden");
        const codeInput = document.querySelector("#totp-login-code");
        const errorEl = document.querySelector("#totp-login-error");
        if (codeInput) codeInput.value = "";
        if (errorEl) errorEl.textContent = "";
        if (codeInput) codeInput.focus();
    }
}

function closeTotpVerifyModal() {
    const modal = document.querySelector("#totp-verify-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    currentTempSessionId = null;
}

async function verifyTotpLogin() {
    const codeInput = document.querySelector("#totp-login-code");
    const errorEl = document.querySelector("#totp-login-error");

    if (!codeInput || !errorEl) return;

    const code = codeInput.value.trim();
    errorEl.textContent = "";

    if (!/^\d{6}$/.test(code)) {
        errorEl.textContent = "6자리 숫자를 입력하세요.";
        return;
    }

    if (!currentTempSessionId) {
        errorEl.textContent = "세션 정보가 없습니다. 다시 로그인하세요.";
        return;
    }

    try {
        const response = await fetch("/api/totp/verify-login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                token: code,
                tempSessionId: currentTempSessionId
            })
        });

        const data = await response.json();

        if (!response.ok) {
            errorEl.textContent = data.error || "인증에 실패했습니다.";
            return;
        }

        // 로그인 성공
        window.location.href = "/";
    } catch (error) {
        console.error("TOTP 검증 실패:", error);
        errorEl.textContent = "인증 중 오류가 발생했습니다.";
    }
}

async function useBackupCode() {
    const backupCode = prompt("백업 코드를 입력하세요:");
    if (!backupCode) return;

    const errorEl = document.querySelector("#totp-login-error");
    if (errorEl) errorEl.textContent = "";

    if (!currentTempSessionId) {
        if (errorEl) errorEl.textContent = "세션 정보가 없습니다. 다시 로그인하세요.";
        return;
    }

    try {
        const response = await fetch("/api/totp/verify-backup-code", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                backupCode: backupCode.trim(),
                tempSessionId: currentTempSessionId
            })
        });

        const data = await response.json();

        if (!response.ok) {
            alert(data.error || "백업 코드 인증에 실패했습니다.");
            return;
        }

        // 로그인 성공
        window.location.href = "/";
    } catch (error) {
        console.error("백업 코드 검증 실패:", error);
        alert("백업 코드 인증 중 오류가 발생했습니다.");
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("#login-form");
    if (form) {
        form.addEventListener("submit", handleLogin);
    }

    // TOTP 검증 모달 이벤트 바인딩
    const verifyBtn = document.querySelector("#verify-totp-login-btn");
    if (verifyBtn) {
        verifyBtn.addEventListener("click", verifyTotpLogin);
    }

    const cancelBtn = document.querySelector("#cancel-totp-login-btn");
    if (cancelBtn) {
        cancelBtn.addEventListener("click", closeTotpVerifyModal);
    }

    const backupCodeBtn = document.querySelector("#use-backup-code-btn");
    if (backupCodeBtn) {
        backupCodeBtn.addEventListener("click", useBackupCode);
    }

    // TOTP 로그인 코드 입력 시 Enter 키 처리
    const totpCodeInput = document.querySelector("#totp-login-code");
    if (totpCodeInput) {
        totpCodeInput.addEventListener("keypress", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                verifyTotpLogin();
            }
        });
    }

    // 2FA 방식 선택 모달 이벤트 바인딩
    const selectPasskeyBtn = document.querySelector("#select-passkey-btn");
    if (selectPasskeyBtn) {
        selectPasskeyBtn.addEventListener("click", async () => {
            close2FAMethodSelectModal();
            await startPasskeyAuth();
        });
    }

    const selectTotpBtn = document.querySelector("#select-totp-btn");
    if (selectTotpBtn) {
        selectTotpBtn.addEventListener("click", () => {
            close2FAMethodSelectModal();
            showTotpVerifyModal();
        });
    }

    const cancelTwoFASelectBtn = document.querySelector("#cancel-twofa-select-btn");
    if (cancelTwoFASelectBtn) {
        cancelTwoFASelectBtn.addEventListener("click", close2FAMethodSelectModal);
    }

    // 패스키 인증 모달 이벤트 바인딩
    const cancelPasskeyAuthBtn = document.querySelector("#cancel-passkey-auth-btn");
    if (cancelPasskeyAuthBtn) {
        cancelPasskeyAuthBtn.addEventListener("click", closePasskeyAuthModal);
    }

    const useTotpInsteadBtn = document.querySelector("#use-totp-instead-btn");
    if (useTotpInsteadBtn) {
        useTotpInsteadBtn.addEventListener("click", () => {
            closePasskeyAuthModal();
            showTotpVerifyModal();
        });
    }
});

// 2FA 방식 선택 모달
function show2FAMethodSelectModal() {
    const modal = document.querySelector("#twofa-method-select-modal");
    const passkeyBtn = document.querySelector("#select-passkey-btn");
    const totpBtn = document.querySelector("#select-totp-btn");

    if (!modal) return;

    // 사용 가능한 방법에 따라 버튼 표시
    if (passkeyBtn) {
        passkeyBtn.style.display = availableMethods.includes('passkey') ? 'block' : 'none';
    }
    if (totpBtn) {
        totpBtn.style.display = availableMethods.includes('totp') ? 'block' : 'none';
    }

    modal.classList.remove("hidden");
}

function close2FAMethodSelectModal() {
    const modal = document.querySelector("#twofa-method-select-modal");
    if (modal) modal.classList.add("hidden");
}

// 패스키 인증
async function startPasskeyAuth() {
    const modal = document.querySelector("#passkey-auth-modal");
    const errorEl = document.querySelector("#passkey-auth-error");

    if (modal) modal.classList.remove("hidden");
    if (errorEl) errorEl.textContent = "";

    try {
        // 1. 서버에서 인증 옵션 가져오기
        const optionsRes = await fetch("/api/passkey/authenticate/options", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ tempSessionId: currentTempSessionId })
        });

        if (!optionsRes.ok) {
            const errorData = await optionsRes.json();
            throw new Error(errorData.error || "인증 옵션을 가져올 수 없습니다.");
        }

        const options = await optionsRes.json();

        // 2. SimpleWebAuthn 브라우저 라이브러리로 인증 시작
        const webAuthn = await loadSimpleWebAuthn();
        const credential = await webAuthn.startAuthentication(options);

        // 3. 서버에서 인증 검증
        const verifyRes = await fetch("/api/passkey/authenticate/verify", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                credential: credential,
                tempSessionId: currentTempSessionId
            })
        });

        if (!verifyRes.ok) {
            const errorData = await verifyRes.json();
            throw new Error(errorData.error || "인증에 실패했습니다.");
        }

        // 로그인 성공
        window.location.href = "/";
    } catch (error) {
        console.error("패스키 인증 실패:", error);
        if (errorEl) {
            errorEl.textContent = error.message || "패스키 인증 중 오류가 발생했습니다.";
        }
    }
}

function closePasskeyAuthModal() {
    const modal = document.querySelector("#passkey-auth-modal");
    if (modal) modal.classList.add("hidden");
}