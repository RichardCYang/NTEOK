let currentTempSessionId = null;

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
            showTotpVerifyModal();
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
});