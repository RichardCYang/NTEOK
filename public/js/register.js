import { secureFetch } from './ui-utils.js';

async function handleRegister(event) {
    event.preventDefault();

    const usernameInput = document.querySelector("#username");
    const passwordInput = document.querySelector("#password");
    const passwordConfirmInput = document.querySelector("#passwordConfirm");
    const errorEl = document.querySelector("#register-error");

    if (!usernameInput || !passwordInput || !passwordConfirmInput || !errorEl)
        return;

    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const passwordConfirm = passwordConfirmInput.value;

    errorEl.textContent = "";

    if (!username || !password || !passwordConfirm) {
        errorEl.textContent = "아이디와 비밀번호를 모두 입력해 주세요.";
        return;
    }

    if (password !== passwordConfirm) {
        errorEl.textContent = "비밀번호와 비밀번호 확인이 일치하지 않습니다.";
        return;
    }

    if (username.length < 3 || username.length > 64) {
        errorEl.textContent = "아이디는 3~64자 사이로 입력해 주세요.";
        return;
    }

    if (password.length < 10) {
        errorEl.textContent = "비밀번호는 10자 이상이어야 합니다.";
        return;
    }

    const BCRYPT_MAX_PASSWORD_BYTES = 72;
    const passwordBytes = new TextEncoder().encode(password).length;
    if (passwordBytes > BCRYPT_MAX_PASSWORD_BYTES) {
        errorEl.textContent = `비밀번호가 너무 깁니다. (UTF-8 기준 최대 ${BCRYPT_MAX_PASSWORD_BYTES}바이트)`;
        return;
    }

    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    const strength = [hasUpperCase, hasLowerCase, hasNumbers, hasSpecialChar]
        .filter(Boolean).length;

    if (strength < 3) {
        errorEl.textContent = "비밀번호는 대문자, 소문자, 숫자, 특수문자 중 3가지 이상을 포함해야 합니다.";
        return;
    }

    try {
        const options = window.csrfUtils.addCsrfHeader({
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ username, password })
        });

        const res = await secureFetch("/api/auth/register", options);

        if (!res.ok) {
            let message = "회원가입에 실패했습니다.";
            try {
                const data = await res.json();
                if (data && data.error) {
                    message = data.error;
                }
            } catch (_) {
            }
            errorEl.textContent = message;
            return;
        }

        window.location.href = "/";
    } catch (error) {
        console.error("회원가입 요청 오류:", error);
        errorEl.textContent = "서버와 통신 중 오류가 발생했습니다.";
    }
}

document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("#register-form");
    if (form) {
        form.addEventListener("submit", handleRegister);
    }
});