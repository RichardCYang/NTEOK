/**
 * TOTP 2단계 인증 관리 모듈
 */

import { hideParentModalForChild, restoreParentModalFromChild } from './modal-parent-manager.js';

/**
 * CSRF 쿠키 가져오기
 */
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null;
}

/**
 * TOTP 상태 업데이트
 */
export async function updateTotpStatus() {
    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch('/api/totp/status', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            }
        });

        if (!response.ok) {
            return;
        }

        const data = await response.json();
        const statusEl = document.querySelector('#totp-status');
        const setupBtn = document.querySelector('#totp-setup-btn');

        if (statusEl) {
            statusEl.textContent = data.enabled ? '활성화' : '비활성화';
            statusEl.style.color = data.enabled ? '#16a34a' : '#6b7280';
        }

        if (setupBtn) {
            setupBtn.textContent = data.enabled ? '비활성화' : '설정';
        }
    } catch (error) {
        console.error('TOTP 상태 확인 실패:', error);
    }
}

/**
 * TOTP 설정 모달 열기
 */
export async function openTotpSetupModal() {
    const statusEl = document.querySelector('#totp-status');
    const isEnabled = statusEl && statusEl.textContent === '활성화';

    const modal = document.querySelector('#totp-setup-modal');
    const step1 = document.querySelector('#totp-setup-step1');
    const step2 = document.querySelector('#totp-setup-step2');
    const disableConfirm = document.querySelector('#totp-disable-confirm');

    if (!modal) return;

	// 보안 설정 모달(부모)을 잠깐 닫고, TOTP 모달만 단독으로 띄움
	hideParentModalForChild('#security-settings-modal', modal);

    // 모든 단계 숨기기
    if (step1) step1.style.display = 'none';
    if (step2) step2.style.display = 'none';
    if (disableConfirm) disableConfirm.style.display = 'none';

    if (isEnabled) {
        // TOTP 비활성화 화면 표시
        if (disableConfirm) {
            disableConfirm.style.display = 'block';
            const passwordInput = document.querySelector('#totp-disable-password');
            const errorEl = document.querySelector('#totp-disable-error');
            if (passwordInput) passwordInput.value = '';
            if (errorEl) errorEl.textContent = '';
        }
    } else {
        // TOTP 설정 시작
        try {
            const csrfToken = getCookie('nteok_csrf');
            const response = await fetch('/api/totp/setup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken
                }
            });

            if (!response.ok) {
                alert('TOTP 설정을 시작할 수 없습니다.');
				// 부모 모달 복구
				restoreParentModalFromChild(modal);
                return;
            }

            const data = await response.json();

            // QR 코드 표시
            const qrcodeEl = document.querySelector('#totp-qrcode');
            const secretEl = document.querySelector('#totp-secret-display');
            if (qrcodeEl) {
            	// 보안: innerHTML 대신 DOM API 사용
                qrcodeEl.textContent = "";
                const img = document.createElement("img");
                // qrCode는 일반적으로 data:image/png;base64,... 형태를 기대
                const src = String(data.qrCode || "");
                if (!src.startsWith("data:image/")) {
                    // 예상치 못한 스키마 차단
                    throw new Error("Invalid QR code image source");
                }
                img.src = src;
                img.alt = "QR Code";
                img.style.maxWidth = "200px";
                qrcodeEl.appendChild(img);
            }
            if (secretEl) {
                secretEl.textContent = data.secret;
            }

            // Step 1 표시
            if (step1) {
                step1.style.display = 'block';
                const codeInput = document.querySelector('#totp-verify-code');
                const errorEl = document.querySelector('#totp-setup-error');
                if (codeInput) codeInput.value = '';
                if (errorEl) errorEl.textContent = '';
                if (codeInput) codeInput.focus();
            }
        } catch (error) {
            console.error('TOTP 설정 실패:', error);
            alert('TOTP 설정 중 오류가 발생했습니다.');
			// 부모 모달 복구
			restoreParentModalFromChild(modal);
            return;
        }
    }

    modal.classList.remove('hidden');
}

/**
 * TOTP 설정 모달 닫기
 */
export function closeTotpSetupModal() {
    const modal = document.querySelector('#totp-setup-modal');
    if (modal) {
        modal.classList.add('hidden');
		// 부모 모달(보안 설정) 복구
		restoreParentModalFromChild(modal);
    }
}

/**
 * TOTP 활성화 검증
 */
export async function verifyTotpSetup() {
    const codeInput = document.querySelector('#totp-verify-code');
    const errorEl = document.querySelector('#totp-setup-error');

    if (!codeInput || !errorEl) return;

    const code = codeInput.value.trim();
    errorEl.textContent = '';

    if (!/^\d{6}$/.test(code)) {
        errorEl.textContent = '6자리 숫자를 입력하세요.';
        return;
    }

    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch('/api/totp/verify-setup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ token: code })
        });

        const data = await response.json();

        if (!response.ok) {
            errorEl.textContent = data.error || 'TOTP 활성화에 실패했습니다.';
            return;
        }

        // Step 2로 이동 (백업 코드 표시)
        const step1 = document.querySelector('#totp-setup-step1');
        const step2 = document.querySelector('#totp-setup-step2');
        const backupCodesEl = document.querySelector('#totp-backup-codes');

        if (step1) step1.style.display = 'none';
        if (step2) step2.style.display = 'block';

        if (backupCodesEl && data.backupCodes) {
            backupCodesEl.innerHTML = data.backupCodes
                .map(code => `<div>${code}</div>`)
                .join('');
        }

        updateTotpStatus();
    } catch (error) {
        console.error('TOTP 활성화 실패:', error);
        errorEl.textContent = 'TOTP 활성화 중 오류가 발생했습니다.';
    }
}

/**
 * 백업 코드 복사
 */
export function copyBackupCodes() {
    const backupCodesEl = document.querySelector('#totp-backup-codes');
    if (!backupCodesEl) return;

    const codes = Array.from(backupCodesEl.children)
        .map(div => div.textContent)
        .join('\n');

    navigator.clipboard.writeText(codes).then(() => {
        alert('백업 코드가 클립보드에 복사되었습니다.');
    }).catch(error => {
        console.error('복사 실패:', error);
        alert('복사에 실패했습니다.');
    });
}

/**
 * TOTP 비활성화
 */
export async function disableTotp() {
    const passwordInput = document.querySelector('#totp-disable-password');
    const errorEl = document.querySelector('#totp-disable-error');

    if (!passwordInput || !errorEl) return;

    const password = passwordInput.value.trim();
    errorEl.textContent = '';

    if (!password) {
        errorEl.textContent = '비밀번호를 입력하세요.';
        return;
    }

    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch('/api/totp/disable', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({ password })
        });

        const data = await response.json();

        if (!response.ok) {
            errorEl.textContent = data.error || 'TOTP 비활성화에 실패했습니다.';
            return;
        }

        alert('TOTP 2단계 인증이 비활성화되었습니다.');
        closeTotpSetupModal();
        updateTotpStatus();
    } catch (error) {
        console.error('TOTP 비활성화 실패:', error);
        errorEl.textContent = 'TOTP 비활성화 중 오류가 발생했습니다.';
    }
}

/**
 * TOTP 모달 이벤트 바인딩
 */
export function bindTotpModals() {
    // TOTP 설정 버튼
    const setupBtn = document.querySelector('#totp-setup-btn');
    if (setupBtn) {
        setupBtn.addEventListener('click', () => {
            openTotpSetupModal();
        });
    }

    // TOTP 모달 닫기 버튼들
    const closeBtn = document.querySelector('#close-totp-setup-btn');
    const cancelSetupBtn = document.querySelector('#cancel-totp-setup-btn');
    const cancelDisableBtn = document.querySelector('#cancel-totp-disable-btn');
    const closeSuccessBtn = document.querySelector('#close-totp-success-btn');

    if (closeBtn) {
        closeBtn.addEventListener('click', closeTotpSetupModal);
    }
    if (cancelSetupBtn) {
        cancelSetupBtn.addEventListener('click', closeTotpSetupModal);
    }
    if (cancelDisableBtn) {
        cancelDisableBtn.addEventListener('click', closeTotpSetupModal);
    }
    if (closeSuccessBtn) {
        closeSuccessBtn.addEventListener('click', closeTotpSetupModal);
    }

    // TOTP 활성화 버튼
    const verifyBtn = document.querySelector('#verify-totp-btn');
    if (verifyBtn) {
        verifyBtn.addEventListener('click', verifyTotpSetup);
    }

    // TOTP 비활성화 버튼
    const confirmDisableBtn = document.querySelector('#confirm-totp-disable-btn');
    if (confirmDisableBtn) {
        confirmDisableBtn.addEventListener('click', disableTotp);
    }

    // 백업 코드 복사 버튼
    const copyBtn = document.querySelector('#copy-backup-codes-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyBackupCodes);
    }

    // 설정 모달이 열릴 때 TOTP 상태 업데이트
    const settingsBtn = document.querySelector('#settings-btn');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {
            updateTotpStatus();
        });
    }
}
