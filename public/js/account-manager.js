/**
 * 계정 관리 모듈
 */
import { secureFetch } from './ui-utils.js';

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
 * 계정 삭제 모달 열기
 */
export function openDeleteAccountModal() {
    const modal = document.querySelector('#delete-account-modal');
    const passwordInput = document.querySelector('#delete-account-password');
    const confirmTextInput = document.querySelector('#delete-account-confirm-text');
    const errorEl = document.querySelector('#delete-account-error');

    if (!modal) return;

    // 입력 필드 초기화
    if (passwordInput) passwordInput.value = '';
    if (confirmTextInput) confirmTextInput.value = '';
    if (errorEl) errorEl.textContent = '';

    modal.classList.remove('hidden');

    // 비밀번호 입력에 포커스
    if (passwordInput) {
        passwordInput.focus();
    }
}

/**
 * 계정 삭제 모달 닫기
 */
export function closeDeleteAccountModal() {
    const modal = document.querySelector('#delete-account-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

/**
 * 계정 삭제 확인 및 실행
 */
export async function confirmDeleteAccount() {
    const passwordInput = document.querySelector('#delete-account-password');
    const confirmTextInput = document.querySelector('#delete-account-confirm-text');
    const errorEl = document.querySelector('#delete-account-error');

    if (!passwordInput || !confirmTextInput || !errorEl) return;

    const password = passwordInput.value.trim();
    const confirmText = confirmTextInput.value.trim();

    errorEl.textContent = '';

    // 유효성 검증
    if (!password) {
        errorEl.textContent = '비밀번호를 입력하세요.';
        passwordInput.focus();
        return;
    }

    if (confirmText !== '계정 삭제') {
        errorEl.textContent = '"계정 삭제"를 정확히 입력하세요.';
        confirmTextInput.focus();
        return;
    }

    // 최종 확인
    const finalConfirm = confirm(
        '정말로 계정을 삭제하시겠습니까?\n\n이 작업은 되돌릴 수 없으며 모든 데이터가 영구적으로 삭제됩니다.'
    );

    if (!finalConfirm) {
        return;
    }

    try {
        const response = await secureFetch('/api/auth/account', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ password, confirmText })
        });

        const data = await response.json();

        if (!response.ok) {
            errorEl.textContent = data.error || '계정 삭제에 실패했습니다.';
            return;
        }

        // 성공 시 로그인 페이지로 리디렉션
        alert('계정이 삭제되었습니다.');
        window.location.href = '/login.html';
    } catch (error) {
        console.error('계정 삭제 실패:', error);
        errorEl.textContent = '계정 삭제 중 오류가 발생했습니다.';
    }
}

/**
 * 계정 관리 버튼 이벤트 바인딩
 */
export function bindAccountManagementButtons() {
    // 계정 삭제 버튼
    const deleteBtn = document.querySelector('#delete-account-btn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', openDeleteAccountModal);
    }

    // 모달 닫기 버튼들
    const closeBtn = document.querySelector('#close-delete-account-btn');
    const cancelBtn = document.querySelector('#cancel-delete-account-btn');

    if (closeBtn) {
        closeBtn.addEventListener('click', closeDeleteAccountModal);
    }
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeDeleteAccountModal);
    }

    // 계정 삭제 확인 버튼
    const confirmBtn = document.querySelector('#confirm-delete-account-btn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', confirmDeleteAccount);
    }
}
