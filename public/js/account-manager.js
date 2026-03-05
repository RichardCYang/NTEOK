import { secureFetch } from './ui-utils.js';

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null;
}

export function openDeleteAccountModal() {
    const modal = document.querySelector('#delete-account-modal');
    const passwordInput = document.querySelector('#delete-account-password');
    const confirmTextInput = document.querySelector('#delete-account-confirm-text');
    const errorEl = document.querySelector('#delete-account-error');

    if (!modal) return;

    if (passwordInput) passwordInput.value = '';
    if (confirmTextInput) confirmTextInput.value = '';
    if (errorEl) errorEl.textContent = '';

    modal.classList.remove('hidden');

    if (passwordInput) {
        passwordInput.focus();
    }
}

export function closeDeleteAccountModal() {
    const modal = document.querySelector('#delete-account-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

export async function confirmDeleteAccount() {
    const passwordInput = document.querySelector('#delete-account-password');
    const confirmTextInput = document.querySelector('#delete-account-confirm-text');
    const errorEl = document.querySelector('#delete-account-error');

    if (!passwordInput || !confirmTextInput || !errorEl) return;

    const password = passwordInput.value.trim();
    const confirmText = confirmTextInput.value.trim();

    errorEl.textContent = '';

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

    const finalConfirm = confirm(
        '정말로 계정을 삭제하시겠습니까?\n\n이 작업은 되돌릴 수 없으며 모든 데이터가 영구적으로 삭제됩니다.\n(참고: 협업 중인 다른 사용자의 데이터는 해당 사용자의 계정으로 안전하게 분리 보관됩니다.)'
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

        alert('계정이 삭제되었습니다.');
        window.location.href = '/login.html';
    } catch (error) {
        console.error('계정 삭제 실패:', error);
        errorEl.textContent = '계정 삭제 중 오류가 발생했습니다.';
    }
}

export function bindAccountManagementButtons() {
    const deleteBtn = document.querySelector('#delete-account-btn');
    if (deleteBtn) {
        deleteBtn.addEventListener('click', openDeleteAccountModal);
    }

    const closeBtn = document.querySelector('#close-delete-account-btn');
    const cancelBtn = document.querySelector('#cancel-delete-account-btn');

    if (closeBtn) {
        closeBtn.addEventListener('click', closeDeleteAccountModal);
    }
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeDeleteAccountModal);
    }

    const confirmBtn = document.querySelector('#confirm-delete-account-btn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', confirmDeleteAccount);
    }
}
