/**
 * 패스키 관리 모듈
 */

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

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) {
        return parts.pop().split(';').shift();
    }
    return null;
}

export async function updatePasskeyStatus() {
    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch('/api/passkey/status', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            }
        });

        if (!response.ok) return;

        const data = await response.json();
        const statusEl = document.querySelector('#passkey-status');

        if (statusEl) {
            statusEl.textContent = data.enabled ? '활성화' : '비활성화';
            statusEl.style.color = data.enabled ? '#16a34a' : '#6b7280';
        }

        return data;
    } catch (error) {
        console.error('패스키 상태 확인 실패:', error);
    }
}

export async function openPasskeyManageModal() {
    const modal = document.querySelector('#passkey-manage-modal');
    if (!modal) return;

    // 패스키 목록 로드
    await loadPasskeyList();

    modal.classList.remove('hidden');
}

export function closePasskeyManageModal() {
    const modal = document.querySelector('#passkey-manage-modal');
    if (modal) modal.classList.add('hidden');
}

async function loadPasskeyList() {
    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch('/api/passkey/status', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            }
        });

        if (!response.ok) return;

        const data = await response.json();
        const listEl = document.querySelector('#passkey-list');

        if (!listEl) return;

        if (data.passkeys.length === 0) {
            listEl.innerHTML = '<p style="color: #6b7280; font-size: 13px; padding: 12px; background: #f9fafb; border-radius: 3px;">등록된 패스키가 없습니다.</p>';
            return;
        }

        listEl.innerHTML = data.passkeys.map(pk => `
            <div style="display: flex; justify-content: space-between; align-items: center; padding: 12px; background: #f9fafb; border-radius: 3px; margin-bottom: 8px;">
                <div>
                    <div style="font-weight: 500; font-size: 14px; color: #374151;">
                        <i class="fa-solid fa-key" style="margin-right: 8px; color: #2d5f5d;"></i>
                        ${pk.deviceName}
                    </div>
                    <div style="font-size: 12px; color: #6b7280; margin-top: 4px;">
                        등록: ${new Date(pk.createdAt).toLocaleDateString('ko-KR')}
                        ${pk.lastUsed ? `· 마지막 사용: ${new Date(pk.lastUsed).toLocaleDateString('ko-KR')}` : ''}
                    </div>
                </div>
                <button type="button" class="delete-passkey-btn" data-id="${pk.id}" style="padding: 6px 12px; background: #ef4444; color: white; border: none; border-radius: 3px; cursor: pointer; font-size: 12px;">
                    삭제
                </button>
            </div>
        `).join('');

        // 삭제 버튼 이벤트 바인딩
        document.querySelectorAll('.delete-passkey-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const passkeyId = btn.getAttribute('data-id');
                if (confirm('이 패스키를 삭제하시겠습니까?')) {
                    await deletePasskey(passkeyId);
                }
            });
        });
    } catch (error) {
        console.error('패스키 목록 로드 실패:', error);
    }
}

async function deletePasskey(passkeyId) {
    try {
        const csrfToken = getCookie('nteok_csrf');
        const response = await fetch(`/api/passkey/${passkeyId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            }
        });

        if (!response.ok) {
            const errorData = await response.json();
            alert(errorData.error || '패스키 삭제에 실패했습니다.');
            return;
        }

        // 목록 새로고침
        await loadPasskeyList();
        await updatePasskeyStatus();
    } catch (error) {
        console.error('패스키 삭제 실패:', error);
        alert('패스키 삭제 중 오류가 발생했습니다.');
    }
}

export function openPasskeyRegisterModal() {
    const modal = document.querySelector('#passkey-register-modal');
    const deviceNameInput = document.querySelector('#passkey-device-name');
    const errorEl = document.querySelector('#passkey-register-error');

    if (!modal) return;

    if (deviceNameInput) deviceNameInput.value = '';
    if (errorEl) errorEl.textContent = '';

    modal.classList.remove('hidden');
}

export function closePasskeyRegisterModal() {
    const modal = document.querySelector('#passkey-register-modal');
    if (modal) modal.classList.add('hidden');
}

export async function registerPasskey() {
    const deviceNameInput = document.querySelector('#passkey-device-name');
    const errorEl = document.querySelector('#passkey-register-error');

    if (!errorEl) return;

    errorEl.textContent = '';
    const deviceName = deviceNameInput ? deviceNameInput.value.trim() : '';

    try {
        // 1. 서버에서 등록 옵션 가져오기
        const csrfToken = getCookie('nteok_csrf');
        const optionsRes = await fetch('/api/passkey/register/options', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            }
        });

        if (!optionsRes.ok) {
            const errorData = await optionsRes.json();
            throw new Error(errorData.error || '등록 옵션을 가져올 수 없습니다.');
        }

        const options = await optionsRes.json();

        // 2. SimpleWebAuthn 브라우저 라이브러리로 등록 시작
        const webAuthn = await loadSimpleWebAuthn();
        const credential = await webAuthn.startRegistration(options);

        // 3. 서버에서 등록 검증
        const verifyRes = await fetch('/api/passkey/register/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            body: JSON.stringify({
                credential: credential,
                deviceName: deviceName || '알 수 없는 디바이스'
            })
        });

        if (!verifyRes.ok) {
            const errorData = await verifyRes.json();
            throw new Error(errorData.error || '등록에 실패했습니다.');
        }

        // 성공
        alert('패스키가 성공적으로 등록되었습니다.');
        closePasskeyRegisterModal();
        await loadPasskeyList();
        await updatePasskeyStatus();
    } catch (error) {
        console.error('패스키 등록 실패:', error);
        errorEl.textContent = error.message || '패스키 등록 중 오류가 발생했습니다.';
    }
}

export function bindPasskeyModals() {
    const manageBtn = document.querySelector('#passkey-manage-btn');
    if (manageBtn) {
        manageBtn.addEventListener('click', openPasskeyManageModal);
    }

    const closeManageBtn = document.querySelector('#close-passkey-manage-btn');
    if (closeManageBtn) {
        closeManageBtn.addEventListener('click', closePasskeyManageModal);
    }

    const addPasskeyBtn = document.querySelector('#add-passkey-btn');
    if (addPasskeyBtn) {
        addPasskeyBtn.addEventListener('click', openPasskeyRegisterModal);
    }

    const cancelRegisterBtn = document.querySelector('#cancel-passkey-register-btn');
    if (cancelRegisterBtn) {
        cancelRegisterBtn.addEventListener('click', closePasskeyRegisterModal);
    }

    const confirmRegisterBtn = document.querySelector('#confirm-passkey-register-btn');
    if (confirmRegisterBtn) {
        confirmRegisterBtn.addEventListener('click', registerPasskey);
    }

    // 설정 모달이 열릴 때 패스키 상태 업데이트
    const settingsBtn = document.querySelector('#settings-btn');
    if (settingsBtn) {
        settingsBtn.addEventListener('click', () => {
            updatePasskeyStatus();
        });
    }
}
