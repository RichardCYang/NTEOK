/**
 * 저장소 관리자
 */
import * as api from './api-utils.js';
import { showLoadingOverlay, hideLoadingOverlay, escapeHtml, escapeHtmlAttr } from './ui-utils.js';

export function initStoragesManager(appState, onStorageSelected) {
    const storageScreen = document.getElementById('storage-selection-screen');
    const storageList = document.getElementById('storage-list');
    const addStorageBtn = document.getElementById('add-storage-btn');
    const logoutBtn = document.getElementById('storage-logout-btn');
    const appEl = document.querySelector('.app');

    // 저장소 목록 렌더링
    function renderStorages(storages) {
        storageList.innerHTML = '';
        
        if (storages.length === 0) {
            storageList.innerHTML = `
                <div style="grid-column: 1 / -1; padding: 100px 40px; text-align: center; color: var(--sub-font-color); font-size: 16px; background: var(--primary-color); border-radius: 16px; border: 2px dashed var(--border-color);">
                    <i class="fa-solid fa-folder-open" style="font-size: 48px; margin-bottom: 20px; display: block; opacity: 0.3;"></i>
                    생성된 저장소가 없습니다. 상단의 버튼을 눌러 첫 번째 저장소를 만들어보세요!
                </div>
            `;
            return;
        }

        storages.forEach(storage => {
            const item = document.createElement('div');
            item.className = 'storage-item';
            
            const date = new Date(storage.createdAt || storage.created_at).toLocaleDateString();
            const isOwner = storage.is_owner === 1 || storage.is_owner === true;
            const isAdmin = isOwner || storage.permission === 'ADMIN';
            const isEncrypted = !!(Number(storage.is_encrypted) === 1 || storage.isEncrypted);
            
            // 보안: innerHTML 템플릿에 들어가는 값은 반드시 이스케이프 처리
            const safeStorageId = escapeHtmlAttr(storage.id);
            const safeStorageName = escapeHtml(storage.name || '');
            const safeOwnerName = escapeHtml(storage.owner_name || '');

            item.innerHTML = `
                <div class="storage-item-actions">
                    ${isOwner ? `
                        <button class="storage-action-btn rename-btn" title="이름 변경" data-id="${safeStorageId}">
                            <i class="fa-solid fa-pen"></i>
                        </button>
                    ` : ''}
                    ${isAdmin ? `
                        <button class="storage-action-btn collab-btn" title="참여자 관리" data-id="${safeStorageId}">
                            <i class="fa-solid fa-user-group"></i>
                        </button>
                    ` : ''}
                    ${isOwner ? `
                        <button class="storage-action-btn delete-btn delete" title="저장소 삭제" data-id="${safeStorageId}">
                            <i class="fa-regular fa-trash-can"></i>
                        </button>
                    ` : `
                        <button class="storage-action-btn delete-btn delete" title="공유 해제" data-id="${safeStorageId}">
                            <i class="fa-solid fa-right-from-bracket"></i>
                        </button>
                    `}
                </div>
                <div class="storage-icon-wrapper ${isEncrypted ? 'encrypted' : ''}">
                    <i class="fa-solid ${isEncrypted ? 'fa-lock' : 'fa-database'}"></i>
                </div>
                <div class="storage-item-info">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
                        <span class="storage-item-name">${safeStorageName}</span>
                        ${isEncrypted ? `<span class="storage-item-encrypted-badge"><i class="fa-solid fa-shield-halved"></i> E2EE</span>` : ''}
                        ${!isOwner ? `<span class="storage-item-shared-badge">공유됨</span>` : ''}
                    </div>
                    <span class="storage-item-meta">${date}${!isOwner ? ` (${safeOwnerName})` : ''}</span>
                </div>
            `;
            
            item.addEventListener('click', (e) => {
                // 삭제/참여자/이름변경 버튼 클릭 시 이벤트 전파 방지
                if (e.target.closest('.storage-action-btn')) return;
                selectStorage(storage.id);
            });

            const renameBtn = item.querySelector('.rename-btn');
            if (renameBtn) {
                renameBtn.addEventListener('click', async (e) => {
                    e.stopPropagation();
                    const newName = prompt('저장소의 새 이름을 입력하세요:', storage.name);
                    if (!newName || !newName.trim() || newName === storage.name) return;

                    showLoadingOverlay();
                    try {
                        await api.put(`/api/storages/${storage.id}`, { name: newName.trim() });
                        storage.name = newName.trim();
                        renderStorages(appState.storages);
                    } catch (error) {
                        console.error('저장소 이름 변경 실패:', error);
                        alert(error.message || '저장소 이름 변경에 실패했습니다.');
                    } finally {
                        hideLoadingOverlay();
                    }
                });
            }

            const collabBtn = item.querySelector('.collab-btn');
            if (collabBtn) {
                collabBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    showCollaboratorsModal(storage);
                });
            }

            const deleteBtn = item.querySelector('.delete-btn');
            deleteBtn.addEventListener('click', async (e) => {
                e.stopPropagation();
                
                const ownedStorages = appState.storages.filter(s => s.is_owner);
                if (isOwner && ownedStorages.length <= 1) {
                    alert('최소 하나의 소유한 저장소는 유지해야 합니다.');
                    return;
                }

                const confirmMsg = isOwner 
                    ? `'${storage.name}' 저장소를 삭제하시겠습니까?\n포함된 모든 컬렉션과 페이지가 영구적으로 삭제됩니다.`
                    : `'${storage.name}' 저장소의 공유를 해제하시겠습니까?`;

                if (!confirm(confirmMsg)) {
                    return;
                }

                showLoadingOverlay();
                try {
                    await api.del(`/api/storages/${storage.id}`);
                    appState.storages = appState.storages.filter(s => s.id !== storage.id);
                    renderStorages(appState.storages);
                } catch (error) {
                    console.error('저장소 작업 실패:', error);
                    alert(error.message || '저장소 작업에 실패했습니다.');
                } finally {
                    hideLoadingOverlay();
                }
            });

            storageList.appendChild(item);
        });
    }

    // 참여자 관리 모달
    const collabModal = document.getElementById('storage-collaborators-modal');
    const closeCollabBtn = document.getElementById('close-storage-collaborators-btn');
    const searchInput = document.getElementById('collaborator-search-input');
    const searchResults = document.getElementById('collaborator-search-results');
    const collabList = document.getElementById('storage-collaborator-list');
    const addCollabBtn = document.getElementById('add-collaborator-btn');
    const permissionSelect = document.getElementById('collaborator-permission');

    let currentManagingStorage = null;
    let selectedUser = null;
    let searchTimeout = null;

    function showCollaboratorsModal(storage) {
        currentManagingStorage = storage;
        selectedUser = null;
        searchInput.value = '';
        searchResults.classList.add('hidden');
        collabModal.classList.remove('hidden');
        loadCollaborators();
    }

    async function loadCollaborators() {
        collabList.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--sub-font-color);">불러오는 중...</div>';
        try {
            const collaborators = await api.get(`/api/storages/${currentManagingStorage.id}/collaborators`);
            renderCollaborators(collaborators);
        } catch (error) {
            console.error('참여자 로드 실패:', error);
            if (error.status === 403) {
                collabList.innerHTML = '<div style="text-align: center; padding: 20px; color: #ef4444;">참여자 목록을 조회할 권한이 없습니다.</div>';
            } else {
                collabList.innerHTML = '<div style="text-align: center; padding: 20px; color: #ef4444;">로드 실패</div>';
            }
        }
    }

    function renderCollaborators(collaborators) {
        collabList.innerHTML = '';
        if (collaborators.length === 0) {
            collabList.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--sub-font-color); font-size: 13px;">추가된 참여자가 없습니다.</div>';
            return;
        }

        collaborators.forEach(collab => {
            const item = document.createElement('div');
            item.className = 'collaborator-item';
            
            // 보안: 사용자명/권한 문자열은 신뢰할 수 없으므로 HTML 이스케이프
            const safeCollabName = escapeHtml(collab.username || '');
            const safeCollabId = escapeHtmlAttr(collab.id);

            item.innerHTML = `
                <div class="collaborator-info">
                    <span class="collaborator-name">${safeCollabName}</span>
                </div>
                <div class="collaborator-actions">
                    <select class="collaborator-permission-select" data-user-id="${safeCollabId}">
                        <option value="READ" ${collab.permission === 'READ' ? 'selected' : ''}>읽기</option>
                        <option value="EDIT" ${collab.permission === 'EDIT' ? 'selected' : ''}>편집</option>
                        <option value="ADMIN" ${collab.permission === 'ADMIN' ? 'selected' : ''}>관리</option>
                    </select>
                    <button class="collaborator-remove-btn" title="삭제">
                        <i class="fa-solid fa-user-minus"></i>
                    </button>
                </div>
            `;

            const permissionSelect = item.querySelector('.collaborator-permission-select');
            permissionSelect.addEventListener('change', async () => {
                const newPermission = permissionSelect.value;
                try {
                    await api.post(`/api/storages/${currentManagingStorage.id}/collaborators`, {
                        targetUserId: collab.id,
                        permission: newPermission
                    });
                } catch (error) {
                    alert('권한 수정 실패: ' + error.message);
                    // 실패 시 원래 값으로 복구하기 위해 목록 재요청
                    loadCollaborators();
                }
            });

            item.querySelector('.collaborator-remove-btn').addEventListener('click', async () => {
                if (!confirm(`'${collab.username}' 님을 저장소에서 제외하시겠습니까?`)) return;
                
                try {
                    await api.del(`/api/storages/${currentManagingStorage.id}/collaborators/${collab.id}`);
                    loadCollaborators();
                } catch (error) {
                    alert('참여자 삭제 실패: ' + error.message);
                }
            });

            collabList.appendChild(item);
        });
    }

    searchInput.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        const query = searchInput.value.trim();
        if (query.length < 2) {
            searchResults.classList.add('hidden');
            return;
        }

        searchTimeout = setTimeout(async () => {
            try {
                const users = await api.get(`/api/storages/users/search?q=${encodeURIComponent(query)}`);
                renderSearchResults(users);
            } catch (error) {
                console.error('사용자 검색 실패:', error);
            }
        }, 300);
    });

    function renderSearchResults(users) {
        searchResults.innerHTML = '';
        if (users.length === 0) {
            searchResults.innerHTML = '<div class="search-result-item" style="color: #6b7280; cursor: default;">검색 결과 없음</div>';
        } else {
            users.forEach(user => {
                const item = document.createElement('div');
                item.className = 'search-result-item';
                item.textContent = user.username;
                item.addEventListener('click', () => {
                    selectedUser = user;
                    searchInput.value = user.username;
                    searchResults.classList.add('hidden');
                });
                searchResults.appendChild(item);
            });
        }
        searchResults.classList.remove('hidden');
    }

    addCollabBtn.addEventListener('click', async () => {
        if (!selectedUser) {
            alert('먼저 사용자를 검색하여 선택해주세요.');
            return;
        }

        try {
            await api.post(`/api/storages/${currentManagingStorage.id}/collaborators`, {
                targetUserId: selectedUser.id,
                permission: permissionSelect.value
            });
            selectedUser = null;
            searchInput.value = '';
            loadCollaborators();
        } catch (error) {
            alert('참여자 추가 실패: ' + error.message);
        }
    });

    closeCollabBtn.addEventListener('click', () => {
        collabModal.classList.add('hidden');
    });

    // 외부 클릭 시 검색 결과 닫기
    document.addEventListener('click', (e) => {
        if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) {
            searchResults.classList.add('hidden');
        }
    });

    // 저장소 선택
    async function selectStorage(storageId) {
        // 보안: 저장소 진입 시 무조건 이전 키 삭제 (메모리 잔존 방지)
        window.cryptoManager.clearStorageKey();

        const storage = appState.storages.find(s => s.id === storageId);
        if (!storage) return;

        // 속성명 및 타입 호환성 체크 (DB snake_case, API camelCase, String/Number/Boolean 혼용 대응)
        const isEncryptedStorage = !!(Number(storage.is_encrypted) === 1 || storage.isEncrypted === true || storage.isEncrypted === 1);

        // 암호화된 저장소인 경우 잠금 해제 확인
        if (isEncryptedStorage) {
            const unlocked = await openUnlockStorageModal(storage);
            if (!unlocked) return; // 취소거나 실패
        }

        showLoadingOverlay();
        try {
            const data = await api.get(`/api/storages/${storageId}/data`);
            
            const permission = (storage.is_owner === 1 || storage.is_owner === true) ? 'ADMIN' : storage.permission;
            
            appState.currentStorageId = storageId;
            appState.currentStoragePermission = permission;
            appState.currentStorageIsEncrypted = isEncryptedStorage; // 상태 저장
            
            // 화면 전환
            storageScreen.classList.add('hidden');
            appEl.classList.remove('hidden');
            
            // 콜백 호출 (컬렉션 및 페이지 데이터 전달)
            if (onStorageSelected) {
                onStorageSelected({ ...data, permission, isEncryptedStorage });
            }
        } catch (error) {
            console.error('저장소 데이터 로드 실패:', error);
            alert('저장소 데이터를 불러오지 못했습니다.');
        } finally {
            hideLoadingOverlay();
        }
    }

    // --- 저장소 잠금 해제 모달 ---
    const unlockModal = document.getElementById('unlock-storage-modal');
    const unlockForm = document.getElementById('unlock-storage-form');
    const unlockInput = document.getElementById('unlock-storage-password');
    const unlockError = document.getElementById('unlock-storage-error');
    const unlockName = document.getElementById('unlock-storage-name');
    const closeUnlockBtn = document.getElementById('close-unlock-storage-btn');
    
    let unlockResolve = null;

    function openUnlockStorageModal(storage) {
        return new Promise((resolve) => {
            unlockResolve = resolve;
            unlockName.textContent = storage.name;
            unlockInput.value = '';
            unlockError.textContent = '';
            unlockModal.classList.remove('hidden');
            unlockInput.focus();
            
            // 모달 닫기 버튼 처리 (취소)
            const closeHandler = () => {
                unlockModal.classList.add('hidden');
                cleanup();
                resolve(false);
            };
            
            // 이벤트 리스너 임시 등록
            closeUnlockBtn.onclick = closeHandler;
            
            const submitHandler = async (e) => {
                e.preventDefault();
                const password = unlockInput.value;
                if (!password) return;

                unlockError.textContent = '확인 중...';
                
                // 암호 검증 및 키 설정
                const success = await window.cryptoManager.verifyAndSetStorageKey(
                    password,
                    storage.encryption_salt,
                    storage.encryption_check
                );

                if (success) {
                    unlockModal.classList.add('hidden');
                    cleanup();
                    resolve(true);
                } else {
                    unlockError.textContent = '비밀번호가 올바르지 않습니다.';
                    unlockInput.select();
                }
            };

            unlockForm.onsubmit = submitHandler;

            function cleanup() {
                closeUnlockBtn.onclick = null;
                unlockForm.onsubmit = null;
            }
        });
    }

    // --- 저장소 생성 모달 ---
    const createModal = document.getElementById('create-storage-modal');
    const createForm = document.getElementById('create-storage-form');
    const createName = document.getElementById('new-storage-name');
    const createEncrypt = document.getElementById('new-storage-encrypt');
    const createPwFields = document.getElementById('storage-password-fields');
    const createPw = document.getElementById('new-storage-password');
    const createPwConfirm = document.getElementById('new-storage-password-confirm');
    const createError = document.getElementById('create-storage-error');
    const closeCreateBtn = document.getElementById('close-create-storage-btn');
    const cancelCreateBtn = document.getElementById('cancel-create-storage-btn');

    // 새 저장소 만들기 버튼
    addStorageBtn.addEventListener('click', () => {
        createName.value = '';
        createEncrypt.checked = false;
        createPwFields.classList.add('hidden');
        createPw.value = '';
        createPwConfirm.value = '';
        createError.textContent = '';
        createModal.classList.remove('hidden');
        createName.focus();
    });

    createEncrypt.addEventListener('change', () => {
        if (createEncrypt.checked) {
            createPwFields.classList.remove('hidden');
            createPw.setAttribute('required', 'true');
            createPwConfirm.setAttribute('required', 'true');
        } else {
            createPwFields.classList.add('hidden');
            createPw.removeAttribute('required');
            createPwConfirm.removeAttribute('required');
        }
    });

    function closeCreateModal() {
        createModal.classList.add('hidden');
    }

    closeCreateBtn.addEventListener('click', closeCreateModal);
    cancelCreateBtn.addEventListener('click', closeCreateModal);

    createForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const name = createName.value.trim();
        const isEncrypted = createEncrypt.checked;
        
        if (!name) return;

        let encryptionSalt = null;
        let encryptionCheck = null;

        if (isEncrypted) {
            const pw = createPw.value;
            const pwConf = createPwConfirm.value;

            if (pw.length < 8) {
                createError.textContent = '비밀번호는 8자 이상이어야 합니다.';
                return;
            }
            if (pw !== pwConf) {
                createError.textContent = '비밀번호가 일치하지 않습니다.';
                return;
            }

            // 암호화 데이터 생성
            createError.style.color = '#3b82f6'; // 파란색 (진행 중)
            createError.textContent = '강력한 암호화 키 생성 중...';
            try {
                const cryptoData = await window.cryptoManager.createStorageEncryptionData(pw);
                encryptionSalt = cryptoData.salt;
                encryptionCheck = cryptoData.check;
            } catch (err) {
                console.error("Crypto generation failed", err);
                createError.style.color = '#ef4444'; // 빨간색 (에러)
                createError.textContent = '암호화 설정 생성 실패';
                return;
            }
        }

        showLoadingOverlay();
        try {
            const body = { 
                name,
                isEncrypted,
                encryptionSalt,
                encryptionCheck
            };
            
            const newStorage = await api.post('/api/storages', body);
            appState.storages.push(newStorage);
            renderStorages(appState.storages);
            closeCreateModal();
        } catch (error) {
            console.error('저장소 생성 실패:', error);
            createError.style.color = '#ef4444'; // 빨간색 (에러)
            createError.textContent = error.message || '저장소 생성에 실패했습니다.';
        } finally {
            hideLoadingOverlay();
        }
    });

    // 로그아웃
    logoutBtn.addEventListener('click', async () => {
        try {
            await api.post('/api/auth/logout');
            window.location.href = '/login';
        } catch (error) {
            console.error('로그아웃 실패:', error);
        }
    });

    return {
        show() {
            storageScreen.classList.remove('hidden');
            appEl.classList.add('hidden');
            renderStorages(appState.storages);
        },
        hide() {
            storageScreen.classList.add('hidden');
            appEl.classList.remove('hidden');
        }
    };
}
