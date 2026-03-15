import * as api from './api-utils.js';
import { showLoadingOverlay, hideLoadingOverlay, escapeHtml, escapeHtmlAttr } from './ui-utils.js';

const keyState = { myKid: null };

// Ensure user has ECDH key pair for DEK v1 sharing
async function ensureUserKeyPair(loginPassword) {
    try {
        // Check if user has existing keys
        const existingKeys = await api.get('/api/user-keys/me');
        if (existingKeys && existingKeys.length > 0) {
            const latestKey = existingKeys[0];
            const { ticket } = await api.post(`/api/user-keys/${encodeURIComponent(latestKey.kid)}/export-ticket`, {});
            if (!ticket) throw new Error('티켓 발급 실패');
            const exported = await api.post(`/api/user-keys/${encodeURIComponent(latestKey.kid)}/export-private`, { ticket });
            const privKey = await window.cryptoManager.decryptPrivateKey(
                exported.encryptedPrivateKey,
                exported.keyWrapSalt,
                loginPassword
            );
            window.cryptoManager.setMyEcdhPrivateKey(privKey);
            keyState.myKid = latestKey.kid;
            return;
        }

        // Generate new ECDH key pair
        const keyPair = await window.cryptoManager.generateEcdhKeyPair();
        const kid = crypto.randomUUID();

        // Export public key to Base64
        const publicKeySpki = await window.cryptoManager.exportPublicKeyToBase64(keyPair.publicKey);

        // Encrypt private key
        const { encryptedPrivateKey, keyWrapSalt } = await window.cryptoManager.encryptPrivateKey(
            keyPair.privateKey,
            loginPassword
        );

        // Register key pair with server
        await api.post('/api/user-keys', {
            kid,
            publicKeySpki,
            encryptedPrivateKey,
            keyWrapSalt,
            deviceLabel: `Device ${new Date().toLocaleDateString()}`
        });

        // Set in memory
        window.cryptoManager.setMyEcdhPrivateKey(keyPair.privateKey);
        keyState.myKid = kid;
    } catch (error) {
        console.error('ensureUserKeyPair failed:', error);
        throw error;
    }
}

export function initStoragesManager(appState, onStorageSelected) {
    const storageScreen = document.getElementById('storage-selection-screen');
    const storageList = document.getElementById('storage-list');
    const addStorageBtn = document.getElementById('add-storage-btn');
    const logoutBtn = document.getElementById('storage-logout-btn');
    const appEl = document.querySelector('.app');

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
            const canManageCollaborators = isOwner;
            const isEncrypted = !!(Number(storage.is_encrypted) === 1 || storage.isEncrypted);
            
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
                    ${canManageCollaborators ? `
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
                    ? `'${storage.name}' 저장소를 삭제하시겠습니까?\n포함된 모든 컬렉션과 페이지가 영구적으로 삭제됩니다.\n(참고: 다른 협업자가 작성한 페이지는 해당 사용자의 복구 저장소로 안전하게 이관됩니다.)`
                    : `'${storage.name}' 저장소의 공유를 해제하시겠습니까?`;
                if (!confirm(confirmMsg)) return;

                showLoadingOverlay();
                try {
                    const result = await api.del(`/api/storages/${storage.id}`);
                    appState.storages = appState.storages.filter(s => s.id !== storage.id);
                    renderStorages(appState.storages);

                    if (result?.transferred && Object.keys(result.transferred).length > 0) {
                        const userCount = Object.keys(result.transferred).length;
                        const totalPages = Object.values(result.transferred).reduce((sum, item) => sum + (item.movedPages || 0), 0);
                        alert(`저장소가 삭제되었습니다.\n\n[데이터 이관 리포트]\n- 대상 협업자: ${userCount}명\n- 이관된 페이지: 총 ${totalPages}개\n\n협업자들의 데이터는 각 사용자의 'Recovered' 저장소로 안전하게 분리 보관되었습니다.`);
                    }
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
            if (error.status === 403) collabList.innerHTML = '<div style="text-align: center; padding: 20px; color: #ef4444;">참여자 목록을 조회할 권한이 없습니다.</div>';
            else collabList.innerHTML = '<div style="text-align: center; padding: 20px; color: #ef4444;">로드 실패</div>';
        }
    }

    function renderCollaborators(collaborators) {
        const canManageCollaborators = currentManagingStorage && (currentManagingStorage.is_owner === 1 || currentManagingStorage.is_owner === true);
        collabList.innerHTML = '';
        if (collaborators.length === 0) {
            collabList.innerHTML = '<div style="text-align: center; padding: 20px; color: var(--sub-font-color); font-size: 13px;">추가된 참여자가 없습니다.</div>';
            return;
        }

        collaborators.forEach(collab => {
            const item = document.createElement('div');
            item.className = 'collaborator-item';
            
            const safeCollabName = escapeHtml(collab.username || '');
            const safeCollabId = escapeHtmlAttr(collab.id);

            const info = document.createElement('div');
            info.className = 'collaborator-info';
            const name = document.createElement('span');
            name.className = 'collaborator-name';
            name.textContent = String(collab.username || '');
            info.appendChild(name);

            const actions = document.createElement('div');
            actions.className = 'collaborator-actions';
            const select = document.createElement('select');
            select.className = 'collaborator-permission-select';
            select.dataset.userId = String(collab.id);
            if (!canManageCollaborators) select.disabled = true;

            ['READ', 'EDIT', 'ADMIN'].forEach((perm) => {
                const opt = document.createElement('option');
                opt.value = perm;
                opt.textContent = perm === 'READ' ? '읽기' : perm === 'EDIT' ? '편집' : '관리';
                if (collab.permission === perm) opt.selected = true;
                select.appendChild(opt);
            });

            actions.appendChild(select);

            if (canManageCollaborators) {
                const removeBtn = document.createElement('button');
                removeBtn.className = 'collaborator-remove-btn';
                removeBtn.title = '삭제';
                const icon = document.createElement('i');
                icon.className = 'fa-solid fa-user-minus';
                removeBtn.appendChild(icon);
                actions.appendChild(removeBtn);
            }

            item.appendChild(info);
            item.appendChild(actions);

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
                    loadCollaborators();
                }
            });

            const removeBtn = item.querySelector('.collaborator-remove-btn');
            if (removeBtn) {
                removeBtn.addEventListener('click', async () => {
                    if (!confirm(`'${collab.username}' 님을 저장소에서 제외하시겠습니까?`)) return;
                    try {
                        await api.del(`/api/storages/${currentManagingStorage.id}/collaborators/${collab.id}`);
                        loadCollaborators();
                    } catch (error) {
                        alert('참여자 삭제 실패: ' + error.message);
                    }
                });
            }

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
                const users = await api.get(`/api/storages/${currentManagingStorage.id}/users/search?q=${encodeURIComponent(query)}`);
                renderSearchResults(users);
            } catch (error) {
                console.error('사용자 검색 실패:', error);
            }
        }, 300);
    });

    function renderSearchResults(users) {
        searchResults.innerHTML = '';
        if (users.length === 0) searchResults.innerHTML = '<div class="search-result-item" style="color: #6b7280; cursor: default;">검색 결과 없음</div>';
        else {
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
        const canManageCollaborators = currentManagingStorage && (currentManagingStorage.is_owner === 1 || currentManagingStorage.is_owner === true);
        if (!canManageCollaborators) {
            alert('저장소 소유자만 참여자를 추가할 수 있습니다.');
            return;
        }
        if (!selectedUser) {
            alert('먼저 사용자를 검색하여 선택해주세요.');
            return;
        }

        try {
            const body = {
                targetUserId: selectedUser.id,
                permission: permissionSelect.value
            };

            // For DEK v1 encrypted storage, wrap DEK for collaborator
            if (Number(currentManagingStorage.is_encrypted) === 1 && Number(currentManagingStorage.dek_version) === 1) {
                // Check if we have the extractable DEK in memory
                if (!window.cryptoManager.hasUnlockedShareKey()) {
                    alert('저장소 잠금을 해제해야 협업자를 추가할 수 있습니다.');
                    return;
                }

                // Get target user's public keys
                const publicKeys = await api.get(`/api/user-keys/public/${selectedUser.id}?storageId=${encodeURIComponent(currentManagingStorage.id)}`);
                if (!publicKeys || publicKeys.length === 0) {
                    alert('대상 사용자가 아직 암호화 키를 등록하지 않았습니다. 사용자에게 먼저 로그인하도록 안내해주세요.');
                    return;
                }

                // Use the most recent public key
                const latestPubKey = publicKeys[0];

                // Wrap DEK for collaborator
                const { wrappedDek, ephemeralPublicKey } =
                    await window.cryptoManager.withUnlockedShareKey((dek) =>
                        window.cryptoManager.wrapDekForCollaborator(
                            dek,
                            latestPubKey.publicKeySpki || latestPubKey.public_key_spki
                        )
                    );

                body.wrappedDek = wrappedDek;
                body.wrappingKid = latestPubKey.kid;
                body.ephemeralPublicKey = ephemeralPublicKey;
            }

            await api.post(`/api/storages/${currentManagingStorage.id}/collaborators`, body);
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

    document.addEventListener('click', (e) => {
        if (!searchInput.contains(e.target) && !searchResults.contains(e.target)) searchResults.classList.add('hidden');
    });

    async function selectStorage(storageId, skipHistory = false) {
        window.cryptoManager.clearStorageKey();

        const storage = appState.storages.find(s => s.id === storageId);
        if (!storage) return;

        const isEncryptedStorage = !!(Number(storage.is_encrypted) === 1 || storage.isEncrypted === true || storage.isEncrypted === 1);

        if (isEncryptedStorage) {
            const unlocked = await openUnlockStorageModal(storage);
            if (!unlocked) return; 
        }

        showLoadingOverlay();
        try {
            const data = await api.get(`/api/storages/${storageId}/data`);
            
            const permission = (storage.is_owner === 1 || storage.is_owner === true) ? 'ADMIN' : storage.permission;
            
            appState.currentStorageId = storageId;
            appState.currentStoragePermission = permission;
            appState.currentStorageIsEncrypted = isEncryptedStorage; 
            
            storageScreen.classList.add('hidden');
            appEl.classList.remove('hidden');
            
            if (!skipHistory) history.pushState({ view: 'app', storageId }, '', window.location.pathname);

            if (onStorageSelected) onStorageSelected({ ...data, permission, isEncryptedStorage });
        } catch (error) {
            console.error('저장소 데이터 로드 실패:', error);
            alert('저장소 데이터를 불러오지 못했습니다.');
        } finally {
            hideLoadingOverlay();
        }
    }

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

            const closeHandler = () => {
                unlockModal.classList.add('hidden');
                cleanup();
                resolve(false);
            };

            closeUnlockBtn.onclick = closeHandler;

            const submitHandler = async (e) => {
                e.preventDefault();
                const password = unlockInput.value;
                if (!password) return;

                unlockError.textContent = '확인 중...';

                try {
                    let success = false;

                    // Check if DEK v1 encrypted
                    if (Number(storage.dek_version) === 1) {
                        const isOwner = Number(storage.is_owner) === 1;

                        if (isOwner) {
                            // Owner: unlock with password + wrapped DEK
                            success = await window.cryptoManager.unlockStorageWithDek(
                                storage.wrapped_dek || storage.wrappedDek,
                                password,
                                storage.encryption_salt || storage.encryptionSalt
                            );
                        } else {
                            // Collaborator: get wrapped DEK and unlock with ECDH
                            try {
                                // Ensure ECDH private key is available
                                const keyPairs = await api.get('/api/user-keys/me');
                                if (!keyPairs || keyPairs.length === 0) {
                                    unlockError.textContent = '사용자 키가 없습니다. 다시 로그인해주세요.';
                                    return;
                                }

                                const latestKey = keyPairs[0];
                                const { ticket } = await api.post(`/api/user-keys/${encodeURIComponent(latestKey.kid)}/export-ticket`, {});
                                if (!ticket) throw new Error('티켓 발급 실패');
                                const exported = await api.post(`/api/user-keys/${encodeURIComponent(latestKey.kid)}/export-private`, { ticket });
                                const privKey = await window.cryptoManager.decryptPrivateKey(
                                    exported.encryptedPrivateKey,
                                    exported.keyWrapSalt,
                                    password
                                );

                                // Get wrapped DEK from server
                                const { ticket: wrappedDekTicket } =
                                    await api.post(`/api/storages/${storage.id}/my-wrapped-dek-ticket`, {});

                                const wrappedDekRecord =
                                    await api.post(`/api/storages/${storage.id}/my-wrapped-dek`, {
                                        purpose: 'unlock-storage',
                                        ticket: wrappedDekTicket
                                    });

                                // Unlock with ECDH
                                success = await window.cryptoManager.unlockStorageWithEcdh(
                                    wrappedDekRecord.wrappedDek,
                                    wrappedDekRecord.ephemeralPublicKey,
                                    privKey
                                );
                            } catch (err) {
                                console.error('ECDH unlock failed:', err);
                                unlockError.textContent = '저장소 복호화에 실패했습니다.';
                                unlockInput.select();
                                return;
                            }
                        }
                    } else {
                        // Legacy PBKDF2 mode
                        success = await window.cryptoManager.verifyAndSetStorageKey(
                            password,
                            storage.encryption_salt,
                            storage.encryption_check
                        );
                    }

                    if (success) {
                        unlockModal.classList.add('hidden');
                        cleanup();
                        resolve(true);
                    } else {
                        unlockError.textContent = '비밀번호가 올바르지 않습니다.';
                        unlockInput.select();
                    }
                } catch (error) {
                    console.error('Unlock error:', error);
                    unlockError.textContent = error.message || '복호화 중 오류가 발생했습니다.';
                    unlockInput.select();
                } finally {
                    unlockInput.value = '';
                }
            };

            unlockForm.onsubmit = submitHandler;

            function cleanup() {
                closeUnlockBtn.onclick = null;
                unlockForm.onsubmit = null;
            }
        });
    }

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
        let dekVersion = 0;
        let wrappedDek = null;
        let wrappingKid = null;

        if (isEncrypted) {
            const pw = createPw.value;
            const pwConf = createPwConfirm.value;

            if (pw.length < 12) {
                createError.textContent = '암호 문구는 12 자 이상이어야 합니다.';
                return;
            }
            if (pw !== pwConf) {
                createError.textContent = '비밀번호가 일치하지 않습니다.';
                return;
            }

            createError.style.color = '#3b82f6';
            createError.textContent = '암호화 설정 준비 중...';
            try {
                // Ensure user has ECDH key pair (DEK v1)
                await ensureUserKeyPair(pw);

                // Generate DEK
                const dek = await window.cryptoManager.generateDek();

                // Derive KEK and wrap DEK
                const { key: kek, saltBase64: kekSalt } = await window.cryptoManager.deriveKek(pw);
                wrappedDek = await window.cryptoManager.wrapDekWithKek(dek, kek);

                encryptionSalt = kekSalt;
                dekVersion = 1;
                wrappingKid = keyState.myKid;
            } catch (err) {
                console.error("Crypto generation failed", err);
                createError.style.color = '#ef4444';
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
                encryptionCheck,
                dekVersion,
                wrappedDek,
                wrappingKid
            };

            const newStorage = await api.post('/api/storages', body);
            appState.storages.push(newStorage);
            renderStorages(appState.storages);
            closeCreateModal();
        } catch (error) {
            console.error('저장소 생성 실패:', error);
            createError.style.color = '#ef4444';
            createError.textContent = error.message || '저장소 생성에 실패했습니다.';
        } finally {
            hideLoadingOverlay();
        }
    });

    logoutBtn.addEventListener('click', async () => {
        try {
            await api.post('/api/auth/logout');
            window.location.href = '/login';
        } catch (error) {
            console.error('로그아웃 실패:', error);
        }
    });

    return {
        show(skipHistory = false) {
            storageScreen.classList.remove('hidden');
            appEl.classList.add('hidden');
            renderStorages(appState.storages);
            
            if (!skipHistory) history.pushState({ view: 'storages' }, '', window.location.pathname);
        },
        hide() {
            storageScreen.classList.add('hidden');
            appEl.classList.remove('hidden');
        },
        selectStorage(storageId, skipHistory = false) {
            return selectStorage(storageId, skipHistory);
        }
    };
}
