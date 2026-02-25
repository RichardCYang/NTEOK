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
            
            // 보안: innerHTML 템플릿에 들어가는 값은 반드시 이스케이프 처리
            // - storage.name / storage.owner_name 은 DB에 저장되는 사용자 입력이므로 신뢰할 수 없음
            const safeStorageId = escapeHtmlAttr(storage.id);
            const safeStorageName = escapeHtml(storage.name || '');
            const safeOwnerName = escapeHtml(storage.owner_name || '');

            item.innerHTML = `
                <div class="storage-item-actions">
                    ${isOwner ? `
                        <button class="storage-action-btn collab-btn" title="참여자 관리" data-id="${safeStorageId}">
                            <i class="fa-solid fa-user-group"></i>
                        </button>
                        <button class="storage-action-btn delete-btn delete" title="저장소 삭제" data-id="${safeStorageId}">
                            <i class="fa-regular fa-trash-can"></i>
                        </button>
                    ` : `
                        <button class="storage-action-btn delete-btn delete" title="공유 해제" data-id="${safeStorageId}">
                            <i class="fa-solid fa-right-from-bracket"></i>
                        </button>
                    `}
                </div>
                <div class="storage-icon-wrapper">
                    <i class="fa-solid fa-database"></i>
                </div>
                <div class="storage-item-info">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
                        <span class="storage-item-name">${safeStorageName}</span>
                        ${!isOwner ? `<span class="storage-item-shared-badge">공유됨</span>` : ''}
                    </div>
                    <span class="storage-item-meta">${date}${!isOwner ? ` (${safeOwnerName})` : ''}</span>
                </div>
            `;
            
            item.addEventListener('click', (e) => {
                // 삭제/참여자 버튼 클릭 시 이벤트 전파 방지
                if (e.target.closest('.storage-action-btn')) return;
                selectStorage(storage.id);
            });

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

            if (isOwner) {
                const collabBtn = item.querySelector('.collab-btn');
                collabBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    showCollaboratorsModal(storage);
                });
            }
            
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
            
            const permissionLabel = {
                'READ': '읽기',
                'EDIT': '편집',
                'ADMIN': '관리'
            }[collab.permission] || collab.permission;

            // 보안: 사용자명/권한 문자열은 신뢰할 수 없으므로 HTML 이스케이프
            const safeCollabName = escapeHtml(collab.username || '');
            const safePermissionLabel = escapeHtml(permissionLabel || '');

            item.innerHTML = `
                <div class="collaborator-info">
                    <span class="collaborator-name">${safeCollabName}</span>
                </div>
                <div class="collaborator-actions">
                    <span class="collaborator-permission-badge">${safePermissionLabel}</span>
                    <button class="collaborator-remove-btn" title="삭제">
                        <i class="fa-solid fa-user-minus"></i>
                    </button>
                </div>
            `;

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
        showLoadingOverlay();
        try {
            const data = await api.get(`/api/storages/${storageId}/data`);
            
            const storage = appState.storages.find(s => s.id === storageId);
            const permission = (storage.is_owner === 1 || storage.is_owner === true) ? 'ADMIN' : storage.permission;
            
            appState.currentStorageId = storageId;
            appState.currentStoragePermission = permission;
            
            // 화면 전환
            storageScreen.classList.add('hidden');
            appEl.classList.remove('hidden');
            
            // 콜백 호출 (컬렉션 및 페이지 데이터 전달)
            if (onStorageSelected) {
                onStorageSelected({ ...data, permission });
            }
        } catch (error) {
            console.error('저장소 데이터 로드 실패:', error);
            alert('저장소 데이터를 불러오지 못했습니다.');
        } finally {
            hideLoadingOverlay();
        }
    }

    // 새 저장소 만들기
    addStorageBtn.addEventListener('click', async () => {
        const name = prompt('새 저장소 이름을 입력하세요:', '새 저장소');
        if (!name || !name.trim()) return;

        showLoadingOverlay();
        try {
            const newStorage = await api.post('/api/storages', { name: name.trim() });
            appState.storages.push(newStorage);
            renderStorages(appState.storages);
        } catch (error) {
            console.error('저장소 생성 실패:', error);
            alert('저장소 생성에 실패했습니다.');
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
