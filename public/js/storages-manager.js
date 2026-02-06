/**
 * 저장소 관리자
 */
import * as api from './api-utils.js';
import { showLoadingOverlay, hideLoadingOverlay } from './ui-utils.js';

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
            
            const date = new Date(storage.createdAt).toLocaleDateString();
            
            item.innerHTML = `
                <button class="storage-delete-btn" title="저장소 삭제" data-id="${storage.id}">
                    <i class="fa-regular fa-trash-can"></i>
                </button>
                <div class="storage-icon-wrapper">
                    <i class="fa-solid fa-database"></i>
                </div>
                <div class="storage-item-info">
                    <span class="storage-item-name">${storage.name}</span>
                    <span class="storage-item-meta">${date}</span>
                </div>
            `;
            
            item.addEventListener('click', (e) => {
                // 삭제 버튼 클릭 시 이벤트 전파 방지
                if (e.target.closest('.storage-delete-btn')) return;
                selectStorage(storage.id);
            });

            const deleteBtn = item.querySelector('.storage-delete-btn');
            deleteBtn.addEventListener('click', async (e) => {
                e.stopPropagation();
                
                if (appState.storages.length <= 1) {
                    alert('최소 하나의 저장소는 유지해야 합니다.');
                    return;
                }

                if (!confirm(`'${storage.name}' 저장소를 삭제하시겠습니까?\n포함된 모든 컬렉션과 페이지가 영구적으로 삭제됩니다.`)) {
                    return;
                }

                showLoadingOverlay();
                try {
                    await api.del(`/api/storages/${storage.id}`);
                    appState.storages = appState.storages.filter(s => s.id !== storage.id);
                    renderStorages(appState.storages);
                } catch (error) {
                    console.error('저장소 삭제 실패:', error);
                    alert(error.message || '저장소 삭제에 실패했습니다.');
                } finally {
                    hideLoadingOverlay();
                }
            });
            
            storageList.appendChild(item);
        });
    }

    // 저장소 선택
    async function selectStorage(storageId) {
        showLoadingOverlay();
        try {
            const data = await api.get(`/api/storages/${storageId}/data`);
            
            appState.currentStorageId = storageId;
            
            // 화면 전환
            storageScreen.classList.add('hidden');
            appEl.classList.remove('hidden');
            
            // 콜백 호출 (컬렉션 및 페이지 데이터 전달)
            if (onStorageSelected) {
                onStorageSelected(data);
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
