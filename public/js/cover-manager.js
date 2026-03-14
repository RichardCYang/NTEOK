
import { secureFetch, escapeHtmlAttr } from './ui-utils.js';
import { appendPageScopeParam } from './url-utils.js';

let state = null;
let isRepositioning = false;
let repositionStartY = 0;
let repositionStartPos = 50;

export function initCoverManager(appState) {
    state = appState;

    document.getElementById('add-cover-btn')?.addEventListener('click', openCoverModal);
    document.getElementById('change-cover-btn')?.addEventListener('click', openCoverModal);
    document.getElementById('remove-cover-btn')?.addEventListener('click', removeCover);
    document.getElementById('reposition-cover-btn')?.addEventListener('click', startRepositioning);

    const closeBtn = document.getElementById('close-cover-modal-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', closeCoverModal);
    }

    const modal = document.getElementById('cover-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.classList.contains('modal-overlay')) {
                closeCoverModal();
            }
        });
    }

    document.querySelectorAll('.cover-tab').forEach(tab => {
        tab.addEventListener('click', async (e) => {
            const tabName = e.target.dataset.tab;
            await switchCoverTab(tabName);
        });
    });

    document.querySelectorAll('.cover-option').forEach(option => {
        option.addEventListener('click', async (e) => {
            const coverPath = e.currentTarget.dataset.cover;
            await selectDefaultCover(coverPath);
        });
    });

    document.getElementById('cover-upload-btn')?.addEventListener('click', () => {
        document.getElementById('cover-upload-input').click();
    });

    document.getElementById('cover-upload-input')?.addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (file) {
            await uploadCustomCover(file);
            e.target.value = ''; 
        }
    });
}

function buildSafeCoverUrl(ref) {
    if (typeof ref !== 'string') return null;
    const s = ref.trim();
    const parts = s.split('/');
    if (parts.length !== 2) return null;
    const [scope, filename] = parts;
    if (!(scope === 'default' || /^\d{1,12}$/.test(scope))) return null;
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(filename)) return null;
    if (filename.includes('..')) return null;
    if (!/\.(?:jpe?g|png|gif|webp)$/i.test(filename)) return null;

    return appendPageScopeParam(
        `/covers/${encodeURIComponent(scope)}/${encodeURIComponent(filename)}`,
        window.appState?.currentPageId
    );
}

export function showCover(coverImage, coverPosition = 50) {
    if (!coverImage) {
        hideCover();
        return;
    }

    const container = document.getElementById('page-cover-container');
    const imageEl = document.getElementById('page-cover-image');
    const addBtn = document.getElementById('add-cover-btn');
    const overlay = container?.querySelector('.page-cover-overlay');

    if (container && imageEl) {
        container.style.display = 'block';
        const coverUrl = buildSafeCoverUrl(coverImage);
        if (!coverUrl) { hideCover(); return; }
        imageEl.style.backgroundImage = `url("${coverUrl}")`;
        imageEl.style.backgroundPositionY = `${coverPosition}%`;

        if (addBtn) addBtn.style.display = 'none';

        if (overlay) {
            overlay.style.display = state?.isWriteMode ? 'flex' : 'none';
        }
    }
}

export function hideCover() {
    const container = document.getElementById('page-cover-container');
    const addBtn = document.getElementById('add-cover-btn');

    if (container) container.style.display = 'none';

    if (addBtn && state?.isWriteMode) {
        addBtn.style.display = 'flex';
    }
}

function openCoverModal() {
    const modal = document.getElementById('cover-modal');
    if (modal) {
        modal.classList.remove('hidden');
        switchCoverTab('default'); 
    }
}

async function switchCoverTab(tabName) {
    document.querySelectorAll('.cover-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });

    document.querySelectorAll('.cover-tab-content').forEach(content => {
        content.classList.toggle('active', content.dataset.tabContent === tabName);
    });

    if (tabName === 'user') {
        await loadUserCovers();
    }
}

async function selectDefaultCover(coverPath) {
    if (!state?.currentPageId) return;

    try {
        const res = await secureFetch(`/api/pages/${state.currentPageId}/cover`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ coverImage: coverPath })
        });

        if (res.ok) {
            showCover(coverPath, 50);
            closeCoverModal();
            console.log('기본 커버 선택 완료:', coverPath);
        } else {
            throw new Error('커버 선택 실패');
        }
    } catch (error) {
        console.error('기본 커버 선택 오류:', error);
        alert('커버 이미지 선택에 실패했습니다.');
    }
}

async function uploadCustomCover(file) {
    if (!state?.currentPageId) return;

    if (file.size > 2 * 1024 * 1024) {
        alert('파일 크기는 2MB 이하여야 합니다.');
        return;
    }

    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
        alert('JPG, PNG, GIF, WEBP 형식만 지원됩니다.');
        return;
    }

    try {
        const formData = new FormData();
        formData.append('cover', file);

        const res = await secureFetch(`/api/pages/${state.currentPageId}/cover`, {
            method: 'POST',
            body: formData,
            credentials: 'include'
        });

        if (res.ok) {
            const data = await res.json();
            showCover(data.coverImage, 50);
            await switchCoverTab('user');
            console.log('커스텀 커버 업로드 완료:', data.coverImage);
        } else {
            throw new Error('커버 업로드 실패');
        }
    } catch (error) {
        console.error('커버 업로드 오류:', error);
        alert('커버 이미지 업로드에 실패했습니다.');
    }
}

async function removeCover() {
    if (!state?.currentPageId) return;

    if (!confirm('커버 이미지를 제거하시겠습니까?')) {
        return;
    }

    try {
        const res = await secureFetch(`/api/pages/${state.currentPageId}/cover`, {
            method: 'DELETE'
        });

        if (res.ok) {
            hideCover();
            console.log('커버 제거 완료');
        } else {
            throw new Error('커버 제거 실패');
        }
    } catch (error) {
        console.error('커버 제거 오류:', error);
        alert('커버 이미지 제거에 실패했습니다.');
    }
}

function startRepositioning() {
    if (isRepositioning) {
        stopRepositioning();
        return;
    }

    isRepositioning = true;
    const container = document.getElementById('page-cover-container');
    const imageEl = document.getElementById('page-cover-image');
    const btn = document.getElementById('reposition-cover-btn');

    if (!container || !imageEl) return;

    container.classList.add('repositioning');
    if (btn) btn.innerHTML = '<i class="fa-solid fa-check"></i> 완료';

    const currentPos = imageEl.style.backgroundPositionY;
    repositionStartPos = parseInt(currentPos) || 50;

    const onMouseDown = (e) => {
        e.preventDefault();
        repositionStartY = e.clientY;
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    };

    const onMouseMove = (e) => {
        e.preventDefault();
        const deltaY = e.clientY - repositionStartY;
        const containerHeight = container.offsetHeight;
        const deltaPercent = (deltaY / containerHeight) * 100;
        let newPos = repositionStartPos + deltaPercent;
        newPos = Math.max(0, Math.min(100, newPos));

        imageEl.style.backgroundPositionY = `${newPos}%`;
    };

    const onMouseUp = async (e) => {
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);

        const finalPos = parseInt(imageEl.style.backgroundPositionY) || 50;

        try {
            await secureFetch(`/api/pages/${state.currentPageId}/cover`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ coverPosition: finalPos })
            });
            console.log('커버 위치 저장:', finalPos);
        } catch (error) {
            console.error('커버 위치 저장 오류:', error);
        }
    };

    imageEl.addEventListener('mousedown', onMouseDown);

    container._repositionCleanup = () => {
        imageEl.removeEventListener('mousedown', onMouseDown);
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
    };
}

function stopRepositioning() {
    isRepositioning = false;
    const container = document.getElementById('page-cover-container');
    const btn = document.getElementById('reposition-cover-btn');

    if (container) {
        container.classList.remove('repositioning');
        if (container._repositionCleanup) {
            container._repositionCleanup();
            delete container._repositionCleanup;
        }
    }

    if (btn) btn.innerHTML = '<i class="fa-solid fa-arrows-up-down"></i> 위치 조정';
}

function closeCoverModal() {
    const modal = document.getElementById('cover-modal');
    if (modal) modal.classList.add('hidden');
}

export function updateCoverButtonsVisibility() {
    const container = document.getElementById('page-cover-container');
    const overlay = container?.querySelector('.page-cover-overlay');
    const addBtn = document.getElementById('add-cover-btn');

    if (overlay) {
        overlay.style.display = state?.isWriteMode ? 'flex' : 'none';
    }

    if (addBtn) {
        const hasNoCover = !container || container.style.display === 'none';
        addBtn.style.display = (state?.isWriteMode && hasNoCover) ? 'flex' : 'none';
    }
}

async function loadUserCovers() {
    const gallery = document.getElementById('user-cover-gallery');
    if (!gallery) return;

    try {
        const res = await secureFetch('/api/pages/covers/user', {
            method: 'GET'
        });

        if (!res.ok) {
            throw new Error('사용자 커버 목록 조회 실패');
        }

        const covers = await res.json();

        if (covers.length === 0) {
            gallery.innerHTML = '<p class="cover-gallery-empty">업로드된 커버 이미지가 없습니다.</p>';
            return;
        }

        gallery.innerHTML = covers.map(cover => `
        	<div class="user-cover-option" data-cover="${escapeHtmlAttr(cover.path)}">
                <img src="/covers/${escapeHtmlAttr(cover.path)}" alt="사용자 커버">
                <button class="delete-cover-btn" data-filename="${escapeHtmlAttr(cover.filename)}" title="삭제">
                    <i class="fa-solid fa-trash"></i>
                </button>
            </div>
        `).join('');

        gallery.querySelectorAll('.user-cover-option').forEach(option => {
            option.addEventListener('click', async (e) => {
                if (e.target.closest('.delete-cover-btn')) return;

                const coverPath = option.dataset.cover;
                await selectDefaultCover(coverPath);
            });
        });

        gallery.querySelectorAll('.delete-cover-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const filename = btn.dataset.filename;
                await deleteUserCover(filename);
            });
        });

    } catch (error) {
        console.error('사용자 커버 목록 로드 오류:', error);
        gallery.innerHTML = '<p class="cover-gallery-empty" style="color: #f44;">커버 목록을 불러오는데 실패했습니다.</p>';
    }
}

async function deleteUserCover(filename) {
    if (!confirm('이 커버 이미지를 삭제하시겠습니까?')) {
        return;
    }

    try {
        const res = await secureFetch(`/api/pages/covers/${filename}`, {
            method: 'DELETE'
        });

        if (res.ok) {
            console.log('커버 이미지 삭제 완료:', filename);
            await loadUserCovers(); 
        } else {
            const data = await res.json();
            throw new Error(data.error || '커버 삭제 실패');
        }
    } catch (error) {
        console.error('커버 삭제 오류:', error);
        alert(error.message || '커버 이미지 삭제에 실패했습니다.');
    }
}

export function hideCover() {
    const container = document.getElementById('page-cover-container');
    const addBtn = document.getElementById('add-cover-btn');

    if (container) container.style.display = 'none';

    if (addBtn && state?.isWriteMode) {
        addBtn.style.display = 'flex';
    }
}

function openCoverModal() {
    const modal = document.getElementById('cover-modal');
    if (modal) {
        modal.classList.remove('hidden');
        switchCoverTab('default'); 
    }
}

async function switchCoverTab(tabName) {
    document.querySelectorAll('.cover-tab').forEach(tab => {
        tab.classList.toggle('active', tab.dataset.tab === tabName);
    });

    document.querySelectorAll('.cover-tab-content').forEach(content => {
        content.classList.toggle('active', content.dataset.tabContent === tabName);
    });

    if (tabName === 'user') {
        await loadUserCovers();
    }
}

async function selectDefaultCover(coverPath) {
    if (!state?.currentPageId) return;

    try {
        const res = await secureFetch(`/api/pages/${state.currentPageId}/cover`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ coverImage: coverPath })
        });

        if (res.ok) {
            showCover(coverPath, 50);
            closeCoverModal();
            console.log('기본 커버 선택 완료:', coverPath);
        } else {
            throw new Error('커버 선택 실패');
        }
    } catch (error) {
        console.error('기본 커버 선택 오류:', error);
        alert('커버 이미지 선택에 실패했습니다.');
    }
}

async function uploadCustomCover(file) {
    if (!state?.currentPageId) return;

    if (file.size > 2 * 1024 * 1024) {
        alert('파일 크기는 2MB 이하여야 합니다.');
        return;
    }

    const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
    if (!allowedTypes.includes(file.type)) {
        alert('JPG, PNG, GIF, WEBP 형식만 지원됩니다.');
        return;
    }

    try {
        const formData = new FormData();
        formData.append('cover', file);

        const res = await secureFetch(`/api/pages/${state.currentPageId}/cover`, {
            method: 'POST',
            body: formData,
            credentials: 'include'
        });

        if (res.ok) {
            const data = await res.json();
            showCover(data.coverImage, 50);
            await switchCoverTab('user');
            console.log('커스텀 커버 업로드 완료:', data.coverImage);
        } else {
            throw new Error('커버 업로드 실패');
        }
    } catch (error) {
        console.error('커버 업로드 오류:', error);
        alert('커버 이미지 업로드에 실패했습니다.');
    }
}

async function removeCover() {
    if (!state?.currentPageId) return;

    if (!confirm('커버 이미지를 제거하시겠습니까?')) {
        return;
    }

    try {
        const res = await secureFetch(`/api/pages/${state.currentPageId}/cover`, {
            method: 'DELETE'
        });

        if (res.ok) {
            hideCover();
            console.log('커버 제거 완료');
        } else {
            throw new Error('커버 제거 실패');
        }
    } catch (error) {
        console.error('커버 제거 오류:', error);
        alert('커버 이미지 제거에 실패했습니다.');
    }
}

function startRepositioning() {
    if (isRepositioning) {
        stopRepositioning();
        return;
    }

    isRepositioning = true;
    const container = document.getElementById('page-cover-container');
    const imageEl = document.getElementById('page-cover-image');
    const btn = document.getElementById('reposition-cover-btn');

    if (!container || !imageEl) return;

    container.classList.add('repositioning');
    if (btn) btn.innerHTML = '<i class="fa-solid fa-check"></i> 완료';

    const currentPos = imageEl.style.backgroundPositionY;
    repositionStartPos = parseInt(currentPos) || 50;

    const onMouseDown = (e) => {
        e.preventDefault();
        repositionStartY = e.clientY;
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
    };

    const onMouseMove = (e) => {
        e.preventDefault();
        const deltaY = e.clientY - repositionStartY;
        const containerHeight = container.offsetHeight;
        const deltaPercent = (deltaY / containerHeight) * 100;
        let newPos = repositionStartPos + deltaPercent;
        newPos = Math.max(0, Math.min(100, newPos));

        imageEl.style.backgroundPositionY = `${newPos}%`;
    };

    const onMouseUp = async (e) => {
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);

        const finalPos = parseInt(imageEl.style.backgroundPositionY) || 50;

        try {
            await secureFetch(`/api/pages/${state.currentPageId}/cover`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ coverPosition: finalPos })
            });
            console.log('커버 위치 저장:', finalPos);
        } catch (error) {
            console.error('커버 위치 저장 오류:', error);
        }
    };

    imageEl.addEventListener('mousedown', onMouseDown);

    container._repositionCleanup = () => {
        imageEl.removeEventListener('mousedown', onMouseDown);
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
    };
}

function stopRepositioning() {
    isRepositioning = false;
    const container = document.getElementById('page-cover-container');
    const btn = document.getElementById('reposition-cover-btn');

    if (container) {
        container.classList.remove('repositioning');
        if (container._repositionCleanup) {
            container._repositionCleanup();
            delete container._repositionCleanup;
        }
    }

    if (btn) btn.innerHTML = '<i class="fa-solid fa-arrows-up-down"></i> 위치 조정';
}

function closeCoverModal() {
    const modal = document.getElementById('cover-modal');
    if (modal) modal.classList.add('hidden');
}

export function updateCoverButtonsVisibility() {
    const container = document.getElementById('page-cover-container');
    const overlay = container?.querySelector('.page-cover-overlay');
    const addBtn = document.getElementById('add-cover-btn');

    if (overlay) {
        overlay.style.display = state?.isWriteMode ? 'flex' : 'none';
    }

    if (addBtn) {
        const hasNoCover = !container || container.style.display === 'none';
        addBtn.style.display = (state?.isWriteMode && hasNoCover) ? 'flex' : 'none';
    }
}

async function loadUserCovers() {
    const gallery = document.getElementById('user-cover-gallery');
    if (!gallery) return;

    try {
        const res = await secureFetch('/api/pages/covers/user', {
            method: 'GET'
        });

        if (!res.ok) {
            throw new Error('사용자 커버 목록 조회 실패');
        }

        const covers = await res.json();

        if (covers.length === 0) {
            gallery.innerHTML = '<p class="cover-gallery-empty">업로드된 커버 이미지가 없습니다.</p>';
            return;
        }

        gallery.innerHTML = covers.map(cover => `
        	<div class="user-cover-option" data-cover="${escapeHtmlAttr(cover.path)}">
                <img src="/covers/${escapeHtmlAttr(cover.path)}" alt="사용자 커버">
                <button class="delete-cover-btn" data-filename="${escapeHtmlAttr(cover.filename)}" title="삭제">
                    <i class="fa-solid fa-trash"></i>
                </button>
            </div>
        `).join('');

        gallery.querySelectorAll('.user-cover-option').forEach(option => {
            option.addEventListener('click', async (e) => {
                if (e.target.closest('.delete-cover-btn')) return;

                const coverPath = option.dataset.cover;
                await selectDefaultCover(coverPath);
            });
        });

        gallery.querySelectorAll('.delete-cover-btn').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                e.stopPropagation();
                const filename = btn.dataset.filename;
                await deleteUserCover(filename);
            });
        });

    } catch (error) {
        console.error('사용자 커버 목록 로드 오류:', error);
        gallery.innerHTML = '<p class="cover-gallery-empty" style="color: #f44;">커버 목록을 불러오는데 실패했습니다.</p>';
    }
}

async function deleteUserCover(filename) {
    if (!confirm('이 커버 이미지를 삭제하시겠습니까?')) {
        return;
    }

    try {
        const res = await secureFetch(`/api/pages/covers/${filename}`, {
            method: 'DELETE'
        });

        if (res.ok) {
            console.log('커버 이미지 삭제 완료:', filename);
            await loadUserCovers(); 
        } else {
            const data = await res.json();
            throw new Error(data.error || '커버 삭제 실패');
        }
    } catch (error) {
        console.error('커버 삭제 오류:', error);
        alert(error.message || '커버 이미지 삭제에 실패했습니다.');
    }
}
