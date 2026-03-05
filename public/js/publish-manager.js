
import { secureFetch } from './ui-utils.js';

let state = null;
const publishState = {
    pageId: null,
    token: null,
    url: null,
    published: false,
    allowComments: false
};

export function initPublishManager(appState) {
    state = appState;
}

export async function checkPublishStatus(pageId) {
    if (!pageId) return;

    try {
        const res = await secureFetch(`/api/pages/${encodeURIComponent(pageId)}/publish`);
        if (!res.ok) {
            console.log("발행 상태 확인 실패:", res.status);
            publishState.published = false;
            publishState.pageId = pageId;
            publishState.allowComments = false;
            return;
        }

        const data = await res.json();
        publishState.pageId = pageId;
        publishState.published = data.published || false;
        publishState.token = data.token || null;
        publishState.url = data.url || null;
        publishState.allowComments = data.allowComments || false;

        updatePublishButton();
    } catch (error) {
        console.error("발행 상태 확인 오류:", error);
        publishState.published = false;
    }
}

export function updatePublishButton() {
    const publishBtn = document.getElementById('publish-btn');

    if (!publishBtn) return;

    if (state?.isWriteMode) {
        publishBtn.style.display = 'none';
        return;
    }

    if (state?.currentPageIsEncrypted) {
        publishBtn.style.display = 'none';
        return;
    }

    if (state?.currentStoragePermission !== 'ADMIN') {
        publishBtn.style.display = 'none';
        return;
    }

    publishBtn.style.display = 'flex';

    if (publishState.published) {
        publishBtn.title = '발행 취소';
        publishBtn.classList.add('published');
    } else {
        publishBtn.title = '발행';
        publishBtn.classList.remove('published');
    }
}

export function openPublishModal() {
    const modal = document.getElementById('page-publish-modal');
    const beforeContent = document.getElementById('publish-before-content');
    const afterContent = document.getElementById('publish-after-content');
    const errorDiv = document.getElementById('publish-error');

    if (!modal) return;

    errorDiv.textContent = '';

    if (publishState.published) {
        beforeContent.style.display = 'none';
        afterContent.style.display = 'block';
        const linkInput = document.getElementById('publish-link-input');
        if (linkInput) {
            linkInput.value = publishState.url || '';
        }
        
        const allowCommentsCheckbox = document.getElementById('publish-allow-comments');
        if (allowCommentsCheckbox) {
            allowCommentsCheckbox.checked = publishState.allowComments;
        }
    } else {
        beforeContent.style.display = 'block';
        afterContent.style.display = 'none';
        
        const allowCommentsCheckbox = document.getElementById('publish-allow-comments-before');
        if (allowCommentsCheckbox) {
            allowCommentsCheckbox.checked = false;
        }
    }

    modal.classList.remove('hidden');
}

export function closePublishModal() {
    const modal = document.getElementById('page-publish-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

export async function publishPage() {
    if (!publishState.pageId) {
        showPublishError('페이지를 찾을 수 없습니다.');
        return;
    }

    const beforeContent = document.getElementById('publish-before-content');
    const afterContent = document.getElementById('publish-after-content');
    const confirmBtn = document.getElementById('confirm-publish-btn');
    
    let allowComments = false;
    const allowCommentsCheckboxBefore = document.getElementById('publish-allow-comments-before');
    if (allowCommentsCheckboxBefore) {
        allowComments = allowCommentsCheckboxBefore.checked;
    }

    if (confirmBtn) confirmBtn.disabled = true;

    try {
        const res = await secureFetch(`/api/pages/${encodeURIComponent(publishState.pageId)}/publish`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ allowComments })
        });

        if (!res.ok) {
            const error = await res.json();
            throw new Error(error.error || '발행 실패');
        }

        const data = await res.json();
        publishState.token = data.token;
        publishState.url = data.url;
        publishState.published = true;
        publishState.allowComments = data.allowComments;

        beforeContent.style.display = 'none';
        afterContent.style.display = 'block';

        const linkInput = document.getElementById('publish-link-input');
        if (linkInput) {
            linkInput.value = data.url;
        }
        
        const allowCommentsCheckbox = document.getElementById('publish-allow-comments');
        if (allowCommentsCheckbox) {
            allowCommentsCheckbox.checked = publishState.allowComments;
        }

        updatePublishButton();

        console.log('페이지 발행 완료:', data.url);
    } catch (error) {
        console.error('발행 오류:', error);
        showPublishError(error.message || '발행에 실패했습니다.');
    } finally {
        if (confirmBtn) confirmBtn.disabled = false;
    }
}

async function updatePublishSettings() {
    if (!publishState.published || !publishState.pageId) return;
    
    const allowCommentsCheckbox = document.getElementById('publish-allow-comments');
    const allowComments = allowCommentsCheckbox ? allowCommentsCheckbox.checked : false;

    try {
         const res = await secureFetch(`/api/pages/${encodeURIComponent(publishState.pageId)}/publish`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ allowComments })
        });
        
        if (!res.ok) {
            throw new Error('설정 업데이트 실패');
        }
        
        const data = await res.json();
        publishState.allowComments = data.allowComments;
        console.log('발행 설정 업데이트 완료:', allowComments);
        
    } catch (error) {
        console.error('설정 업데이트 오류:', error);
        alert('설정을 업데이트하지 못했습니다.');
        if (allowCommentsCheckbox) {
            allowCommentsCheckbox.checked = !allowComments;
        }
    }
}

export async function unpublishPage() {
    if (!publishState.pageId) {
        showPublishError('페이지를 찾을 수 없습니다.');
        return;
    }

    const unpublishBtn = document.getElementById('unpublish-btn');
    if (unpublishBtn) unpublishBtn.disabled = true;

    try {
        const res = await secureFetch(`/api/pages/${encodeURIComponent(publishState.pageId)}/publish`, {
            method: 'DELETE'
        });

        if (!res.ok) {
            const error = await res.json();
            throw new Error(error.error || '발행 취소 실패');
        }

        publishState.token = null;
        publishState.url = null;
        publishState.published = false;

        const beforeContent = document.getElementById('publish-before-content');
        const afterContent = document.getElementById('publish-after-content');
        beforeContent.style.display = 'block';
        afterContent.style.display = 'none';

        updatePublishButton();

        console.log('발행 취소 완료');
    } catch (error) {
        console.error('발행 취소 오류:', error);
        showPublishError(error.message || '발행 취소에 실패했습니다.');
    } finally {
        if (unpublishBtn) unpublishBtn.disabled = false;
    }
}

export async function copyPublishLink() {
    if (!publishState.url) {
        showPublishError('복사할 링크가 없습니다.');
        return;
    }

    try {
        await navigator.clipboard.writeText(publishState.url);

        const copyBtn = document.getElementById('copy-publish-link-btn');
        if (copyBtn) {
            const originalText = copyBtn.innerHTML;
            copyBtn.innerHTML = '<i class="fa-solid fa-check"></i> 복사됨';
            copyBtn.disabled = true;

            setTimeout(() => {
                copyBtn.innerHTML = originalText;
                copyBtn.disabled = false;
            }, 2000);
        }
    } catch (error) {
        console.error('클립보드 복사 오류:', error);
        showPublishError('링크 복사에 실패했습니다.');
    }
}

function showPublishError(message) {
    const errorDiv = document.getElementById('publish-error');
    if (errorDiv) {
        errorDiv.textContent = message;
    }
}

export function bindPublishEvents() {
    const publishBtn = document.getElementById('publish-btn');
    if (publishBtn) {
        publishBtn.addEventListener('click', () => {
            if (publishState.published) {
                openPublishModal();
            } else {
                openPublishModal();
            }
        });
    }

    const closeBtn = document.getElementById('close-publish-modal-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', closePublishModal);
    }

    const modal = document.getElementById('page-publish-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.classList.contains('modal-overlay')) {
                closePublishModal();
            }
        });
    }

    const cancelBtn = document.getElementById('cancel-publish-btn');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closePublishModal);
    }

    const confirmBtn = document.getElementById('confirm-publish-btn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', publishPage);
    }

    const unpublishBtn = document.getElementById('unpublish-btn');
    if (unpublishBtn) {
        unpublishBtn.addEventListener('click', unpublishPage);
    }

    const copyBtn = document.getElementById('copy-publish-link-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyPublishLink);
    }

    const closeSuccessBtn = document.getElementById('close-publish-success-btn');
    if (closeSuccessBtn) {
        closeSuccessBtn.addEventListener('click', closePublishModal);
    }
    
    const allowCommentsCheckbox = document.getElementById('publish-allow-comments');
    if (allowCommentsCheckbox) {
        allowCommentsCheckbox.addEventListener('change', updatePublishSettings);
    }
}
