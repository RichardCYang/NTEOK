/**
 * 페이지 발행 관리 모듈
 */

import { secureFetch } from './ui-utils.js';

// 전역 상태
let state = null;
const publishState = {
    pageId: null,
    token: null,
    url: null,
    published: false,
    allowComments: false
};

/**
 * 발행 관리자 초기화
 */
export function initPublishManager(appState) {
    state = appState;
}

/**
 * 페이지 발행 상태 확인
 */
export async function checkPublishStatus(pageId) {
    if (!pageId) return;

    try {
        const res = await fetch(`/api/pages/${encodeURIComponent(pageId)}/publish`);
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

/**
 * 발행 버튼 업데이트 (표시/숨김 및 텍스트 변경)
 */
export function updatePublishButton() {
    const publishBtn = document.getElementById('publish-btn');
    const publishBtnText = document.getElementById('publish-btn-text');

    if (!publishBtn) return;

    // 쓰기 모드일 때는 숨김
    if (state?.isWriteMode) {
        publishBtn.style.display = 'none';
        return;
    }

    // 읽기 모드일 때
    // 암호화된 페이지는 숨김
    if (state?.currentPageIsEncrypted) {
        publishBtn.style.display = 'none';
        return;
    }

    // 평문 페이지는 표시
    publishBtn.style.display = 'flex';

    // 발행 상태에 따라 버튼 텍스트 및 클래스 변경
    if (publishState.published) {
        publishBtnText.textContent = '발행 취소';
        publishBtn.classList.add('published');
    } else {
        publishBtnText.textContent = '발행';
        publishBtn.classList.remove('published');
    }
}

/**
 * 발행 모달 열기
 */
export function openPublishModal() {
    const modal = document.getElementById('page-publish-modal');
    const beforeContent = document.getElementById('publish-before-content');
    const afterContent = document.getElementById('publish-after-content');
    const errorDiv = document.getElementById('publish-error');

    if (!modal) return;

    // 상태 초기화
    errorDiv.textContent = '';

    if (publishState.published) {
        // 이미 발행됨: 발행 후 화면 표시
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
        // 발행되지 않음: 발행 전 화면 표시
        beforeContent.style.display = 'block';
        afterContent.style.display = 'none';
        
        // 기본값 초기화 (원하면 여기서 false로)
        const allowCommentsCheckbox = document.getElementById('publish-allow-comments-before');
        if (allowCommentsCheckbox) {
            allowCommentsCheckbox.checked = false;
        }
    }

    modal.classList.remove('hidden');
}

/**
 * 발행 모달 닫기
 */
export function closePublishModal() {
    const modal = document.getElementById('page-publish-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

/**
 * 페이지 발행 (또는 설정 업데이트)
 */
export async function publishPage() {
    if (!publishState.pageId) {
        showPublishError('페이지를 찾을 수 없습니다.');
        return;
    }

    const beforeContent = document.getElementById('publish-before-content');
    const afterContent = document.getElementById('publish-after-content');
    const confirmBtn = document.getElementById('confirm-publish-btn');
    
    // 발행 전 화면에서 체크박스 값 가져오기
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

        // UI 업데이트
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

        // 버튼 상태 업데이트
        updatePublishButton();

        console.log('페이지 발행 완료:', data.url);
    } catch (error) {
        console.error('발행 오류:', error);
        showPublishError(error.message || '발행에 실패했습니다.');
    } finally {
        if (confirmBtn) confirmBtn.disabled = false;
    }
}

/**
 * 발행 설정 업데이트 (이미 발행된 상태에서 체크박스 변경 시)
 */
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
        // 실패 시 체크박스 원복?
        if (allowCommentsCheckbox) {
            allowCommentsCheckbox.checked = !allowComments;
        }
    }
}

/**
 * 발행 취소
 */
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

        // UI 업데이트
        const beforeContent = document.getElementById('publish-before-content');
        const afterContent = document.getElementById('publish-after-content');
        beforeContent.style.display = 'block';
        afterContent.style.display = 'none';

        // 버튼 상태 업데이트
        updatePublishButton();

        console.log('발행 취소 완료');
    } catch (error) {
        console.error('발행 취소 오류:', error);
        showPublishError(error.message || '발행 취소에 실패했습니다.');
    } finally {
        if (unpublishBtn) unpublishBtn.disabled = false;
    }
}

/**
 * 공유 링크 복사
 */
export async function copyPublishLink() {
    if (!publishState.url) {
        showPublishError('복사할 링크가 없습니다.');
        return;
    }

    try {
        await navigator.clipboard.writeText(publishState.url);

        // 성공 피드백
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

/**
 * 에러 메시지 표시
 */
function showPublishError(message) {
    const errorDiv = document.getElementById('publish-error');
    if (errorDiv) {
        errorDiv.textContent = message;
    }
}

/**
 * 이벤트 바인딩
 */
export function bindPublishEvents() {
    // 발행 버튼 클릭
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

    // 모달 닫기 버튼
    const closeBtn = document.getElementById('close-publish-modal-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', closePublishModal);
    }

    // 모달 오버레이 클릭 시 닫기
    const modal = document.getElementById('page-publish-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal || e.target.classList.contains('modal-overlay')) {
                closePublishModal();
            }
        });
    }

    // 발행 전: 취소 버튼
    const cancelBtn = document.getElementById('cancel-publish-btn');
    if (cancelBtn) {
        cancelBtn.addEventListener('click', closePublishModal);
    }

    // 발행 전: 발행하기 버튼
    const confirmBtn = document.getElementById('confirm-publish-btn');
    if (confirmBtn) {
        confirmBtn.addEventListener('click', publishPage);
    }

    // 발행 후: 발행 취소 버튼
    const unpublishBtn = document.getElementById('unpublish-btn');
    if (unpublishBtn) {
        unpublishBtn.addEventListener('click', unpublishPage);
    }

    // 발행 후: 링크 복사 버튼
    const copyBtn = document.getElementById('copy-publish-link-btn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyPublishLink);
    }

    // 발행 후: 완료 버튼
    const closeSuccessBtn = document.getElementById('close-publish-success-btn');
    if (closeSuccessBtn) {
        closeSuccessBtn.addEventListener('click', closePublishModal);
    }
    
    // 발행 후: 댓글 허용 체크박스 변경
    const allowCommentsCheckbox = document.getElementById('publish-allow-comments');
    if (allowCommentsCheckbox) {
        allowCommentsCheckbox.addEventListener('change', updatePublishSettings);
    }
}
