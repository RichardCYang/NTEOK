/**
 * 컬렉션 공유 관리 모듈
 */

import { secureFetch, escapeHtml, escapeHtmlAttr } from './ui-utils.js';

// 전역 상태
let currentSharingCollectionId = null;

/**
 * 공유 모달 열기
 */
export function openShareModal(collectionId) {
    currentSharingCollectionId = collectionId;
    const modal = document.querySelector("#share-collection-modal");
    if (modal) {
        modal.classList.remove("hidden");
        loadShareList(collectionId);
    }
}

/**
 * 공유 모달 닫기
 */
export function closeShareModal() {
    const modal = document.querySelector("#share-collection-modal");
    if (modal) {
        modal.classList.add("hidden");
    }
    currentSharingCollectionId = null;
}

/**
 * 사용자 공유 목록 로드
 */
export async function loadShareList(collectionId) {
    try {
        const res = await fetch(`/api/collections/${encodeURIComponent(collectionId)}/shares`);
        if (!res.ok) throw new Error("HTTP " + res.status);

        const shares = await res.json();
        const listEl = document.querySelector("#share-list");

        if (!listEl) return;

        if (shares.length === 0) {
            listEl.innerHTML = '<div style="color: #6b7280; font-size: 13px;">공유 중인 사용자가 없습니다.</div>';
            return;
        }

        listEl.innerHTML = shares.map(share => `
            <div class="share-item">
                <div class="share-item-info">
                    <div class="share-item-username">${escapeHtml(share.username)}</div>
                    <div class="share-item-permission">${escapeHtml(share.permission)}</div>
                </div>
                <div class="share-item-actions">
                    <button class="danger-button remove-share-btn" data-collection-id="${escapeHtmlAttr(collectionId)}" data-share-id="${escapeHtmlAttr(share.id)}" style="padding: 4px 8px; font-size: 12px;">
                        삭제
                    </button>
                </div>
            </div>
        `).join('');

        listEl.querySelectorAll('.remove-share-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const colId = btn.dataset.collectionId;
                const shareId = btn.dataset.shareId;
                await removeShare(colId, shareId);
            });
        });
    } catch (error) {
        console.error("공유 목록 로드 오류:", error);
    }
}


/**
 * 사용자에게 공유하기
 */
export async function handleShareUser(event) {
    event.preventDefault();

    const usernameInput = document.querySelector("#share-username");
    const permissionSelect = document.querySelector("#share-permission");
    const errorEl = document.querySelector("#share-error");

    if (!usernameInput || !permissionSelect || !errorEl) return;

    const username = usernameInput.value.trim();
    const permission = permissionSelect.value;

    errorEl.textContent = "";

    if (!username) {
        errorEl.textContent = "사용자명을 입력해 주세요.";
        return;
    }

    try {
        const res = await secureFetch(`/api/collections/${encodeURIComponent(currentSharingCollectionId)}/shares`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, permission })
        });

        if (!res.ok) {
            const error = await res.json();
            throw new Error(error.error || "공유 실패");
        }

        usernameInput.value = "";
        await loadShareList(currentSharingCollectionId);
        alert("공유가 완료되었습니다.");
    } catch (error) {
        console.error("공유 오류:", error);
        errorEl.textContent = error.message;
    }
}


/**
 * 사용자 공유 삭제
 */
export async function removeShare(collectionId, shareId) {
    if (!confirm("이 공유를 삭제하시겠습니까?")) return;

    try {
        const res = await secureFetch(`/api/collections/${encodeURIComponent(collectionId)}/shares/${shareId}`, {
            method: "DELETE"
        });

        if (!res.ok) throw new Error("HTTP " + res.status);

        await loadShareList(collectionId);
    } catch (error) {
        console.error("공유 삭제 오류:", error);
        alert("공유 삭제 중 오류가 발생했습니다.");
    }
}


/**
 * 공유 모달 이벤트 바인딩
 */
export function bindShareModal() {
    const closeBtn = document.querySelector("#close-share-modal-btn");
    const userForm = document.querySelector("#share-user-form");

    if (closeBtn) {
        closeBtn.addEventListener("click", closeShareModal);
    }

    if (userForm) {
        userForm.addEventListener("submit", handleShareUser);
    }
}
