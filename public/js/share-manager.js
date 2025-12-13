/**
 * 컬렉션 공유 관리 모듈
 */

import { secureFetch, escapeHtml } from './ui-utils.js';

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
        loadShareLinks(collectionId);
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
                    <div class="share-item-permission">${share.permission}</div>
                </div>
                <div class="share-item-actions">
                    <button class="danger-button remove-share-btn" data-collection-id="${escapeHtml(collectionId)}" data-share-id="${share.id}" style="padding: 4px 8px; font-size: 12px;">
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
 * 공유 링크 목록 로드
 */
export async function loadShareLinks(collectionId) {
    try {
        const res = await fetch(`/api/collections/${encodeURIComponent(collectionId)}/share-links`);
        if (!res.ok) throw new Error("HTTP " + res.status);

        const links = await res.json();
        const listEl = document.querySelector("#link-list");

        if (!listEl) return;

        if (links.length === 0) {
            listEl.innerHTML = '<div style="color: #6b7280; font-size: 13px;">생성된 링크가 없습니다.</div>';
            return;
        }

        listEl.innerHTML = links.map(link => {
            const expiryText = link.expiresAt
                ? `만료: ${new Date(link.expiresAt).toLocaleString()}`
                : '무기한';

            return `
                <div class="link-item">
                    <div class="link-item-url">${escapeHtml(link.url)}</div>
                    <div class="link-item-meta">
                        <span>${link.permission} · ${expiryText}</span>
                        <div style="display: flex; gap: 6px;">
                            <button class="copy-link-btn" data-url="${escapeHtml(link.url)}" style="padding: 4px 8px; font-size: 11px; border: none; background: #2d5f5d; color: white; border-radius: 2px; cursor: pointer;">
                                복사
                            </button>
                            <button class="danger-button remove-link-btn" data-collection-id="${escapeHtml(collectionId)}" data-link-id="${link.id}" style="padding: 4px 8px; font-size: 11px;">
                                삭제
                            </button>
                        </div>
                    </div>
                </div>
            `;
        }).join('');

        listEl.querySelectorAll('.copy-link-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const url = btn.dataset.url;
                copyLinkToClipboard(url);
            });
        });

        listEl.querySelectorAll('.remove-link-btn').forEach(btn => {
            btn.addEventListener('click', async () => {
                const colId = btn.dataset.collectionId;
                const linkId = btn.dataset.linkId;
                await removeShareLink(colId, linkId);
            });
        });
    } catch (error) {
        console.error("링크 목록 로드 오류:", error);
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
 * 공유 링크 생성
 */
export async function handleShareLink(event) {
    event.preventDefault();

    const permissionSelect = document.querySelector("#link-permission");
    const expiresInput = document.querySelector("#link-expires");
    const errorEl = document.querySelector("#link-error");

    if (!permissionSelect || !expiresInput || !errorEl) return;

    const permission = permissionSelect.value;
    const expiresInDays = expiresInput.value ? parseInt(expiresInput.value) : null;

    errorEl.textContent = "";

    try {
        const res = await secureFetch(`/api/collections/${encodeURIComponent(currentSharingCollectionId)}/share-links`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ permission, expiresInDays })
        });

        if (!res.ok) {
            const error = await res.json();
            throw new Error(error.error || "링크 생성 실패");
        }

        expiresInput.value = "";
        await loadShareLinks(currentSharingCollectionId);
        alert("링크가 생성되었습니다.");
    } catch (error) {
        console.error("링크 생성 오류:", error);
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
 * 공유 링크 삭제
 */
export async function removeShareLink(collectionId, linkId) {
    if (!confirm("이 링크를 삭제하시겠습니까?")) return;

    try {
        const res = await secureFetch(`/api/collections/${encodeURIComponent(collectionId)}/share-links/${linkId}`, {
            method: "DELETE"
        });

        if (!res.ok) throw new Error("HTTP " + res.status);

        await loadShareLinks(collectionId);
    } catch (error) {
        console.error("링크 삭제 오류:", error);
        alert("링크 삭제 중 오류가 발생했습니다.");
    }
}

/**
 * 링크 클립보드 복사
 */
export function copyLinkToClipboard(url) {
    navigator.clipboard.writeText(url).then(() => {
        alert("링크가 복사되었습니다!");
    }).catch(err => {
        console.error("복사 실패:", err);
        alert("링크 복사에 실패했습니다.");
    });
}

/**
 * 공유 모달 이벤트 바인딩
 */
export function bindShareModal() {
    const closeBtn = document.querySelector("#close-share-modal-btn");
    const userForm = document.querySelector("#share-user-form");
    const linkForm = document.querySelector("#share-link-form");
    const tabs = document.querySelectorAll(".share-tab");

    if (closeBtn) {
        closeBtn.addEventListener("click", closeShareModal);
    }

    if (userForm) {
        userForm.addEventListener("submit", handleShareUser);
    }

    if (linkForm) {
        linkForm.addEventListener("submit", handleShareLink);
    }

    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            const targetTab = tab.dataset.tab;

            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");

            document.querySelectorAll(".share-tab-content").forEach(content => {
                content.classList.remove("active");
            });

            const targetContent = document.querySelector(`#share-${targetTab}-tab`);
            if (targetContent) {
                targetContent.classList.add("active");
            }
        });
    });
}
