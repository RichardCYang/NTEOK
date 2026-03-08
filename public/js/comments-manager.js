import { secureFetch, escapeHtml } from './ui-utils.js';

const state = {
	pageId: null,
    shareToken: null,
    sharedCsrfToken: null,
    comments: [],
    isVisible: true,
    currentUser: null,
    isExpanded: false 
};

export function initCommentsManager(appState) {
    state.currentUser = appState.currentUser;
}

export async function loadAndRenderComments(pageId, containerId = 'page-comments-section', shareToken = null) {
	state.pageId = pageId;
    state.shareToken = shareToken;
    const container = document.getElementById(containerId);
    if (!container) return;


	try {
    	const endpoint = shareToken ? `/api/comments/shared/${encodeURIComponent(shareToken)}` : `/api/comments/${pageId}`;
        const res = await secureFetch(endpoint);

        if (res.status === 403 || res.status === 404) {
	        container.innerHTML = '';
	        container.classList.add('hidden');
	        return;
        }

        if (!res.ok) {
            throw new Error('댓글 로드 실패');
        }

        const payload = await res.json();
        if (Array.isArray(payload)) {
            state.comments = payload;
            state.sharedCsrfToken = null;
        } else {
            state.comments = payload.comments || [];
            state.sharedCsrfToken = payload.csrfToken || null;
        }
        container.classList.remove('hidden');
        renderComments(container);

    } catch (error) {
        console.error('댓글 로드 오류:', error);
        container.classList.add('hidden');
    }

        if (!res.ok) {
            throw new Error('댓글 로드 실패');
        }

        const payload = await res.json();
        if (Array.isArray(payload)) {
            state.comments = payload;
            state.sharedCsrfToken = null;
        } else {
            state.comments = payload.comments || [];
            state.sharedCsrfToken = payload.csrfToken || null;
        }
        container.classList.remove('hidden');
        renderComments(container);

    } catch (error) {
        console.error('댓글 로드 오류:', error);
        container.classList.add('hidden');
    }
}

function renderComments(container) {
    const count = state.comments.length;

    let toggleText = '';
    if (count === 0) {
        toggleText = '<i class="fa-regular fa-comment"></i> 댓글 추가';
    } else {
        toggleText = `<i class="fa-regular fa-comment"></i> 댓글 ${count}개`;
    }

    let bodyHtml = '';
    if (state.isExpanded) {
        const commentsHtml = state.comments.map(comment => renderCommentItem(comment)).join('');

        const inputBlockHtml = renderNewCommentBlock();

        bodyHtml = `
            <div class="comments-body">
                <div class="comments-header-row">
                    <div class="comments-title-expanded">댓글</div>
                    <button class="close-comments-btn" title="접기">
                        <i class="fa-solid fa-angle-up"></i>
                    </button>
                </div>

                <div class="comments-list">
                    ${commentsHtml}
                    ${inputBlockHtml}
                </div>
            </div>
        `;
    }

    container.innerHTML = `
        <div class="comments-wrapper ${state.isExpanded ? 'expanded' : ''}">
            ${!state.isExpanded ? `
                <button class="comment-toggle-btn">
                    ${toggleText}
                </button>
            ` : ''}
            ${bodyHtml}
        </div>
    `;

    if (state.isExpanded) {
        bindEvents(container);
    } else {
        const toggleBtn = container.querySelector('.comment-toggle-btn');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                state.isExpanded = true;
                renderComments(container);
            });
        }
    }
}

function renderNewCommentBlock() {
    const showNameInput = !state.currentUser;

    let avatarContent;
    if (state.currentUser) {
        avatarContent = escapeHtml(state.currentUser.username.charAt(0).toUpperCase());
    } else {
        avatarContent = '<i class="fa-regular fa-user"></i>';
    }

    const authorName = state.currentUser ? state.currentUser.username : (showNameInput ? 'Guest' : 'Anonymous');

    return `
        <div class="comment-item new-comment-item">
            <div class="comment-avatar">${avatarContent}</div>
            <div class="comment-content-wrapper">
                <div class="comment-meta">
                    <span class="comment-author">${escapeHtml(authorName)}</span>
                </div>
                <div class="new-comment-block-wrapper">
                    ${showNameInput ? `
                    <input type="text" id="guest-name-input" placeholder="이름 (선택)" class="comment-guest-name-block">
                    ` : ''}
                    <div class="comment-input-row-block">
                        <textarea id="new-comment-input" placeholder="댓글을 추가해보세요..." rows="1"></textarea>
                        <button id="submit-comment-btn" class="comment-send-btn-block" disabled>
                            <i class="fa-solid fa-arrow-up"></i>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function bindEvents(container) {
    const closeBtn = container.querySelector('.close-comments-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            state.isExpanded = false;
            state.editingCommentId = null;
            renderComments(container);
        });
    }

    const input = container.querySelector('#new-comment-input');
    const submitBtn = container.querySelector('#submit-comment-btn');
    const nameInput = container.querySelector('#guest-name-input');

    if (input) {

        input.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';

            if (this.value.trim().length > 0) {
                submitBtn.removeAttribute('disabled');
                submitBtn.classList.add('active');
            } else {
                submitBtn.setAttribute('disabled', 'true');
                submitBtn.classList.remove('active');
            }
        });

        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                submitComment();
            }
        });

        if (nameInput) {
            nameInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    e.preventDefault();
                    input.focus();
                }
            });
        }
    }

    if (submitBtn) {
        submitBtn.addEventListener('click', submitComment);
    }

    container.querySelectorAll('.delete-comment-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const commentId = e.target.closest('button').dataset.commentId;
            deleteComment(commentId);
        });
    });

    container.querySelectorAll('.edit-comment-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const commentId = e.target.closest('button').dataset.commentId;
            startEditing(commentId);
        });
    });

    container.querySelectorAll('.save-edit-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const commentId = e.target.closest('button').dataset.commentId;
            saveEdit(commentId);
        });
    });

    container.querySelectorAll('.cancel-edit-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            cancelEditing();
        });
    });

    container.querySelectorAll('.edit-comment-textarea').forEach(textarea => {
        textarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
        textarea.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                const commentId = e.target.dataset.commentId;
                saveEdit(commentId);
            } else if (e.key === 'Escape') {
                cancelEditing();
            }
        });
        textarea.focus();
        textarea.setSelectionRange(textarea.value.length, textarea.value.length);
    });
}

function renderCommentItem(comment) {
    const timeAgo = formatTimeAgo(new Date(comment.createdAt));

    const initial = comment.author ? comment.author.charAt(0).toUpperCase() : '?';

    const canDelete = comment.isMyComment;

    return `
        <div class="comment-item" id="comment-${comment.id}">
            <div class="comment-avatar">${escapeHtml(initial)}</div>
            <div class="comment-content-wrapper">
                <div class="comment-meta">
                    <span class="comment-author">${escapeHtml(comment.author || 'Guest')}</span>
                    <span class="comment-date">${timeAgo}</span>
                    ${canDelete ? `
                        <button class="delete-comment-btn" data-comment-id="${comment.id}" title="삭제">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    ` : ''}
                </div>
                <div class="comment-text">${escapeHtml(comment.content).replace(/\n/g, '<br>')}</div>
            </div>
        </div>
    `;
}

async function submitComment() {
    const input = document.getElementById('new-comment-input');
    const nameInput = document.getElementById('guest-name-input');
    const content = input.value.trim();
    const guestName = nameInput ? nameInput.value.trim() : null;

    if (!content) return;

    const submitBtn = document.getElementById('submit-comment-btn');
    if (submitBtn) {
        submitBtn.textContent = '등록 중...';
        submitBtn.disabled = true;
    }

    try {
        const body = { content, guestName };
		const endpoint = state.shareToken ? `/api/comments/shared/${encodeURIComponent(state.shareToken)}` : `/api/comments/${state.pageId}`;
		const headers = { 'Content-Type': 'application/json' };
        if (state.shareToken && state.sharedCsrfToken) {
            headers['X-Shared-CSRF-Token'] = state.sharedCsrfToken;
        }

		const res = await secureFetch(endpoint, {
            method: 'POST',
            headers,
            body: JSON.stringify(body)
        });

        if (!res.ok) {
            throw new Error('댓글 작성 실패');
        }

        await loadAndRenderComments(state.pageId, 'page-comments-section', state.shareToken);
    } catch (error) {
        console.error('댓글 작성 오류:', error);
        alert('댓글을 등록하지 못했습니다.');
        if (submitBtn) {
            submitBtn.textContent = '등록';
            submitBtn.disabled = false;
        }
    }
}

async function deleteComment(commentId) {
    if (!confirm('댓글을 삭제하시겠습니까?')) return;

    try {
        const res = await secureFetch(`/api/comments/${commentId}`, {
            method: 'DELETE'
        });

        if (!res.ok) {
            throw new Error('삭제 실패');
        }

        const el = document.getElementById(`comment-${commentId}`);
        if (el) {
            el.remove();
            state.comments = state.comments.filter(c => c.id != commentId);
            const titleEl = document.querySelector('.comments-title span');
            if (titleEl) {
                titleEl.textContent = `댓글 ${state.comments.length}`;
            }
        }

    } catch (error) {
        console.error('댓글 삭제 오류:', error);
        alert('댓글을 삭제하지 못했습니다.');
    }
}

function formatTimeAgo(date) {
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);

    if (diffInSeconds < 60) return '방금 전';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}분 전`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}시간 전`;
    if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)}일 전`;

    return date.toLocaleDateString();
}