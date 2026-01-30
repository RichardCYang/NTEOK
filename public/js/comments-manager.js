import { secureFetch, escapeHtml } from './ui-utils.js';

// 상태 관리
const state = {
	pageId: null,
    shareToken: null,
    comments: [],
    isVisible: true,
    currentUser: null,
    isExpanded: false // 댓글 섹션 펼침 여부
};

// 초기화
export function initCommentsManager(appState) {
    state.currentUser = appState.currentUser;
}

// 댓글 섹션 렌더링
export async function loadAndRenderComments(pageId, containerId = 'page-comments-section', shareToken = null) {
	state.pageId = pageId;
    state.shareToken = shareToken;
    const container = document.getElementById(containerId);
    if (!container) return;

    // 초기화: 로딩 중에는 아무것도 표시하지 않거나 로딩 인디케이터 표시
    // 노션 스타일: 상단에 조그만 버튼만 보이게 하려면 로딩 중에도 버튼 형태가 나을 수 있음
    // 여기서는 데이터 로드 후 렌더링

    try {
    	const endpoint = shareToken ? `/api/comments/shared/${encodeURIComponent(shareToken)}` : `/api/comments/${pageId}`;
        const res = await secureFetch(endpoint);

        // 403 Forbidden 등 에러 처리
        if (res.status === 403 || res.status === 404) {
	        container.innerHTML = '';
	        container.classList.add('hidden');
	        return;
        }

        if (!res.ok) {
            throw new Error('댓글 로드 실패');
        }

        state.comments = await res.json();
        container.classList.remove('hidden');
        renderComments(container);

    } catch (error) {
        console.error('댓글 로드 오류:', error);
        // 에러 시 숨김
        container.classList.add('hidden');
    }
}

// 댓글 목록 렌더링
function renderComments(container) {
    const count = state.comments.length;

    // 토글 버튼 텍스트
    let toggleText = '';
    if (count === 0) {
        toggleText = '<i class="fa-regular fa-comment"></i> 댓글 추가';
    } else {
        toggleText = `<i class="fa-regular fa-comment"></i> 댓글 ${count}개`;
    }

    // 펼쳐졌을 때의 UI
    let bodyHtml = '';
    if (state.isExpanded) {
        // 기존 댓글 목록 HTML
        const commentsHtml = state.comments.map(comment => renderCommentItem(comment)).join('');

        // 입력 블록 HTML (마지막에 추가)
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

    // 이벤트 바인딩
    if (state.isExpanded) {
        bindEvents(container);
    } else {
        // 토글 버튼 클릭 (펼치기)
        const toggleBtn = container.querySelector('.comment-toggle-btn');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', () => {
                state.isExpanded = true;
                renderComments(container);
            });
        }
    }
}

// 새 댓글 입력 블록 HTML 생성
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

// 이벤트 바인딩 분리
function bindEvents(container) {
    // 접기 버튼
    const closeBtn = container.querySelector('.close-comments-btn');
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            state.isExpanded = false;
            state.editingCommentId = null;
            renderComments(container);
        });
    }

    // 새 댓글 입력창
    const input = container.querySelector('#new-comment-input');
    const submitBtn = container.querySelector('#submit-comment-btn');
    const nameInput = container.querySelector('#guest-name-input');

    if (input) {
        // 초기 포커스: 댓글이 없으면 바로 포커스, 있으면 사용자가 클릭해야 함 (여기선 자동 포커스 끔)
        // input.focus();

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

    // 기존 댓글 액션 (삭제, 수정)
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

    // 수정 모드: 저장/취소
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

    // 수정 텍스트에어리어 자동 높이
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
        // 포커스 및 커서 끝으로
        textarea.focus();
        textarea.setSelectionRange(textarea.value.length, textarea.value.length);
    });
}

// 개별 댓글 렌더링
function renderCommentItem(comment) {
    // 시간 포맷 (상대 시간)
    const timeAgo = formatTimeAgo(new Date(comment.createdAt));

    // 아바타: 이니셜 (게스트인 경우 아이콘 사용 고려 가능하나, 일관성을 위해 이니셜/물음표 사용)
    const initial = comment.author ? comment.author.charAt(0).toUpperCase() : '?';

    // 내 댓글 여부: API에서 isMyComment를 보내주므로 그것을 사용
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

// 댓글 등록
async function submitComment() {
    const input = document.getElementById('new-comment-input');
    const nameInput = document.getElementById('guest-name-input');
    const content = input.value.trim();
    const guestName = nameInput ? nameInput.value.trim() : null;

    if (!content) return;

    // 버튼 비활성화
    const submitBtn = document.getElementById('submit-comment-btn');
    if (submitBtn) {
        submitBtn.textContent = '등록 중...';
        submitBtn.disabled = true;
    }

    try {
        const body = { content, guestName };
		const endpoint = state.shareToken ? `/api/comments/shared/${encodeURIComponent(state.shareToken)}` : `/api/comments/${state.pageId}`;
		const res = await secureFetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!res.ok) {
            throw new Error('댓글 작성 실패');
        }

        // 재로드
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

// 댓글 삭제
async function deleteComment(commentId) {
    if (!confirm('댓글을 삭제하시겠습니까?')) return;

    try {
        const res = await secureFetch(`/api/comments/${commentId}`, {
            method: 'DELETE'
        });

        if (!res.ok) {
            throw new Error('삭제 실패');
        }

        // UI에서 제거 (부드럽게)
        const el = document.getElementById(`comment-${commentId}`);
        if (el) {
            el.remove();
            // 데이터 갱신
            state.comments = state.comments.filter(c => c.id != commentId);
            // 카운트 갱신
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

// 유틸: 상대 시간 포맷 (간단 구현)
function formatTimeAgo(date) {
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);

    if (diffInSeconds < 60) return '방금 전';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}분 전`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}시간 전`;
    if (diffInSeconds < 604800) return `${Math.floor(diffInSeconds / 86400)}일 전`;

    // 그 외는 날짜 표시
    return date.toLocaleDateString();
}