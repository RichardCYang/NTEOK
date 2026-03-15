import { secureFetch, escapeHtml } from './ui-utils.js';
import { setTrustedHTML, createFragmentFromTrustedHTML } from './sanitize.js';

function safeSetInnerHTML(element, html) {
    setTrustedHTML(element, html);
}

function safeCreateElementFromHTML(html) {
    return createFragmentFromTrustedHTML(html);
}

const state = {
    pageId: null,
    comments: [],
    isVisible: true,
    currentUser: null,
    isExpanded: false
};

export function initCommentsManager(appState) {
    state.currentUser = appState.currentUser;
}

export async function loadAndRenderComments(pageId, containerId = 'page-comments-section') {
    state.pageId = pageId;
    const container = document.getElementById(containerId);
    if (!container) return;

    try {
        const res = await secureFetch(`/api/comments/${pageId}`);

        if (res.status === 403 || res.status === 404) {
            while (container.firstChild) container.removeChild(container.firstChild);
            container.classList.add('hidden');
            return;
        }

        if (!res.ok) throw new Error('댓글 로드 실패');

        state.comments = await res.json();
        container.classList.remove('hidden');
        renderComments(container);
    } catch (error) {
        console.error('댓글 로드 오류:', error);
        container.classList.add('hidden');
    }
}

function renderComments(container) {
    while (container.firstChild) container.removeChild(container.firstChild);
    
    const wrapper = document.createElement('div');
    wrapper.className = `comments-wrapper ${state.isExpanded ? 'expanded' : ''}`;
    
    const count = state.comments.length;
    
    if (!state.isExpanded) {
        const toggleBtn = document.createElement('button');
        toggleBtn.className = 'comment-toggle-btn';
        
        const icon = document.createElement('i');
        icon.className = 'fa-regular fa-comment';
        toggleBtn.appendChild(icon);
        
        const text = document.createTextNode(count === 0 ? ' 댓글 추가' : ` 댓글 ${count}개`);
        toggleBtn.appendChild(text);
        
        toggleBtn.addEventListener('click', () => {
            state.isExpanded = true;
            renderComments(container);
        });
        
        wrapper.appendChild(toggleBtn);
    } else {
        const commentsBody = document.createElement('div');
        commentsBody.className = 'comments-body';
        
        const headerRow = document.createElement('div');
        headerRow.className = 'comments-header-row';
        
        const title = document.createElement('div');
        title.className = 'comments-title-expanded';
        title.textContent = '댓글';
        headerRow.appendChild(title);
        
        const closeBtn = document.createElement('button');
        closeBtn.className = 'close-comments-btn';
        closeBtn.title = '접기';
        
        const closeIcon = document.createElement('i');
        closeIcon.className = 'fa-solid fa-angle-up';
        closeBtn.appendChild(closeIcon);
        headerRow.appendChild(closeBtn);
        
        commentsBody.appendChild(headerRow);
        
        const commentsList = document.createElement('div');
        commentsList.className = 'comments-list';
        
        state.comments.forEach(comment => {
            const commentElement = createCommentItem(comment);
            commentsList.appendChild(commentElement);
        });
        
        const newCommentElement = createNewCommentBlock();
        commentsList.appendChild(newCommentElement);
        
        commentsBody.appendChild(commentsList);
        wrapper.appendChild(commentsBody);
        
        bindEvents(container);
    }
    
    container.appendChild(wrapper);
}

function createNewCommentBlock() {
    const commentItem = document.createElement('div');
    commentItem.className = 'comment-item new-comment-item';
    
    const avatarDiv = document.createElement('div');
    avatarDiv.className = 'comment-avatar';
    
    if (state.currentUser) {
        const initial = state.currentUser.username.charAt(0).toUpperCase();
        avatarDiv.textContent = initial;
    } else {
        const icon = document.createElement('i');
        icon.className = 'fa-regular fa-user';
        avatarDiv.appendChild(icon);
    }
    
    commentItem.appendChild(avatarDiv);
    
    const contentWrapper = document.createElement('div');
    contentWrapper.className = 'comment-content-wrapper';
    
    const metaDiv = document.createElement('div');
    metaDiv.className = 'comment-meta';
    
    const authorSpan = document.createElement('span');
    authorSpan.className = 'comment-author';
    authorSpan.textContent = state.currentUser ? state.currentUser.username : 'Anonymous';
    metaDiv.appendChild(authorSpan);
    
    contentWrapper.appendChild(metaDiv);
    
    const newCommentWrapper = document.createElement('div');
    newCommentWrapper.className = 'new-comment-block-wrapper';
    
    const inputRow = document.createElement('div');
    inputRow.className = 'comment-input-row-block';
    
    const textarea = document.createElement('textarea');
    textarea.id = 'new-comment-input';
    textarea.placeholder = '댓글을 추가해보세요...';
    textarea.rows = 1;
    inputRow.appendChild(textarea);
    
    const submitBtn = document.createElement('button');
    submitBtn.id = 'submit-comment-btn';
    submitBtn.className = 'comment-send-btn-block';
    submitBtn.disabled = true;
    
    const submitIcon = document.createElement('i');
    submitIcon.className = 'fa-solid fa-arrow-up';
    submitBtn.appendChild(submitIcon);
    inputRow.appendChild(submitBtn);
    
    newCommentWrapper.appendChild(inputRow);
    contentWrapper.appendChild(newCommentWrapper);
    commentItem.appendChild(contentWrapper);
    
    return commentItem;
}

function bindEvents(container) {
    const closeBtn = container.querySelector('.close-comments-btn');
    if (closeBtn) closeBtn.addEventListener('click', () => {
        state.isExpanded = false;
        state.editingCommentId = null;
        renderComments(container);
    });

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
        if (nameInput) nameInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                input.focus();
            }
        });
    }

    if (submitBtn) submitBtn.addEventListener('click', submitComment);

    container.querySelectorAll('.delete-comment-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const commentId = e.target.closest('button').dataset.commentId;
            deleteComment(commentId);
        });
    });
}

function createCommentItem(comment) {
    const timeAgo = formatTimeAgo(new Date(comment.createdAt));
    const initial = comment.author ? comment.author.charAt(0).toUpperCase() : '?';
    const canDelete = comment.isMyComment;
    
    const commentItem = document.createElement('div');
    commentItem.className = 'comment-item';
    commentItem.id = `comment-${comment.id}`;
    
    const avatarDiv = document.createElement('div');
    avatarDiv.className = 'comment-avatar';
    avatarDiv.textContent = initial;
    commentItem.appendChild(avatarDiv);
    
    const contentWrapper = document.createElement('div');
    contentWrapper.className = 'comment-content-wrapper';
    
    const metaDiv = document.createElement('div');
    metaDiv.className = 'comment-meta';
    
    const authorSpan = document.createElement('span');
    authorSpan.className = 'comment-author';
    authorSpan.textContent = comment.author || 'Guest';
    metaDiv.appendChild(authorSpan);
    
    const dateSpan = document.createElement('span');
    dateSpan.className = 'comment-date';
    dateSpan.textContent = timeAgo;
    metaDiv.appendChild(dateSpan);
    
    if (canDelete) {
        const deleteBtn = document.createElement('button');
        deleteBtn.className = 'delete-comment-btn';
        deleteBtn.dataset.commentId = comment.id;
        deleteBtn.title = '삭제';
        
        const deleteIcon = document.createElement('i');
        deleteIcon.className = 'fa-solid fa-xmark';
        deleteBtn.appendChild(deleteIcon);
        metaDiv.appendChild(deleteBtn);
    }
    
    contentWrapper.appendChild(metaDiv);
    
    const textDiv = document.createElement('div');
    textDiv.className = 'comment-text';
    
    const lines = comment.content.split('\n');
    lines.forEach((line, index) => {
        if (index > 0) {
            textDiv.appendChild(document.createElement('br'));
        }
        textDiv.appendChild(document.createTextNode(line));
    });
    
    contentWrapper.appendChild(textDiv);
    commentItem.appendChild(contentWrapper);
    
    return commentItem;
}

async function submitComment() {
    const input = document.getElementById('new-comment-input');
    const content = input.value.trim();
    if (!content) return;
    const submitBtn = document.getElementById('submit-comment-btn');
    if (submitBtn) {
        submitBtn.disabled = true;
    }
    try {
        const body = { content };
        const res = await secureFetch(`/api/comments/${state.pageId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!res.ok) throw new Error('댓글 작성 실패');
        await loadAndRenderComments(state.pageId, 'page-comments-section');
    } catch (error) {
        console.error('댓글 작성 오류:', error);
        alert('댓글을 등록하지 못했습니다.');
        if (submitBtn) {
            submitBtn.disabled = false;
        }
    }
}

async function deleteComment(commentId) {
    if (!confirm('댓글을 삭제하시겠습니까?')) return;
    try {
        const res = await secureFetch(`/api/comments/${commentId}`, { method: 'DELETE' });
        if (!res.ok) throw new Error('삭제 실패');
        const el = document.getElementById(`comment-${commentId}`);
        if (el) {
            el.remove();
            state.comments = state.comments.filter(c => c.id != commentId);
            const titleEl = document.querySelector('.comments-title span');
            if (titleEl) titleEl.textContent = `댓글 ${state.comments.length}`;
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