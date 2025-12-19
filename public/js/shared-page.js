/**
 * 공개 페이지 스크립트
 */

/**
 * 북마크 블록 렌더링 함수
 * @param {HTMLElement} container - 렌더링 대상 컨테이너
 */
function renderBookmarks(container) {
    // 북마크 컨테이너 렌더링 (BookmarkContainerBlock)
    container.querySelectorAll('[data-type="bookmark-container"]').forEach((el) => {
        renderBookmarkContainer(el);
    });

    // 독립 북마크 블록 렌더링 (BookmarkBlock)
    container.querySelectorAll('[data-type="bookmark-block"]').forEach((el) => {
        renderBookmarkBlock(el);
    });
}

/**
 * 북마크 컨테이너 렌더링
 */
function renderBookmarkContainer(element) {
    const icon = element.getAttribute('data-icon') || '🔖';
    const title = element.getAttribute('data-title') || '북마크';

    // 기존 내용 백업
    const bookmarks = Array.from(element.querySelectorAll('[data-type="bookmark-block"]')).map(el => ({
        url: el.getAttribute('data-url'),
        title: el.getAttribute('data-title'),
        description: el.getAttribute('data-description'),
        thumbnail: el.getAttribute('data-thumbnail')
    }));

    // 컨테이너 재구성
    element.innerHTML = '';
    element.className = 'bookmark-container-wrapper';
    element.setAttribute('data-type', 'bookmark-container');

    // 헤더
    const header = document.createElement('div');
    header.className = 'bookmark-container-header';

    const titleContainer = document.createElement('div');
    titleContainer.className = 'bookmark-container-title-container';

    const iconEl = document.createElement('div');
    iconEl.className = 'bookmark-container-icon';
    iconEl.textContent = icon;

    const titleEl = document.createElement('div');
    titleEl.className = 'bookmark-container-title';
    titleEl.textContent = title;

    titleContainer.appendChild(iconEl);
    titleContainer.appendChild(titleEl);
    header.appendChild(titleContainer);
    element.appendChild(header);

    // 콘텐츠
    const content = document.createElement('div');
    content.className = 'bookmark-container-content';

    bookmarks.forEach(bookmark => {
        const card = createBookmarkCard(bookmark);
        content.appendChild(card);
    });

    element.appendChild(content);
}

/**
 * 독립 북마크 블록 렌더링
 */
function renderBookmarkBlock(element) {
    const bookmark = {
        url: element.getAttribute('data-url'),
        title: element.getAttribute('data-title'),
        description: element.getAttribute('data-description'),
        thumbnail: element.getAttribute('data-thumbnail')
    };

    const wrapper = document.createElement('div');
    wrapper.className = 'bookmark-block-wrapper';
    const card = createBookmarkCard(bookmark);
    wrapper.appendChild(card);

    element.replaceWith(wrapper);
}

/**
 * 북마크 카드 생성
 */
function createBookmarkCard(bookmark) {
    const card = document.createElement('a');
    card.className = 'bookmark-card';
    card.href = bookmark.url || '#';
    card.target = '_blank';
    card.rel = 'noopener noreferrer';
    card.style.color = 'inherit';

    // 텍스트 정보
    const textContainer = document.createElement('div');
    textContainer.className = 'bookmark-text';

    const titleElement = document.createElement('div');
    titleElement.className = 'bookmark-title';
    titleElement.textContent = bookmark.title || bookmark.url || '제목 없음';

    const descElement = document.createElement('div');
    descElement.className = 'bookmark-description';
    descElement.textContent = bookmark.description || '';

    const urlContainer = document.createElement('div');
    urlContainer.className = 'bookmark-url';
    urlContainer.textContent = bookmark.url || '';

    textContainer.appendChild(titleElement);
    if (bookmark.description) {
        textContainer.appendChild(descElement);
    }
    textContainer.appendChild(urlContainer);

    card.appendChild(textContainer);

    // 썸네일
    const thumbnailContainer = document.createElement('div');
    thumbnailContainer.className = 'bookmark-thumbnail';

    if (bookmark.thumbnail) {
        const thumbnail = document.createElement('img');
        const proxyUrl = `/api/pages/proxy/image?url=${encodeURIComponent(bookmark.thumbnail)}`;
        thumbnail.src = proxyUrl;
        thumbnail.alt = bookmark.title || '';

        thumbnail.onload = () => {
            thumbnailContainer.classList.remove('error');
        };

        thumbnail.onerror = () => {
            console.warn('[BookmarkBlock] 썸네일 로드 실패:', proxyUrl);
            thumbnailContainer.classList.add('error');
            thumbnail.style.display = 'none';
        };

        thumbnailContainer.appendChild(thumbnail);
    } else {
        thumbnailContainer.classList.add('error');
    }

    const errorMessage = document.createElement('div');
    errorMessage.className = 'bookmark-thumbnail-error';
    errorMessage.textContent = '이미지 없음';
    thumbnailContainer.appendChild(errorMessage);

    card.appendChild(thumbnailContainer);

    return card;
}

/**
 * 북마크 이미지 프록시 처리
 */
function processBookmarkImages(container) {
    container.querySelectorAll('.bookmark-thumbnail img').forEach((img) => {
        const currentSrc = img.src;
        if (!currentSrc.includes('/api/pages/proxy/image')) {
            const proxyUrl = `/api/pages/proxy/image?url=${encodeURIComponent(img.src)}`;
            img.src = proxyUrl;
        }
    });
}

/**
 * 체크박스(to-do list) 렌더링 함수
 * @param {HTMLElement} container - 렌더링 대상 컨테이너
 */
function renderCheckboxes(container) {
    // taskList 타입의 ul 요소를 모두 찾아서 처리
    container.querySelectorAll('ul[data-type="taskList"]').forEach((ul) => {
        // 각 li 항목 처리
        ul.querySelectorAll('li').forEach((li) => {
            const isChecked = li.getAttribute('data-checked') === 'true';

            // 이미 렌더링된 경우 건너뛰기
            if (li.querySelector('input[type="checkbox"]')) {
                const checkbox = li.querySelector('input[type="checkbox"]');
                checkbox.checked = isChecked;
                return;
            }

            // 기존 내용 백업
            const content = li.innerHTML;

            // li 내용 재구성
            li.innerHTML = '';

            // label과 checkbox 생성
            const label = document.createElement('label');
            const checkbox = document.createElement('input');
            checkbox.type = 'checkbox';
            checkbox.checked = isChecked;
            checkbox.disabled = true; // 공개 페이지에서는 체크박스 비활성화

            label.appendChild(checkbox);
            li.appendChild(label);

            // 콘텐츠 div 생성
            const contentDiv = document.createElement('div');
            contentDiv.innerHTML = content;
            li.appendChild(contentDiv);
        });
    });
}

(async () => {
    try {
        // URL에서 토큰 추출
        const token = window.location.pathname.split('/').pop();
        if (!token) {
            throw new Error('토큰이 없습니다.');
        }

        // 페이지 데이터 로드
        const response = await fetch(`/api/shared/page/${encodeURIComponent(token)}`);
        if (!response.ok) {
            throw new Error('페이지를 찾을 수 없습니다.');
        }

        const data = await response.json();

        // 제목 설정
        document.title = `${data.title || '제목 없음'} - NTEOK`;
        document.getElementById('page-title-text').textContent = data.title || '제목 없음';

        // 아이콘 표시
        if (data.icon) {
            const iconEl = document.getElementById('page-icon');
            iconEl.textContent = data.icon;
            iconEl.style.display = 'inline';
        }

        // 커버 이미지 표시
        if (data.coverImage) {
            const coverEl = document.getElementById('page-cover');
            coverEl.style.backgroundImage = `url('/covers/${data.coverImage}')`;
            if (data.coverPosition) {
                coverEl.style.backgroundPositionY = `${data.coverPosition}%`;
            }
            coverEl.style.display = 'block';
        }

        // 콘텐츠 표시
        const editorEl = document.getElementById('page-editor');
        editorEl.innerHTML = data.content || '<p></p>';
        editorEl.classList.remove('shared-page-loading');

        // 북마크 블록 렌더링
        renderBookmarks(editorEl);

        // 체크박스 렌더링
        renderCheckboxes(editorEl);

        // KaTeX 수식 렌더링
        if (window.katex) {
            document.querySelectorAll('.katex-block, .katex-inline').forEach((el) => {
                try {
                    const isDisplay = el.classList.contains('katex-block');
                    const latex = el.dataset.latex || el.textContent;
                    el.innerHTML = '';
                    window.katex.render(latex, el, { displayMode: isDisplay, throwOnError: false });
                } catch (err) {
                    console.error('KaTeX 렌더링 오류:', err);
                }
            });
        }

        // 북마크 이미지 프록시 처리
        processBookmarkImages(editorEl);

    } catch (error) {
        console.error('페이지 로드 오류:', error);
        const editorEl = document.getElementById('page-editor');
        editorEl.innerHTML = `
            <div class="shared-page-error">
                <div class="shared-page-error-message">
                    <p><i class="fa-solid fa-exclamation-circle"></i></p>
                    <p>${error.message || '페이지를 불러올 수 없습니다.'}</p>
                    <p style="font-size: 13px; margin-top: 16px; color: #6b7280;">
                        <a href="/" style="color: #2d5f5d; text-decoration: underline;">홈으로 돌아가기</a>
                    </p>
                </div>
            </div>
        `;
        editorEl.classList.remove('shared-page-loading');
    }
})();
