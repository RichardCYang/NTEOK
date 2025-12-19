/**
 * 공개 페이지 스크립트
 */

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
