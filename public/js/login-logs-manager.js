/**
 * 로그인 로그 관리 모듈
 * 로그인 성공/실패 기록을 조회하고 표시하는 기능을 제공합니다.
 */

import { hideParentModalForChild, restoreParentModalFromChild } from './modal-parent-manager.js';

// 페이지네이션 설정
const LOGS_PER_PAGE = 20;
let currentPage = 1;

/**
 * HTML 이스케이프 (XSS 방지)
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * 날짜/시간 포맷팅
 */
function formatDateTime(dateStr) {
    if (!dateStr) return '-';
    const date = new Date(dateStr);
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

/**
 * 위치 정보 포맷팅
 */
function formatLocation(log) {
    const parts = [];
    if (log.city) parts.push(log.city);
    if (log.region) parts.push(log.region);
    if (log.country) parts.push(log.country);

    if (parts.length === 0) return '알 수 없음';
    return parts.join(', ');
}

/**
 * User Agent 파싱 (간단한 버전)
 */
function parseUserAgent(userAgent) {
    if (!userAgent) return { device: '알 수 없음', icon: 'fa-question' };

    const ua = userAgent.toLowerCase();

    // 모바일 디바이스 체크
    if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone') || ua.includes('ipad')) {
        if (ua.includes('android')) {
            return { device: 'Android 모바일', icon: 'fa-mobile-screen-button' };
        } else if (ua.includes('iphone')) {
            return { device: 'iPhone', icon: 'fa-mobile-screen-button' };
        } else if (ua.includes('ipad')) {
            return { device: 'iPad', icon: 'fa-tablet-screen-button' };
        }
        return { device: '모바일', icon: 'fa-mobile-screen-button' };
    }

    // 데스크톱 OS 체크
    if (ua.includes('windows')) {
        return { device: 'Windows PC', icon: 'fa-desktop' };
    } else if (ua.includes('mac os')) {
        return { device: 'Mac', icon: 'fa-desktop' };
    } else if (ua.includes('linux')) {
        return { device: 'Linux PC', icon: 'fa-desktop' };
    }

    return { device: '데스크톱', icon: 'fa-desktop' };
}

/**
 * 로그인 로그 통계 로드
 */
async function loadLoginLogsStats() {
    try {
        const response = await fetch('/api/auth/login-logs/stats', {
            method: 'GET',
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('통계 로드 실패');
        }

        const stats = await response.json();

        // 통계 카드 업데이트
        document.getElementById('login-logs-success-count').textContent = stats.successCount || 0;
        document.getElementById('login-logs-failure-count').textContent = stats.failureCount || 0;
        document.getElementById('login-logs-unique-ips').textContent = stats.uniqueIPs || 0;

        const lastLoginElement = document.getElementById('login-logs-last-login');
        if (stats.lastLoginAt) {
            lastLoginElement.textContent = formatDateTime(stats.lastLoginAt);
        } else {
            lastLoginElement.textContent = '기록 없음';
        }
    } catch (error) {
        console.error('통계 로드 오류:', error);
    }
}

/**
 * 로그인 로그 목록 로드
 */
async function loadLoginLogs(page = 1) {
    try {
        const offset = (page - 1) * LOGS_PER_PAGE;
        const response = await fetch(`/api/auth/login-logs?limit=${LOGS_PER_PAGE}&offset=${offset}`, {
            method: 'GET',
            credentials: 'include'
        });

        if (!response.ok) {
            throw new Error('로그 로드 실패');
        }

        const data = await response.json();

        // 테이블 렌더링
        renderLoginLogsTable(data.logs);

        // 페이지네이션 렌더링
        renderPagination(data.total, page);

        currentPage = page;
    } catch (error) {
        console.error('로그 로드 오류:', error);
        const tbody = document.getElementById('login-logs-table-body');
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">로그를 불러오는 중 오류가 발생했습니다.</td></tr>';
    }
}

/**
 * 로그인 로그 테이블 렌더링
 */
function renderLoginLogsTable(logs) {
    const tbody = document.getElementById('login-logs-table-body');

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">최근 30일간 로그인 기록이 없습니다.</td></tr>';
        return;
    }

    tbody.innerHTML = logs.map(log => {
        const statusBadge = log.success
            ? '<span class="login-log-status-badge success">성공</span>'
            : `<span class="login-log-status-badge failure">실패${log.failure_reason ? ` (${escapeHtml(log.failure_reason)})` : ''}</span>`;

        const location = formatLocation(log);
        const { device, icon } = parseUserAgent(log.user_agent);

        return `
            <tr>
                <td>${formatDateTime(log.created_at)}</td>
                <td>${escapeHtml(log.ip_address)}</td>
                <td>${log.port}</td>
                <td>${escapeHtml(location)}</td>
                <td>${statusBadge}</td>
                <td>
                    <i class="fa-solid ${icon}"></i>
                    ${escapeHtml(device)}
                </td>
            </tr>
        `;
    }).join('');
}

/**
 * 페이지네이션 렌더링
 */
function renderPagination(total, currentPage) {
    const totalPages = Math.ceil(total / LOGS_PER_PAGE);
    const container = document.getElementById('login-logs-pagination');

    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '';

    // 이전 버튼
    if (currentPage > 1) {
        html += `<button class="pagination-btn" data-page="${currentPage - 1}">
            <i class="fa-solid fa-chevron-left"></i> 이전
        </button>`;
    } else {
        html += `<button class="pagination-btn" disabled>
            <i class="fa-solid fa-chevron-left"></i> 이전
        </button>`;
    }

    // 페이지 번호 버튼
    const maxButtons = 5;
    let startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
    let endPage = Math.min(totalPages, startPage + maxButtons - 1);

    if (endPage - startPage < maxButtons - 1) {
        startPage = Math.max(1, endPage - maxButtons + 1);
    }

    for (let i = startPage; i <= endPage; i++) {
        if (i === currentPage) {
            html += `<button class="pagination-btn active" data-page="${i}" aria-current="page">${i}</button>`;
        } else {
            html += `<button class="pagination-btn" data-page="${i}">${i}</button>`;
        }
    }

    // 다음 버튼
    if (currentPage < totalPages) {
        html += `<button class="pagination-btn" data-page="${currentPage + 1}">
            다음 <i class="fa-solid fa-chevron-right"></i>
        </button>`;
    } else {
        html += `<button class="pagination-btn" disabled>
            다음 <i class="fa-solid fa-chevron-right"></i>
        </button>`;
    }

    container.innerHTML = html;
}

/**
 * 특정 페이지로 이동
 */
function goToPage(page) {
    loadLoginLogs(page);
}

/**
 * 로그인 로그 모달 열기
 */
function openLoginLogsModal() {
	const modal = document.getElementById('login-logs-modal');
	if (!modal) return;

	// 보안 설정 모달(부모)을 잠깐 닫고, 로그인 로그 모달만 단독으로 띄움
	hideParentModalForChild('#security-settings-modal', modal);

	modal.classList.remove('hidden');

	// 데이터 로드
    currentPage = 1;
    loadLoginLogsStats();
    loadLoginLogs(1);
}

/**
 * 로그인 로그 모달 닫기
 */
function closeLoginLogsModal() {
	const modal = document.getElementById('login-logs-modal');
	if (!modal) return;

	modal.classList.add('hidden');

	// 부모 모달(보안 설정) 복구
	restoreParentModalFromChild(modal);
}

/**
 * 이벤트 바인딩
 */
export function bindLoginLogsModal() {
    const viewLogsBtn = document.getElementById('view-login-logs-btn');
    const closeBtn = document.getElementById('close-login-logs-btn');
    const modal = document.getElementById('login-logs-modal');

    if (viewLogsBtn) {
        viewLogsBtn.addEventListener('click', openLoginLogsModal);
    }

    if (closeBtn) {
        closeBtn.addEventListener('click', closeLoginLogsModal);
    }

    // 모달 오버레이(바깥 영역) 클릭 시 닫기
    if (modal) {
	   	const overlay = modal.querySelector('.modal-overlay');
	    if (overlay)
	        overlay.addEventListener('click', closeLoginLogsModal);
    }
    const pagination = document.getElementById('login-logs-pagination');

    if (pagination) {
        pagination.addEventListener('click', (event) => {
            const button = event.target.closest('button.pagination-btn');
            if (!button || button.disabled) return;

            const page = Number(button.dataset.page);
            if (!Number.isFinite(page) || page === currentPage) return;

            goToPage(page);
        });
    }

}

// 전역 객체로 export (페이지네이션 버튼에서 접근하기 위해)
window.loginLogsManager = {
    goToPage
};
