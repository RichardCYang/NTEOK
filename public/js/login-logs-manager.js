
import { hideParentModalForChild, restoreParentModalFromChild } from './modal-parent-manager.js';
import { secureFetch } from './ui-utils.js';

const LOGS_PER_PAGE = 20;
let currentPage = 1;

function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

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

function formatLocation(log) {
    const parts = [];
    if (log.city) parts.push(log.city);
    if (log.region) parts.push(log.region);
    if (log.country) parts.push(log.country);

    if (parts.length === 0) return '알 수 없음';
    return parts.join(', ');
}

function parseUserAgent(userAgent) {
    if (!userAgent) return { device: '알 수 없음', icon: 'fa-question' };

    const ua = userAgent.toLowerCase();

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

    if (ua.includes('windows')) {
        return { device: 'Windows PC', icon: 'fa-desktop' };
    } else if (ua.includes('mac os')) {
        return { device: 'Mac', icon: 'fa-desktop' };
    } else if (ua.includes('linux')) {
        return { device: 'Linux PC', icon: 'fa-desktop' };
    }

    return { device: '데스크톱', icon: 'fa-desktop' };
}

async function loadLoginLogsStats() {
    try {
        const response = await secureFetch('/api/auth/login-logs/stats', {
            method: 'GET'
        });

        if (!response.ok) {
            throw new Error('통계 로드 실패');
        }

        const stats = await response.json();

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

async function loadLoginLogs(page = 1) {
    try {
        const offset = (page - 1) * LOGS_PER_PAGE;
        const response = await secureFetch(`/api/auth/login-logs?limit=${LOGS_PER_PAGE}&offset=${offset}`, {
            method: 'GET'
        });

        if (!response.ok) {
            throw new Error('로그 로드 실패');
        }

        const data = await response.json();

        renderLoginLogsTable(data.logs);

        renderPagination(data.total, page);

        currentPage = page;
    } catch (error) {
        console.error('로그 로드 오류:', error);
        const tbody = document.getElementById('login-logs-table-body');
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">로그를 불러오는 중 오류가 발생했습니다.</td></tr>';
    }
}

function renderLoginLogsTable(logs) {
    const tbody = document.getElementById('login-logs-table-body');

    if (!logs || logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">최근 30일간 로그인 기록이 없습니다.</td></tr>';
        return;
    }

    tbody.textContent = '';
    logs.forEach((log) => {
        const tr = document.createElement('tr');

        const cells = [
            formatDateTime(log.created_at),
            String(log.ip_address || ''),
            String(log.port || ''),
            formatLocation(log),
            log.success ? '성공' : `실패${log.failure_reason ? ` (${log.failure_reason})` : ''}`,
            parseUserAgent(log.user_agent).device
        ];

        cells.forEach((value) => {
            const td = document.createElement('td');
            td.textContent = String(value || '');
            tr.appendChild(td);
        });

        tbody.appendChild(tr);
    });
}

function renderPagination(total, currentPage) {
    const totalPages = Math.ceil(total / LOGS_PER_PAGE);
    const container = document.getElementById('login-logs-pagination');

    if (totalPages <= 1) {
        container.innerHTML = '';
        return;
    }

    let html = '';

    if (currentPage > 1) {
        html += `<button class="pagination-btn" data-page="${currentPage - 1}">
            <i class="fa-solid fa-chevron-left"></i> 이전
        </button>`;
    } else {
        html += `<button class="pagination-btn" disabled>
            <i class="fa-solid fa-chevron-left"></i> 이전
        </button>`;
    }

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

function goToPage(page) {
    loadLoginLogs(page);
}

function openLoginLogsModal() {
	const modal = document.getElementById('login-logs-modal');
	if (!modal) return;

	hideParentModalForChild('#security-settings-modal', modal);

	modal.classList.remove('hidden');

    currentPage = 1;
    loadLoginLogsStats();
    loadLoginLogs(1);
}

function closeLoginLogsModal() {
	const modal = document.getElementById('login-logs-modal');
	if (!modal) return;

	modal.classList.add('hidden');

	restoreParentModalFromChild(modal);
}

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

window.loginLogsManager = {
    goToPage
};
