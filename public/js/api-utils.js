/**
 * API 호출 유틸리티
 */
import { secureFetch } from './ui-utils.js';

/**
 * API 요청을 보내고 결과를 반환합니다.
 * @param {string} url - 요청 URL
 * @param {Object} options - fetch 옵션
 * @returns {Promise<any>} - 응답 데이터
 */
export async function apiRequest(url, options = {}) {
    try {
        const response = await secureFetch(url, options);
        
        // 응답 본문이 비어있는지 확인
        const contentType = response.headers.get("content-type");
        let data = null;
        if (contentType && contentType.includes("application/json")) {
            data = await response.json();
        }

        if (!response.ok) {
            const error = new Error(data?.error || `HTTP ${response.status}`);
            error.status = response.status;
            error.data = data;
            throw error;
        }

        return data;
    } catch (error) {
        console.error(`API Request Error [${url}]:`, error);
        throw error;
    }
}

/**
 * GET 요청
 */
export async function get(url) {
    return apiRequest(url, { method: 'GET' });
}

/**
 * POST 요청
 */
export async function post(url, body) {
    return apiRequest(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

/**
 * PUT 요청
 */
export async function put(url, body) {
    return apiRequest(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

/**
 * PATCH 요청
 */
export async function patch(url, body) {
    return apiRequest(url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

/**
 * DELETE 요청
 */
export async function del(url) {
    return apiRequest(url, { method: 'DELETE' });
}
