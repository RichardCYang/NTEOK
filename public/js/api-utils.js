import { secureFetch } from './ui-utils.js';

export async function apiRequest(url, options = {}) {
    try {
        const response = await secureFetch(url, options);
        
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

export async function get(url) {
    return apiRequest(url, { method: 'GET' });
}

export async function post(url, body) {
    return apiRequest(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

export async function put(url, body) {
    return apiRequest(url, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

export async function patch(url, body) {
    return apiRequest(url, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
}

export async function del(url) {
    return apiRequest(url, { method: 'DELETE' });
}
