/**
 * ==================== WebSocket 서버 모듈 ====================
 * WebSocket 서버 및 실시간 동기화 기능 (컬렉션 제거 버전)
 */

const WebSocket = require("ws");
const Y = require("yjs");
const { formatDateForDb } = require("./network-utils");

function validateAndNormalizeIcon(raw) {
	if (raw === undefined || raw === null) return null;
	if (typeof raw !== "string") return null;
	const icon = raw.trim();
	if (icon === "") return null;
	if (/[<>]/.test(icon)) return null;
	if (/[\x00-\x1F\x7F]/.test(icon)) return null;
	const FA_CLASS_RE = /^(fa-(?:solid|regular|brands|duotone|light|thin))\s+fa-[a-z0-9-]+$/i;
	const FA_SINGLE_RE = /^fa-[a-z0-9-]+$/i;
	if (FA_CLASS_RE.test(icon) || FA_SINGLE_RE.test(icon)) return icon;
	if (icon.length <= 8 && !/\s/.test(icon) && !/["'`&]/.test(icon)) return icon;
	return null;
}

const wsConnections = {
    pages: new Map(), 
    storages: new Map(), 
	users: new Map(), 
    sessions: new Map() 
};

async function wsRevokeUserAccessFromCollection(pool, storageId, revokedUserId, opts = {}) {
	const reason = typeof opts.reason === 'string' ? opts.reason : '접근 권한이 회수되었습니다.';
	if (!pool || !storageId || !Number.isFinite(revokedUserId)) return;

	const affectedSockets = new Set();
	const affectedPageIds = [];

	const storageSet = wsConnections.storages.get(storageId);
	if (storageSet) {
		for (const conn of Array.from(storageSet)) {
			if (conn.userId === revokedUserId) {
				storageSet.delete(conn);
				affectedSockets.add(conn.ws);
			}
		}
		if (storageSet.size === 0) wsConnections.storages.delete(storageId);
	}

	let pageRows = [];
	try {
		const [rows] = await pool.execute(`SELECT id FROM pages WHERE storage_id = ?`, [storageId]);
		pageRows = Array.isArray(rows) ? rows : [];
	} catch (e) {
		pageRows = [];
	}

	for (const row of pageRows) {
		const pageId = row?.id;
		if (!pageId) continue;
		const pageSet = wsConnections.pages.get(pageId);
		if (!pageSet) continue;
		let removed = false;
		for (const conn of Array.from(pageSet)) {
			if (conn.userId === revokedUserId) {
				pageSet.delete(conn);
				affectedSockets.add(conn.ws);
				removed = true;
			}
		}
		if (removed) {
			affectedPageIds.push(pageId);
			try { wsBroadcastToPage(pageId, 'user-left', { userId: revokedUserId }, revokedUserId); } catch (e) {}
		}
		if (pageSet.size === 0) wsConnections.pages.delete(pageId);
	}

	const payload = JSON.stringify({ event: 'access-revoked', data: { storageId, pageIds: affectedPageIds, message: reason } });
	for (const ws of affectedSockets) {
		try { if (ws && ws.readyState === WebSocket.OPEN) ws.send(payload); } catch (e) {}
	}
}

const yjsDocuments = new Map();
const USER_COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B195', '#C06C84'];
const wsConnectionLimiter = new Map();
const WS_RATE_LIMIT_WINDOW = 60 * 1000;
const WS_RATE_LIMIT_MAX_CONNECTIONS = 10;
const WS_MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
const WS_MAX_AWARENESS_UPDATE_BYTES = 32 * 1024;

function registerSessionConnection(sessionId, ws) {
    if (!sessionId) return;
    if (!wsConnections.sessions.has(sessionId)) wsConnections.sessions.set(sessionId, new Set());
    wsConnections.sessions.get(sessionId).add(ws);
}

function unregisterSessionConnection(sessionId, ws) {
    if (!sessionId) return;
    const set = wsConnections.sessions.get(sessionId);
    if (!set) return;
    set.delete(ws);
    if (set.size === 0) wsConnections.sessions.delete(sessionId);
}

function wsCloseConnectionsForSession(sessionId, code = 1008, reason = 'Session invalidated') {
    const set = wsConnections.sessions.get(sessionId);
    if (!set || set.size === 0) return;
    for (const ws of set) {
        try { if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) ws.close(code, reason); } catch (err) {}
    }
    wsConnections.sessions.delete(sessionId);
}

function getUserColor(userId) { return USER_COLORS[userId % USER_COLORS.length]; }

function cleanupInactiveConnections(pool, sanitizeHtmlContent) {
    const now = Date.now();
    const TIMEOUT = 30 * 60 * 1000;
    yjsDocuments.forEach((doc, pageId) => {
        if (now - doc.lastAccess > TIMEOUT) {
            saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, doc.ydoc).catch(e => {});
            yjsDocuments.delete(pageId);
        }
    });
}

function extractFilesFromContent(content) {
    const files = [];
    if (content) {
        const fileRegex = /<div[^>]+data-type="file-block"[^>]+data-src=["']\/paperclip\/([^"']+)["']/g;
        let match;
        while ((match = fileRegex.exec(content)) !== null) files.push(match[1]);
    }
    return files;
}

async function cleanupOrphanedFiles(pool, filePaths, excludePageId) {
    if (!filePaths || filePaths.length === 0) return;
    const fs = require('fs');
    const path = require('path');
    for (const filePath of filePaths) {
        try {
            const parts = filePath.split('/');
            if (parts.length !== 2) continue;
            const [rows] = await pool.execute(`SELECT COUNT(*) as count FROM pages WHERE content LIKE ? AND id != ?`, [`%/paperclip/${filePath}%`, excludePageId]);
            if (rows[0].count === 0) {
                const fullPath = path.join(__dirname, 'paperclip', filePath);
                if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
            }
        } catch (err) {}
    }
}

async function saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc) {
    try {
        const yMetadata = ydoc.getMap('metadata');
		const title = yMetadata.get('title') || '제목 없음';
		const icon = validateAndNormalizeIcon(yMetadata.get('icon'));
        const sortOrder = yMetadata.get('sortOrder') || 0;
        const parentId = yMetadata.get('parentId') || null;
        const rawContent = yMetadata.get('content') || '<p></p>';
        const content = sanitizeHtmlContent(rawContent);

        const [existingRows] = await pool.execute('SELECT content, is_encrypted, user_id FROM pages WHERE id = ?', [pageId]);
        let finalContent = content;
        let oldFiles = [];
        if (existingRows.length > 0) {
            const existing = existingRows[0];
            if (existing.is_encrypted === 1) finalContent = '';
            else oldFiles = extractFilesFromContent(existing.content);
        }

		let yjsStateToSave = Buffer.from(Y.encodeStateAsUpdate(ydoc));
        await pool.execute(`UPDATE pages SET title = ?, content = ?, icon = ?, sort_order = ?, parent_id = ?, yjs_state = ?, updated_at = NOW() WHERE id = ?`, [title, finalContent, icon, sortOrder, parentId, yjsStateToSave, pageId]);

        if (existingRows.length > 0 && existingRows[0].is_encrypted === 0) {
            const newFiles = extractFilesFromContent(content);
            const deletedFiles = oldFiles.filter(f => !newFiles.includes(f));
            if (deletedFiles.length > 0) cleanupOrphanedFiles(pool, deletedFiles, pageId).catch(e => {});
        }
    } catch (error) { throw error; }
}

async function loadOrCreateYjsDoc(pool, sanitizeHtmlContent, pageId) {
    if (yjsDocuments.has(pageId)) {
        const doc = yjsDocuments.get(pageId);
        doc.lastAccess = Date.now();
        return doc.ydoc;
    }
    const [rows] = await pool.execute('SELECT title, content, icon, sort_order, parent_id, yjs_state FROM pages WHERE id = ?', [pageId]);
    const ydoc = new Y.Doc();
    const yMetadata = ydoc.getMap('metadata');
	if (rows.length > 0) {
	    const page = rows[0];
	    if (page.yjs_state) {
	        try { Y.applyUpdate(ydoc, Buffer.from(page.yjs_state)); yMetadata.set('seeded', true); } catch (e) { yMetadata.set('seeded', false); }
	    } else { yMetadata.set('seeded', false); }
	    if (yMetadata.get('title') == null) yMetadata.set('title', page.title || '제목 없음');
	    if (yMetadata.get('icon') == null) yMetadata.set('icon', page.icon || null);
	    if (yMetadata.get('sortOrder') == null) yMetadata.set('sortOrder', page.sort_order || 0);
	    if (yMetadata.get('parentId') == null) yMetadata.set('parentId', page.parent_id || null);

	    // 보안: DB/Yjs 상태에 들어있는 HTML 스냅샷은 신뢰하지 말고 서버 정책으로 항상 정화한다.
	    // - 협업(WS) 경로에서는 init 상태가 그대로 브라우저 렌더링으로 이어질 수 있으므로(Stored XSS 방어)
	    //   여기서 한 번 더 강제 정화를 적용한다.
	    const _rawHtml = (yMetadata.get('content') == null)
	        ? (page.content || '<p></p>')
	        : yMetadata.get('content');
	    const _safeHtml = (typeof sanitizeHtmlContent === 'function') ? sanitizeHtmlContent(_rawHtml) : _rawHtml;
	    yMetadata.set('content', _safeHtml);
	}
    yjsDocuments.set(pageId, { ydoc, lastAccess: Date.now(), saveTimeout: null });
    return ydoc;
}

function wsBroadcastToPage(pageId, event, data, excludeUserId = null) {
    const connections = wsConnections.pages.get(pageId);
    if (!connections) return;
    const message = JSON.stringify({ event, data });
    connections.forEach(conn => {
        if (excludeUserId && conn.userId === excludeUserId) return;
        try { if (conn.ws.readyState === WebSocket.OPEN) conn.ws.send(message); } catch (error) {}
    });
}

function wsBroadcastToStorage(storageId, event, data, excludeUserId = null, options = {}) {
    const connections = wsConnections.storages.get(storageId);
    if (!connections) return;
	const pv = options?.pageVisibility;
	const restrictToOwner = pv && pv.isEncrypted === true && pv.shareAllowed === false && Number.isFinite(pv.ownerUserId);
	const pvs = options?.pageVisibilities;
	const shouldFilterPageIds = Boolean(pvs && data && Array.isArray(data.pageIds));

    connections.forEach(conn => {
        if (excludeUserId && conn.userId === excludeUserId) return;
        if (restrictToOwner && conn.userId !== pv.ownerUserId) return;
        let payloadData = data;
  		if (shouldFilterPageIds) {
 			const filtered = data.pageIds.filter(id => {
				const v = pvs[id];
				if (!v) return true;
				if (v.isEncrypted === true && v.shareAllowed === false) return conn.userId === v.ownerUserId;
				return true;
 			});
 			if (filtered.length === 0) return;
 			payloadData = Object.assign({}, data, { pageIds: filtered });
  		}
        try { if (conn.ws.readyState === WebSocket.OPEN) conn.ws.send(JSON.stringify({ event, data: payloadData })); } catch (error) {}
    });
}

function wsBroadcastToUser(userId, event, data, excludeSessionId = null) {
    const connections = wsConnections.users.get(userId);
    if (!connections) return;
    const message = JSON.stringify({ event, data });
    connections.forEach(conn => {
        if (excludeSessionId && conn.sessionId === excludeSessionId) return;
        try { if (conn.ws.readyState === WebSocket.OPEN) conn.ws.send(message); } catch (error) {}
    });
}

function checkWebSocketRateLimit(clientIp) {
    const now = Date.now();
    const limit = wsConnectionLimiter.get(clientIp);
    if (limit) {
        if (now < limit.resetTime) { if (limit.count >= WS_RATE_LIMIT_MAX_CONNECTIONS) return false; limit.count++; }
        else wsConnectionLimiter.set(clientIp, { count: 1, resetTime: now + WS_RATE_LIMIT_WINDOW });
    } else wsConnectionLimiter.set(clientIp, { count: 1, resetTime: now + WS_RATE_LIMIT_WINDOW });
    return true;
}

async function getStoragePermission(pool, userId, storageId) {
    // 1. 소유자 확인
    const [ownerRows] = await pool.execute(
        `SELECT id FROM storages WHERE id = ? AND user_id = ?`,
        [storageId, userId]
    );
    if (ownerRows.length > 0) return 'ADMIN';

    // 2. 공유 확인
    const [shareRows] = await pool.execute(
        `SELECT permission FROM storage_shares 
         WHERE storage_id = ? AND shared_with_user_id = ?`,
        [storageId, userId]
    );
    if (shareRows.length > 0) return shareRows[0].permission;

    return null;
}

function initWebSocketServer(server, sessions, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId) {
    const wss = new WebSocket.Server({ server, path: '/ws', maxPayload: WS_MAX_MESSAGE_BYTES });
    wss.on('connection', async (ws, req) => {
    	try {
			const remoteAddress = req.socket?.remoteAddress;
			const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() || remoteAddress || 'unknown';
		    if (!checkWebSocketRateLimit(clientIp)) { ws.close(1008, 'Rate limit exceeded'); return; }
		    const cookies = {};
		    if (req.headers.cookie) req.headers.cookie.split(';').forEach(c => { const p = c.split('='); cookies[p[0].trim()] = (p[1] || '').trim(); });
		    const sessionId = cookies[SESSION_COOKIE_NAME];
		    if (!sessionId) { ws.close(1008, 'Unauthorized'); return; }
		    const session = typeof getSessionFromId === 'function' ? getSessionFromId(sessionId) : sessions.get(sessionId);
		    if (!session || !session.userId) { ws.close(1008, 'Unauthorized'); return; }
		    ws.userId = session.userId; ws.username = session.username; ws.sessionId = sessionId; ws.isAlive = true;
			registerSessionConnection(sessionId, ws);
		    ws.on('pong', () => { ws.isAlive = true; });
			ws.on('message', async (msg) => {
		        try { const data = JSON.parse(msg); await handleWebSocketMessage(ws, data, pool, sanitizeHtmlContent, getSessionFromId); } catch (e) { ws.send(JSON.stringify({ event: 'error', data: { message: 'Failed' } })); }
		    });
		    ws.on('close', () => { cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent); });
		    ws.send(JSON.stringify({ event: 'connected', data: { userId: session.userId, username: session.username } }));
      	} catch (err) { try { ws.close(1011, 'Error'); } catch (_) {} }
    });
    const heartbeatInterval = setInterval(() => { wss.clients.forEach(ws => { if (ws.isAlive === false) { cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent); return ws.terminate(); } ws.isAlive = false; ws.ping(); }); }, 60000);
    wss.on('close', () => { clearInterval(heartbeatInterval); });
    return wss;
}

async function handleWebSocketMessage(ws, data, pool, sanitizeHtmlContent, getSessionFromId) {
	const { type, payload } = data;
	if (ws.sessionId && typeof getSessionFromId === 'function') {
	    const s = getSessionFromId(ws.sessionId);
	    if (!s || !s.userId) { try { ws.close(1008, 'Expired'); } catch (e) {} return; }
	}
	switch (type) {
        case 'subscribe-page': await handleSubscribePage(ws, payload, pool, sanitizeHtmlContent); break;
        case 'unsubscribe-page': handleUnsubscribePage(ws, payload, pool, sanitizeHtmlContent); break;
        case 'subscribe-storage': await handleSubscribeStorage(ws, payload, pool); break;
        case 'unsubscribe-storage': handleUnsubscribeStorage(ws, payload); break;
        case 'subscribe-user': handleSubscribeUser(ws, payload); break;
        case 'yjs-update': await handleYjsUpdate(ws, payload, pool, sanitizeHtmlContent); break;
        case 'awareness-update': handleAwarenessUpdate(ws, payload); break;
    }
}

async function handleSubscribePage(ws, payload, pool, sanitizeHtmlContent) {
    const { pageId } = payload;
    const userId = ws.userId;
    try {
        const [rows] = await pool.execute(`SELECT p.id, p.is_encrypted, p.storage_id FROM pages p WHERE p.id = ?`, [pageId]);
        if (!rows.length) { ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } })); return; }
        
        const page = rows[0];
        const permission = await getStoragePermission(pool, userId, page.storage_id);
        
        if (!permission) { ws.send(JSON.stringify({ event: 'error', data: { message: 'Unauthorized' } })); return; }
        
        if (page.is_encrypted === 1) {
            // 암호화된 페이지는 실시간 편집 지원 안 함 (단순 동기화만 하거나 제외)
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Encrypted pages do not support real-time collaboration yet' } }));
            return;
        }

        if (!wsConnections.pages.has(pageId)) wsConnections.pages.set(pageId, new Set());
        const conns = wsConnections.pages.get(pageId);
        for (const c of Array.from(conns)) { if (c.userId === userId && c.ws !== ws) { conns.delete(c); try { c.ws.close(1008, 'Duplicate'); } catch (e) {} } }
        const color = getUserColor(userId);
        conns.add({ ws, userId, username: ws.username, color, permission });
        const ydoc = await loadOrCreateYjsDoc(pool, sanitizeHtmlContent, pageId);
        ws.send(JSON.stringify({ event: 'init', data: { state: Buffer.from(Y.encodeStateAsUpdate(ydoc)).toString('base64'), userId, username: ws.username, color, permission } }));
        wsBroadcastToPage(pageId, 'user-joined', { userId, username: ws.username, color, permission }, userId);
    } catch (e) { ws.send(JSON.stringify({ event: 'error', data: { message: 'Failed' } })); }
}

function handleUnsubscribePage(ws, payload, pool, sanitizeHtmlContent) {
    const { pageId } = payload;
    const conns = wsConnections.pages.get(pageId);
    if (conns) {
        conns.forEach(c => { if (c.ws === ws) conns.delete(c); });
        if (conns.size === 0) { wsConnections.pages.delete(pageId); const doc = yjsDocuments.get(pageId); if (doc) saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, doc.ydoc).catch(e => {}); }
        wsBroadcastToPage(pageId, 'user-left', { userId: ws.userId }, ws.userId);
    }
}

async function handleSubscribeStorage(ws, payload, pool) {
    const { storageId } = payload;
    const userId = ws.userId;
    try {
        const permission = await getStoragePermission(pool, userId, storageId);
        if (!permission) { ws.send(JSON.stringify({ event: 'error', data: { message: 'Unauthorized' } })); return; }
        if (!wsConnections.storages.has(storageId)) wsConnections.storages.set(storageId, new Set());
        wsConnections.storages.get(storageId).add({ ws, userId, permission });
    } catch (e) {}
}

function handleUnsubscribeStorage(ws, payload) {
    const { storageId } = payload;
    const conns = wsConnections.storages.get(storageId);
    if (conns) { conns.forEach(c => { if (c.ws === ws) conns.delete(c); }); if (conns.size === 0) wsConnections.storages.delete(storageId); }
}

function handleSubscribeUser(ws, payload) {
    if (!wsConnections.users.has(ws.userId)) wsConnections.users.set(ws.userId, new Set());
    wsConnections.users.get(ws.userId).add({ ws, sessionId: ws.sessionId });
}

async function handleYjsUpdate(ws, payload, pool, sanitizeHtmlContent) {
	const { pageId, update } = payload || {};
	try {
        if (!pageId || typeof update !== 'string' || !isSubscribedToPage(ws, pageId)) return;
        
        // 권한 확인 (EDIT 또는 ADMIN)
        const conns = wsConnections.pages.get(pageId);
        const myConn = Array.from(conns).find(c => c.ws === ws);
        if (!myConn || !['EDIT', 'ADMIN'].includes(myConn.permission)) return;

        const ydoc = await loadOrCreateYjsDoc(pool, sanitizeHtmlContent, pageId);
        Y.applyUpdate(ydoc, Buffer.from(update, 'base64'));
        wsBroadcastToPage(pageId, 'yjs-update', { update }, ws.userId);
        const doc = yjsDocuments.get(pageId);
        if (doc) { if (doc.saveTimeout) clearTimeout(doc.saveTimeout); doc.saveTimeout = setTimeout(() => { saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc).catch(e => {}); }, 1000); }
    } catch (e) {}
}

function isSubscribedToPage(ws, pageId) {
    const conns = wsConnections.pages.get(pageId);
    if (!conns) return false;
    for (const c of conns) if (c.ws === ws) return true;
    return false;
}

function handleAwarenessUpdate(ws, payload) {
    const { pageId, awarenessUpdate } = payload;
    if (!pageId || !isSubscribedToPage(ws, pageId)) return;
    wsBroadcastToPage(pageId, 'awareness-update', { awarenessUpdate, fromUserId: ws.userId }, ws.userId);
}

function cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent) {
	unregisterSessionConnection(ws.sessionId, ws);
    wsConnections.pages.forEach((conns, pid) => {
        conns.forEach(c => { if (c.ws === ws) { conns.delete(c); wsBroadcastToPage(pid, 'user-left', { userId: ws.userId }, ws.userId); } });
        if (conns.size === 0) { wsConnections.pages.delete(pid); const doc = yjsDocuments.get(pid); if (doc) saveYjsDocToDatabase(pool, sanitizeHtmlContent, pid, doc.ydoc).catch(e => {}); }
    });
    wsConnections.storages.forEach((conns, sid) => { conns.forEach(c => { if (c.ws === ws) conns.delete(c); }); if (conns.size === 0) wsConnections.storages.delete(sid); });
    const uconns = wsConnections.users.get(ws.userId);
    if (uconns) { uconns.forEach(c => { if (c.ws === ws) uconns.delete(c); }); if (uconns.size === 0) wsConnections.users.delete(ws.userId); }
}

function startRateLimitCleanup() { return setInterval(() => { const now = Date.now(); wsConnectionLimiter.forEach((l, ip) => { if (now > l.resetTime) wsConnectionLimiter.delete(ip); }); }, 300000); }
function startInactiveConnectionsCleanup(pool, sanitizeHtmlContent) { return setInterval(() => cleanupInactiveConnections(pool, sanitizeHtmlContent), 600000); }

module.exports = { initWebSocketServer, wsBroadcastToPage, wsBroadcastToStorage, wsBroadcastToUser, wsRevokeUserAccessFromCollection, startRateLimitCleanup, startInactiveConnectionsCleanup, wsConnections, yjsDocuments, saveYjsDocToDatabase, wsCloseConnectionsForSession };