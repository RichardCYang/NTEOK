/**
 * ==================== WebSocket 서버 모듈 ====================
 * WebSocket 서버 및 실시간 동기화 기능 (컬렉션 제거 버전)
 */

const WebSocket = require("ws");
const Y = require("yjs");
const { URL } = require("url");
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

const yjsDocuments = new Map();
const USER_COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B195', '#C06C84'];
const wsConnectionLimiter = new Map();
const WS_RATE_LIMIT_WINDOW = 60 * 1000;
const WS_RATE_LIMIT_MAX_CONNECTIONS = 10;
const WS_MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
const WS_MAX_AWARENESS_UPDATE_BYTES = 32 * 1024;

// 권한 변경/회수 반영을 위한 주기적 재검증(밀리초)
const WS_PERMISSION_REFRESH_MS = (() => {
    const n = Number.parseInt(process.env.WS_PERMISSION_REFRESH_MS || '5000', 10);
    if (!Number.isFinite(n)) return 5000;
    return Math.max(500, Math.min(60_000, n));
})();

const WS_MAX_ACTIVE_CONNECTIONS_PER_IP = Number.parseInt(process.env.WS_MAX_ACTIVE_CONNECTIONS_PER_IP || '25', 10);
const WS_MAX_ACTIVE_CONNECTIONS_PER_SESSION = Number.parseInt(process.env.WS_MAX_ACTIVE_CONNECTIONS_PER_SESSION || '10', 10);

const wsActiveConnectionsByIp = new Map();
const wsActiveConnectionsBySession = new Map();

function canRegisterActive(map, key, max) {
    if (!key) return false;
    const lim = Number.isFinite(max) ? max : 0;
    if (lim <= 0) return false;
    const cur = map.get(key) || 0;
    return cur < lim;
}

function registerActive(map, key) {
    const cur = map.get(key) || 0;
    map.set(key, cur + 1);
}

function unregisterActive(map, key) {
    const cur = (map.get(key) || 0) - 1;
    if (cur <= 0) map.delete(key);
    else map.set(key, cur);
}

function releaseActiveConnectionSlots(ws) {
    if (!ws || ws._activeSlotsReleased) return;
    ws._activeSlotsReleased = true;

    if (ws._activeIpKey) {
        unregisterActive(wsActiveConnectionsByIp, ws._activeIpKey);
        ws._activeIpKey = null;
    }
    if (ws._activeSessionKey) {
        unregisterActive(wsActiveConnectionsBySession, ws._activeSessionKey);
        ws._activeSessionKey = null;
    }
}

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

function normalizePaperclipRef(ref) {
    // ref expected: "<userId>/<filename>" from HTML like /paperclip/<userId>/<filename>
    if (typeof ref !== 'string') return null;
    const s = ref.trim();
    if (!s || s.length > 512) return null;

    const parts = s.split('/');
    if (parts.length !== 2) return null;
    const [userIdRaw, filenameRaw] = parts;

    if (!/^\d{1,12}$/.test(userIdRaw)) return null;

    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(filenameRaw)) return null;
    if (filenameRaw.includes('..') || /[\x00-\x1F\x7F]/.test(filenameRaw)) return null;

    return `${userIdRaw}/${filenameRaw}`;
}

function extractFilesFromContent(content) {
    const files = [];
    if (!content) return files;

    // data-src="/paperclip/<userId>/<filename>" 형태만 추출
    // (파일명/유저ID allowlist 적용; path traversal 시도는 무시)
    const fileRegex = /<div[^>]*data-type=["']file-block["'][^>]*data-src=["']\/paperclip\/([^"']+)["'][^>]*>/gi;
    let match;
    while ((match = fileRegex.exec(String(content))) !== null) {
        const ref = normalizePaperclipRef(match[1]);
        if (ref) files.push(ref);
    }
    return files;
}

async function cleanupOrphanedFiles(pool, filePaths, excludePageId) {
    if (!filePaths || filePaths.length === 0) return;

    const fs = require('fs');
    const path = require('path');
    const baseDir = path.resolve(__dirname, 'paperclip') + path.sep;

    // LIKE 패턴에서 와일드카드(% _) 오인 방지
    const escapeLike = (s) => String(s).replace(/[\\%_]/g, (m) => '\\\\' + m);

    for (const ref of filePaths) {
        try {
            const normalized = normalizePaperclipRef(ref);
            if (!normalized) continue;

            const fileUrl = `/paperclip/${normalized}`;
            const likePattern = `%${escapeLike(fileUrl)}%`;

            const [rows] = await pool.execute(
                `SELECT COUNT(*) as count FROM pages WHERE content LIKE ? ESCAPE '\\\\' AND id != ?`,
                [likePattern, excludePageId]
            );
            if (!rows || !rows[0] || rows[0].count > 0) continue;

            const fullPath = path.resolve(__dirname, 'paperclip', normalized);
            if (!fullPath.startsWith(baseDir)) {
                console.warn(`[보안] orphan cleanup traversal blocked: ${normalized}`);
                continue;
            }

            if (fs.existsSync(fullPath)) fs.unlinkSync(fullPath);
        } catch (err) {
            // best-effort cleanup
        }
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
    const [rows] = await pool.execute(
        `SELECT title, content, icon, sort_order, parent_id, yjs_state,
                user_id, storage_id, is_encrypted, share_allowed
         FROM pages
         WHERE id = ?`,
        [pageId]
    );

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

        // 보안/권한 검증에 필요한 최소 메타 저장
        yjsDocuments.set(pageId, {
            ydoc,
            lastAccess: Date.now(),
            saveTimeout: null,
            ownerUserId: Number(page.user_id),
            storageId: String(page.storage_id),
            isEncrypted: page.is_encrypted === 1,
            shareAllowed: page.share_allowed === 1
        });
        return ydoc;
	}
    yjsDocuments.set(pageId, {
        ydoc,
        lastAccess: Date.now(),
        saveTimeout: null,
        ownerUserId: null,
        storageId: null,
        isEncrypted: false,
        shareAllowed: true
    });
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

function initWebSocketServer(server, sessions, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest) {
    /**
     * ==================== WebSocket 보안: Origin 검증 (CSWSH 방지) ====================
     * - WebSocket은 브라우저의 SOP/CORS로 보호되지 않으므로, 핸드셰이크에서 Origin allowlist 검증이 필요합니다.
     * - BASE_URL(예: https://example.com) 기준으로 허용 Origin을 구성합니다.
     *   (리버스 프록시/도메인 변경 시 BASE_URL을 정확히 설정하세요.)
     */
    const allowedWsOrigins = (() => {
        const set = new Set();
        try { set.add(new URL(BASE_URL).origin); } catch (_) {}

        // 개발 환경에서 흔히 사용하는 로컬 오리진 허용
        if (!IS_PRODUCTION) {
            const port = process.env.PORT || 3000;
            try { set.add(new URL(`http://localhost:${port}`).origin); } catch (_) {}
            try { set.add(new URL(`http://127.0.0.1:${port}`).origin); } catch (_) {}
        }
        return set;
    })();

    function isWsOriginAllowed(originHeader) {
        if (typeof originHeader !== "string") return false;
        const raw = originHeader.trim();
        // 브라우저는 Origin을 보냅니다. 'null'은 sandbox/파일 등 의심 상황이므로 거부.
        if (!raw || raw === "null") return false;
        try {
            const origin = new URL(raw).origin;
            return allowedWsOrigins.has(origin);
        } catch {
            return false;
        }
    }

    const wss = new WebSocket.Server({
        server,
        path: '/ws',
        maxPayload: WS_MAX_MESSAGE_BYTES,
        /**
         * 핸드셰이크 단계에서 Origin 검증 (Cross-Site WebSocket Hijacking 방지)
         * - 브라우저는 Origin 헤더를 자동으로 포함하며 JS로 임의 변경 불가
         */
        verifyClient: (info, done) => {
            try {
                const origin = info?.origin || info?.req?.headers?.origin;
                if (!isWsOriginAllowed(origin)) {
                    return done(false, 403, 'Forbidden');
                }
                return done(true);
            } catch (_) {
                return done(false, 403, 'Forbidden');
            }
        }
    });

    wss.on('connection', async (ws, req) => {
        try {
            // 추가 방어: 라이브러리/프록시 환경에 따라 verifyClient가 우회될 가능성을 대비해
            // connection 단계에서도 Origin을 재검증합니다.
            const origin = req?.headers?.origin;
            if (!isWsOriginAllowed(origin)) {
                try { ws.close(1008, 'Forbidden'); } catch (_) {}
                return;
            }

            ws.on('close', () => { cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent); });

            const clientIp = (typeof getClientIpFromRequest === 'function')
                ? getClientIpFromRequest(req)
                : (req.socket?.remoteAddress || 'unknown');
            const ipKey = (typeof clientIp === 'string' && clientIp.trim()) ? clientIp.trim() : 'unknown';

            if (!canRegisterActive(wsActiveConnectionsByIp, ipKey, WS_MAX_ACTIVE_CONNECTIONS_PER_IP)) {
                ws.close(1008, 'Too many connections');
                return;
            }
            registerActive(wsActiveConnectionsByIp, ipKey);
            ws._activeIpKey = ipKey;

		    if (!checkWebSocketRateLimit(ipKey)) { ws.close(1008, 'Rate limit exceeded'); return; }

		    const cookies = {};
		    if (req.headers.cookie) req.headers.cookie.split(';').forEach(c => { const p = c.split('='); cookies[p[0].trim()] = (p[1] || '').trim(); });
		    const sessionId = cookies[SESSION_COOKIE_NAME];
		    if (!sessionId) { ws.close(1008, 'Unauthorized'); return; }

            if (!canRegisterActive(wsActiveConnectionsBySession, sessionId, WS_MAX_ACTIVE_CONNECTIONS_PER_SESSION)) {
                ws.close(1008, 'Too many sessions');
                return;
            }
            registerActive(wsActiveConnectionsBySession, sessionId);
            ws._activeSessionKey = sessionId;

		    const session = typeof getSessionFromId === 'function' ? getSessionFromId(sessionId) : sessions.get(sessionId);
		    if (!session || !session.userId) { ws.close(1008, 'Unauthorized'); return; }
		    ws.userId = session.userId; ws.username = session.username; ws.sessionId = sessionId; ws.isAlive = true;
			registerSessionConnection(sessionId, ws);
		    ws.on('pong', () => { ws.isAlive = true; });
			ws.on('message', async (msg) => {
		        try { const data = JSON.parse(msg); await handleWebSocketMessage(ws, data, pool, sanitizeHtmlContent, getSessionFromId); } catch (e) { ws.send(JSON.stringify({ event: 'error', data: { message: 'Failed' } })); }
		    });
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
        conns.add({ ws, userId, username: ws.username, color, permission, storageId: page.storage_id, permCheckedAt: Date.now() });
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
        wsConnections.storages.get(storageId).add({ ws, userId, permission, storageId, permCheckedAt: Date.now() });
    } catch (e) {}
}

function handleUnsubscribeStorage(ws, payload) {
    const { storageId } = payload;
    const conns = wsConnections.storages.get(storageId);
    if (conns) { conns.forEach(c => { if (c.ws === ws) conns.delete(c); }); if (conns.size === 0) wsConnections.storages.delete(storageId); }
}

async function refreshConnPermission(pool, conn) {
    if (!conn || !conn.storageId) return conn?.permission || null;
    const now = Date.now();
    const last = conn.permCheckedAt || 0;
    if (now - last < WS_PERMISSION_REFRESH_MS) return conn.permission;

    const fresh = await getStoragePermission(pool, conn.userId, conn.storageId);
    conn.permCheckedAt = now;
    conn.permission = fresh;
    return fresh;
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
        if (!myConn) return;

        // 권한 재검증(권한 회수/다운그레이드 즉시 반영)
        const freshPerm = await refreshConnPermission(pool, myConn);
        if (!freshPerm) {
            // 접근 회수: 페이지 구독에서 제거하고 클라이언트에 통지
            conns.delete(myConn);
            if (conns.size === 0) wsConnections.pages.delete(pageId);
            try { ws.send(JSON.stringify({ event: 'access-revoked', data: { pageId } })); } catch (e) {}
            return;
        }

        if (!['EDIT', 'ADMIN'].includes(freshPerm)) return;

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
    // DoS 방지: 활성 연결 슬롯 해제 (중복 호출 대비 idempotent)
    releaseActiveConnectionSlots(ws);

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



/**
 * 저장소 권한이 회수된 사용자를 해당 storage/page 구독에서 즉시 강제 해제
 * - 협업자 제거/권한 변경 시 서버에서 호출해 열려 있는 WebSocket 기반 권한 지속을 차단
 */
function wsKickUserFromStorage(storageId, targetUserId, closeCode = 1008, reason = 'Access revoked') {
    const sid = String(storageId);
    const uid = String(targetUserId);

    // storage 구독 제거
    const storConns = wsConnections.storages.get(sid);

    if (storConns) {
        for (const c of Array.from(storConns)) {
            if (String(c.userId) === uid) {
                storConns.delete(c);
                try { c.ws.send(JSON.stringify({ event: 'access-revoked', data: { storageId: sid } })); } catch (e) {}
            }
        }
        if (storConns.size === 0) wsConnections.storages.delete(sid);
    }

    // page 구독 제거 (storageId가 같은 것만)
    for (const [pageId, pageConns] of Array.from(wsConnections.pages.entries())) {
        for (const c of Array.from(pageConns)) {
            if (String(c.userId) === uid && String(c.storageId) === sid) {
                pageConns.delete(c);
                try { c.ws.send(JSON.stringify({ event: 'access-revoked', data: { pageId, storageId: sid } })); } catch (e) {}
            }
        }
        if (pageConns.size === 0) wsConnections.pages.delete(pageId);
    }

    // 해당 사용자의 모든 WS를 끊어 재연결 유도
    const userConns = wsConnections.users.get(uid);
    if (userConns) for (const c of Array.from(userConns)) { try { c.ws.close(closeCode, reason); } catch (e) {} }
}

module.exports = { initWebSocketServer, wsBroadcastToPage, wsBroadcastToStorage, wsBroadcastToUser, startRateLimitCleanup, startInactiveConnectionsCleanup, wsConnections, yjsDocuments, saveYjsDocToDatabase, wsCloseConnectionsForSession, wsKickUserFromStorage };