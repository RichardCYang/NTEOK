/**
 * ==================== WebSocket 서버 모듈 ====================
 * WebSocket 서버 및 실시간 동기화 기능 (컬렉션 제거 버전)
 */

const WebSocket = require("ws");
const Y = require("yjs");
const { URL } = require("url");
const { formatDateForDb } = require("./network-utils");
const { validateAndNormalizeIcon } = require("./utils/icon-utils");

// WebSocket 입력 정화: Prototype Pollution 방어
// HTTP(body) 미들웨어(server.js)는 REST API 요청만 처리하므로,
// WebSocket 메시지(JSON.parse 결과)에는 별도 위험 키 제거가 필수
// __proto__/constructor/prototype이 own-property로 존재하면
// Object.assign/라이브러리 merge 경로에서 프로토타입 오염(CWE-1321) + DoS 유발 가능
const DANGEROUS_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function stripDangerousKeysDeep(value) {
    if (!value || typeof value !== "object") return value;
    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i++) {
            value[i] = stripDangerousKeysDeep(value[i]);
        }
        return value;
    }
    for (const k of Object.keys(value)) {
        if (DANGEROUS_OBJECT_KEYS.has(k)) {
            delete value[k];
            continue;
        }
        value[k] = stripDangerousKeysDeep(value[k]);
    }
    return value;
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

// ==================== WebSocket DoS 방어: 메시지 레이트/크기 제한 ====================
// 연결 수 제한만으로는 1개 연결에서의 메시지 플러딩을 막기 어려움
// WebSocket 메시지 처리(JSON.parse, base64 decode, Yjs applyUpdate, DB save)는 CPU/메모리 소비
// (CWE-400 Uncontrolled Resource Consumption)
const WS_MSG_RATE_WINDOW_MS = (() => {
    const v = parseInt(process.env.WS_MSG_RATE_WINDOW_MS || "10000", 10);
    return Number.isFinite(v) && v >= 1000 && v <= 600000 ? v : 10000;
})();

const WS_MSG_RATE_MAX = (() => {
    const v = parseInt(process.env.WS_MSG_RATE_MAX || "400", 10);
    return Number.isFinite(v) && v >= 20 && v <= 10000 ? v : 400;
})();

const WS_YJS_RATE_MAX = (() => {
    const v = parseInt(process.env.WS_YJS_RATE_MAX || "200", 10);
    return Number.isFinite(v) && v >= 10 && v <= 5000 ? v : 200;
})();

const WS_AWARENESS_RATE_MAX = (() => {
    const v = parseInt(process.env.WS_AWARENESS_RATE_MAX || "300", 10);
    return Number.isFinite(v) && v >= 10 && v <= 5000 ? v : 300;
})();

const WS_MAX_YJS_UPDATE_BYTES = (() => {
    const v = parseInt(process.env.WS_MAX_YJS_UPDATE_BYTES || String(512 * 1024), 10);
    return Number.isFinite(v) && v >= (32 * 1024) && v <= WS_MAX_MESSAGE_BYTES ? v : (512 * 1024);
})();

const WS_MAX_YJS_STATE_BYTES = (() => {
    const v = parseInt(process.env.WS_MAX_YJS_STATE_BYTES || String(1024 * 1024), 10);
    return Number.isFinite(v) && v >= (128 * 1024) && v <= (32 * 1024 * 1024) ? v : (1024 * 1024);
})();

/**
 * Yjs 문서 크기(추정치) 상한
 * - encodeStateAsUpdate()는 문서 크기/히스토리에 비례해 CPU/메모리를 크게 소모할 수 있음
 * - 악성 협업자가 과도한 업데이트/삭제를 유도하면 서버가 OOM/응답불가(DoS)에 빠질 수 있음 (CWE-400)
 */
const WS_MAX_DOC_EST_BYTES = (() => {
    const def = Math.max(WS_MAX_YJS_STATE_BYTES * 8, 8 * 1024 * 1024); // 기본: 8MB 또는 state 저장 상한의 8배
    const v = parseInt(process.env.WS_MAX_DOC_EST_BYTES || String(def), 10);
    if (!Number.isFinite(v)) return def;
    return Math.max(512 * 1024, Math.min(64 * 1024 * 1024, v)); // 512KB~64MB
})();

function byteLenUtf8(value) {
    try { return Buffer.byteLength(String(value ?? ''), 'utf8'); } catch { return 0; }
}

const WS_MAX_YJS_UPDATE_B64_CHARS = Math.ceil(WS_MAX_YJS_UPDATE_BYTES / 3) * 4 + 8;
const WS_MAX_AWARENESS_UPDATE_B64_CHARS = Math.ceil(WS_MAX_AWARENESS_UPDATE_BYTES / 3) * 4 + 8;

function initWsMessageRateState(ws) {
    ws._msgRate = { windowStart: Date.now(), total: 0, yjs: 0, awareness: 0, badJson: 0 };
}

function consumeWsMessageBudget(ws, kind) {
    if (!ws || !ws._msgRate) return true;
    const now = Date.now();
    if (now - ws._msgRate.windowStart >= WS_MSG_RATE_WINDOW_MS) {
        ws._msgRate.windowStart = now;
        ws._msgRate.total = 0;
        ws._msgRate.yjs = 0;
        ws._msgRate.awareness = 0;
        ws._msgRate.badJson = 0;
    }
    ws._msgRate.total++;
    if (ws._msgRate.total > WS_MSG_RATE_MAX) return false;
    if (kind === "yjs-update") { ws._msgRate.yjs++; if (ws._msgRate.yjs > WS_YJS_RATE_MAX) return false; }
    if (kind === "awareness-update") { ws._msgRate.awareness++; if (ws._msgRate.awareness > WS_AWARENESS_RATE_MAX) return false; }
    if (kind === "bad-json") { ws._msgRate.badJson++; if (ws._msgRate.badJson > 20) return false; }
    return true;
}

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

/**
 * 특정 페이지에 연결된 모든 WebSocket을 강제 종료 (문서 비대화 DoS 방어)
 */
function wsCloseConnectionsForPage(pageId, code = 1009, reason = 'Document too large') {
    const pid = String(pageId || '');
    const conns = wsConnections.pages.get(pid);
    if (!conns || conns.size === 0) {
        if (yjsDocuments.has(pid)) yjsDocuments.delete(pid);
        return;
    }

    for (const c of Array.from(conns)) {
        try { c.ws.send(JSON.stringify({ event: 'collab-reset', data: { pageId: pid, reason } })); } catch (_) {}
        try { c.ws.close(code, reason); } catch (_) {}
    }

    wsConnections.pages.delete(pid);
    if (yjsDocuments.has(pid)) yjsDocuments.delete(pid);
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

/**
 * 보안(중요): paperclip 참조는 항상 해당 페이지 소유자의 디렉터리만 대상으로 해야 함
 *
 * 취약점 배경:
 * - 기존 cleanupOrphanedFiles는 ref("<userId>/<filename>")의 userId가 누구인지와 무관하게,
 *   다른 페이지에서 더 이상 참조되지 않는다는 조건만 만족하면 paperclip 디렉터리에서 파일을 삭제하였음
 * - 악의적 협업자(동일 저장소의 EDIT/ADMIN 권한)는 Yjs 업데이트를 통해 본인 페이지에
 *   타 사용자(userId)의 /paperclip URL을 삽입/삭제하는 방식으로, 해당 사용자의 고아(orphan) 첨부 파일을
 *   임의로 삭제할 수 있었음(무단 파기/데이터 손실)
 *
 * 완화:
 * - ref의 userId가 pageOwnerUserId와 일치하는 경우에만 추적/정리 대상으로 포함
 * - DB 조회(참조 여부 확인)도 동일 소유자의 pages로 범위를 제한
 */
function normalizePaperclipRefForOwner(ref, pageOwnerUserId) {
    const normalized = normalizePaperclipRef(ref);
    if (!normalized) return null;
    const [uid] = normalized.split('/');
    if (!uid) return null;
    const ownerIdStr = String(pageOwnerUserId ?? '').trim();
    if (!ownerIdStr || uid !== ownerIdStr) return null;
    return normalized;
}

function extractFilesFromContent(content, pageOwnerUserId = null) {
    const files = [];
    if (!content) return files;

    // data-src="/paperclip/<userId>/<filename>" 형태만 추출
    // (파일명/유저ID allowlist 적용; path traversal 시도는 무시)
    const fileRegex = /<div[^>]*data-type=["']file-block["'][^>]*data-src=["']\/paperclip\/([^"']+)["'][^>]*>/gi;
    let match;
    while ((match = fileRegex.exec(String(content))) !== null) {
        const ref = (pageOwnerUserId !== null && pageOwnerUserId !== undefined)
            ? normalizePaperclipRefForOwner(match[1], pageOwnerUserId)
            : normalizePaperclipRef(match[1]);
        if (ref) files.push(ref);
    }
    return files;
}

async function cleanupOrphanedFiles(pool, filePaths, excludePageId, pageOwnerUserId) {
    if (!filePaths || filePaths.length === 0) return;

    const fs = require('fs');
    const path = require('path');
    // 특정 사용자 디렉터리로 scope를 제한 (타 사용자 파일 임의 삭제 방지)
    const ownerIdStr = String(pageOwnerUserId ?? '').trim();
    if (!ownerIdStr || !/^\d{1,12}$/.test(ownerIdStr)) return;
    const baseDir = path.resolve(__dirname, 'paperclip', ownerIdStr) + path.sep;

    // LIKE 패턴에서 와일드카드(% _) 오인 방지
    const escapeLike = (s) => String(s).replace(/[\\%_]/g, (m) => '\\\\' + m);

    for (const ref of filePaths) {
        try {
            const normalized = normalizePaperclipRefForOwner(ref, ownerIdStr);
            if (!normalized) continue;

            const fileUrl = `/paperclip/${normalized}`;
            const likePattern = `%${escapeLike(fileUrl)}%`;

            // 동일 사용자(페이지 소유자) 범위 내에서만 참조 여부 확인
            // - 다른 사용자가 우연히 동일 문자열을 포함했는지 여부는 중요하지 않음
            // - 그리고 다른 사용자의 pages를 스캔하면, 악의적 협업자가 문자열 조작으로
            //   의도치 않은 삭제/보존을 유도할 여지가 생김
            const [rows] = await pool.execute(
                `SELECT COUNT(*) as count
                   FROM pages
                  WHERE user_id = ?
                    AND content LIKE ? ESCAPE '\\\\'
                    AND id != ?`,
                [ownerIdStr, likePattern, excludePageId]
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
        const isEncrypted = (existingRows.length > 0 && existingRows[0].is_encrypted === 1);
        const pageOwnerUserId = (existingRows.length > 0 ? existingRows[0].user_id : null);
        let finalContent = content;
        let oldFiles = [];
        if (existingRows.length > 0) {
            const existing = existingRows[0];
            if (existing.is_encrypted === 1) finalContent = '';
            else oldFiles = extractFilesFromContent(existing.content, pageOwnerUserId);
        }

        // 보안: 암호화된 페이지는 yjs_state에 문서 스냅샷(평문)이 남을 수 있으므로 DB에 저장하지 않음
        // - 페이지 암호화의 핵심은 서버/DB 어디에도 평문이 남지 않게 하는 것
        // - 암호화 페이지에 대한 WS 구독은 이미 차단하지만(실시간 협업 미지원)
        //   경쟁 조건/레거시 문서 객체가 남아 있는 경우 저장 타이밍에 평문이 영구 저장될 수 있음
        // DoS 방지: 큰 문서는 encodeStateAsUpdate 자체를 호출하지 않음 (CWE-400)
        // - encodeStateAsUpdate는 문서 크기/히스토리에 비례해 CPU/메모리 스파이크 유발 가능
        // - approxBytes가 저장 상한을 이미 초과한 경우 인코딩 자체를 건너뜀
        let yjsStateToSave = null;
        if (!isEncrypted) {
            const meta = yjsDocuments.get(pageId);
            const approx = meta?.approxBytes;
            if (Number.isFinite(approx) && approx <= WS_MAX_YJS_STATE_BYTES) {
                try {
                    yjsStateToSave = Buffer.from(Y.encodeStateAsUpdate(ydoc));
                    // DoS/DB bloat 방지: 실제 인코딩 크기도 재확인
                    if (yjsStateToSave.length > WS_MAX_YJS_STATE_BYTES) yjsStateToSave = null;
                } catch (_) {
                    yjsStateToSave = null;
                }
            }
            // approx 미설정(undefined/NaN)이거나 상한 초과 시: HTML snapshot 저장만 유지
        }

        await pool.execute(
            `UPDATE pages SET title = ?, content = ?, icon = ?, sort_order = ?, parent_id = ?, yjs_state = ?, updated_at = NOW() WHERE id = ?`,
            [title, finalContent, icon, sortOrder, parentId, yjsStateToSave, pageId]
        );

        if (existingRows.length > 0 && existingRows[0].is_encrypted === 0) {
            const newFiles = extractFilesFromContent(content, pageOwnerUserId);
            const deletedFiles = oldFiles.filter(f => !newFiles.includes(f));
            if (deletedFiles.length > 0) cleanupOrphanedFiles(pool, deletedFiles, pageId, pageOwnerUserId).catch(e => {});
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
         WHERE id = ?
           AND deleted_at IS NULL`,
        [pageId]
    );

    const ydoc = new Y.Doc();
    const yMetadata = ydoc.getMap('metadata');
	if (rows.length > 0) {
	    const page = rows[0];

	    // 보안: 암호화 페이지는 yjs_state를 절대 신뢰/복원하지 않는다(평문 잔존/복호화 우회 방지)
	    if (page.is_encrypted === 1) {
	        yMetadata.set('seeded', false);
	    } else if (page.yjs_state) {
	        try { Y.applyUpdate(ydoc, Buffer.from(page.yjs_state)); yMetadata.set('seeded', true); } catch (e) { yMetadata.set('seeded', false); }
	    } else {
	        yMetadata.set('seeded', false);
	    }
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
            // 추정 크기(대략): yjs_state + HTML snapshot 크기 기반 (DoS 방어용)
            approxBytes: (Buffer.isBuffer(page.yjs_state) ? page.yjs_state.length : 0) + byteLenUtf8(_safeHtml),
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
        approxBytes: 0,
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
 			// Object.assign은 [[Set]]을 사용하여 __proto__ setter를 호출할 수 있으므로
 			// spread 연산자([[Define]] 사용)로 대체 — 프로토타입 오염 경로 제거
 			payloadData = { ...data, pageIds: filtered };
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

function initWebSocketServer(server, sessions, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest, pageSqlPolicy) {
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
            ws.on('error', () => { /* prevent unhandled errors */ });

            // per-connection 메시지 레이트 리밋 상태 초기화
            initWsMessageRateState(ws);

			ws.on('message', async (msg, isBinary) => {
		        try {
                    // JSON only: 바이너리 프레임은 거부
                    if (isBinary) {
                        if (!consumeWsMessageBudget(ws, "bad-json")) { try { ws.close(1008, 'Rate limit exceeded'); } catch (_) {} }
                        else { try { ws.close(1003, 'Binary not supported'); } catch (_) {} }
                        return;
                    }

                    const text = (typeof msg === 'string') ? msg : (Buffer.isBuffer(msg) ? msg.toString('utf8') : String(msg));
                    if (text.length > (WS_MAX_MESSAGE_BYTES + 1024)) { try { ws.close(1009, 'Message too big'); } catch (_) {} return; }

                    let data;
                    try { data = JSON.parse(text); }
                    catch (_) {
                        if (!consumeWsMessageBudget(ws, "bad-json")) { try { ws.close(1008, 'Rate limit exceeded'); } catch (_) {} }
                        else { try { ws.send(JSON.stringify({ event: 'error', data: { message: 'Invalid message' } })); } catch (_) {} }
                        return;
                    }

                    // WebSocket 입력은 HTTP 미들웨어를 거치지 않으므로
                    // JSON.parse 직후 __proto__/constructor/prototype 위험 키 제거 필수
                    // (Object.assign/라이브러리 merge 경로에서 프로토타입 오염 차단)
                    data = stripDangerousKeysDeep(data);
                    if (!data || typeof data !== "object") {
                        try { ws.send(JSON.stringify({ event: 'error', data: { message: 'Invalid message' } })); } catch (_) {}
                        return;
                    }

                    const kind = (data && typeof data.type === 'string') ? data.type : 'unknown';
                    if (!consumeWsMessageBudget(ws, kind)) { try { ws.close(1008, 'Rate limit exceeded'); } catch (_) {} return; }

                    await handleWebSocketMessage(ws, data, pool, sanitizeHtmlContent, getSessionFromId, pageSqlPolicy);
                } catch (_) {
                    try { ws.send(JSON.stringify({ event: 'error', data: { message: 'Failed' } })); } catch (_) {}
                }
		    });
		    ws.send(JSON.stringify({ event: 'connected', data: { userId: session.userId, username: session.username } }));
      	} catch (err) { try { ws.close(1011, 'Error'); } catch (_) {} }
    });
    const heartbeatInterval = setInterval(() => { wss.clients.forEach(ws => { if (ws.isAlive === false) { cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent); return ws.terminate(); } ws.isAlive = false; ws.ping(); }); }, 60000);
    wss.on('close', () => { clearInterval(heartbeatInterval); });
    return wss;
}

async function handleWebSocketMessage(ws, data, pool, sanitizeHtmlContent, getSessionFromId, pageSqlPolicy) {
	const { type, payload } = data;
	if (ws.sessionId && typeof getSessionFromId === 'function') {
	    const s = getSessionFromId(ws.sessionId);
	    if (!s || !s.userId) { try { ws.close(1008, 'Expired'); } catch (e) {} return; }
	}
	switch (type) {
        case 'subscribe-page': await handleSubscribePage(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'unsubscribe-page': handleUnsubscribePage(ws, payload, pool, sanitizeHtmlContent); break;
        case 'subscribe-storage': await handleSubscribeStorage(ws, payload, pool); break;
        case 'unsubscribe-storage': handleUnsubscribeStorage(ws, payload); break;
        case 'subscribe-user': handleSubscribeUser(ws, payload); break;
        case 'yjs-update': await handleYjsUpdate(ws, payload, pool, sanitizeHtmlContent); break;
        case 'awareness-update': handleAwarenessUpdate(ws, payload); break;
    }
}

async function handleSubscribePage(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy) {
    const { pageId } = payload;
    const userId = ws.userId;
    try {
        // 보안: WebSocket에서도 HTTP API와 동일한 가시성 정책(pageSqlPolicy)을 적용해야 함
        // - 암호화(is_encrypted=1) + 공유불가(share_allowed=0) 페이지는 작성자만 접근 가능
        const vis = (pageSqlPolicy && typeof pageSqlPolicy.andVisible === "function")
            ? pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId })
            : { sql: " AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)", params: [userId] };

        const [rows] = await pool.execute(
            `SELECT p.id, p.user_id, p.is_encrypted, p.share_allowed, p.storage_id
             FROM pages p
             WHERE p.id = ?
               AND p.deleted_at IS NULL
             ${vis.sql}`,
            [pageId, ...vis.params]
        );

        // 존재 여부/권한 여부 노출 최소화: 접근 불가도 동일하게 Not found
        if (!rows.length) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        const page = rows[0];
        const permission = await getStoragePermission(pool, userId, page.storage_id);

        if (!permission) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        // 방어적 재검증(정책 누락/변경 대비)
        if (page.is_encrypted === 1 && page.share_allowed === 0 && Number(page.user_id) !== Number(userId)) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        if (page.is_encrypted === 1) {
            // 암호화된 페이지는 실시간 편집 지원 안 함 (단순 동기화만 하거나 제외)
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Encrypted pages do not support real-time collaboration yet' } }));
            return;
        }

        const ydoc = await loadOrCreateYjsDoc(pool, sanitizeHtmlContent, pageId);

        // DoS 방어: approxBytes 기반 문서 크기 사전 검사 (CWE-400)
        const meta = yjsDocuments.get(pageId);
        if (meta && Number.isFinite(meta.approxBytes) && meta.approxBytes > WS_MAX_DOC_EST_BYTES) {
            wsCloseConnectionsForPage(pageId, 1009, 'Document too large - collaboration reset');
            return;
        }

        if (!wsConnections.pages.has(pageId)) wsConnections.pages.set(pageId, new Set());
        const conns = wsConnections.pages.get(pageId);
        for (const c of Array.from(conns)) {
            if (c.userId === userId && c.ws !== ws) { conns.delete(c); try { c.ws.close(1008, 'Duplicate'); } catch (_) {} }
        }
        const color = getUserColor(userId);
        conns.add({ ws, userId, username: ws.username, color, permission, storageId: page.storage_id, permCheckedAt: Date.now() });

        // init 상태 인코딩 (실제 크기 재확인 + OOM 방어)
        let stateB64 = '';
        try {
            const stateBuf = Buffer.from(Y.encodeStateAsUpdate(ydoc));
            if (stateBuf.length > WS_MAX_DOC_EST_BYTES) {
                wsCloseConnectionsForPage(pageId, 1009, 'Document too large - collaboration reset');
                return;
            }
            stateB64 = stateBuf.toString('base64');
        } catch (_) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Failed to init document' } }));
            return;
        }
        ws.send(JSON.stringify({ event: 'init', data: { state: stateB64, userId, username: ws.username, color, permission } }));
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
        // DoS 방지: 업데이트 크기 제한 (base64 길이 + 디코딩 후 바이트)
        if (update.length > WS_MAX_YJS_UPDATE_B64_CHARS) throw new Error('Update too large');
        const updateBuf = Buffer.from(update, 'base64');
        if (updateBuf.length > WS_MAX_YJS_UPDATE_BYTES) throw new Error('Update too large');

        // 보안: 협업 업데이트에 위험 URI 패턴이 포함되면 즉시 거부 (DOM XSS/DoS 방어)
        // - Yjs update는 바이너리지만, 문자열(URI)이 그대로 포함되는 경우가 많아 최소 차단선으로 유효
        const BAD = [
            Buffer.from('javascript:', 'utf8'),
            Buffer.from('data:', 'utf8'),
            Buffer.from('vbscript:', 'utf8'),
            Buffer.from('file:', 'utf8')
        ];

        for (const sig of BAD) {
            if (updateBuf.indexOf(sig) !== -1) {
                try { ws.close(1008, 'Blocked unsafe update'); } catch (_) {}
                return;
            }
        }

        // DoS 방어: 업데이트 적용 전 누적 크기 검사 (CWE-400)
        const doc = yjsDocuments.get(pageId);
        if (doc) {
            const cur = Number.isFinite(doc.approxBytes) ? doc.approxBytes : 0;
            const next = cur + updateBuf.length;
            if (next > WS_MAX_DOC_EST_BYTES) {
                // HTML snapshot만 저장하고 협업 세션 리셋
                try { await saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc); } catch (_) {}
                wsCloseConnectionsForPage(pageId, 1009, 'Document too large - collaboration reset');
                return;
            }
        }

        Y.applyUpdate(ydoc, updateBuf);
        // approxBytes 갱신 (누적 추정 크기)
        if (doc) doc.approxBytes = (Number.isFinite(doc.approxBytes) ? doc.approxBytes : 0) + updateBuf.length;

        wsBroadcastToPage(pageId, 'yjs-update', { update }, ws.userId);
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
    const { pageId, awarenessUpdate } = payload || {};
    if (!pageId || typeof awarenessUpdate !== 'string' || !isSubscribedToPage(ws, pageId)) return;

    // DoS 방지: awareness는 작아야 함(커서/선택 정보)
    if (awarenessUpdate.length > WS_MAX_AWARENESS_UPDATE_B64_CHARS) return;

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