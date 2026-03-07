
const WebSocket = require("ws");
const Y = require("yjs");
const { URL } = require("url");
const { formatDateForDb } = require("./network-utils");
const { validateAndNormalizeIcon } = require("./utils/icon-utils");

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

let _wsPool = null;
let _wsSanitizeHtmlContent = null;

const emergencyPersistState = new Map(); 

const EMERGENCY_PERSIST_MAX_ATTEMPTS = Math.max(0, Math.min(30, Number.parseInt(process.env.YJS_EMERGENCY_PERSIST_MAX_ATTEMPTS || '8', 10)));
const EMERGENCY_PERSIST_BASE_MS = Math.max(200, Math.min(60000, Number.parseInt(process.env.YJS_EMERGENCY_PERSIST_BASE_MS || '1500', 10)));
const EMERGENCY_PERSIST_MAX_MS = Math.max(500, Math.min(300000, Number.parseInt(process.env.YJS_EMERGENCY_PERSIST_MAX_MS || '60000', 10)));

function computeEmergencyPersistDelayMs(attempt) {
    const a = Math.max(1, Math.min(30, attempt));
    return Math.min(EMERGENCY_PERSIST_MAX_MS, Math.floor(EMERGENCY_PERSIST_BASE_MS * Math.pow(2, a - 1)));
}

function inferForceClearYjsStateFromReason(reason) {
    const r = String(reason || '').toLowerCase();
    return !r || r.includes('too large') || r.includes('oversize') || r.includes('resync') || r.includes('reset');
}


function scheduleEmergencyPersistThenDrop(pageId, reason, opts = {}) {
    const pid = String(pageId || '').trim();
    if (!pid) return;

    const docInfo = yjsDocuments.get(pid);
    if (!docInfo || !docInfo.ydoc || docInfo.isEncrypted) {
        if (yjsDocuments.has(pid)) dropYjsDocument(pid);
        return;
    }

    if (!_wsPool || typeof _wsPool.execute !== 'function' || typeof _wsSanitizeHtmlContent !== 'function') {
        try { if (docInfo.saveTimeout) clearTimeout(docInfo.saveTimeout); } catch (_) {}
        dropYjsDocument(pid);
        return;
    }

    if (emergencyPersistState.get(pid)?.timer) return;

    try { if (docInfo.saveTimeout) clearTimeout(docInfo.saveTimeout); } catch (_) {}
    docInfo.saveTimeout = null;

    const forceClearYjsState = (opts.forceClearYjsState !== undefined) ? opts.forceClearYjsState : inferForceClearYjsStateFromReason(reason);
    const epoch = bumpYjsSaveEpoch(pid);
    const state = { epoch, attempts: 0, timer: null, forceClearYjsState };
    emergencyPersistState.set(pid, state);

    const attempt = async () => {
        const cur = emergencyPersistState.get(pid);
        if (!cur) return;
        try {
            const result = await enqueueYjsDbSave(pid, () =>
                saveYjsDocToDatabase(_wsPool, _wsSanitizeHtmlContent, pid, docInfo.ydoc, {
                    epoch: cur.epoch,
                    forceClearYjsState: cur.forceClearYjsState
                })
            );
            if (result?.status === 'skipped-epoch') { emergencyPersistState.delete(pid); return; }
            emergencyPersistState.delete(pid);
            dropYjsDocument(pid, { bumpEpoch: false });
        } catch (e) {
            cur.attempts++;
            cur.timer = null;
            if (EMERGENCY_PERSIST_MAX_ATTEMPTS > 0 && cur.attempts <= EMERGENCY_PERSIST_MAX_ATTEMPTS) {
                cur.timer = setTimeout(attempt, computeEmergencyPersistDelayMs(cur.attempts));
                emergencyPersistState.set(pid, cur);
            } else {
                emergencyPersistState.delete(pid);
            }
        }
    };
    state.timer = setTimeout(attempt, 0);
    emergencyPersistState.set(pid, state);
}

const yjsDbSaveQueue = new Map(); 

function enqueueYjsDbSave(pageId, taskFn) {
    const pid = String(pageId || '').trim();
    if (!pid) return Promise.resolve({ status: 'skipped-no-pageid' });

    const prev = yjsDbSaveQueue.get(pid) || Promise.resolve();
    const next = prev
        .catch(() => {})
        .then(() => taskFn());

    yjsDbSaveQueue.set(
        pid,
        next.finally(() => {
            if (yjsDbSaveQueue.get(pid) === next) yjsDbSaveQueue.delete(pid);
        })
    );
    return next;
}

async function flushAllPendingYjsDbSaves() {
    const pending = Array.from(yjsDbSaveQueue.values());
    if (!pending.length) return;
    await Promise.allSettled(pending);
}

const yjsSaveEpoch = new Map(); 

function getYjsSaveEpoch(pageId) {
    const pid = String(pageId || '');
    return yjsSaveEpoch.get(pid) || 0;
}

function bumpYjsSaveEpoch(pageId) {
    const pid = String(pageId || '');
    const current = yjsSaveEpoch.get(pid) || 0;
    const next = current + 1;
    yjsSaveEpoch.set(pid, next);
    return next;
}

function dropYjsDocument(pageId, opts = {}) {
    const pid = String(pageId || '');
    const bumpEpoch = opts.bumpEpoch !== false;
    if (bumpEpoch) bumpYjsSaveEpoch(pid);
    const doc = yjsDocuments.get(pid);
    if (doc?.saveTimeout) {
        try { clearTimeout(doc.saveTimeout); } catch (_) {}
        doc.saveTimeout = null;
    }
    yjsDocuments.delete(pid);
}

const yjsE2EEStates = new Map();

const e2eeSnapshotLeaders = new Map();

const USER_COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B195', '#C06C84'];
const wsConnectionLimiter = new Map();
const WS_RATE_LIMIT_WINDOW = 60 * 1000;
const WS_RATE_LIMIT_MAX_CONNECTIONS = 10;
const WS_MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
const WS_MAX_AWARENESS_UPDATE_BYTES = 32 * 1024;

const E2EE_SNAPSHOT_EXPECT_MS = (() => {
    const n = Number.parseInt(process.env.E2EE_SNAPSHOT_EXPECT_MS || '1500', 10);
    if (!Number.isFinite(n)) return 1500;
    return Math.max(300, Math.min(10_000, n));
})();

const e2eeLastUpdateAt = new Map();        
const e2eeLastSnapshotAt = new Map();      
const e2eeSnapshotRequestTimers = new Map(); 

const E2EE_UPDATELOG_FLUSH_MS = (() => {
    const n = Number.parseInt(process.env.E2EE_UPDATELOG_FLUSH_MS || '200', 10);
    return (Number.isFinite(n) && n >= 0) ? n : 200;
})();
const E2EE_UPDATELOG_MAX_BATCH = (() => {
    const n = Number.parseInt(process.env.E2EE_UPDATELOG_MAX_BATCH || '50', 10);
    return (Number.isFinite(n) && n > 0) ? n : 50;
})();
const E2EE_UPDATELOG_MAX_UPDATES_PER_PAGE = (() => {
    const n = Number.parseInt(process.env.E2EE_UPDATELOG_MAX_UPDATES_PER_PAGE || '5000', 10);
    return (Number.isFinite(n) && n > 0) ? n : 5000;
})();
const E2EE_PENDING_SEND_CHUNK_MAX_B64_CHARS = (() => {
    const n = Number.parseInt(process.env.E2EE_PENDING_SEND_CHUNK_MAX_B64_CHARS || '262144', 10); 
    return (Number.isFinite(n) && n > 0) ? n : 262144;
})();

const e2eeUpdateLogBuffer = new Map(); 
let e2eeUpdateLogFlushTimer = null;

function bufferE2eeUpdateLog(pool, pageId, updateBuf) {
    if (!pageId || !updateBuf) return;
    const pid = String(pageId);
    if (!e2eeUpdateLogBuffer.has(pid)) e2eeUpdateLogBuffer.set(pid, []);
    
    const queue = e2eeUpdateLogBuffer.get(pid);
    if (queue.length >= E2EE_UPDATELOG_MAX_UPDATES_PER_PAGE) return;

    queue.push({ ms: Date.now(), blob: updateBuf });

    if (!e2eeUpdateLogFlushTimer) {
        e2eeUpdateLogFlushTimer = setTimeout(() => {
            e2eeUpdateLogFlushTimer = null;
            flushAllPendingE2eeUpdateLogs(pool).catch(() => {});
        }, E2EE_UPDATELOG_FLUSH_MS);
    }
}

async function flushAllPendingE2eeUpdateLogs(pool) {
    if (e2eeUpdateLogBuffer.size === 0) return;

    const pageIds = Array.from(e2eeUpdateLogBuffer.keys());
    for (const pid of pageIds) {
        const queue = e2eeUpdateLogBuffer.get(pid);
        if (!queue || queue.length === 0) {
            e2eeUpdateLogBuffer.delete(pid);
            continue;
        }

        const batch = queue.splice(0, E2EE_UPDATELOG_MAX_BATCH);
        if (queue.length === 0) e2eeUpdateLogBuffer.delete(pid);

        try {
            const values = [];
            const placeholders = [];
            for (const item of batch) {
                placeholders.push('(?, ?, ?, ?)');
                values.push(pid, item.ms, formatDateForDb(new Date(item.ms)), item.blob);
            }

            await pool.execute(`
                INSERT INTO e2ee_yjs_updates (page_id, created_at_ms, created_at, update_blob)
                VALUES ${placeholders.join(', ')}
            `, values);
        } catch (e) {
            console.error(`[E2EE] WAL flush 실패(page=${pid}):`, e.message);
        }
    }

    if (e2eeUpdateLogBuffer.size > 0 && !e2eeUpdateLogFlushTimer) {
        e2eeUpdateLogFlushTimer = setTimeout(() => {
            e2eeUpdateLogFlushTimer = null;
            flushAllPendingE2eeUpdateLogs(pool).catch(() => {});
        }, E2EE_UPDATELOG_FLUSH_MS);
    }
}

async function sendPendingE2eeUpdatesToClient(ws, pool, pageId, sinceMs) {
    try {
        const [rows] = await pool.execute(`
            SELECT update_blob FROM e2ee_yjs_updates
            WHERE page_id = ? AND created_at_ms > ?
            ORDER BY created_at_ms ASC, id ASC
        `, [pageId, sinceMs || 0]);

        if (!rows || rows.length === 0) {
            ws.send(JSON.stringify({ event: 'e2ee-pending-updates', data: { pageId, done: true } }));
            return;
        }

        let currentBatch = [];
        let currentSize = 0;

        for (const row of rows) {
            const b64 = row.update_blob.toString('base64');
            if (currentSize + b64.length > E2EE_PENDING_SEND_CHUNK_MAX_B64_CHARS && currentBatch.length > 0) {
                ws.send(JSON.stringify({
                    event: 'e2ee-pending-updates',
                    data: { pageId, updates: currentBatch, done: false }
                }));
                currentBatch = [];
                currentSize = 0;
            }
            currentBatch.push(b64);
            currentSize += b64.length;
        }

        if (currentBatch.length > 0) {
            ws.send(JSON.stringify({
                event: 'e2ee-pending-updates',
                data: { pageId, updates: currentBatch, done: false }
            }));
        }

        ws.send(JSON.stringify({ event: 'e2ee-pending-updates', data: { pageId, done: true } }));
    } catch (e) {
        console.error(`[E2EE] WAL 전송 실패(page=${pageId}):`, e.message);
        ws.send(JSON.stringify({ event: 'e2ee-pending-updates', data: { pageId, done: true, error: true } }));
    }
}

function clearE2eeSnapshotRequestTimer(pageId) {
    const pid = String(pageId || '');
    const t = e2eeSnapshotRequestTimers.get(pid);
    if (t) {
        try { clearTimeout(t); } catch (_) {}
        e2eeSnapshotRequestTimers.delete(pid);
    }
}

function wsRequestE2eeSnapshot(pageId) {
    const pid = String(pageId || '');
    if (!pid) return;
    const conns = wsConnections.pages.get(pid);
    if (!conns || conns.size === 0) return;
    for (const c of Array.from(conns)) {
        try {
            if (!c || !c.isE2ee) continue;
            if (!['EDIT','ADMIN'].includes(c.permission)) continue;
            if (c.ws && c.ws.readyState === WebSocket.OPEN) {
                c.ws.send(JSON.stringify({ event: 'request-yjs-state-e2ee', data: { pageId: pid } }));
            }
        } catch (_) {}
    }
}

function wsRequestPageSnapshot(pageId) {
    const pid = String(pageId || '');
    if (!pid) return;
    const conns = wsConnections.pages.get(pid);
    if (!conns || conns.size === 0) return;
    for (const c of Array.from(conns)) {
        try {
            if (!c || c.isE2ee) continue;
            if (!['EDIT','ADMIN'].includes(c.permission)) continue;
            if (c.ws && c.ws.readyState === WebSocket.OPEN) {
                c.ws.send(JSON.stringify({ event: 'request-page-snapshot', data: { pageId: pid } }));
            }
        } catch (_) {}
    }
}

const oversizeResyncCloseTimers = new Map(); 

function scheduleOversizeResyncSnapshotThenClose(pageId, reason = 'Document too large - collaboration reset') {
    const pid = String(pageId || '');
    if (!pid) return;
    if (oversizeResyncCloseTimers.has(pid)) return;

    wsRequestPageSnapshot(pid);

    const delay = Math.max(800, Math.min(5000, (typeof E2EE_SNAPSHOT_EXPECT_MS === 'number' ? (E2EE_SNAPSHOT_EXPECT_MS + 800) : 2300)));
    const t = setTimeout(() => {
        oversizeResyncCloseTimers.delete(pid);
        try { wsCloseConnectionsForPage(pid, 1009, reason); } catch (_) {}
    }, delay);
    oversizeResyncCloseTimers.set(pid, t);
}

function clearOversizeResyncTimer(pageId) {
    const pid = String(pageId || '');
    const t = oversizeResyncCloseTimers.get(pid);
    if (t) {
        try { clearTimeout(t); } catch (_) {}
        oversizeResyncCloseTimers.delete(pid);
    }
}

const E2EE_LEADER_IDLE_HANDOFF_MS = (() => {
    const n = Number.parseInt(process.env.E2EE_LEADER_IDLE_HANDOFF_MS || '2000', 10);
    if (!Number.isFinite(n)) return 2000;
    return Math.max(500, Math.min(60_000, n));
})();


function hasActiveE2eeSessionOnPage(pageId, sessionId) {
    const pid = String(pageId || '');
    const sid = String(sessionId || '');
    if (!pid || !sid) return false;
    const conns = wsConnections.pages.get(pid);
    if (!conns || conns.size === 0) return false;
    for (const c of Array.from(conns)) {
        if (!c || !c.isE2ee) continue;
        if (String(c.sessionId) !== sid) continue;
        const rs = c.ws && c.ws.readyState;
        if (rs === WebSocket.OPEN || rs === WebSocket.CONNECTING) return true;
    }
    return false;
}

function ensureE2eeLeaderForActiveEditor(pageId, myConn) {
    const pid = String(pageId || '');
    if (!pid || !myConn || !myConn.sessionId) return getActiveE2eeLeader(pid);
    let leader = getActiveE2eeLeader(pid);
    const now = Date.now();
    if (!leader) {
        leader = { sessionId: myConn.sessionId, userId: myConn.userId, lastSeenAt: now };
        e2eeSnapshotLeaders.set(pid, leader);
        return leader;
    }
    if (String(leader.sessionId) === String(myConn.sessionId)) {
        leader.lastSeenAt = now;
        return leader;
    }
    if (now - (leader.lastSeenAt || 0) > E2EE_LEADER_IDLE_HANDOFF_MS) {
        leader = { sessionId: myConn.sessionId, userId: myConn.userId, lastSeenAt: now };
        e2eeSnapshotLeaders.set(pid, leader);
        return leader;
    }
    return leader;
}

function getActiveE2eeLeader(pageId) {
    const pid = String(pageId);
    const leader = e2eeSnapshotLeaders.get(pid);
    if (!leader) return null;
    if (!hasActiveE2eeSessionOnPage(pid, leader.sessionId)) {
        e2eeSnapshotLeaders.delete(pid);
        return null;
    }
    if (Date.now() - leader.lastSeenAt > 30000) {
        e2eeSnapshotLeaders.delete(pid);
        return null;
    }
    return leader;
}

function maybeElectE2eeLeader(pageId, myConn) {
    const pid = String(pageId);
    let leader = getActiveE2eeLeader(pid);
    if (!leader) {
        leader = { sessionId: myConn.sessionId, userId: myConn.userId, lastSeenAt: Date.now() };
        e2eeSnapshotLeaders.set(pid, leader);
    }
    return leader;
}

function touchE2eeLeader(pageId, myConn) {
    const pid = String(pageId);
    const leader = e2eeSnapshotLeaders.get(pid);
    if (leader && leader.sessionId === myConn.sessionId) {
        leader.lastSeenAt = Date.now();
        return true;
    }
    return false;
}

const E2EE_SAVE_RETRY_MAX_ATTEMPTS = (() => {
    const v = Number.parseInt(process.env.E2EE_SAVE_RETRY_MAX_ATTEMPTS || '6', 10);
    return Number.isFinite(v) ? Math.max(0, Math.min(20, v)) : 6;
})();
const E2EE_SAVE_RETRY_BASE_MS = (() => {
    const v = Number.parseInt(process.env.E2EE_SAVE_RETRY_BASE_MS || '2000', 10);
    return Number.isFinite(v) ? Math.max(200, Math.min(60_000, v)) : 2000;
})();
const E2EE_SAVE_RETRY_MAX_MS = (() => {
    const v = Number.parseInt(process.env.E2EE_SAVE_RETRY_MAX_MS || '60000', 10);
    return Number.isFinite(v) ? Math.max(500, Math.min(300_000, v)) : 60000;
})();
function computeE2eeRetryDelayMs(attempt) {
    const a = Math.max(1, Math.min(30, attempt));
    const base = E2EE_SAVE_RETRY_BASE_MS * Math.pow(2, a - 1);
    return Math.min(E2EE_SAVE_RETRY_MAX_MS, Math.floor(base));
}

function scheduleE2EESave(pool, pageId, encryptedState, encryptedHtml, snapshotAtMs = null) {
    const pid = String(pageId || '');
    if (!pid || !encryptedState) return;

    const prev = yjsE2EEStates.get(pid) || {};
    if (prev.saveTimeout) {
        try { clearTimeout(prev.saveTimeout); } catch (_) {}
    }

    const next = {
        ...prev,
        encryptedState,
        ...(encryptedHtml !== undefined ? { encryptedHtml } : {}),
        storedAt: Date.now(),
        snapshotAtMs: Number.isFinite(snapshotAtMs) ? snapshotAtMs : (prev.snapshotAtMs || Date.now()),
        retryCount: 0,
        saveTimeout: null
    };

    const attemptSave = async () => {
        const cur = yjsE2EEStates.get(pid);
        if (!cur) return;
        if (cur.encryptedState !== encryptedState) return;

        try {
            await saveE2EEStateToDatabase(pool, pid, cur.encryptedState, cur.encryptedHtml, cur.snapshotAtMs);
            yjsE2EEStates.delete(pid);
        } catch (error) {
            const attempt = (cur.retryCount || 0) + 1;
            cur.retryCount = attempt;
            cur.saveTimeout = null;

            console.error(`[E2EE] 페이지 ${pid} 상태 저장 실패(시도 ${attempt}):`, error?.message || error);

            if (E2EE_SAVE_RETRY_MAX_ATTEMPTS > 0 && attempt <= E2EE_SAVE_RETRY_MAX_ATTEMPTS) {
                const delay = computeE2eeRetryDelayMs(attempt);
                cur.saveTimeout = setTimeout(attemptSave, delay);
                yjsE2EEStates.set(pid, cur);
            }
        }
    };

    next.saveTimeout = setTimeout(attemptSave, 1500);
    yjsE2EEStates.set(pid, next);
}

async function flushPendingE2eeSaveForPage(pool, pageId) {
    const pid = String(pageId || '');
    const state = yjsE2EEStates.get(pid);
    if (!state) return;

    if (state.saveTimeout) {
        try { clearTimeout(state.saveTimeout); } catch (_) {}
        state.saveTimeout = null;
    }

    try {
        await saveE2EEStateToDatabase(pool, pid, state.encryptedState, state.encryptedHtml, state.snapshotAtMs);
    } catch (e) {
        console.error(`[E2EE] flushPendingE2eeSaveForPage(${pid}) 실패:`, e);
    } finally {
        yjsE2EEStates.delete(pid);
    }
}

async function flushAllPendingE2eeSaves(pool) {
    const pageIds = Array.from(yjsE2EEStates.keys());
    console.log(`[E2EE] Graceful shutdown: flushing ${pageIds.length} pending E2EE saves...`);
    for (const pageId of pageIds) {
        await flushPendingE2eeSaveForPage(pool, pageId);
    }
}

async function saveE2EEStateToDatabase(pool, pageId, encryptedState, encryptedHtml, snapshotAtMs = null) {
    if (!encryptedState) return;

    try {
        const baseMs = Number.isFinite(snapshotAtMs) ? snapshotAtMs : Date.now();
        const updateTime = formatDateForDb(new Date(baseMs));

        let sql = `UPDATE pages
                   SET e2ee_yjs_state = ?,
                       e2ee_yjs_state_updated_at = ?,
                       updated_at = ?`;
        const params = [Buffer.from(encryptedState, 'base64'), updateTime, updateTime];

        if (encryptedHtml !== undefined && encryptedHtml !== null) {
            sql += `, encrypted_content = ?`;
            params.push(String(encryptedHtml));
        }

        sql += ` WHERE id = ?`;
        params.push(pageId);

        await pool.execute(sql, params);

        await pool.execute(`DELETE FROM e2ee_yjs_updates WHERE page_id = ? AND created_at_ms < ?`, [pageId, baseMs]);
    } catch (error) {
        throw error;
    }
}

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

const WS_MAX_DOC_EST_BYTES = (() => {
    const def = Math.max(WS_MAX_YJS_STATE_BYTES * 8, 8 * 1024 * 1024); 
    const v = parseInt(process.env.WS_MAX_DOC_EST_BYTES || String(def), 10);
    if (!Number.isFinite(v)) return def;
    return Math.max(512 * 1024, Math.min(64 * 1024 * 1024, v)); 
})();

function byteLenUtf8(value) {
    try { return Buffer.byteLength(String(value ?? ''), 'utf8'); } catch { return 0; }
}

function cloneYDocForValidation(srcYDoc) {
    const cloned = new Y.Doc();
    Y.applyUpdate(cloned, Y.encodeStateAsUpdate(srcYDoc));
    return cloned;
}

const FORBIDDEN_PROTOCOL_RE = /\b(?:javascript|vbscript|data|file):/i;
const FORBIDDEN_EVENT_ATTR_RE = /\bon[a-z]+\s*=/i;
const FORBIDDEN_TAG_RE = /<(?:script|iframe|object|embed|meta|link|style)\b/i;

function getRealtimeXmlString(candidateYDoc) {
    try {
        const frag = candidateYDoc.getXmlFragment("prosemirror");
        if (!frag) return "";
        return typeof frag.toString === "function" ? frag.toString() : "";
    } catch { return ""; }
}

function validateRealtimeFragment(candidateYDoc) {
    const xml = getRealtimeXmlString(candidateYDoc);
    if (!xml) return { ok: false, reason: "Missing collaborative fragment" };
    if (FORBIDDEN_PROTOCOL_RE.test(xml)) return { ok: false, reason: "Forbidden protocol in collaborative fragment" };
    if (FORBIDDEN_EVENT_ATTR_RE.test(xml)) return { ok: false, reason: "Event handler attribute in collaborative fragment" };
    if (FORBIDDEN_TAG_RE.test(xml)) return { ok: false, reason: "Forbidden tag in collaborative fragment" };
    return { ok: true };
}

function validateRealtimeYjsCandidate(candidateYDoc, sanitizeHtmlContent) {
    try {
        const yMeta = candidateYDoc.getMap('metadata');

        if (!yMeta.has('content')) return { ok: false, code: 1008, reason: 'Missing content' };

        if (yMeta.has('title')) {
            const title = yMeta.get('title');
            if (typeof title !== 'string') return { ok: false, code: 1008, reason: 'Invalid title type' };
            if (byteLenUtf8(title) > 512) return { ok: false, code: 1009, reason: 'Title too large' };
        }

        if (yMeta.has('icon')) {
            const rawIcon = yMeta.get('icon');
            const normalized = validateAndNormalizeIcon(rawIcon);
            if (rawIcon != null && typeof rawIcon !== 'string')
                return { ok: false, code: 1008, reason: 'Invalid icon type' };

            if (typeof rawIcon === 'string' && normalized !== rawIcon.trim())
                return { ok: false, code: 1008, reason: 'Invalid icon value' };
        }

        if (yMeta.has('parentId')) {
            const parentId = yMeta.get('parentId');
            if (!(parentId == null || typeof parentId === 'string'))
                return { ok: false, code: 1008, reason: 'Invalid parentId type' };

            if (typeof parentId === 'string' && byteLenUtf8(parentId) > 128)
                return { ok: false, code: 1008, reason: 'Invalid parentId' };
        }

        if (yMeta.has('content')) {
            const rawContent = yMeta.get('content');
            if (typeof rawContent !== 'string') return { ok: false, code: 1008, reason: 'Invalid content type' };
            if (byteLenUtf8(rawContent) > (2 * 1024 * 1024))
                return { ok: false, code: 1009, reason: 'Content too large' };

            const sanitized = sanitizeHtmlContent(rawContent);
            if (sanitized !== rawContent)
                return { ok: false, code: 1008, reason: 'Unsafe content' };
        }

        const fragmentValidation = validateRealtimeFragment(candidateYDoc);
        if (!fragmentValidation.ok) return { ok: false, code: 1008, reason: fragmentValidation.reason };

        return { ok: true };
    } catch (_) {
        return { ok: false, code: 1008, reason: 'Invalid Yjs state' };
    }
}

const WS_MAX_YJS_UPDATE_B64_CHARS = Math.ceil(WS_MAX_YJS_UPDATE_BYTES / 3) * 4 + 8;
const WS_MAX_AWARENESS_UPDATE_B64_CHARS = Math.ceil(WS_MAX_AWARENESS_UPDATE_BYTES / 3) * 4 + 8;
const WS_MAX_YJS_STATE_B64_CHARS = Math.ceil(WS_MAX_YJS_STATE_BYTES / 3) * 4 + 8;

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
    if (kind === "yjs-update" || kind === "yjs-state" || kind === "yjs-update-e2ee" || kind === "yjs-state-e2ee") { ws._msgRate.yjs++; if (ws._msgRate.yjs > WS_YJS_RATE_MAX) return false; }
    if (kind === "awareness-update") { ws._msgRate.awareness++; if (ws._msgRate.awareness > WS_AWARENESS_RATE_MAX) return false; }
    if (kind === "bad-json") { ws._msgRate.badJson++; if (ws._msgRate.badJson > 20) return false; }
    return true;
}

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

function wsCloseConnectionsForPage(pageId, code = 1009, reason = 'Document too large') {
    const pid = String(pageId || '');
    clearOversizeResyncTimer(pid);
    const conns = wsConnections.pages.get(pid);

    if (conns && conns.size > 0) {
        for (const c of Array.from(conns)) {
            try { c.ws.send(JSON.stringify({ event: 'collab-reset', data: { pageId: pid, reason } })); } catch (_) {}
            try { c.ws.close(code, reason); } catch (_) {}
        }
    }

    wsConnections.pages.delete(pid);

    scheduleEmergencyPersistThenDrop(pid, reason);
}

function wsHasActiveConnectionsForPage(pageId) {
    const pid = String(pageId || '').trim();
    if (!pid) return false;
    const conns = wsConnections.pages.get(pid);
    return !!(conns && conns.size > 0);
}

function getUserColor(userId) { return USER_COLORS[userId % USER_COLORS.length]; }

function cleanupInactiveConnections(pool, sanitizeHtmlContent) {
    const now = Date.now();
    const TIMEOUT = 30 * 60 * 1000;
    yjsDocuments.forEach((doc, pageId) => {
        if (now - doc.lastAccess <= TIMEOUT) return;

        const conns = wsConnections.pages.get(String(pageId));
        if (conns && conns.size > 0) {
            doc.lastAccess = now; 
            return;
        }

        if (doc.saveTimeout) {
            try { clearTimeout(doc.saveTimeout); } catch (_) {}
            doc.saveTimeout = null;
        }

        const epoch = bumpYjsSaveEpoch(pageId);

        enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, doc.ydoc, { epoch }))
            .then(() => {
                dropYjsDocument(pageId, { bumpEpoch: false });
            })
            .catch((e) => {
                try {
                    console.error('[YJS] inactivity cleanup save failed:', String(pageId), e?.message || e);
                } catch (_) {}
                doc.lastAccess = now; 
            });
    });
}

function normalizePaperclipRef(ref) {
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


    const html = String(content);
    const seen = new Set();
    const pushUnique = (type, ref, extra = null) => {
        const k = `${type}:${ref}`;
        if (seen.has(k)) return;
        seen.add(k);
        files.push(extra ? { type, ref, ...extra } : { type, ref });
    };

    const paperclipUrlRegex = /\/paperclip\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})(?=$|["'\s<>?)#&])/g;
    let match;
    while ((match = paperclipUrlRegex.exec(html)) !== null) {
        const candidate = `${match[1]}/${match[2]}`;
        const ref = (pageOwnerUserId !== null && pageOwnerUserId !== undefined)
            ? normalizePaperclipRefForOwner(candidate, pageOwnerUserId)
            : normalizePaperclipRef(candidate);
        if (ref) pushUnique('paperclip', ref);
    }

    const fileBlockRegex = /<div[^>]*data-type=["']file-block["'][^>]*data-src=["']\/paperclip\/([^"']+)["'][^>]*>/gi;
    while ((match = fileBlockRegex.exec(html)) !== null) {
        const ref = (pageOwnerUserId !== null && pageOwnerUserId !== undefined)
            ? normalizePaperclipRefForOwner(match[1], pageOwnerUserId)
            : normalizePaperclipRef(match[1]);
        if (ref) pushUnique('paperclip', ref);
    }

    const imgsUrlRegex = /\/imgs\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})(?=$|["'\s<>?)#&])/g;
    while ((match = imgsUrlRegex.exec(html)) !== null) {
        const ownerId = parseInt(match[1], 10);
        const filename = match[2];
        if (!Number.isFinite(ownerId)) continue;
        if (pageOwnerUserId === null || pageOwnerUserId === undefined || ownerId === pageOwnerUserId) {
            if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(filename)) continue;
            if (filename.includes('..') || /[\x00-\x1F\x7F]/.test(filename)) continue;
            pushUnique('imgs', `${ownerId}/${filename}`, { filename });
        }
    }

    return files;
}


function escapeLikeForSql(s) {
    return String(s).replace(/[\\%_]/g, (m) => `\\${m}`);
}

async function countPlaintextPaperclipRefs(pool, ownerId, filename, excludePageId) {
    const fileUrlPart = `/paperclip/${ownerId}/${filename}`;
    const likePattern = `%${escapeLikeForSql(fileUrlPart)}%`;

    const params = [ownerId, likePattern];
    let sql = `
        SELECT COUNT(*) AS cnt
          FROM pages
         WHERE user_id = ?
           AND is_encrypted = 0
           AND deleted_at IS NULL
           AND content LIKE ? ESCAPE '\\\\'
    `;
    if (excludePageId) {
        sql += ` AND id != ?`;
        params.push(excludePageId);
    }

    const [rows] = await pool.execute(sql, params);
    return Number(rows?.[0]?.cnt || 0);
}

async function backfillPaperclipRefsFromPlaintextContent(pool, ownerId, filename) {
    const fileUrlPart = `/paperclip/${ownerId}/${filename}`;
    const likePattern = `%${escapeLikeForSql(fileUrlPart)}%`;
    try {
        await pool.execute(
            `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
             SELECT id, ?, ?, 'paperclip', NOW()
               FROM pages
              WHERE user_id = ?
                AND is_encrypted = 0
                AND deleted_at IS NULL
                AND content LIKE ? ESCAPE '\\\\'`,
            [ownerId, filename, ownerId, likePattern]
        );
    } catch (_) {}
}

function findActiveYjsPagesReferencingPaperclip(ownerIdStr, filename, excludePageId) {
    try {
        if (!yjsDocuments) return [];
        const needle = `/paperclip/${ownerIdStr}/${filename}`;
        const out = [];
        for (const [pid, info] of yjsDocuments.entries()) {
            if (!info?.ydoc) continue;
            if (excludePageId && String(pid) === String(excludePageId)) continue;
            if (String(info.ownerUserId) !== String(ownerIdStr)) continue;
            if (info.isEncrypted === true) continue;

            const meta = info.ydoc.getMap('metadata');
            const html = meta?.get('content') || '';
            if (typeof html === 'string' && html.includes(needle)) {
                out.push(String(pid));
                continue;
            }
            try {
                const xml = info.ydoc.getXmlFragment('prosemirror')?.toString?.() || '';
                if (typeof xml === 'string' && xml.includes(needle)) out.push(String(pid));
            } catch (_) {}
        }
        return out;
    } catch (_) {
        return [];
    }
}

async function backfillPaperclipRefsForPageIds(pool, pageIds, ownerId, filename) {
    if (!Array.isArray(pageIds) || pageIds.length === 0) return;
    const values = pageIds.map(() => `(?, ?, ?, 'paperclip', NOW())`).join(',');
    const params = [];
    for (const pid of pageIds) params.push(String(pid), ownerId, filename);
    try {
        await pool.execute(
            `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
             VALUES ${values}`,
            params
        );
    } catch (_) {}
}

function movePaperclipToTrash(fs, path, fullPath, ownerIdStr, filename) {
    try {
        const trashDir = path.resolve(__dirname, 'paperclip-trash', String(ownerIdStr));
        const trashBase = path.resolve(trashDir) + path.sep;
        if (!fs.existsSync(trashDir)) fs.mkdirSync(trashDir, { recursive: true, mode: 0o700 });

        const stamp = `${Date.now().toString(36)}-${Math.random().toString(16).slice(2, 10)}`;
        const dest = path.resolve(trashDir, `${stamp}-${filename}`);
        if (!dest.startsWith(trashBase)) return false;

        try { fs.renameSync(fullPath, dest); return true; }
        catch { fs.copyFileSync(fullPath, dest); fs.unlinkSync(fullPath); return true; }
    } catch (_) {
        return false;
    }
}

async function cleanupOrphanedFiles(pool, filePaths, excludePageId, pageOwnerUserId) {
    if (!filePaths || filePaths.length === 0) return;

    const fs = require('fs');
    const path = require('path');
    const ownerIdStr = String(pageOwnerUserId ?? '').trim();
    if (!ownerIdStr || !/^\d{1,12}$/.test(ownerIdStr)) return;
    const baseDir = path.resolve(__dirname, 'paperclip', ownerIdStr) + path.sep;

    for (const item of filePaths) {
        try {
            if (item.type !== 'paperclip') continue;
            const ref = item.ref;

            const normalized = normalizePaperclipRefForOwner(ref, ownerIdStr);
            if (!normalized) continue;

            const [ownerId, filename] = normalized.split('/');

            const [rows] = await pool.execute(
                `SELECT COUNT(*) as count
                   FROM page_file_refs
                  WHERE owner_user_id = ?
                    AND stored_filename = ?
                    AND file_type = 'paperclip'
                    AND page_id != ?`,
                [ownerId, filename, excludePageId]
            );
            if (!rows || !rows[0] || rows[0].count > 0) continue;

            const plaintextRefs = await countPlaintextPaperclipRefs(pool, ownerId, filename, excludePageId);
            if (plaintextRefs > 0) {
                await backfillPaperclipRefsFromPlaintextContent(pool, ownerId, filename);
                continue;
            }

            try {
                if (excludePageId) {
                    const fileUrlPart = `/paperclip/${ownerId}/${filename}`;
                    const likePattern = `%${escapeLikeForSql(fileUrlPart)}%`;
                    const [selfRows] = await pool.execute(
                        `SELECT COUNT(*) AS cnt
                           FROM pages
                          WHERE id = ?
                            AND user_id = ?
                            AND is_encrypted = 0
                            AND content LIKE ? ESCAPE '\\\\'`,
                        [excludePageId, ownerId, likePattern]
                    );
                    if (Number(selfRows?.[0]?.cnt || 0) > 0) {
                        await backfillPaperclipRefsForPageIds(pool, [String(excludePageId)], ownerId, filename);
                        continue;
                    }
                }
            } catch (_) {}

            const activePages = findActiveYjsPagesReferencingPaperclip(ownerIdStr, filename, excludePageId);
            if (activePages.length > 0) {
                await backfillPaperclipRefsForPageIds(pool, activePages, ownerId, filename);
                continue;
            }

            const fullPath = path.resolve(__dirname, 'paperclip', normalized);
            if (!fullPath.startsWith(baseDir)) {
                console.warn(`[보안] orphan cleanup traversal blocked: ${normalized}`);
                continue;
            }

            if (fs.existsSync(fullPath)) {
                const moved = movePaperclipToTrash(fs, path, fullPath, ownerIdStr, filename);
                if (!moved) {
                    try { fs.unlinkSync(fullPath); } catch (_) {}
                }
            }
        } catch (err) {
        }
    }
}

async function saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, opts = {}) {
    try {
        const { epoch, allowDeleted = false, forceClearYjsState = false, preserveDbMetadata = false, actorUserId = null } = opts;
        if (epoch !== undefined && getYjsSaveEpoch(pageId) > epoch) return { status: 'skipped-epoch' };

        const [existingRows] = await pool.execute(
            'SELECT title, content, icon, sort_order, parent_id, is_encrypted, user_id, deleted_at FROM pages WHERE id = ?',
            [pageId]
        );

        if (existingRows.length === 0) return { status: 'aborted-deleted' };
        const existing = existingRows[0];
        if (existing.deleted_at !== null && !allowDeleted) return { status: 'aborted-deleted' };

        const yMetadata = ydoc.getMap('metadata');
        const metaHasString = (k) => (yMetadata && yMetadata.has(k) && typeof yMetadata.get(k) === 'string');
        const metaHasAny = (k) => (yMetadata && yMetadata.has(k));

        const title = preserveDbMetadata ? existing.title : (metaHasString('title') ? yMetadata.get('title') : (existing.title || '제목 없음'));
        const icon = validateAndNormalizeIcon(preserveDbMetadata ? existing.icon : (metaHasString('icon') ? yMetadata.get('icon') : (existing.icon || null)));
        const sortOrder = preserveDbMetadata ? (Number(existing.sort_order) || 0) : (metaHasAny('sortOrder') ? (Number(yMetadata.get('sortOrder')) || 0) : (Number(existing.sort_order) || 0));
        const parentId = preserveDbMetadata ? (existing.parent_id || null) : (metaHasAny('parentId') ? (yMetadata.get('parentId') || null) : (existing.parent_id || null));

        const isEncrypted = (existing.is_encrypted === 1);
        const metaContent = metaHasAny('content') ? yMetadata.get('content') : undefined;
        const shouldUpdateContent = (typeof metaContent === 'string');
        const content = shouldUpdateContent ? sanitizeHtmlContent(metaContent || '<p></p>') : null;

        if (!shouldUpdateContent && !isEncrypted) wsRequestPageSnapshot(pageId);

        const pageOwnerUserId = (existing.user_id);
        let finalContent = '';
        let oldFiles = [];

        if (isEncrypted) {
            finalContent = '';
        } else {
            finalContent = shouldUpdateContent ? (content || '<p></p>') : (existing.content || '<p></p>');
            oldFiles = extractFilesFromContent(existing.content, pageOwnerUserId);
        }

        let yjsStateToSave = null;
        if (!isEncrypted && !forceClearYjsState) {
            const meta = yjsDocuments.get(pageId);
            const approx = meta?.approxBytes;
            if (Number.isFinite(approx) && approx <= WS_MAX_YJS_STATE_BYTES) {
                try {
                    yjsStateToSave = Buffer.from(Y.encodeStateAsUpdate(ydoc));
                    if (yjsStateToSave.length > WS_MAX_YJS_STATE_BYTES) yjsStateToSave = null;
                } catch (_) { yjsStateToSave = null; }
            }
        }

        if (epoch !== undefined && getYjsSaveEpoch(pageId) > epoch) return { status: 'skipped-epoch' };

        await pool.execute(
            `UPDATE pages SET title = ?, content = ?, icon = ?, sort_order = ?, parent_id = ?, yjs_state = ?, updated_at = NOW() WHERE id = ?`,
            [title, finalContent, icon, sortOrder, parentId, yjsStateToSave, pageId]
        );

        if (!isEncrypted && shouldUpdateContent && actorUserId !== null && Number(actorUserId) === Number(pageOwnerUserId)) {
            const newFiles = extractFilesFromContent(content, pageOwnerUserId);
            try {
                for (const file of newFiles) {
                    const parts = file.ref.split('/');
                    const ownerId = parseInt(parts[0], 10);
                    const filename = parts[1];
                    if (ownerId === pageOwnerUserId) {
                        await pool.execute(
                            `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
                             VALUES (?, ?, ?, ?, NOW())`,
                            [pageId, ownerId, filename, file.type]
                        );
                    }
                }

                const currentPaperclipFiles = newFiles.filter(f => f.type === 'paperclip').map(f => f.ref.split('/')[1]);
                if (currentPaperclipFiles.length > 0) {
                    await pool.execute(
                        `DELETE FROM page_file_refs
                          WHERE page_id = ? AND owner_user_id = ? AND file_type = 'paperclip'
                            AND stored_filename NOT IN (${currentPaperclipFiles.map(() => '?').join(',')})`,
                        [pageId, pageOwnerUserId, ...currentPaperclipFiles]
                    );
                } else {
                    await pool.execute(`DELETE FROM page_file_refs WHERE page_id = ? AND owner_user_id = ? AND file_type = 'paperclip'`, [pageId, pageOwnerUserId]);
                }

                const currentImgsFiles = newFiles.filter(f => f.type === 'imgs').map(f => f.ref.split('/')[1]);
                if (currentImgsFiles.length > 0) {
                    await pool.execute(
                        `DELETE FROM page_file_refs
                          WHERE page_id = ? AND owner_user_id = ? AND file_type = 'imgs'
                            AND stored_filename NOT IN (${currentImgsFiles.map(() => '?').join(',')})`,
                        [pageId, pageOwnerUserId, ...currentImgsFiles]
                    );
                } else {
                    await pool.execute(`DELETE FROM page_file_refs WHERE page_id = ? AND owner_user_id = ? AND file_type = 'imgs'`, [pageId, pageOwnerUserId]);
                }
            } catch (regErr) { console.error('보안 레지스트리 동기화 실패:', regErr); }

            const deletedFiles = oldFiles.filter(f => !newFiles.some(nf => nf.ref === f.ref));
            if (deletedFiles.length > 0) cleanupOrphanedFiles(pool, deletedFiles, pageId, pageOwnerUserId).catch(() => {});
        }
        return { status: 'saved' };
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

	    const _rawHtml = (yMetadata.get('content') == null)
	        ? (page.content || '<p></p>')
	        : yMetadata.get('content');
	    const _safeHtml = (typeof sanitizeHtmlContent === 'function') ? sanitizeHtmlContent(_rawHtml) : _rawHtml;
	    yMetadata.set('content', _safeHtml);

        yjsDocuments.set(pageId, {
            ydoc,
            lastAccess: Date.now(),
            saveTimeout: null,
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
    const [ownerRows] = await pool.execute(
        `SELECT id FROM storages WHERE id = ? AND user_id = ?`,
        [storageId, userId]
    );
    if (ownerRows.length > 0) return 'ADMIN';

    const [shareRows] = await pool.execute(
        `SELECT permission FROM storage_shares
         WHERE storage_id = ? AND shared_with_user_id = ?`,
        [storageId, userId]
    );
    if (shareRows.length > 0) return shareRows[0].permission;

    return null;
}

const { redis, ensureRedis } = require("./lib/redis");

(async () => {
	await ensureRedis();
	const sub = redis.duplicate();
	await sub.connect();
	await sub.subscribe("session-revoke", (message) => {
		try {
			const { sessionId, reason } = JSON.parse(message);
			wsCloseConnectionsForSession(sessionId, 1008, reason || "Session revoked");
		} catch (_) {}
	});
})();

function initWebSocketServer(server, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest, pageSqlPolicy) {
    _wsPool = pool;
    _wsSanitizeHtmlContent = sanitizeHtmlContent;
    const allowedWsOrigins = (() => {
        const set = new Set();
        try { set.add(new URL(BASE_URL).origin); } catch (_) {}

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
        verifyClient: (info, done) => {
            try {
                const origin = info?.origin || info?.req?.headers?.origin;
                if (!isWsOriginAllowed(origin)) return done(false, 403, 'Forbidden');
                return done(true);
            } catch (_) {
                return done(false, 403, 'Forbidden');
            }
        }
    });

    wss.on('connection', async (ws, req) => {
        try {
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

		    const session = typeof getSessionFromId === 'function' ? await getSessionFromId(sessionId) : null;
		    if (!session || !session.userId) { ws.close(1008, 'Unauthorized'); return; }
		    ws.userId = session.userId; ws.username = session.username; ws.sessionId = sessionId; ws.isAlive = true;
			registerSessionConnection(sessionId, ws);
		    ws.on('pong', () => { ws.isAlive = true; });
            ws.on('error', () => {  }); 

            initWsMessageRateState(ws);

			ws.on('message', async (msg, isBinary) => {
		        try {
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
	    const s = await getSessionFromId(ws.sessionId);
	    if (!s || !s.userId) { try { ws.close(1008, 'Expired'); } catch (e) {} return; }
	}
	switch (type) {
        case 'subscribe-page': await handleSubscribePage(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'unsubscribe-page': handleUnsubscribePage(ws, payload, pool, sanitizeHtmlContent); break;
        case 'subscribe-storage': await handleSubscribeStorage(ws, payload, pool); break;
        case 'unsubscribe-storage': handleUnsubscribeStorage(ws, payload); break;
        case 'subscribe-user': handleSubscribeUser(ws, payload); break;
        case 'page-snapshot': await handlePageSnapshot(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'force-save': await handleForceSave(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'force-save-e2ee': await handleForceSaveE2EE(ws, payload, pool, pageSqlPolicy); break;
        case 'yjs-update': await handleYjsUpdate(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'yjs-state': await handleYjsState(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'awareness-update': await handleAwarenessUpdate(ws, payload, pool, pageSqlPolicy); break;
        case 'subscribe-page-e2ee': await handleSubscribePageE2EE(ws, payload, pool, pageSqlPolicy); break;
        case 'yjs-update-e2ee': await handleYjsUpdateE2EE(ws, payload, pool, pageSqlPolicy); break;
        case 'yjs-state-e2ee': await handleYjsStateE2EE(ws, payload, pool, pageSqlPolicy); break;
    }
}

async function handleSubscribePage(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy) {
    const { pageId } = payload;
    const userId = ws.userId;
    try {
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

        if (page.is_encrypted === 1 && page.share_allowed === 0 && Number(page.user_id) !== Number(userId)) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        if (page.is_encrypted === 1) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Encrypted pages do not support real-time collaboration yet' } }));
            return;
        }

        const ydoc = await loadOrCreateYjsDoc(pool, sanitizeHtmlContent, pageId);

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
        ws.send(JSON.stringify({
            event: 'init',
            data: { pageId: String(pageId), state: stateB64, userId, username: ws.username, color, permission }
        }));
        wsBroadcastToPage(pageId, 'user-joined', { userId, username: ws.username, color, permission }, userId);
    } catch (e) { ws.send(JSON.stringify({ event: 'error', data: { message: 'Failed' } })); }
}

function handleUnsubscribePage(ws, payload, pool, sanitizeHtmlContent) {
    const { pageId } = payload;
    const pid = String(pageId || '');
    const conns = wsConnections.pages.get(pid);
    if (!conns) return;
    let removed = null;
    for (const c of Array.from(conns)) {
        if (c && c.ws === ws) { removed = c; conns.delete(c); }
    }
    try {
        if (removed && removed.isE2ee && removed.sessionId) {
            const leader = e2eeSnapshotLeaders.get(pid);
            if (leader && String(leader.sessionId) === String(removed.sessionId)) {
                if (!hasActiveE2eeSessionOnPage(pid, leader.sessionId)) e2eeSnapshotLeaders.delete(pid);
            }
        }
    } catch (_) {}
    if (conns.size === 0) {
        wsConnections.pages.delete(pid);
        try { e2eeSnapshotLeaders.delete(pid); } catch (_) {}
        clearE2eeSnapshotRequestTimer(pid);
        e2eeLastUpdateAt.delete(pid);
        e2eeLastSnapshotAt.delete(pid);

        const doc = yjsDocuments.get(pid);
        if (doc) {
            const epoch = getYjsSaveEpoch(pid);
            enqueueYjsDbSave(pid, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pid, doc.ydoc, { epoch }))
                .catch(e => { console.error('[YJS] unsubscribe save failed:', String(pid), e?.message || e); });
        }
    }
    wsBroadcastToPage(pid, 'user-left', { userId: ws.userId }, ws.userId);
}


async function handleSubscribePageE2EE(ws, payload, pool, pageSqlPolicy) {
    const { pageId } = payload;
    const userId = ws.userId;
    try {
        const vis = (pageSqlPolicy && typeof pageSqlPolicy.andVisible === 'function')
            ? pageSqlPolicy.andVisible({ alias: 'p', viewerUserId: userId })
            : { sql: ' AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)', params: [userId] };

        const [rows] = await pool.execute(
            `SELECT p.id, p.user_id, p.is_encrypted, p.share_allowed, p.storage_id,
                    p.e2ee_yjs_state,
                    p.e2ee_yjs_state_updated_at,
                    p.updated_at,
                    UNIX_TIMESTAMP(p.e2ee_yjs_state_updated_at) * 1000 AS e2ee_yjs_state_updated_ms,
                    s.is_encrypted AS storage_is_encrypted
             FROM pages p
             JOIN storages s ON p.storage_id = s.id
             WHERE p.id = ?
               AND p.deleted_at IS NULL
             ${vis.sql}`,
            [pageId, ...vis.params]
        );

        if (!rows.length) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        const page = rows[0];

        if (page.is_encrypted !== 1 || page.storage_is_encrypted !== 1) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page is not E2EE encrypted' } }));
            return;
        }

        const permission = await getStoragePermission(pool, userId, page.storage_id);
        if (!permission) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        if (page.share_allowed === 0 && Number(page.user_id) !== Number(userId)) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        if (!wsConnections.pages.has(pageId)) wsConnections.pages.set(pageId, new Set());
        const conns = wsConnections.pages.get(pageId);
        for (const c of Array.from(conns)) {
            if (c.userId === userId && c.ws !== ws) { conns.delete(c); try { c.ws.close(1008, 'Duplicate'); } catch (_) {} }
        }
        const color = getUserColor(userId);
        const myConn = { ws, userId, username: ws.username, color, permission, storageId: page.storage_id, permCheckedAt: Date.now(), isE2ee: true, sessionId: ws.sessionId };
        conns.add(myConn);

        let encryptedState = null;
        const memEntry = yjsE2EEStates.get(String(pageId));
        if (memEntry) {
            encryptedState = memEntry.encryptedState;
        } else if (page.e2ee_yjs_state) {
            try {
                const blob = page.e2ee_yjs_state;
                if (Buffer.isBuffer(blob)) {
                    const asUtf8 = blob.toString('utf8');
                    if (/^[A-Za-z0-9+/=]+$/.test(asUtf8) && asUtf8.length >= 16) {
                        encryptedState = asUtf8;
                    } else {
                        encryptedState = blob.toString('base64');
                    }
                } else if (typeof blob === 'string') {
                    encryptedState = blob;
                } else {
                    encryptedState = String(blob);
                }

                if (encryptedState && !/^[A-Za-z0-9+/=]+$/.test(encryptedState)) encryptedState = null;
                if (encryptedState) yjsE2EEStates.set(String(pageId), { encryptedState, storedAt: Date.now(), snapshotAtMs: Number(page.e2ee_yjs_state_updated_ms) || Date.now() });
            } catch (_) {}
        }

        const toIsoMaybe = (v) => {
            if (!v) return null;
            try {
                if (v instanceof Date) return v.toISOString();
                let s = String(v);
                if (!s.includes('T') && s.includes(' ')) s = s.replace(' ', 'T');
                return s.endsWith('Z') ? s : (s + 'Z');
            } catch (_) {
                return null;
            }
        };

        ws.send(JSON.stringify({
            event: 'init-e2ee',
            data: {
                pageId: String(pageId),
                encryptedState,
                e2eeStateUpdatedAt: toIsoMaybe(page.e2ee_yjs_state_updated_at),
                pageUpdatedAt: toIsoMaybe(page.updated_at),
                userId, username: ws.username, color, permission
            }
        }));
        if (encryptedState) {
            e2eeLastSnapshotAt.set(String(pageId), Date.now());
        }

        const sinceMs = Number(page.e2ee_yjs_state_updated_ms) || 0;
        sendPendingE2eeUpdatesToClient(ws, pool, pageId, sinceMs).catch(() => {});

        if (['EDIT', 'ADMIN'].includes(permission)) {
            const leader = maybeElectE2eeLeader(pageId, myConn);
            const isLeader = (leader.sessionId === myConn.sessionId);
            ws.send(JSON.stringify({ event: 'e2ee-leader-status', data: { isLeader } }));
        }

        wsBroadcastToPage(pageId, 'user-joined', { userId, username: ws.username, color, permission }, userId);
    } catch (e) {
        ws.send(JSON.stringify({ event: 'error', data: { message: 'Failed' } }));
    }
}

async function handleYjsUpdateE2EE(ws, payload, pool, pageSqlPolicy) {
    const { pageId, update } = payload || {};
    try {
        if (!pageId || typeof update !== 'string' || !isSubscribedToPage(ws, pageId)) return;

        const conns = wsConnections.pages.get(pageId);
        const myConn = Array.from(conns).find(c => c.ws === ws);
        if (!myConn || !myConn.isE2ee) return;

        const freshPerm = await refreshConnPermission(pool, myConn, { force: true });
        if (!freshPerm) {
            revokePageSubscription(ws, pageId, conns, myConn, 'storage-access-revoked');
            return;
        }
        if (!['EDIT', 'ADMIN'].includes(freshPerm)) return;

        ensureE2eeLeaderForActiveEditor(pageId, myConn);

        if (update.length > WS_MAX_YJS_UPDATE_B64_CHARS) return;
        const updateBuf = Buffer.from(update, 'base64');
        if (updateBuf.length > WS_MAX_YJS_UPDATE_BYTES) return;

        wsBroadcastToPage(pageId, 'yjs-update-e2ee', { update }, ws.userId);

        bufferE2eeUpdateLog(pool, pageId, updateBuf);

        const pid = String(pageId);
        const now = Date.now();
        e2eeLastUpdateAt.set(pid, now);

        if (!e2eeSnapshotRequestTimers.has(pid)) {
            const timer = setTimeout(() => {
                try {
                    e2eeSnapshotRequestTimers.delete(pid);
                    const lu = e2eeLastUpdateAt.get(pid) || 0;
                    const ls = e2eeLastSnapshotAt.get(pid) || 0;
                    if (lu > ls) wsRequestE2eeSnapshot(pid);
                } catch (_) {}
            }, E2EE_SNAPSHOT_EXPECT_MS);
            e2eeSnapshotRequestTimers.set(pid, timer);
        }
    } catch (e) {}
}

async function handleYjsStateE2EE(ws, payload, pool, pageSqlPolicy) {
    const { pageId, encryptedState, encryptedHtml } = payload || {};
    try {
        if (!pageId || typeof encryptedState !== 'string' || !isSubscribedToPage(ws, pageId)) return;

        const conns = wsConnections.pages.get(pageId);
        const myConn = Array.from(conns).find(c => c.ws === ws);
        if (!myConn || !myConn.isE2ee) return;

        const freshPerm = await refreshConnPermission(pool, myConn); 
        if (!['EDIT', 'ADMIN'].includes(freshPerm)) return;

        const leader = ensureE2eeLeaderForActiveEditor(pageId, myConn);
        if (leader && String(leader.sessionId) !== String(myConn.sessionId)) return;

        const maxStateB64Chars = Math.ceil(WS_MAX_YJS_STATE_BYTES / 3) * 4 + 8;
        if (encryptedState.length > maxStateB64Chars) return;
        if (!/^[A-Za-z0-9+/=]+$/.test(encryptedState)) return;
        try {
            const buf = Buffer.from(encryptedState, 'base64');
            if (!buf || buf.length < 28) return;
        } catch (_) { return; }

        yjsE2EEStates.set(String(pageId), { encryptedState, storedAt: Date.now() });

        const pid = String(pageId);
        e2eeLastSnapshotAt.set(pid, Date.now());
        clearE2eeSnapshotRequestTimer(pid);

        touchE2eeLeader(pageId, myConn);

        scheduleE2EESave(pool, pageId, encryptedState, encryptedHtml, Date.now());

    } catch (e) {}
}

function cleanupInactiveE2EEStates() {
    const now = Date.now();
    const TIMEOUT = 24 * 60 * 60 * 1000; 

    yjsE2EEStates.forEach((entry, pageId) => {
        if (now - entry.storedAt > TIMEOUT)
            yjsE2EEStates.delete(pageId);
    });

	e2eeSnapshotLeaders.forEach((leader, pageId) => {
        if (now - leader.lastSeenAt > 60000)
            e2eeSnapshotLeaders.delete(pageId);
    });
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

async function refreshConnPermission(pool, conn, { force = false } = {}) {
    if (!conn || !conn.storageId) return conn?.permission || null;
    const now = Date.now();
    const last = conn.permCheckedAt || 0;
    if (!force && now - last < WS_PERMISSION_REFRESH_MS) return conn.permission;

    const fresh = await getStoragePermission(pool, conn.userId, conn.storageId);
    conn.permCheckedAt = now;
    conn.permission = fresh;
    return fresh;
}

function handleSubscribeUser(ws, payload) {
    if (!wsConnections.users.has(ws.userId)) wsConnections.users.set(ws.userId, new Set());
    wsConnections.users.get(ws.userId).add({ ws, sessionId: ws.sessionId });
}

async function handlePageSnapshot(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy) {
    const { pageId, html, title, resyncNeeded } = payload || {};
    if (!pageId || typeof html !== 'string') return;
    if (!isSubscribedToPage(ws, pageId)) return;

    const conns = wsConnections.pages.get(pageId);
    const myConn = conns ? Array.from(conns).find(c => c.ws === ws) : null;
    if (!myConn) return;

    let access;
    try {
        access = await ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn, { forcePermissionRefresh: true });
    } catch (_) { return; }

    if (!access.ok) {
        revokePageSubscription(ws, pageId, conns, myConn, access.reason);
        return;
    }
    if (!['EDIT', 'ADMIN'].includes(access.permission)) return;

    if (Number(access.page?.is_encrypted) === 1) return;

    if (byteLenUtf8(html) > (2 * 1024 * 1024)) return;
    const safeHtml = (typeof sanitizeHtmlContent === 'function') ? sanitizeHtmlContent(html) : html;

    const docMeta = yjsDocuments.get(String(pageId));
    if (docMeta?.ydoc) {
        const yMeta = docMeta.ydoc.getMap('metadata');
        docMeta.ydoc.transact(() => {
            yMeta.set('content', safeHtml);
            if (typeof title === 'string' && title.trim()) {
                yMeta.set('title', title.trim().slice(0, 255));
            }
        }, 'snapshot');

        if (docMeta.saveTimeout) clearTimeout(docMeta.saveTimeout);

        if (emergencyPersistState.has(pageId)) return;

        const needsResync = (resyncNeeded === true || resyncNeeded === 1 || String(resyncNeeded || '').toLowerCase() === 'true');

        if (needsResync) {
            const epoch = bumpYjsSaveEpoch(pageId);
            try {
                await enqueueYjsDbSave(pageId, () =>
                    saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, docMeta.ydoc, { epoch, forceClearYjsState: true, actorUserId: ws.userId })
                );
            } catch (e) {
                console.error('[YJS] snapshot resync-save failed:', String(pageId), e?.message || e);
            }
            try { clearOversizeResyncTimer(pageId); } catch (_) {}
            try { wsCloseConnectionsForPage(pageId, 1012, 'Resync required - reload'); } catch (_) {}
            return;
        }

        const epoch = getYjsSaveEpoch(pageId);
        docMeta.saveTimeout = setTimeout(() => {
            enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, docMeta.ydoc, { epoch }))
                .catch(e => { console.error('[YJS] snapshot best-effort save failed:', String(pageId), e?.message || e); });
        }, 1000);
    }
}

async function handleForceSave(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy) {
    const { pageId } = payload || {};
    if (!pageId) return;
    if (!isSubscribedToPage(ws, pageId)) return;

    const conns = wsConnections.pages.get(pageId);
    const myConn = conns ? Array.from(conns).find(c => c.ws === ws) : null;
    if (!myConn) return;

    let access;
    try {
        access = await ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn, { forcePermissionRefresh: true });
    } catch (_) { return; }

    if (!access.ok) {
        revokePageSubscription(ws, pageId, conns, myConn, access.reason);
        return;
    }
    if (!['EDIT', 'ADMIN'].includes(access.permission)) return;
    if (Number(access.page?.is_encrypted) === 1) return;

    try {
        const ydoc = await loadOrCreateYjsDoc(pool, sanitizeHtmlContent, pageId);
        const epoch = bumpYjsSaveEpoch(pageId);
        await enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, { epoch, actorUserId: ws.userId }));
        ws.send(JSON.stringify({
            event: 'page-saved',
            data: { pageId: String(pageId), updatedAt: new Date().toISOString() }
        }));
    } catch (_) {}
}

async function handleForceSaveE2EE(ws, payload, pool, pageSqlPolicy) {
    const { pageId } = payload || {};
    if (!pageId || !isSubscribedToPage(ws, pageId)) return;

    const conns = wsConnections.pages.get(pageId);
    const myConn = conns ? Array.from(conns).find(c => c.ws === ws) : null;
    if (!myConn || !myConn.isE2ee) return;

    let access;
    try {
        access = await ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn, { forcePermissionRefresh: true });
    } catch (_) { return; }

    if (!access.ok) {
        revokePageSubscription(ws, pageId, conns, myConn, access.reason);
        return;
    }
    if (!['EDIT', 'ADMIN'].includes(access.permission)) return;

    await flushPendingE2eeSaveForPage(pool, pageId);

    ws.send(JSON.stringify({
        event: 'page-saved',
        data: { pageId: String(pageId), updatedAt: new Date().toISOString() }
    }));
}

function revokePageSubscription(ws, pageId, conns, myConn, reason = 'Access revoked') {
    try {
        const pid = String(pageId || '');
        if (conns && myConn) {
            conns.delete(myConn);
            try {
                if (myConn.isE2ee && myConn.sessionId) {
                    const leader = e2eeSnapshotLeaders.get(pid);
                    if (leader && String(leader.sessionId) === String(myConn.sessionId)) {
                        if (!hasActiveE2eeSessionOnPage(pid, leader.sessionId)) e2eeSnapshotLeaders.delete(pid);
                    }
                }
            } catch (_) {}
        }
        if (conns && conns.size === 0) {
            wsConnections.pages.delete(pid);
            try { e2eeSnapshotLeaders.delete(pid); } catch (_) {}
        }
        ws.send(JSON.stringify({ event: 'access-revoked', data: { pageId: pid, reason } }));
    } catch (_) {}
}

async function ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn, opts = {}) {
    if (!myConn) return { ok: false, reason: 'not-subscribed' };

    const userId = myConn.userId;
    const vis = (pageSqlPolicy && typeof pageSqlPolicy.andVisible === 'function')
        ? pageSqlPolicy.andVisible({ alias: 'p', viewerUserId: userId })
        : { sql: ' AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)', params: [userId] };

    const [rows] = await pool.execute(
        `SELECT p.id, p.user_id, p.is_encrypted, p.share_allowed, p.storage_id
           FROM pages p
          WHERE p.id = ?
            AND p.deleted_at IS NULL
            ${vis.sql}`,
        [pageId, ...vis.params]
    );

    if (!rows.length)
        return { ok: false, reason: 'page-not-visible' };

    const page = rows[0];

    myConn.storageId = page.storage_id;

    const freshPerm = await refreshConnPermission(pool, myConn, {
        force: Boolean(opts.forcePermissionRefresh)
    });
    if (!freshPerm)
        return { ok: false, reason: 'storage-access-revoked' };

    if (Number(page.is_encrypted) === 1) {
        if (!myConn.isE2ee)
            return { ok: false, reason: 'encrypted-page-no-realtime' };
    }

    return { ok: true, permission: freshPerm, page };
}

async function validateYjsParentAssignment(pool, pageSqlPolicy, {
    viewerUserId,
    pageId,
    pageStorageId,
    candidateParentId
}) {
    if (candidateParentId == null || candidateParentId === "")
        return { ok: true, parentId: null };

    if (typeof candidateParentId !== "string")
        return { ok: false, reason: "invalid-parent-type" };

    const parentId = candidateParentId.trim();
    if (!parentId || parentId.length > 64)
        return { ok: false, reason: "invalid-parent-format" };

    if (parentId === pageId)
        return { ok: false, reason: "self-parent" };

    const vis = (pageSqlPolicy && typeof pageSqlPolicy.andVisible === 'function')
        ? pageSqlPolicy.andVisible({ alias: 'p', viewerUserId })
        : { sql: ' AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)', params: [viewerUserId] };

    const [rows] = await pool.execute(
        `SELECT p.id, p.storage_id
           FROM pages p
           LEFT JOIN storage_shares ss ON p.storage_id = ss.storage_id AND ss.shared_with_user_id = ?
          WHERE p.id = ?
            AND p.deleted_at IS NULL
            AND (p.user_id = ? OR ss.storage_id IS NOT NULL)
            ${vis.sql}`,
        [viewerUserId, parentId, viewerUserId, ...vis.params]
    );

    if (!rows.length) return { ok: false, reason: "parent-not-visible" };
    if (String(rows[0].storage_id) !== String(pageStorageId))
        return { ok: false, reason: "cross-storage-parent" };

    return { ok: true, parentId };
}

async function handleYjsUpdate(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy) {
	const { pageId, update } = payload || {};
	try {
        if (!pageId || typeof update !== 'string' || !isSubscribedToPage(ws, pageId)) return;

        const conns = wsConnections.pages.get(pageId);
        const myConn = Array.from(conns).find(c => c.ws === ws);
        if (!myConn) return;

        const access = await ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn, {
            forcePermissionRefresh: true
        });
        if (!access.ok) {
            revokePageSubscription(ws, pageId, conns, myConn, access.reason);
            return;
        }
        const freshPerm = access.permission;

        if (!['EDIT', 'ADMIN'].includes(freshPerm)) return;

        const ydoc = await loadOrCreateYjsDoc(pool, sanitizeHtmlContent, pageId);
        if (update.length > WS_MAX_YJS_UPDATE_B64_CHARS) throw new Error('Update too large');
        const updateBuf = Buffer.from(update, 'base64');
        if (updateBuf.length > WS_MAX_YJS_UPDATE_BYTES) throw new Error('Update too large');

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

        const doc = yjsDocuments.get(pageId);
        if (doc) {
            const cur = Number.isFinite(doc.approxBytes) ? doc.approxBytes : 0;
            const next = cur + updateBuf.length;
            if (next > WS_MAX_DOC_EST_BYTES) {
                try { await enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc)); } catch (_) {}
                wsCloseConnectionsForPage(pageId, 1009, 'Document too large - collaboration reset');
                return;
            }
        }

        try {
            const probe = cloneYDocForValidation(ydoc);
            Y.applyUpdate(probe, updateBuf);

            const sem = validateRealtimeYjsCandidate(probe, sanitizeHtmlContent);
            if (!sem.ok) {
                try { ws.close(sem.code || 1008, sem.reason || 'Rejected invalid update'); } catch (_) {}
                return;
            }
        } catch (_) {
            try { ws.close(1008, 'Malformed Yjs update'); } catch (_) {}
            return;
        }

        Y.applyUpdate(ydoc, updateBuf);
        if (doc) doc.approxBytes = (Number.isFinite(doc.approxBytes) ? doc.approxBytes : 0) + updateBuf.length;

        const yMeta = ydoc.getMap('metadata');
        const currentContent = typeof yMeta.get('content') === 'string' ? yMeta.get('content') : '<p></p>';
        yMeta.set('content', sanitizeHtmlContent(currentContent));

        try {
            const requestedParentId = yMeta.get('parentId') ?? null;
            const parentCheck = await validateYjsParentAssignment(pool, pageSqlPolicy, {
                viewerUserId: ws.userId,
                pageId,
                pageStorageId: access.page.storage_id,
                candidateParentId: requestedParentId
            });
            if (!parentCheck.ok) {
                yMeta.set('parentId', null);
                try { ws.close(1008, 'Invalid parent assignment'); } catch (_) {}
                return;
            }
            if ((requestedParentId || null) !== (parentCheck.parentId || null))
                yMeta.set('parentId', parentCheck.parentId);
        } catch (_) { return; }

        if (emergencyPersistState.has(pageId)) return;

        wsBroadcastToPage(pageId, 'yjs-update', { update }, ws.userId);
        if (doc) {
            if (doc.saveTimeout || emergencyPersistState.has(pageId)) return;

            const epoch = getYjsSaveEpoch(pageId); 
            doc.saveTimeout = setTimeout(() => {
                enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, { epoch, actorUserId: ws.userId }))
                    .catch(e => { console.error('[YJS] debounce save failed:', String(pageId), e?.message || e); });
            }, 1000);
        }
    } catch (e) {}
}

async function handleYjsState(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy) {
	const { pageId, state } = payload || {};
	try {
		if (!pageId || typeof state !== 'string' || !isSubscribedToPage(ws, pageId)) return;

		const conns = wsConnections.pages.get(pageId);
		const myConn = Array.from(conns).find(c => c.ws === ws);
		if (!myConn) return;

		const access = await ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn, {
			forcePermissionRefresh: true
		});
		if (!access.ok) {
			revokePageSubscription(ws, pageId, conns, myConn, access.reason);
			return;
		}
		const freshPerm = access.permission;
		if (!['EDIT', 'ADMIN'].includes(freshPerm)) return;

		if (state.length > WS_MAX_YJS_STATE_B64_CHARS) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'State too large' } }));
            scheduleOversizeResyncSnapshotThenClose(pageId, 'Document state too large');
            return;
        }
		const stateBuf = Buffer.from(state, 'base64');
		if (stateBuf.length > WS_MAX_YJS_STATE_BYTES) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'State too large' } }));
            scheduleOversizeResyncSnapshotThenClose(pageId, 'Document state too large');
            return;
        }

		const ydoc = await loadOrCreateYjsDoc(pool, sanitizeHtmlContent, pageId);

        const BAD = [
            Buffer.from('javascript:', 'utf8'),
            Buffer.from('data:', 'utf8'),
            Buffer.from('vbscript:', 'utf8'),
            Buffer.from('file:', 'utf8')
        ];
        for (const sig of BAD) {
            if (stateBuf.indexOf(sig) !== -1) {
                try { ws.close(1008, 'Blocked unsafe state'); } catch (_) {}
                return;
            }
        }

		if (stateBuf.length > WS_MAX_DOC_EST_BYTES) {
			wsCloseConnectionsForPage(pageId, 1009, 'Document too large - collaboration reset');
			return;
		}

		try {
			const probe = cloneYDocForValidation(ydoc);
			Y.applyUpdate(probe, stateBuf);

			const sem = validateRealtimeYjsCandidate(probe, sanitizeHtmlContent);
			if (!sem.ok) {
				try { ws.close(sem.code || 1008, sem.reason || 'Rejected invalid state'); } catch (_) {}
				return;
			}
		} catch (_) {
			try { ws.close(1008, 'Malformed Yjs state'); } catch (_) {}
			return;
		}

		Y.applyUpdate(ydoc, stateBuf);

		const yMeta = ydoc.getMap('metadata');
		const currentContent = typeof yMeta.get('content') === 'string' ? yMeta.get('content') : '<p></p>';
		yMeta.set('content', sanitizeHtmlContent(currentContent));

		const doc = yjsDocuments.get(pageId);
		if (doc) {
			const cur = Number.isFinite(doc.approxBytes) ? doc.approxBytes : 0;
			doc.approxBytes = Math.max(cur, stateBuf.length); 
		}

        try {
            const requestedParentId = yMeta.get('parentId') ?? null;
            const parentCheck = await validateYjsParentAssignment(pool, pageSqlPolicy, {
                viewerUserId: ws.userId,
                pageId,
                pageStorageId: access.page.storage_id,
                candidateParentId: requestedParentId
            });
            if (!parentCheck.ok) {
                yMeta.set('parentId', null);
                try { ws.close(1008, 'Invalid parent assignment'); } catch (_) {}
                return;
            }
            if ((requestedParentId || null) !== (parentCheck.parentId || null))
                yMeta.set('parentId', parentCheck.parentId);
        } catch (_) { return; }

		if (emergencyPersistState.has(pageId)) return;

		wsBroadcastToPage(pageId, 'yjs-state', { state }, ws.userId);

		if (doc) {
			if (doc.saveTimeout || emergencyPersistState.has(pageId)) return;

			const epoch = getYjsSaveEpoch(pageId); 
			doc.saveTimeout = setTimeout(() => {
				enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, { epoch, actorUserId: ws.userId }))
                    .catch(e => { console.error('[YJS] state save failed:', String(pageId), e?.message || e); });
			}, 1000);
		}
	} catch (e) {
		console.error('[WS] handleYjsState error:', e);
	}
}

function isSubscribedToPage(ws, pageId) {
    const conns = wsConnections.pages.get(pageId);
    if (!conns) return false;
    for (const c of conns) if (c.ws === ws) return true;
    return false;
}

async function handleAwarenessUpdate(ws, payload, pool, pageSqlPolicy) {
    const { pageId, awarenessUpdate } = payload || {};
    if (!pageId || typeof awarenessUpdate !== 'string' || !isSubscribedToPage(ws, pageId)) return;

    const conns = wsConnections.pages.get(pageId);
    if (!conns) return;
    const myConn = Array.from(conns).find(c => c.ws === ws);
    if (!myConn) return;

    try {
        const access = await ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn);
        if (!access.ok) {
            revokePageSubscription(ws, pageId, conns, myConn, access.reason);
            return;
        }
    } catch (_) {
        return;
    }

    if (awarenessUpdate.length > WS_MAX_AWARENESS_UPDATE_B64_CHARS) return;

    wsBroadcastToPage(pageId, 'awareness-update', { awarenessUpdate, fromUserId: ws.userId }, ws.userId);
}

function cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent) {
    releaseActiveConnectionSlots(ws);

	unregisterSessionConnection(ws.sessionId, ws);
    wsConnections.pages.forEach((conns, pid) => {
        let removed = null;
        conns.forEach(c => {
            if (c.ws === ws) {
                removed = c;
                conns.delete(c);
                wsBroadcastToPage(pid, 'user-left', { userId: ws.userId }, ws.userId);
            }
        });
        try {
            if (removed && removed.isE2ee && removed.sessionId) {
                const leader = e2eeSnapshotLeaders.get(pid);
                if (leader && String(leader.sessionId) === String(removed.sessionId)) {
                    if (!hasActiveE2eeSessionOnPage(pid, leader.sessionId)) e2eeSnapshotLeaders.delete(pid);
                }
            }
        } catch (_) {}
        if (conns.size === 0) {
            wsConnections.pages.delete(pid);
            try { e2eeSnapshotLeaders.delete(pid); } catch (_) {}
            clearE2eeSnapshotRequestTimer(pid);
            e2eeLastUpdateAt.delete(pid);
            e2eeLastSnapshotAt.delete(pid);

            const doc = yjsDocuments.get(pid);
            if (doc) {
                const epoch = getYjsSaveEpoch(pid);
                enqueueYjsDbSave(pid, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pid, doc.ydoc, { epoch }))
                    .catch(e => { console.error('[YJS] connection cleanup save failed:', String(pid), e?.message || e); });
            }
        }
    });
    wsConnections.storages.forEach((conns, sid) => { conns.forEach(c => { if (c.ws === ws) conns.delete(c); }); if (conns.size === 0) wsConnections.storages.delete(sid); });
    const uconns = wsConnections.users.get(ws.userId);
    if (uconns) { uconns.forEach(c => { if (c.ws === ws) uconns.delete(c); }); if (uconns.size === 0) wsConnections.users.delete(ws.userId); }
}

function startRateLimitCleanup() { return setInterval(() => { const now = Date.now(); wsConnectionLimiter.forEach((l, ip) => { if (now > l.resetTime) wsConnectionLimiter.delete(ip); }); }, 300000); }

function startInactiveConnectionsCleanup(pool, sanitizeHtmlContent) { return setInterval(() => { cleanupInactiveConnections(pool, sanitizeHtmlContent); cleanupInactiveE2EEStates(); }, 600000); }

function invalidateYjsPersistenceForPage(pageId) {
    bumpYjsSaveEpoch(pageId);
}

function wsKickUserFromStorage(storageId, targetUserId, closeCode = 1008, reason = 'Access revoked') {
    const sid = String(storageId);
    const uid = String(targetUserId);

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

    for (const [pageId, pageConns] of Array.from(wsConnections.pages.entries())) {
        for (const c of Array.from(pageConns)) {
            if (String(c.userId) === uid && String(c.storageId) === sid) {
                pageConns.delete(c);
                try { c.ws.send(JSON.stringify({ event: 'access-revoked', data: { pageId, storageId: sid } })); } catch (e) {}
                try {
                    if (c.isE2ee) {
                        const leader = e2eeSnapshotLeaders.get(String(pageId));
                        if (leader && String(leader.userId) === uid) e2eeSnapshotLeaders.delete(String(pageId));
                    }
                } catch (_) {}
            }
        }
        if (pageConns.size === 0) {
            wsConnections.pages.delete(pageId);
            try { e2eeSnapshotLeaders.delete(String(pageId)); } catch (_) {}
        }
    }

    const userConns = wsConnections.users.get(uid);
    if (userConns) for (const c of Array.from(userConns)) { try { c.ws.close(closeCode, reason); } catch (e) {} }
}

module.exports = {
    initWebSocketServer,
    wsBroadcastToPage,
    wsBroadcastToStorage,
    wsBroadcastToUser,
    startRateLimitCleanup,
    startInactiveConnectionsCleanup,
    wsConnections,
    yjsDocuments,
    yjsE2EEStates,
    saveYjsDocToDatabase,
    enqueueYjsDbSave,
    flushAllPendingYjsDbSaves,
    flushPendingE2eeSaveForPage,
    flushAllPendingE2eeSaves,
    flushAllPendingE2eeUpdateLogs,
    wsCloseConnectionsForSession,
    wsCloseConnectionsForPage,
    wsHasActiveConnectionsForPage,
    wsKickUserFromStorage,
    extractFilesFromContent,
    invalidateYjsPersistenceForPage
};