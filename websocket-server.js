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

// WebSocket 모듈 전역(의존성 주입)
// wsCloseConnectionsForPage 같은 헬퍼는 pool/sanitizeHtmlContent에 직접 접근할 수 없어서,
// initWebSocketServer에서 한 번 주입해 모듈 스코프에 보관함
// (중요) 문서 리셋/강제 종료 시점에도 최신 편집분을 DB에 best-effort로 남기기 위해 사용함
let _wsPool = null;
let _wsSanitizeHtmlContent = null;

// 데이터 유실 방지(핵심): 협업 세션 강제 종료(wsCloseConnectionsForPage) 시
// 문서를 drop 하기 전에 마지막 스냅샷(HTML)을 DB에 긴급 저장함
// 저장 실패 시에도 즉시 drop 하지 않고, 백오프로 재시도하여 서버 재시작/크래시 시 유실 위험을 줄임
const emergencyPersistState = new Map(); // pageId -> { epoch, attempts, timer, forceClearYjsState }

const EMERGENCY_PERSIST_MAX_ATTEMPTS = (() => {
    const v = Number.parseInt(process.env.YJS_EMERGENCY_PERSIST_MAX_ATTEMPTS || '8', 10);
    return Number.isFinite(v) ? Math.max(0, Math.min(30, v)) : 8;
})();
const EMERGENCY_PERSIST_BASE_MS = (() => {
    const v = Number.parseInt(process.env.YJS_EMERGENCY_PERSIST_BASE_MS || '1500', 10);
    return Number.isFinite(v) ? Math.max(200, Math.min(60_000, v)) : 1500;
})();
const EMERGENCY_PERSIST_MAX_MS = (() => {
    const v = Number.parseInt(process.env.YJS_EMERGENCY_PERSIST_MAX_MS || '60000', 10);
    return Number.isFinite(v) ? Math.max(500, Math.min(300_000, v)) : 60000;
})();
function computeEmergencyPersistDelayMs(attempt) {
    const a = Math.max(1, Math.min(30, attempt));
    const base = EMERGENCY_PERSIST_BASE_MS * Math.pow(2, a - 1);
    return Math.min(EMERGENCY_PERSIST_MAX_MS, Math.floor(base));
}

function inferForceClearYjsStateFromReason(reason) {
    const r = String(reason || '').toLowerCase();
    // oversize / resync / collaboration reset 등은 yjs_state 저장이 비용이 크거나 위험하므로 clear 우선함
    if (!r) return true;
    return r.includes('too large') || r.includes('oversize') || r.includes('resync') || r.includes('reset');
}

function scheduleEmergencyPersistThenDrop(pageId, reason, opts = {}) {
    const pid = String(pageId || '').trim();
    if (!pid) return;

    const docInfo = yjsDocuments.get(pid);
    if (!docInfo || !docInfo.ydoc) {
        // 문서가 없으면 기존 동작(즉시 drop)으로 귀결함
        if (yjsDocuments.has(pid)) dropYjsDocument(pid);
        return;
    }

    // 암호화 페이지는 서버가 평문을 저장하면 안 되므로(보안), 즉시 drop함
    if (docInfo.isEncrypted === true) {
        dropYjsDocument(pid);
        return;
    }

    // pool/sanitize가 없으면 저장 불가함 -> 최소한 타이머는 정리하고 drop함 (fallback)
    if (!_wsPool || typeof _wsPool.execute !== 'function' || typeof _wsSanitizeHtmlContent !== 'function') {
        try { if (docInfo.saveTimeout) clearTimeout(docInfo.saveTimeout); } catch (_) {}
        docInfo.saveTimeout = null;
        dropYjsDocument(pid);
        return;
    }

    // 이미 긴급 저장이 예약되어 있으면 중복 예약 금지함
    const existing = emergencyPersistState.get(pid);
    if (existing && existing.timer) return;

    // 기존 디바운스 저장 타이머는 취소함 (중복 저장/레이스 방지)
    try { if (docInfo.saveTimeout) clearTimeout(docInfo.saveTimeout); } catch (_) {}
    docInfo.saveTimeout = null;

    const forceClearYjsState = (opts.forceClearYjsState === true || opts.forceClearYjsState === false)
        ? opts.forceClearYjsState
        : inferForceClearYjsStateFromReason(reason);

    // 진행 중/예약된 저장 무효화 + 이번 저장에 사용할 epoch 발급함
    const epoch = bumpYjsSaveEpoch(pid);

    const state = {
        epoch,
        attempts: 0,
        timer: null,
        forceClearYjsState
    };
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

            // epoch가 더 최신으로 올라가 저장이 스킵된 경우:
            // 다른 경로(REST 저장/정리 루틴)가 더 최신 상태를 다루고 있다는 의미이므로
            // 데이터 유실을 막기 위해 여기서는 drop 하지 않고 문서를 유지함
            if (result && result.status === 'skipped-epoch') {
                emergencyPersistState.delete(pid);
                return;
            }

            emergencyPersistState.delete(pid);
            // 저장 성공 후에만 문서를 drop함 (bumpEpoch=false: 방금 저장한 epoch를 무효화하지 않음)
            dropYjsDocument(pid, { bumpEpoch: false });
        } catch (e) {
            cur.attempts = (cur.attempts || 0) + 1;
            cur.timer = null;

            const msg = e?.message || e;
            try { console.error(`[YJS] emergency persist failed(page=${pid}, attempt=${cur.attempts}):`, msg); } catch (_) {}

            if (EMERGENCY_PERSIST_MAX_ATTEMPTS > 0 && cur.attempts <= EMERGENCY_PERSIST_MAX_ATTEMPTS) {
                const delay = computeEmergencyPersistDelayMs(cur.attempts);
                cur.timer = setTimeout(attempt, delay);
                emergencyPersistState.set(pid, cur);
                return;
            }

            // 최종 실패: 데이터 보존을 위해 문서를 메모리에 유지함 (다음 inactivity cleanup/수동 resync로 회복 가능함)
            emergencyPersistState.delete(pid);
        }
    };

    // 첫 시도는 즉시(0ms) 실행해 유실 창을 최소화함
    state.timer = setTimeout(attempt, 0);
    emergencyPersistState.set(pid, state);
}

// 데이터 유실 방지: 동일 페이지(pageId)에 대해 saveYjsDocToDatabase()가 병렬로 실행되는 것을 방지
// 병렬 실행 시 나중에 시작한 저장이 먼저 커밋되고, 먼저 시작한 저장이 나중에 커밋되면서
// 최신 데이터를 과거 상태로 되돌리는 현상(Lost Update)을 막기 위해 직렬화 처리
const yjsDbSaveQueue = new Map(); // 페이지 ID별 프로미스 체인

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

// 데이터 유실 방지: Yjs -> DB 저장 레이스 취소 토큰(epoch)
// REST 저장(PUT)이 발생하면 epoch를 증가시켜, 이전에 예약된(setTimeout) WS 저장이
// DB를 덮어쓰지 못하도록 무효화(fail-closed) 진행
const yjsSaveEpoch = new Map(); // pageId -> number

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

/**
 * yjsDocuments 엔트리 안전 제거
 * - saveTimeout이 남아있으면, 문서가 Map에서 제거된 뒤에도 타이머 콜백이 실행되어
 *   DB에 오래된 상태를 덮어써 데이터 유실이 발생할 수 있음 (특히 REST 저장과 경쟁)
 */
function dropYjsDocument(pageId, opts = {}) {
    const pid = String(pageId || '');
    // 기본 동작: 진행 중이거나 예약된 저장 무효화
    // - 단, 저장 후 정리 경로에서 epoch를 올리면(=무효화)
    //   saveYjsDocToDatabase의 DB UPDATE 직전 epoch 재확인에서 취소되어
    //   결과적으로 데이터가 저장되지 않는 레이스가 발생할 수 있음
    //   (예: inactivity cleanup)
    const bumpEpoch = opts.bumpEpoch !== false;
    if (bumpEpoch) bumpYjsSaveEpoch(pid);
    const doc = yjsDocuments.get(pid);
    if (doc?.saveTimeout) {
        try { clearTimeout(doc.saveTimeout); } catch (_) {}
        doc.saveTimeout = null;
    }
    yjsDocuments.delete(pid);
}

// E2EE 암호화 저장소 페이지의 encrypted Yjs state 보관 (서버는 평문 불가)
// pageId -> { encryptedState: string (base64), encryptedHtml: string, saveTimeout: timer }
const yjsE2EEStates = new Map();

// E2EE 암호화 저장소 페이지의 리더(스냅샷 저장 담당자) 보관
// pageId -> { sessionId: string, userId: number, lastSeenAt: number }
const e2eeSnapshotLeaders = new Map();

const USER_COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B195', '#C06C84'];
const wsConnectionLimiter = new Map();
const WS_RATE_LIMIT_WINDOW = 60 * 1000;
const WS_RATE_LIMIT_MAX_CONNECTIONS = 10;
const WS_MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
const WS_MAX_AWARENESS_UPDATE_BYTES = 32 * 1024;

// ==================== E2EE 스냅샷 요청 (데이터 유실 방지) ====================
// 서버가 복호화할 수 없는 E2EE 증분 업데이트의 경우, 전체 스냅샷 수신에 의존해 DB에 저장함
// 편집자가 탭을 닫거나 크래시가 발생해 스냅샷이 전송되지 않으면 데이터가 유실될 수 있음
// 이를 방지하기 위해 증분 업데이트 수신 후 일정 시간 내에 스냅샷이 도착하지 않으면
// 현재 접속 중인 다른 편집 권한 사용자들에게 스냅샷 업로드를 요청함
const E2EE_SNAPSHOT_EXPECT_MS = (() => {
    const n = Number.parseInt(process.env.E2EE_SNAPSHOT_EXPECT_MS || '1500', 10);
    if (!Number.isFinite(n)) return 1500;
    return Math.max(300, Math.min(10_000, n));
})();

const e2eeLastUpdateAt = new Map();        // pageId -> ms
const e2eeLastSnapshotAt = new Map();      // pageId -> ms
const e2eeSnapshotRequestTimers = new Map(); // pageId -> timeout

// ==================== E2EE Incremental Update Log (DB WAL) ====================
// E2EE 페이지에서 스냅샷 저장 사이 데이터 유실 방지용 WAL
// 증분 업데이트(yjs-update-e2ee)를 DB에 누적 저장하여 재접속 시 복구함
// 서버는 암호문 상태로만 저장하므로 키 정보가 없어도 무관함
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
    const n = Number.parseInt(process.env.E2EE_PENDING_SEND_CHUNK_MAX_B64_CHARS || '262144', 10); // 256KB
    return (Number.isFinite(n) && n > 0) ? n : 262144;
})();

const e2eeUpdateLogBuffer = new Map(); // pageId -> [{ ms, blob }]
let e2eeUpdateLogFlushTimer = null;

/**
 * E2EE 증분 업데이트를 DB WAL에 기록하도록 버퍼링함
 */
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

/**
 * 버퍼링된 모든 E2EE 증분 로그를 DB에 배치 INSERT함
 */
async function flushAllPendingE2eeUpdateLogs(pool) {
    if (e2eeUpdateLogBuffer.size === 0) return;

    const pageIds = Array.from(e2eeUpdateLogBuffer.keys());
    for (const pid of pageIds) {
        const queue = e2eeUpdateLogBuffer.get(pid);
        if (!queue || queue.length === 0) {
            e2eeUpdateLogBuffer.delete(pid);
            continue;
        }

        // 배치 단위로 끊어서 처리함
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

    // 남은 항목이 있으면 다음 틱에 재시도함
    if (e2eeUpdateLogBuffer.size > 0 && !e2eeUpdateLogFlushTimer) {
        e2eeUpdateLogFlushTimer = setTimeout(() => {
            e2eeUpdateLogFlushTimer = null;
            flushAllPendingE2eeUpdateLogs(pool).catch(() => {});
        }, E2EE_UPDATELOG_FLUSH_MS);
    }
}

/**
 * 신규 접속한 클라이언트에게 마지막 스냅샷 이후의 WAL을 전송함
 */
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

        // 너무 큰 페이로드를 피하기 위해 chunk 단위로 끊어서 전송함
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

/**
 * 데이터 유실 방지(Self-heal): 비암호화 페이지의 HTML 스냅샷 재전송 요청
 * - 서버 메모리의 Yjs 문서에 metadata.content 가 유실된 경우(동기화 이상/버그),
 *   편집 권한이 있는 클라이언트들에게 현재 에디터의 HTML을 스냅샷으로 보내달라고 요청
 */
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

// ==================== 대용량 full-state 구제 (데이터 유실 방지) ====================
// 클라이언트가 resync 모드에서 대용량 Yjs state를 보낼 때 서버 제한을 초과하는 경우 발생함
// 단순히 연결을 끊으면 클라이언트의 최신 편집분이 저장되지 않아 데이터 유실로 보임
// 전략: 가벼운 HTML 스냅샷을 먼저 요청하여 DB에 보존한 뒤 세션을 리셋함
const oversizeResyncCloseTimers = new Map(); // pageId -> timeout

function scheduleOversizeResyncSnapshotThenClose(pageId, reason = 'Document too large - collaboration reset') {
    const pid = String(pageId || '');
    if (!pid) return;
    if (oversizeResyncCloseTimers.has(pid)) return;

    // 활성 편집자에게 HTML 스냅샷 전송 요청함 (best-effort)
    wsRequestPageSnapshot(pid);

    // 클라이언트가 응답할 시간을 준 뒤 세션 리셋함
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

// ==================== E2EE Leader Election & Persistence Helpers ====================
const E2EE_LEADER_IDLE_HANDOFF_MS = (() => {
    const n = Number.parseInt(process.env.E2EE_LEADER_IDLE_HANDOFF_MS || '2000', 10);
    if (!Number.isFinite(n)) return 2000;
    return Math.max(500, Math.min(60_000, n));
})();

// E2EE 리더 선출 및 핸드오프 정책
// 기존 설계는 1명의 리더만 전체 스냅샷(yjs-state-e2ee)을 DB에 저장할 수 있음
// 하지만 리더가 편집 없이 접속만 유지하는 경우, 다른 편집자의 스냅샷 저장이 거부되어 최신 암호화 상태가 유실될 수 있음
// 이를 방지하기 위해 리더가 일정 시간 비활성 상태이면 활성 편집자에게 리더 권한을 자동으로 핸드오프하고,
// 연결 종료나 권한 회수 시에는 기존 리더를 즉시 제거함

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
    // 리더 세션이 실제로 연결돼 있지 않으면 즉시 무효화 (stale leader 방지)
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

/**
 * E2EE 스냅샷(암호문) DB 저장 (디바운스/버퍼 + 재시도)
 * - Yjs 증분 업데이트가 올 때마다 즉시 DB에 쓰는 것은 비효율적이므로 디바운스로 마지막 입력분만 저장
 * - 저장 실패(일시적인 DB 장애/락 등) 시, 기존 구현은 재시도를 하지 않아
 *   다음 편집이 없으면 최신 암호문 상태가 영속화되지 못하고 서버/프로세스 종료 시 유실될 수 있음
 *
 * 참고: 언로드/백그라운드 전환 시 네트워크 요청은 브라우저에서 신뢰할 수 없으므로,
 *       서버 측에서는 저장 실패 시 재시도가 데이터 유실 위험을 크게 낮춤
 */
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
    // attempt: 1,2,3...
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

    // 새 입력이 들어오면 retryCount는 리셋 (최신 상태 우선)
    const next = {
        ...prev,
        encryptedState,
        // encryptedHtml이 명시적으로 주어지지 않으면 기존 값을 유지(=무의미한 NULL 덮어쓰기 방지)
        ...(encryptedHtml !== undefined ? { encryptedHtml } : {}),
        storedAt: Date.now(),
        snapshotAtMs: Number.isFinite(snapshotAtMs) ? snapshotAtMs : (prev.snapshotAtMs || Date.now()),
        retryCount: 0,
        saveTimeout: null
    };

    const attemptSave = async () => {
        const cur = yjsE2EEStates.get(pid);
        if (!cur) return;
        // 최신 입력이 아닌 saveTimeout 콜백이면 중단
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

    // 기본 디바운스(성능) — 실패 시에는 백오프 재시도
    next.saveTimeout = setTimeout(attemptSave, 1500);
    yjsE2EEStates.set(pid, next);
}

/**
 * 대기 중인 E2EE 저장 작업을 즉시 실행 (플러시)
 */
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

/**
 * 서버 종료 시 모든 대기 중인 E2EE 저장 작업을 플러시
 */
async function flushAllPendingE2eeSaves(pool) {
    const pageIds = Array.from(yjsE2EEStates.keys());
    console.log(`[E2EE] Graceful shutdown: flushing ${pageIds.length} pending E2EE saves...`);
    for (const pageId of pageIds) {
        await flushPendingE2eeSaveForPage(pool, pageId);
    }
}

/**
 * E2EE 상태를 데이터베이스에 실제 저장 (SQL 실행)
 */
async function saveE2EEStateToDatabase(pool, pageId, encryptedState, encryptedHtml, snapshotAtMs = null) {
    if (!encryptedState) return;

    try {
        const baseMs = Number.isFinite(snapshotAtMs) ? snapshotAtMs : Date.now();
        const updateTime = formatDateForDb(new Date(baseMs));

        // 데이터 유실 방지:
        // - encryptedHtml(암호화된 HTML 스냅샷)은 일부 클라이언트/상황에서 누락될 수 있음(undefined/null)
        // - 기존 구현처럼 NULL로 덮어쓰면, 백업/복구 경로에서 사용할 수 있는 암호문 스냅샷이 사라질 수 있음
        // - 따라서 encryptedHtml이 명시적으로 제공된 경우에만 갱신하고, 그렇지 않으면 기존 값을 유지
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

        // 스냅샷 이전(< snapshotAtMs)의 증분 로그 정리 (유실 방지 위해 '<' 사용)
        await pool.execute(`DELETE FROM e2ee_yjs_updates WHERE page_id = ? AND created_at_ms < ?`, [pageId, baseMs]);
    } catch (error) {
        throw error;
    }
}

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

/**
 * 보안: 실시간 Yjs 업데이트를 본 문서에 적용하기 전에 복제본에 먼저 적용해 검증
 * - 서버가 클라이언트 정화/검증에 의존하지 않도록 함 (CWE-602)
 * - 브로드캐스트 전에 위험 HTML/비정상 metadata 상태를 차단
 */
function cloneYDocForValidation(srcYDoc) {
    const cloned = new Y.Doc();
    // 현재 상태를 스냅샷으로 복제
    Y.applyUpdate(cloned, Y.encodeStateAsUpdate(srcYDoc));
    return cloned;
}

function validateRealtimeYjsCandidate(candidateYDoc, sanitizeHtmlContent) {
    try {
        const yMeta = candidateYDoc.getMap('metadata');

        // 데이터 유실 방지(중요): 필수 메타 키(content)가 사라진 상태를 저장하면
        // saveYjsDocToDatabase의 fallback 로직에 의해 문서가 빈 값으로 덮어써질 수 있음
        // (클라이언트 버그/악성 업데이트 모두 포함) → 필수 키가 없으면 즉시 거부
        if (!yMeta.has('content')) return { ok: false, code: 1008, reason: 'Missing content' };

        // title
        if (yMeta.has('title')) {
            const title = yMeta.get('title');
            if (typeof title !== 'string') return { ok: false, code: 1008, reason: 'Invalid title type' };
            if (byteLenUtf8(title) > 512) return { ok: false, code: 1009, reason: 'Title too large' };
        }

        // icon (서버 규칙과 동일 검증)
        if (yMeta.has('icon')) {
            const rawIcon = yMeta.get('icon');
            const normalized = validateAndNormalizeIcon(rawIcon);
            // null 허용(비우기) / 문자열이면 normalize 결과와 정합성 체크
            if (rawIcon != null && typeof rawIcon !== 'string')
                return { ok: false, code: 1008, reason: 'Invalid icon type' };

            if (typeof rawIcon === 'string' && normalized !== rawIcon.trim())
                return { ok: false, code: 1008, reason: 'Invalid icon value' };
        }

        // parentId 기본 타입 제한 (세부 접근통제는 기존 validateYjsParentAssignment가 담당)
        if (yMeta.has('parentId')) {
            const parentId = yMeta.get('parentId');
            if (!(parentId == null || typeof parentId === 'string'))
                return { ok: false, code: 1008, reason: 'Invalid parentId type' };

            if (typeof parentId === 'string' && byteLenUtf8(parentId) > 128)
                return { ok: false, code: 1008, reason: 'Invalid parentId' };
        }

        // content 저장 시점에만 sanitize 하지 말고 실시간 경로에서도 동일 기준 적용
        if (yMeta.has('content')) {
            const rawContent = yMeta.get('content');
            if (typeof rawContent !== 'string') return { ok: false, code: 1008, reason: 'Invalid content type' };
            if (byteLenUtf8(rawContent) > (2 * 1024 * 1024))
                return { ok: false, code: 1009, reason: 'Content too large' };

            const sanitized = sanitizeHtmlContent(rawContent);
            // 정화 결과가 달라지면 서버 관점에서 위험/비정상 입력으로 간주하여 거부
            if (sanitized !== rawContent)
                return { ok: false, code: 1008, reason: 'Unsafe content' };
        }

        return { ok: true };
    } catch (_) {
        return { ok: false, code: 1008, reason: 'Invalid Yjs state' };
    }
}

const WS_MAX_YJS_UPDATE_B64_CHARS = Math.ceil(WS_MAX_YJS_UPDATE_BYTES / 3) * 4 + 8;
const WS_MAX_AWARENESS_UPDATE_B64_CHARS = Math.ceil(WS_MAX_AWARENESS_UPDATE_BYTES / 3) * 4 + 8;
// Full-state(resync) payload upper bound (base64 chars)
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
    clearOversizeResyncTimer(pid);
    const conns = wsConnections.pages.get(pid);

    if (conns && conns.size > 0) {
        for (const c of Array.from(conns)) {
            try { c.ws.send(JSON.stringify({ event: 'collab-reset', data: { pageId: pid, reason } })); } catch (_) {}
            try { c.ws.close(code, reason); } catch (_) {}
        }
    }

    // 구독 맵에서는 먼저 제거해 추가 업데이트 유입을 차단함
    wsConnections.pages.delete(pid);

    // 데이터 유실 방지(핵심): 강제 종료/리셋 시점에 문서를 즉시 drop 하지 말고
    // 마지막 HTML 스냅샷을 DB에 긴급 저장한 뒤에 drop함
    // (실패 시 재시도, 성공 후 drop)
    scheduleEmergencyPersistThenDrop(pid, reason);
}

function getUserColor(userId) { return USER_COLORS[userId % USER_COLORS.length]; }

function cleanupInactiveConnections(pool, sanitizeHtmlContent) {
    const now = Date.now();
    const TIMEOUT = 30 * 60 * 1000;
    yjsDocuments.forEach((doc, pageId) => {
        if (now - doc.lastAccess <= TIMEOUT) return;

        // 데이터 유실/문서 파손 방지:
        // - 구독(연결)이 살아있는 상태에서 서버 메모리 문서를 drop 하면
        //   클라이언트는 계속 편집/동기화 중인데 서버 문서가 사라져 재동기화/충돌로 이어질 수 있음
        // - 활성 구독이 남아있으면 정리 금지
        const conns = wsConnections.pages.get(String(pageId));
        if (conns && conns.size > 0) {
            doc.lastAccess = now; // 활동으로 간주하여 유예
            return;
        }

        // pending debounce save가 남아있다면 먼저 정리 (중복 저장/레이스 방지)
        if (doc.saveTimeout) {
            try { clearTimeout(doc.saveTimeout); } catch (_) {}
            doc.saveTimeout = null;
        }

        const epoch = bumpYjsSaveEpoch(pageId);

        // 중요:
        // - dropYjsDocument()가 epoch를 bump 하면, 방금 시작한 saveYjsDocToDatabase가
        //   DB UPDATE 직전(epoch 재확인)에서 스스로 취소되어 저장이 되지 않는 레이스가 발생할 수 있음
        // - 따라서 저장 성공(또는 epoch 스킵) 이후에 bumpEpoch=false로 정리
        // - 저장 실패 시에는 문서를 유지하여 다음 cleanup 주기에서 재시도(=데이터 유실 방지)
        enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, doc.ydoc, { epoch }))
            .then(() => {
                dropYjsDocument(pageId, { bumpEpoch: false });
            })
            .catch((e) => {
                try {
                    console.error('[YJS] inactivity cleanup save failed:', String(pageId), e?.message || e);
                } catch (_) {}
                // 저장 실패: drop하지 않고 유지(다음 주기에 재시도)
                doc.lastAccess = now; // 즉시 재시도 폭주 방지
            });
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

    // paperclip 추출: data-src="/paperclip/<userId>/<filename>" (file-block)
    const fileRegex = /<div[^>]*data-type=["']file-block["'][^>]*data-src=["']\/paperclip\/([^"']+)["'][^>]*>/gi;
    let match;
    while ((match = fileRegex.exec(String(content))) !== null) {
        const ref = (pageOwnerUserId !== null && pageOwnerUserId !== undefined)
            ? normalizePaperclipRefForOwner(match[1], pageOwnerUserId)
            : normalizePaperclipRef(match[1]);
        if (ref) files.push({ type: 'paperclip', ref });
    }

    // imgs 추출: src="/imgs/<userId>/<filename>" (img tags, image-with-caption 등)
    // - userId가 pageOwnerUserId와 일치하는 경우만 수집 (보안 규칙 준수)
    const imgRegex = /src=["']\/imgs\/(\d+)\/([A-Za-z0-9._-]+)["']/gi;
    while ((match = imgRegex.exec(String(content))) !== null) {
        const ownerId = parseInt(match[1], 10);
        const filename = match[2];
        if (pageOwnerUserId === null || pageOwnerUserId === undefined || ownerId === pageOwnerUserId) {
            files.push({ type: 'imgs', ref: `${ownerId}/${filename}`, filename });
        }
    }
    return files;
}

// ============================================================
// 데이터 유실 방지(핵심): orphan cleanup(첨부파일 정리)에서 레지스트리(page_file_refs)만
// 의존하면, 다음 상황에서 참조 중인 파일을 고아로 오판해 영구 삭제할 수 있음
//  - 다른 페이지에 복사/붙여넣기로 재사용했지만 아직 저장/동기화가 끝나지 않아 레지스트리가 미등록인 경우
//  - 과거 버전/에러로 인해 레지스트리가 누락된 평문 페이지가 존재하는 경우
//
// 완화:
//  1. pages.content(평문 페이지)에서의 실제 참조도 함께 검사(레지스트리 self-heal 포함)
//  2. 서버 메모리의 활성 Yjs 문서(아직 DB에 flush되지 않은 상태)에서도 참조를 검사
//  3. 최종 삭제는 paperclip-trash로 이동(soft delete) 후, 별도 보존 기간이 지난 뒤에만 purge 권장
// ============================================================

function escapeLikeForSql(s) {
    // MySQL LIKE: % and _ are wildcards. Backslash is the default escape.
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
    // 특정 사용자 디렉터리로 scope를 제한 (타 사용자 파일 임의 삭제 방지)
    const ownerIdStr = String(pageOwnerUserId ?? '').trim();
    if (!ownerIdStr || !/^\d{1,12}$/.test(ownerIdStr)) return;
    const baseDir = path.resolve(__dirname, 'paperclip', ownerIdStr) + path.sep;

    for (const item of filePaths) {
        try {
            // 현재 orphan cleanup은 paperclip 만 대상으로 함 (imgs는 별도 정책 필요)
            if (item.type !== 'paperclip') continue;
            const ref = item.ref;

            const normalized = normalizePaperclipRefForOwner(ref, ownerIdStr);
            if (!normalized) continue;

            const [ownerId, filename] = normalized.split('/');

            // 보안(핵심): page_file_refs 레지스트리로 1차 참조 여부 판단
            // - 레지스트리 누락(복붙 직후 flush 지연 등) 오탐 방지를 위해 2차/3차 방어 추가
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

            // 2차 방어: 평문 페이지(content)에 실제 참조가 존재하는지 검사 + self-heal
            const plaintextRefs = await countPlaintextPaperclipRefs(pool, ownerId, filename, excludePageId);
            if (plaintextRefs > 0) {
                await backfillPaperclipRefsFromPlaintextContent(pool, ownerId, filename);
                continue;
            }

            // 3차 방어: 활성 Yjs 문서(메모리)에서 참조 검사 + self-heal
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
                // 영구 삭제 대신 휴지통(paperclip-trash)으로 이동(soft delete)
                const moved = movePaperclipToTrash(fs, path, fullPath, ownerIdStr, filename);
                if (!moved) {
                    try { fs.unlinkSync(fullPath); } catch (_) {}
                }
            }
        } catch (err) {
            // best-effort cleanup
        }
    }
}

async function saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, opts = {}) {
    try {
        const { epoch, allowDeleted = false, forceClearYjsState = false, preserveDbMetadata = false } = opts;
        // epoch 확인 (시작 시): 이미 더 새로운 REST 저장이 발생했다면 중단
        if (epoch !== undefined && getYjsSaveEpoch(pageId) > epoch) return { status: 'skipped-epoch' };

        // 데이터 유실 방지(중간): 최신 DB 상태를 읽어 삭제 여부 및 메타 정보 확인
        const [existingRows] = await pool.execute(
            'SELECT title, content, icon, sort_order, parent_id, is_encrypted, user_id, deleted_at FROM pages WHERE id = ?',
            [pageId]
        );

        // 페이지가 이미 삭제되었으면 저장을 중단하여 유령 데이터가 되살아나지 않도록 함
        // - 단, soft-delete(휴지통) 시점에 마지막 편집 내용을 보존해야 하는 경우가 있어
        //   allowDeleted=true 인 경우에는 deleted_at 을 그대로 유지한 채 content/yjs_state만 갱신을 허용
        if (existingRows.length === 0) {
            return { status: 'aborted-deleted' };
        }
        const existing = existingRows[0];
        if (existing.deleted_at !== null && !allowDeleted) {
            return { status: 'aborted-deleted' };
        }

        const yMetadata = ydoc.getMap('metadata');
        // 데이터 유실 방지(핵심):
        // - Y.Map은 delete/clear가 가능하므로(협업자/버그/악성 클라이언트) metadata의 필수 키(content 등)가 사라질 수 있음
        // - 기존 구현은 content 키가 없으면 저장을 중단했는데, 이 경우 yjs_state까지 저장되지 않아
        //   서버 재시작/문서 언로드 시 최신 편집분이 통째로 유실될 수 있음
        // - 따라서 content 키가 없을 때는 DB content는 유지 + yjs_state는 계속 저장으로 fail-safe 처리
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

        if (!shouldUpdateContent && !isEncrypted) {
            // 데이터 유실 방지: 서버 메모리 Yjs 에 content 키가 없으면 클라이언트에 재전송 요청(Self-heal)
            wsRequestPageSnapshot(pageId);
        }

        const pageOwnerUserId = (existing.user_id);
        let finalContent = '';
        let oldFiles = [];

        if (isEncrypted) {
            finalContent = '';
        } else {
            // content 키가 사라진 경우(shouldUpdateContent=false)에는 DB content를 유지
            finalContent = shouldUpdateContent ? (content || '<p></p>') : (existing.content || '<p></p>');
            oldFiles = extractFilesFromContent(existing.content, pageOwnerUserId);
        }

        // 보안: 암호화된 페이지는 yjs_state에 문서 스냅샷(평문)이 남을 수 있으므로 DB에 저장하지 않음
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

        // epoch 재확인 (DB UPDATE 직전): I/O 대기 중에 무효화되었을 수 있음
        if (epoch !== undefined && getYjsSaveEpoch(pageId) > epoch) return { status: 'skipped-epoch' };

        await pool.execute(
            `UPDATE pages SET title = ?, content = ?, icon = ?, sort_order = ?, parent_id = ?, yjs_state = ?, updated_at = NOW() WHERE id = ?`,
            [title, finalContent, icon, sortOrder, parentId, yjsStateToSave, pageId]
        );

        if (!isEncrypted && shouldUpdateContent) {
            const newFiles = extractFilesFromContent(content, pageOwnerUserId);

            try {
                // 신규 파일 등록
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

                // 레지스트리 제거
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
    // 모듈 스코프 의존성 주입 (긴급 저장/강제 종료 시 사용함)
    _wsPool = pool;
    _wsSanitizeHtmlContent = sanitizeHtmlContent;
    /**
     * ==================== WebSocket 보안: Origin 검증 (CSWSH 방지) ====================
     * - WebSocket은 브라우저의 SOP/CORS로 보호되지 않으므로, 핸드셰이크에서 Origin allowlist 검증이 필요함
     * - BASE_URL(예: https://example.com) 기준으로 허용 Origin을 구성함
     *   (리버스 프록시/도메인 변경 시 BASE_URL을 정확히 설정하길 권장함)
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
        // 데이터 유실 방지: 연결 종료 직전 HTML 스냅샷을 서버에 강제 전달
        case 'page-snapshot': await handlePageSnapshot(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        // 데이터 유실 방지: 사용자가 Ctrl+S/모드 전환 등으로 지금 저장을 요청
        case 'force-save': await handleForceSave(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'force-save-e2ee': await handleForceSaveE2EE(ws, payload, pool, pageSqlPolicy); break;
        case 'yjs-update': await handleYjsUpdate(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'yjs-state': await handleYjsState(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy); break;
        case 'awareness-update': await handleAwarenessUpdate(ws, payload, pool, pageSqlPolicy); break;
        // E2EE (저장소 암호화) 전용 핸들러
        case 'subscribe-page-e2ee': await handleSubscribePageE2EE(ws, payload, pool, pageSqlPolicy); break;
        case 'yjs-update-e2ee': await handleYjsUpdateE2EE(ws, payload, pool, pageSqlPolicy); break;
        case 'yjs-state-e2ee': await handleYjsStateE2EE(ws, payload, pool, pageSqlPolicy); break;
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
    // stale leader 정리
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
        // ===== 데이터 유실 방지: 구독 종료 시 타이머/상태 정리 =====
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

// ==================== E2EE (저장소 레벨 암호화) 전용 핸들러 ====================

/**
 * E2EE 페이지 구독 핸들러
 * - 저장소가 암호화된 경우에만 허용 (page.is_encrypted=1 AND storage.is_encrypted=1)
 * - 서버는 암호문만 중계하며 내용을 알 수 없음 (True E2EE)
 */
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

        // 보안: 페이지와 저장소 모두 암호화된 경우에만 E2EE 구독 허용
        if (page.is_encrypted !== 1 || page.storage_is_encrypted !== 1) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page is not E2EE encrypted' } }));
            return;
        }

        const permission = await getStoragePermission(pool, userId, page.storage_id);
        if (!permission) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        // 방어적 재검증
        if (page.share_allowed === 0 && Number(page.user_id) !== Number(userId)) {
            ws.send(JSON.stringify({ event: 'error', data: { message: 'Page not found' } }));
            return;
        }

        if (!wsConnections.pages.has(pageId)) wsConnections.pages.set(pageId, new Set());
        const conns = wsConnections.pages.get(pageId);
        // 중복 연결 제거
        for (const c of Array.from(conns)) {
            if (c.userId === userId && c.ws !== ws) { conns.delete(c); try { c.ws.close(1008, 'Duplicate'); } catch (_) {} }
        }
        const color = getUserColor(userId);
        // isE2ee: true — ensureActivePageAccess에서 E2EE 연결 허용 식별자
        const myConn = { ws, userId, username: ws.username, color, permission, storageId: page.storage_id, permCheckedAt: Date.now(), isE2ee: true, sessionId: ws.sessionId };
        conns.add(myConn);

        // 저장된 암호화 상태 전송 (메모리 우선 -> DB 폴백)
        let encryptedState = null;
        const memEntry = yjsE2EEStates.get(String(pageId));
        if (memEntry) {
            encryptedState = memEntry.encryptedState;
        } else if (page.e2ee_yjs_state) {
            // DB에 저장된 상태가 있으면 로드
            // 중요: e2ee_yjs_state는 LONGBLOB(바이너리)로 저장되므로,
            // 클라이언트가 기대하는 base64 문자열로 되돌릴 때는 반드시 base64 인코딩을 사용해야 함
            // (과거/마이그레이션 호환을 위해 base64 텍스트로 저장된 경우도 감지)
            try {
                const blob = page.e2ee_yjs_state;
                if (Buffer.isBuffer(blob)) {
                    const asUtf8 = blob.toString('utf8');
                    // base64 텍스트로 저장된 레거시(혹은 마이그레이션) 형식이면 그대로 사용
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

        // 마지막 스냅샷 이후의 WAL 전송함
        const sinceMs = Number(page.e2ee_yjs_state_updated_ms) || 0;
        sendPendingE2eeUpdatesToClient(ws, pool, pageId, sinceMs).catch(() => {});

        // 리더 선출 시도 (스냅샷 저장 담당)
        // - 편집 권한이 있는 사용자만 리더가 될 수 있음
        if (['EDIT', 'ADMIN'].includes(permission)) {
            const leader = maybeElectE2eeLeader(pageId, myConn);
            const isLeader = (leader.sessionId === myConn.sessionId);
            ws.send(JSON.stringify({ event: 'e2ee-leader-status', data: { isLeader } }));
        }

        // 기존 참여자들에게 user-joined 알림 (그들이 최신 state를 새 참여자에게 전달)
        wsBroadcastToPage(pageId, 'user-joined', { userId, username: ws.username, color, permission }, userId);
    } catch (e) {
        ws.send(JSON.stringify({ event: 'error', data: { message: 'Failed' } }));
    }
}

/**
 * E2EE Yjs 업데이트 중계 핸들러
 * - 서버는 암호문을 검증하지 않고 단순 중계
 * - 크기/권한 제한은 그대로 적용
 */
async function handleYjsUpdateE2EE(ws, payload, pool, pageSqlPolicy) {
    const { pageId, update } = payload || {};
    try {
        if (!pageId || typeof update !== 'string' || !isSubscribedToPage(ws, pageId)) return;

        const conns = wsConnections.pages.get(pageId);
        const myConn = Array.from(conns).find(c => c.ws === ws);
        if (!myConn || !myConn.isE2ee) return;

        // 권한 재검증 (E2EE라도 편집 권한 필요)
        const freshPerm = await refreshConnPermission(pool, myConn, { force: true });
        if (!freshPerm) {
            revokePageSubscription(ws, pageId, conns, myConn, 'storage-access-revoked');
            return;
        }
        if (!['EDIT', 'ADMIN'].includes(freshPerm)) return;

        // 데이터 유실 방지: 활성 편집자가 리더를 승계하도록 핸드오프(리더 고착 방지)
        ensureE2eeLeaderForActiveEditor(pageId, myConn);

        // 크기 제한
        if (update.length > WS_MAX_YJS_UPDATE_B64_CHARS) return;
        const updateBuf = Buffer.from(update, 'base64');
        if (updateBuf.length > WS_MAX_YJS_UPDATE_BYTES) return;

        // 암호문 중계 (내용 검증 불가/불필요 — 서버는 키 없음)
        wsBroadcastToPage(pageId, 'yjs-update-e2ee', { update }, ws.userId);

        // WAL(증분 로그) 기록함
        bufferE2eeUpdateLog(pool, pageId, updateBuf);

        // ===== 데이터 유실 방지(핵심): 스냅샷 요청 백스톱 =====
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

/**
 * E2EE 전체 상태 스냅샷 저장 핸들러
 * - 클라이언트가 주기적으로 전체 암호화 상태를 서버에 저장 (늦게 입장하는 참여자를 위한 초기 상태)
 * - 브로드캐스트 없음; 서버 내부 캐시에만 저장 + DB 영속화
 * - 리더(Leader) 클라이언트만 저장 권한을 가짐 (충돌 방지)
 */
async function handleYjsStateE2EE(ws, payload, pool, pageSqlPolicy) {
    const { pageId, encryptedState, encryptedHtml } = payload || {};
    try {
        if (!pageId || typeof encryptedState !== 'string' || !isSubscribedToPage(ws, pageId)) return;

        const conns = wsConnections.pages.get(pageId);
        const myConn = Array.from(conns).find(c => c.ws === ws);
        if (!myConn || !myConn.isE2ee) return;

        // 권한 체크
        const freshPerm = await refreshConnPermission(pool, myConn); // 캐시 허용
        if (!['EDIT', 'ADMIN'].includes(freshPerm)) return;

        // 리더 선출/핸드오프: 리더가 비활성이면 활성 편집자로 승계
        const leader = ensureE2eeLeaderForActiveEditor(pageId, myConn);
        if (leader && String(leader.sessionId) !== String(myConn.sessionId)) return;

        // 크기 제한 (state는 update보다 클 수 있으므로 state용 상한 적용)
        const maxStateB64Chars = Math.ceil(WS_MAX_YJS_STATE_BYTES / 3) * 4 + 8;
        if (encryptedState.length > maxStateB64Chars) return;
        // 데이터 유실 방지: 잘못된 base64 입력이 DB 상태를 오염시키지 않도록 fail-closed 검증
        if (!/^[A-Za-z0-9+/=]+$/.test(encryptedState)) return;
        try {
            const buf = Buffer.from(encryptedState, 'base64');
            // AES-GCM: IV(12) + 최소 태그(16) = 28 bytes 미만이면 비정상
            if (!buf || buf.length < 28) return;
        } catch (_) { return; }

        // 메모리 캐시 업데이트
        yjsE2EEStates.set(String(pageId), { encryptedState, storedAt: Date.now() });

        // ===== 데이터 유실 방지: 스냅샷 수신 시 타이머/상태 갱신 =====
        const pid = String(pageId);
        e2eeLastSnapshotAt.set(pid, Date.now());
        clearE2eeSnapshotRequestTimer(pid);

        // 리더 활동 갱신
        touchE2eeLeader(pageId, myConn);

        // DB 영속화 (Debounced)
        scheduleE2EESave(pool, pageId, encryptedState, encryptedHtml, Date.now());

    } catch (e) {}
}

/**
 * 비활성 E2EE 상태 및 리더 정리 (메모리 누수 방지)
 */
function cleanupInactiveE2EEStates() {
    const now = Date.now();
    const TIMEOUT = 24 * 60 * 60 * 1000; // 24시간 미접근 시 정리

    // States 정리
    yjsE2EEStates.forEach((entry, pageId) => {
        if (now - entry.storedAt > TIMEOUT)
            yjsE2EEStates.delete(pageId);
    });

    // Leaders 정리 (30초 timeout보다 넉넉하게, 혹은 getActiveE2eeLeader에서 lazy cleanup 하므로 여기선 전체 스캔으로 정리)
	e2eeSnapshotLeaders.forEach((leader, pageId) => {
		// 1분 이상 잠수면 정리
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

/**
 * 데이터 유실 방지: 탭 종료/페이지 이탈 직전 클라이언트가 밀어넣는 HTML 스냅샷 처리
 * - 암호화(E2EE) 페이지는 서버가 평문을 알면 안 되므로 거부
 * - 메모리 Y.Doc의 metadata에만 반영 (별도 DB 저장 없이 다음 saveTimeout에 자동 포함)
 */
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

    // E2EE/암호화 페이지: 서버는 평문을 알면 안 되므로 snapshot 업로드 자체를 거부
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

        // 데이터 유실 방지: 스냅샷을 받았으므로 즉시(또는 짧은 지연 후) 저장을 예약하여 유실 위험 최소화
        if (docMeta.saveTimeout) clearTimeout(docMeta.saveTimeout);

        // 긴급 저장이 이미 예약된 경우(scheduleEmergencyPersistThenDrop)
        // 일반 디바운스 저장을 추가로 예약하지 않음 (레이스 및 중복 drop 방지)
        if (emergencyPersistState.has(pageId)) return;

        const needsResync = (resyncNeeded === true || resyncNeeded === 1 || String(resyncNeeded || '').toLowerCase() === 'true');

        // 데이터 유실 방지: needsResync 스냅샷은 content는 저장하되 yjs_state는 강제로 NULL로 저장(forceClearYjsState)
        // 그리고 협업 세션을 리셋하여 다음 재접속 시 HTML 스냅샷으로 fragment를 재구성하도록 유도
        if (needsResync) {
            const epoch = bumpYjsSaveEpoch(pageId);
            try {
                await enqueueYjsDbSave(pageId, () =>
                    saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, docMeta.ydoc, { epoch, forceClearYjsState: true })
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

/**
 * 데이터 유실 방지: 클라이언트가 즉시 DB 저장을 요청 (Ctrl+S / 모드 전환 등)
 * - 권한 재검증 후 saveYjsDocToDatabase 즉시 실행
 * - 저장 완료 후 'page-saved' ACK 전송
 */
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
        await enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, { epoch }));
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

    // ACK 전송 (클라이언트 UI 갱신용)
    ws.send(JSON.stringify({
        event: 'page-saved',
        data: { pageId: String(pageId), updatedAt: new Date().toISOString() }
    }));
}

/**
 * 보안: 페이지 구독을 즉시 취소하고 클라이언트에 통지
 */
function revokePageSubscription(ws, pageId, conns, myConn, reason = 'Access revoked') {
    try {
        const pid = String(pageId || '');
        if (conns && myConn) {
            conns.delete(myConn);
            // stale leader 정리(권한회수/정책변경)
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

/**
 * 보안: 메시지 수신 시점에 페이지 가시성 + 암호화 상태 + 저장소 권한을 재검증
 * - 구독 이후 정책이 바뀌어도 즉시 반영 (Complete Mediation)
 */
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

    // 구독 이후 storageId가 변경됐을 수 있으므로 최신화
    myConn.storageId = page.storage_id;

    // 저장소 권한 재검증
    // - 쓰기 경로(yjs-update)는 캐시를 우회해 즉시 반영(권한 하향/회수 레이스 방지)
    const freshPerm = await refreshConnPermission(pool, myConn, {
        force: Boolean(opts.forcePermissionRefresh)
    });
    if (!freshPerm)
        return { ok: false, reason: 'storage-access-revoked' };

    // 암호화 페이지: E2EE 모드로 구독된 연결만 허용 (저장소 암호화), 그 외는 차단
    if (Number(page.is_encrypted) === 1) {
        if (!myConn.isE2ee)
            return { ok: false, reason: 'encrypted-page-no-realtime' };
    }

    return { ok: true, permission: freshPerm, page };
}

// 보안(방어-in-depth): Yjs metadata 의 parentId 도 객체 단위 권한 + 저장소 일치 검증
// - REST 경로 검증만으로는 직접 WebSocket/Yjs 업데이트 조작을 막을 수 없음
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

        // 권한 확인 (EDIT 또는 ADMIN)
        const conns = wsConnections.pages.get(pageId);
        const myConn = Array.from(conns).find(c => c.ws === ws);
        if (!myConn) return;

        // 보안: 메시지 단위로 페이지 가시성 + 암호화 상태 + 저장소 권한 재검증
        // - 구독 이후 페이지가 암호화/비공개로 전환되어도 즉시 차단 (Complete Mediation)
        // - 쓰기 경로(yjs-update)는 캐시를 우회해 즉시 반영(권한 하향/회수 레이스 방지)
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
                try { await enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc)); } catch (_) {}
                wsCloseConnectionsForPage(pageId, 1009, 'Document too large - collaboration reset');
                return;
            }
        }

        // 보안: 본 문서 적용/브로드캐스트 전에 복제본에 먼저 적용하여 서버측 의미론 검증 수행
        // (클라이언트 검증 우회 + 단순 문자열 필터 우회 방지)
        try {
            const probe = cloneYDocForValidation(ydoc);
            Y.applyUpdate(probe, updateBuf);

            const sem = validateRealtimeYjsCandidate(probe, sanitizeHtmlContent);
            if (!sem.ok) {
                try { ws.close(sem.code || 1008, sem.reason || 'Rejected invalid update'); } catch (_) {}
                return;
            }
        } catch (_) {
            // malformed / pathological update 등
            try { ws.close(1008, 'Malformed Yjs update'); } catch (_) {}
            return;
        }

        // 검증 통과 후에만 실제 문서에 적용
        Y.applyUpdate(ydoc, updateBuf);
        // approxBytes 갱신 (누적 추정 크기)
        if (doc) doc.approxBytes = (Number.isFinite(doc.approxBytes) ? doc.approxBytes : 0) + updateBuf.length;

        // 보안: 협업 metadata.parentId 에 대한 서버측 재검증 (BOLA 방어)
        try {
            const yMeta = ydoc.getMap('metadata');
            const requestedParentId = yMeta.get('parentId') ?? null;
            const parentCheck = await validateYjsParentAssignment(pool, pageSqlPolicy, {
                viewerUserId: ws.userId,
                pageId,
                pageStorageId: access.page.storage_id,
                candidateParentId: requestedParentId
            });
            if (!parentCheck.ok) {
                // 악성/비정상 parentId 는 저장되지 않도록 즉시 무효화
                yMeta.set('parentId', null);
                try { ws.close(1008, 'Invalid parent assignment'); } catch (_) {}
                return;
            }
            if ((requestedParentId || null) !== (parentCheck.parentId || null))
                yMeta.set('parentId', parentCheck.parentId);
        } catch (_) { return; }

        // 긴급 저장이 진행 중이면 실시간 업데이트 중단 (레이스 방지)
        if (emergencyPersistState.has(pageId)) return;

        wsBroadcastToPage(pageId, 'yjs-update', { update }, ws.userId);
        if (doc) {
            // (중요) 긴급 저장이 이미 예약된 경우(scheduleEmergencyPersistThenDrop)
            // 일반 디바운스 저장을 추가로 예약하지 않음 (레이스 및 중복 drop 방지)
            if (doc.saveTimeout || emergencyPersistState.has(pageId)) return;

            const epoch = getYjsSaveEpoch(pageId); // 현재 시점의 epoch 캡처
            doc.saveTimeout = setTimeout(() => {
                enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, { epoch }))
                    .catch(e => { console.error('[YJS] debounce save failed:', String(pageId), e?.message || e); });
            }, 1000);
        }
    } catch (e) {}
}

async function handleYjsState(ws, payload, pool, sanitizeHtmlContent, pageSqlPolicy) {
	const { pageId, state } = payload || {};
	try {
		if (!pageId || typeof state !== 'string' || !isSubscribedToPage(ws, pageId)) return;

		// 권한 확인 (EDIT 또는 ADMIN)
		const conns = wsConnections.pages.get(pageId);
		const myConn = Array.from(conns).find(c => c.ws === ws);
		if (!myConn) return;

		// 보안: 메시지 단위 재검증
		const access = await ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn, {
			forcePermissionRefresh: true
		});
		if (!access.ok) {
			revokePageSubscription(ws, pageId, conns, myConn, access.reason);
			return;
		}
		const freshPerm = access.permission;
		if (!['EDIT', 'ADMIN'].includes(freshPerm)) return;

		// DoS 방지: State 크기 제한
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

        // 보안: 협업 업데이트에 위험 URI 패턴이 포함되면 즉시 거부
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

		// DoS 방어: 적용 후 예상 크기 확인 (여기선 state 자체가 전체이므로 stateBuf 길이와 비슷하거나 큼)
		if (stateBuf.length > WS_MAX_DOC_EST_BYTES) {
			wsCloseConnectionsForPage(pageId, 1009, 'Document too large - collaboration reset');
			return;
		}

		// 보안: 복제본 검증 (Validation)
		try {
			// full-state는 applyUpdate 시 기존 상태와 병합됨.
			// 악성 상태가 섞여 들어오는지 확인하기 위해 probe에 적용
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

		// 검증 통과 -> 실제 적용
		Y.applyUpdate(ydoc, stateBuf);

		const doc = yjsDocuments.get(pageId);
		// approxBytes 갱신: full state 적용 후엔 정확한 크기 알기 어려우므로 encode해서 측정하거나,
		// 혹은 단순히 현재 크기에 더하는 건 부정확함.
		// 하지만 Yjs 특성상 히스토리가 쌓이므로, stateBuf 크기만큼 늘어난다고 가정(보수적 접근)
		if (doc) {
			const cur = Number.isFinite(doc.approxBytes) ? doc.approxBytes : 0;
			doc.approxBytes = Math.max(cur, stateBuf.length); // full state이므로 최소 이만큼은 됨
		}

        // 보안: parentId 검증
        try {
            const yMeta = ydoc.getMap('metadata');
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

		// 긴급 저장이 진행 중이면 실시간 업데이트 중단 (레이스 방지)
		if (emergencyPersistState.has(pageId)) return;

		// 다른 클라이언트에게 state 전송 (브로드캐스트)
		// yjs-state 이벤트로 보냄 -> 클라이언트는 이를 받아 applyUpdate
		wsBroadcastToPage(pageId, 'yjs-state', { state }, ws.userId);

		if (doc) {
			// (중요) 긴급 저장이 이미 예약된 경우(scheduleEmergencyPersistThenDrop)
			// 일반 디바운스 저장을 추가로 예약하지 않음 (레이스 및 중복 drop 방지)
			if (doc.saveTimeout || emergencyPersistState.has(pageId)) return;

			const epoch = getYjsSaveEpoch(pageId); // 현재 시점의 epoch 캡처
			doc.saveTimeout = setTimeout(() => {
				enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, { epoch }))
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

    // 보안: awareness도 메시지 단위 권한 재검증
    // - 권한 회수 후 커서/선택 영역 presence 정보 누출 차단 (CWE-285)
    try {
        const access = await ensureActivePageAccess(pool, pageSqlPolicy, pageId, myConn);
        if (!access.ok) {
            revokePageSubscription(ws, pageId, conns, myConn, access.reason);
            return;
        }
    } catch (_) {
        return;
    }

    // DoS 방지: awareness는 작아야 함(커서/선택 정보)
    if (awarenessUpdate.length > WS_MAX_AWARENESS_UPDATE_B64_CHARS) return;

    wsBroadcastToPage(pageId, 'awareness-update', { awarenessUpdate, fromUserId: ws.userId }, ws.userId);
}

function cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent) {
    // DoS 방지: 활성 연결 슬롯 해제 (중복 호출 대비 idempotent)
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
        // stale leader 정리
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
            // ===== 데이터 유실 방지: 구독 종료 시 타이머/상태 정리 =====
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

/**
 * REST API 등 외부에서 페이지 데이터가 직접 수정(PUT)될 때
 * 진행 중인 Yjs 저장 시퀀스를 즉시 무효화
 */
function invalidateYjsPersistenceForPage(pageId) {
    bumpYjsSaveEpoch(pageId);
}

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
                // 강제 퇴장 대상이 리더였으면 즉시 제거
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

    // 해당 사용자의 모든 WS를 끊어 재연결 유도
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
    wsKickUserFromStorage,
    extractFilesFromContent,
    invalidateYjsPersistenceForPage
};