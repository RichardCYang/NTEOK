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
    yjsSaveEpoch.set(pid, current + 1);
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

const USER_COLORS = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B195', '#C06C84'];
const wsConnectionLimiter = new Map();
const WS_RATE_LIMIT_WINDOW = 60 * 1000;
const WS_RATE_LIMIT_MAX_CONNECTIONS = 10;
const WS_MAX_MESSAGE_BYTES = 2 * 1024 * 1024;
const WS_MAX_AWARENESS_UPDATE_BYTES = 32 * 1024;

// ==================== E2EE Leader Election & Persistence Helpers ====================
const E2EE_LEADER_IDLE_HANDOFF_MS = (() => {
    const n = Number.parseInt(process.env.E2EE_LEADER_IDLE_HANDOFF_MS || '2000', 10);
    if (!Number.isFinite(n)) return 2000;
    return Math.max(500, Math.min(60_000, n));
})();

// E2EE 리더 선출/핸드오프 정책
// - 기존 설계는 1명의 리더만 yjs-state-e2ee(전체 스냅샷)를 DB에 저장할 수 있음
// - 하지만 리더가 편집을 하지 않고 접속만 유지하는 동안, 다른 편집자의 스냅샷 저장이 거부되어
//   최신 암호화 상태가 DB에 남지 않는(=데이터 유실) 문제가 발생할 수 있음
// - 해결:
//     (1) 리더가 일정 시간 이상 비활성일 때, 활성 편집자에게 리더를 자동 핸드오프
//     (2) disconnect/권한회수 시 stale leader 즉시 제거

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
 * E2EE 스냅샷(암호문) DB 저장 (디바운스/버퍼)
 * - Yjs 증분 업데이트가 올 때마다 즉시 DB에 쓰는 것은 비효율적이므로, 1.5초간 대기 후 마지막 입력분만 저장
 * - 'yjsE2EEStates' 맵에 대기 중인 작업을 관리
 */
function scheduleE2EESave(pool, pageId, encryptedState, encryptedHtml) {
    let state = yjsE2EEStates.get(pageId);
    if (state && state.saveTimeout) {
        clearTimeout(state.saveTimeout);
    }
    
    const timeout = setTimeout(async () => {
        try {
            await saveE2EEStateToDatabase(pool, pageId, encryptedState, encryptedHtml);
            yjsE2EEStates.delete(pageId);
        } catch (error) {
            console.error(`[E2EE] 페이지 ${pageId} 상태 저장 실패:`, error);
        }
    }, 1500);

    yjsE2EEStates.set(pageId, {
        encryptedState,
        encryptedHtml,
        saveTimeout: timeout
    });
}

/**
 * 대기 중인 E2EE 저장 작업을 즉시 실행 (플러시)
 */
async function flushPendingE2eeSaveForPage(pool, pageId) {
    const state = yjsE2EEStates.get(pageId);
    if (state && state.saveTimeout) {
        clearTimeout(state.saveTimeout);
        state.saveTimeout = null;
        try {
            await saveE2EEStateToDatabase(pool, pageId, state.encryptedState, state.encryptedHtml);
        } catch (e) {
            console.error(`[E2EE] flushPendingE2eeSaveForPage(${pageId}) 실패:`, e);
        }
        yjsE2EEStates.delete(pageId);
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
async function saveE2EEStateToDatabase(pool, pageId, encryptedState, encryptedHtml) {
    if (!encryptedState) return;

    try {
        const updateTime = new Date().toISOString().slice(0, 19).replace('T', ' ');
        // E2EE 모드에서는 e2ee_yjs_state 컬럼을 사용하고, content는 암호화된 HTML(encryptedHtml)로 덮어씀
        // (암호화된 HTML은 서버 측에서 검색/미리보기는 불가능하지만, 백업 시 평문 유출을 막는 용도)
        await pool.execute(
            `UPDATE pages 
             SET e2ee_yjs_state = ?, 
                 e2ee_yjs_state_updated_at = ?,
                 encrypted_content = ?,
                 updated_at = ?
             WHERE id = ?`,
            [
                Buffer.from(encryptedState, 'base64'), 
                updateTime,
                encryptedHtml || null,
                updateTime,
                pageId
            ]
        );
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
    const conns = wsConnections.pages.get(pid);
    if (!conns || conns.size === 0) {
        if (yjsDocuments.has(pid)) dropYjsDocument(pid);
        return;
    }

    for (const c of Array.from(conns)) {
        try { c.ws.send(JSON.stringify({ event: 'collab-reset', data: { pageId: pid, reason } })); } catch (_) {}
        try { c.ws.close(code, reason); } catch (_) {}
    }

    wsConnections.pages.delete(pid);
    if (yjsDocuments.has(pid)) dropYjsDocument(pid);
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

        const epoch = getYjsSaveEpoch(pageId);

        // 중요:
        // - dropYjsDocument()가 epoch를 bump 하면, 방금 시작한 saveYjsDocToDatabase가
        //   DB UPDATE 직전(epoch 재확인)에서 스스로 취소되어 저장이 되지 않는 레이스가 발생할 수 있음
        // - 따라서 저장 성공(또는 epoch 스킵) 이후에 bumpEpoch=false로 정리
        // - 저장 실패 시에는 문서를 유지하여 다음 cleanup 주기에서 재시도(=데이터 유실 방지)
        saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, doc.ydoc, { epoch })
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

            // 보안(핵심): page_file_refs 레지스트리로 참조 여부 판단(암호화/지연/협업에도 안전)
            // - 기존 pages.content LIKE 방식은 암호화 페이지(content='')에서 참조 중인 파일을 오판 삭제함
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

async function saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, opts = {}) {
    try {
        const { epoch } = opts;
        // epoch 확인 (시작 시): 이미 더 새로운 REST 저장이 발생했다면 중단
        if (epoch !== undefined && getYjsSaveEpoch(pageId) > epoch) return { status: 'skipped-epoch' };

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

        // epoch 재확인 (DB UPDATE 직전): I/O 대기 중에 무효화되었을 수 있음
        if (epoch !== undefined && getYjsSaveEpoch(pageId) > epoch) return { status: 'skipped-epoch' };

        await pool.execute(
            `UPDATE pages SET title = ?, content = ?, icon = ?, sort_order = ?, parent_id = ?, yjs_state = ?, updated_at = NOW() WHERE id = ?`,
            [title, finalContent, icon, sortOrder, parentId, yjsStateToSave, pageId]
        );

        if (existingRows.length > 0 && existingRows[0].is_encrypted === 0) {
            const newFiles = extractFilesFromContent(content, pageOwnerUserId);

            // 보안: 정당 참조 레지스트리(page_file_refs) 동기화
            // - 실시간 편집 중 새로 추가된 첨부파일이나 이미지를 등록
            // - 페이지에서 제거된 파일은 이 페이지와의 매핑 정보를 레지스트리에서 제거
            try {
                // 신규 파일 등록 (INSERT IGNORE)
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

                // 이 페이지에서 더 이상 참조되지 않는 레지스트리 제거
                // 중요: pageOwnerUserId scope만 삭제해야 타 사용자 첨부 레지스트리를 건드리지 않음
                const currentPaperclipFiles = newFiles.filter(f => f.type === 'paperclip').map(f => f.ref.split('/')[1]);
                if (currentPaperclipFiles.length > 0) {
                    await pool.execute(
                        `DELETE FROM page_file_refs
                          WHERE page_id = ?
                            AND owner_user_id = ?
                            AND file_type = 'paperclip'
                            AND stored_filename NOT IN (${currentPaperclipFiles.map(() => '?').join(',')})`,
                        [pageId, pageOwnerUserId, ...currentPaperclipFiles]
                    );
                } else {
                    await pool.execute(
                        `DELETE FROM page_file_refs
                          WHERE page_id = ? AND owner_user_id = ? AND file_type = 'paperclip'`,
                        [pageId, pageOwnerUserId]
                    );
                }

                const currentImgsFiles = newFiles.filter(f => f.type === 'imgs').map(f => f.ref.split('/')[1]);
                if (currentImgsFiles.length > 0) {
                    await pool.execute(
                        `DELETE FROM page_file_refs
                          WHERE page_id = ?
                            AND owner_user_id = ?
                            AND file_type = 'imgs'
                            AND stored_filename NOT IN (${currentImgsFiles.map(() => '?').join(',')})`,
                        [pageId, pageOwnerUserId, ...currentImgsFiles]
                    );
                } else {
                    await pool.execute(
                        `DELETE FROM page_file_refs
                          WHERE page_id = ? AND owner_user_id = ? AND file_type = 'imgs'`,
                        [pageId, pageOwnerUserId]
                    );
                }
            } catch (regErr) {
                console.error('보안 레지스트리 동기화 실패 (비치명적):', regErr);
            }

            const deletedFiles = oldFiles.filter(f => !newFiles.some(nf => nf.ref === f.ref));
            if (deletedFiles.length > 0) cleanupOrphanedFiles(pool, deletedFiles, pageId, pageOwnerUserId).catch(e => {});
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
        ws.send(JSON.stringify({ event: 'init', data: { state: stateB64, userId, username: ws.username, color, permission } }));
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
        const doc = yjsDocuments.get(pid);
        if (doc) {
            const epoch = getYjsSaveEpoch(pid);
            saveYjsDocToDatabase(pool, sanitizeHtmlContent, pid, doc.ydoc, { epoch })
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
                if (encryptedState) yjsE2EEStates.set(String(pageId), { encryptedState, storedAt: Date.now() });
            } catch (_) {}
        }

        ws.send(JSON.stringify({
            event: 'init-e2ee',
            data: { encryptedState, userId, username: ws.username, color, permission }
        }));

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

        // 리더 활동 갱신
        touchE2eeLeader(pageId, myConn);

        // DB 영속화 (Debounced)
        scheduleE2EESave(pool, pageId, encryptedState, encryptedHtml);

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
    const { pageId, html, title } = payload || {};
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
        await saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc);
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
                try { await saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc); } catch (_) {}
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

        wsBroadcastToPage(pageId, 'yjs-update', { update }, ws.userId);
        if (doc) {
            if (doc.saveTimeout) clearTimeout(doc.saveTimeout);
            const epoch = getYjsSaveEpoch(pageId); // 현재 시점의 epoch 캡처
            doc.saveTimeout = setTimeout(() => {
                saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, { epoch })
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
		if (state.length > WS_MAX_YJS_STATE_B64_CHARS) throw new Error('State too large');
		const stateBuf = Buffer.from(state, 'base64');
		if (stateBuf.length > WS_MAX_YJS_STATE_BYTES) throw new Error('State too large');

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

		// 다른 클라이언트에게 state 전송 (브로드캐스트)
		// yjs-state 이벤트로 보냄 -> 클라이언트는 이를 받아 applyUpdate
		wsBroadcastToPage(pageId, 'yjs-state', { state }, ws.userId);

		if (doc) {
			if (doc.saveTimeout) clearTimeout(doc.saveTimeout);
            const epoch = getYjsSaveEpoch(pageId); // 현재 시점의 epoch 캡처
			doc.saveTimeout = setTimeout(() => {
				saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc, { epoch })
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
            const doc = yjsDocuments.get(pid);
            if (doc) {
                const epoch = getYjsSaveEpoch(pid);
                saveYjsDocToDatabase(pool, sanitizeHtmlContent, pid, doc.ydoc, { epoch })
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
    flushPendingE2eeSaveForPage,
    flushAllPendingE2eeSaves,
    wsCloseConnectionsForSession,
    wsCloseConnectionsForPage,
    wsKickUserFromStorage,
    extractFilesFromContent,
    invalidateYjsPersistenceForPage
};