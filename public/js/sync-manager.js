/**
 * WebSocket 및 Yjs 동기화 관리 모듈
 * 실시간 협업 편집을 위한 클라이언트 측 동기화 로직
 */

import * as Y from 'yjs';
import { sanitizeEditorHtml } from './sanitize.js';
import { Awareness, encodeAwarenessUpdate, applyAwarenessUpdate, removeAwarenessStates } from 'y-protocols/awareness.js';
import { ySyncPlugin, yCursorPlugin, yUndoPlugin, undo, redo, prosemirrorToYXmlFragment } from 'y-prosemirror';
import { keymap } from 'prosemirror-keymap';
import { DOMParser } from 'prosemirror-model';
import { escapeHtml, showErrorInEditor, syncPageUpdatedAtPadding } from './ui-utils.js';
import { showCover, hideCover } from './cover-manager.js';
import { renderPageList } from './pages-manager.js';

// 전역 상태
let ws = null;
let reconnectAttempts = 0;
let reconnectTimer = null;
let ydoc = null;
let yXmlFragment = null;
let yMetadata = null;
let currentPageId = null;
let currentStorageId = null;
let lastLocalUpdateTime = 0;
let updateTimeout = null;
let yjsPmPlugins = [];				// y-prosemirror(동시편집) 플러그인 추적/해제용
let yjsPmPluginKeys = new Set();	// y-prosemirror(동시편집) 플러그인 중복 확인용

// 네트워크 끊김/대용량 업데이트 등으로 인해 서버로 전송되지 못한 변경사항이 있으면
// 재연결 후 full-state(resync)를 수행해 데이터 유실 방지
// pageId -> boolean
const resyncNeededByPage = new Map();
let resyncDebounceTimer = null;

// 데이터 유실 방지: 즉시 저장(force-save) 요청에 대한 서버 ACK 대기 콜백
// pageId -> { resolve, timer }
const pendingForceSaves = new Map();

// E2EE (저장소 암호화) 동기화 상태
let isE2eeSync = false;				// 현재 페이지가 E2EE 모드인지 여부
let e2eeStatePushTimeout = null;	// 주기적 상태 스냅샷 서버 저장용 타이머
let e2eeStatePushPageId = null;	// 마지막으로 스냅샷 저장이 예약된 페이지 (E2EE)

// E2EE 스냅샷 저장 디바운스(ms)
// - 값이 클수록 DB/CPU 부하는 줄지만, 탭 종료/새로고침 직전 변경분 유실 가능성이 커짐
// - 기본값은 데이터 유실 위험을 낮추기 위해 800ms로 설정
const E2EE_STATE_PUSH_DEBOUNCE_MS = (() => {
	const v = Number.parseInt(window?.__NTEOK_E2EE_SNAPSHOT_DEBOUNCE_MS || '800', 10);
	return Number.isFinite(v) ? Math.max(200, Math.min(5000, v)) : 800;
})();

// 커서 공유 상태
// 서버와 동일한 상한(기본값). 운영에서 서버(.env) 값 변경 시 함께 맞추는 것을 권장
const WS_MAX_YJS_UPDATE_BYTES = 512 * 1024;        // 512KB
const WS_MAX_AWARENESS_UPDATE_BYTES = 32 * 1024;   // 32KB

// 서버 기본값(WS_MAX_YJS_STATE_BYTES)과 맞춰야 함
const WS_MAX_YJS_STATE_BYTES = 1024 * 1024;        // 1MB

const cursorState = {
    awareness: null,			// Awareness 인스턴스
    remoteCursors: new Map(),	// clientId -> DOM element
    localClientId: null,		// 로컬 클라이언트 ID
    throttleTimer: null,		// Throttle 타이머
    lastSentPosition: null,		// 마지막 전송 위치 (중복 방지)
	localUserId: null,			// 로컬 사용자 ID
	// 커서 추적(이벤트 리스너) 중복 설치 방지/정리용
    trackingEditor: null,
    selectionUpdateHandler: null,
    blurHandler: null
};

const state = {
    editor: null,
    currentPageId: null,
    currentStorageId: null,
    fetchPageList: null,
    pages: []
};

// ------------------------------
// base64 helpers (large update 안전)
// ------------------------------
function uint8ToBase64(update) {
	const u8 = update instanceof Uint8Array ? update : new Uint8Array(update);
	let s = '';
	const chunk = 0x8000;
	for (let i = 0; i < u8.length; i += chunk)
		s += String.fromCharCode(...u8.subarray(i, i + chunk));
	return btoa(s);
}

function base64ToUint8(b64) {
	const bin = atob(b64);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++)
		out[i] = bin.charCodeAt(i);
	return out;
}

function markResyncNeeded(pageId) {
	if (!pageId) return;
	resyncNeededByPage.set(String(pageId), true);
}

function clearResyncNeeded(pageId) {
	if (!pageId) return;
	resyncNeededByPage.delete(String(pageId));
}

function isResyncNeeded(pageId) {
	if (!pageId) return false;
	return resyncNeededByPage.get(String(pageId)) === true;
}

function scheduleResync(pageId, delayMs = 350) {
	markResyncNeeded(pageId);
	if (resyncDebounceTimer) clearTimeout(resyncDebounceTimer);
	resyncDebounceTimer = setTimeout(() => {
		if (ws && ws.readyState === WebSocket.OPEN && ydoc && String(currentPageId) === String(pageId)) {
			sendYjsState(pageId);
		}
	}, delayMs);
}

function sendYjsState(pageId) {
	if (!pageId || !ydoc) return false;
	if (!ws || ws.readyState !== WebSocket.OPEN) return false;

	try {
		const stateUpdate = Y.encodeStateAsUpdate(ydoc);
		if (stateUpdate && (stateUpdate.byteLength || stateUpdate.length) && (stateUpdate.byteLength || stateUpdate.length) > WS_MAX_YJS_STATE_BYTES) {
			console.warn('[WS] yjs-state too large; cannot resync');
			showInfo('문서가 너무 커서 전체 상태 동기화를 할 수 없습니다. (문서/첨부를 줄이거나 새 페이지로 분리해 주세요)');
			return false;
		}

		ws.send(JSON.stringify({
			type: 'yjs-state',
			payload: {
				pageId,
				state: uint8ToBase64(stateUpdate)
			}
		}));

		clearResyncNeeded(pageId);
		return true;
	} catch (e) {
		console.error('[WS] yjs-state 전송 실패:', e);
		markResyncNeeded(pageId);
		return false;
	}
}


export function onLocalEditModeChanged(isWriteMode) {
	// 원격 커서 DOM 정리(내가 쓰기모드면 숨김 정책)
	if (isWriteMode) {
		cursorState.remoteCursors.forEach(el => el.remove());
		cursorState.remoteCursors.clear();
	}
}

export function updateAwarenessMode(isWrite) {
	if (!cursorState.awareness) return;

	cursorState.awareness.setLocalStateField('mode', isWrite ? 'write' : 'read');
	cursorState.awareness.setLocalStateField('modeSince', Date.now());
}

function getPrimaryWriterClientId() {
	let primary = null;
	let best = Infinity;

	cursorState.awareness.getStates().forEach((st, cid) => {
		if (!st || st.mode !== 'write') return;
		const since = typeof st.modeSince === 'number' ? st.modeSince : Infinity;
		if (since < best || (since === best && (primary == null || cid < primary))) {
		    best = since;
		    primary = cid;
		}
	});

	return primary;
}

/**
 * 초기화
 */
export function initSyncManager(appState) {
    Object.assign(state, appState);

    // 네트워크 상태 감지
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    // Visibility API로 탭 전환 감지
    document.addEventListener('visibilitychange', handleVisibilityChange);

    // 데이터 유실 방지: 탭 종료/브라우저 닫기 직전 미반영 변경분을 서버에 best-effort로 전달
    window.addEventListener('pagehide', () => {
        if (!state.currentPageId) return;

        if (isE2eeSync) {
            // E2EE는 pagehide/beforeunload에서 async가 보장되지 않으므로 best-effort로 즉시 스냅샷 저장을 시작
            flushE2eeStateBestEffort(state.currentPageId, 'pagehide');
            try { sendForceSaveE2ee(state.currentPageId); } catch (_) {}
            return;
        }

        flushPendingUpdates();
        sendPageSnapshotNow(state.currentPageId);
        // waitForAck=false: 비동기 ACK 대기는 언로드 중 불가능
        if (ws && ws.readyState === WebSocket.OPEN) {
            try {
                ws.send(JSON.stringify({ type: 'force-save', payload: { pageId: state.currentPageId } }));
            } catch (_) {}
        }
    }, { capture: true });

    window.addEventListener('beforeunload', () => {
        if (!state.currentPageId) return;

        if (isE2eeSync) {
            flushE2eeStateBestEffort(state.currentPageId, 'beforeunload');
            try { sendForceSaveE2ee(state.currentPageId); } catch (_) {}
            return;
        }

        flushPendingUpdates();
        sendPageSnapshotNow(state.currentPageId);
    }, { capture: true });

    // WebSocket 연결
    connectWebSocket();
}

/**
 * WebSocket 연결
 */
function connectWebSocket() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    console.log('[WS] 연결 시도:', wsUrl);

    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
        console.log('[WS] 연결 성공');
        reconnectAttempts = 0;

        // 페이지 재구독
        if (currentPageId) {
            subscribePage(currentPageId);
        }

        // 저장소 재구독
        if (currentStorageId) {
            subscribeStorage(currentStorageId);
        }

        // 사용자 알림 구독
        subscribeUser();
    };

    ws.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
        } catch (error) {
            console.error('[WS] 메시지 파싱 오류:', error);
        }
    };

    ws.onerror = (error) => {
        console.error('[WS] 연결 오류:', error);
    };

    ws.onclose = () => {
        console.log('[WS] 연결 종료');
        ws = null;

        // 재연결 시도
        attemptReconnect();
    };
}

/**
 * WebSocket 재연결
 */
function attemptReconnect() {
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
    }

    reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000); // 최대 30초

    console.log(`[WS] ${delay}ms 후 재연결 시도 (${reconnectAttempts}번째)`);

    reconnectTimer = setTimeout(() => {
        connectWebSocket();
    }, delay);
}

/**
 * WebSocket 메시지 처리
 */
function handleWebSocketMessage(message) {
    const { event, data } = message;

    switch (event) {
        case 'connected':
            console.log('[WS] 서버 연결 확인:', data);
            break;
        case 'init':
            handleInit(data);
            break;
        case 'init-e2ee':
            // async 핸들러 — Promise rejection은 catch로 처리
            handleInitE2EE(data).catch(e => console.error('[E2EE] init 처리 오류:', e));
            break;
        case 'reconnected':
            console.log('[WS] 재연결 완료 - 기존 상태 유지');
            break;
        case 'yjs-update':
            handleYjsUpdate(data);
            break;
		case 'yjs-state':
			handleYjsState(data);
			break;
        case 'yjs-update-e2ee':
            handleYjsUpdateE2EEEvent(data).catch(e => console.error('[E2EE] update 처리 오류:', e));
            break;
        case 'user-joined':
            handleUserJoined(data);
            break;
        case 'user-left':
            handleUserLeft(data);
            break;
        case 'metadata-change':
            handleMetadataChange(data);
            break;
        case 'page-created':
            handlePageCreated(data);
            break;
        case 'page-deleted':
            handlePageDeleted(data);
            break;
        case 'duplicate-login':
            handleDuplicateLogin(data);
			break;
		case 'access-revoked':
            handleAccessRevoked(data);
            break;
        case 'awareness-update':
            handleRemoteAwarenessUpdate(data);
            break;
        case 'page-saved':
            handlePageSaved(data);
            break;
        case 'error':
            console.error('[WS] 서버 오류:', data.message);
            break;
        default:
            console.warn('[WS] 알 수 없는 이벤트:', event);
    }
}

/**
 * 페이지 동기화 시작
 * @param {string} pageId - 페이지 ID
 * @param {boolean} isPageEncrypted - 페이지 is_encrypted 플래그
 * @param {boolean} isStorageEncrypted - 페이지가 속한 저장소의 E2EE 여부
 */
export async function startPageSync(pageId, isPageEncrypted, isStorageEncrypted = false) {
    stopPageSync();

    if (isPageEncrypted) {
        if (isStorageEncrypted) {
            // 저장소 E2EE: 저장소 키가 메모리에 있는 경우만 허용
            const storageKey = window.cryptoManager.getStorageKey();
            if (!storageKey) {
                showInfo('저장소 키가 없어 실시간 협업을 시작할 수 없습니다. 저장소를 다시 열어주세요.');
                return;
            }
            isE2eeSync = true;
        } else {
            // 페이지 개별 암호화: 동기화 비활성화
            showInfo('암호화된 페이지는 실시간 협업이 지원되지 않습니다.');
            return;
        }
    }

    // 기존 연결 정리
    currentPageId = pageId;
    state.currentPageId = pageId;

    // Yjs 문서 생성
    ydoc = new Y.Doc();
    yXmlFragment = ydoc.getXmlFragment('prosemirror');
    yMetadata = ydoc.getMap('metadata');

    // Awareness 초기화
    cursorState.awareness = new Awareness(ydoc);
    cursorState.localClientId = ydoc.clientID;
	cursorState.awareness.on('change', (changes, origin) => handleAwarenessChange(changes, origin));

    // WebSocket으로 페이지 구독
    if (ws && ws.readyState === WebSocket.OPEN) {
        subscribePage(pageId);
    }

    // Yjs 변경 감지 → 서버 전송
    ydoc.on('update', (update, origin) => {
        // 로컬 변경사항만 서버로 전송 (remote는 제외)
        if (origin !== 'remote' && origin !== 'seed') {
            if (isE2eeSync) {
                sendYjsUpdateE2EE(pageId, update);
            } else {
                sendYjsUpdate(pageId, update);
            }
        }
    });
}

/**
 * 페이지 구독 (일반 또는 E2EE 모드)
 */
function subscribePage(pageId) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        console.warn('[WS] WebSocket이 연결되지 않았습니다.');
        return;
    }

    const type = isE2eeSync ? 'subscribe-page-e2ee' : 'subscribe-page';
    ws.send(JSON.stringify({
        type,
        payload: {
            pageId,
            isReconnect: false
        }
    }));
}

/**
 * 페이지 동기화 중지
 */
export function stopPageSync() {
    const pageIdToUnsubscribe = currentPageId;
    currentPageId = null;
    state.currentPageId = null;

    // E2EE 상태 정리
    isE2eeSync = false;
    if (e2eeStatePushTimeout) {
        clearTimeout(e2eeStatePushTimeout);
        e2eeStatePushTimeout = null;
    }

	detachYjsProsemirrorBinding();
	// setupEditorBindingWithXmlFragment에서 붙인 스냅샷 핸들러 정리
	if (state.editor && state.editor._snapshotHandler) {
		state.editor.off?.('update', state.editor._snapshotHandler);
		state.editor._snapshotHandler = null;
	}

	// 페이지를 떠나기 직전에 스냅샷(HTML)을 yMetadata에 강제 반영
	// - debounce 타이밍(1s) 때문에 최종 변경사항이 서버로 전달되지 않으면
	//   서버 DB content 스냅샷이 뒤처져 검색/백업/첨부 레지스트리 등에 영향
	try { flushPendingUpdates(); } catch (_) {}

	if (updateTimeout) {
		clearTimeout(updateTimeout);
		updateTimeout = null;
	}

	// 연결 끊김 중 편집(또는 대용량 변경)이 있었다면 unsubscribe 전에 full-state(resync) 1회 시도
	if (pageIdToUnsubscribe && isResyncNeeded(pageIdToUnsubscribe)) {
		sendYjsState(pageIdToUnsubscribe);
	}

    if (pageIdToUnsubscribe && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'unsubscribe-page',
            payload: { pageId: pageIdToUnsubscribe }
        }));
    }

    // 모든 원격 커서 제거
    cursorState.remoteCursors.forEach(element => element.remove());
    cursorState.remoteCursors.clear();

    // Awareness 정리
    if (cursorState.awareness) {
		cursorState.awareness.setLocalState(null);
        cursorState.awareness.destroy();
        cursorState.awareness = null;
    }

    // Throttle 타이머 정리
    if (cursorState.throttleTimer) {
        clearTimeout(cursorState.throttleTimer);
        cursorState.throttleTimer = null;
    }

    cursorState.lastSentPosition = null;

    if (ydoc) {
        ydoc.destroy();
        ydoc = null;
        yXmlFragment = null;
        yMetadata = null;
    }

    lastLocalUpdateTime = 0;
}

/**
 * 대기 중인 업데이트를 즉시 실행
 * 읽기 모드 전환 시 데이터 손실 방지
 */
export function flushPendingUpdates() {
    if (updateTimeout) {
        clearTimeout(updateTimeout);

        // 즉시 실행 (yMetadata만 업데이트, 에디터는 toggleEditMode에서 동기화)
        if (state.editor && yMetadata) {
            const newContent = state.editor.getHTML();
            const oldContent = yMetadata.get('content');

            if (newContent !== oldContent) {
                yMetadata.set('content', newContent);
            }
        }

        updateTimeout = null;
    }
}

/**
 * 데이터 유실 방지: 서버 force-save ACK 수신 처리
 */
function handlePageSaved(data) {
    const pageId = data?.pageId ? String(data.pageId) : null;
    if (!pageId) return;
    const pending = pendingForceSaves.get(pageId);
    if (pending) {
        clearTimeout(pending.timer);
        pendingForceSaves.delete(pageId);
        pending.resolve({ ok: true, updatedAt: data.updatedAt });
    }
}

/**
 * 데이터 유실 방지: 탭 종료/페이지 이탈 직전 HTML 스냅샷을 서버로 전송 (best-effort)
 * - E2EE 모드에서는 평문 HTML을 서버로 보내면 안 되므로 완전 차단
 */
function sendPageSnapshotNow(pageId) {
    if (isE2eeSync) return false;
    if (!pageId || !ws || ws.readyState !== WebSocket.OPEN) return false;
    if (!state.editor || !yMetadata) return false;

    const html = state.editor.getHTML();
    if (!html) return false;
    // 2MB 초과 시 서버가 어차피 거부하므로 전송하지 않음
    if (new Blob([html]).size > 2 * 1024 * 1024) return false;

    const titleInput = document.querySelector('#page-title-input');
    const title = titleInput ? titleInput.value : undefined;

    try {
        ws.send(JSON.stringify({
            type: 'page-snapshot',
            payload: { pageId, html, ...(title ? { title } : {}) }
        }));
        return true;
    } catch (_) {
        return false;
    }
}

/**
 * 데이터 유실 방지: 즉시 DB 저장 요청 (WS force-save)
 * - 비암호화 페이지의 Ctrl+S / 모드 전환 저장에 사용
 * - includeSnapshot=true 이면 snapshot을 먼저 전송해 최신 HTML이 반영되도록 함
 * - waitForAck=true 이면 'page-saved' 이벤트를 기다려 updatedAt을 반환 (최대 5초 타임아웃)
 */
export async function requestImmediateSave(pageId, { includeSnapshot = true, waitForAck = true } = {}) {
    if (!pageId || !ws || ws.readyState !== WebSocket.OPEN) return null;
    // E2EE 페이지는 snapshot 제외
    if (isE2eeSync) includeSnapshot = false;
    if (includeSnapshot) {
        flushPendingUpdates();
        sendPageSnapshotNow(pageId);
    }
    try {
        ws.send(JSON.stringify({ type: 'force-save', payload: { pageId } }));
    } catch (_) {
        return null;
    }
    if (!waitForAck) return { ok: true };
    return new Promise((resolve) => {
        const timer = setTimeout(() => {
            pendingForceSaves.delete(String(pageId));
            resolve(null);
        }, 5000);
        pendingForceSaves.set(String(pageId), { resolve, timer });
    });
}

/**
 * yMetadata에서 에디터로 콘텐츠 동기화
 * 읽기 모드 전환 시 호출
 */
export function syncEditorFromMetadata() {
    if (state.editor && yMetadata) {
        const content = yMetadata.get('content');
        if (content) {
            const currentContent = state.editor.getHTML();
            if (content !== currentContent) {
				state.editor._syncIsUpdating = true;
				try
				{
					state.editor.commands.setContent(sanitizeEditorHtml(content), { emitUpdate: false });
				}
				finally
				{
					state.editor._syncIsUpdating = false;
				}
            }
        }
    }
}

/**
 * Yjs 업데이트 서버 전송
 */
function sendYjsUpdate(pageId, update) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        markResyncNeeded(pageId);
        console.warn('[WS] WebSocket이 연결되지 않았습니다. (resync 필요)');
        return;
    }

    // 서버에서 거부될 수준의 큰 update는 클라이언트에서 선제 차단(협업 끊김/재연결 UX 완화)
    if (update && (update.byteLength || update.length) && (update.byteLength || update.length) > WS_MAX_YJS_UPDATE_BYTES) {
        console.warn('[WS] yjs-update too large; fallback to yjs-state');
        scheduleResync(pageId, 50);
        return;
    }

	const base64Update = uint8ToBase64(update);

    try {
        ws.send(JSON.stringify({
            type: 'yjs-update',
            payload: {
                pageId,
                update: base64Update
            }
        }));
    } catch (e) {
        console.error('[WS] yjs-update 전송 실패 (resync로 폴백):', e);
        scheduleResync(pageId, 100);
    }
}

/**
 * 초기 상태 처리
 */
function handleInit(data) {
    try {
        // Yjs 상태 복원
		const stateUpdate = base64ToUint8(data.state);
		// init update는 원격으로 취급해서 다시 서버로 브로드캐스트하지 않게 origin 지정
		Y.applyUpdate(ydoc, stateUpdate, 'remote');

		// 사용자 정보를 awareness에 설정
        if (cursorState.awareness && data.userId && data.username && data.color) {
       		// cursorState에 localUserId 저장
        	cursorState.localUserId = data.userId;

            cursorState.awareness.setLocalStateField('user', {
                userId: data.userId,
				username: data.username,
                name: data.username,
                color: data.color
            });
		}

        // 진짜 동시편집 바인딩 (Y.XmlFragment <-> ProseMirror)
        setupEditorBindingWithXmlFragment();

        if (isResyncNeeded(state.currentPageId)) {
            console.warn('[WS] resync 수행: offline/large update로 인해 누락된 변경사항 보정');
            setTimeout(() => {
                if (String(currentPageId) === String(state.currentPageId))
                    sendYjsState(state.currentPageId);
            }, 0);
        }

        console.log('[WS] 초기 상태 로드 완료');
    } catch (error) {
        console.error('[WS] 초기 상태 처리 오류:', error);
    }
}

/**
 * Yjs 업데이트 처리
 */
function handleYjsUpdate(data) {
	try {
		const update = base64ToUint8(data.update);

        // 원격 업데이트는 'remote' origin으로 표시
        // yMetadata.observe()가 자동으로 에디터를 업데이트함
        Y.applyUpdate(ydoc, update, 'remote');
    } catch (error) {
        console.error('[WS] Yjs 업데이트 처리 오류:', error);
    }
}

function handleYjsState(data) {
	try {
		if (!data || typeof data.state !== 'string') return;
		const stateUpdate = base64ToUint8(data.state);
		Y.applyUpdate(ydoc, stateUpdate, 'remote');
	} catch (error) {
		console.error('[WS] Yjs state 처리 오류:', error);
	}
}

/**
 * 사용자 입장 처리
 */
function handleUserJoined(data) {
    try {
        showUserNotification(`${data.username}님이 입장했습니다.`, data.color);

        // E2EE 모드: 새 참여자가 입장하면 현재 풀 스테이트를 update로 전송
        // → 새 참여자가 서버 스냅샷보다 최신 상태를 받을 수 있게 함
        if (isE2eeSync && currentPageId && ydoc) {
            sendYjsFullStateAsUpdate(currentPageId).catch(e =>
                console.error('[E2EE] 풀 스테이트 전송 오류:', e)
            );
        }
    } catch (error) {
        console.error('[WS] user-joined 처리 오류:', error);
    }
}

/**
 * 사용자 퇴장 처리
 */
function handleUserLeft(data) {
    try {
        if (!cursorState.awareness || !data?.userId) return;

        // 서버에서 user-left 이벤트가 오면, 해당 userId에 매핑된 모든 cid(=awareness clientId) 커서를 제거
        const removeClientIds = [];
        cursorState.awareness.getStates().forEach((st, cid) => {
            if (st?.user?.userId === data.userId)
                removeClientIds.push(cid);
        });

        if (removeClientIds.length > 0) {
            removeAwarenessStates(cursorState.awareness, removeClientIds, 'remote');
            // (옵션) 커스텀 DOM 커서가 켜져 있는 경우 대비
            removeClientIds.forEach(cid => {
                try { removeCursor(cid); } catch (e) {}
            });
        }
    } catch (error) {
        console.error('[WS] user-left 처리 오류:', error);
    }
}

/**
 * 저장소 메타데이터 동기화 시작
 */
export function startStorageSync(storageId) {
    stopStorageSync();

    currentStorageId = storageId;
    state.currentStorageId = storageId;

    if (ws && ws.readyState === WebSocket.OPEN) {
        subscribeStorage(storageId);
    }
}

/**
 * 저장소 구독
 */
function subscribeStorage(storageId) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        console.warn('[WS] WebSocket이 연결되지 않았습니다.');
        return;
    }

    ws.send(JSON.stringify({
        type: 'subscribe-storage',
        payload: { storageId }
    }));

    console.log('[WS] 저장소 구독:', storageId);
}

/**
 * 저장소 동기화 중지
 */
export function stopStorageSync() {
    if (currentStorageId && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'unsubscribe-storage',
            payload: { storageId: currentStorageId }
        }));
    }

    currentStorageId = null;
    state.currentStorageId = null;
}

/**
 * 사용자 알림 구독
 */
function subscribeUser() {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        return;
    }

    ws.send(JSON.stringify({
        type: 'subscribe-user',
        payload: {}
    }));

    console.log('[WS] 사용자 알림 구독');
}

/**
 * 메타데이터 변경 처리
 */
function handleMetadataChange(data) {
    try {
        // 로컬 상태(pages 배열) 업데이트
        if (state.pages) {
            const page = state.pages.find(p => p.id === data.pageId);
            if (page) {
                page[data.field] = data.value;
            }
        }

        // 현재 페이지의 메타데이터 변경인 경우 Yjs 메타데이터도 업데이트
        if (data.pageId === state.currentPageId && yMetadata) {
            // Yjs 메타데이터에서 지원하는 필드만 업데이트
            const supportedFields = ['title', 'icon', 'sortOrder', 'parentId'];
            if (supportedFields.includes(data.field)) {
                // 'remote' origin을 지정하여 이 변경사항이 다시 서버로 전송되지 않도록 함 (루프 방지)
                ydoc.transact(() => {
                    yMetadata.set(data.field, data.value);
                }, 'remote');
                console.log(`[Sync] Yjs 메타데이터 업데이트: ${data.field} = ${data.value}`);
            }
        }

        // 커버 이미지 동기화
        if (data.field === 'coverImage' && data.pageId === state.currentPageId) {
            if (data.value) {
                const page = state.pages.find(p => p.id === data.pageId);
                const pos = page ? (page.coverPosition || 50) : 50;
                showCover(data.value, pos);
            } else {
                hideCover();
            }
        }

        // 커버 위치 동기화
        if (data.field === 'coverPosition' && data.pageId === state.currentPageId) {
            const page = state.pages.find(p => p.id === data.pageId);
            if (page) page.coverPosition = data.value;
            
            const imageEl = document.getElementById('page-cover-image');
            if (imageEl) {
                imageEl.style.backgroundPositionY = `${data.value}%`;
            }
        }

        // 여백 동기화 (모바일에서는 기본 CSS 사용)
        if (data.field === 'horizontalPadding' && data.pageId === state.currentPageId) {
            const page = state.pages.find(p => p.id === data.pageId);
            if (page) page.horizontalPadding = data.value;

            const editorEl = document.querySelector('.editor');
            if (editorEl) {
                const isMobile = window.innerWidth <= 900;
                if (data.value === null || isMobile) {
                    editorEl.style.paddingLeft = '';
                    editorEl.style.paddingRight = '';
                } else {
                    editorEl.style.paddingLeft = `${data.value}px`;
                    editorEl.style.paddingRight = `${data.value}px`;
                }
            }

            syncPageUpdatedAtPadding();

            // 하위 페이지 섹션 여백도 동기화
            if (window.syncSubpagesPadding) {
                window.syncSubpagesPadding(data.value);
            }
        }

        // 사이드바 업데이트
        updatePageInSidebar(data.pageId, data.field, data.value);

        // 하위 페이지 메타데이터 변경 시 업데이트
        if (window.handleSubpageMetadataChange) {
            window.handleSubpageMetadataChange(data);
        }
    } catch (error) {
        console.error('[WS] metadata-change 처리 오류:', error);
    }
}

/**
 * 페이지 생성 처리
 */
function handlePageCreated(data) {
    try {
        // 페이지 목록 새로고침
        if (state.fetchPageList) {
            state.fetchPageList().then(() => {
                renderPageList();
            });
        }
    } catch (error) {
        console.error('[WS] page-created 처리 오류:', error);
    }
}

/**
 * 페이지 삭제 처리
 */
function handlePageDeleted(data) {
    try {
        const deletedPageId = data.pageId;

        // state.pages 배열에서 삭제된 페이지 제거
        if (state.pages) {
            const pageIndex = state.pages.findIndex(p => p.id === deletedPageId);
            if (pageIndex !== -1) {
                state.pages.splice(pageIndex, 1);
            }
        }

        // 현재 선택된 페이지가 삭제된 경우
        if (state.currentPageId === deletedPageId) {
            console.log('[WS] 현재 페이지가 삭제되었습니다:', deletedPageId);

            // 페이지 동기화 중지
            stopPageSync();

            // 에디터 내용 비우고 메시지 표시
            if (state.editor) {
                showErrorInEditor(
                    '이 페이지는 삭제되었습니다.',
                    state.editor
                );
            }

            // 현재 페이지 ID 초기화
            state.currentPageId = null;

            // 페이지 제목 초기화
            const titleInput = document.querySelector("#page-title-input");
            if (titleInput) {
                titleInput.value = '';
            }
        }

        // 페이지 목록 새로고침
        if (state.fetchPageList) {
            state.fetchPageList().then(() => {
                renderPageList();
            });
        }
    } catch (error) {
        console.error('[WS] page-deleted 처리 오류:', error);
    }
}

/**
 * 중복 로그인 처리
 */
function handleDuplicateLogin(data) {
    alert(data.message || '다른 위치에서 로그인하여 현재 세션이 종료됩니다.');
    window.location.href = '/login';
}

/**
 * 서버 측 권한 회수 알림
 * - 컬렉션 공유가 삭제되었거나 접근 권한이 회수된 경우
 * - 기존 WS 구독이 강제로 해제되며(서버), 클라이언트는 UI를 갱신
 */
function handleAccessRevoked(data) {
    try {
        const storageId = data?.storageId;
        const revokedPageIds = Array.isArray(data?.pageIds) ? data.pageIds : [];
        const message = data?.message || '접근 권한이 회수되었습니다.';

        // 현재 보고 있는 페이지가 영향권이면 즉시 동기화 종료 + 에러 표기
        if (state.currentPageId && revokedPageIds.includes(state.currentPageId)) {
            stopPageSync();
            if (state.editor)
                showErrorInEditor(message, state.editor);
            state.currentPageId = null;
        }

        // 현재 구독 중인 저장소가 권한 회수 대상이면 구독 종료
        if (storageId && state.currentStorageId === storageId) {
            stopStorageSync();
            state.currentStorageId = null;
        }

        showInfo(message);

        // 사이드바 목록 새로고침 (권한 변경 즉시 반영)
        if (state.fetchPageList) {
            state.fetchPageList().then(() => {
                renderPageList();
            });
        }
    } catch (error) {
        console.error('[WS] access-revoked 처리 오류:', error);
    }
}

/**
 * 보안: 사이드바 아이콘을 안전하게 생성 (innerHTML 금지)
 * - FontAwesome class: 허용 문자만 남기고 className으로 세팅
 * - Emoji/텍스트: textContent로만 삽입
 */
function createSafeSidebarIconElement(value) {
	if (!value) return null;
	const v = String(value);

	// FontAwesome 클래스처럼 보이면 className으로만 설정
	if (v.startsWith('fa-')) {
		const safeClass = v.replace(/[^a-zA-Z0-9 _-]/g, '').trim();
		if (!safeClass) return null;
		const i = document.createElement('i');
		i.className = safeClass;
		i.style.marginRight = "6px";
		i.style.color = "#2d5f5d";
		return i;
	}

	// Emoji/짧은 텍스트: textContent 사용
	const s = document.createElement('span');
	s.className = "page-icon";
	s.style.marginRight = "6px";
	s.style.fontSize = "16px";
	s.textContent = v;
	return s;
}

/**
 * titleSpan에서 아이콘을 제외한 텍스트만 안전하게 추출
 */
function getSidebarTitleText(titleSpan) {
	if (!titleSpan) return '';
	const texts = [];
	titleSpan.childNodes.forEach(n => {
		if (n.nodeType === Node.TEXT_NODE) texts.push(n.textContent || '');
	});
	return texts.join('').trim();
}

/**
 * 사이드바 페이지 정보 업데이트
 */
function updatePageInSidebar(pageId, field, value) {
    const pageElement = document.querySelector(`[data-page-id="${pageId}"]`);
    if (!pageElement) {
        return;
    }

    if (field === 'title') {
        const titleSpan = pageElement.querySelector('.page-list-item-title');
        if (titleSpan) {
        	// 기존 아이콘을 안전한 값(className/textContent)으로 재구성
            const existingIcon = titleSpan.querySelector('i, span.page-icon');
            let iconValue = null;
            if (existingIcon)
                iconValue = existingIcon.tagName === 'I' ? existingIcon.className : existingIcon.textContent;

            // 전체를 DOM API로 재구성 (innerHTML 금지)
            titleSpan.textContent = '';
            const iconEl = createSafeSidebarIconElement(iconValue);
            if (iconEl) titleSpan.appendChild(iconEl);
            titleSpan.appendChild(document.createTextNode(String(value ?? '')));
        }
    } else if (field === 'icon') {
        const titleSpan = pageElement.querySelector('.page-list-item-title');
        if (titleSpan) {
        	const titleText = getSidebarTitleText(titleSpan);

            // 전체를 DOM API로 재구성 (innerHTML 금지)
            titleSpan.textContent = '';
            const iconEl = createSafeSidebarIconElement(value);
            if (iconEl) titleSpan.appendChild(iconEl);
            titleSpan.appendChild(document.createTextNode(titleText));
        }
    }
}

/**
 * 사용자 알림 표시
 */
function showUserNotification(message, color) {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${color};
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 10000;
        animation: slideIn 0.3s ease-out;
        font-size: 14px;
        font-weight: 500;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

/**
 * 정보 메시지 표시
 */
function showInfo(message) {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4ECDC4;
        color: white;
        padding: 12px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 10000;
        font-size: 14px;
        font-weight: 500;
    `;
    notification.textContent = message;
    document.body.appendChild(notification);

    setTimeout(() => notification.remove(), 5000);
}

/**
 * 온라인 복구 핸들러
 */
function handleOnline() {
    showInfo('네트워크 연결이 복구되었습니다.');

    // WebSocket 재연결
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        connectWebSocket();
    }
}

/**
 * 오프라인 핸들러
 */
function handleOffline() {
    showInfo('네트워크 연결이 끊어졌습니다. 로컬 변경사항은 보존됩니다.');
}

/**
 * Visibility 변경 핸들러
 */
function handleVisibilityChange() {
    if (document.hidden) {
        // 탭이 숨겨질 때 (모바일 앱 전환 등) 즉시 저장 시도
        if (state.currentPageId) {
            if (isE2eeSync) {
                flushE2eeStateBestEffort(state.currentPageId, 'hidden');
                try { sendForceSaveE2ee(state.currentPageId); } catch (_) {}
            } else {
                flushPendingUpdates();
                sendPageSnapshotNow(state.currentPageId);
            }
        }
    } else {
        // WebSocket 연결 확인 및 재연결
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            connectWebSocket();
        }
    }
}

function detachYjsProsemirrorBinding() {
	if (!state.editor || !state.editor.view) return;
	const view = state.editor.view;

	// yjsPmPluginKeys에 기록된 key를 가진 플러그인들을 전부 제거
	if (yjsPmPluginKeys.size > 0) {
		const plugins = view.state.plugins.filter(p => !yjsPmPluginKeys.has(p.key));
		view.updateState(view.state.reconfigure({ plugins }));
	} else if (yjsPmPlugins?.length) {
		// (예비) 예전 방식(인스턴스) 제거
		const plugins = view.state.plugins.filter(p => !yjsPmPlugins.includes(p));
		view.updateState(view.state.reconfigure({ plugins }));
	}

	yjsPmPlugins = [];
	yjsPmPluginKeys.clear();
}

function buildCursorDOM(user) {
	const cursor = document.createElement('span');
	cursor.classList.add('ProseMirror-yjs-cursor');
	cursor.style.borderLeftColor = user?.color || '#999';

	const label = document.createElement('div');
	label.classList.add('ProseMirror-yjs-cursor-label');
	label.style.backgroundColor = user?.color || '#999';
	label.textContent = user?.name || user?.username || 'User';
	cursor.appendChild(label);
	return cursor;
}

function attachYjsProsemirrorBinding() {
	if (!state.editor?.view) return;
  	const view = state.editor.view;

   	// 새 협업 플러그인 생성
    const syncPlugin = ySyncPlugin(yXmlFragment);
    const cursorPlugin = yCursorPlugin(cursorState.awareness, { cursorBuilder: buildCursorDOM });
    const undoPlugin = yUndoPlugin();
    const keymapPlugin = keymap({ 'Mod-z': undo, 'Mod-y': redo, 'Mod-Shift-z': redo });

	const collabPlugins = [syncPlugin, cursorPlugin, undoPlugin, keymapPlugin];
	yjsPmPlugins = collabPlugins;

	// 키 기록 (keymapPlugin은 보통 고유키라 중복문제 없지만, 기록해도 무방)
	collabPlugins.forEach(p => {
		if (p?.key)
			yjsPmPluginKeys.add(p.key);
	});

	// 기존 플러그인 중에서 yjs 키를 가진 것들은 제거하고 다시 붙인다 (중복 방지)
	const basePlugins = view.state.plugins.filter(p => !yjsPmPluginKeys.has(p.key));

	view.updateState(
		view.state.reconfigure({
		    plugins: [...collabPlugins, ...basePlugins], // collab을 앞에
		})
	);
}

function seedYjsFromCurrentEditorHtmlIfNeeded() {
	const alreadySeeded = yMetadata.get('seeded') === true;
	const fragmentEmpty = (typeof yXmlFragment.length === 'number') ? (yXmlFragment.length === 0) : false;
	if (alreadySeeded && !fragmentEmpty) return;

	const html = state.editor.getHTML() || '<p></p>';
	const div = document.createElement('div');
	div.innerHTML = html;
	const pmDoc = DOMParser.fromSchema(state.editor.schema).parse(div);

	ydoc.transact(() => {
		try { yXmlFragment.delete(0, yXmlFragment.length); } catch (_) {}
		prosemirrorToYXmlFragment(pmDoc, yXmlFragment);
		yMetadata.set('seeded', true);
		yMetadata.set('content', html);
	}, 'seed');
}

function setupEditorBindingWithXmlFragment() {
	if (!state.editor || !ydoc) {
		console.error('[WS] 에디터 바인딩 실패: editor/ydoc 없음');
		return;
	}

	const editor = state.editor;
	const view = editor.view;
	const schema = view.state.schema;

	// 공유 문서(진짜 협업 데이터)
	yXmlFragment = ydoc.getXmlFragment('prosemirror');
	yMetadata = ydoc.getMap('metadata'); // (옵션) 저장용 스냅샷/메타데이터

	// Yjs <-> ProseMirror 동시편집 플러그인 부착
	attachYjsProsemirrorBinding();

	// 만약 서버/DB에서 HTML만 있고 fragment가 비어있다면, 최초 1회만 HTML을 fragment로 주입
	const htmlSnapshot = yMetadata.get('content');
	const fragEmpty = (yXmlFragment.toJSON?.() ?? []).length === 0;
	if (fragEmpty && typeof htmlSnapshot === 'string' && htmlSnapshot.trim())
		editor.commands.setContent(sanitizeEditorHtml(htmlSnapshot), { emitUpdate: true });

	// 저장용 스냅샷(HTML)만 yMetadata에 유지 (서버 저장 로직 호환)
	editor.off?.('update', editor._snapshotHandler);
	editor._snapshotHandler = ({ editor, transaction }) => {
		// Yjs 동기화로 인한 업데이트(원격 변경사항 반영)인 경우 스냅샷 업데이트 건너뜀
		// 이를 통해 무한 루프나 불필요한 네트워크 트래픽, Yjs 내부 오류(Unexpected case) 방지
		if (editor._syncIsUpdating || (transaction && (transaction.getMeta('y-sync$') || transaction.getMeta('y-prosemirror-sync')))) {
			return;
		}

		clearTimeout(updateTimeout);
		updateTimeout = setTimeout(() => {
		    try {
			    const html = editor.getHTML();
				if (yMetadata && yMetadata.get('content') !== html)
					yMetadata.set('content', html);
		    } catch {}
		}, 1000);
	};
	editor.on('update', editor._snapshotHandler);

	console.log('[WS] yXmlFragment 기반 동시편집 바인딩 완료');
}

/**
 * Awareness 변경 감지 핸들러
 */
function handleAwarenessChange({ added, updated, removed }, origin) {
	// yCursorPlugin이 커서 렌더링을 ProseMirror decoration으로 처리하므로
	// 여기서는 네트워크 전송만 담당한다.
	if (origin !== 'remote') {
	    const update = encodeAwarenessUpdate(cursorState.awareness, [
		    ...added, ...updated, ...removed,
	    ]);
	    sendAwarenessUpdate(update);
	}
}

/**
 * Awareness 업데이트 서버 전송
 */
function sendAwarenessUpdate(update) {
    if (!currentPageId || !ws || ws.readyState !== WebSocket.OPEN) return;

    // awareness는 커서/선택 정보이므로 크기가 커지면 무시(협업 자체는 유지)
    if (update && (update.byteLength || update.length) && (update.byteLength || update.length) > WS_MAX_AWARENESS_UPDATE_BYTES)
        return;

	const base64Update = uint8ToBase64(update);

    ws.send(JSON.stringify({
        type: 'awareness-update',
        payload: {
            pageId: currentPageId,
            awarenessUpdate: base64Update
        }
    }));
}

/**
 * 중복 커서 확인 함수
 */
function dedupeAwarenessByUserId(userId) {
    if (!cursorState.awareness || !userId) return;

    const entries = [];
    cursorState.awareness.getStates().forEach((st, cid) => {
        if (st?.user?.userId === userId)
            entries.push([cid, st]);
    });

    if (entries.length <= 1) return;

    // lastUpdate가 가장 큰(가장 최근 움직인) cid 1개만 남김
    entries.sort((a, b) => ((b[1]?.cursor?.lastUpdate ?? 0) - (a[1]?.cursor?.lastUpdate ?? 0)));
    const removeClientIds = entries.slice(1).map(([cid]) => cid);

    removeAwarenessStates(cursorState.awareness, removeClientIds, 'remote');
    removeClientIds.forEach(cid => {
        try { removeCursor(cid); } catch (e) {}
    });
}

/**
 * 원격 Awareness 업데이트 처리
 */
function handleRemoteAwarenessUpdate(data) {
    if (!cursorState.awareness) return;
    try {
		const update = base64ToUint8(data.awarenessUpdate);
        applyAwarenessUpdate(cursorState.awareness, update, 'remote');

        // 같은 userId가 새로고침 등으로 여러 cid를 남기면, 가장 최신 커서(lastUpdate) 1개만 남긴다.
		if (data?.fromUserId)
		    dedupeAwarenessByUserId(data.fromUserId);
    } catch (error) {
        console.error('[WS] Awareness 업데이트 처리 오류:', error);
    }
}

/**
* 원격 커서를 올려둘 스크롤 컨테이너 반환
* - 이 프로젝트는 #editor 자체가 overflow-y: auto 인 스크롤 컨테이너임
* - body에 붙이면 #editor 스크롤과 분리되어 커서가 스크롤을 따라다니는 현상이 발생
*/
function getEditorScrollContainer() {
    return document.getElementById('editor') || state?.editor?.view?.dom;
}

/**
 * 커서 렌더링
 */
function renderCursor(clientId, awarenessState) {
    const { cursor, user } = awarenessState;
    if (!cursor || !user || !state.editor) return;

    // 기존 커서 요소 확인
	let cursorElement = cursorState.remoteCursors.get(clientId);

	const scrollContainer = getEditorScrollContainer();
	if (!scrollContainer) return;

	if (!cursorElement) {
        cursorElement = createCursorElement(user);
        cursorState.remoteCursors.set(clientId, cursorElement);
		scrollContainer.appendChild(cursorElement);
	} else if (cursorElement.parentElement !== scrollContainer) {
		scrollContainer.appendChild(cursorElement);
    }

    // ProseMirror position을 DOM coordinates로 변환
    try {
        const editorView = state.editor.view;
        const coords = editorView.coordsAtPos(cursor.head);
        updateCursorPosition(cursorElement, coords, user, scrollContainer);
    } catch (error) {
        console.warn('[Cursor] Position 변환 오류:', error);
        removeCursor(clientId);
    }
}

/**
 * 커서 DOM 요소 생성
 */
function createCursorElement(user) {
    const container = document.createElement('div');
    container.className = 'remote-cursor-container';

    // 커서 라인
    const cursor = document.createElement('div');
    cursor.className = 'remote-cursor';
    cursor.style.backgroundColor = user.color;

    // 사용자 이름 라벨
    const label = document.createElement('div');
    label.className = 'remote-cursor-label';
    label.style.backgroundColor = user.color;
    label.textContent = user.username;

    container.appendChild(cursor);
    container.appendChild(label);

    return container;
}

/**
 * 커서 위치 업데이트
 */
function updateCursorPosition(element, coords, user, scrollContainer) {
	const container = scrollContainer || getEditorScrollContainer();
	if (!container) return;

	if (getComputedStyle(container).position === 'static')
		container.style.position = 'relative';

	const containerRect = container.getBoundingClientRect();
	const left = (coords.left - containerRect.left) + container.scrollLeft;
	const top = (coords.top - containerRect.top) + container.scrollTop;

    element.style.position = 'absolute';
    element.style.left = `${left}px`;
    element.style.top = `${top}px`;
    element.style.height = `${coords.bottom - coords.top}px`;
    element.style.display = 'block';

    // 에디터 영역 벗어나면 숨김
    if (coords.top < containerRect.top || coords.top > containerRect.bottom)
        element.style.display = 'none';
}

/**
 * 커서 제거
 */
function removeCursor(clientId) {
    const element = cursorState.remoteCursors.get(clientId);
    if (element) {
        element.remove();
        cursorState.remoteCursors.delete(clientId);
    }
}

// ==================== E2EE (저장소 암호화) 실시간 협업 헬퍼 ====================

/**
 * Uint8Array/ArrayBuffer를 AES-GCM으로 암호화 (IV 앞에 붙임)
 */
async function encryptBytes(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plainBytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key,
        plainBytes
    );
    const combined = new Uint8Array(12 + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), 12);
    return combined;
}

/**
 * IV(앞 12바이트) + 암호문을 AES-GCM으로 복호화
 */
async function decryptBytes(combinedData, key) {
    const combined = combinedData instanceof Uint8Array ? combinedData : new Uint8Array(combinedData);
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key,
        ciphertext
    );
    return new Uint8Array(decrypted);
}

/**
 * E2EE 암호화 Yjs 증분 업데이트 전송
 */
async function sendYjsUpdateE2EE(pageId, update) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    const storageKey = window.cryptoManager.getStorageKey();
    if (!storageKey) {
        console.warn('[E2EE] 저장소 키 없음 — 업데이트 전송 불가');
        return;
    }

    if (update && (update.byteLength || update.length) > WS_MAX_YJS_UPDATE_BYTES) {
        console.warn('[E2EE] yjs-update-e2ee 크기 초과 — 클라이언트 차단');
        return;
    }

    try {
        const encrypted = await encryptBytes(update, storageKey);
        ws.send(JSON.stringify({
            type: 'yjs-update-e2ee',
            payload: { pageId, update: uint8ToBase64(encrypted) }
        }));

        // 편집 후 3초 디바운스 → 서버에 전체 상태 스냅샷 저장
        scheduleE2EEStatePush(pageId);
    } catch (e) {
        console.error('[E2EE] 업데이트 암호화 실패:', e);
    }
}

/**
 * E2EE 전체 상태 서버 저장 예약 (Debounce)
 * - 편집할 때마다 타이머를 리셋하여, 마지막 입력 후 지정된 시간(E2EE_STATE_PUSH_DEBOUNCE_MS) 뒤에만 저장 수행
 * - 서버는 이 스냅샷을 늦게 입장하는 참여자의 초기 상태로 사용
 */
function scheduleE2EEStatePush(pageId) {
    if (!pageId || !isE2eeSync) return;
    e2eeStatePushPageId = pageId;
    if (e2eeStatePushTimeout) clearTimeout(e2eeStatePushTimeout);
    e2eeStatePushTimeout = setTimeout(async () => {
        e2eeStatePushTimeout = null;
        e2eeStatePushPageId = null;
        await sendYjsStateE2EE(pageId);
    }, E2EE_STATE_PUSH_DEBOUNCE_MS);
}

/**
 * 대기 중인 E2EE 상태 저장을 즉시 실행 (동기 방식)
 * - Prosemirror detach 또는 탭 종료 직전에 호출
 */
export async function flushE2eeState() {
    if (e2eeStatePushTimeout) {
        clearTimeout(e2eeStatePushTimeout);
        e2eeStatePushTimeout = null;
    }
    const pageId = e2eeStatePushPageId || currentPageId;
    if (pageId && isE2eeSync) {
        e2eeStatePushPageId = null;
        await sendYjsStateE2EE(pageId);
    }
}

/**
 * E2EE 스냅샷 객체 생성 (암호화)
 */
async function buildE2eeSnapshot(pageId) {
    if (!ydoc || !pageId) return null;
    const storageKey = window.cryptoManager.getStorageKey();
    if (!storageKey) return null;

    try {
        const stateUpdate = Y.encodeStateAsUpdate(ydoc);
        const encryptedState = await encryptBytes(stateUpdate, storageKey);

        let encryptedHtml = null;
        if (state.editor) {
            const html = state.editor.getHTML();
            if (window.cryptoManager && typeof window.cryptoManager.encryptWithKey === 'function')
                encryptedHtml = await window.cryptoManager.encryptWithKey(html, storageKey);
        }

        return {
            pageId,
            encryptedState: uint8ToBase64(encryptedState),
            encryptedHtml
        };
    } catch (e) {
        console.error('[E2EE] 스냅샷 생성 실패:', e);
        return null;
    }
}

/**
 * E2EE 데이터 유실 방지: 언로드/숨김 시 async 대기 없이 즉시 전송 시도 (best-effort)
 */
async function flushE2eeStateBestEffort(pageId, context = '') {
    if (!pageId || !isE2eeSync || !ydoc) return;
    if (e2eeStatePushTimeout) {
        clearTimeout(e2eeStatePushTimeout);
        e2eeStatePushTimeout = null;
    }
    e2eeStatePushPageId = null;

    try {
        const snapshot = await buildE2eeSnapshot(pageId);
        if (snapshot) await sendYjsStateE2EE(pageId, snapshot);
    } catch (_) {}
}

/**
 * E2EE 데이터 유실 방지: 서버 측 디바운스(DB write) 즉시 플러시 요청
 */
function sendForceSaveE2ee(pageId) {
    if (!pageId || !ws || ws.readyState !== WebSocket.OPEN) return;
    try {
        ws.send(JSON.stringify({ type: 'force-save-e2ee', payload: { pageId } }));
    } catch (_) {}
}

/**
 * E2EE 전체 Yjs 상태를 서버에 저장 (늦은 참여자 초기 상태 제공)
 */
async function sendYjsStateE2EE(pageId, prebuiltSnapshot = null) {
    if (!ws || ws.readyState !== WebSocket.OPEN || !pageId) return;

    try {
        const snapshot = prebuiltSnapshot || await buildE2eeSnapshot(pageId);
        if (!snapshot) return;

        ws.send(JSON.stringify({
            type: 'yjs-state-e2ee',
            payload: snapshot
        }));
    } catch (e) {
        console.error('[E2EE] 상태 저장 전송 실패:', e);
    }
}

/**
 * E2EE 전체 상태를 update로 브로드캐스트 (새 참여자 실시간 동기화용)
 * - user-joined 이벤트 수신 시 기존 참여자가 최신 상태를 전달
 */
async function sendYjsFullStateAsUpdate(pageId) {
    if (!ws || ws.readyState !== WebSocket.OPEN || !ydoc || !pageId) return;

    const storageKey = window.cryptoManager.getStorageKey();
    if (!storageKey) return;

    try {
        const stateUpdate = Y.encodeStateAsUpdate(ydoc);
        const encrypted = await encryptBytes(stateUpdate, storageKey);
        ws.send(JSON.stringify({
            type: 'yjs-update-e2ee',
            payload: { pageId, update: uint8ToBase64(encrypted) }
        }));
        console.log('[E2EE] 풀 스테이트를 새 참여자에게 전달');
    } catch (e) {
        console.error('[E2EE] 풀 스테이트 전달 실패:', e);
    }
}

/**
 * E2EE init 이벤트 처리
 * - 서버에서 암호화 상태(스냅샷)를 받아 복호화 후 Yjs 문서에 적용
 * - 스냅샷이 없으면 현재 에디터 HTML로 Yjs 문서 초기화
 */
async function handleInitE2EE(data) {
    try {
        if (data.encryptedState) {
            const storageKey = window.cryptoManager.getStorageKey();
            if (!storageKey) {
                console.warn('[E2EE] 저장소 키 없음 — init 상태 복호화 불가');
            } else {
                const combined = base64ToUint8(data.encryptedState);
                const stateUpdate = await decryptBytes(combined, storageKey);
                Y.applyUpdate(ydoc, stateUpdate, 'remote');
                console.log('[E2EE] 서버 스냅샷 복호화 및 적용 완료');
            }
        }

        // 서버 스냅샷이 없거나 fragment가 비어있으면 현재 에디터 HTML로 시드
        seedYjsFromCurrentEditorHtmlIfNeeded();

        // 사용자 정보 awareness 설정
        if (cursorState.awareness && data.userId && data.username && data.color) {
            cursorState.localUserId = data.userId;
            cursorState.awareness.setLocalStateField('user', {
                userId: data.userId,
                username: data.username,
                name: data.username,
                color: data.color
            });
        }

        // Yjs <-> ProseMirror 바인딩
        setupEditorBindingWithXmlFragment();

        // 서버에 현재 상태 스냅샷 저장 (늦은 참여자를 위한 초기 상태)
        await sendYjsStateE2EE(currentPageId);

        console.log('[E2EE] 초기화 완료');
    } catch (error) {
        console.error('[E2EE] init 처리 오류:', error);
        // 오류 시에도 바인딩은 시도
        try { seedYjsFromCurrentEditorHtmlIfNeeded(); } catch (_) {}
        setupEditorBindingWithXmlFragment();
    }
}

/**
 * E2EE 암호화 Yjs 업데이트 수신 처리
 */
async function handleYjsUpdateE2EEEvent(data) {
    try {
        if (!ydoc) return;
        const storageKey = window.cryptoManager.getStorageKey();
        if (!storageKey) {
            console.warn('[E2EE] 저장소 키 없음 — 업데이트 복호화 불가');
            return;
        }
        const combined = base64ToUint8(data.update);
        const stateUpdate = await decryptBytes(combined, storageKey);
        Y.applyUpdate(ydoc, stateUpdate, 'remote');
    } catch (error) {
        console.error('[E2EE] 업데이트 복호화/적용 오류:', error);
    }
}
