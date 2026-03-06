
import * as Y from 'yjs';
import { sanitizeEditorHtml } from './sanitize.js';
import { Awareness, encodeAwarenessUpdate, applyAwarenessUpdate, removeAwarenessStates } from 'y-protocols/awareness.js';
import { ySyncPlugin, yCursorPlugin, yUndoPlugin, undo, redo, prosemirrorToYXmlFragment } from 'y-prosemirror';
import { keymap } from 'prosemirror-keymap';
import { DOMParser } from 'prosemirror-model';
import { escapeHtml, showErrorInEditor, syncPageUpdatedAtPadding } from './ui-utils.js';
import { showCover, hideCover } from './cover-manager.js';
import { renderPageList } from './pages-manager.js';

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
let yjsPmPlugins = [];				
let yjsPmPluginKeys = new Set();	

const resyncNeededByPage = new Map();
let resyncDebounceTimer = null;

const pendingForceSaves = new Map();

let isE2eeSync = false;				
let isE2eeWalSyncing = false;       
let e2eeWalUpdateBuffer = [];       
let e2eeStatePushTimeout = null;	
let e2eeStatePushPageId = null;	

const E2EE_STATE_PUSH_DEBOUNCE_MS = (() => {
	const v = Number.parseInt(window?.__NTEOK_E2EE_SNAPSHOT_DEBOUNCE_MS || '800', 10);
	return Number.isFinite(v) ? Math.max(200, Math.min(5000, v)) : 800;
})();

const WS_MAX_YJS_UPDATE_BYTES = 512 * 1024;        
const WS_MAX_AWARENESS_UPDATE_BYTES = 32 * 1024;   

const WS_MAX_YJS_STATE_BYTES = 1024 * 1024;        

const cursorState = {
    awareness: null,			
    remoteCursors: new Map(),	
    localClientId: null,		
    throttleTimer: null,		
    lastSentPosition: null,		
	localUserId: null,			
    trackingEditor: null,
    selectionUpdateHandler: null,
    blurHandler: null
};

const state = {
    editor: null,
    currentPageId: null,
    currentStorageId: null,
    currentPageUpdatedAt: null,
    fetchPageList: null,
    pages: []
};

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

export function initSyncManager(appState) {
    state.editor = appState.editor;
    state.fetchPageList = appState.fetchPageList;
    state.pages = appState.pages;

    Object.defineProperty(state, 'currentPageId', { get: () => appState.currentPageId });
    Object.defineProperty(state, 'currentStorageId', { get: () => appState.currentStorageId });
    Object.defineProperty(state, 'currentPageUpdatedAt', { get: () => appState.currentPageUpdatedAt });

    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    document.addEventListener('visibilitychange', handleVisibilityChange);

    window.addEventListener('pagehide', () => {
        if (!state.currentPageId) return;

        if (isE2eeSync) {
            flushE2eeStateBestEffort(state.currentPageId, 'pagehide');
            try { sendForceSaveE2ee(state.currentPageId); } catch (_) {}
            return;
        }

        flushPendingUpdates();

        if (isResyncNeeded(state.currentPageId)) {
            sendYjsState(state.currentPageId);
        }

        sendPageSnapshotNow(state.currentPageId);
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

        if (isResyncNeeded(state.currentPageId)) {
            sendYjsState(state.currentPageId);
        }

        sendPageSnapshotNow(state.currentPageId);
    }, { capture: true });

    connectWebSocket();
}

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

        if (currentPageId) {
            subscribePage(currentPageId);
        }

        if (currentStorageId) {
            subscribeStorage(currentStorageId);
        }

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

        attemptReconnect();
    };
}

function attemptReconnect() {
    if (reconnectTimer) {
        clearTimeout(reconnectTimer);
    }

    reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000); 

    console.log(`[WS] ${delay}ms 후 재연결 시도 (${reconnectAttempts}번째)`);

    reconnectTimer = setTimeout(() => {
        connectWebSocket();
    }, delay);
}

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
        case 'e2ee-pending-updates':
            handleE2eePendingUpdates(data).catch(e => console.error('[E2EE] WAL 복구 오류:', e));
            break;
        case 'request-yjs-state-e2ee':
            handleRequestYjsStateE2EE(data).catch(e => console.error('[E2EE] snapshot 요청 처리 오류:', e));
            break;
        case 'request-page-snapshot':
            handleRequestPageSnapshot(data).catch(e => console.error('[Self-heal] snapshot 요청 처리 오류:', e));
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

export async function startPageSync(pageId, isPageEncrypted, isStorageEncrypted = false) {
    stopPageSync();

    if (isPageEncrypted) {
        if (isStorageEncrypted) {
            const storageKey = window.cryptoManager.getStorageKey();
            if (!storageKey) {
                showInfo('저장소 키가 없어 실시간 협업을 시작할 수 없습니다. 저장소를 다시 열어주세요.');
                return;
            }
            isE2eeSync = true;
        } else {
            showInfo('암호화된 페이지는 실시간 협업이 지원되지 않습니다.');
            return;
        }
    }

    currentPageId = pageId;
    state.currentPageId = pageId;

    ydoc = new Y.Doc();
    yXmlFragment = ydoc.getXmlFragment('prosemirror');
    yMetadata = ydoc.getMap('metadata');

    cursorState.awareness = new Awareness(ydoc);
    cursorState.localClientId = ydoc.clientID;
	cursorState.awareness.on('change', (changes, origin) => handleAwarenessChange(changes, origin));

    if (ws && ws.readyState === WebSocket.OPEN) {
        subscribePage(pageId);
    }

    ydoc.on('update', (update, origin) => {
        if (origin !== 'remote' && origin !== 'seed') {
            if (isE2eeSync) {
                sendYjsUpdateE2EE(pageId, update);
            } else {
                sendYjsUpdate(pageId, update);
            }
        }
    });
}

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

export function stopPageSync() {
    const pageIdToUnsubscribe = currentPageId;
    currentPageId = null;
    state.currentPageId = null;

    isE2eeSync = false;
    if (e2eeStatePushTimeout) {
        clearTimeout(e2eeStatePushTimeout);
        e2eeStatePushTimeout = null;
    }

	detachYjsProsemirrorBinding();
	if (state.editor && state.editor._snapshotHandler) {
		state.editor.off?.('update', state.editor._snapshotHandler);
		state.editor._snapshotHandler = null;
	}

	try { flushPendingUpdates(); } catch (_) {}

	if (updateTimeout) {
		clearTimeout(updateTimeout);
		updateTimeout = null;
	}

	if (pageIdToUnsubscribe && isResyncNeeded(pageIdToUnsubscribe)) {
		sendYjsState(pageIdToUnsubscribe);
	}

    if (pageIdToUnsubscribe && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'unsubscribe-page',
            payload: { pageId: pageIdToUnsubscribe }
        }));
    }

    cursorState.remoteCursors.forEach(element => element.remove());
    cursorState.remoteCursors.clear();

    if (cursorState.awareness) {
		cursorState.awareness.setLocalState(null);
        cursorState.awareness.destroy();
        cursorState.awareness = null;
    }

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

export function flushPendingUpdates() {
    if (updateTimeout) {
        clearTimeout(updateTimeout);

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

function sendPageSnapshotNow(pageId) {
    if (isE2eeSync) return false;
    if (!pageId || !ws || ws.readyState !== WebSocket.OPEN) return false;
    if (!state.editor || !yMetadata) return false;

    const html = state.editor.getHTML();
    if (!html) return false;
    if (new Blob([html]).size > 2 * 1024 * 1024) return false;

    const titleInput = document.querySelector('#page-title-input');
    const title = titleInput ? titleInput.value : undefined;

    const resyncNeeded = isResyncNeeded(pageId);

    try {
        ws.send(JSON.stringify({
            type: 'page-snapshot',
            payload: { pageId, html, resyncNeeded, ...(title ? { title } : {}) }
        }));
        return true;
    } catch (_) {
        return false;
    }
}

export async function requestImmediateSave(pageId, { includeSnapshot = true, waitForAck = true } = {}) {
    if (!pageId || !ws || ws.readyState !== WebSocket.OPEN) return null;
    try {
        if (isE2eeSync) {
            if (includeSnapshot) {
                await flushE2eeState();
            }
            ws.send(JSON.stringify({ type: 'force-save-e2ee', payload: { pageId } }));
        } else {
            if (includeSnapshot) {
                flushPendingUpdates();
                sendPageSnapshotNow(pageId);
            }
            ws.send(JSON.stringify({ type: 'force-save', payload: { pageId } }));
        }
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

function sendYjsUpdate(pageId, update) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        markResyncNeeded(pageId);
        console.warn('[WS] WebSocket이 연결되지 않았습니다. (resync 필요)');
        return;
    }

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

function handleInit(data) {
    try {
        const incomingPageId = data?.pageId ? String(data.pageId) : null;
        if (incomingPageId && typeof currentPageId !== 'undefined' && currentPageId && incomingPageId !== String(currentPageId)) {
            console.warn('[WS] stale init ignored:', incomingPageId, '!=', String(currentPageId));
            return;
        }
        const stateUpdate = base64ToUint8(data.state);
		Y.applyUpdate(ydoc, stateUpdate, 'remote');

        if (cursorState.awareness && data.userId && data.username && data.color) {
        	cursorState.localUserId = data.userId;

            cursorState.awareness.setLocalStateField('user', {
                userId: data.userId,
				username: data.username,
                name: data.username,
                color: data.color
            });
		}

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

function handleYjsUpdate(data) {
	try {
		const update = base64ToUint8(data.update);
        if (looksUnsafeRealtimePayload(update)) {
            console.warn("Blocked unsafe realtime update");
            ws?.close();
            return;
        }
        Y.applyUpdate(ydoc, update, 'remote');
    } catch (error) {
        console.error('[WS] Yjs 업데이트 처리 오류:', error);
    }
}

function handleYjsState(data) {
	try {
		if (!data || typeof data.state !== 'string') return;
		const stateUpdate = base64ToUint8(data.state);
        if (looksUnsafeRealtimePayload(stateUpdate)) {
            console.warn("Blocked unsafe realtime state");
            ws?.close();
            return;
        }
		Y.applyUpdate(ydoc, stateUpdate, 'remote');
	} catch (error) {
		console.error('[WS] Yjs state 처리 오류:', error);
	}
}

function handleUserJoined(data) {
    try {
        showUserNotification(`${data.username}님이 입장했습니다.`, data.color);

        if (isE2eeSync && currentPageId && ydoc) {
            sendYjsFullStateAsUpdate(currentPageId).catch(e =>
                console.error('[E2EE] 풀 스테이트 전송 오류:', e)
            );
        }
    } catch (error) {
        console.error('[WS] user-joined 처리 오류:', error);
    }
}

function handleUserLeft(data) {
    try {
        if (!cursorState.awareness || !data?.userId) return;

        const removeClientIds = [];
        cursorState.awareness.getStates().forEach((st, cid) => {
            if (st?.user?.userId === data.userId)
                removeClientIds.push(cid);
        });

        if (removeClientIds.length > 0) {
            removeAwarenessStates(cursorState.awareness, removeClientIds, 'remote');
            removeClientIds.forEach(cid => {
                try { removeCursor(cid); } catch (e) {}
            });
        }
    } catch (error) {
        console.error('[WS] user-left 처리 오류:', error);
    }
}

export function startStorageSync(storageId) {
    stopStorageSync();

    currentStorageId = storageId;
    state.currentStorageId = storageId;

    if (ws && ws.readyState === WebSocket.OPEN) {
        subscribeStorage(storageId);
    }
}

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

function handleMetadataChange(data) {
    try {
        if (state.pages) {
            const page = state.pages.find(p => p.id === data.pageId);
            if (page) {
                page[data.field] = data.value;
            }
        }

        if (data.pageId === state.currentPageId && yMetadata) {
            const supportedFields = ['title', 'icon', 'sortOrder', 'parentId'];
            if (supportedFields.includes(data.field)) {
                ydoc.transact(() => {
                    yMetadata.set(data.field, data.value);
                }, 'remote');
                console.log(`[Sync] Yjs 메타데이터 업데이트: ${data.field} = ${data.value}`);
            }
        }

        if (data.field === 'coverImage' && data.pageId === state.currentPageId) {
            if (data.value) {
                const page = state.pages.find(p => p.id === data.pageId);
                const pos = page ? (page.coverPosition || 50) : 50;
                showCover(data.value, pos);
            } else {
                hideCover();
            }
        }

        if (data.field === 'coverPosition' && data.pageId === state.currentPageId) {
            const page = state.pages.find(p => p.id === data.pageId);
            if (page) page.coverPosition = data.value;

            const imageEl = document.getElementById('page-cover-image');
            if (imageEl) {
                imageEl.style.backgroundPositionY = `${data.value}%`;
            }
        }

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

            if (window.syncSubpagesPadding) {
                window.syncSubpagesPadding(data.value);
            }
        }

        updatePageInSidebar(data.pageId, data.field, data.value);

        if (window.handleSubpageMetadataChange) {
            window.handleSubpageMetadataChange(data);
        }
    } catch (error) {
        console.error('[WS] metadata-change 처리 오류:', error);
    }
}

function handlePageCreated(data) {
    try {
        if (state.fetchPageList) {
            state.fetchPageList().then(() => {
                renderPageList();
            });
        }
    } catch (error) {
        console.error('[WS] page-created 처리 오류:', error);
    }
}

function handlePageDeleted(data) {
    try {
        const deletedPageId = data.pageId;

        if (state.pages) {
            const pageIndex = state.pages.findIndex(p => p.id === deletedPageId);
            if (pageIndex !== -1) {
                state.pages.splice(pageIndex, 1);
            }
        }

        if (state.currentPageId === deletedPageId) {
            console.log('[WS] 현재 페이지가 삭제되었습니다:', deletedPageId);

            stopPageSync();

            if (state.editor) {
                showErrorInEditor(
                    '이 페이지는 삭제되었습니다.',
                    state.editor
                );
            }

            state.currentPageId = null;

            const titleInput = document.querySelector("#page-title-input");
            if (titleInput) {
                titleInput.value = '';
            }
        }

        if (state.fetchPageList) {
            state.fetchPageList().then(() => {
                renderPageList();
            });
        }
    } catch (error) {
        console.error('[WS] page-deleted 처리 오류:', error);
    }
}

function handleDuplicateLogin(data) {
    alert(data.message || '다른 위치에서 로그인하여 현재 세션이 종료됩니다.');
    window.location.href = '/login';
}

function handleAccessRevoked(data) {
    try {
        const storageId = data?.storageId;
        const revokedPageIds = Array.isArray(data?.pageIds) ? data.pageIds : [];
        const message = data?.message || '접근 권한이 회수되었습니다.';

        if (state.currentPageId && revokedPageIds.includes(state.currentPageId)) {
            stopPageSync();
            if (state.editor)
                showErrorInEditor(message, state.editor);
            state.currentPageId = null;
        }

        if (storageId && state.currentStorageId === storageId) {
            stopStorageSync();
            state.currentStorageId = null;
        }

        showInfo(message);

        if (state.fetchPageList) {
            state.fetchPageList().then(() => {
                renderPageList();
            });
        }
    } catch (error) {
        console.error('[WS] access-revoked 처리 오류:', error);
    }
}

function createSafeSidebarIconElement(value) {
	if (!value) return null;
	const v = String(value);

	if (v.startsWith('fa-')) {
		const safeClass = v.replace(/[^a-zA-Z0-9 _-]/g, '').trim();
		if (!safeClass) return null;
		const i = document.createElement('i');
		i.className = safeClass;
		i.style.marginRight = "6px";
		i.style.color = "#2d5f5d";
		return i;
	}

	const s = document.createElement('span');
	s.className = "page-icon";
	s.style.marginRight = "6px";
	s.style.fontSize = "16px";
	s.textContent = v;
	return s;
}

function getSidebarTitleText(titleSpan) {
	if (!titleSpan) return '';
	const texts = [];
	titleSpan.childNodes.forEach(n => {
		if (n.nodeType === Node.TEXT_NODE) texts.push(n.textContent || '');
	});
	return texts.join('').trim();
}

function updatePageInSidebar(pageId, field, value) {
    const pageElement = document.querySelector(`[data-page-id="${pageId}"]`);
    if (!pageElement) {
        return;
    }

    if (field === 'title') {
        const titleSpan = pageElement.querySelector('.page-list-item-title');
        if (titleSpan) {
            const existingIcon = titleSpan.querySelector('i, span.page-icon');
            let iconValue = null;
            if (existingIcon)
                iconValue = existingIcon.tagName === 'I' ? existingIcon.className : existingIcon.textContent;

            titleSpan.textContent = '';
            const iconEl = createSafeSidebarIconElement(iconValue);
            if (iconEl) titleSpan.appendChild(iconEl);
            titleSpan.appendChild(document.createTextNode(String(value ?? '')));
        }
    } else if (field === 'icon') {
        const titleSpan = pageElement.querySelector('.page-list-item-title');
        if (titleSpan) {
        	const titleText = getSidebarTitleText(titleSpan);

            titleSpan.textContent = '';
            const iconEl = createSafeSidebarIconElement(value);
            if (iconEl) titleSpan.appendChild(iconEl);
            titleSpan.appendChild(document.createTextNode(titleText));
        }
    }
}

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

function handleOnline() {
    showInfo('네트워크 연결이 복구되었습니다.');

    if (!ws || ws.readyState !== WebSocket.OPEN) {
        connectWebSocket();
    }
}

function looksUnsafeRealtimePayload(update) {
    try {
        const text = new TextDecoder().decode(update);
        return /\b(?:javascript|vbscript|data|file):/i.test(text)
            || /\bon[a-z]+\s*=/i.test(text)
            || /<(?:script|iframe|object|embed|meta|link|style)\b/i.test(text);
    } catch { return true; }
}

function handleOffline() {
    showInfo('네트워크 연결이 끊어졌습니다. 로컬 변경사항은 보존됩니다.');
}

function handleVisibilityChange() {
    if (document.hidden) {
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
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            connectWebSocket();
        }
    }
}

function detachYjsProsemirrorBinding() {
	if (!state.editor || !state.editor.view) return;
	const view = state.editor.view;

	if (yjsPmPluginKeys.size > 0) {
		const plugins = view.state.plugins.filter(p => !yjsPmPluginKeys.has(p.key));
		view.updateState(view.state.reconfigure({ plugins }));
	} else if (yjsPmPlugins?.length) {
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

    const syncPlugin = ySyncPlugin(yXmlFragment);
    const cursorPlugin = yCursorPlugin(cursorState.awareness, { cursorBuilder: buildCursorDOM });
    const undoPlugin = yUndoPlugin();
    const keymapPlugin = keymap({ 'Mod-z': undo, 'Mod-y': redo, 'Mod-Shift-z': redo });

	const collabPlugins = [syncPlugin, cursorPlugin, undoPlugin, keymapPlugin];
	yjsPmPlugins = collabPlugins;

	collabPlugins.forEach(p => {
		if (p?.key)
			yjsPmPluginKeys.add(p.key);
	});

	const basePlugins = view.state.plugins.filter(p => !yjsPmPluginKeys.has(p.key));

	view.updateState(
		view.state.reconfigure({
		    plugins: [...collabPlugins, ...basePlugins], 
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

	yXmlFragment = ydoc.getXmlFragment('prosemirror');
	yMetadata = ydoc.getMap('metadata'); 

	attachYjsProsemirrorBinding();

	const htmlSnapshot = yMetadata.get('content');
	const fragEmpty = (yXmlFragment.toJSON?.() ?? []).length === 0;
	if (fragEmpty && typeof htmlSnapshot === 'string' && htmlSnapshot.trim())
		editor.commands.setContent(sanitizeEditorHtml(htmlSnapshot), { emitUpdate: true });

	editor.off?.('update', editor._snapshotHandler);
	editor._snapshotHandler = ({ editor, transaction }) => {
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

function handleAwarenessChange({ added, updated, removed }, origin) {
	if (origin !== 'remote') {
	    const update = encodeAwarenessUpdate(cursorState.awareness, [
		    ...added, ...updated, ...removed,
	    ]);
	    sendAwarenessUpdate(update);
	}
}

function sendAwarenessUpdate(update) {
    if (!currentPageId || !ws || ws.readyState !== WebSocket.OPEN) return;

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

function dedupeAwarenessByUserId(userId) {
    if (!cursorState.awareness || !userId) return;

    const entries = [];
    cursorState.awareness.getStates().forEach((st, cid) => {
        if (st?.user?.userId === userId)
            entries.push([cid, st]);
    });

    if (entries.length <= 1) return;

    entries.sort((a, b) => ((b[1]?.cursor?.lastUpdate ?? 0) - (a[1]?.cursor?.lastUpdate ?? 0)));
    const removeClientIds = entries.slice(1).map(([cid]) => cid);

    removeAwarenessStates(cursorState.awareness, removeClientIds, 'remote');
    removeClientIds.forEach(cid => {
        try { removeCursor(cid); } catch (e) {}
    });
}

function handleRemoteAwarenessUpdate(data) {
    if (!cursorState.awareness) return;
    try {
		const update = base64ToUint8(data.awarenessUpdate);
        applyAwarenessUpdate(cursorState.awareness, update, 'remote');

		if (data?.fromUserId)
		    dedupeAwarenessByUserId(data.fromUserId);
    } catch (error) {
        console.error('[WS] Awareness 업데이트 처리 오류:', error);
    }
}

function getEditorScrollContainer() {
    return document.getElementById('editor') || state?.editor?.view?.dom;
}

function renderCursor(clientId, awarenessState) {
    const { cursor, user } = awarenessState;
    if (!cursor || !user || !state.editor) return;

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

    try {
        const editorView = state.editor.view;
        const coords = editorView.coordsAtPos(cursor.head);
        updateCursorPosition(cursorElement, coords, user, scrollContainer);
    } catch (error) {
        console.warn('[Cursor] Position 변환 오류:', error);
        removeCursor(clientId);
    }
}

function createCursorElement(user) {
    const container = document.createElement('div');
    container.className = 'remote-cursor-container';

    const cursor = document.createElement('div');
    cursor.className = 'remote-cursor';
    cursor.style.backgroundColor = user.color;

    const label = document.createElement('div');
    label.className = 'remote-cursor-label';
    label.style.backgroundColor = user.color;
    label.textContent = user.username;

    container.appendChild(cursor);
    container.appendChild(label);

    return container;
}

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

    if (coords.top < containerRect.top || coords.top > containerRect.bottom)
        element.style.display = 'none';
}

function removeCursor(clientId) {
    const element = cursorState.remoteCursors.get(clientId);
    if (element) {
        element.remove();
        cursorState.remoteCursors.delete(clientId);
    }
}


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

        scheduleE2EEStatePush(pageId);
    } catch (e) {
        console.error('[E2EE] 업데이트 암호화 실패:', e);
    }
}

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

function sendForceSaveE2ee(pageId) {
    if (!pageId || !ws || ws.readyState !== WebSocket.OPEN) return;
    try {
        ws.send(JSON.stringify({ type: 'force-save-e2ee', payload: { pageId } }));
    } catch (_) {}
}

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

async function handleInitE2EE(data) {
    try {
        const incomingPageId = data?.pageId ? String(data.pageId) : null;
        if (incomingPageId && typeof currentPageId !== 'undefined' && currentPageId && incomingPageId !== String(currentPageId)) {
            console.warn('[E2EE] stale init-e2ee ignored:', incomingPageId, '!=', String(currentPageId));
            return;
        }

        isE2eeWalSyncing = true;
        e2eeWalUpdateBuffer = [];

        const parseIsoMs = (v) => {
            if (!v) return null;
            let s = String(v);
            if (!s.includes('T') && s.includes(' ')) s = s.replace(' ', 'T');
            const t = Date.parse(s);
            return Number.isFinite(t) ? t : null;
        };

        const localUpdatedMs = parseIsoMs(state.currentPageUpdatedAt);
        const serverE2eeUpdatedMs = parseIsoMs(data?.e2eeStateUpdatedAt);

        const shouldTrustServerSnapshot = (() => {
            if (!data?.encryptedState) return false;
            if (!localUpdatedMs || !serverE2eeUpdatedMs) return true;
            return serverE2eeUpdatedMs + 1000 >= localUpdatedMs;
        })();

        if (data.encryptedState && shouldTrustServerSnapshot) {
            const storageKey = window.cryptoManager.getStorageKey();
            if (!storageKey) {
                console.warn('[E2EE] 저장소 키 없음 — init 상태 복호화 불가');
            } else {
                const combined = base64ToUint8(data.encryptedState);
                const stateUpdate = await decryptBytes(combined, storageKey);
                Y.applyUpdate(ydoc, stateUpdate, 'remote');
                console.log('[E2EE] 서버 스냅샷 복호화 및 적용 완료');
            }
        } else if (data.encryptedState && !shouldTrustServerSnapshot) {
            console.warn('[E2EE] 서버 스냅샷이 stale로 판단되어 무시함 (data.e2eeStateUpdatedAt < REST updatedAt)');
        }

        seedYjsFromCurrentEditorHtmlIfNeeded();

        if (cursorState.awareness && data.userId && data.username && data.color) {
            cursorState.localUserId = data.userId;
            cursorState.awareness.setLocalStateField('user', {
                userId: data.userId,
                username: data.username,
                name: data.username,
                color: data.color
            });
        }

        setupEditorBindingWithXmlFragment();

        await sendYjsStateE2EE(currentPageId);

        console.log('[E2EE] 초기화 완료');
    } catch (error) {
        console.error('[E2EE] init 처리 오류:', error);
        try { seedYjsFromCurrentEditorHtmlIfNeeded(); } catch (_) {}
        setupEditorBindingWithXmlFragment();
    }
}

async function handleE2eePendingUpdates(data) {
    if (!isE2eeSync) return;
    const pageId = data?.pageId ? String(data.pageId) : null;
    if (pageId && String(currentPageId) !== pageId) return;

    if (data.updates && Array.isArray(data.updates)) {
        const storageKey = window.cryptoManager.getStorageKey();
        if (!storageKey) {
            console.warn('[E2EE] 저장소 키 없음 — WAL 복구 불가');
        } else {
            for (const b64 of data.updates) {
                try {
                    const combined = base64ToUint8(b64);
                    const stateUpdate = await decryptBytes(combined, storageKey);
                    Y.applyUpdate(ydoc, stateUpdate, 'remote');
                } catch (e) {
                    console.error('[E2EE] WAL 업데이트 적용 실패:', e);
                }
            }
        }
    }

    if (data.done) {
        isE2eeWalSyncing = false;
        console.log('[E2EE] WAL 동기화 완료, 버퍼링된 업데이트 적용 시작');
        
        const buffered = e2eeWalUpdateBuffer;
        e2eeWalUpdateBuffer = [];
        for (const update of buffered) {
            handleYjsUpdateE2EEEvent(update).catch(() => {});
        }
    }
}

async function handleYjsUpdateE2EEEvent(data) {
    try {
        if (!ydoc) return;

        if (isE2eeWalSyncing) {
            e2eeWalUpdateBuffer.push(data);
            return;
        }

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

async function handleRequestPageSnapshot(data) {
    const pageId = data?.pageId ? String(data.pageId) : null;
    if (!pageId || isE2eeSync || String(currentPageId) !== pageId) return;

    console.log('[Self-heal] 서버로부터 HTML 스냅샷 업로드 요청 수신');
    try {
        const sent = sendPageSnapshotNow(pageId);
        if (sent) {
            await requestImmediateSave(pageId, { includeSnapshot: false, waitForAck: false });
        }
    } catch (e) {
        console.error('[Self-heal] 스냅샷 요청 응답 실패:', e);
    }
}

async function handleRequestYjsStateE2EE(data) {
    const pageId = data?.pageId ? String(data.pageId) : null;
    if (!pageId || !isE2eeSync || String(currentPageId) !== pageId) return;

    console.log('[E2EE] 서버로부터 스냅샷 업로드 요청 수신');
    try {
        await sendYjsStateE2EE(pageId);
        sendForceSaveE2ee(pageId);
    } catch (e) {
        console.error('[E2EE] 스냅샷 요청 응답 실패:', e);
    }
}
