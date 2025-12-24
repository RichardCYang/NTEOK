/**
 * WebSocket 및 Yjs 동기화 관리 모듈
 * 실시간 협업 편집을 위한 클라이언트 측 동기화 로직
 */

import * as Y from 'https://cdn.jsdelivr.net/npm/yjs@13.6.18/+esm';
import { Awareness, encodeAwarenessUpdate, applyAwarenessUpdate } from 'https://esm.sh/y-protocols@1.0.6/awareness';
import { escapeHtml, showErrorInEditor } from './ui-utils.js';
import { showCover, hideCover } from './cover-manager.js';

// 전역 상태
let ws = null;
let reconnectAttempts = 0;
let reconnectTimer = null;
let ydoc = null;
let yXmlFragment = null;
let yMetadata = null;
let currentPageId = null;
let currentCollectionId = null;
let lastLocalUpdateTime = 0;
let updateTimeout = null;
let hasInitializedPage = false; // 페이지 초기화 완료 플래그 (재연결 감지용)

// 커서 공유 상태
const cursorState = {
    awareness: null,              // Awareness 인스턴스
    remoteCursors: new Map(),     // clientId -> DOM element
    localClientId: null,          // 로컬 클라이언트 ID
    throttleTimer: null,          // Throttle 타이머
    lastSentPosition: null        // 마지막 전송 위치 (중복 방지)
};

const state = {
    editor: null,
    currentPageId: null,
    currentCollectionId: null,
    fetchPageList: null,
    pages: []
};

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

        // 컬렉션 재구독
        if (currentCollectionId) {
            subscribeCollection(currentCollectionId);
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
            hasInitializedPage = true; // 초기화 완료 플래그 설정
            break;
        case 'reconnected':
            console.log('[WS] 재연결 완료 - 기존 상태 유지');
            break;
        case 'yjs-update':
            handleYjsUpdate(data);
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
        case 'awareness-update':
            handleRemoteAwarenessUpdate(data);
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
 */
export async function startPageSync(pageId, isEncrypted) {
    // 암호화 페이지는 동기화 비활성화
    if (isEncrypted) {
        showInfo('암호화된 페이지는 실시간 협업이 지원되지 않습니다.');
        return;
    }

    // 페이지 전환 시에만 초기화 플래그 리셋
    if (currentPageId !== pageId) {
        hasInitializedPage = false;
    }

    // 기존 연결 정리
    stopPageSync();

    currentPageId = pageId;
    state.currentPageId = pageId;

    // Yjs 문서 생성
    ydoc = new Y.Doc();
    yXmlFragment = ydoc.getXmlFragment('prosemirror');
    yMetadata = ydoc.getMap('metadata');

    // Awareness 초기화
    cursorState.awareness = new Awareness(ydoc);
    cursorState.localClientId = ydoc.clientID;
    cursorState.awareness.on('change', handleAwarenessChange);

    // WebSocket으로 페이지 구독
    if (ws && ws.readyState === WebSocket.OPEN) {
        subscribePage(pageId);
    }

    // Yjs 변경 감지 → 서버 전송
    ydoc.on('update', (update, origin) => {
        // 로컬 변경사항만 서버로 전송 (remote는 제외)
        if (origin !== 'remote') {
            sendYjsUpdate(pageId, update);
        }
    });
}

/**
 * 페이지 구독
 */
function subscribePage(pageId) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        console.warn('[WS] WebSocket이 연결되지 않았습니다.');
        return;
    }

    ws.send(JSON.stringify({
        type: 'subscribe-page',
        payload: {
            pageId,
            isReconnect: hasInitializedPage // 재연결 플래그 전송
        }
    }));

    console.log('[WS] 페이지 구독:', pageId, hasInitializedPage ? '(재연결)' : '(최초 연결)');
}

/**
 * 페이지 동기화 중지
 */
export function stopPageSync() {
    if (currentPageId && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'unsubscribe-page',
            payload: { pageId: currentPageId }
        }));
    }

    // 모든 원격 커서 제거
    cursorState.remoteCursors.forEach(element => element.remove());
    cursorState.remoteCursors.clear();

    // Awareness 정리
    if (cursorState.awareness) {
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

    currentPageId = null;
    state.currentPageId = null;
    lastLocalUpdateTime = 0;
    hasInitializedPage = false; // 플래그 초기화
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
 * yMetadata에서 에디터로 콘텐츠 동기화
 * 읽기 모드 전환 시 호출
 */
export function syncEditorFromMetadata() {
    if (state.editor && yMetadata) {
        const content = yMetadata.get('content');
        if (content) {
            const currentContent = state.editor.getHTML();
            if (content !== currentContent) {
                state.editor.commands.setContent(content, { emitUpdate: false });
            }
        }
    }
}

/**
 * Yjs 업데이트 서버 전송
 */
function sendYjsUpdate(pageId, update) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        console.warn('[WS] WebSocket이 연결되지 않았습니다.');
        return;
    }

    const base64Update = btoa(String.fromCharCode(...new Uint8Array(update)));

    ws.send(JSON.stringify({
        type: 'yjs-update',
        payload: {
            pageId,
            update: base64Update
        }
    }));
}

/**
 * 초기 상태 처리
 */
function handleInit(data) {
    try {
        // Yjs 상태 복원
        const stateUpdate = Uint8Array.from(atob(data.state), c => c.charCodeAt(0));
        Y.applyUpdate(ydoc, stateUpdate);

        // 사용자 정보를 awareness에 설정
        if (cursorState.awareness && data.userId && data.username && data.color) {
            cursorState.awareness.setLocalStateField('user', {
                userId: data.userId,
                username: data.username,
                color: data.color
            });
        }

        // Tiptap 에디터와 연결
        setupEditorBinding();

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
        const update = Uint8Array.from(atob(data.update), c => c.charCodeAt(0));

        // 원격 업데이트는 'remote' origin으로 표시
        // yMetadata.observe()가 자동으로 에디터를 업데이트함
        Y.applyUpdate(ydoc, update, 'remote');
    } catch (error) {
        console.error('[WS] Yjs 업데이트 처리 오류:', error);
    }
}

/**
 * 사용자 입장 처리
 */
function handleUserJoined(data) {
    try {
        showUserNotification(`${data.username}님이 입장했습니다.`, data.color);
    } catch (error) {
        console.error('[WS] user-joined 처리 오류:', error);
    }
}

/**
 * 사용자 퇴장 처리
 */
function handleUserLeft(data) {
    // 필요 시 처리
}

/**
 * 컬렉션 메타데이터 동기화 시작
 */
export function startCollectionSync(collectionId) {
    stopCollectionSync();

    currentCollectionId = collectionId;
    state.currentCollectionId = collectionId;

    if (ws && ws.readyState === WebSocket.OPEN) {
        subscribeCollection(collectionId);
    }
}

/**
 * 컬렉션 구독
 */
function subscribeCollection(collectionId) {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
        console.warn('[WS] WebSocket이 연결되지 않았습니다.');
        return;
    }

    ws.send(JSON.stringify({
        type: 'subscribe-collection',
        payload: { collectionId }
    }));

    console.log('[WS] 컬렉션 구독:', collectionId);
}

/**
 * 컬렉션 동기화 중지
 */
export function stopCollectionSync() {
    if (currentCollectionId && ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({
            type: 'unsubscribe-collection',
            payload: { collectionId: currentCollectionId }
        }));
    }

    currentCollectionId = null;
    state.currentCollectionId = null;
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
        // 커버 이미지 동기화
        if (data.field === 'coverImage' && data.pageId === state.currentPageId) {
            if (data.value) {
                showCover(data.value, 50);
            } else {
                hideCover();
            }
        }

        // 커버 위치 동기화
        if (data.field === 'coverPosition' && data.pageId === state.currentPageId) {
            const imageEl = document.getElementById('page-cover-image');
            if (imageEl) {
                imageEl.style.backgroundPositionY = `${data.value}%`;
            }
        }

        // 사이드바 업데이트
        updatePageInSidebar(data.pageId, data.field, data.value);
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
            state.fetchPageList();
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
            state.fetchPageList();
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
            const icon = titleSpan.querySelector('i, span.page-icon');
            const iconHtml = icon ? icon.outerHTML : '';
            titleSpan.innerHTML = iconHtml + escapeHtml(value);
        }
    } else if (field === 'icon') {
        const titleSpan = pageElement.querySelector('.page-list-item-title');
        if (titleSpan) {
            const textContent = titleSpan.textContent.trim();
            let iconHtml = '';
            if (value) {
                if (value.startsWith('fa-')) {
                    iconHtml = `<i class="${value}" style="margin-right: 6px; color: #2d5f5d;"></i>`;
                } else {
                    iconHtml = `<span class="page-icon" style="margin-right: 6px; font-size: 16px;">${value}</span>`;
                }
            }
            titleSpan.innerHTML = iconHtml + escapeHtml(textContent);
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
    if (!document.hidden) {
        // WebSocket 연결 확인 및 재연결
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            connectWebSocket();
        }
    }
}

/**
 * Tiptap 에디터와 Yjs 바인딩 설정
 */
function setupEditorBinding() {
    if (!state.editor || !ydoc || !yMetadata) {
        console.error('[WS] 에디터 바인딩 실패: 필수 요소 없음');
        return;
    }

    // 현재 에디터 콘텐츠를 Yjs에 저장
    const currentContent = state.editor.getHTML();
    yMetadata.set('content', currentContent);

    // 보류 중인 원격 업데이트
    let remoteUpdatePending = null;

    // Tiptap 에디터 변경 시 Yjs 업데이트
    let isUpdating = false;

    // yMetadata 변경 감지 → 에디터 업데이트 (원격 변경만)
    yMetadata.observe((event, transaction) => {
        if (isUpdating) {
            return;
        }

        // 로컬 변경은 무시 (에디터가 이미 최신 상태)
        // 원격 변경(origin === 'remote')만 에디터에 적용
        if (transaction.origin !== 'remote') {
            return;
        }

        const content = yMetadata.get('content');
        if (content && state.editor) {
            const currentContent = state.editor.getHTML();
            if (content !== currentContent) {
                // 에디터에 포커스가 있고 최근 200ms 이내에 로컬 업데이트가 있었는지 확인
                const editorHasFocus = state.editor.view.hasFocus();
                const timeSinceLastUpdate = Date.now() - lastLocalUpdateTime;
                const isRecentlyTyping = timeSinceLastUpdate < 200;

                if (editorHasFocus && isRecentlyTyping) {
                    // 사용자가 타이핑 중이면 업데이트 보류
                    remoteUpdatePending = content;
                } else {
                    // 타이핑 중이 아니거나 포커스가 없으면 즉시 업데이트
                    isUpdating = true;
                    state.editor.commands.setContent(content, { emitUpdate: false });
                    isUpdating = false;
                }
            }
        }
    });

    state.editor.on('update', ({ editor }) => {
        // 원격 업데이트로 인한 변경은 무시
        if (isUpdating) {
            return;
        }

        // 마지막 로컬 업데이트 시간 기록
        lastLocalUpdateTime = Date.now();

        // Debounce (50ms) - 실시간 반응
        if (updateTimeout) {
            clearTimeout(updateTimeout);
        }

        updateTimeout = setTimeout(() => {
            const newContent = editor.getHTML();
            const oldContent = yMetadata.get('content');

            if (newContent !== oldContent) {
                // origin을 지정하지 않으면 로컬 업데이트로 처리됨
                yMetadata.set('content', newContent);
            }
            updateTimeout = null; // 타이머 초기화
        }, 50);
    });

    // 에디터 포커스 해제 시 보류 중인 원격 업데이트 적용
    state.editor.on('blur', () => {
        if (remoteUpdatePending) {
            isUpdating = true;
            state.editor.commands.setContent(remoteUpdatePending, { emitUpdate: false });
            remoteUpdatePending = null;
            isUpdating = false;
        }
    });

    // 보류 중인 업데이트를 저장하는 함수
    state.editor._setPendingRemoteUpdate = (content) => {
        remoteUpdatePending = content;
    };

    // Yjs 원격 업데이트를 에디터에 적용할 때 사용할 플래그 저장
    state.editor._syncIsUpdating = false;

    console.log('[WS] 에디터 바인딩 완료');

    // 커서 추적 시작
    setupCursorTracking();
}

/**
 * 커서 위치 추적 설정
 */
function setupCursorTracking() {
    if (!state.editor || !cursorState.awareness) return;

    // 에디터 selection 변경 감지
    state.editor.on('selectionUpdate', ({ editor }) => {
        throttledSendCursorPosition(editor);
    });

    // 포커스 해제 시 커서 제거
    state.editor.on('blur', () => {
        if (cursorState.awareness) {
            cursorState.awareness.setLocalStateField('cursor', null);
        }
    });
}

/**
 * Throttled 커서 위치 전송 (100ms)
 */
function throttledSendCursorPosition(editor) {
    if (cursorState.throttleTimer) {
        clearTimeout(cursorState.throttleTimer);
    }

    cursorState.throttleTimer = setTimeout(() => {
        sendCursorPosition(editor);
    }, 100);
}

/**
 * 커서 위치 전송
 */
function sendCursorPosition(editor) {
    if (!editor || !cursorState.awareness) return;

    const { selection } = editor.state;
    const { anchor, head } = selection;

    // 중복 전송 방지
    const position = { anchor, head };
    if (JSON.stringify(position) === JSON.stringify(cursorState.lastSentPosition)) {
        return;
    }

    cursorState.lastSentPosition = position;

    // Awareness state 업데이트
    cursorState.awareness.setLocalStateField('cursor', {
        anchor,
        head,
        type: anchor === head ? 'cursor' : 'selection',
        lastUpdate: Date.now()
    });
}

/**
 * Awareness 변경 감지 핸들러
 */
function handleAwarenessChange({ added, updated, removed }) {
    // 제거된 사용자 커서 삭제
    removed.forEach(clientId => {
        removeCursor(clientId);
    });

    // 추가/업데이트된 사용자 커서 렌더링
    [...added, ...updated].forEach(clientId => {
        if (clientId === cursorState.localClientId) return; // 자신 제외

        const awarenessState = cursorState.awareness.getStates().get(clientId);
        if (awarenessState && awarenessState.cursor && awarenessState.user) {
            renderCursor(clientId, awarenessState);
        } else {
            removeCursor(clientId);
        }
    });

    // Awareness 업데이트를 서버로 전송
    const update = encodeAwarenessUpdate(cursorState.awareness, [
        ...added, ...updated, ...removed
    ]);
    sendAwarenessUpdate(update);
}

/**
 * Awareness 업데이트 서버 전송
 */
function sendAwarenessUpdate(update) {
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    const base64Update = btoa(String.fromCharCode(...new Uint8Array(update)));

    ws.send(JSON.stringify({
        type: 'awareness-update',
        payload: {
            pageId: currentPageId,
            awarenessUpdate: base64Update
        }
    }));
}

/**
 * 원격 Awareness 업데이트 처리
 */
function handleRemoteAwarenessUpdate(data) {
    if (!cursorState.awareness) return;

    try {
        const update = Uint8Array.from(atob(data.awarenessUpdate), c => c.charCodeAt(0));
        applyAwarenessUpdate(cursorState.awareness, update, 'remote');
    } catch (error) {
        console.error('[WS] Awareness 업데이트 처리 오류:', error);
    }
}

/**
 * 커서 렌더링
 */
function renderCursor(clientId, awarenessState) {
    const { cursor, user } = awarenessState;
    if (!cursor || !user || !state.editor) return;

    // 기존 커서 요소 확인
    let cursorElement = cursorState.remoteCursors.get(clientId);

    if (!cursorElement) {
        cursorElement = createCursorElement(user);
        cursorState.remoteCursors.set(clientId, cursorElement);
        document.body.appendChild(cursorElement);
    }

    // ProseMirror position을 DOM coordinates로 변환
    try {
        const editorView = state.editor.view;
        const coords = editorView.coordsAtPos(cursor.head);
        updateCursorPosition(cursorElement, coords, user);
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
function updateCursorPosition(element, coords, user) {
    const editorRect = state.editor.view.dom.getBoundingClientRect();

    element.style.position = 'absolute';
    element.style.left = `${coords.left}px`;
    element.style.top = `${coords.top}px`;
    element.style.height = `${coords.bottom - coords.top}px`;
    element.style.display = 'block';

    // 에디터 영역 벗어나면 숨김
    if (coords.top < editorRect.top || coords.top > editorRect.bottom) {
        element.style.display = 'none';
    }
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
