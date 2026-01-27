/**
 * WebSocket 및 Yjs 동기화 관리 모듈
 * 실시간 협업 편집을 위한 클라이언트 측 동기화 로직
 */

import * as Y from 'yjs';
import DOMPurify from 'dompurify';
import { Awareness, encodeAwarenessUpdate, applyAwarenessUpdate, removeAwarenessStates } from 'y-protocols/awareness.js';
import { ySyncPlugin, yCursorPlugin, yUndoPlugin, undo, redo, prosemirrorToYXmlFragment } from 'y-prosemirror';
import { keymap } from 'prosemirror-keymap';
import { DOMParser } from 'prosemirror-model';
import { escapeHtml, showErrorInEditor, syncPageUpdatedAtPadding } from './ui-utils.js';
import { showCover, hideCover } from './cover-manager.js';
import { renderPageList } from './pages-manager.js';

// 보안: 협업/메타데이터 HTML 스냅샷은 절대 신뢰하지 않기
// - WebSocket/Yjs 업데이트는 클라이언트를 우회해 임의 HTML을 주입할 수 있음
// - setContent()는 HTML을 파싱해 DOM을 만들므로, 반드시 DOMPurify로 정화 후 적용
const PURIFY_CONFIG = {
	// 허용할 HTML 태그 목록
	ALLOWED_TAGS: [
		'p','br','strong','em','u','s','code','pre',
		'h1','h2','h3','h4','h5','h6',
		'ul','ol','li','blockquote',
		'a','span','div','hr',
		'table','thead','tbody','tr','th','td',
		'img','figure',
		'label','input'
	],
	// 허용할 속성 목록 (커스텀 데이터 속성 포함)
	ALLOWED_ATTR: [
		'style','class','href','target','rel','data-type','data-latex','colspan','rowspan','colwidth',
		'src','alt','data-src','data-alt','data-caption','data-width','data-align','data-url','data-title',
		'data-description','data-thumbnail','data-id','data-icon','data-checked','type','checked',
		'data-callout-type','data-content','data-columns','data-is-open'
	],
	// data-* 속성 허용 여부 (true로 설정하여 커스텀 노드의 속성 보존)
	ALLOW_DATA_ATTR: true,
	// 안전한 URI 패턴 정의
	ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
};

function sanitizeEditorHtml(html) {
	if (!html || typeof html !== 'string') return html;
	return DOMPurify.sanitize(html, PURIFY_CONFIG);
}

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
let yjsPmPlugins = [];				// y-prosemirror(동시편집) 플러그인 추적/해제용
let yjsPmPluginKeys = new Set();	// y-prosemirror(동시편집) 플러그인 중복 확인용

// 커서 공유 상태
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
    currentCollectionId: null,
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


export function onLocalEditModeChanged(isWriteMode) {
	// 로컬 커서 정리
	if (cursorState.awareness) {
		if (!isWriteMode) {
		    cursorState.awareness.setLocalStateField('cursor', null);
		    cursorState.lastSentPosition = null;
		}
	}

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

	if (!isWrite) {
		cursorState.awareness.setLocalStateField('cursor', null);
		cursorState.lastSentPosition = null;
	}
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
    stopPageSync();
    // 암호화 페이지는 동기화 비활성화
    if (isEncrypted) {
        showInfo('암호화된 페이지는 실시간 협업이 지원되지 않습니다.');
        return;
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
	detachYjsProsemirrorBinding();
	// setupEditorBindingWithXmlFragment에서 붙인 스냅샷 핸들러 정리
	if (state.editor && state.editor._snapshotHandler) {
		state.editor.off?.('update', state.editor._snapshotHandler);
		state.editor._snapshotHandler = null;
	}

	// 커서 추적 리스너 정리(재연결 시 중복 설치 방지)
	teardownCursorTracking();

	if (updateTimeout) {
		clearTimeout(updateTimeout);
		updateTimeout = null;
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
        console.warn('[WS] WebSocket이 연결되지 않았습니다.');
        return;
    }

	const base64Update = uint8ToBase64(update);

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
        // 현재 페이지의 메타데이터 변경인 경우 Yjs 메타데이터도 업데이트
        if (data.pageId === state.currentPageId && yMetadata) {
            // Yjs 메타데이터에서 지원하는 필드만 업데이트
            const supportedFields = ['title', 'icon', 'sortOrder', 'parentId'];
            if (supportedFields.includes(data.field)) {
                yMetadata.set(data.field, data.value);
                console.log(`[Sync] Yjs 메타데이터 업데이트: ${data.field} = ${data.value}`);
            }
        }

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
    if (!document.hidden) {
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
	editor._snapshotHandler = ({ editor }) => {
		clearTimeout(updateTimeout);
		updateTimeout = setTimeout(() => {
		    try {
			    const html = editor.getHTML();
				if (yMetadata.get('content') !== html)
					yMetadata.set('content', html);
		    } catch {}
		}, 250);
	};
	editor.on('update', editor._snapshotHandler);

	// 커서 추적(blur/selectionUpdate) 이벤트 연결
	setupCursorTracking();

	console.log('[WS] yXmlFragment 기반 동시편집 바인딩 완료');
}

function teardownCursorTracking() {
	const editor = cursorState.trackingEditor;
	if (!editor) return;

	// 이벤트 리스너 제거
	if (cursorState.selectionUpdateHandler) {
		editor.off?.('selectionUpdate', cursorState.selectionUpdateHandler);
	}
	if (cursorState.blurHandler) {
		editor.off?.('blur', cursorState.blurHandler);
	}

	cursorState.trackingEditor = null;
	cursorState.selectionUpdateHandler = null;
	cursorState.blurHandler = null;
}

/**
 * 커서 위치 추적 설정
 */
function setupCursorTracking() {
	if (!state.editor || !cursorState.awareness) return;

	// 에디터 인스턴스가 바뀌었거나(재연결/재생성) 기존 핸들러가 남아있으면 정리 후 재설치
	if (cursorState.trackingEditor && cursorState.trackingEditor !== state.editor)
		teardownCursorTracking();

	// 이미 설치된 경우 재설치 방지
	if (cursorState.trackingEditor === state.editor && cursorState.selectionUpdateHandler && cursorState.blurHandler)
		return;

	cursorState.trackingEditor = state.editor;

	// 에디터 selection 변경 감지
	cursorState.selectionUpdateHandler = ({ editor }) => {
		throttledSendCursorPosition(editor);
	};

	// 포커스 해제 시 커서 제거
	cursorState.blurHandler = () => {
		if (cursorState.awareness) {
			cursorState.awareness.setLocalStateField('cursor', null);
			cursorState.lastSentPosition = null;
   		}
	};

	state.editor.on('selectionUpdate', cursorState.selectionUpdateHandler);
	state.editor.on('blur', cursorState.blurHandler);
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

    // 읽기모드(or 편집 불가)이면 내 커서를 즉시 제거
    if (!editor.isEditable) {
	    cursorState.awareness.setLocalStateField('cursor', null);
	    cursorState.lastSentPosition = null;
	    return;
    }

    const hasFocus = !!(editor.view && editor.view.hasFocus && editor.view.hasFocus());
    if (!hasFocus) {
		cursorState.awareness.setLocalStateField('cursor', null);
		cursorState.lastSentPosition = null;
		return;
    }

    if (editor._syncIsUpdating) return;

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
