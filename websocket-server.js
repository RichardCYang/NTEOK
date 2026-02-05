/**
 * ==================== WebSocket 서버 모듈 ====================
 * WebSocket 서버 및 실시간 동기화 기능
 */

const WebSocket = require("ws");
const Y = require("yjs");
const { formatDateForDb } = require("./network-utils");

/**
 * NOTE: WebSocket/Yjs 경로의 메타데이터도 반드시 서버에서 검증해야 함 (OWASP WebSocket Security)
 * icon 검증/정규화 (HTTP API와 동일한 보안 수준 유지)
 * - FontAwesome class 허용: fa-solid fa-star 또는 fa-star
 * - Emoji/짧은 텍스트 허용(길이 제한 + 위험문자 차단)
 * - 실패 시 null 반환 (fail-closed)
 */
function validateAndNormalizeIcon(raw) {
	if (raw === undefined || raw === null) return null;
	if (typeof raw !== "string") return null;
	const icon = raw.trim();
	if (icon === "") return null;

	// HTML/태그 관련 문자 차단
	if (/[<>]/.test(icon)) return null;
	// 제어문자 차단
	if (/[\x00-\x1F\x7F]/.test(icon)) return null;

	const FA_CLASS_RE = /^(fa-(?:solid|regular|brands|duotone|light|thin))\s+fa-[a-z0-9-]+$/i;
	const FA_SINGLE_RE = /^fa-[a-z0-9-]+$/i;

	if (FA_CLASS_RE.test(icon) || FA_SINGLE_RE.test(icon)) return icon;

	// emoji/짧은 문자열: 공백/따옴표/백틱/& 차단 + 길이 제한
	if (icon.length <= 8 && !/\s/.test(icon) && !/["'`&]/.test(icon)) return icon;

	return null;
}

// WebSocket 연결 풀
const wsConnections = {
    pages: new Map(), // pageId -> Set<{ws, userId, username, color}>
    collections: new Map(), // collectionId -> Set<{ws, userId, permission}>
	users: new Map(), // userId -> Set<{ws, sessionId}>
    sessions: new Map() // sessionId -> Set<WebSocket>
};

/**
 * ==================== 권한 회수(Revocation) 처리 ====================
 *
 * [취약점] 공유 권한이 삭제/회수되더라도 기존 WebSocket 구독이 유지되면,
 *   - 서버는 구독 시점에만 권한을 확인하고
 *   - 이후 브로드캐스트(wsBroadcastToPage/wsBroadcastToCollection)는
 *     연결 풀에 남아있는 소켓에게 계속 데이터를 전송할 수 있음
 *
 * 결과적으로, 공유를 해제한 뒤에도 상대가 페이지/컬렉션의 실시간 업데이트를 계속 수신하여
 * 공유 해제(권한 회수)가 즉시 반영되지 않는 Broken Access Control이 발생
 *
 * [해결] 공유 삭제(또는 권한 회수) 시점에, 해당 사용자에 대해
 *   - 컬렉션 구독 제거
 *   - 해당 컬렉션에 속한 페이지 구독 제거
 *   - 클라이언트에게 access-revoked 이벤트로 UI 갱신 유도
 */
async function wsRevokeUserAccessFromCollection(pool, collectionId, revokedUserId, opts = {}) {
	const reason = typeof opts.reason === 'string' ? opts.reason : '접근 권한이 회수되었습니다.';
	if (!pool || !collectionId || !Number.isFinite(revokedUserId)) return;

	const affectedSockets = new Set();
	const affectedPageIds = [];

	// 컬렉션 구독 제거
	const collectionSet = wsConnections.collections.get(collectionId);
	if (collectionSet) {
		for (const conn of Array.from(collectionSet)) {
			if (conn.userId === revokedUserId) {
				collectionSet.delete(conn);
				affectedSockets.add(conn.ws);
			}
		}
		if (collectionSet.size === 0) wsConnections.collections.delete(collectionId);
	}

	// 해당 컬렉션에 속한 페이지 목록 조회
	let pageRows = [];
	try {
		const [rows] = await pool.execute(
			`SELECT id FROM pages WHERE collection_id = ?`,
			[collectionId]
		);
		pageRows = Array.isArray(rows) ? rows : [];
	} catch (e) {
		console.error('[WS] 권한 회수 처리 중 페이지 목록 조회 실패:', e);
		pageRows = [];
	}

	// 페이지 구독 제거
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
			// 다른 사용자들에게 'user-left'를 브로드캐스트하여 커서/awareness 정리 유도
			try {
				wsBroadcastToPage(pageId, 'user-left', { userId: revokedUserId }, revokedUserId);
			} catch (e) {
				// 브로드캐스트 실패는 무시(권한 회수 자체는 계속 진행)
			}
		}

		if (pageSet.size === 0) wsConnections.pages.delete(pageId);
	}

	// 당사자에게 알림(UX): 클라이언트가 페이지/컬렉션 UI를 갱신할 수 있도록 이벤트 전송
	const payload = JSON.stringify({
		event: 'access-revoked',
		data: {
			collectionId,
			pageIds: affectedPageIds,
			message: reason
		}
	});

	for (const ws of affectedSockets) {
		try {
			if (ws && ws.readyState === WebSocket.OPEN) {
				ws.send(payload);
			}
		} catch (e) {
			// ignore
		}
	}
}

// Yjs 문서 캐시 (메모리 관리)
const yjsDocuments = new Map(); // pageId -> {ydoc, lastAccess, saveTimeout}

// 사용자 색상 (협업 UI용, 10가지 색상 순환)
const USER_COLORS = [
    '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8',
    '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B195', '#C06C84'
];

// WebSocket Rate Limiting
const wsConnectionLimiter = new Map(); // IP -> { count, resetTime }
const WS_RATE_LIMIT_WINDOW = 60 * 1000; // 1분
const WS_RATE_LIMIT_MAX_CONNECTIONS = 10; // 분당 최대 10회 연결
const WS_MAX_MESSAGE_BYTES = 2 * 1024 * 1024; // 2MiB (필요 시 조정)
const WS_MAX_AWARENESS_UPDATE_BYTES = 32 * 1024; // 32KiB (필요 시 조정)

/**
 * 세션ID -> WebSocket 연결 매핑
 * - 로그아웃/세션 만료 시 즉시 연결을 끊기 위해 사용
 */
function registerSessionConnection(sessionId, ws) {
    if (!sessionId) return;
    if (!wsConnections.sessions.has(sessionId))
        wsConnections.sessions.set(sessionId, new Set());
    wsConnections.sessions.get(sessionId).add(ws);
}

function unregisterSessionConnection(sessionId, ws) {
    if (!sessionId) return;
    const set = wsConnections.sessions.get(sessionId);
    if (!set) return;
    set.delete(ws);
    if (set.size === 0)
        wsConnections.sessions.delete(sessionId);
}

/**
 * 특정 세션의 모든 WebSocket 연결 종료
 */
function wsCloseConnectionsForSession(sessionId, code = 1008, reason = 'Session invalidated') {
    const set = wsConnections.sessions.get(sessionId);
    if (!set || set.size === 0) return;

    for (const ws of set) {
        try {
            if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)
                ws.close(code, reason);
        } catch (err) {
            // 아무 동작도 안함
        }
    }
    wsConnections.sessions.delete(sessionId);
}

/**
 * 사용자 ID 기반 색상 할당
 */
function getUserColor(userId) {
    return USER_COLORS[userId % USER_COLORS.length];
}

/**
 * SSE 연결 정리 (30분 비활성 시)
 */
function cleanupInactiveConnections(pool, sanitizeHtmlContent) {
    const now = Date.now();
    const TIMEOUT = 30 * 60 * 1000; // 30분

    yjsDocuments.forEach((doc, pageId) => {
        if (now - doc.lastAccess > TIMEOUT) {
            // 마지막 저장 후 메모리에서 제거
            saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, doc.ydoc).catch(err => {
                console.error(`[SSE] 비활성 문서 저장 실패 (${pageId}):`, err);
            });
            yjsDocuments.delete(pageId);
        }
    });
}

/**
 * 페이지에서 파일 URL 추출 (헬퍼)
 */
function extractFilesFromContent(content) {
    const files = [];
    if (content) {
        const fileRegex = /<div[^>]+data-type="file-block"[^>]+data-src=["']\/paperclip\/([^"']+)["']/g;
        let match;
        while ((match = fileRegex.exec(content)) !== null) {
            files.push(match[1]); // "userId/filename.ext"
        }
    }
    return files;
}

/**
 * 고립된 파일 삭제 (헬퍼)
 */
async function cleanupOrphanedFiles(pool, filePaths, excludePageId) {
    if (!filePaths || filePaths.length === 0) return;
    const fs = require('fs');
    const path = require('path');

    for (const filePath of filePaths) {
        try {
            const parts = filePath.split('/');
            if (parts.length !== 2) continue;

            // 다른 페이지에서 사용 중인지 확인 (현재 페이지 제외)
            const [rows] = await pool.execute(
                `SELECT COUNT(*) as count FROM pages WHERE content LIKE ? AND id != ?`,
                [`%/paperclip/${filePath}%`, excludePageId]
            );

            if (rows[0].count === 0) {
                const fullPath = path.join(__dirname, 'paperclip', filePath);
                if (fs.existsSync(fullPath)) {
                    fs.unlinkSync(fullPath);
                    console.log(`[WS 보안] 참조 없는 파일 삭제됨: ${fullPath}`);
                }
            }
        } catch (err) {
            console.error(`[WS] 파일 정리 오류 (${filePath}):`, err);
        }
    }
}

/**
 * Yjs 문서를 데이터베이스에 저장
 */
async function saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc) {
    try {
        const yXmlFragment = ydoc.getXmlFragment('prosemirror');
        const yMetadata = ydoc.getMap('metadata');

        // 메타데이터 추출
		const title = yMetadata.get('title') || '제목 없음';

        // 보안: WebSocket/Yjs 경로에서도 icon 정규화/검증 (DB 오염 방지)
		const icon = validateAndNormalizeIcon(yMetadata.get('icon'));

        const sortOrder = yMetadata.get('sortOrder') || 0;
        const parentId = yMetadata.get('parentId') || null;

        const rawContent = extractHtmlFromYDoc(ydoc);
        const content = sanitizeHtmlContent(rawContent);

        // [보안] 기존 데이터와 비교를 위해 이전 정보 조회
        const [existingRows] = await pool.execute(
            'SELECT content, is_encrypted, user_id FROM pages WHERE id = ?',
            [pageId]
        );

        let finalContent = content;
        let oldFiles = [];
        let userId = null;

        if (existingRows.length > 0) {
            const existing = existingRows[0];
            userId = existing.user_id;
            if (existing.is_encrypted === 1) {
                finalContent = '';  // 암호화된 페이지는 content 비움
            } else {
                oldFiles = extractFilesFromContent(existing.content);
            }
        }

        // Yjs 상태(바이너리) 저장 로직
		let yjsStateToSave = null;
		if (!(existingRows.length > 0 && existingRows[0].is_encrypted === 1)) {
		    yjsStateToSave = Buffer.from(Y.encodeStateAsUpdate(ydoc));
		}

        await pool.execute(
            `UPDATE pages
             SET title = ?, content = ?, icon = ?, sort_order = ?, parent_id = ?, yjs_state = ?, updated_at = NOW()
             WHERE id = ?`,
            [title, finalContent, icon, sortOrder, parentId, yjsStateToSave, pageId]
        );

        // [보안] 저장 후 파일 정리 수행
        if (existingRows.length > 0 && existingRows[0].is_encrypted === 0) {
            const newFiles = extractFilesFromContent(content);
            const deletedFiles = oldFiles.filter(f => !newFiles.includes(f));
            if (deletedFiles.length > 0) {
                cleanupOrphanedFiles(pool, deletedFiles, pageId).catch(e => console.error(e));
            }
        }
    } catch (error) {
        console.error(`[SSE] 페이지 저장 실패 (${pageId}):`, error);
        throw error;
    }
}

/**
 * Y.XmlFragment를 HTML로 변환 (간단한 구현)
 * 실제 운영 시 ProseMirror DOMSerializer 사용 권장
 */
function extractHtmlFromYDoc(ydoc) {
    const yXmlFragment = ydoc.getXmlFragment('prosemirror');
    const yMetadata = ydoc.getMap('metadata');
    const content = yMetadata.get('content');

    if (content) {
        return content;
    }

    return '<p>실시간 협업 중...</p>';
}

/**
 * Yjs 문서 로드 또는 생성
 */
async function loadOrCreateYjsDoc(pool, pageId) {
    if (yjsDocuments.has(pageId)) {
        const doc = yjsDocuments.get(pageId);
        doc.lastAccess = Date.now();
        return doc.ydoc;
    }

    // 데이터베이스에서 페이지 로드
    const [rows] = await pool.execute(
        'SELECT title, content, icon, sort_order, parent_id, yjs_state FROM pages WHERE id = ?',
        [pageId]
    );

    const ydoc = new Y.Doc();
    const yXmlFragment = ydoc.getXmlFragment('prosemirror');
    const yMetadata = ydoc.getMap('metadata');

	if (rows.length > 0) {
	    const page = rows[0];

	    // DB에 저장된 Yjs 상태가 있으면 우선 복원 (진짜 동시편집 상태)
	    if (page.yjs_state) {
	        try {
	            const update = page.yjs_state instanceof Buffer ? page.yjs_state : Buffer.from(page.yjs_state);
	            Y.applyUpdate(ydoc, update);
	            yMetadata.set('seeded', true);
	        } catch (e) {
	            console.warn(`[WS] yjs_state 복원 실패 (${pageId}) - HTML 스냅샷으로 대체:`, e);
	            yMetadata.set('seeded', false);
	        }
	    } else {
	        yMetadata.set('seeded', false);
	    }

	    // 메타데이터 기본값 채움 (이미 문서에 있으면 덮어쓰지 않음)
	    if (yMetadata.get('title') == null) yMetadata.set('title', page.title || '제목 없음');
	    if (yMetadata.get('icon') == null) yMetadata.set('icon', page.icon || null);
	    if (yMetadata.get('sortOrder') == null) yMetadata.set('sortOrder', page.sort_order || 0);
	    if (yMetadata.get('parentId') == null) yMetadata.set('parentId', page.parent_id || null);

	    // HTML 스냅샷(content)은 검색/발행/미리보기용
	    if (yMetadata.get('content') == null) yMetadata.set('content', page.content || '<p></p>');
	}

    yjsDocuments.set(pageId, {
        ydoc,
        lastAccess: Date.now(),
        saveTimeout: null
    });

    return ydoc;
}

/**
 * WebSocket 브로드캐스트 (페이지)
 */
function wsBroadcastToPage(pageId, event, data, excludeUserId = null) {
    const connections = wsConnections.pages.get(pageId);
    if (!connections) return;

    const message = JSON.stringify({ event, data });

    connections.forEach(conn => {
        if (excludeUserId && conn.userId === excludeUserId) return;
        try {
            if (conn.ws.readyState === WebSocket.OPEN) {
                conn.ws.send(message);
            }
        } catch (error) {
            console.error(`[WS] 브로드캐스트 실패 (userId: ${conn.userId}):`, error);
        }
    });
}

/**
 * WebSocket 브로드캐스트 (컬렉션)
 */
function wsBroadcastToCollection(collectionId, event, data, excludeUserId = null, options = {}) {
    const connections = wsConnections.collections.get(collectionId);
    if (!connections) return;

	// 보안: 공유 컬렉션 안에 비공유 암호화 페이지(share_allowed=0)가 존재할 수 있으므로,
	// 컬렉션 단위 브로드캐스트라도 객체 수준(page) 접근 제어를 재검증하여 메타데이터 누출을 방지
	// - options.pageVisibility: { ownerUserId: number, isEncrypted: boolean, shareAllowed: boolean }
	// - options.pageVisibilities: { [pageId]: { ownerUserId, isEncrypted, shareAllowed } } (pageIds 배열 필터링용)
	const pv = options && options.pageVisibility ? options.pageVisibility : null;
	const restrictToOwner = pv && pv.isEncrypted === true && pv.shareAllowed === false && Number.isFinite(pv.ownerUserId);

	const pvs = options && options.pageVisibilities ? options.pageVisibilities : null;
	const shouldFilterPageIds = Boolean(pvs && data && Array.isArray(data.pageIds));

    const baseMessage = shouldFilterPageIds ? null : JSON.stringify({ event, data });

    connections.forEach(conn => {
        if (excludeUserId && conn.userId === excludeUserId) return;

        // 비공유 암호화 페이지는 생성자(소유자)에게만 이벤트 전달
        if (restrictToOwner && conn.userId !== pv.ownerUserId) return;

        let payloadData = data;

  		// pages-reordered 같은 pageIds 배열 이벤트는 수신자별로 숨김 페이지를 필터링
  		if (shouldFilterPageIds) {
 			const original = data.pageIds;
 			const filtered = original.filter((pageId) => {
				const v = pvs[pageId];
				if (!v) return true;
				const r = v && v.isEncrypted === true && v.shareAllowed === false && Number.isFinite(v.ownerUserId);
				if (!r) return true;
				return conn.userId === v.ownerUserId;
 			});

 			// 숨김 페이지만 포함된 이벤트는 굳이 전송하지 않음(존재 자체를 암시하지 않도록)
 			if (filtered.length === 0) return;

 			payloadData = Object.assign({}, data, { pageIds: filtered });
  		}

        try {
			if (conn.ws.readyState === WebSocket.OPEN) {
				const message = baseMessage || JSON.stringify({ event, data: payloadData });
                conn.ws.send(message);
            }
        } catch (error) {
            console.error(`[WS] 브로드캐스트 실패 (userId: ${conn.userId}):`, error);
        }
    });
}

/**
 * WebSocket 브로드캐스트 (사용자)
 */
function wsBroadcastToUser(userId, event, data, excludeSessionId = null) {
    const connections = wsConnections.users.get(userId);
    if (!connections) return;

    const message = JSON.stringify({ event, data });

    connections.forEach(conn => {
        if (excludeSessionId && conn.sessionId === excludeSessionId) return;
        try {
            if (conn.ws.readyState === WebSocket.OPEN) {
                conn.ws.send(message);
            }
        } catch (error) {
            console.error(`[WS] 사용자 브로드캐스트 실패 (userId: ${userId}):`, error);
        }
    });
}

/**
 * WebSocket 연결 Rate Limiting
 */
function checkWebSocketRateLimit(clientIp) {
    const now = Date.now();
    const limit = wsConnectionLimiter.get(clientIp);

    if (limit) {
        if (now < limit.resetTime) {
            if (limit.count >= WS_RATE_LIMIT_MAX_CONNECTIONS) {
                return false; // Rate limit exceeded
            }
            limit.count++;
        } else {
            // 시간 윈도우가 지났으므로 리셋
            wsConnectionLimiter.set(clientIp, { count: 1, resetTime: now + WS_RATE_LIMIT_WINDOW });
        }
    } else {
        wsConnectionLimiter.set(clientIp, { count: 1, resetTime: now + WS_RATE_LIMIT_WINDOW });
    }

    return true; // 허용
}

/**
 * WebSocket 서버 초기화
 */
function initWebSocketServer(server, sessions, getCollectionPermission, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId) {
    const wss = new WebSocket.Server({
        server,
		path: '/ws',
        maxPayload: WS_MAX_MESSAGE_BYTES
    });

    wss.on('connection', async (ws, req) => {
    	try
     	{
    		// Rate Limiting 체크
			// - 개발(직접 접속): req.socket.remoteAddress 사용
			// - 리버스 프록시(Nginx/Caddy/Cloudflare 등) 뒤: remoteAddress가 ::1/127.0.0.1로
			//   고정되는 경우가 있어 X-Forwarded-For/X-Real-IP를 우선 반영(단, 루프백일 때만)
			const remoteAddress = req.socket?.remoteAddress;
			const xForwardedFor = req.headers['x-forwarded-for'];
			const xRealIp = req.headers['x-real-ip'];
			const forwardedIp = typeof xForwardedFor === 'string'
				? xForwardedFor.split(',')[0].trim()
				: (typeof xRealIp === 'string' ? xRealIp.trim() : null);
			const isLoopback = remoteAddress === '::1'
				|| remoteAddress === '127.0.0.1'
				|| (typeof remoteAddress === 'string' && remoteAddress.startsWith('::ffff:127.'));
			const clientIp = (forwardedIp && (isLoopback || !remoteAddress))
				? forwardedIp
				: (remoteAddress || 'unknown');
		    if (!checkWebSocketRateLimit(clientIp)) {
		        console.warn(`[WS Rate Limit] IP ${clientIp}의 연결 시도가 차단되었습니다.`);
		        ws.close(1008, 'Too many connection attempts. Please try again later.');
		        return;
		    }

		    // Origin 검증 (CSWSH 방지 강화)
		    // - 기본 정책: Origin/Referer가 없으면 차단
		    // - 예외가 필요하면 WS_ALLOW_NO_ORIGIN=true 로 opt-in
		    const allowNoOrigin = String(process.env.WS_ALLOW_NO_ORIGIN || "false").toLowerCase() === "true";

		    // 허용 Origin 목록: ALLOWED_ORIGINS(콤마) 우선, 없으면 BASE_URL만 허용
		    let allowedOrigins = new Set();
		    try {
		        allowedOrigins = new Set(
		            String(process.env.ALLOWED_ORIGINS || BASE_URL || "")
		                .split(",")
		                .map(s => s.trim())
		                .filter(Boolean)
		                .map(u => new URL(u).origin)
		        );
		    } catch (_) {
		        // 파싱 실패 시 보수적으로 BASE_URL origin만 허용
		        try {
		            allowedOrigins = new Set([new URL(BASE_URL).origin]);
		        } catch {}
		    }

		    const originHeader = req.headers.origin;
		    const refererHeader = req.headers.referer;
		    let reqOrigin = null;

		    // Origin/Referer는 신뢰할 수 없는 입력이므로 파싱 오류가 나더라도 예외가 전파되지 않게 방어
		    if (typeof originHeader === "string" && originHeader && originHeader !== "null") {
		        reqOrigin = originHeader.trim();
		    } else if (typeof refererHeader === "string" && refererHeader) {
		        try {
		            reqOrigin = new URL(refererHeader).origin;
		        } catch {
		            reqOrigin = null;
		        }
		    }

		    if (!reqOrigin && !allowNoOrigin) {
		        console.warn(`[WS 보안] Origin/Referer 없는 연결 차단 - IP: ${clientIp}`);
		        ws.close(1008, 'Origin required');
		        return;
		    }

			if (reqOrigin) {
				try {
					const originUrl = new URL(reqOrigin).origin;
		            if (!allowedOrigins.has(originUrl)) {
		                console.warn(`[WS 보안] 허용되지 않은 Origin 차단 - Origin: ${originUrl}, IP: ${clientIp}`);
		                ws.close(1008, 'Invalid origin');
		                return;
		            }

		            // 프로덕션에서는 https Origin만 허용(선택적으로 강화)
		            if (IS_PRODUCTION && originUrl.startsWith("http://")) {
		                console.warn(`[WS 보안] HTTP Origin 차단(Production) - Origin: ${originUrl}, IP: ${clientIp}`);
		                ws.close(1008, 'HTTPS required in production');
		                return;
		            }
		        } catch (error) {
		       	console.warn(`[WS 보안] Origin 파싱 실패 - Origin: ${String(reqOrigin || originHeader || refererHeader || '')}, IP: ${clientIp}`, error.message);
		            ws.close(1008, 'Invalid origin format');
		            return;
		        }
			} else {
		        // Origin 헤더가 없는 경우 (일부 클라이언트 라이브러리)
		        // 프로덕션 환경에서는 차단, 개발 환경에서는 경고만
		        if (IS_PRODUCTION) {
		            console.warn(`[WS 보안] Origin 헤더 없는 연결 시도 차단 - IP: ${clientIp}`);
		            ws.close(1008, 'Origin header required');
		            return;
		        } else {
		            console.warn(`[WS 개발] Origin 헤더 없는 연결 허용 (개발 환경) - IP: ${clientIp}`);
		        }
		    }

		    // 쿠키 파싱
		    const cookies = {};
		    if (req.headers.cookie) {
		        req.headers.cookie.split(';').forEach(cookie => {
		            const parts = cookie.split('=');
		            cookies[parts[0].trim()] = (parts[1] || '').trim();
		        });
		    }

		    // 세션 인증
		    const sessionId = cookies[SESSION_COOKIE_NAME];
		    if (!sessionId) {
		        ws.close(1008, 'Unauthorized');
		        return;
		    }

		    const session = typeof getSessionFromId === 'function' ? getSessionFromId(sessionId) : sessions.get(sessionId);
		    if (!session || !session.userId) {
		        ws.close(1008, 'Unauthorized');
		        return;
		    }

		    // 연결 메타데이터 저장
		    ws.userId = session.userId;
		    ws.username = session.username;
		    ws.sessionId = sessionId;
			ws.isAlive = true;

			// 세션 -> WebSocket 연결 매핑 등록 (로그아웃/세션 만료 대응)
			registerSessionConnection(sessionId, ws);

			// 핑/퐁 heartbeat
		    ws.on('pong', () => {
		        ws.isAlive = true;
		    });

		    // 메시지 핸들러
			ws.on('message', async (message) => {
				// 과도하게 큰 메시지는 즉시 차단 (DoS 방지)
		        const messageBytes = typeof message === 'string'
		            ? Buffer.byteLength(message, 'utf8')
		            : message?.length;
		        if (messageBytes && messageBytes > WS_MAX_MESSAGE_BYTES) {
		            ws.close(1009, 'Message too big');
		            return;
		        }

		        try {
		            const data = JSON.parse(message);
		            await handleWebSocketMessage(ws, data, pool, getCollectionPermission, sanitizeHtmlContent, getSessionFromId);
		        } catch (error) {
		            console.error('[WS] 메시지 처리 오류:', error);
		            ws.send(JSON.stringify({ event: 'error', data: { message: '메시지 처리 실패' } }));
		        }
		    });

		    // 연결 종료 핸들러
		    ws.on('close', () => {
		        cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent);
		    });

		    // 에러 핸들러
		    ws.on('error', (error) => {
		        console.error('[WS] 연결 오류:', error);
		        cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent);
		    });

		    // 초기 연결 확인 메시지
		    ws.send(JSON.stringify({
		        event: 'connected',
		        data: {
		            userId: session.userId,
		            username: session.username
		        }
		    }));
      	} catch (err) {
			console.error('[WS] connection handler error:', err);
			try { ws.close(1011, 'Internal error'); } catch (_) {}
		}
    });

    // 60초마다 Heartbeat (끊어진 연결 정리)
    const heartbeatInterval = setInterval(() => {
        wss.clients.forEach((ws) => {
            if (ws.isAlive === false) {
                cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent);
                return ws.terminate();
            }
            ws.isAlive = false;
            ws.ping();
        });
    }, 60000);

    wss.on('close', () => {
        clearInterval(heartbeatInterval);
    });

    return wss;
}

/**
 * WebSocket 메시지 핸들러
 */
async function handleWebSocketMessage(ws, data, pool, getCollectionPermission, sanitizeHtmlContent, getSessionFromId) {
	const { type, payload } = data;

	// 매 메시지마다 세션 유효성 확인 (세션 만료/로그아웃 즉시 반영)
	// getSessionFromId가 주입되지 않은 환경에서는(예: HTTP 폴백 구성 누락)
	// null로 평가되어 모든 메시지 처리 시 연결이 종료되는 문제가 생길 수 있으므로,
	// 주입된 경우에만 검증을 수행합니다.
	if (ws.sessionId && typeof getSessionFromId === 'function') {
	    const session = getSessionFromId(ws.sessionId);
	    if (!session || !session.userId) {
	        try { ws.close(1008, 'Session expired'); } catch (e) {}
	        return;
	    }
	}

	switch (type) {
        case 'subscribe-page':
            await handleSubscribePage(ws, payload, pool);
            break;
        case 'unsubscribe-page':
            handleUnsubscribePage(ws, payload, pool, sanitizeHtmlContent);
            break;
        case 'subscribe-collection':
            await handleSubscribeCollection(ws, payload, getCollectionPermission);
            break;
        case 'unsubscribe-collection':
            handleUnsubscribeCollection(ws, payload);
            break;
        case 'subscribe-user':
            handleSubscribeUser(ws, payload);
            break;
        case 'yjs-update':
            await handleYjsUpdate(ws, payload, pool, sanitizeHtmlContent);
            break;
        case 'awareness-update':
            handleAwarenessUpdate(ws, payload);
            break;
        default:
            console.warn('[WS] 알 수 없는 메시지 타입:', type);
    }
}

/**
 * 페이지 구독
 */
async function handleSubscribePage(ws, payload, pool) {
    const { pageId } = payload;
    const userId = ws.userId;

    try {
        // 권한 확인
        const [rows] = await pool.execute(
            `SELECT p.id, p.is_encrypted, p.collection_id, c.user_id as collection_owner, cs.permission
             FROM pages p
             LEFT JOIN collections c ON p.collection_id = c.id
             LEFT JOIN collection_shares cs ON c.id = cs.collection_id AND cs.shared_with_user_id = ?
             WHERE p.id = ? AND p.is_encrypted = 0
               AND (c.user_id = ? OR cs.permission IN ('EDIT', 'ADMIN'))`,
            [userId, pageId, userId]
        );

        if (!rows.length) {
            ws.send(JSON.stringify({
                event: 'error',
                data: { message: '권한이 없거나 암호화된 페이지입니다.' }
            }));
            return;
        }

        // 연결 풀에 추가
        if (!wsConnections.pages.has(pageId)) {
            wsConnections.pages.set(pageId, new Set());
        }

        const pageConnections = wsConnections.pages.get(pageId);

        // 새로고침/재연결로 동일 userId가 중복 subscribe 되면,
        // 기존 연결을 제거/종료해서 awareness clientId(=cid) 커서가 2개 뜨는 현상 방지
        let hadDuplicate = false;
        for (const conn of Array.from(pageConnections)) {
            if (conn.userId === userId && conn.ws !== ws) {
                hadDuplicate = true;
                pageConnections.delete(conn);
                try { conn.ws.close(1008, 'Duplicate page connection'); } catch (e) {}
            }
        }
        if (hadDuplicate) {
            // 클라이언트가 user-left를 수신하면 해당 userId의 모든 cid 커서를 정리하도록 유도
            wsBroadcastToPage(pageId, 'user-left', { userId, reason: 'duplicate-connection' }, userId);
        }

        const userColor = getUserColor(userId);
        const connection = { ws, userId, username: ws.username, color: userColor };
        pageConnections.add(connection);

        // 재연결 여부와 상관없이 항상 init state를 보낸다.
        // Yjs update는 병합되므로 재전송은 안전하며, 클라이언트 상태 파괴/재생성에도 견고해진다.
        const ydoc = await loadOrCreateYjsDoc(pool, pageId);
        const stateVector = Y.encodeStateAsUpdate(ydoc);
        const base64State = Buffer.from(stateVector).toString('base64');

        ws.send(JSON.stringify({
            event: 'init',
            data: {
                state: base64State,
                userId,
                username: ws.username,
                color: userColor
            }
        }));

        console.log(`[WS] 페이지 init 상태 전송: ${pageId} (사용자: ${ws.username})`);

        // 다른 사용자들에게 입장 알림
        wsBroadcastToPage(pageId, 'user-joined', { userId, username: ws.username, color: userColor }, userId);
    } catch (error) {
        console.error('[WS] 페이지 구독 오류:', error);
        ws.send(JSON.stringify({ event: 'error', data: { message: '페이지 구독 실패' } }));
    }
}

/**
 * 페이지 구독 해제
 */
function handleUnsubscribePage(ws, payload, pool, sanitizeHtmlContent) {
    const { pageId } = payload;
    const connections = wsConnections.pages.get(pageId);

    if (connections) {
        connections.forEach(conn => {
            if (conn.ws === ws) {
                connections.delete(conn);
            }
        });

        if (connections.size === 0) {
            wsConnections.pages.delete(pageId);

            // 문서 저장
            const docData = yjsDocuments.get(pageId);
            if (docData) {
                saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, docData.ydoc).catch(err => {
                    console.error(`[WS] 페이지 저장 실패 (${pageId}):`, err);
                });
            }
        }

        wsBroadcastToPage(pageId, 'user-left', { userId: ws.userId }, ws.userId);
    }
}

/**
 * 컬렉션 구독
 */
async function handleSubscribeCollection(ws, payload, getCollectionPermission) {
    const { collectionId } = payload;
    const userId = ws.userId;

    try {
        const permission = await getCollectionPermission(collectionId, userId);
        if (!permission || !permission.permission) {
            ws.send(JSON.stringify({ event: 'error', data: { message: '권한 없음' } }));
            return;
        }

        if (!wsConnections.collections.has(collectionId)) {
            wsConnections.collections.set(collectionId, new Set());
        }

        const connection = { ws, userId, permission: permission.permission };
        wsConnections.collections.get(collectionId).add(connection);
    } catch (error) {
        console.error('[WS] 컬렉션 구독 오류:', error);
        ws.send(JSON.stringify({ event: 'error', data: { message: '컬렉션 구독 실패' } }));
    }
}

/**
 * 컬렉션 구독 해제
 */
function handleUnsubscribeCollection(ws, payload) {
    const { collectionId } = payload;
    const connections = wsConnections.collections.get(collectionId);

    if (connections) {
        connections.forEach(conn => {
            if (conn.ws === ws) {
                connections.delete(conn);
            }
        });

        if (connections.size === 0) {
            wsConnections.collections.delete(collectionId);
        }
    }
}

/**
 * 사용자 알림 구독
 */
function handleSubscribeUser(ws, payload) {
    const userId = ws.userId;
    const sessionId = ws.sessionId;

    if (!wsConnections.users.has(userId)) {
        wsConnections.users.set(userId, new Set());
    }

    const connection = { ws, sessionId };
    wsConnections.users.get(userId).add(connection);
}

/**
 * Yjs 업데이트 처리
 */
async function handleYjsUpdate(ws, payload, pool, sanitizeHtmlContent) {
	const { pageId, update } = payload || {};
    const userId = ws.userId;

	try {
		// subscribe-page 우회 방지: 구독(연결 풀 등록) 없이 yjs-update를 처리하면, 임의 pageId로 DB 로드/캐시 생성/저장 루프를
        // 유발할 수 있어 리소스 고갈(DoS) 공격면 발생 -> WebSocket은 메시지 단위로 검증/인가를 강제해야 함. (OWASP 권고)
        if (!pageId || typeof update !== 'string' || update.length === 0) {
            ws.send(JSON.stringify({ event: 'error', data: { message: '잘못된 요청' } }));
            return;
        }

        // 반드시 subscribe-page를 거친 연결만 업데이트 허용
        if (!isSubscribedToPage(ws, pageId)) {
            console.warn(`[WS] yjs-update 차단 (구독되지 않은 pageId: ${pageId}, userId: ${userId})`);
            ws.send(JSON.stringify({ event: 'error', data: { message: '페이지를 구독하지 않았습니다.' } }));
            return;
        }

        // 권한 확인
        const [rows] = await pool.execute(
            `SELECT p.id FROM pages p
             LEFT JOIN collections c ON p.collection_id = c.id
             LEFT JOIN collection_shares cs ON c.id = cs.collection_id AND cs.shared_with_user_id = ?
             WHERE p.id = ? AND p.is_encrypted = 0
               AND (c.user_id = ? OR cs.permission IN ('EDIT', 'ADMIN'))`,
            [userId, pageId, userId]
        );

        if (!rows.length) {
            ws.send(JSON.stringify({ event: 'error', data: { message: '권한 없음' } }));
            return;
        }

        // Base64 디코딩
		const updateData = Buffer.from(update, 'base64');
		if (!updateData || updateData.length === 0) {
            ws.send(JSON.stringify({ event: 'error', data: { message: '업데이트 형식이 올바르지 않습니다.' } }));
            return;
        }

        // Yjs 문서에 적용
        const ydoc = await loadOrCreateYjsDoc(pool, pageId);
        Y.applyUpdate(ydoc, updateData);

        // 다른 클라이언트들에게 브로드캐스트
        wsBroadcastToPage(pageId, 'yjs-update', { update }, userId);

        // Debounced 저장
        const docData = yjsDocuments.get(pageId);
        if (docData) {
            if (docData.saveTimeout) {
                clearTimeout(docData.saveTimeout);
            }
            docData.saveTimeout = setTimeout(() => {
                saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, ydoc).catch(err => {
                    console.error(`[WS] Debounce 저장 실패 (${pageId}):`, err);
                });
            }, 1000);
        }
    } catch (error) {
        console.error('[WS] Yjs 업데이트 처리 오류:', error);
        ws.send(JSON.stringify({ event: 'error', data: { message: '업데이트 실패' } }));
    }
}

/**
 * 해당 ws가 특정 페이지를 구독 중인지 확인
 */
function isSubscribedToPage(ws, pageId) {
    const connections = wsConnections.pages.get(pageId);
	if (!connections)
		return false;

    for (const conn of connections) {
		if (conn.ws === ws)
			return true;
    }
    return false;
}

/**
 * Awareness 업데이트 브로드캐스트
 */
function handleAwarenessUpdate(ws, payload) {
    const { pageId, awarenessUpdate } = payload;
	const userId = ws.userId;

	// 구독(권한) 체크: subscribe-page를 거치지 않은 연결은 브로드캐스트 금지
    if (!pageId || !isSubscribedToPage(ws, pageId)) {
        console.warn(`[WS] awareness-update 차단 (구독되지 않은 pageId: ${pageId}, userId: ${userId})`);
        return;
    }

    // 과도하게 큰 awareness 업데이트는 차단 (UI 교란/DoS 방지)
    const awarenessBytes = Buffer.byteLength(JSON.stringify(awarenessUpdate ?? null), 'utf8');
    if (awarenessBytes > WS_MAX_AWARENESS_UPDATE_BYTES) {
        console.warn(`[WS] awareness-update 차단 (payload too big: ${awarenessBytes} bytes, userId: ${userId}, pageId: ${pageId})`);
        return;
    }

	// 같은 페이지의 다른 사용자들에게 브로드캐스트
    wsBroadcastToPage(pageId, 'awareness-update', {
        awarenessUpdate,
        fromUserId: userId
    }, userId);
}

/**
 * WebSocket 연결 정리
 */
function cleanupWebSocketConnection(ws, pool, sanitizeHtmlContent) {
	const userId = ws.userId;
	const sessionId = ws.sessionId;

	// 세션 매핑 정리
	unregisterSessionConnection(sessionId, ws);

	// 페이지 연결 정리
    wsConnections.pages.forEach((connections, pageId) => {
        connections.forEach(conn => {
            if (conn.ws === ws) {
                connections.delete(conn);
                wsBroadcastToPage(pageId, 'user-left', { userId }, userId);
            }
        });

        if (connections.size === 0) {
            wsConnections.pages.delete(pageId);

            // 문서 저장
            const docData = yjsDocuments.get(pageId);
            if (docData) {
                saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, docData.ydoc).catch(err => {
                    console.error(`[WS] 연결 종료 시 저장 실패 (${pageId}):`, err);
                });
            }
        }
    });

    // 컬렉션 연결 정리
    wsConnections.collections.forEach((connections, collectionId) => {
        connections.forEach(conn => {
            if (conn.ws === ws) {
                connections.delete(conn);
            }
        });

        if (connections.size === 0) {
            wsConnections.collections.delete(collectionId);
        }
    });

    // 사용자 연결 정리
    if (wsConnections.users.has(userId)) {
        const userConnections = wsConnections.users.get(userId);
        userConnections.forEach(conn => {
            if (conn.ws === ws) {
                userConnections.delete(conn);
            }
        });

        if (userConnections.size === 0) {
            wsConnections.users.delete(userId);
        }
    }
}

/**
 * Rate Limit 엔트리 정리
 */
function startRateLimitCleanup() {
    return setInterval(() => {
        const now = Date.now();
        for (const [ip, limit] of wsConnectionLimiter.entries()) {
            if (now > limit.resetTime) {
                wsConnectionLimiter.delete(ip);
            }
        }
    }, 5 * 60 * 1000);
}

/**
 * 비활성 연결 정리 시작
 */
function startInactiveConnectionsCleanup(pool, sanitizeHtmlContent) {
    return setInterval(() => {
        cleanupInactiveConnections(pool, sanitizeHtmlContent);
    }, 10 * 60 * 1000);
}

module.exports = {
    initWebSocketServer,
    wsBroadcastToPage,
    wsBroadcastToCollection,
	wsBroadcastToUser,
    wsRevokeUserAccessFromCollection,
    startRateLimitCleanup,
    startInactiveConnectionsCleanup,
    wsConnections,
    yjsDocuments,
	saveYjsDocToDatabase,
	wsCloseConnectionsForSession
};
