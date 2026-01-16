require('dotenv').config();

const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const expressRateLimit = require("express-rate-limit");
const rateLimit = expressRateLimit.rateLimit || expressRateLimit;
const DOMPurify = require("isomorphic-dompurify");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const Y = require("yjs");
const https = require("https");
const http = require("http");
const certManager = require("./cert-manager");
const multer = require("multer");
const fs = require("fs");
const compression = require("compression");
const ipKeyGenerator = expressRateLimit.ipKeyGenerator || (expressRateLimit.default && expressRateLimit.default.ipKeyGenerator);

if (typeof ipKeyGenerator !== "function")
	throw new Error("express-rate-limit의 ipKeyGenerator를 찾지 못했습니다. 라이브러리 버전을 확인해 주세요.");

const RATE_LIMIT_IPV6_SUBNET = (() => {
    const n = Number(process.env.RATE_LIMIT_IPV6_SUBNET || 56);
    return Number.isFinite(n) ? n : 56;
})();

// 분리된 모듈 import
const {
    getLocationFromIP,
    isPrivateOrLocalIP,
    checkCountryWhitelist,
    maskIPAddress,
    formatDateForDb,
    recordLoginAttempt,
    getClientIpFromRequest,
    normalizeIp
} = require("./network-utils");

const {
    initWebSocketServer,
    wsBroadcastToPage,
    wsBroadcastToCollection,
    wsBroadcastToUser,
    startRateLimitCleanup,
    startInactiveConnectionsCleanup,
    wsConnections,
    yjsDocuments,
	saveYjsDocToDatabase,
	wsCloseConnectionsForSession
} = require("./websocket-server");

const app = express();
const PORT = process.env.PORT || 3000;

// HTTP 압축 활성화 (성능 최적화)
app.use(compression({
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    },
    level: 6, // 압축 레벨 (1-9, 6이 균형적)
    threshold: 1024 // 1KB 이상만 압축
}));

// req.clientIp 에 실제 클라이언트 IP를 저장.
// - 직접 접속: remoteAddress
// - 같은 호스트 리버스 프록시: X-Forwarded-For / X-Real-IP 반영
// - 그 외 프록시: TRUST_PROXY_CIDRS로 명시적으로 허용한 프록시만 신뢰
app.use((req, res, next) => {
    req.clientIp = getClientIpFromRequest(req);
    next();
});

// 세션 / 인증 관련 설정
const SESSION_COOKIE_NAME = "nteok_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7일 (idle timeout)
const SESSION_ABSOLUTE_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7일 (absolute timeout)
const CSRF_COOKIE_NAME = "nteok_csrf";
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const BASE_URL = process.env.BASE_URL || (IS_PRODUCTION ? "https://localhost:3000" : "http://localhost:3000");

function getClientIp(req) {
    // trust proxy가 설정되면 req.ips가 채워짐(최초가 원 클라이언트)
    const ips = Array.isArray(req.ips) ? req.ips : [];
    const candidate = ips.length > 0 ? ips[0] : req.socket?.remoteAddress;
    return normalizeIp(candidate);
}

// 보안 개선: 기본 관리자 계정 비밀번호를 강제로 변경하도록 경고
// 운영(PROD)에서는 ADMIN_PASSWORD 미설정 상태로 부팅하지 않도록 fail-closed 처리
const DEFAULT_ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";

let DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!DEFAULT_ADMIN_PASSWORD) {
    if (IS_PRODUCTION) {
        console.error("\n" + "=".repeat(80));
        console.error("❌ 프로덕션 환경에서 ADMIN_PASSWORD가 설정되지 않았습니다.");
        console.error("   - 보안을 위해 랜덤 비밀번호를 생성/로그로 출력하지 않습니다.");
        console.error("   - .env 또는 배포 환경변수에 ADMIN_PASSWORD를 설정한 뒤 다시 실행하세요.");
        console.error("=".repeat(80) + "\n");
        process.exit(1);
    }

    // 개발/로컬 환경: 편의상 임시 랜덤 비밀번호 생성 + 콘솔 경고
    DEFAULT_ADMIN_PASSWORD = crypto.randomBytes(16).toString("hex");
    console.warn("\n" + "=".repeat(80));
    console.warn("⚠️  보안 경고: 기본 관리자 비밀번호가 환경변수로 설정되지 않았습니다! (개발/로컬)");
    console.warn(`   관리자 계정: ${DEFAULT_ADMIN_USERNAME}`);
    console.warn(`   임시 비밀번호: ${DEFAULT_ADMIN_PASSWORD}`);
    console.warn("   첫 로그인 후 반드시 비밀번호를 변경하세요!");
    console.warn("=".repeat(80) + "\n");
}

const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 12);

// 프로덕션 환경에서 필수 환경변수 검증
if (IS_PRODUCTION) {
    const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'BASE_URL', 'ADMIN_PASSWORD'];
    const missingVars = requiredEnvVars.filter(key => !process.env[key]);

    if (missingVars.length > 0) {
        console.error("\n" + "=".repeat(80));
        console.error("❌ 프로덕션 환경에서 필수 환경변수가 설정되지 않았습니다:");
        missingVars.forEach(varName => {
            console.error(`   - ${varName}`);
        });
        console.error("=".repeat(80) + "\n");
        process.exit(1);
    }
}

/**
 * DB 연결 설정 정보
 */
const DB_CONFIG = {
    host: process.env.DB_HOST || "localhost",
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "admin",
    database: process.env.DB_NAME || "nteok",
    charset: "utf8mb4",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool;
const sessions = new Map();
// 사용자별 세션 추적 (userId -> Set<sessionId>)
const userSessions = new Map();

/**
 * 만료된 세션 정리 작업
 * 주기적으로 실행하여 메모리 누수 방지
 */
function cleanupExpiredSessions() {
    const now = Date.now();
    let cleanedCount = 0;

    sessions.forEach((session, sessionId) => {
        let shouldDelete = false;

        // 임시 세션 (pendingUserId) 정리 - 10분 경과
        if (session.pendingUserId && session.createdAt + 10 * 60 * 1000 < now) {
            shouldDelete = true;
        }

        // 정식 세션의 절대 만료 시간 체크
        if (session.absoluteExpiry && session.absoluteExpiry <= now) {
            shouldDelete = true;
        }

        // Idle timeout 체크
        if (session.expiresAt && session.expiresAt <= now) {
            shouldDelete = true;
        }

		if (shouldDelete) {
			// 세션 만료 시 해당 세션으로 열린 WebSocket 연결도 즉시 종료
			try {
			    wsCloseConnectionsForSession(sessionId, 1008, 'Session expired');
			} catch (e) {}

            sessions.delete(sessionId);
            cleanedCount++;

            // userSessions에서도 제거
            if (session.userId) {
                const userSessionSet = userSessions.get(session.userId);
                if (userSessionSet) {
                    userSessionSet.delete(sessionId);
                    if (userSessionSet.size === 0) {
                        userSessions.delete(session.userId);
                    }
                }
            }
        }
    });

    if (cleanedCount > 0) {
        console.log(`[세션 정리] ${cleanedCount}개의 만료된 세션을 정리했습니다. (남은 세션: ${sessions.size})`);
    }
}

// 5분마다 세션 정리 작업 실행
setInterval(cleanupExpiredSessions, 5 * 60 * 1000);

/**
 * 만료된 WebAuthn 챌린지 정리
 */
function cleanupExpiredWebAuthnChallenges() {
    const now = formatDateForDb(new Date());
    pool.execute("DELETE FROM webauthn_challenges WHERE expires_at < ?", [now])
        .then(([result]) => {
            if (result.affectedRows > 0) {
                console.log(`[WebAuthn 챌린지 정리] ${result.affectedRows}개의 만료된 챌린지를 정리했습니다.`);
            }
        })
        .catch(err => console.error("WebAuthn 챌린지 정리 중 오류:", err));
}

// 5분마다 WebAuthn 챌린지 정리 작업 실행
setInterval(cleanupExpiredWebAuthnChallenges, 5 * 60 * 1000);

/**
 * 30일 이상 오래된 로그인 로그 정리
 */
function cleanupOldLoginLogs() {
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const thirtyDaysAgoStr = formatDateForDb(thirtyDaysAgo);

    pool.execute("DELETE FROM login_logs WHERE created_at < ?", [thirtyDaysAgoStr])
        .then(([result]) => {
            if (result.affectedRows > 0) {
                console.log(`[로그인 로그 정리] ${result.affectedRows}개의 30일 이상 된 로그를 삭제했습니다.`);
            }
        })
        .catch(err => console.error("로그인 로그 정리 중 오류:", err));
}

// IP 처리 및 로그인 기록 함수들은 network-utils.js 모듈로 이동됨

/**
 * 보안 개선: 암호학적으로 안전한 페이지 ID 생성
 * Math.random() 대신 crypto.randomBytes 사용
 */
function generatePageId(now) {
    const iso = now.toISOString().replace(/[:.]/g, "-");
    const rand = crypto.randomBytes(6).toString("hex"); // 12자 hex 문자열
    return "page-" + iso + "-" + rand;
}

/**
 * 보안 개선: 암호학적으로 안전한 컬렉션 ID 생성
 * Math.random() 대신 crypto.randomBytes 사용
 */
function generateCollectionId(now) {
    const iso = now.toISOString().replace(/[:.]/g, "-");
    const rand = crypto.randomBytes(6).toString("hex"); // 12자 hex 문자열
    return "col-" + iso + "-" + rand;
}

/**
 * DB DATETIME 값을 ISO 문자열로 변환
 */
function toIsoString(value) {
    if (!value) {
        return null;
    }
    if (value instanceof Date) {
        return value.toISOString();
    }
    if (typeof value === "string") {
        if (value.endsWith("Z")) {
            return value;
        }
        return value + "Z";
    }
    return String(value);
}

/**
 * CSRF 토큰 생성
 */
function generateCsrfToken() {
    return crypto.randomBytes(32).toString("hex");
}

/**
 * XSS 방지: HTML 태그 제거 (sanitization)
 * 사용자 입력값에서 잠재적으로 위험한 HTML 태그를 제거
 * 제목 등 평문 필드에 사용
 */
function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return input;
    }
    // HTML 태그 제거
    return input.replace(/<[^>]*>/g, '');
}

/**
 * 보안 개선: HTML 콘텐츠 정화 (DOMPurify)
 * 에디터 콘텐츠 등 HTML이 필요한 필드에 사용
 */
function sanitizeHtmlContent(html) {
    if (typeof html !== 'string') {
        return html;
    }

    // DOMPurify로 안전한 HTML만 허용
    return DOMPurify.sanitize(html, {
        ALLOWED_TAGS: [
            'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
            'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'ul', 'ol', 'li', 'blockquote',
            'a', 'span', 'div',
            'hr',
            'table', 'thead', 'tbody', 'tr', 'th', 'td',
            'img', 'figure',
            'label', 'input'
        ],
        ALLOWED_ATTR: ['style', 'class', 'href', 'target', 'rel', 'data-type', 'data-latex', 'colspan', 'rowspan', 'colwidth', 'src', 'alt', 'data-src', 'data-alt', 'data-caption', 'data-width', 'data-align', 'data-url', 'data-title', 'data-description', 'data-thumbnail', 'data-id', 'data-icon', 'data-checked', 'type', 'checked', 'data-callout-type', 'data-content', 'data-columns'],
        ALLOW_DATA_ATTR: false,
        ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
    });
}

/**
 * 보안 개선: 비밀번호 강도 검증
 * @param {string} password - 검증할 비밀번호
 * @returns {{valid: boolean, error?: string}}
 */
function validatePasswordStrength(password) {
    if (!password || typeof password !== 'string') {
        return { valid: false, error: "비밀번호를 입력해 주세요." };
    }

    if (password.length < 10) {
        return { valid: false, error: "비밀번호는 10자 이상이어야 합니다." };
    }

    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    const strength = [hasUpperCase, hasLowerCase, hasNumbers, hasSpecialChar]
        .filter(Boolean).length;

    if (strength < 3) {
        return {
            valid: false,
            error: "비밀번호는 대문자, 소문자, 숫자, 특수문자 중 3가지 이상을 포함해야 합니다."
        };
    }

    return { valid: true };
}

/**
 * 보안 개선: 에러 로깅 (프로덕션에서는 상세 정보 숨김)
 * @param {string} context - 에러 발생 위치
 * @param {Error} error - 에러 객체
 */
function logError(context, error) {
    if (IS_PRODUCTION) {
        // 프로덕션: 간단한 에러 메시지만
        console.error(`[오류] ${context}`);
        // 실제 프로덕션에서는 로깅 서비스로 전송 권장 (e.g., Sentry, Winston)
    } else {
        // 개발: 상세한 스택 트레이스
        console.error(`[오류] ${context}:`, error);
    }
}

/**
 * CSRF 토큰 검증 (Double Submit Cookie 패턴)
 */
function verifyCsrfToken(req) {
    const tokenFromHeader = req.headers["x-csrf-token"];
    const tokenFromCookie = req.cookies[CSRF_COOKIE_NAME];

    if (typeof tokenFromHeader !== "string" || typeof tokenFromCookie !== "string") return false;
    if (tokenFromHeader.length !== tokenFromCookie.length) return false;

    try
    {
	   	// 타이밍 공격 방지를 위한 상수 시간 비교
	    return crypto.timingSafeEqual(
	        Buffer.from(tokenFromHeader, "utf8"),
	        Buffer.from(tokenFromCookie, "utf8")
	    );
    }
    catch
    {
		return false;
    }
}

/**
 * 세션 생성
 * 보안 개선: idle timeout과 absolute timeout 모두 적용
 * 중복 로그인 감지: 사용자 설정에 따라 차단 또는 기존 세션 파기
 * @param {Object} user - 사용자 정보 (id, username, blockDuplicateLogin 포함)
 * @returns {Object} - { success: boolean, sessionId?: string, error?: string }
 */
function createSession(user) {
    const sessionId = crypto.randomBytes(24).toString("hex");
    const now = Date.now();
    const expiresAt = now + SESSION_TTL_MS; // idle timeout
    const absoluteExpiry = now + SESSION_ABSOLUTE_TTL_MS; // absolute timeout

    // 중복 로그인 감지: 기존 세션 확인
    const existingSessions = userSessions.get(user.id);
    if (existingSessions && existingSessions.size > 0) {
        // 보안: 사용자명 일부만 표시
        const maskedUsername = user.username.substring(0, 2) + '***';
        console.log(`[중복 로그인 감지] 사용자 ID ${user.id} (${maskedUsername})의 기존 세션 ${existingSessions.size}개 발견`);

        // 사용자 설정 확인: 중복 로그인 차단 모드
        if (user.blockDuplicateLogin) {
            console.log(`[중복 로그인 차단] 사용자 ID ${user.id} (${maskedUsername})의 새 로그인 시도 거부`);
            return {
                success: false,
                error: '이미 다른 위치에서 로그인 중입니다. 기존 세션을 먼저 종료하거나, 설정에서 "중복 로그인 차단" 옵션을 해제해주세요.'
            };
        }

        // 중복 로그인 허용 모드: 기존 세션들에게 알림 전송
        wsBroadcastToUser(user.id, 'duplicate-login', {
            message: '다른 위치에서 로그인하여 현재 세션이 종료됩니다.',
            timestamp: new Date().toISOString()
        });

        // 기존 세션 모두 파기
		existingSessions.forEach(oldSessionId => {
			// 기존 세션에 매달린 WebSocket 연결도 즉시 종료
			try {
			    wsCloseConnectionsForSession(oldSessionId, 1008, 'Duplicate login');
			} catch (e) {}

            sessions.delete(oldSessionId);
            // 보안: 세션 ID 일부만 표시
            console.log(`[세션 파기] 세션 ID: ${oldSessionId.substring(0, 8)}...`);
        });

        // 사용자 세션 목록 초기화
        existingSessions.clear();
    }

    // 새 세션 생성
    sessions.set(sessionId, {
    	type: "auth",
        userId: user.id,
        username: user.username,
        expiresAt,
        absoluteExpiry,
        createdAt: now
    });

    // 사용자 세션 목록에 추가
    if (!userSessions.has(user.id)) {
        userSessions.set(user.id, new Set());
    }
    userSessions.get(user.id).add(sessionId);

    // 보안: 세션 ID와 사용자명 일부만 표시
    const maskedUsername = user.username.substring(0, 2) + '***';
    console.log(`[세션 생성] 사용자: ${maskedUsername} (ID: ${user.id}), 세션 ID: ${sessionId.substring(0, 8)}...`);

    return { success: true, sessionId };
}

/**
 * 요청에서 세션 읽기
 * 보안 개선: idle timeout과 absolute timeout 모두 검증
 */
function getSessionFromRequest(req) {
    if (!req.cookies)
        return null;

    const sessionId = req.cookies[SESSION_COOKIE_NAME];
    if (!sessionId)
    	return null;

    const session = sessions.get(sessionId);
    if (!session)
    	return null;

    // 2FA 인증을 위한 임시 세션이 아닌 정식 인증 세션 인정하도록 코드 수정
	if (session.type !== 'auth' || !session.userId)
		return null;

	// 세션 만료 정보가 없는 세션 정보이면 무효 처리
	if (!session.expiresAt || !session.absoluteExpiry) {
		sessions.delete(sessionId);
		return null;
	}

    const now = Date.now();

    // 절대 만료 시간 체크 (세션 생성 후 7일)
    if (session.absoluteExpiry <= now) {
        console.warn(`[세션 만료] 세션 ID ${sessionId.substring(0, 8)}... - 절대 만료 시간 초과 (사용자: ${session.userId})`);
        sessions.delete(sessionId);
        // userSessions에서도 제거
        if (session.userId) {
            const userSessionSet = userSessions.get(session.userId);
            if (userSessionSet) {
                userSessionSet.delete(sessionId);
                if (userSessionSet.size === 0) {
                    userSessions.delete(session.userId);
                }
            }
        }
        return null;
    }

    // Idle timeout 체크 (마지막 활동 후 7일)
    if (session.expiresAt <= now) {
        console.warn(`[세션 만료] 세션 ID ${sessionId.substring(0, 8)}... - 비활성 시간 초과 (사용자: ${session.userId})`);
        sessions.delete(sessionId);
        // userSessions에서도 제거
        if (session.userId) {
            const userSessionSet = userSessions.get(session.userId);
            if (userSessionSet) {
                userSessionSet.delete(sessionId);
                if (userSessionSet.size === 0) {
                    userSessions.delete(session.userId);
                }
            }
        }
        return null;
    }

    // 세션이 유효하면 idle timeout 갱신
    session.expiresAt = now + SESSION_TTL_MS;

    return { id: sessionId, ...session };
}

/**
 * 인증이 필요한 API용 미들웨어
 */
function authMiddleware(req, res, next) {
    const session = getSessionFromRequest(req);

    if (!session) {
        const sessionId = req.cookies[SESSION_COOKIE_NAME];
        // 보안: 세션 ID 일부만 표시
        const maskedSessionId = sessionId ? `${sessionId.substring(0, 8)}...` : '없음';
        console.warn(`[인증 실패] ${req.method} ${req.path} - 세션 ID: ${maskedSessionId}, 유효한 세션: 없음, IP: ${req.clientIp || req.ip}`);
        return res.status(401).json({ error: "로그인이 필요합니다." });
    }

    req.user = {
        id: session.userId,
        username: session.username
    };

    next();
}

/**
 * CSRF 토큰 검증 미들웨어
 * GET, HEAD, OPTIONS 요청은 제외
 */
function csrfMiddleware(req, res, next) {
    // 안전한 메서드는 CSRF 검증 불필요
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
        return next();
    }

    // 로그인/회원가입/2FA 검증은 CSRF 토큰 없이도 허용 (첫 접속 시)
    // 참고: app.use("/api", csrfMiddleware)로 적용되므로 req.path는 /api 이후 경로
    if (req.path === "/auth/login" ||
        req.path === "/auth/register" ||
        req.path === "/totp/verify-login" ||
        req.path === "/totp/verify-backup-code" ||
        req.path === "/passkey/authenticate/options" ||
        req.path === "/passkey/authenticate/verify" ||
        req.path === "/passkey/login/options" ||
        req.path === "/passkey/login/verify" ||
        req.path === "/passkey/login/userless/options" ||
        req.path === "/passkey/login/userless/verify") {
        return next();
    }

    // CSRF 토큰 검증
    if (!verifyCsrfToken(req)) {
        console.warn("CSRF 토큰 검증 실패:", req.path, req.method);
        return res.status(403).json({ error: "CSRF 토큰이 유효하지 않습니다." });
    }

    next();
}

/**
 * DB 초기화: 커넥션 풀 생성 + 테이블/기본 페이지 생성 + 사용자 정보 테이블 생성
 */
async function initDb() {
    pool = await mysql.createPool(DB_CONFIG);

    // users 테이블 생성
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS users (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(64) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            totp_secret VARCHAR(64) NULL,
            totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
            passkey_enabled TINYINT(1) NOT NULL DEFAULT 0,
            block_duplicate_login TINYINT(1) NOT NULL DEFAULT 0,
            country_whitelist_enabled TINYINT(1) NOT NULL DEFAULT 0,
            allowed_login_countries TEXT NULL
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // 기존 users 테이블에 국가 화이트리스트 컬럼 추가 (마이그레이션)
    try {
        await pool.execute(`
            ALTER TABLE users
            ADD COLUMN country_whitelist_enabled TINYINT(1) NOT NULL DEFAULT 0
        `);
        console.log('✓ country_whitelist_enabled 컬럼 추가됨');
    } catch (error) {
        // 컬럼이 이미 존재하면 무시
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.error('country_whitelist_enabled 컬럼 추가 오류:', error.message);
        }
    }

    try {
        await pool.execute(`
            ALTER TABLE users
            ADD COLUMN theme VARCHAR(64) NOT NULL DEFAULT 'default'
        `);
        console.log('✓ theme 컬럼 추가됨');
    } catch (error) {
        // 컬럼이 이미 존재하면 무시
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.error('theme 컬럼 추가 오류:', error.message);
        }
    }

    try {
        await pool.execute(`
            ALTER TABLE users
            ADD COLUMN allowed_login_countries TEXT NULL
        `);
        console.log('✓ allowed_login_countries 컬럼 추가됨');
    } catch (error) {
        // 컬럼이 이미 존재하면 무시
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.error('allowed_login_countries 컬럼 추가 오류:', error.message);
        }
    }

    // (TOTP 컬럼들은 이제 CREATE TABLE에 포함됨)

    // users 가 하나도 없으면 기본 관리자 계정 생성
    const [userRows] = await pool.execute("SELECT COUNT(*) AS cnt FROM users");
    const userCount = userRows[0].cnt;

    if (userCount === 0) {
        const now = new Date();
        const nowStr = formatDateForDb(now);

        const username = DEFAULT_ADMIN_USERNAME;
        const rawPassword = DEFAULT_ADMIN_PASSWORD;

        // bcrypt 가 내부적으로 랜덤 SALT 를 포함한 해시를 생성함
        const passwordHash = await bcrypt.hash(rawPassword, BCRYPT_SALT_ROUNDS);

        await pool.execute(
            `
            INSERT INTO users (username, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            `,
            [username, passwordHash, nowStr, nowStr]
        );

        console.log("기본 관리자 계정 생성 완료. username:", username);
    }

    // collections 테이블 생성 (users 테이블 생성 후)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS collections (
            id          VARCHAR(64)  NOT NULL PRIMARY KEY,
            user_id     INT          NOT NULL,
            name        VARCHAR(255) NOT NULL,
            sort_order  INT          NOT NULL DEFAULT 0,
            created_at  DATETIME     NOT NULL,
            updated_at  DATETIME     NOT NULL,
            is_encrypted TINYINT(1) NOT NULL DEFAULT 0,
            default_encryption TINYINT(1) NOT NULL DEFAULT 0,
            enforce_encryption TINYINT(1) NOT NULL DEFAULT 0,
            CONSTRAINT fk_collections_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // pages 테이블 생성
    await pool.execute(`
    	CREATE TABLE IF NOT EXISTS pages (
            id          VARCHAR(64)  NOT NULL PRIMARY KEY,
            sort_order  INT          NOT NULL DEFAULT 0,
            user_id     INT          NOT NULL,
            title       VARCHAR(255) NOT NULL,
            content     MEDIUMTEXT   NOT NULL,
            created_at  DATETIME     NOT NULL,
            updated_at  DATETIME     NOT NULL,
            parent_id   VARCHAR(64)  NULL,
            is_encrypted TINYINT(1) NOT NULL DEFAULT 0,
            encryption_salt VARCHAR(255) NULL,
            encrypted_content MEDIUMTEXT NULL,
            yjs_state	LONGBLOB NULL,
            share_allowed TINYINT(1) NOT NULL DEFAULT 0,
            icon VARCHAR(100) NULL,
            cover_image VARCHAR(255) NULL,
            cover_position INT NOT NULL DEFAULT 50,
            CONSTRAINT fk_pages_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_pages_parent
                FOREIGN KEY (parent_id)
                REFERENCES pages(id)
                ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // 기존 테이블의 charset을 utf8mb4로 변경 (이모지 지원)
    try {
        await pool.execute(`
            ALTER TABLE pages
            CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
        `);

        // pages 테이블에 yjs_state 컬럼 추가 (기존 컬럼 없을 경우만) - 실시간 동시 편집(Yjs) 상태 저장
        await pool.execute(`
            ALTER TABLE pages
            ADD COLUMN IF NOT EXISTS yjs_state LONGBLOB NULL
        `);
    } catch (error) {
        // 이미 utf8mb4인 경우 무시
        if (error && error.code !== 'ER_BAD_FIELD_ERROR') {
            console.warn("pages 테이블 charset 변경 중 경고:", error.message);
        }
    }

    // pages 테이블에 collection_id 컬럼 추가 (없을 경우만)
    await pool.execute(`
        ALTER TABLE pages
        ADD COLUMN IF NOT EXISTS collection_id VARCHAR(64) NULL
    `);

    // pages.collection_id 외래키 추가 (이미 있는 경우 무시)
    try {
        await pool.execute(`
            ALTER TABLE pages
            ADD CONSTRAINT fk_pages_collection
                FOREIGN KEY (collection_id)
                REFERENCES collections(id)
                ON DELETE CASCADE
        `);
    } catch (error) {
        // 이미 존재하는 경우 무시
        if (error && error.code !== "ER_DUP_KEY" && error.code !== "ER_CANNOT_ADD_FOREIGN") {
            console.warn("pages.collection_id FK 추가 중 경고:", error.message);
        }
    }

    // pages 테이블에 horizontal_padding 컬럼 추가 (없을 경우만)
    await pool.execute(`
        ALTER TABLE pages
        ADD COLUMN IF NOT EXISTS horizontal_padding INT NULL
    `);
    console.log('✓ horizontal_padding 컬럼 추가 확인');

    // (페이지 관련 컬럼들은 이제 CREATE TABLE에 포함됨)

    // collection_shares 테이블 생성 (사용자 간 직접 공유)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS collection_shares (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            collection_id VARCHAR(64) NOT NULL,
            owner_user_id INT NOT NULL,
            shared_with_user_id INT NOT NULL,
            permission VARCHAR(20) NOT NULL DEFAULT 'READ',
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            CONSTRAINT fk_collection_shares_collection
                FOREIGN KEY (collection_id)
                REFERENCES collections(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_collection_shares_owner
                FOREIGN KEY (owner_user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_collection_shares_shared_with
                FOREIGN KEY (shared_with_user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT uc_collection_shares_unique
                UNIQUE (collection_id, shared_with_user_id),
            INDEX idx_shared_with_user (shared_with_user_id),
            INDEX idx_collection_permission (collection_id, permission)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // share_links 테이블 생성 (링크 기반 공유)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS share_links (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(64) NOT NULL UNIQUE,
            collection_id VARCHAR(64) NOT NULL,
            owner_user_id INT NOT NULL,
            permission VARCHAR(20) NOT NULL DEFAULT 'READ',
            expires_at DATETIME NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            CONSTRAINT fk_share_links_collection
                FOREIGN KEY (collection_id)
                REFERENCES collections(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_share_links_owner
                FOREIGN KEY (owner_user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            INDEX idx_token_active (token, is_active),
            INDEX idx_collection_links (collection_id),
            INDEX idx_expires_at (expires_at)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // backup_codes 테이블 생성 (TOTP 백업 코드)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS backup_codes (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            code_hash VARCHAR(255) NOT NULL,
            used TINYINT(1) NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL,
            used_at DATETIME NULL,
            CONSTRAINT fk_backup_codes_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            INDEX idx_user_codes (user_id, used)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // (passkey_enabled, block_duplicate_login은 이제 CREATE TABLE에 포함됨)

    // passkeys 테이블 생성 (WebAuthn 크레덴셜 저장)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS passkeys (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            credential_id VARCHAR(512) NOT NULL UNIQUE,
            public_key TEXT NOT NULL,
            counter BIGINT UNSIGNED NOT NULL DEFAULT 0,
            transports VARCHAR(255) NULL,
            aaguid VARCHAR(36) NULL,
            device_name VARCHAR(100) NULL,
            last_used_at DATETIME NULL,
            created_at DATETIME NOT NULL,
            CONSTRAINT fk_passkeys_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            INDEX idx_user_id (user_id),
            INDEX idx_credential_id (credential_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // webauthn_challenges 테이블 생성 (임시 챌린지 저장)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS webauthn_challenges (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            session_id VARCHAR(64) NOT NULL,
            challenge VARCHAR(255) NOT NULL,
            operation VARCHAR(20) NOT NULL,
            created_at DATETIME NOT NULL,
            expires_at DATETIME NOT NULL,
            INDEX idx_session_id (session_id),
            INDEX idx_expires_at (expires_at)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // 페이지 발행 링크 테이블
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS page_publish_links (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(64) NOT NULL UNIQUE,
            page_id VARCHAR(64) NOT NULL,
            owner_user_id INT NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            CONSTRAINT fk_page_publish_links_page
                FOREIGN KEY (page_id)
                REFERENCES pages(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_page_publish_links_owner
                FOREIGN KEY (owner_user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            INDEX idx_token_active (token, is_active),
            INDEX idx_page_id (page_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // login_logs 테이블 생성 (로그인 시도 기록)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS login_logs (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT NULL,
            username VARCHAR(64) NULL,
            ip_address VARCHAR(45) NOT NULL,
            port INT NOT NULL,
            country VARCHAR(2) NULL,
            region VARCHAR(100) NULL,
            city VARCHAR(100) NULL,
            timezone VARCHAR(100) NULL,
            user_agent TEXT NULL,
            success TINYINT(1) NOT NULL,
            failure_reason VARCHAR(100) NULL,
            created_at DATETIME NOT NULL,
            INDEX idx_user_logs (user_id, created_at DESC),
            INDEX idx_created_at (created_at),
            CONSTRAINT fk_login_logs_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // ============================================================
    // E2EE 시스템 재설계: 선택적 암호화 (마스터 키 시스템 제거)
    // ============================================================
    // - 모든 E2EE 관련 컬럼들은 CREATE TABLE에 포함됨
    // - 마스터 키 시스템 제거로 더 이상 필요 없음
    // ============================================================

    // 컬렉션이 없는 기존 사용자 데이터 마이그레이션
    await backfillCollections();

    // ============================================================
    // 성능 최적화: 데이터베이스 인덱스 추가
    // ============================================================

    // pages 테이블 인덱스 (컬렉션별 페이지 조회 최적화)
    try {
        await pool.execute(`
            CREATE INDEX IF NOT EXISTS idx_pages_collection_user
            ON pages(collection_id, user_id)
        `);
        console.log('✓ pages.collection_id, user_id 인덱스 생성 완료');
    } catch (error) {
        if (error.code !== 'ER_DUP_KEYNAME') {
            console.warn('pages 인덱스 생성 중 경고:', error.message);
        }
    }

    // pages 테이블 인덱스 (사용자별 최신 페이지 조회 최적화)
    try {
        await pool.execute(`
            CREATE INDEX IF NOT EXISTS idx_pages_user_updated
            ON pages(user_id, updated_at DESC)
        `);
        console.log('✓ pages.user_id, updated_at 인덱스 생성 완료');
    } catch (error) {
        if (error.code !== 'ER_DUP_KEYNAME') {
            console.warn('pages 인덱스 생성 중 경고:', error.message);
        }
    }

    // pages 테이블 인덱스 (하위 페이지 정렬 최적화)
    try {
        await pool.execute(`
            CREATE INDEX IF NOT EXISTS idx_pages_parent_sort
            ON pages(parent_id, sort_order)
        `);
        console.log('✓ pages.parent_id, sort_order 인덱스 생성 완료');
    } catch (error) {
        if (error.code !== 'ER_DUP_KEYNAME') {
            console.warn('pages 인덱스 생성 중 경고:', error.message);
        }
    }

    // collections 테이블 인덱스 (사용자별 컬렉션 조회 최적화)
    try {
        await pool.execute(`
            CREATE INDEX IF NOT EXISTS idx_collections_user_sort
            ON collections(user_id, sort_order, updated_at DESC)
        `);
        console.log('✓ collections.user_id, sort_order 인덱스 생성 완료');
    } catch (error) {
        if (error.code !== 'ER_DUP_KEYNAME') {
            console.warn('collections 인덱스 생성 중 경고:', error.message);
        }
    }
}

/**
 * 사용자별 기본 컬렉션을 생성하고, collection_id 가 비어있는 페이지에 할당
 */
async function backfillCollections() {
    const [users] = await pool.execute(`SELECT id, username FROM users`);

    for (const user of users) {
        const userId = user.id;

        // 사용자 컬렉션 존재 여부 확인
        const [existingCols] = await pool.execute(
            `SELECT id FROM collections WHERE user_id = ? ORDER BY sort_order ASC, updated_at DESC LIMIT 1`,
            [userId]
        );

        let collectionId = existingCols.length ? existingCols[0].id : null;

        // 없으면 기본 컬렉션 생성
        if (!collectionId) {
            const now = new Date();
            const nowStr = formatDateForDb(now);
            collectionId = generateCollectionId(now);

            await pool.execute(
                `
                INSERT INTO collections (id, user_id, name, sort_order, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                `,
                [collectionId, userId, "기본 컬렉션", 0, nowStr, nowStr]
            );
        }

        // collection_id 가 비어있는 페이지에 기본 컬렉션 할당
        await pool.execute(
            `
            UPDATE pages
            SET collection_id = ?
            WHERE user_id = ? AND (collection_id IS NULL OR collection_id = '')
            `,
            [collectionId, userId]
        );
    }
}

/**
 * 사용자별 컬렉션 순서 구하기
 */
async function getNextCollectionSortOrder(userId) {
    const [rows] = await pool.execute(
        `SELECT COALESCE(MAX(sort_order), -1) AS maxOrder FROM collections WHERE user_id = ?`,
        [userId]
    );
    return Number(rows[0].maxOrder) + 1;
}

/**
 * 컬렉션 접근 권한 확인
 * @param {string} collectionId - 컬렉션 ID
 * @param {number} userId - 사용자 ID
 * @returns {Promise<{permission: string|null, isOwner: boolean}>}
 */
async function getCollectionPermission(collectionId, userId) {
    // 1. 소유자 확인
    const [ownerRows] = await pool.execute(
        `SELECT id FROM collections WHERE id = ? AND user_id = ?`,
        [collectionId, userId]
    );

    if (ownerRows.length > 0) {
        return { permission: 'ADMIN', isOwner: true };
    }

    // 2. 직접 공유 확인
    const [shareRows] = await pool.execute(
        `SELECT permission FROM collection_shares
         WHERE collection_id = ? AND shared_with_user_id = ?`,
        [collectionId, userId]
    );

    if (shareRows.length > 0) {
        return { permission: shareRows[0].permission, isOwner: false };
    }

    return { permission: null, isOwner: false };
}

/**
 * 공유 불가능한 암호화 페이지 존재 여부 확인
 * @param {string} collectionId - 컬렉션 ID
 * @returns {Promise<boolean>}
 */
async function hasEncryptedPages(collectionId) {
    const [rows] = await pool.execute(
        `SELECT COUNT(*) as count FROM pages
         WHERE collection_id = ? AND is_encrypted = 1 AND share_allowed = 0`,
        [collectionId]
    );
    return rows[0].count > 0;
}

/**
 * 공유 링크 토큰 생성
 * @returns {string} - 64자 hex 문자열
 */
function generateShareToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * 페이지 발행 토큰 생성
 */
function generatePublishToken() {
    return crypto.randomBytes(32).toString('hex');
}

/**
 * 새 컬렉션 생성
 */
async function createCollection({ userId, name }) {
    const now = new Date();
    const nowStr = formatDateForDb(now);
    const id = generateCollectionId(now);
    const sortOrder = await getNextCollectionSortOrder(userId);

    await pool.execute(
        `
        INSERT INTO collections (id, user_id, name, sort_order, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        `,
        [id, userId, name, sortOrder, nowStr, nowStr]
    );

    return {
        id,
        name,
        sortOrder,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
        isOwner: true,
        permission: 'OWNER'
    };
}

/**
 * 레이트 리밋 설정
 */
// 일반 API 레이트 리밋 (창당 100 요청)
const generalLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1분
    max: 100, // 최대 100 요청
    message: { error: "너무 많은 요청이 발생했습니다. 잠시 후 다시 시도해 주세요." },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET)
});

// 로그인/회원가입 레이트 리밋 (브루트포스 방지)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 5, // 최대 5번 시도
    message: { error: "너무 많은 로그인 시도가 발생했습니다. 15분 후 다시 시도해 주세요." },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET),
    skipSuccessfulRequests: true, // 성공한 요청은 카운트하지 않음
});

// TOTP 인증 레이트 리밋 (브루트포스 방지)
const totpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 10, // 최대 10번 시도
    message: { error: "너무 많은 인증 시도가 발생했습니다. 15분 후 다시 시도해 주세요." },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET)
});

// 패스키 인증 레이트 리밋 (브루트포스 방지)
const passkeyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 10, // 최대 10번 시도
    message: { error: "너무 많은 패스키 인증 요청이 발생했습니다. 잠시 후 다시 시도해 주세요." },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET)
});

// SSE 연결 레이트 리밋
const sseConnectionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 50, // 사용자당 최대 50개 연결
    message: { error: "SSE 연결 제한 초과" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => (req.user?.id ? `user:${req.user.id}` : ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET))
});

// 외부 fetch(프록시/메타데이터) 전용 레이트 리밋
const outboundFetchLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 20,
    message: { error: "외부 리소스 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요." },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => (req.user?.id ? `user:${req.user.id}` : ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET))
});

// WebSocket 및 실시간 동기화 기능은 websocket-server.js 모듈로 이동됨

/**
 * 미들웨어 설정
 */

// 보안: JSON 바디 크기 제한(DoS 완화)
// 필요하면 .env에서 JSON_BODY_LIMIT=2mb 등으로 조정
const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "1mb";
app.use(express.json({ limit: JSON_BODY_LIMIT }));

// urlencoded를 쓰는 폼 요청이 있다면 함께 제한(없으면 유지해도 무방)
app.use(express.urlencoded({ extended: false, limit: JSON_BODY_LIMIT }));
app.use(cookieParser());

// 정보 노출 완화 (헤더 불필요한 정보 제거)
app.disable("x-powered-by");

// CSP nonce 생성 (요청마다 새로 발급)
app.use((req, res, next) => {
	req.clientIp = getClientIp(req);
	res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
	next();
});

// 보안 개선: 기본 보안 헤더 추가 (XSS, 클릭재킹 방지 등)
app.use((req, res, next) => {
    // 보안 개선: CSP 강화 - unsafe-inline 제거 권장
    // 참고: 모든 인라인 스타일을 외부 CSS로 이동하면 'unsafe-inline' 제거 가능
    // -> nonce 기반 CSP로 전환
    const nonce = res.locals.cspNonce;
    res.setHeader(
        "Content-Security-Policy",
		"default-src 'self'; " +
		"base-uri 'self'; " +
        "object-src 'none'; " +
        "frame-ancestors 'none'; " +
        "frame-src 'self' https://www.youtube.com https://youtube.com; " +
        "form-action 'self'; " +
        `script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net https://esm.sh; ` +
        "style-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; " +
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self' https://cdn.jsdelivr.net https://esm.sh;"
    );

    // 추가 보안 헤더
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    // X-XSS-Protection은 구식이며 CSP로 충분히 대체됨 (제거)
	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

	// Permissions Policy (필요 시 허용 목록으로 조정)
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    // HSTS (HTTPS에서만, production 권장)
    if (IS_PRODUCTION)
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');

	next();
});

// CSRF 토큰 쿠키 설정 미들웨어 (모든 요청에 대해)
app.use((req, res, next) => {
    // CSRF 쿠키가 없으면 생성
    if (!req.cookies[CSRF_COOKIE_NAME]) {
        const token = generateCsrfToken();
        res.cookie(CSRF_COOKIE_NAME, token, {
            httpOnly: false, // JavaScript에서 읽을 수 있어야 함
            sameSite: "strict",
            secure: IS_PRODUCTION,  // 보안 개선: 환경에 따라 설정
            maxAge: SESSION_TTL_MS
        });
    }
    next();
});

// CSRF 검증 미들웨어 (API 엔드포인트에만 적용)
app.use("/api", csrfMiddleware);

// 일반 API 레이트 리밋 적용
app.use("/api", generalLimiter);

// 정적 자산 캐싱 설정 (성능 최적화)
app.use(express.static(path.join(__dirname, "public"), {
    index: false,
    maxAge: IS_PRODUCTION ? '7d' : 0, // 프로덕션: 7일, 개발: 캐시 안 함
    etag: true, // ETag 활성화 (변경 감지)
    lastModified: true, // Last-Modified 헤더 추가
    immutable: IS_PRODUCTION, // Cache-Control: immutable 추가 (프로덕션만)
    setHeaders: (res, filePath, stat) => {
        // HTML 파일은 캐시 안 함 (동적 업데이트 필요)
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
        // JS/CSS는 적극적으로 캐싱
        else if (filePath.endsWith('.js') || filePath.endsWith('.css')) {
            res.setHeader('Cache-Control', IS_PRODUCTION
                ? 'public, max-age=604800, immutable' // 7일, 불변
                : 'no-cache');
        }
        // 이미지/폰트는 장기 캐싱
        else if (filePath.match(/\.(jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=2592000, immutable'); // 30일
        }
    }
}));

// Serve themes statically
app.use('/themes', express.static(path.join(__dirname, 'themes')));

// 언어 파일 정적 서빙
app.use('/languages', express.static(path.join(__dirname, 'languages')));

// 보안 개선: 정적 파일 접근 제어 (인증된 사용자만 접근 가능)
// 기본 커버 이미지는 인증 없이 접근 가능
app.use('/covers/default', express.static(path.join(__dirname, 'covers', 'default')));

// 사용자별 커버 이미지 - 인증 필요
app.get('/covers/:userId/:filename', authMiddleware, async (req, res) => {
	const requestedUserId = parseInt(req.params.userId, 10);

	if (!Number.isFinite(requestedUserId))
		return res.status(400).json({ error: '잘못된 요청입니다.' });

	const filename = req.params.filename;
    const currentUserId = req.user.id;

    try {
        // 파일명 새니타이제이션 (경로 조작 방지)
        const sanitizedFilename = path.basename(filename);
        const filePath = path.join(__dirname, 'covers', String(requestedUserId), sanitizedFilename);

        // 파일 존재 확인
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '파일을 찾을 수 없습니다.' });
        }

        // 권한 확인: 본인 파일이거나, 공유받은 페이지의 커버인 경우
        if (requestedUserId === currentUserId) {
            // 본인 파일 - 접근 허용
            return res.sendFile(filePath);
        }

        // 다른 사용자의 파일 - (1) 현재 사용자가 접근 가능한 컬렉션인지
        // (2) 파일 소유자(requestedUserId) 또한 그 컬렉션의 참여자인지 검증
        const coverPath = `${requestedUserId}/${sanitizedFilename}`;
        const [rows] = await pool.execute(
            `SELECT p.id
                FROM pages p
                JOIN collections c ON p.collection_id = c.id
                LEFT JOIN collection_shares cs_cur ON c.id = cs_cur.collection_id AND cs_cur.shared_with_user_id = ?
                LEFT JOIN collection_shares cs_req ON c.id = cs_req.collection_id AND cs_req.shared_with_user_id = ?
                WHERE p.cover_image = ?
                AND (c.user_id = ? OR cs_cur.shared_with_user_id IS NOT NULL)
                AND (c.user_id = ? OR cs_req.shared_with_user_id IS NOT NULL)
                LIMIT 1`,
            [currentUserId, requestedUserId, coverPath, currentUserId, requestedUserId]
        );

        if (rows.length > 0) {
            // 공유받은 페이지의 커버 - 접근 허용
            return res.sendFile(filePath);
        }

        // 권한 없음
        console.warn(`[보안] 사용자 ${currentUserId}이(가) 권한 없이 커버 이미지 접근 시도: ${coverPath}`);
        return res.status(403).json({ error: '접근 권한이 없습니다.' });

    } catch (error) {
        logError('GET /covers/:userId/:filename', error);
        res.status(500).json({ error: '파일 로드 실패' });
    }
});

// 에디터 이미지 - 인증 필요
app.get('/imgs/:userId/:filename', authMiddleware, async (req, res) => {
	const requestedUserId = parseInt(req.params.userId, 10);

	if (!Number.isFinite(requestedUserId))
		return res.status(400).json({ error: '잘못된 요청입니다.' });

	const filename = req.params.filename;
    const currentUserId = req.user.id;

    try {
        // 파일명 새니타이제이션 (경로 조작 방지)
        const sanitizedFilename = path.basename(filename);
        const filePath = path.join(__dirname, 'imgs', String(requestedUserId), sanitizedFilename);

        // 파일 존재 확인
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '파일을 찾을 수 없습니다.' });
        }

        // 권한 확인: 본인 파일이거나, 공유받은 페이지의 이미지인 경우
        if (requestedUserId === currentUserId) {
            // 본인 파일 - 접근 허용
            return res.sendFile(filePath);
        }

        // 다른 사용자의 파일 - 공유받은 페이지의 이미지인지 확인
        const imagePath = `${requestedUserId}/${sanitizedFilename}`;
        const imageUrl = `/imgs/${imagePath}`;

        // LIKE 와일드카드(%, _) 및 \\ 이스케이프 (패턴 오인 방지)
        const escapeLike = (s) => String(s).replace(/[\\%_]/g, (m) => `\\${m}`);
        const likePattern = `%${escapeLike(imageUrl)}%`;

        // 이미지가 포함된 페이지가 공유되었는지 확인
        const [rows] = await pool.execute(
            `SELECT p.id
	            FROM pages p
	            JOIN collections c ON p.collection_id = c.id
	            LEFT JOIN collection_shares cs_cur ON c.id = cs_cur.collection_id AND cs_cur.shared_with_user_id = ?
	            WHERE p.content LIKE ? ESCAPE '\\\\'
	            AND (c.user_id = ? OR cs_cur.shared_with_user_id IS NOT NULL)
	            -- 보안패치 : 이미지 소유자가 실제로 참여/생성한 페이지 or 컬렉션에서만 허용
	            AND (p.user_id = ? OR c.user_id = ?)
	            LIMIT 1`,
            [currentUserId, likePattern, currentUserId, requestedUserId, requestedUserId]
        );

        if (rows.length > 0) {
            // 공유받은 페이지의 이미지 - 접근 허용
            return res.sendFile(filePath);
        }

        // 권한 없음
        console.warn(`[보안] 사용자 ${currentUserId}이(가) 권한 없이 이미지 접근 시도: ${imagePath}`);
        return res.status(403).json({ error: '접근 권한이 없습니다.' });

    } catch (error) {
        logError('GET /imgs/:userId/:filename', error);
        res.status(500).json({ error: '파일 로드 실패' });
    }
});

/**
 * multer 설정 (커버 이미지 업로드)
 */
const coverStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.user.id;
        const userCoverDir = path.join(__dirname, 'covers', String(userId));
        fs.mkdirSync(userCoverDir, { recursive: true });
        cb(null, userCoverDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const coverUpload = multer({
    storage: coverStorage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('이미지 파일만 업로드 가능합니다 (jpg, png, gif, webp)'));
        }
    }
});

// 에디터 이미지 업로드를 위한 multer 설정
const editorImageStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.user.id;
        const userImgDir = path.join(__dirname, 'imgs', String(userId));
        fs.mkdirSync(userImgDir, { recursive: true });
        cb(null, userImgDir);
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const editorImageUpload = multer({
    storage: editorImageStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif|webp/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('이미지 파일만 업로드 가능합니다 (jpg, png, gif, webp)'));
        }
    }
});

// 테마 업로드를 위한 multer 설정
const themeStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const themesDir = path.join(__dirname, 'themes');
        fs.mkdirSync(themesDir, { recursive: true });
        cb(null, themesDir);
    },
    filename: (req, file, cb) => {
        // Sanitize filename
        const sanitizedFilename = path.basename(file.originalname, '.css').replace(/[^a-zA-Z0-9-]/g, '') + '.css';
        cb(null, sanitizedFilename);
    }
});

const themeUpload = multer({
    storage: themeStorage,
    limits: { fileSize: 100 * 1024 }, // 100KB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /css/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = file.mimetype === 'text/css';
        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('CSS 파일만 업로드 가능합니다.'));
        }
    }
});

/**
 * WebSocket용 세션 검증 헬퍼
 * - getSessionFromRequest()와 동일한 만료/idle 갱신 로직을 재사용
 */
function getSessionFromId(sessionId) {
    if (!sessionId) return null;
    // getSessionFromRequest는 req.cookies만 사용하므로 최소 객체로 호출
    return getSessionFromRequest({ cookies: { [SESSION_COOKIE_NAME]: sessionId } });
}

// WebSocket Rate Limiting, 서버 초기화, 메시지 핸들러 등은 websocket-server.js 모듈로 이동됨

/**
 * 서버 시작 (HTTPS 자동 설정)
 */
(async () => {
    try {
        await initDb();

        // 로그인 로그 정리 작업 시작 (pool 초기화 후)
        setInterval(cleanupOldLoginLogs, 24 * 60 * 60 * 1000);
        cleanupOldLoginLogs();

        // ==================== 라우트 Import (DB 초기화 후) ====================

        /**
         * 각 라우트 파일에 필요한 의존성들을 주입합니다.
         * pool이 initDb()에서 생성되므로, DB 초기화 이후에 라우트를 등록합니다.
         */
        const routeDependencies = {
            pool,
            bcrypt,
            crypto,
            express,
            Y,
            speakeasy,
            QRCode,
            sessions,
            userSessions,
            createSession,
            getSessionFromRequest,
            generateCsrfToken,
            formatDateForDb,
            validatePasswordStrength,
            logError,
            authMiddleware,
            csrfMiddleware,
            toIsoString,
            sanitizeInput,
            sanitizeHtmlContent,
            generatePageId,
            generateCollectionId,
            createCollection,
            getCollectionPermission,
            hasEncryptedPages,
            generateShareToken,
            generatePublishToken,
            // WebSocket 관련 (websocket-server.js 모듈에서 import)
            wsConnections,
            wsBroadcastToPage,
            wsBroadcastToCollection,
			wsBroadcastToUser,
			wsCloseConnectionsForSession,
            saveYjsDocToDatabase,
            yjsDocuments,
            authLimiter,
            totpLimiter,
            passkeyLimiter,
            outboundFetchLimiter,
            sseConnectionLimiter,
            SESSION_COOKIE_NAME,
            CSRF_COOKIE_NAME,
            SESSION_TTL_MS,
            IS_PRODUCTION,
            BCRYPT_SALT_ROUNDS,
            BASE_URL,
            coverUpload,
            editorImageUpload,
            themeUpload,
            path,
            fs,
            // 네트워크 관련 (network-utils.js 모듈에서 import)
            recordLoginAttempt,
            getLocationFromIP,
            maskIPAddress,
            isPrivateOrLocalIP,
            checkCountryWhitelist,
            getClientIpFromRequest
        };

        // 라우트 파일 Import
        const indexRoutes = require('./routes/index')(routeDependencies);
        const authRoutes = require('./routes/auth')(routeDependencies);
        const collectionsRoutes = require('./routes/collections')(routeDependencies);
        const pagesRoutes = require('./routes/pages')(routeDependencies);
        const bootstrapRoutes = require('./routes/bootstrap')(routeDependencies);
        const sharesRoutes = require('./routes/shares')(routeDependencies);
        const totpRoutes = require('./routes/totp')(routeDependencies);
        const passkeyRoutes = require('./routes/passkey')(routeDependencies);
        const backupRoutes = require('./routes/backup')(routeDependencies);
        const themesRoutes = require('./routes/themes')(routeDependencies);

        // 라우트 등록
        app.use('/', indexRoutes);
        app.use('/api/auth', authRoutes);
        app.use('/api/collections', collectionsRoutes);
        app.use('/api/pages', pagesRoutes);
        app.use('/api/bootstrap', bootstrapRoutes);
        app.use('/api', sharesRoutes);
        app.use('/api/totp', totpRoutes);
        app.use('/api/passkey', passkeyRoutes);
        app.use('/api/backup', backupRoutes);
        app.use('/api/themes', themesRoutes);

        // DuckDNS 설정 확인
        const DUCKDNS_DOMAIN = process.env.DUCKDNS_DOMAIN;
        const DUCKDNS_TOKEN = process.env.DUCKDNS_TOKEN;
        const CERT_EMAIL = process.env.CERT_EMAIL || 'admin@example.com';

        // HTTPS 설정이 있는 경우
        if (DUCKDNS_DOMAIN && DUCKDNS_TOKEN) {
            console.log('\n' + '='.repeat(80));
            console.log('🔐 HTTPS 모드로 시작합니다.');
            console.log(`   도메인: ${DUCKDNS_DOMAIN}`);
            console.log('='.repeat(80) + '\n');

            try {
                // Let's Encrypt 인증서 발급/로드
                const certData = await certManager.getCertificate(
                    DUCKDNS_DOMAIN,
                    DUCKDNS_TOKEN,
                    CERT_EMAIL
                );

                // HTTPS 서버 생성
                const httpsOptions = {
                    key: certData.key,
                    cert: certData.cert
                };

                const httpsServer = https.createServer(httpsOptions, app);

                httpsServer.listen(PORT, () => {
                    console.log('\n' + '='.repeat(80));
                    console.log(`✅ NTEOK 서버가 HTTPS로 실행 중`);
                    console.log(`   URL: https://${DUCKDNS_DOMAIN}:${PORT}`);
                    console.log('='.repeat(80) + '\n');
                });

                // WebSocket 서버 초기화
                initWebSocketServer(httpsServer, sessions, getCollectionPermission, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId);

                // WebSocket Rate Limit 정리 작업 시작
                startRateLimitCleanup();

                // 비활성 연결 정리 작업 시작
                startInactiveConnectionsCleanup(pool, sanitizeHtmlContent);

                // HTTP -> HTTPS 리다이렉트 서버 (포트 80)
                if (process.env.ENABLE_HTTP_REDIRECT === 'true') {
                    const HTTP_REDIRECT_PORT = 80;
                    const redirectApp = express();

                    redirectApp.use((req, res) => {
                        const httpsUrl = `https://${DUCKDNS_DOMAIN}${PORT !== 443 ? ':' + PORT : ''}${req.url}`;
                        res.redirect(301, httpsUrl);
                    });

                    http.createServer(redirectApp).listen(HTTP_REDIRECT_PORT, () => {
                        console.log(`🔄 HTTP -> HTTPS 리다이렉트 활성화 (포트 ${HTTP_REDIRECT_PORT})`);
                    });
                }

                // 인증서 자동 갱신 스케줄러
                certManager.scheduleRenewal(DUCKDNS_DOMAIN, DUCKDNS_TOKEN, CERT_EMAIL, (newCert) => {
                    console.log('\n' + '='.repeat(80));
                    console.log('🔄 인증서가 갱신되었습니다.');
                    console.log('⚠️  서버를 재시작하여 새 인증서를 적용해주세요.');
                    console.log('='.repeat(80) + '\n');
                });

            } catch (certError) {
                console.error('\n' + '='.repeat(80));
                console.error('❌ HTTPS 인증서 발급 실패. HTTP 모드로 폴백합니다.');
                console.error(`   오류: ${certError.message}`);
                console.error('='.repeat(80) + '\n');

                // HTTP 모드로 폴백
                const httpServer = app.listen(PORT, () => {
                    console.log(`⚠️  NTEOK 앱이 HTTP로 실행 중: http://localhost:${PORT}`);
                });

                // WebSocket 서버 초기화
                // HTTP 모드에서도 WebSocket 메시지 처리 시 세션 검증 로직(getSessionFromId)을 사용해야
                // 동기화 메시지가 "Session expired"로 오판되어 연결이 반복 종료되는 문제를 방지할 수 있습니다.
                initWebSocketServer(httpServer, sessions, getCollectionPermission, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId);

                // WebSocket Rate Limit 정리 작업 시작
                startRateLimitCleanup();

                // 비활성 연결 정리 작업 시작
                startInactiveConnectionsCleanup(pool, sanitizeHtmlContent);
            }
        } else {
            // HTTPS 설정이 없는 경우 - HTTP 모드
            console.log('\n' + '='.repeat(80));
            console.log('ℹ️  HTTPS 설정이 없습니다. HTTP 모드로 시작합니다.');
            console.log('   HTTPS를 사용하려면 .env 파일에 다음을 추가하세요:');
            console.log('   - DUCKDNS_DOMAIN=your-domain.duckdns.org');
            console.log('   - DUCKDNS_TOKEN=your-duckdns-token');
            console.log('='.repeat(80) + '\n');

            const httpServer = app.listen(PORT, () => {
                console.log(`NTEOK 앱이 HTTP로 실행 중: http://localhost:${PORT}`);
            });

            // WebSocket 서버 초기화
            // HTTP 모드에서도 WebSocket 메시지 처리 시 세션 검증 로직(getSessionFromId)을 사용해야
            // 동기화 메시지가 "Session expired"로 오판되어 연결이 반복 종료되는 문제를 방지할 수 있습니다.
            initWebSocketServer(httpServer, sessions, getCollectionPermission, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId);

            // WebSocket Rate Limit 정리 작업 시작
            startRateLimitCleanup();

            // 비활성 연결 정리 작업 시작
            startInactiveConnectionsCleanup(pool, sanitizeHtmlContent);
        }

    } catch (error) {
        console.error("서버 시작 중 치명적 오류:", error);
        process.exit(1);
    }
})();
