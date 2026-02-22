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
const { installDomPurifySecurityHooks, assertImageFileSignature } = require("./security-utils");
const ipKeyGenerator = expressRateLimit.ipKeyGenerator || (expressRateLimit.default && expressRateLimit.default.ipKeyGenerator);

// DOMPurify 보안 훅 설치 (target=_blank에 rel=noopener/noreferrer 강제 등)
installDomPurifySecurityHooks(DOMPurify);

// DOMPurify 추가 방어: data-url/data-thumbnail 스킴 검증
// 북마크 블록은 data-url/data-thumbnail에 URL을 저장했다가, 클라이언트에서 <a href> / 이미지 프록시로 승격
// href/src는 DOMPurify가 기본적으로 URI 검증을 하지만, data-*는 보통 검증 대상이 아니라서 별도 방어 필요
const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
function isSafeHttpUrlOrRelative(value) {
    if (typeof value !== "string") return false;
    const v = value.trim();
    if (!v) return false;
    if (CONTROL_CHARS_RE.test(v)) return false;
    // 상대 URL 허용(필요 없으면 제거 가능)
    // 주의: //evil.com 같은 protocol-relative URL은 외부로 탈출하므로 차단
    if (v.startsWith("//")) return false;
    if (v.startsWith("/") || v.startsWith("#")) return true;
    try {
        const u = new URL(v);
        return u.protocol === "http:" || u.protocol === "https:";
    } catch {
        return false;
    }
}

// 보안: data-src(특히 YouTube 블록) 값은 DOMPurify의 기본 URI 검증 대상이 아니므로 별도 검증이 필요
// - 이 앱은 <div data-type="youtube" data-src="..."></div> 형태로 URL을 저장한 뒤, 클라이언트에서 iframe.src 로 승격(render)
// - 따라서 data-src에 javascript:/data: 등의 위험 스킴이 섞이면 저장형 XSS로 이어질 수 있음
const YOUTUBE_ALLOWED_HOSTS = new Set([
    'youtube.com',
    'www.youtube.com',
    'm.youtube.com',
    'youtu.be',
    'youtube-nocookie.com',
    'www.youtube-nocookie.com'
]);

function parseYoutubeStartSeconds(u) {
    // start=123 또는 t=123 / t=1m30s 정도만 보수적으로 지원
    const startRaw = u.searchParams.get('start') || u.searchParams.get('t') || '';
    if (!startRaw) return null;

    if (/^\d+$/.test(startRaw)) {
        const n = parseInt(startRaw, 10);
        return Number.isFinite(n) && n > 0 && n < 24 * 60 * 60 ? n : null;
    }

    const m = String(startRaw).toLowerCase().match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
    if (!m) return null;
    const h = m[1] ? parseInt(m[1], 10) : 0;
    const mm = m[2] ? parseInt(m[2], 10) : 0;
    const s = m[3] ? parseInt(m[3], 10) : 0;
    const total = h * 3600 + mm * 60 + s;
    return Number.isFinite(total) && total > 0 && total < 24 * 60 * 60 ? total : null;
}

function normalizeYouTubeEmbedUrl(value) {
    if (typeof value !== 'string') return null;
    const v = value.trim();
    if (!v) return null;
    if (CONTROL_CHARS_RE.test(v)) return null;

    let u;
    try { u = new URL(v); } catch { return null; }

    if (!(u.protocol === 'http:' || u.protocol === 'https:')) return null;

    const host = u.hostname.toLowerCase();
    if (!YOUTUBE_ALLOWED_HOSTS.has(host)) return null;

    let videoId = null;
    if (host === 'youtu.be') videoId = u.pathname.split('/').filter(Boolean)[0] || null;
    else if (u.pathname.startsWith('/embed/')) videoId = u.pathname.split('/').filter(Boolean)[1] || null;
    else if (u.pathname === '/watch') videoId = u.searchParams.get('v');
    else if (u.pathname.startsWith('/shorts/')) videoId = u.pathname.split('/').filter(Boolean)[1] || null;

    if (!videoId || !/^[A-Za-z0-9_-]{11}$/.test(videoId)) return null;

    const out = new URL(`https://www.youtube-nocookie.com/embed/${videoId}`);
    const start = parseYoutubeStartSeconds(u);
    if (start) out.searchParams.set('start', String(start));
    return out.toString();
}

if (typeof DOMPurify?.addHook === "function") {
    DOMPurify.addHook("uponSanitizeAttribute", (_node, hookEvent) => {
        const name = String(hookEvent?.attrName || "").toLowerCase();
        if (name === "data-url" || name === "data-thumbnail") {
            if (!isSafeHttpUrlOrRelative(String(hookEvent.attrValue || ""))) {
                hookEvent.keepAttr = false;
                hookEvent.forceKeepAttr = false;
            }
        }

        // data-src는 DOMPurify 기본 URI 검증 대상이 아니므로 별도 검증 필요
        // - file-block: data-src를 클릭 시 window.open()에 사용(저장형 XSS/피싱 sink)
        // - image-with-caption: data-src를 img.src로 승격
        // - youtube-block: data-src를 iframe.src로 승격 (도메인/형식 엄격 검증)
        if (name === "data-src") {
            const nodeType = String(_node?.getAttribute?.('data-type') || '').toLowerCase();
            const raw = String(hookEvent.attrValue || "");

            // YouTube는 허용 도메인/경로로 정규화 (fail-closed)
            if (nodeType === "youtube-block" || nodeType === "youtube") {
                const safe = normalizeYouTubeEmbedUrl(raw);
                if (!safe) {
                    hookEvent.keepAttr = false;
                    hookEvent.forceKeepAttr = false;
                } else {
                    hookEvent.attrValue = safe;
                }
                return;
            }

            // 일반적인 data-src는 http(s) 또는 안전한 상대경로만 허용
            if (!isSafeHttpUrlOrRelative(raw)) {
                hookEvent.keepAttr = false;
                hookEvent.forceKeepAttr = false;
                return;
            }

            // file-block는 내부 첨부(/paperclip/<userId>/<storedFilename>)만 허용
            // - 과거처럼 "/paperclip/" prefix만 확인하면 "/paperclip/../server.js" 같은 경로 조작이 가능
            // - storedFilename은 서버가 생성한 안전한 파일명(디렉터리 구분자/.. 없음)이어야 함
            if (nodeType === "file-block") {
                // 프로토콜/스킴 공격(//evil.com) 차단은 위 isSafeHttpUrlOrRelative에서 처리
                // 여기서는 path traversal 방지 목적의 엄격 allowlist 적용
                const m = raw.match(/^\/paperclip\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/);
                if (!m) {
                    hookEvent.keepAttr = false;
                    hookEvent.forceKeepAttr = false;
                    return;
                }
                const filename = m[2];
                // 이중 점(../, ..\) 및 제어문자 등 추가 방어
                if (!filename || filename.includes('..') || /[\x00-\x1F\x7F]/.test(filename)) {
                    hookEvent.keepAttr = false;
                    hookEvent.forceKeepAttr = false;
                    return;
                }
            }
        }
    });
}

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
    wsBroadcastToStorage,
	wsBroadcastToUser,
    startRateLimitCleanup,
    startInactiveConnectionsCleanup,
    wsConnections,
    yjsDocuments,
	saveYjsDocToDatabase,
	wsCloseConnectionsForSession,
    wsKickUserFromStorage
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
const SESSION_COOKIE_NAME_RAW = "nteok_session";
const CSRF_COOKIE_NAME_RAW = "nteok_csrf";

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7일 (idle timeout)
const SESSION_ABSOLUTE_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7일 (absolute timeout)

const IS_PRODUCTION = process.env.NODE_ENV === "production";
const BASE_URL = process.env.BASE_URL || (IS_PRODUCTION ? "https://localhost:3000" : "http://localhost:3000");

// 보안: Secure 쿠키/HSTS 활성 여부를 NODE_ENV가 아닌 실제 HTTPS 운영 여부로 판단
// - NODE_ENV 누락(=production 미설정) 상태에서도 HTTPS 운영 시 세션 쿠키가 HTTP로 노출되는 문제 방지
const IS_HTTPS_BASE_URL = (() => {
    try { return new URL(BASE_URL).protocol === "https:"; }
    catch { return /^https:\/\//i.test(String(BASE_URL)); }
})();

/**
 * HTTPS 강제 옵션
 * - 프로덕션에서 인증서 발급/로드가 실패했을 때 HTTP로 조용히 폴백하면, 평문 전송(자격증명/세션 탈취) 위험이 매우 큼
 * - 기본값(안전): 프로덕션에서는 HTTPS 실패 시 서버 시작을 중단(fail-closed)
 * - 예외적으로(긴급 대응 등) HTTP 폴백이 필요하면 ALLOW_INSECURE_HTTP_FALLBACK=true 로 명시적으로 허용
 * - REQUIRE_HTTPS=true 를 켜면 개발 환경에서도 동일하게 fail-closed로 동작
 */
const REQUIRE_HTTPS = String(process.env.REQUIRE_HTTPS || '').toLowerCase() === 'true';

const COOKIE_SECURE = IS_HTTPS_BASE_URL || REQUIRE_HTTPS;

// 보안: __Host- prefix 적용 (Secure + Path=/ + No Domain)
// - HTTPS 환경일 때만 적용 가능 (prefix 요구사항)
const SESSION_COOKIE_NAME = COOKIE_SECURE ? `__Host-${SESSION_COOKIE_NAME_RAW}` : SESSION_COOKIE_NAME_RAW;
const CSRF_COOKIE_NAME = COOKIE_SECURE ? `__Host-${CSRF_COOKIE_NAME_RAW}` : CSRF_COOKIE_NAME_RAW;

const ENABLE_HSTS = String(process.env.ENABLE_HSTS ?? "true").toLowerCase() !== "false";
function isLocalhostHost(host) {
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

const HSTS_ENABLED = (() => {
    if (!COOKIE_SECURE || !ENABLE_HSTS) return false;
    try { return !isLocalhostHost(new URL(BASE_URL).hostname); }
    catch { return false; }
})();

const ALLOW_INSECURE_HTTP_FALLBACK = String(process.env.ALLOW_INSECURE_HTTP_FALLBACK || '').toLowerCase() === 'true';

// TOTP 비밀키 (2FA) 최소 암호화
// - TOTP 공유 비밀키를 DB에 평문 저장하면, DB 유출 시 2FA가 즉시 무력화됨
// - 해결: AES-256-GCM(AEAD)으로 암호화하여 저장 + 키는 환경변수/시크릿 매니저로 분리
function decode32ByteKey(raw) {
    if (!raw) return null;
    const s = String(raw).trim();
    if (!s) return null;
    // 64-hex(32 bytes)
    if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, "hex");
    // base64(32 bytes)
    try {
        const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
        const buf = Buffer.from(b64, "base64");
        if (buf.length === 32) return buf;
    } catch {}
    return null;
}

const _decodedTotpSecretKey = decode32ByteKey(process.env.TOTP_SECRET_ENC_KEY);
const TOTP_SECRET_ENC_KEY = _decodedTotpSecretKey || (!IS_PRODUCTION ? crypto.randomBytes(32) : null);

if (!_decodedTotpSecretKey) {
    if (IS_PRODUCTION) {
        console.error("❌ [SECURITY] TOTP_SECRET_ENC_KEY가 설정되지 않았습니다. (프로덕션에서는 필수)");
        process.exit(1);
    } else {
        console.warn("⚠️  [SECURITY] TOTP_SECRET_ENC_KEY가 없어 임시 키로 동작합니다. 재시작 시 기존 2FA 복호화가 불가능할 수 있습니다.");
    }
}

function encryptTotpSecret(plainBase32) {
    if (!plainBase32) return null;
    if (!TOTP_SECRET_ENC_KEY)
        throw new Error("TOTP_SECRET_ENC_KEY 누락 -> TOTP 비밀키를 암호화 할 수 없습니다");

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", TOTP_SECRET_ENC_KEY, iv);
    const ciphertext = Buffer.concat([cipher.update(String(plainBase32), "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${ciphertext.toString("base64")}`;
}

function decryptTotpSecret(storedValue) {
    if (!storedValue) return null;
    const s = String(storedValue);

    // 레거시(평문 base32) 호환
    if (!s.startsWith("v1:")) return s;
    if (!TOTP_SECRET_ENC_KEY)
        throw new Error("TOTP_SECRET_ENC_KEY 누락 -> TOTP 비밀키를 복호화 할 수 없습니다");

    const parts = s.split(":");
    if (parts.length !== 4)
    	throw new Error("유효하지 않은 암호화 TOTP 비밀키 형식");

    const iv = Buffer.from(parts[1], "base64");
    const tag = Buffer.from(parts[2], "base64");
    const data = Buffer.from(parts[3], "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", TOTP_SECRET_ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

// 보안 개선: 기본 관리자 계정 비밀번호를 강제로 변경하도록 경고
// 운영(PROD)에서는 ADMIN_PASSWORD 미설정 상태로 부팅하지 않도록 fail-closed 처리
const DEFAULT_ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";

let DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!DEFAULT_ADMIN_PASSWORD) {
    // 보안: DEV에서도 정책을 통과하는 강력한 임시 비밀번호를 생성하되,
    // 기본값으로 로그에 노출하지 않는다(로그 유출 → 계정 탈취 위험).
    const SHOW_BOOTSTRAP_PASSWORD_IN_LOGS = String(process.env.SHOW_BOOTSTRAP_PASSWORD_IN_LOGS || "").toLowerCase() === "true";
    if (IS_PRODUCTION) {
        console.error("\n" + "=".repeat(80));
        console.error("❌ 프로덕션 환경에서 ADMIN_PASSWORD가 설정되지 않았습니다.");
        console.error("   - 보안을 위해 랜덤 비밀번호를 생성/로그로 출력하지 않습니다.");
        console.error("   - .env 또는 배포 환경변수에 ADMIN_PASSWORD를 설정한 뒤 다시 실행하세요.");
        console.error("=".repeat(80) + "\n");
        process.exit(1);
    }

    // 개발/로컬 환경: 편의상 임시 랜덤 비밀번호 생성 + 콘솔 경고
    DEFAULT_ADMIN_PASSWORD = generateStrongPassword();
    console.warn("\n" + "=".repeat(80));
    console.warn("⚠️  보안 경고: 기본 관리자 비밀번호가 환경변수로 설정되지 않았습니다! (개발/로컬)");
    console.warn(`   관리자 계정: ${DEFAULT_ADMIN_USERNAME}`);
    if (SHOW_BOOTSTRAP_PASSWORD_IN_LOGS) {
        console.warn(`   임시 비밀번호: ${DEFAULT_ADMIN_PASSWORD}`);
    } else {
        console.warn("   임시 비밀번호: (보안을 위해 로그에 출력하지 않습니다)");
        console.warn("   필요 시 SHOW_BOOTSTRAP_PASSWORD_IN_LOGS=true 로 출력 가능(비권장)");
    }
    console.warn("   첫 로그인 후 반드시 비밀번호를 변경하세요!");
    console.warn("=".repeat(80) + "\n");
}

// 보안: 운영 환경에서는 약한 ADMIN_PASSWORD를 절대 허용하지 않음 (fail-closed)
// - README의 'admin' 같은 기본/약한 비밀번호로 배포되는 것을 방지
{
    const common = new Set(["admin", "password", "administrator"]);
    const pwLower = String(DEFAULT_ADMIN_PASSWORD || "").trim().toLowerCase();
    const strength = validatePasswordStrength(DEFAULT_ADMIN_PASSWORD);

    if (common.has(pwLower) || !strength.valid) {
        const reason = common.has(pwLower)
            ? "너무 흔한 기본 비밀번호입니다."
            : (strength.error || "비밀번호 강도 정책을 만족하지 않습니다.");

        if (IS_PRODUCTION) {
            console.error("\n" + "=".repeat(80));
            console.error("🛑 [보안] ADMIN_PASSWORD가 약하여 서버 시작을 중단합니다.");
            console.error(`   사유: ${reason}`);
            console.error("   해결: 길고(>=10), 예측 불가한 강력 비밀번호로 변경 후 재시작하세요.");
            console.error("=".repeat(80) + "\n");
            process.exit(1);
        } else {
            console.warn("\n" + "=".repeat(80));
            console.warn("⚠️  [DEV 경고] ADMIN_PASSWORD가 약합니다. 임시로 강력 비밀번호로 대체합니다.");
            console.warn(`   사유: ${reason}`);
            DEFAULT_ADMIN_PASSWORD = generateStrongPassword();
            console.warn("   (비밀번호 로그 출력은 기본 비활성화)");
            console.warn("=".repeat(80) + "\n");
        }
    }
}

const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 12);

// 프로덕션 환경에서 필수 환경변수 검증
if (IS_PRODUCTION) {
    const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'BASE_URL', 'ADMIN_PASSWORD', 'TOTP_SECRET_ENC_KEY'];
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
 *
 * 보안: DB 자격증명에 기본값(root/admin 등)을 두면, 운영에서 환경변수 누락/오설정(NODE_ENV 누락 등)
 * 상황에서 매우 쉽게 기본 자격증명으로 노출될 수 있음
 *
 * - 기본값 정책: fail-closed (환경변수 미설정 시 즉시 종료)
 * - 로컬 개발 편의: ALLOW_INSECURE_DB_DEFAULTS=true 를 명시적으로 켠 경우에만,
 *   그리고 DB_HOST가 localhost 계열일 때에만 예전 기본값(root/admin/nteok)을 허용
 */
const ALLOW_INSECURE_DB_DEFAULTS = String(process.env.ALLOW_INSECURE_DB_DEFAULTS || '').toLowerCase() === 'true';

if (ALLOW_INSECURE_DB_DEFAULTS && IS_PRODUCTION) {
    console.error("🛑 [보안] 프로덕션에서는 ALLOW_INSECURE_DB_DEFAULTS=true 를 사용할 수 없습니다.");
    process.exit(1);
}

function envOrDie(name, { defaultValue, allowInsecureDev = false } = {}) {
    const raw = process.env[name];
    const v = (raw === undefined || raw === null) ? "" : String(raw).trim();
    if (v) return v;

    if (allowInsecureDev && ALLOW_INSECURE_DB_DEFAULTS) return defaultValue;

    console.error("🛑 [보안] 필수 환경변수가 누락되었습니다:", name);
    console.error("   - 해결: .env 또는 배포 환경변수에 값을 설정하세요.");
    console.error("   - (로컬 개발만) ALLOW_INSECURE_DB_DEFAULTS=true 로 기존 기본값을 명시적으로 허용할 수 있습니다. (비권장)");
    process.exit(1);
}

const DB_HOST = envOrDie("DB_HOST", { defaultValue: "localhost", allowInsecureDev: true });
const DB_USER = envOrDie("DB_USER", { defaultValue: "root", allowInsecureDev: true });
const DB_PASSWORD = envOrDie("DB_PASSWORD", { defaultValue: "admin", allowInsecureDev: true });
const DB_NAME = envOrDie("DB_NAME", { defaultValue: "nteok", allowInsecureDev: true });

// 방어: insecure defaults는 로컬호스트 DB에서만 허용
if (ALLOW_INSECURE_DB_DEFAULTS) {
    const h = String(DB_HOST || "").toLowerCase();
    const isLocalDb = (h === "localhost" || h === "127.0.0.1" || h === "::1");
    if (!isLocalDb) {
        console.error("🛑 [보안] ALLOW_INSECURE_DB_DEFAULTS=true 는 로컬 DB(localhost)에서만 허용됩니다.");
        console.error(`   현재 DB_HOST="${DB_HOST}"`);
        process.exit(1);
    }
    console.warn("⚠️  [SECURITY] ALLOW_INSECURE_DB_DEFAULTS=true (로컬 개발용) — 기본 DB 자격증명(root/admin)을 사용합니다. 운영에서는 절대 사용하지 마세요.");
}

const DB_CONFIG = {
    host: DB_HOST,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME,
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
 *
 * 보안: 기존 정규식 기반 제거 방식(replace(/<[^>]*>/g, ''))은 우회 가능성이 높음
 * DOMPurify를 사용하여 모든 태그와 속성을 허용하지 않음으로써 안전한 텍스트만 남기도록 개선
 */
function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return input;
    }
    // DOMPurify를 사용하여 모든 태그를 제거 (Text만 남김)
    return DOMPurify.sanitize(input, {
        ALLOWED_TAGS: [], // 허용할 태그 없음
        ALLOWED_ATTR: []  // 허용할 속성 없음
    });
}

/**
 * 업로드 파일명 안전화 유틸
 * - 제어문자 제거(헤더 인젝션 방지)
 * - 경로 구분자 제거(path traversal/혼동 방지)
 * - 따옴표/꺾쇠 등 HTML/헤더 컨텍스트 위험 문자 제거
 */
function sanitizeFilenameComponent(name, maxLen = 120) {
    const s = String(name ?? '').normalize('NFKC');
    const cleaned = s
        .replace(/[\u0000-\u001F\u007F]/g, '')	// 제어 문자
        .replace(/[\\/]/g, '_')                 // 경로 분할 문자
        .replace(/["'<>`]/g, '')                // HTML/attrs/headers에서 위험한 문자 태그
        .trim();
    return (cleaned.length ? cleaned : 'file').slice(0, maxLen);
}

function sanitizeExtension(ext) {
    if (!ext) return '';
    const lower = String(ext).toLowerCase();
    // .abc123 형태만 허용 (임의 문자열/따옴표 섦입 차단)
    return /^\.[a-z0-9]{1,10}$/.test(lower) ? lower : '';
}

function deriveDownloadNameFromStoredFilename(stored) {
    const safeStored = sanitizeFilenameComponent(stored, 200);
    // 저장 규칙: <random>__<displayName><ext>
    const idx = safeStored.indexOf('__');
    if (idx >= 0) {
        const tail = safeStored.slice(idx + 2);
        return tail.length ? tail : 'download';
    }
    return safeStored;
}

function setNoStore(res) {
    // 민감 데이터(세션/노트/첨부/개인 이미지 등)가 브라우저/프록시/히스토리에 캐시되지 않도록 강제
    // - no-store: 어떤 캐시(브라우저/공유 프록시)에도 저장 금지
    // - Pragma/Expires: 구형/레거시 캐시 동작 보조
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
}

function sendSafeDownload(res, filePath, downloadName) {
    // 무조건 다운로드로 취급되게 바이너리 처리
    res.setHeader('Content-Type', 'application/octet-stream');
    // MIME sniffing 방지 (스크립트/스타일 로딩 악용 차단에 중요)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    // 혹시 문서로 렌더링되는 상황에서도 강한 제한
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    setNoStore(res);
    return res.download(filePath, downloadName);
}

function sendSafeImage(res, filePath) {
    // 업로드 파일이 변조/오염되었을 가능성을 방어적으로 차단
    // (확장자만 믿지 않고 매직 넘버로 실제 타입 확인)
    const detected = assertImageFileSignature(filePath, new Set(['jpg', 'jpeg', 'png', 'gif', 'webp']));

    // MIME sniffing을 막아 이미지처럼 보이는 HTML/JS가 문서로 렌더링되는 것을 방지
    res.setHeader('Content-Type', detected.mime);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    // 혹시라도 브라우저가 문서로 처리하는 경우를 대비해 강한 제한(다운로드만큼 강하지 않아도 됨)
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    // 타 사이트에서의 임의 임베드/재사용 최소화(선택)
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

    setNoStore(res);

    // 디렉터리/특수파일 오용 방지
    try {
        const st = fs.statSync(filePath);
        if (!st.isFile()) return res.status(404).end();
        res.setHeader('Content-Length', String(st.size));
    } catch (_) {
        return res.status(404).end();
    }

    const stream = fs.createReadStream(filePath);
    stream.on('error', () => {
        if (!res.headersSent) return res.status(404).end();
        try { res.end(); } catch (_) {}
    });
    return stream.pipe(res);
}

// DOMPurify는 JSDOM 위에서 동작 -> 이때 입력 HTML을 DOM으로 파싱하는 과정에서
// <style> 태그 내부의 CSS 파서가 과도한 재귀/시간을 유발하거나(회귀 버그 포함) 예외를
// 던지면서 서비스 가용성을 떨어뜨릴 수 있음 -> 따라서 DOMPurify 호출 전에 <style> / stylesheet 링크를 사전 제거하고,
// 입력 크기에 상한을 두며, 예외 발생 시 안전한 폴백을 적용
// 일반적인 노트 HTML은 수십 KB 수준이므로 512KiB 상한이면 충분
const MAX_HTML_SANITIZE_BYTES = 512 * 1024;

function escapeHtmlToText(str) {
	return String(str).replace(/[&<>"']/g, (ch) => {
		switch (ch) {
		    case "&": return "&amp;";
		    case "<": return "&lt;";
		    case ">": return "&gt;";
		    case '"': return "&quot;";
		    case "'": return "&#39;";
		    default: return ch;
		}
	});
}

function prefilterHtmlForSanitizer(html) {
	let out = String(html);

	// 크기 상한: 매우 큰 입력은 파싱/정화 비용이 급증할 수 있으므로 방어적으로 절단
	if (Buffer.byteLength(out, "utf8") > MAX_HTML_SANITIZE_BYTES)
		out = out.slice(0, MAX_HTML_SANITIZE_BYTES);

	// JSDOM CSS 파서 DoS 회피: 금지 태그라도 파싱은 먼저 일어나므로 사전 제거 필요
	out = out.replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, "");

	// rel=stylesheet 링크도 방어적으로 제거(에디터 콘텐츠에서 필요 없음)
	out = out.replace(/<link\b[^>]*\brel\s*=\s*(['"])\s*stylesheet\s*\1[^>]*>/gi, "");
	out = out.replace(/<link\b(?=[^>]*\brel\s*=\s*stylesheet\b)[^>]*>/gi, "");

	return out;
}

/**
 * 보안 개선: HTML 콘텐츠 정화 (DOMPurify)
 * 에디터 콘텐츠 등 HTML이 필요한 필드에 사용
 */
function sanitizeHtmlContent(html) {
    if (typeof html !== 'string')
        return html;

    // 방어적 사전 처리(크기 제한, <style> 제거 등)
    const prefiltered = prefilterHtmlForSanitizer(html);

	// DOMPurify로 안전한 HTML만 허용(예외는 폴백)
	try {
		return DOMPurify.sanitize(prefiltered, {
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
	        ALLOWED_ATTR: ['style', 'class', 'href', 'target', 'rel', 'data-type', 'data-latex', 'colspan', 'rowspan', 'colwidth', 'src', 'alt', 'data-src', 'data-alt', 'data-caption', 'data-width', 'data-align', 'data-url', 'data-title', 'data-description', 'data-thumbnail', 'data-id', 'data-icon', 'data-checked', 'type', 'checked', 'data-callout-type', 'data-content', 'data-columns', 'data-is-open', 'data-selected-date', 'data-memos'],
	        ALLOW_DATA_ATTR: true,
	        ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
	    });
	} catch (err) {
		// 파서 회귀/비정상 입력 예외가 프로세스 전체에 영향을 주지 않도록 방어
		console.warn('[보안] sanitizeHtmlContent 실패:', err);
		const escaped = escapeHtmlToText(prefiltered);
		return `<p>${escaped}</p>`;
	}
}

/**
 * 보안 개선: 비밀번호 강도 검증
 * @param {string} password - 검증할 비밀번호
 * @returns {{valid: boolean, error?: string}}
 */
function validatePasswordStrength(password) {
    if (!password || typeof password !== 'string')
        return { valid: false, error: "비밀번호를 입력해 주세요." };

    // bcrypt 구현(특히 C 기반)에서는 NUL(\\u0000) 등 제어문자를 문자열 종료로 처리하는 경우가 있어
    // 강도 정책 우회/인증 모호성(동일 해시) 문제가 생길 수 있으므로 선제적으로 차단
    if (CONTROL_CHARS_RE.test(password))
        return { valid: false, error: "비밀번호에 제어 문자를 사용할 수 없습니다." };

    // bcrypt는 대부분 구현에서 입력의 처음 72바이트까지만 사용
    // UTF-8 기준이므로 한글/이모지 등은 일반 문자 수 보다 더 빨리 제한에 도달
    const BCRYPT_MAX_PASSWORD_BYTES = 72;
    const passwordBytes = Buffer.byteLength(password, "utf8");
    if (passwordBytes > BCRYPT_MAX_PASSWORD_BYTES) {
        return {
            valid: false,
            error: `비밀번호가 너무 깁니다. (UTF-8 기준 최대 ${BCRYPT_MAX_PASSWORD_BYTES}바이트)`
        };
    }

    if (password.length < 10)
        return { valid: false, error: "비밀번호는 10자 이상이어야 합니다." };

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
 * 정책을 통과하는 강력한 랜덤 비밀번호 생성
 * - 최소 4종 문자군 중 3종 이상 포함(현 validatePasswordStrength 정책 준수)
 * - 기본 길이 20
 */
function generateStrongPassword(length = 20) {
    const LOWER = "abcdefghijklmnopqrstuvwxyz";
    const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS = "0123456789";
    const SPECIAL = "!@#$%^&*(),.?\":{}|<>";

    // 보안: Math.random()은 CSPRNG가 아니므로(예측 가능성/편향 가능성)
    // 보안 비밀값(관리자 임시 비밀번호 등) 생성에 사용하면 안 됨
    // Node.js에서는 crypto.randomInt/randomBytes를 사용
    const pick = (chars) => {
        if (!chars || chars.length === 0) throw new Error("generateStrongPassword: empty charset");
        // crypto.randomInt는 0..max-1 구간에서 균등 분포의 암호학적 난수를 반환
        return chars[crypto.randomInt(0, chars.length)];
    };

    // 최소 길이: 정책(10자 이상 + 3종 이상)과 운영 편의성 고려
    const targetLen = Math.max(12, Number.isFinite(Number(length)) ? Number(length) : 20);

    // 최소 구성: 4종 문자군을 모두 포함(정책의 3종 이상을 항상 만족)
    const required = [
        pick(LOWER),
        pick(UPPER),
        pick(DIGITS),
        pick(SPECIAL),
    ];

    const all = LOWER + UPPER + DIGITS + SPECIAL;
    const arr = required.slice();
    for (let i = arr.length; i < targetLen; i++) {
        arr.push(pick(all));
    }

    // 셔플 (CSPRNG 기반 Fisher–Yates)
    for (let i = arr.length - 1; i > 0; i--) {
        const j = crypto.randomInt(0, i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }

    const pw = arr.join("");
    // 혹시 정책 검사에 실패하면 재시도(극히 드묾)
    return validatePasswordStrength(pw).valid ? pw : generateStrongPassword(targetLen);
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
        console.warn(`[인증 실패] ${req.method} ${req.path} - 세션 ID: ${maskedSessionId}, 유효한 세션: 없음, IP: ${req.clientIp}`);
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
    if (["GET", "HEAD", "OPTIONS"].includes(req.method))
        return next();

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
            totp_secret TEXT NULL,
            totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
            passkey_enabled TINYINT(1) NOT NULL DEFAULT 0,
            block_duplicate_login TINYINT(1) NOT NULL DEFAULT 0,
            country_whitelist_enabled TINYINT(1) NOT NULL DEFAULT 0,
            allowed_login_countries TEXT NULL,
            sticky_header TINYINT(1) NOT NULL DEFAULT 0,
            theme VARCHAR(64) NOT NULL DEFAULT 'default'
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // storages 테이블 생성
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS storages (
            id          VARCHAR(64)  NOT NULL PRIMARY KEY,
            user_id     INT          NOT NULL,
            name        VARCHAR(255) NOT NULL,
            sort_order  INT          NOT NULL DEFAULT 0,
            created_at  DATETIME     NOT NULL,
            updated_at  DATETIME     NOT NULL,
            CONSTRAINT fk_storages_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // pages 테이블 생성 (이제 storage_id에 직접 속함)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS pages (
            id          VARCHAR(64)  NOT NULL PRIMARY KEY,
            sort_order  INT          NOT NULL DEFAULT 0,
            user_id     INT          NOT NULL,
            storage_id  VARCHAR(64)  NOT NULL,
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
            horizontal_padding INT NULL,
            deleted_at  DATETIME     NULL,
            CONSTRAINT fk_pages_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_pages_parent
                FOREIGN KEY (parent_id)
                REFERENCES pages(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_pages_storage
                FOREIGN KEY (storage_id)
                REFERENCES storages(id)
                ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // pages 테이블에 deleted_at 컬럼 추가 (하위 호환성)
    try {
        await pool.execute(`ALTER TABLE pages ADD COLUMN deleted_at DATETIME NULL`);
    } catch (e) {
        // 이미 존재하면 무시
    }

    // storage_shares 테이블 생성
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS storage_shares (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            storage_id VARCHAR(64) NOT NULL,
            owner_user_id INT NOT NULL,
            shared_with_user_id INT NOT NULL,
            permission VARCHAR(20) NOT NULL DEFAULT 'READ',
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            CONSTRAINT fk_storage_shares_storage
                FOREIGN KEY (storage_id)
                REFERENCES storages(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_storage_shares_owner
                FOREIGN KEY (owner_user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_storage_shares_shared_with
                FOREIGN KEY (shared_with_user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT uc_storage_shares_unique
                UNIQUE (storage_id, shared_with_user_id),
            INDEX idx_shared_with_user (shared_with_user_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // share_links 테이블 생성 (이제 저장소 단위로 작동)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS share_links (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(64) NOT NULL UNIQUE,
            storage_id VARCHAR(64) NOT NULL,
            owner_user_id INT NOT NULL,
            permission VARCHAR(20) NOT NULL DEFAULT 'READ',
            expires_at DATETIME NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            CONSTRAINT fk_share_links_storage
                FOREIGN KEY (storage_id)
                REFERENCES storages(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_share_links_owner
                FOREIGN KEY (owner_user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            INDEX idx_token_active (token, is_active),
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

    // 페이지 발행 링크 테이블 (페이지 단위이므로 유지)
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS page_publish_links (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(64) NOT NULL UNIQUE,
            page_id VARCHAR(64) NOT NULL,
            owner_user_id INT NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            allow_comments TINYINT(1) NOT NULL DEFAULT 0,
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

    // 보안/호환성: 과거 버전에서 soft-delete된 페이지가 공개 발행 링크를 통해
    // 계속 노출될 수 있었으므로, 시작 시 한 번 정리
    // (deleted_at은 soft delete에서만 채워지며, 영구 삭제는 FK ON DELETE CASCADE로 정리됨)
    await pool.execute(
        `UPDATE page_publish_links ppl
         JOIN pages p ON p.id = ppl.page_id
         SET ppl.is_active = 0, ppl.updated_at = NOW()
         WHERE ppl.is_active = 1 AND p.deleted_at IS NOT NULL`
    );

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

    // 댓글 테이블 생성
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS comments (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            page_id VARCHAR(64) NOT NULL,
            user_id INT NULL,
            guest_name VARCHAR(64) NULL,
            content TEXT NOT NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL,
            CONSTRAINT fk_comments_page FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
            CONSTRAINT fk_comments_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            INDEX idx_comments_page (page_id, created_at)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // 업데이트 히스토리 테이블 생성
    await pool.execute(`
        CREATE TABLE IF NOT EXISTS updates_history (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            storage_id VARCHAR(64) NOT NULL,
            page_id VARCHAR(64) NULL,
            action VARCHAR(50) NOT NULL,
            details TEXT NULL,
            created_at DATETIME NOT NULL,
            CONSTRAINT fk_updates_history_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_updates_history_storage
                FOREIGN KEY (storage_id)
                REFERENCES storages(id)
                ON DELETE CASCADE,
            INDEX idx_user_history (user_id, created_at DESC),
            INDEX idx_storage_history (storage_id, created_at DESC)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    // ============================================================
    // 성능 최적화: 데이터베이스 인덱스 추가
    // ============================================================

    // pages 테이블 인덱스 (저장소별 페이지 조회 최적화)
    try {
        await pool.execute(`
            CREATE INDEX IF NOT EXISTS idx_pages_storage_user
            ON pages(storage_id, user_id)
        `);
        console.log('✓ pages.storage_id, user_id 인덱스 생성 완료');
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

    // users 가 하나도 없으면 기본 관리자 계정 생성
    const [userRows] = await pool.execute("SELECT COUNT(*) AS cnt FROM users");
    const userCount = userRows[0].cnt;

    if (userCount === 0) {
        const now = new Date();
        const nowStr = formatDateForDb(now);

        const username = DEFAULT_ADMIN_USERNAME;
        const rawPassword = DEFAULT_ADMIN_PASSWORD;

        // 보안: DB에 기본 관리자 계정을 생성하기 직전에도 강도 검증(우회 방지)
        const check = validatePasswordStrength(rawPassword);
        if (!check.valid) {
            throw new Error(`ADMIN_PASSWORD 약함: ${check.error || "invalid"}`);
        }

        // bcrypt 가 내부적으로 랜덤 SALT 를 포함한 해시를 생성함
        const passwordHash = await bcrypt.hash(rawPassword, BCRYPT_SALT_ROUNDS);

        const [result] = await pool.execute(
            `
            INSERT INTO users (username, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            `,
            [username, passwordHash, nowStr, nowStr]
        );

        const adminUserId = result.insertId;

        // 기본 저장소 생성
        const storageId = 'stg-' + now.getTime() + '-' + crypto.randomBytes(4).toString('hex');
        await pool.execute(
            `
            INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            `,
            [storageId, adminUserId, "기본 저장소", 0, nowStr, nowStr]
        );

        // 초기 시작 페이지 생성
        const pageId = generatePageId(now);
        const welcomeTitle = "넋(NTEOK)에 오신 것을 환영합니다! 👋";
        const welcomeContent = `
            <h1>반가워요!</h1>
            <p>이곳은 당신의 생각과 기록을 담는 소중한 공간입니다.</p>
            <p>왼쪽 사이드바에서 <strong>새 페이지</strong>를 추가하거나, 상단의 <strong>저장소 전환</strong> 버튼을 통해 다른 저장소를 관리할 수 있습니다.</p>
            <p>저장소마다 서로 다른 페이지 목록을 가지며, 다른 사용자와 저장소 단위로 협업할 수도 있습니다.</p>
        `;

        await pool.execute(
            `
            INSERT INTO pages (id, user_id, storage_id, title, content, sort_order, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [pageId, adminUserId, storageId, welcomeTitle, welcomeContent, 0, nowStr, nowStr]
        );

        console.log("기본 관리자 계정, 저장소 및 시작 페이지 생성 완료. username:", username);
    }
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

/**
 * 보안: __proto__/constructor/prototype 키는 다양한 JS 취약점(프로토타입 오염, 라이브러리 merge 취약점 등)의 트리거가 될 수 있음
 * - CVE-2026-25639(axios mergeConfig DoS)도 JSON.parse로 만들어진 __proto__ own-property가 트리거 포인트
 * - 따라서 요청 body에 포함되면 전역적으로 제거(정상 기능 영향 최소화를 위해 키 제거만 수행)
 *
 * 참고: OWASP Prototype Pollution Prevention Cheat Sheet는 __proto__ 제거가 공격 표면 감소에 도움이라고 언급
 */
const DANGEROUS_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function stripDangerousKeys(value, seen = new WeakSet()) {
    if (!value || typeof value !== "object") return;
    if (seen.has(value)) return;
    seen.add(value);

    if (Array.isArray(value)) {
        for (const item of value) stripDangerousKeys(item, seen);
        return;
    }

    for (const key of Object.keys(value)) {
        if (DANGEROUS_OBJECT_KEYS.has(key)) {
            delete value[key];
            continue;
        }
        stripDangerousKeys(value[key], seen);
    }
}

app.use((req, _res, next) => {
    // JSON + urlencoded 모두 방어 (req.body가 없으면 noop)
    try {
        stripDangerousKeys(req.body);
    } catch (_) {
        // 방어 로직 실패로 요청 전체를 죽이지 않음
    }
    next();
});

/**
 * 보안: 웹 루트(public)에 남은 백업/임시 파일 노출 차단
 * - .backup/.bak/.old/.tmp/.swp 등은 개발 중 흔히 생기며, 남아 있으면 소스/설정/비밀값 유출 위험
 * - OWASP WSTG: Old/Backup/Unreferenced file 점검 권고
 */
const PUBLIC_FORBIDDEN_EXT_RE = /\.(?:bak|backup|old|tmp|swp|swo|orig|save)$/i;
app.use((req, res, next) => {
    // 정적 파일 접근에서 주로 발생하므로 GET/HEAD만 타겟
    if (req.method === "GET" || req.method === "HEAD") {
        const p = String(req.path || "");
        if (PUBLIC_FORBIDDEN_EXT_RE.test(p)) {
            // 존재 여부(oracle) 최소화를 위해 404로 응답
            return res.status(404).end();
        }
    }
    next();
});

// urlencoded를 쓰는 폼 요청이 있다면 함께 제한(없으면 유지해도 무방)
app.use(express.urlencoded({ extended: false, limit: JSON_BODY_LIMIT }));
app.use(cookieParser());

// 정보 노출 완화 (헤더 불필요한 정보 제거)
app.disable("x-powered-by");

// CSP nonce 생성 (요청마다 새로 발급)
app.use((req, res, next) => {
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
        "frame-src 'self' https://www.youtube.com https://youtube.com https://www.youtube-nocookie.com https://youtube-nocookie.com; " +
        "form-action 'self'; " +
        // NOTE: CSP의 핵심은 nonce가 있는 스크립트만 실행 되도록 하는 것
        // 기존처럼 광범위 CDN(예: jsdelivr/esm.sh)을 script-src에 allowlist 하면,
        // XSS가 단 1곳이라도 생겼을 때 공격자가 외부 스크립트를 로드해 완전한 계정 탈취로 확장하기 쉬움 (방어 심층화 상실).
        `script-src 'nonce-${nonce}' 'strict-dynamic'; ` +
        "style-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; " +
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self';"
    );

    // 추가 보안 헤더
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    // X-XSS-Protection은 구식이며 CSP로 충분히 대체됨 (제거)
	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

	// Permissions Policy (필요 시 허용 목록으로 조정)
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    // HSTS (HTTPS에서만, production 권장)
    if (HSTS_ENABLED)
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
            secure: COOKIE_SECURE,  // 보안 개선: 환경에 따라 설정
            path: "/",
            maxAge: SESSION_TTL_MS
        });
    }
    next();
});

// CSRF 검증 미들웨어 (API 엔드포인트에만 적용)
app.use("/api", csrfMiddleware);

// 일반 API 레이트 리밋 적용
app.use("/api", generalLimiter);

// 보안: API 응답(노트/메타데이터 등 민감 정보)이 브라우저 캐시/히스토리에 남지 않도록 설정
// - SPA에서도 XHR/Fetch 응답이 디스크 캐시에 남을 수 있으며, 공유 PC/키오스크에서 특히 위험
app.use("/api", (req, res, next) => {
    setNoStore(res);
    next();
});

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

    setNoStore(res);

    const currentUserId = req.user.id;

    try {
        // 강화된 파일명 새니타이제이션 (경로 조작/특수문자/헤더 인젝션 방지)
        const sanitizedFilename = sanitizeFilenameComponent(req.params.filename, 200);
        if (!sanitizedFilename) {
            return res.status(400).json({ error: '잘못된 파일명입니다.' });
        }

        // 커버 허용 확장자 allowlist (업로드 정책과 동일한 수준으로 제한)
        const ext = path.extname(sanitizedFilename).toLowerCase();
        const ALLOWED_COVER_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp']);
        if (!ALLOWED_COVER_EXTS.has(ext)) {
            return res.status(400).json({ error: '지원하지 않는 파일 형식입니다.' });
        }

        const filePath = path.join(__dirname, 'covers', String(requestedUserId), sanitizedFilename);

        // 파일 존재 확인
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '파일을 찾을 수 없습니다.' });
        }

        // 권한 확인: 본인 파일이거나, 공유받은 페이지의 커버인 경우
        if (requestedUserId === currentUserId) {
            // 본인 파일 - 접근 허용
            return sendSafeImage(res, filePath);
        }

        // 핵심 수정: /imgs, /paperclip과 동일하게 storages + storage_shares 권한 모델로 통일
        const coverPath = `${requestedUserId}/${sanitizedFilename}`;
        const [rows] = await pool.execute(
            `SELECT p.id
               FROM pages p
               JOIN storages s ON p.storage_id = s.id
               LEFT JOIN storage_shares ss_cur
                 ON s.id = ss_cur.storage_id AND ss_cur.shared_with_user_id = ?
              WHERE p.cover_image = ?
                -- 보안패치: 파일 소유자와 참조하는 페이지 소유자 일치
                AND p.user_id = ?
                -- 보안패치: 암호화 + 공유불가 페이지 자산은 타 사용자에게 노출 금지
                AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
                -- 현재 사용자가 이 storage를 소유하거나 공유받았는지
                AND (s.user_id = ? OR ss_cur.shared_with_user_id IS NOT NULL)
              LIMIT 1`,
            [currentUserId, coverPath, requestedUserId, currentUserId, currentUserId]
        );

        if (rows.length > 0) {
            // 공유받은 페이지의 커버 - 접근 허용
            return sendSafeImage(res, filePath);
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

	setNoStore(res);

    const currentUserId = req.user.id;

    try {
        // 강화된 파일명 새니타이제이션 (경로 조작/특수문자/헤더 인젝션 방지)
        const sanitizedFilename = sanitizeFilenameComponent(req.params.filename, 200);
        if (!sanitizedFilename) {
            return res.status(400).json({ error: '잘못된 파일명입니다.' });
        }

        // 이미지 허용 확장자 allowlist
        const ext = path.extname(sanitizedFilename).toLowerCase();
        const ALLOWED_IMG_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp']);
        if (!ALLOWED_IMG_EXTS.has(ext)) {
            return res.status(400).json({ error: '지원하지 않는 파일 형식입니다.' });
        }

        const filePath = path.join(__dirname, 'imgs', String(requestedUserId), sanitizedFilename);

        // 파일 존재 확인
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '파일을 찾을 수 없습니다.' });
        }

        // 권한 확인: 본인 파일이거나, 공유받은 페이지의 이미지인 경우
        if (requestedUserId === currentUserId) {
            // 본인 파일 - 접근 허용
            return sendSafeImage(res, filePath);
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
                JOIN storages s ON p.storage_id = s.id
                LEFT JOIN storage_shares ss_cur ON s.id = ss_cur.storage_id AND ss_cur.shared_with_user_id = ?
                WHERE p.content LIKE ? ESCAPE '\\\\'
                AND (s.user_id = ? OR ss_cur.shared_with_user_id IS NOT NULL)
                -- 보안패치: 암호화 + 공유불가 페이지의 자산은
                -- 페이지 본문 접근이 차단된 사용자(컬렉션 소유자 포함)에게도 노출되면 안 됨
                AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
                -- 보안패치: 파일 소유자와 참조하는 페이지 소유자를 반드시 일치시킴
                AND p.user_id = ?
                LIMIT 1`,
            [currentUserId, likePattern, currentUserId, currentUserId, requestedUserId]
        );

        if (rows.length > 0) {
            // 공유받은 페이지의 이미지 - 접근 허용
            return sendSafeImage(res, filePath);
        }

        // 보안: 실시간 동기화 중인(Yjs) 문서의 내용도 확인
        // DB 저장 지연(약 1초)으로 인해 협업자가 이미지를 즉시 로드하지 못하는 문제 해결
        for (const [pageId, connections] of wsConnections.pages) {
            // 현재 사용자가 이 페이지를 구독 중인지(그리고 연결 메타가 있는지) 확인
            const myConn = Array.from(connections).find(c => c.userId === currentUserId);
            if (!myConn) continue;

            const docInfo = yjsDocuments.get(pageId);
            if (!docInfo) continue;

            // 핵심: Yjs fallback이 권한 우회 통로가 되지 않도록 요청한
            // 이미지 소유자(requestedUserId)와 구독 중인 페이지의 소유자(docInfo.ownerUserId)가 반드시 일치해야 함
            // - 이 검증이 없으면 공격자가 자기 페이지에 피해자 이미지 URL 문자열만 넣고
            // - 피해자 이미지를 무단으로 가져갈 수 있음(IDOR/Broken Access Control)
            if (!Number.isFinite(docInfo.ownerUserId) || Number(docInfo.ownerUserId) !== requestedUserId)
                continue;

            // (방어 심층화) WS 연결이 알고 있는 storageId와 docInfo.storageId가 다르면 스킵
            if (docInfo.storageId && myConn.storageId && String(docInfo.storageId) !== String(myConn.storageId))
                continue;

            // (선택) 암호화 + 공유불가 페이지 자산 우회 노출 방지
            // - subscribe-page는 encrypted 협업을 차단하지만,
            //   혹시라도 doc가 남아있는 경우를 방어적으로 막음
            if (docInfo.isEncrypted === true && docInfo.shareAllowed === false && currentUserId !== requestedUserId)
                continue;

			const ydoc = docInfo.ydoc;

            // HTML 스냅샷 확인
            const content = ydoc.getMap('metadata').get('content') || '';
            if (content.includes(imageUrl))
                return sendSafeImage(res, filePath);

			// HTML 스냅샷이 아직 업데이트 전이라면, Y.XmlFragment 직접 확인
            // toString()은 전체 XML 구조를 반환하므로 속성(data-src)에 포함된 URL도 찾을 수 있음
            const xmlContent = ydoc.getXmlFragment('prosemirror').toString();
            if (xmlContent.includes(imageUrl))
                return sendSafeImage(res, filePath);
        }

        // 권한 없음
		console.warn(`[보안] 사용자 ${currentUserId}이(가) 권한 없이 이미지 접근 시도: ${imagePath}`);
		return res.status(403).json({ error: '접근 권한이 없습니다.' });

    } catch (error) {
        logError('GET /imgs/:userId/:filename', error);
        res.status(500).json({ error: '파일 로드 실패' });
    }
});

// 파일 블록 파일 - 인증 필요
app.get('/paperclip/:userId/:filename', authMiddleware, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId, 10);

    if (!Number.isFinite(requestedUserId))
        return res.status(400).json({ error: '잘못된 요청입니다.' });

    const currentUserId = req.user.id;

    try {
        // 강화된 파일명 새니타이제이션 (경로 조작/특수문자/헤더 인젝션 방지)
        const sanitizedFilename = sanitizeFilenameComponent(req.params.filename, 200);
        if (!sanitizedFilename) {
            return res.status(400).json({ error: '잘못된 파일명입니다.' });
        }

        const filePath = path.join(__dirname, 'paperclip', String(requestedUserId), sanitizedFilename);

        // 다운로드 파일명(표시용)은 URL query (?name=)로 받되, 헤더/경로 컨텍스트에 안전하게 정규화
        // - 저장 파일명이 콘텐츠 해시(예: <sha256>.ext)일 수 있으므로, 사용자에게는 원본명을 유지
        // - 쿼리가 없으면 기존 규칙(<random>__<displayName>)에서 displayName을 추출
        const getDownloadName = () => {
            const raw = req.query?.name;
            if (typeof raw === 'string' && raw.trim().length) {
                let safe = sanitizeFilenameComponent(raw, 200);
                // 확장자가 비어있으면 저장 파일 확장자를 보존(브라우저 UX)
                if (safe && !path.extname(safe)) {
                    const ext = sanitizeExtension(path.extname(sanitizedFilename));
                    if (ext) safe += ext;
                }
                return safe || 'download';
            }
            return deriveDownloadNameFromStoredFilename(sanitizedFilename);
        };

        // 파일 존재 확인
        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '파일을 찾을 수 없습니다.' });
        }

        // 권한 확인: 본인 파일이거나, 공유받은 페이지의 파일인 경우
        if (requestedUserId === currentUserId) {
			const downloadName = getDownloadName();
			return sendSafeDownload(res, filePath, downloadName);
        }

        // 다른 사용자의 파일 - 공유받은 페이지의 파일인지 확인
        const fileUrlPart = `/paperclip/${requestedUserId}/${sanitizedFilename}`;

        // LIKE 와일드카드 이스케이프
        const escapeLike = (s) => String(s).replace(/[\\%_]/g, (m) => `\\${m}`);
        const likePattern = `%${escapeLike(fileUrlPart)}%`;

        // 파일이 포함된 페이지가 공유되었는지 확인
        const [rows] = await pool.execute(
            `SELECT p.id
                FROM pages p
                JOIN storages s ON p.storage_id = s.id
                LEFT JOIN storage_shares ss_cur ON s.id = ss_cur.storage_id AND ss_cur.shared_with_user_id = ?
                WHERE p.content LIKE ? ESCAPE '\\\\'
                AND (s.user_id = ? OR ss_cur.shared_with_user_id IS NOT NULL)
                -- 보안패치: 암호화 + 공유불가 페이지의 첨부파일은
                -- 페이지 본문 접근이 차단된 사용자에게 우회적으로 다운로드되면 안 됨
                AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
                -- 보안패치: 파일 소유자 == 참조 페이지 소유자
                AND p.user_id = ?
                LIMIT 1`,
            [currentUserId, likePattern, currentUserId, currentUserId, requestedUserId]
        );

        if (rows.length > 0) {
            // 공유받은 페이지의 파일 - 접근 허용 (다운로드)
			const downloadName = getDownloadName();
			return sendSafeDownload(res, filePath, downloadName);
        }

        // 권한 없음
        console.warn(`[보안] 사용자 ${currentUserId}이(가) 권한 없이 파일 접근 시도: ${fileUrlPart}`);
        return res.status(403).json({ error: '접근 권한이 없습니다.' });

    } catch (error) {
        logError('GET /paperclip/:userId/:filename', error);
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
	    // 보안: 원본 파일명/확장자는 신뢰하지 않음
	    // - file.originalname은 공격자가 임의 문자열(따옴표, 공백, 이벤트 핸들러 등)을 넣을 수 있음
	    // - 확장자를 그대로 이어붙이면 이후 HTML 템플릿/DOM 렌더링 과정에서 속성 주입(XSS)로 이어질 수 있음
	    // - 일단 안전한 임시 확장자로 저장한 뒤, 라우트에서 파일 시그니처 검증 후 정상 확장자로 변경
	    const uniqueBase = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
	    cb(null, `${uniqueBase}.upload`);
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
		// coverStorage와 동일한 이유로 임시 확장자로 저장
		const uniqueBase = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
		cb(null, `${uniqueBase}.upload`);
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
		/**
	 	 * 보안: 업로드 파일명 충돌로 기존 테마(예: default.css)를 덮어쓰는 취약점 방지
	     * - 원본 파일명은 표시용으로만 쓰고, 실제 저장 파일명은 랜덤 suffix를 붙여 유일하게 만든다
	     * - OWASP/PortSwigger 권고: 업로드 파일 rename하여 충돌/overwrite 방지
	     */
	    const rawBase = path.basename(file.originalname, path.extname(file.originalname));
	    const safeBase = (rawBase || 'theme').replace(/[^a-zA-Z0-9-]/g, '').toLowerCase() || 'theme';
	    const suffix = crypto.randomBytes(8).toString('hex'); // 16진수 문자
	    cb(null, `${safeBase}-${suffix}.css`);
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

// 파일 블록 업로드를 위한 multer 설정
const paperclipStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.user.id;
        const userFileDir = path.join(__dirname, 'paperclip', String(userId));
        fs.mkdirSync(userFileDir, { recursive: true });
        cb(null, userFileDir);
    },
    filename: (req, file, cb) => {
	    // 저장용 이름은 랜덤 + 표시용 이름을 분리
	    const uniquePrefix = `${Date.now()}-${crypto.randomBytes(16).toString('hex')}`;
	    const rawExt = path.extname(file.originalname);
	    const ext = sanitizeExtension(rawExt);
	    const base = sanitizeFilenameComponent(path.basename(file.originalname, rawExt), 120)
	        .replace(/__+/g, '_'); // 구분자 충돌 방지

	    // <random>__<displayName><ext>
	    cb(null, `${uniquePrefix}__${base}${ext}`);
    }
});

const fileUpload = multer({
    storage: paperclipStorage,
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
    // 모든 파일 허용 (실행 파일 등은 서버에서 실행되지 않도록 주의 필요)
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

        // 필수 업로드 폴더 생성
        const uploadDirs = ['covers', 'imgs', 'paperclip', 'themes'];
        uploadDirs.forEach(dir => {
            const dirPath = path.join(__dirname, dir);
            if (!fs.existsSync(dirPath)) {
                fs.mkdirSync(dirPath, { recursive: true });
                console.log(`📁 폴더 생성됨: ${dir}`);
            }
        });

        // 로그인 로그 정리 작업 시작 (pool 초기화 후)
        setInterval(cleanupOldLoginLogs, 24 * 60 * 60 * 1000);
        cleanupOldLoginLogs();

        // ==================== 라우트 Import (DB 초기화 후) ====================

        // ==================== Authorization Policy + Repositories ====================
        // 접근 제어(SQL 조건) 및 DB 접근 경로를 중앙화하여
        // 라우트별 누락으로 인한 Broken Access Control(BOLA/IDOR) 류 취약점 재발을 방지
        const pageSqlPolicy = require('./authz/page-sql-policy');
        const repositories = require('./repositories')({ pool, pageSqlPolicy });

        /**
         * 각 라우트 파일에 필요한 의존성들을 주입합니다.
         * pool이 initDb()에서 생성되므로, DB 초기화 이후에 라우트를 등록합니다.
         */
        const routeDependencies = {
			pool,
			pageSqlPolicy,
            ...repositories,
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
            encryptTotpSecret,
            decryptTotpSecret,
            formatDateForDb,
            validatePasswordStrength,
            logError,
            authMiddleware,
            csrfMiddleware,
            toIsoString,
			sanitizeInput,
			sanitizeFilenameComponent,
            sanitizeExtension,
            sanitizeHtmlContent,
            generatePageId,
            generateShareToken,
            generatePublishToken,
            // WebSocket 관련 (websocket-server.js 모듈에서 import)
            wsConnections,
            wsBroadcastToPage,
            wsBroadcastToStorage,
			wsBroadcastToUser,
			wsCloseConnectionsForSession,
            wsKickUserFromStorage,
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
            COOKIE_SECURE,
            BCRYPT_SALT_ROUNDS,
            BASE_URL,
            coverUpload,
            editorImageUpload,
            themeUpload,
            fileUpload,
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
        const storagesRoutes = require('./routes/storages')(routeDependencies);
        const pagesRoutes = require('./routes/pages')(routeDependencies);
        const bootstrapRoutes = require('./routes/bootstrap')(routeDependencies);
        const totpRoutes = require('./routes/totp')(routeDependencies);
        const passkeyRoutes = require('./routes/passkey')(routeDependencies);
        const backupRoutes = require('./routes/backup')(routeDependencies);
        const themesRoutes = require('./routes/themes')(routeDependencies);
        const commentsRoutes = require('./routes/comments')(routeDependencies);

        // 라우트 등록
        app.use('/', indexRoutes);
        app.use('/api/auth', authRoutes);
        app.use('/api/storages', storagesRoutes);
        app.use('/api/pages', pagesRoutes);
        app.use('/api/bootstrap', bootstrapRoutes);
        app.use('/api/totp', totpRoutes);
        app.use('/api/passkey', passkeyRoutes);
        app.use('/api/backup', backupRoutes);
        app.use('/api/themes', themesRoutes);
        app.use('/api/comments', commentsRoutes);

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
                initWebSocketServer(httpsServer, sessions, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest, pageSqlPolicy);

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
                console.error('❌ HTTPS 인증서 발급 실패.');
                console.error(`   오류: ${certError.message}`);
				console.error('='.repeat(80) + '\n');

				// 보안: 프로덕션에서는 HTTPS 실패 시 HTTP로 조용히 폴백하면 안 됨 (fail-open → 평문 전송)
                const mustFailClosed = (IS_PRODUCTION || REQUIRE_HTTPS) && !ALLOW_INSECURE_HTTP_FALLBACK;

                if (mustFailClosed) {
                    console.error('🛑 [보안] HTTPS 설정이 실패했으므로 서버 시작을 중단합니다. (HTTP 폴백 금지)');
                    console.error('   - 점검: DUCKDNS_DOMAIN / DUCKDNS_TOKEN / CERT_EMAIL, DNS 레코드, 방화벽/포트(80/443) 개방 여부');
                    console.error('   - 긴급 상황에서만: ALLOW_INSECURE_HTTP_FALLBACK=true 로 명시적으로 HTTP 폴백을 허용할 수 있습니다. (비권장)');
                    process.exit(1);
                }

                console.warn('⚠️  [DEV/OVERRIDE] HTTPS 설정 실패로 HTTP 모드로 폴백합니다. (프로덕션에서는 비권장)');

				// HTTP 모드로 폴백
                const httpServer = app.listen(PORT, () => {
                    console.log(`⚠️  NTEOK 앱이 HTTP로 실행 중: http://localhost:${PORT}`);
                });

                // WebSocket 서버 초기화
                // HTTP 모드에서도 WebSocket 메시지 처리 시 세션 검증 로직(getSessionFromId)을 사용해야
                // 동기화 메시지가 "Session expired"로 오판되어 연결이 반복 종료되는 문제를 방지할 수 있습니다.
                initWebSocketServer(httpServer, sessions, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest, pageSqlPolicy);

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
            initWebSocketServer(httpServer, sessions, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest, pageSqlPolicy);

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
