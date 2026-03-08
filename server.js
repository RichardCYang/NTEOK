require('dotenv').config();

const express = require("express");
const path = require("path");
const fs = require("fs");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const expressRateLimit = require("express-rate-limit");
const rateLimit = expressRateLimit.rateLimit || expressRateLimit;
const _isoDomPurify = require("isomorphic-dompurify");
const DOMPurify = _isoDomPurify?.default || _isoDomPurify;

// Safely get dompurify version since package.json might not be exported in v3+
let domPurifyPkg;
try {
	domPurifyPkg = require("dompurify/package.json");
} catch (e) {
	// Fallback: Use version from object or manually read package.json via fs to bypass exports restriction
	let version = DOMPurify?.version;
	if (!version) {
		try {
			const entry = require.resolve("dompurify");
			const pkgPath = path.join(path.dirname(entry), "package.json");
			const pkgPathUp = path.join(path.dirname(entry), "..", "package.json");
			const target = fs.existsSync(pkgPath) ? pkgPath : (fs.existsSync(pkgPathUp) ? pkgPathUp : null);
			if (target) version = JSON.parse(fs.readFileSync(target, "utf8")).version;
		} catch (e2) {}
	}
	domPurifyPkg = { version: version || "unknown" };
}

function isVulnerableDomPurify(version) {
	const [maj, min, patch] = String(version).split(".").map(n => Number(n));
	if (!Number.isFinite(maj) || !Number.isFinite(min) || !Number.isFinite(patch)) return true;
	if (maj === 2 && min === 5 && patch >= 3 && patch <= 8) return true;
	if (maj === 3) {
		if (min === 1 && patch >= 3) return true;
		if (min === 2) return true;
		if (min === 3 && patch <= 1) return true;
	}
	return false;
}

if (isVulnerableDomPurify(domPurifyPkg.version)) throw new Error(`[boot] Refusing to start with vulnerable DOMPurify version: ${domPurifyPkg.version}`);

const publicPurifyPath = path.join(__dirname, "public", "lib", "dompurify", "dompurify.js");
try {
    const publicPurifyBundle = fs.readFileSync(publicPurifyPath, "utf8");
    const expected = String(domPurifyPkg.version);
    const bundleLooksMatched = publicPurifyBundle.includes(`o.version="${expected}"`) || 
                               publicPurifyBundle.includes(`version="${expected}"`) || 
                               publicPurifyBundle.includes(`version='${expected}'`) ||
                               publicPurifyBundle.includes(`DOMPurify.version = '${expected}'`) ||
                               publicPurifyBundle.includes(`DOMPurify.version = "${expected}"`);
    if (!bundleLooksMatched) throw new Error(`[boot] DOMPurify browser bundle mismatch: npm=${expected}, public bundle is stale`);
} catch (e) {
    throw new Error(`[boot] DOMPurify bundle integrity check failed: ${e.message}`);
}

const { redis, ensureRedis } = require("./lib/redis");
const { assertLoginNotLocked, recordLoginFailure, clearLoginFailures } = require("./lib/login-guard");
const { getSession, saveSession, listUserSessions, revokeSession } = require("./lib/session-store");
const buildRecentReauth = require("./middlewares/recent-reauth");
const { RedisStore } = require("rate-limit-redis");

const clearDomPurifyWindow = typeof _isoDomPurify?.clearWindow === "function"
	? _isoDomPurify.clearWindow.bind(_isoDomPurify)
	: null;
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const Y = require("yjs");
const https = require("https");
const http = require("http");
const certManager = require("./cert-manager");
const multer = require("multer");

const MULTIPART_COMMON_LIMITS = Object.freeze({
    files: 1,
    fields: 16,
    parts: 20,
    fieldNameSize: 100,
    fieldSize: 64 * 1024,
    headerPairs: 2000
});

function collectUploadedFilePaths(req) {
    const out = [];
    const pushOne = (f) => {
        if (f && typeof f.path === "string") out.push(f.path);
    };

    pushOne(req?.file);

    if (Array.isArray(req?.files)) {
        req.files.forEach(pushOne);
    } else if (req?.files && typeof req.files === "object") {
        for (const value of Object.values(req.files)) {
            if (Array.isArray(value)) value.forEach(pushOne);
            else pushOne(value);
        }
    }

    return [...new Set(out)];
}

function cleanupUploadedFiles(req) {
    for (const fp of collectUploadedFilePaths(req)) {
        try {
            if (fs.existsSync(fp)) fs.unlinkSync(fp);
        } catch (_) {}
    }
}
const compression = require("compression");
const {
	detectImageTypeFromMagic,
	assertImageFileSignature,
	assertSafeAttachmentFile,
	assertSafeCsvContent,
	installDomPurifySecurityHooks,
	isHostnameAllowedForPreview
} = require("./security-utils");
const ipKeyGenerator = expressRateLimit.ipKeyGenerator || (expressRateLimit.default && expressRateLimit.default.ipKeyGenerator);

const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
function isSafeHttpUrlOrRelative(value) {
    if (typeof value !== "string") return false;
    const v = value.trim();
    if (!v) return false;
    if (CONTROL_CHARS_RE.test(v)) return false;
    if (v.startsWith("//")) return false;
    if (v.startsWith("/") || v.startsWith("#")) return true;
    try {
        const u = new URL(v);
        return u.protocol === "http:" || u.protocol === "https:";
    } catch {
        return false;
    }
}

function sanitizeHttpHrefStrict(value, { allowRelative = false } = {}) {
    if (typeof value !== "string") return null;
    const v = value.trim();
    if (!v || CONTROL_CHARS_RE.test(v) || v.startsWith("//")) return null;
    if (allowRelative && (v.startsWith("/") || v.startsWith("#"))) return v;
    try {
        const u = new URL(v);
        if (u.protocol !== "http:" && u.protocol !== "https:") return null;
        u.username = "";
        u.password = "";
        return u.toString();
    } catch {
        return null;
    }
}

const YOUTUBE_ALLOWED_HOSTS = new Set([
    'youtube.com',
    'www.youtube.com',
    'm.youtube.com',
    'youtu.be',
    'youtube-nocookie.com',
    'www.youtube-nocookie.com'
]);

function parseYoutubeStartSeconds(u) {
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

function sanitizeBookmarkImageUrl(value) {
    if (typeof value !== "string") return null;
    const v = value.trim();
    if (!v) return null;
    if (CONTROL_CHARS_RE.test(v)) return null;
    if (v.startsWith("//") || v.startsWith("#")) return null;
    if (v.startsWith("/")) return v;

    try {
        const u = new URL(v);
        if (u.protocol !== "http:" && u.protocol !== "https:") return null;
        if (u.username || u.password) return null;
        if (net.isIP(u.hostname) && isPrivateOrLocalIP(u.hostname)) return null;
        return u.toString();
    } catch {
        return null;
    }
}

function applyDomPurifyPolicy() {
    try {
        if (typeof DOMPurify.removeAllHooks === "function") DOMPurify.removeAllHooks();
        if (typeof DOMPurify.clearConfig === "function") DOMPurify.clearConfig();
    } catch (_) {}
    installDomPurifySecurityHooks(DOMPurify);
    if (typeof DOMPurify?.addHook === "function") {
        DOMPurify.addHook("uponSanitizeAttribute", (_node, hookEvent) => {
            const name = String(hookEvent?.attrName || "").toLowerCase();

            if (name === "href") {
                const safe = sanitizeHttpHrefStrict(String(hookEvent.attrValue || ""), { allowRelative: true });
                if (!safe) {
                    hookEvent.keepAttr = false;
                    hookEvent.forceKeepAttr = false;
                } else {
                    hookEvent.attrValue = safe;
                }
            }

            if (name === "data-url" || name === "data-thumbnail") {
                const safe = sanitizeHttpHrefStrict(String(hookEvent.attrValue || ""), { allowRelative: false });
                if (!safe) {
                    hookEvent.keepAttr = false;
                    hookEvent.forceKeepAttr = false;
                } else {
                    hookEvent.attrValue = safe;
                }
            }

            if (name === "data-favicon") {
                const safe = sanitizeBookmarkImageUrl(String(hookEvent.attrValue || ""));
                if (!safe) {
                    hookEvent.keepAttr = false;
                    hookEvent.forceKeepAttr = false;
                } else {
                    hookEvent.attrValue = safe;
                }
            }

            if (name === "data-src") {
                const nodeType = String(_node?.getAttribute?.('data-type') || '').toLowerCase();
                const raw = String(hookEvent.attrValue || "");

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

                const safe = sanitizeHttpHrefStrict(raw, { allowRelative: true });
                if (!safe) {
                    hookEvent.keepAttr = false;
                    hookEvent.forceKeepAttr = false;
                    return;
                }
                hookEvent.attrValue = safe;

                if (nodeType === "file-block") {
                    const m = raw.match(/^\/paperclip\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/);
                    if (!m) {
                        hookEvent.keepAttr = false;
                        hookEvent.forceKeepAttr = false;
                        return;
                    }
                    const filename = m[2];
                    if (!filename || filename.includes('..') || /[\x00-\x1F\x7F]/.test(filename)) {
                        hookEvent.keepAttr = false;
                        hookEvent.forceKeepAttr = false;
                        return;
                    }
                }
            }
        });
    }
}

applyDomPurifyPolicy();

const DOMPURIFY_CLEAR_EVERY_CALLS = (() => {
    const n = Number.parseInt(process.env.DOMPURIFY_CLEAR_EVERY_CALLS || "2000", 10);
    return Number.isFinite(n) ? Math.max(200, Math.min(200000, n)) : 2000;
})();

let _dompurifyCallCount = 0;
let _dompurifyClearing = false;

function maybeRecycleDomPurify() {
    if (!clearDomPurifyWindow) return;
    _dompurifyCallCount++;
    if (_dompurifyCallCount < DOMPURIFY_CLEAR_EVERY_CALLS) return;
    if (_dompurifyClearing) return;
    _dompurifyClearing = true;
    try {
        _dompurifyCallCount = 0;
        clearDomPurifyWindow();
        applyDomPurifyPolicy();
    } finally {
        _dompurifyClearing = false;
    }
}

if (typeof ipKeyGenerator !== "function")
	throw new Error("express-rate-limit의 ipKeyGenerator를 찾지 못했습니다. 라이브러리 버전을 확인해 주세요.");

const RATE_LIMIT_IPV6_SUBNET = (() => {
    const n = Number(process.env.RATE_LIMIT_IPV6_SUBNET || 56);
    return Number.isFinite(n) ? n : 56;
})();

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
	enqueueYjsDbSave,
	flushAllPendingYjsDbSaves,
	flushAllPendingE2eeSaves,
	flushAllPendingE2eeUpdateLogs,

	wsCloseConnectionsForSession,
    wsCloseConnectionsForPage,
    wsHasActiveConnectionsForPage,
    wsKickUserFromStorage,
    extractFilesFromContent,
    invalidateYjsPersistenceForPage
} = require("./websocket-server");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(compression({
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    },
    level: 6,
    threshold: 1024
}));

app.use((req, res, next) => {
    req.clientIp = getClientIpFromRequest(req);
    next();
});

const SESSION_COOKIE_NAME_RAW = "nteok_session";
const CSRF_COOKIE_NAME_RAW = "nteok_csrf";

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const SESSION_ABSOLUTE_TTL_MS = 1000 * 60 * 60 * 24 * 7;

function isLocalhostHost(host) {
    return host === "localhost" || host === "127.0.0.1" || host === "::1";
}

const IS_PRODUCTION = process.env.NODE_ENV === "production";
const BASE_URL = process.env.BASE_URL || (IS_PRODUCTION ? "https://localhost:3000" : "http://localhost:3000");

if (IS_PRODUCTION) {
    const url = new URL(BASE_URL);
    if (url.protocol !== "https:" && !isLocalhostHost(url.hostname)) throw new Error("[security] BASE_URL must be HTTPS in production");
}

const IS_HTTPS_BASE_URL = (() => {
    try { return new URL(BASE_URL).protocol === "https:"; }
    catch { return false; }
})();

const REQUIRE_HTTPS = String(process.env.REQUIRE_HTTPS || '').toLowerCase() === 'true';

const ALLOW_INSECURE_COOKIES = String(process.env.ALLOW_INSECURE_COOKIES || '').toLowerCase() === 'true';
const FORCE_SECURE_COOKIES = (() => {
    const raw = String(process.env.FORCE_SECURE_COOKIES || '').toLowerCase();
    if (raw === 'true') return true;
    if (raw === 'false') return false;
    return IS_PRODUCTION;
})();

const COOKIE_SECURE = IS_PRODUCTION ? true : ((!ALLOW_INSECURE_COOKIES) && (FORCE_SECURE_COOKIES || IS_HTTPS_BASE_URL || REQUIRE_HTTPS));

if (IS_PRODUCTION && !COOKIE_SECURE) throw new Error("[security] COOKIE_SECURE must be true in production");

const SESSION_COOKIE_NAME = COOKIE_SECURE ? `__Host-${SESSION_COOKIE_NAME_RAW}` : SESSION_COOKIE_NAME_RAW;
const CSRF_COOKIE_NAME = COOKIE_SECURE ? `__Host-${CSRF_COOKIE_NAME_RAW}` : CSRF_COOKIE_NAME_RAW;
const PREAUTH_CSRF_COOKIE_NAME_RAW = "nteok_preauth_csrf";
const PREAUTH_CSRF_COOKIE_NAME = COOKIE_SECURE ? `__Host-${PREAUTH_CSRF_COOKIE_NAME_RAW}` : PREAUTH_CSRF_COOKIE_NAME_RAW;

const CSRF_HMAC_KEY = Buffer.from(
	process.env.CSRF_HMAC_KEY || crypto.randomBytes(32).toString("hex"),
	"utf8"
);

function generateCsrfTokenForSession(sessionId, purpose = "api") {
	const sid = String(sessionId || "");
	const ts = String(Date.now());
	const nonce = crypto.randomBytes(16).toString("hex");
	const payload = `${sid}.${purpose}.${ts}.${nonce}`;
	const sig = crypto.createHmac("sha256", CSRF_HMAC_KEY).update(payload).digest("hex");
	return `${payload}.${sig}`;
}

function verifyCsrfTokenForSession(sessionId, token, purpose = "api", maxAgeMs = 2 * 60 * 60 * 1000) {
	if (typeof token !== "string") return false;
	const parts = token.split(".");
	if (parts.length !== 5) return false;
	const [sid, tokPurpose, ts, nonce, sig] = parts;
	if (sid !== String(sessionId || "")) return false;
	if (tokPurpose !== purpose) return false;
	if (!/^\d+$/.test(ts)) return false;
	const age = Date.now() - Number(ts);
	if (age < 0 || age > maxAgeMs) return false;
	if (!/^[a-f0-9]{32}$/i.test(nonce) || !/^[a-f0-9]{64}$/i.test(sig)) return false;
	const payload = `${sid}.${tokPurpose}.${ts}.${nonce}`;
	const expected = crypto.createHmac("sha256", CSRF_HMAC_KEY).update(payload).digest("hex");
	try {
		return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
	} catch {
		return false;
	}
}

function generatePreAuthCsrfToken() {
	const nonce = crypto.randomBytes(16).toString("hex");
	const ts = String(Date.now());
	const payload = `preauth.${ts}.${nonce}`;
	const sig = crypto.createHmac("sha256", CSRF_HMAC_KEY).update(payload).digest("hex");
	return `${payload}.${sig}`;
}

function verifyPreAuthCsrfToken(req, maxAgeMs = 30 * 60 * 1000) {
	const tokenFromHeader = req.headers["x-csrf-token"];
	const tokenFromCookie = req.cookies[PREAUTH_CSRF_COOKIE_NAME];
	if (typeof tokenFromHeader !== "string" || tokenFromHeader !== tokenFromCookie) return false;
	const parts = tokenFromHeader.split(".");
	if (parts.length !== 4) return false;
	const [kind, ts, nonce, sig] = parts;
	if (kind !== "preauth" || !/^\d+$/.test(ts)) return false;
	const age = Date.now() - Number(ts);
	if (age < 0 || age > maxAgeMs) return false;
	const payload = `${kind}.${ts}.${nonce}`;
	const expected = crypto.createHmac("sha256", CSRF_HMAC_KEY).update(payload).digest("hex");
	try {
		return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expected, "hex"));
	} catch {
		return false;
	}
}

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

if (IS_PRODUCTION && ALLOW_INSECURE_HTTP_FALLBACK) throw new Error("[security] ALLOW_INSECURE_HTTP_FALLBACK is forbidden in production");

function decode32ByteKey(raw) {
    if (!raw) return null;
    const s = String(raw).trim();
    if (!s) return null;
    if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, "hex");
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
        console.error("❌ [SECURITY] TOTP_SECRET_ENC_KEY 필수 설정 누락");
        process.exit(1);
    } else {
        console.warn("⚠️  [SECURITY] TOTP_SECRET_ENC_KEY 미설정 - 임시 키 사용 (재시작 시 복호화 불가)");
    }
}

function encryptTotpSecret(plainBase32) {
    if (!plainBase32 || !TOTP_SECRET_ENC_KEY) return null;
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", TOTP_SECRET_ENC_KEY, iv);
    const ciphertext = Buffer.concat([cipher.update(String(plainBase32), "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `v1:${iv.toString("base64")}:${tag.toString("base64")}:${ciphertext.toString("base64")}`;
}

function decryptTotpSecret(storedValue) {
    if (!storedValue) return null;
    const s = String(storedValue);
    if (!s.startsWith("v1:") || !TOTP_SECRET_ENC_KEY) return s;

    const parts = s.split(":");
    if (parts.length !== 4) throw new Error("유효하지 않은 암호화 TOTP 비밀키 형식");

    const iv = Buffer.from(parts[1], "base64");
    const tag = Buffer.from(parts[2], "base64");
    const data = Buffer.from(parts[3], "base64");
    const decipher = crypto.createDecipheriv("aes-256-gcm", TOTP_SECRET_ENC_KEY, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}

const DEFAULT_ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
let DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!DEFAULT_ADMIN_PASSWORD) {
    if (IS_PRODUCTION) {
        console.error("❌ ADMIN_PASSWORD 미설정 (프로덕션 필수)");
        process.exit(1);
    }
    DEFAULT_ADMIN_PASSWORD = generateStrongPassword();
    if (String(process.env.SHOW_BOOTSTRAP_PASSWORD_IN_LOGS).toLowerCase() === "true") {
        console.warn(`⚠️  임시 관리자 비밀번호: ${DEFAULT_ADMIN_PASSWORD}`);
    }
}

{
    const pwLower = String(DEFAULT_ADMIN_PASSWORD || "").trim().toLowerCase();
    const strength = validatePasswordStrength(DEFAULT_ADMIN_PASSWORD);
    if (new Set(["admin", "password", "administrator"]).has(pwLower) || !strength.valid) {
        if (IS_PRODUCTION) {
            console.error(`🛑 [보안] ADMIN_PASSWORD 취약: ${strength.error || "강도 정책 위반"}`);
            process.exit(1);
        } else {
            DEFAULT_ADMIN_PASSWORD = generateStrongPassword();
        }
    }
}

const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 12);

if (IS_PRODUCTION) {
    const required = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'BASE_URL', 'ADMIN_PASSWORD', 'TOTP_SECRET_ENC_KEY'];
    const missing = required.filter(key => !process.env[key]);
    if (missing.length > 0) {
        console.error(`❌ 필수 환경변수 누락: ${missing.join(', ')}`);
        process.exit(1);
    }
}

function envOrDie(name, { defaultValue, allowInsecureDev = false } = {}) {
    const v = String(process.env[name] || "").trim();
    if (v) return v;
    if (allowInsecureDev && String(process.env.ALLOW_INSECURE_DB_DEFAULTS).toLowerCase() === 'true') return defaultValue;
    console.error(`🛑 필수 환경변수 누락: ${name}`);
    process.exit(1);
}

const DB_HOST = envOrDie("DB_HOST", { defaultValue: "localhost", allowInsecureDev: true });
const DB_USER = envOrDie("DB_USER", { defaultValue: "root", allowInsecureDev: true });
const DB_PASSWORD = envOrDie("DB_PASSWORD", { defaultValue: "admin", allowInsecureDev: true });
const DB_NAME = envOrDie("DB_NAME", { defaultValue: "nteok", allowInsecureDev: true });

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
function cleanupExpiredWebAuthnChallenges() {
    pool.execute("DELETE FROM webauthn_challenges WHERE expires_at < NOW()")
        .then(([res]) => res.affectedRows > 0 && console.log(`[WebAuthn 정리] ${res.affectedRows}개 만료 챌린지 제거`))
        .catch(err => console.error("WebAuthn 정리 실패:", err));
}
setInterval(cleanupExpiredWebAuthnChallenges, 300000);

function purgePaperclipTrash() {
    try {
        const root = path.resolve(__dirname, 'paperclip-trash');
        if (!fs.existsSync(root)) return;
        const cutoff = Date.now() - (Number(process.env.PAPERCLIP_TRASH_RETENTION_DAYS || 14)) * 86400000;
        let deleted = 0;
        fs.readdirSync(root, { withFileTypes: true }).filter(d => d.isDirectory()).forEach(d => {
            const dir = path.resolve(root, d.name);
            fs.readdirSync(dir).forEach(f => {
                const fp = path.resolve(dir, f);
                try { if (fs.statSync(fp).mtimeMs < cutoff) { fs.unlinkSync(fp); deleted++; } } catch (_) {}
            });
            try { if (fs.readdirSync(dir).length === 0) fs.rmdirSync(dir); } catch (_) {}
        });
        if (deleted > 0) console.log(`[휴지통 정리] ${deleted}개 파일 삭제`);
    } catch (_) {}
}
setInterval(purgePaperclipTrash, 86400000);
setTimeout(purgePaperclipTrash, 10 * 60 * 1000);

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


function generatePageId(now) {
    const iso = now.toISOString().replace(/[:.]/g, "-");
    const rand = crypto.randomBytes(6).toString("hex");
    return "page-" + iso + "-" + rand;
}



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

function generateCsrfToken() {
    return crypto.randomBytes(32).toString("hex");
}

function sanitizeInput(input) {
    if (typeof input !== 'string') {
        return input;
    }
    maybeRecycleDomPurify();
    return DOMPurify.sanitize(input, {
        ALLOWED_TAGS: [],
        ALLOWED_ATTR: []
    });
}

function sanitizeFilenameComponent(name, maxLen = 120) {
    const s = String(name ?? '').normalize('NFKC');
    const cleaned = s
        .replace(/[\u0000-\u001F\u007F]/g, '')
        .replace(/[\\/]/g, '_')
        .replace(/["'<>`]/g, '')
        .trim();
    return (cleaned.length ? cleaned : 'file').slice(0, maxLen);
}

function sanitizeExtension(ext) {
    if (!ext) return '';
    const lower = String(ext).toLowerCase();
    return /^\.[a-z0-9]{1,10}$/.test(lower) ? lower : '';
}

function deriveDownloadNameFromStoredFilename(stored) {
    const safeStored = sanitizeFilenameComponent(stored, 200);
    const idx = safeStored.indexOf('__');
    if (idx >= 0) {
        const tail = safeStored.slice(idx + 2);
        return tail.length ? tail : 'download';
    }
    return safeStored;
}

function setNoStore(res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
}

function sendSafeDownload(res, filePath, downloadName) {
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    setNoStore(res);
    return res.download(filePath, downloadName);
}

function sendSafeImage(res, filePath) {
	const detected = assertImageFileSignature(filePath, new Set(['jpg', 'jpeg', 'png', 'gif', 'webp']));

	res.setHeader('Content-Type', detected.mime);
	res.setHeader('X-Content-Type-Options', 'nosniff');

	res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
	res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

	setNoStore(res);

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

async function resolveReadableLivePageForAsset({ pageId, viewerUserId, ownerUserId }) {
	const [rows] = await pool.execute(
		`SELECT p.id, p.storage_id, p.is_encrypted, p.share_allowed, p.user_id
		   FROM pages p
		   JOIN storages s ON p.storage_id = s.id
		   LEFT JOIN storage_shares ss_cur
			 ON s.id = ss_cur.storage_id
			AND ss_cur.shared_with_user_id = ?
		  WHERE p.id = ?
			AND p.user_id = ?
			AND p.deleted_at IS NULL
			AND (s.user_id = ? OR ss_cur.shared_with_user_id IS NOT NULL)
			AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
		  LIMIT 1`,
		[viewerUserId, pageId, ownerUserId, viewerUserId, viewerUserId]
	);
	return rows[0] || null;
}

async function canUseLiveAssetFallback({ pageId, viewerUserId, ownerUserId, myConn, docInfo }) {
	if (!myConn || !docInfo) return false
	if (!docInfo.storageId || !myConn.storageId) return false
	if (String(docInfo.storageId) !== String(myConn.storageId)) return false
	if (!Number.isFinite(docInfo.ownerUserId) || Number(docInfo.ownerUserId) !== Number(ownerUserId)) return false

	const livePage = await resolveReadableLivePageForAsset({
		pageId,
		viewerUserId,
		ownerUserId
	});
	if (!livePage) return false

	const dbStorageId = String(livePage.storage_id)
	if (String(docInfo.storageId) !== dbStorageId) return false
	if (String(myConn.storageId) !== dbStorageId) return false

	return true
}

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

	if (Buffer.byteLength(out, "utf8") > MAX_HTML_SANITIZE_BYTES)
		out = out.slice(0, MAX_HTML_SANITIZE_BYTES);

	out = out.replace(/<style\b[^>]*>[\s\S]*?<\/style\s*>/gi, "");

	out = out.replace(/<link\b[^>]*\brel\s*=\s*(['"])\s*stylesheet\s*\1[^>]*>/gi, "");
	out = out.replace(/<link\b(?=[^>]*\brel\s*=\s*stylesheet\b)[^>]*>/gi, "");

	return out;
}

const BASE_ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 's', 'code', 'pre',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li', 'blockquote',
    'a', 'span', 'div',
    'hr',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'img', 'figure'
];

const BASE_ALLOWED_ATTR = [
    'class', 'href', 'target', 'rel',
    'data-type', 'data-latex',
    'colspan', 'rowspan', 'colwidth',
    'src', 'alt', 'data-src', 'data-alt', 'data-caption', 'data-width', 'data-align',
    'data-url', 'data-title', 'data-favicon', 'data-description', 'data-thumbnail',
    'data-id', 'data-icon', 'data-checked',
    'data-callout-type', 'data-content',
    'data-columns', 'data-is-open'
];

const EDITOR_ALLOWED_TAGS = [...BASE_ALLOWED_TAGS, 'label', 'input'];
const EDITOR_ALLOWED_ATTR = [
    ...BASE_ALLOWED_ATTR,
    'style', 'type', 'checked',
    'data-selected-date', 'data-memos'
];

function sanitizeHtmlContent(html, { profile = 'editor' } = {}) {
    if (typeof html !== 'string') return html;

    const prefiltered = prefilterHtmlForSanitizer(html);

    try {
        maybeRecycleDomPurify();
        const config = profile === 'shared'
            ? {
                ALLOWED_TAGS: BASE_ALLOWED_TAGS,
                ALLOWED_ATTR: BASE_ALLOWED_ATTR,
                ALLOW_DATA_ATTR: true,
                FORBID_ATTR: ['style'],
                ALLOWED_URI_REGEXP: /^(?:(?:(?:ht)tps?|mailto|tel):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
            }
            : {
                ALLOWED_TAGS: EDITOR_ALLOWED_TAGS,
                ALLOWED_ATTR: EDITOR_ALLOWED_ATTR,
                ALLOW_DATA_ATTR: true,
                ALLOWED_URI_REGEXP: /^(?:(?:(?:ht)tps?|mailto|tel):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i
            };

        return DOMPurify.sanitize(prefiltered, config);
    } catch (err) {
        const escaped = escapeHtmlToText(prefiltered);
        return `<p>${escaped}</p>`;
    }
}

function validatePasswordStrength(password) {
    if (!password || typeof password !== 'string')
        return { valid: false, error: "비밀번호를 입력해 주세요." };

    if (CONTROL_CHARS_RE.test(password))
        return { valid: false, error: "비밀번호에 제어 문자를 사용할 수 없습니다." };

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

function generateStrongPassword(length = 20) {
    const LOWER = "abcdefghijklmnopqrstuvwxyz";
    const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS = "0123456789";
    const SPECIAL = "!@#$%^&*(),.?\":{}|<>";

    const pick = (chars) => {
        if (!chars || chars.length === 0) throw new Error("generateStrongPassword: empty charset");
        return chars[crypto.randomInt(0, chars.length)];
    };

    const targetLen = Math.max(12, Number.isFinite(Number(length)) ? Number(length) : 20);

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

    for (let i = arr.length - 1; i > 0; i--) {
        const j = crypto.randomInt(0, i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
    }

    const pw = arr.join("");
    return validatePasswordStrength(pw).valid ? pw : generateStrongPassword(targetLen);
}

function logError(context, error) {
    if (IS_PRODUCTION) {
        console.error(`[오류] ${context}`);
    } else {
        console.error(`[오류] ${context}:`, error);
    }
}

async function verifyCsrfToken(req) {
	const guestAllowedPaths = [
		'/comments/shared/',
		'/auth/login',
		'/auth/register',
		'/passkey/login/',
		'/passkey/authenticate/',
		'/totp/verify-login',
		'/totp/verify-backup-code',
		'/shared/page/exchange'
	];
	if (guestAllowedPaths.some(p => req.path.startsWith(p))) return true;

	const tokenFromHeader = req.headers["x-csrf-token"];
	const tokenFromCookie = req.cookies[CSRF_COOKIE_NAME];
	if (typeof tokenFromHeader !== "string" || typeof tokenFromCookie !== "string") return false;
	if (tokenFromHeader !== tokenFromCookie) return false;
	const sessionId = req.cookies?.[SESSION_COOKIE_NAME];
	if (!sessionId) return false;
	return verifyCsrfTokenForSession(sessionId, tokenFromHeader, "api");
}

async function csrfMiddleware(req, res, next) {
	if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
	if (!(await verifyCsrfToken(req))) {
		console.warn("CSRF 토큰 검증 실패:", req.path, req.method);
		return res.status(403).json({ error: "CSRF 토큰이 유효하지 않습니다." });
	}
	next();
}

function hashUserAgent(ua) {
	return crypto.createHash("sha256").update(String(ua || "")).digest("hex");
}

async function createSession(user, ctx = {}) {
	const sessionId = crypto.randomBytes(24).toString("hex");
	const now = Date.now();
	const expiresAt = now + SESSION_TTL_MS;
	const absoluteExpiry = now + SESSION_ABSOLUTE_TTL_MS;
	const existingSessions = await listUserSessions(user.id);
	if (existingSessions && existingSessions.length > 0) {
		if (user.blockDuplicateLogin) return { success: false, error: '이미 다른 위치에서 로그인 중입니다.' };
		wsBroadcastToUser(user.id, 'duplicate-login', { message: '다른 위치에서 로그인하여 현재 세션이 종료됩니다.', timestamp: new Date().toISOString() });
		for (const oldSessionId of existingSessions) await revokeSession(oldSessionId, "duplicate-login");
	}
	const session = { type: "auth", userId: user.id, username: user.username, uaHash: hashUserAgent(ctx.userAgent || ""), expiresAt, absoluteExpiry, createdAt: now, lastStrongAuthAt: now };
	await saveSession(sessionId, session, SESSION_ABSOLUTE_TTL_MS);
	return { success: true, sessionId };
}

async function getSessionFromRequest(req) {
	if (!req.cookies) return null;
	const sessionId = req.cookies[SESSION_COOKIE_NAME];
	if (!sessionId) return null;
	const session = await getSession(sessionId);
	if (!session || session.type !== 'auth' || !session.userId) return null;
	const currentUaHash = hashUserAgent(req.headers["user-agent"] || "");
	if (session.uaHash && session.uaHash !== currentUaHash) {
		await revokeSession(sessionId, "ua-mismatch");
		return null;
	}
	const now = Date.now();
	if (session.absoluteExpiry <= now || session.expiresAt <= now) {
		await revokeSession(sessionId, "session-expired");
		return null;
	}
	session.expiresAt = now + SESSION_TTL_MS;
	await saveSession(sessionId, session, SESSION_ABSOLUTE_TTL_MS);
	return { id: sessionId, ...session };
}

async function authMiddleware(req, res, next) {
	const session = await getSessionFromRequest(req);
	if (!session) return res.status(401).json({ error: "로그인이 필요합니다." });
	req.user = { id: session.userId, username: session.username };
	next();
}

async function initDb() {
    pool = await mysql.createPool(DB_CONFIG);

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

    await pool.execute(`
        CREATE TABLE IF NOT EXISTS storages (
            id          VARCHAR(64)  NOT NULL PRIMARY KEY,
            user_id     INT          NOT NULL,
            name        VARCHAR(255) NOT NULL,
            sort_order  INT          NOT NULL DEFAULT 0,
            created_at  DATETIME     NOT NULL,
            updated_at  DATETIME     NOT NULL,
            is_encrypted TINYINT(1) NOT NULL DEFAULT 0,
            encryption_salt VARCHAR(255) NULL,
            encryption_check VARCHAR(512) NULL,
            dek_version TINYINT(1) NOT NULL DEFAULT 0,
            CONSTRAINT fk_storages_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

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
            -- E2EE(저장소 암호화) 실시간 협업 상태(암호문) 영속 저장용
            -- 서버는 평문을 모르므로, 암호화된 Yjs 스냅샷만 저장
            e2ee_yjs_state LONGBLOB NULL,
            e2ee_yjs_state_updated_at DATETIME NULL,
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

    try {
        await pool.execute(`
            UPDATE pages
            SET encryption_salt = NULL,
                encrypted_content = NULL
            WHERE is_encrypted = 0
              AND (encryption_salt IS NOT NULL OR encrypted_content IS NOT NULL)
        `);
    } catch (e) {
        console.error("[Security Cleanup] Failed to clean up stale encryption data:", e.message);
    }

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

    await pool.execute(`
        CREATE TABLE IF NOT EXISTS page_publish_links (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            token VARCHAR(64) NOT NULL UNIQUE,
            page_id VARCHAR(64) NOT NULL,
            owner_user_id INT NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            allow_comments TINYINT(1) NOT NULL DEFAULT 0,
            expires_at DATETIME NULL,
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
            INDEX idx_page_id (page_id),
            INDEX idx_expires_at (expires_at)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    await pool.execute(
        `UPDATE page_publish_links ppl
         JOIN pages p ON p.id = ppl.page_id
         SET ppl.is_active = 0, ppl.updated_at = NOW()
         WHERE ppl.is_active = 1 AND p.deleted_at IS NOT NULL`
    );

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

    await pool.execute(`
        CREATE TABLE IF NOT EXISTS page_file_refs (
            id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            page_id VARCHAR(64) NOT NULL,
            owner_user_id INT NOT NULL,
            stored_filename VARCHAR(200) NOT NULL,
            file_type ENUM('paperclip', 'imgs') NOT NULL DEFAULT 'paperclip',
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

            UNIQUE KEY uq_page_file_ref (page_id, owner_user_id, stored_filename, file_type),
            KEY idx_page_file_lookup (owner_user_id, stored_filename, page_id),

            CONSTRAINT fk_page_file_refs_page
              FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
            CONSTRAINT fk_page_file_refs_owner
              FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    await pool.execute(`
        CREATE TABLE IF NOT EXISTS e2ee_yjs_updates (
            id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            page_id VARCHAR(64) NOT NULL,
            created_at_ms BIGINT NOT NULL,
            created_at DATETIME NOT NULL,
            update_blob LONGBLOB NOT NULL,
            INDEX idx_e2ee_wal_page_ms (page_id, created_at_ms),
            CONSTRAINT fk_e2ee_wal_page FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    await pool.execute(`
        CREATE TABLE IF NOT EXISTS user_key_pairs (
            kid                    VARCHAR(64)  NOT NULL PRIMARY KEY,
            user_id                INT          NOT NULL,
            public_key_spki        TEXT         NOT NULL,
            encrypted_private_key  TEXT         NOT NULL,
            key_wrap_salt          VARCHAR(255) NOT NULL,
            device_label           VARCHAR(100) NULL,
            created_at             DATETIME     NOT NULL,
            CONSTRAINT fk_ukp_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            INDEX idx_ukp_user (user_id)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

    await pool.execute(`
        CREATE TABLE IF NOT EXISTS storage_share_keys (
            id                    BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
            storage_id            VARCHAR(64)  NOT NULL,
            shared_with_user_id   INT          NOT NULL,
            wrapped_dek           TEXT         NOT NULL,
            wrapping_kid          VARCHAR(64)  NOT NULL,
            ephemeral_public_key  TEXT         NULL,
            created_at            DATETIME     NOT NULL,
            UNIQUE KEY uk_ssk (storage_id, shared_with_user_id),
            CONSTRAINT fk_ssk_storage FOREIGN KEY (storage_id) REFERENCES storages(id) ON DELETE CASCADE,
            CONSTRAINT fk_ssk_user    FOREIGN KEY (shared_with_user_id) REFERENCES users(id) ON DELETE CASCADE,
            CONSTRAINT fk_ssk_kid     FOREIGN KEY (wrapping_kid) REFERENCES user_key_pairs(kid)
        ) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci
    `);

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

    try {
        const [refCountRows] = await pool.execute("SELECT COUNT(*) AS cnt FROM page_file_refs");
        if (refCountRows[0].cnt === 0) {
            console.log('보안 레지스트리 백필 시작...');
            const [pages] = await pool.execute("SELECT id, user_id, content FROM pages WHERE is_encrypted = 0 AND deleted_at IS NULL");

            for (const page of pages) {
                if (!page.content) continue;

                const paperclipRe = /\/paperclip\/(\d+)\/([A-Za-z0-9._-]+)/g;
                let match;
                while ((match = paperclipRe.exec(page.content)) !== null) {
                    const ownerId = parseInt(match[1], 10);
                    const filename = match[2];
                    if (ownerId === page.user_id) {
                        await pool.execute(
                            `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
                             VALUES (?, ?, ?, 'paperclip', NOW())`,
                            [page.id, ownerId, filename]
                        );
                    }
                }

                const imgsRe = /\/imgs\/(\d+)\/([A-Za-z0-9._-]+)/g;
                while ((match = imgsRe.exec(page.content)) !== null) {
                    const ownerId = parseInt(match[1], 10);
                    const filename = match[2];
                    if (ownerId === page.user_id) {
                        await pool.execute(
                            `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
                             VALUES (?, ?, ?, 'imgs', NOW())`,
                            [page.id, ownerId, filename]
                        );
                    }
                }
            }
            console.log('✓ 보안 레지스트리 백필 완료');
        }
    } catch (error) {
        console.error('보안 레지스트리 백필 중 오류:', error);
    }

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

    try {
        const [migRows] = await pool.execute(
            `UPDATE pages SET share_allowed = 1
             WHERE is_encrypted = 1 AND encryption_salt IS NULL AND share_allowed = 0`
        );
        if (migRows.affectedRows > 0) {
            console.log(`✓ E2EE 페이지 share_allowed 마이그레이션 완료 (${migRows.affectedRows}건 업데이트)`);
        }
    } catch (error) {
        console.error('E2EE 페이지 share_allowed 마이그레이션 중 오류:', error);
    }

    const [userRows] = await pool.execute("SELECT COUNT(*) AS cnt FROM users");
    const userCount = userRows[0].cnt;

    if (userCount === 0) {
        const now = new Date();
        const nowStr = formatDateForDb(now);

        const username = DEFAULT_ADMIN_USERNAME;
        const rawPassword = DEFAULT_ADMIN_PASSWORD;

        const check = validatePasswordStrength(rawPassword);
        if (!check.valid) {
            throw new Error(`ADMIN_PASSWORD 약함: ${check.error || "invalid"}`);
        }

        const passwordHash = await bcrypt.hash(rawPassword, BCRYPT_SALT_ROUNDS);

        const [result] = await pool.execute(
            `
            INSERT INTO users (username, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            `,
            [username, passwordHash, nowStr, nowStr]
        );

        const adminUserId = result.insertId;

        const storageId = 'stg-' + now.getTime() + '-' + crypto.randomBytes(4).toString('hex');
        await pool.execute(
            `
            INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            `,
            [storageId, adminUserId, "기본 저장소", 0, nowStr, nowStr]
        );

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

function generateShareToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generatePublishToken() {
    return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
    if (!token) return null;
    return crypto.createHash('sha256').update(String(token)).digest('hex');
}

const createRedisStore = (prefix) => new RedisStore({
	sendCommand: (...args) => redis.sendCommand(args),
	prefix: `nteok:rl:${prefix}:`
});

const generalLimiter = rateLimit({
	windowMs: 1 * 60 * 1000,
	max: 100,
	message: { error: "너무 많은 요청이 발생했습니다. 잠시 후 다시 시도해 주세요." },
	standardHeaders: true,
	legacyHeaders: false,
	store: createRedisStore("general"),
	keyGenerator: (req) => ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET)
});

const authLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 5,
	message: { error: "너무 많은 로그인 시도가 발생했습니다. 15분 후 다시 시도해 주세요." },
	standardHeaders: true,
	legacyHeaders: false,
	store: createRedisStore("auth"),
	keyGenerator: (req) => ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET),
	skipSuccessfulRequests: true,
});

const totpLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 10,
	message: { error: "너무 많은 인증 시도가 발생했습니다. 15분 후 다시 시도해 주세요." },
	standardHeaders: true,
	legacyHeaders: false,
	store: createRedisStore("totp"),
	keyGenerator: (req) => ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET)
});

const passkeyLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 10,
	message: { error: "너무 많은 패스키 인증 요청이 발생했습니다. 잠시 후 다시 시도해 주세요." },
	standardHeaders: true,
	legacyHeaders: false,
	store: createRedisStore("passkey"),
	keyGenerator: (req) => ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET)
});

const sseConnectionLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 50,
	message: { error: "SSE 연결 제한 초과" },
	standardHeaders: true,
	legacyHeaders: false,
	store: createRedisStore("sse"),
	keyGenerator: (req) => (req.user?.id ? `user:${req.user.id}` : ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET))
});

const outboundFetchLimiter = rateLimit({
	windowMs: 1 * 60 * 1000,
	max: 20,
	message: { error: "외부 리소스 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요." },
	standardHeaders: true,
	legacyHeaders: false,
	store: createRedisStore("outbound"),
	keyGenerator: (req) => (req.user?.id ? `user:${req.user.id}` : ipKeyGenerator(req.clientIp, RATE_LIMIT_IPV6_SUBNET))
});



const JSON_BODY_LIMIT = process.env.JSON_BODY_LIMIT || "1mb";
app.use(express.json({ limit: JSON_BODY_LIMIT }));

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
    try {
        stripDangerousKeys(req.body);
    } catch (_) {
    }
    next();
});

const PUBLIC_FORBIDDEN_EXT_RE = /\.(?:bak|backup|old|tmp|swp|swo|orig|save)$/i;
app.use((req, res, next) => {
    if (req.method === "GET" || req.method === "HEAD") {
        const p = String(req.path || "");
        if (PUBLIC_FORBIDDEN_EXT_RE.test(p)) {
            return res.status(404).end();
        }
    }
    next();
});

app.use(express.urlencoded({ extended: false, limit: JSON_BODY_LIMIT }));
app.use(cookieParser());

app.disable("x-powered-by");

app.use((req, res, next) => {
	res.locals.cspNonce = crypto.randomBytes(16).toString("base64");
	next();
});

app.use((req, res, next) => {
    const nonce = res.locals.cspNonce;
    res.setHeader(
        "Content-Security-Policy",
		"default-src 'self'; " +
		"base-uri 'self'; " +
        "object-src 'none'; " +
        "frame-ancestors 'none'; " +
        "frame-src 'self' https://www.youtube.com https://youtube.com https://www.youtube-nocookie.com https://youtube-nocookie.com; " +
        "form-action 'self'; " +
        `script-src 'nonce-${nonce}' 'strict-dynamic'; ` +
        `style-src-elem 'self' 'nonce-${nonce}' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://fonts.googleapis.com; ` +
        "style-src-attr 'self' 'unsafe-inline'; " +
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; " +
        "img-src 'self' data: https:; " +
        "connect-src 'self';"
    );

    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
	res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');

    if (HSTS_ENABLED)
        res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');

	next();
});

app.use((req, res, next) => {
	const sessionId = req.cookies?.[SESSION_COOKIE_NAME];
	if (sessionId && !req.cookies[CSRF_COOKIE_NAME]) {
		const token = generateCsrfTokenForSession(sessionId, "api");
		res.cookie(CSRF_COOKIE_NAME, token, {
			httpOnly: false,
			sameSite: "strict",
			secure: COOKIE_SECURE,
			path: "/",
			maxAge: SESSION_TTL_MS
		});
	}
	next();
});

app.use("/api", csrfMiddleware);

app.use("/api", generalLimiter);

app.use("/api", (req, res, next) => {
    setNoStore(res);
    next();
});

app.use(express.static(path.join(__dirname, "public"), {
    index: false,
    maxAge: IS_PRODUCTION ? '7d' : 0,
    etag: true,
    lastModified: true,
    immutable: IS_PRODUCTION,
    setHeaders: (res, filePath, stat) => {
        if (filePath.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
            res.setHeader('Pragma', 'no-cache');
            res.setHeader('Expires', '0');
        }
        else if (filePath.endsWith('.js') || filePath.endsWith('.css')) {
            res.setHeader('Cache-Control', IS_PRODUCTION
                ? 'public, max-age=604800, immutable'
                : 'no-cache');
        }
        else if (filePath.match(/\.(jpg|jpeg|png|gif|ico|svg|woff|woff2|ttf|eot)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
        }
    }
}));

app.use('/themes', express.static(path.join(__dirname, 'themes')));

app.use('/languages', express.static(path.join(__dirname, 'languages')));

app.use('/covers/default', express.static(path.join(__dirname, 'covers', 'default')));

app.get('/covers/:userId/:filename', authMiddleware, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId, 10);

    if (!Number.isFinite(requestedUserId))
        return res.status(400).json({ error: '잘못된 요청입니다.' });

    setNoStore(res);

    const currentUserId = req.user.id;

    try {
        const sanitizedFilename = sanitizeFilenameComponent(req.params.filename, 200);
        if (!sanitizedFilename) {
            return res.status(400).json({ error: '잘못된 파일명입니다.' });
        }

        const ext = path.extname(sanitizedFilename).toLowerCase();
        const ALLOWED_COVER_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp']);
        if (!ALLOWED_COVER_EXTS.has(ext)) {
            return res.status(400).json({ error: '지원하지 않는 파일 형식입니다.' });
        }

        const filePath = path.join(__dirname, 'covers', String(requestedUserId), sanitizedFilename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '파일을 찾을 수 없습니다.' });
        }

        if (requestedUserId === currentUserId) {
            return sendSafeImage(res, filePath);
        }

        const coverPath = `${requestedUserId}/${sanitizedFilename}`;
        const [rows] = await pool.execute(
            `SELECT p.id
               FROM pages p
               JOIN storages s ON p.storage_id = s.id
               LEFT JOIN storage_shares ss_cur
                 ON s.id = ss_cur.storage_id AND ss_cur.shared_with_user_id = ?
              WHERE p.cover_image = ?
                AND p.deleted_at IS NULL
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
            return sendSafeImage(res, filePath);
        }

        console.warn(`[보안] 사용자 ${currentUserId}이(가) 권한 없이 커버 이미지 접근 시도: ${coverPath}`);
        return res.status(403).json({ error: '접근 권한이 없습니다.' });

    } catch (error) {
        logError('GET /covers/:userId/:filename', error);
        res.status(500).json({ error: '파일 로드 실패' });
    }
});

app.get('/imgs/:userId/:filename', authMiddleware, async (req, res) => {
	const requestedUserId = parseInt(req.params.userId, 10);

	if (!Number.isFinite(requestedUserId))
		return res.status(400).json({ error: '잘못된 요청입니다.' });

	setNoStore(res);

    const currentUserId = req.user.id;

    try {
        const sanitizedFilename = sanitizeFilenameComponent(req.params.filename, 200);
        if (!sanitizedFilename) {
            return res.status(400).json({ error: '잘못된 파일명입니다.' });
        }

        const ext = path.extname(sanitizedFilename).toLowerCase();
        const ALLOWED_IMG_EXTS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp']);
        if (!ALLOWED_IMG_EXTS.has(ext)) {
            return res.status(400).json({ error: '지원하지 않는 파일 형식입니다.' });
        }

        const filePath = path.join(__dirname, 'imgs', String(requestedUserId), sanitizedFilename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '파일을 찾을 수 없습니다.' });
        }

        if (requestedUserId === currentUserId) {
            return sendSafeImage(res, filePath);
        }

        const imagePath = `${requestedUserId}/${sanitizedFilename}`;
        const imageUrl = `/imgs/${imagePath}`;

        const escapeLike = (s) => String(s).replace(/[\\%_]/g, (m) => `\\${m}`);
        const likePattern = `%${escapeLike(imageUrl)}%`;

        const [rows] = await pool.execute(
            `SELECT p.id
                FROM page_file_refs pfr
                JOIN pages p ON p.id = pfr.page_id
                JOIN storages s ON p.storage_id = s.id
                LEFT JOIN storage_shares ss_cur ON s.id = ss_cur.storage_id AND ss_cur.shared_with_user_id = ?
                WHERE pfr.owner_user_id = ?
                AND pfr.stored_filename = ?
                AND pfr.file_type = 'imgs'
                AND p.content LIKE ? ESCAPE '\\\\'
                AND p.deleted_at IS NULL
                AND (s.user_id = ? OR ss_cur.shared_with_user_id IS NOT NULL)
                -- 보안패치: 암호화 + 공유불가 페이지의 자산은
                -- 페이지 본문 접근이 차단된 사용자(컬렉션 소유자 포함)에게도 노출되면 안 됨
                AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
                -- 보안패치: 파일 소유자와 참조하는 페이지 소유자를 반드시 일치시킴
                AND p.user_id = ?
                LIMIT 1`,
            [
                currentUserId,
                requestedUserId,
                sanitizedFilename,
                likePattern,
                currentUserId,
                currentUserId,
                requestedUserId
            ]
        );

        if (rows.length > 0) {
            return sendSafeImage(res, filePath);
        }

		for (const [pageId, connections] of wsConnections.pages) {
			const myConn = Array.from(connections).find(c => c.userId === currentUserId);
			if (!myConn) continue

			const docInfo = yjsDocuments.get(pageId);
			if (!docInfo) continue

			if (!(await canUseLiveAssetFallback({
				pageId,
				viewerUserId: currentUserId,
				ownerUserId: requestedUserId,
				myConn,
				docInfo
			}))) continue

			const ydoc = docInfo.ydoc;

			let hasVerifiedImgRef = null;
			const ensureVerifiedImgRef = async () => {
				if (hasVerifiedImgRef !== null) return hasVerifiedImgRef;
				const [refRows] = await pool.execute(
					`SELECT id FROM page_file_refs
					  WHERE page_id = ? AND owner_user_id = ? AND stored_filename = ? AND file_type = 'imgs'
					  LIMIT 1`,
					[pageId, requestedUserId, sanitizedFilename]
				);
				hasVerifiedImgRef = refRows.length > 0;
				return hasVerifiedImgRef;
			};

			const content = ydoc.getMap('metadata').get('content') || '';
			if (content.includes(imageUrl) && await ensureVerifiedImgRef()) return sendSafeImage(res, filePath);

			const xmlContent = ydoc.getXmlFragment('prosemirror').toString();
			if (xmlContent.includes(imageUrl) && await ensureVerifiedImgRef()) return sendSafeImage(res, filePath);
		}

		console.warn(`[보안] 사용자 ${currentUserId}이(가) 권한 없이 이미지 접근 시도: ${imagePath}`);
		return res.status(403).json({ error: '접근 권한이 없습니다.' });

    } catch (error) {
        logError('GET /imgs/:userId/:filename', error);
        res.status(500).json({ error: '파일 로드 실패' });
    }
});

app.get('/paperclip/:userId/:filename', authMiddleware, async (req, res) => {
    const requestedUserId = parseInt(req.params.userId, 10);

    if (!Number.isFinite(requestedUserId))
        return res.status(400).json({ error: '잘못된 요청입니다.' });

    const currentUserId = req.user.id;

    try {
        const sanitizedFilename = sanitizeFilenameComponent(req.params.filename, 200);
        if (!sanitizedFilename) {
            return res.status(400).json({ error: '잘못된 파일명입니다.' });
        }

        const filePath = path.join(__dirname, 'paperclip', String(requestedUserId), sanitizedFilename);

        const getDownloadName = () => {
            const raw = req.query?.name;
            if (typeof raw === 'string' && raw.trim().length) {
                let safe = sanitizeFilenameComponent(raw, 200);
                if (safe && !path.extname(safe)) {
                    const ext = sanitizeExtension(path.extname(sanitizedFilename));
                    if (ext) safe += ext;
                }
                return safe || 'download';
            }
            return deriveDownloadNameFromStoredFilename(sanitizedFilename);
        };

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ error: '파일을 찾을 수 없습니다.' });
        }

        if (requestedUserId === currentUserId) {
			const downloadName = getDownloadName();
			return sendSafeDownload(res, filePath, downloadName);
        }

        const fileUrlPart = `/paperclip/${requestedUserId}/${sanitizedFilename}`;

        const escapeLike = (s) => String(s).replace(/[\\%_]/g, (m) => `\\${m}`);
        const likePattern = `%${escapeLike(fileUrlPart)}%`;

        const [rows] = await pool.execute(
            `SELECT p.id
                FROM page_file_refs pfr
                JOIN pages p ON p.id = pfr.page_id
                JOIN storages s ON p.storage_id = s.id
                LEFT JOIN storage_shares ss_cur ON s.id = ss_cur.storage_id AND ss_cur.shared_with_user_id = ?
                WHERE pfr.owner_user_id = ?
                AND pfr.stored_filename = ?
                AND pfr.file_type = 'paperclip'
                AND p.content LIKE ? ESCAPE '\\\\'
                AND p.deleted_at IS NULL
                AND (s.user_id = ? OR ss_cur.shared_with_user_id IS NOT NULL)
                -- 보안패치: 암호화 + 공유불가 페이지의 첨부파일은
                -- 페이지 본문 접근이 차단된 사용자에게 우회적으로 다운로드되면 안 됨
                AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
                -- 보안패치: 파일 소유자 == 참조 페이지 소유자
                AND p.user_id = ?
                LIMIT 1`,
            [
                currentUserId,
                requestedUserId,
                sanitizedFilename,
                likePattern,
                currentUserId,
                currentUserId,
                requestedUserId
            ]
        );

        if (rows.length > 0) {
			const downloadName = getDownloadName();
			return sendSafeDownload(res, filePath, downloadName);
        }

		for (const [pageId, connections] of wsConnections.pages) {
			const myConn = Array.from(connections).find(c => c.userId === currentUserId);
			if (!myConn) continue

			const docInfo = yjsDocuments.get(pageId);
			if (!docInfo) continue

			if (!(await canUseLiveAssetFallback({
				pageId,
				viewerUserId: currentUserId,
				ownerUserId: requestedUserId,
				myConn,
				docInfo
			}))) continue

			const ydoc = docInfo.ydoc;
			let hasVerifiedFileRef = null;
			const ensureVerifiedFileRef = async () => {
				if (hasVerifiedFileRef !== null) return hasVerifiedFileRef;
				const [refRows] = await pool.execute(
					`SELECT id FROM page_file_refs
					  WHERE page_id = ? AND owner_user_id = ? AND stored_filename = ? AND file_type = 'paperclip'
					  LIMIT 1`,
					[pageId, requestedUserId, sanitizedFilename]
				);
				hasVerifiedFileRef = refRows.length > 0;
				return hasVerifiedFileRef;
			};

			const content = ydoc.getMap('metadata').get('content') || '';
			if (content.includes(fileUrlPart) && await ensureVerifiedFileRef()) {
				const downloadName = getDownloadName();
				return sendSafeDownload(res, filePath, downloadName);
			}

			const xmlContent = ydoc.getXmlFragment('prosemirror').toString();
			if (xmlContent.includes(fileUrlPart) && await ensureVerifiedFileRef()) {
				const downloadName = getDownloadName();
				return sendSafeDownload(res, filePath, downloadName);
			}
		}

        console.warn(`[보안] 사용자 ${currentUserId}이(가) 권한 없이 파일 접근 시도: ${fileUrlPart}`);
        return res.status(403).json({ error: '접근 권한이 없습니다.' });

    } catch (error) {
        logError('GET /paperclip/:userId/:filename', error);
        res.status(500).json({ error: '파일 로드 실패' });
    }
});

const coverStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.user.id;
        const userCoverDir = path.join(__dirname, 'covers', String(userId));
        fs.mkdirSync(userCoverDir, { recursive: true });
        cb(null, userCoverDir);
    },
    filename: (req, file, cb) => {
	    const uniqueBase = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
	    cb(null, `${uniqueBase}.upload`);
    }
});

const coverUpload = multer({
    storage: coverStorage,
    limits: {
        ...MULTIPART_COMMON_LIMITS,
        fileSize: 2 * 1024 * 1024
    },
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

const editorImageStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.user.id;
        const userImgDir = path.join(__dirname, 'imgs', String(userId));
        fs.mkdirSync(userImgDir, { recursive: true });
        cb(null, userImgDir);
    },
    filename: (req, file, cb) => {
		const uniqueBase = `${Date.now()}-${crypto.randomBytes(6).toString('hex')}`;
		cb(null, `${uniqueBase}.upload`);
    }
});

const editorImageUpload = multer({
    storage: editorImageStorage,
    limits: {
        ...MULTIPART_COMMON_LIMITS,
        fileSize: 5 * 1024 * 1024
    },
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

const paperclipStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userId = req.user.id;
        const userFileDir = path.join(__dirname, 'paperclip', String(userId));
        fs.mkdirSync(userFileDir, { recursive: true });
        cb(null, userFileDir);
    },
    filename: (req, file, cb) => {
	    const uniquePrefix = `${Date.now()}-${crypto.randomBytes(16).toString('hex')}`;
	    const rawExt = path.extname(file.originalname);
	    const ext = sanitizeExtension(rawExt);
	    const base = sanitizeFilenameComponent(path.basename(file.originalname, rawExt), 120)
	        .replace(/__+/g, '_');

	    cb(null, `${uniquePrefix}__${base}${ext}`);
    }
});

const fileUpload = multer({
    storage: paperclipStorage,
    limits: {
        ...MULTIPART_COMMON_LIMITS,
        fileSize: 50 * 1024 * 1024,
        fields: 8,
        parts: 12
    },
});

async function getSessionFromId(sessionId) {
	if (!sessionId) return null;
	return await getSessionFromRequest({ cookies: { [SESSION_COOKIE_NAME]: sessionId } });
}


function installGracefulShutdownHandlers(httpServer, pool, sanitizeHtmlContent) {
    const shutdown = async (signal) => {
        console.log(`\n[${signal}] Graceful shutdown sequence started...`);

        if (httpServer) {
            httpServer.close(() => {
                console.log('HTTP/WebSocket server closed.');
            });
        }

        try {
            await flushAllPendingE2eeSaves(pool);
            await flushAllPendingE2eeUpdateLogs(pool);

            await flushAllPendingYjsDbSaves();

            const pageIds = Array.from(yjsDocuments.keys());
            console.log(`[YJS] Flushing ${pageIds.length} active documents to DB...`);
            for (const pageId of pageIds) {
                const doc = yjsDocuments.get(pageId);
                if (doc && doc.ydoc) {
                    await enqueueYjsDbSave(pageId, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, doc.ydoc));
                }
            }
            console.log('[YJS] All documents flushed.');

            if (pool) {
                await pool.end();
                console.log('Database pool closed.');
            }

            console.log('Graceful shutdown completed successfully.');
            process.exit(0);
        } catch (error) {
            console.error('Error during graceful shutdown:', error);
            process.exit(1);
        }
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
}

(async () => {
    try {
        await initDb();

        const uploadDirs = ['covers', 'imgs', 'paperclip'];
        uploadDirs.forEach(dir => {
            const dirPath = path.join(__dirname, dir);
            if (!fs.existsSync(dirPath)) {
                fs.mkdirSync(dirPath, { recursive: true });
                console.log(`📁 폴더 생성됨: ${dir}`);
            }
        });

        setInterval(cleanupOldLoginLogs, 24 * 60 * 60 * 1000);
        cleanupOldLoginLogs();


        const pageSqlPolicy = require('./authz/page-sql-policy');
        const repositories = require('./repositories')({ pool, pageSqlPolicy });

		const routeDependencies = {
			pool,
			redis,
			pageSqlPolicy,
			...repositories,
			bcrypt,
			crypto,
			express,
			Y,
			speakeasy,
			QRCode,
			createSession,
			getSessionFromRequest,
			generateCsrfToken,
			generateCsrfTokenForSession,
			generatePreAuthCsrfToken,
			verifyPreAuthCsrfToken,
			PREAUTH_CSRF_COOKIE_NAME,
			encryptTotpSecret,
			decryptTotpSecret,
			formatDateForDb,
			validatePasswordStrength,
			logError,
			authMiddleware,
			csrfMiddleware,
			requireRecentReauth: buildRecentReauth({ getSessionFromRequest }).requireRecentReauth,
			assertLoginNotLocked,
			recordLoginFailure,
			clearLoginFailures,
			toIsoString,
			sanitizeInput,
			sanitizeFilenameComponent,
			sanitizeExtension,
			sanitizeHtmlContent,
			generatePageId,
			generateShareToken,
			generatePublishToken,
			wsConnections,
			wsBroadcastToPage,
			wsBroadcastToStorage,
			wsBroadcastToUser,
			wsCloseConnectionsForSession,
			wsCloseConnectionsForPage,
			wsHasActiveConnectionsForPage,
			wsKickUserFromStorage,
			extractFilesFromContent,
			invalidateYjsPersistenceForPage,
			saveYjsDocToDatabase,
			enqueueYjsDbSave,
			flushAllPendingYjsDbSaves,
			flushAllPendingE2eeSaves,
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
			fileUpload,
			path,
			fs,
			recordLoginAttempt,
			getLocationFromIP,
			maskIPAddress,
			isPrivateOrLocalIP,
			checkCountryWhitelist,
			getClientIpFromRequest,
			isHostnameAllowedForPreview,
			assertSafeAttachmentFile,
			assertImageFileSignature
		};

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
        const userKeysRoutes = require('./routes/user-keys')(routeDependencies);

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
        app.use('/api/user-keys', userKeysRoutes);

        app.use((err, req, res, next) => {
            if (res.headersSent) return next(err);

            const isMultipart =
                typeof req?.is === "function" &&
                req.is("multipart/form-data");

            if (isMultipart) cleanupUploadedFiles(req);

            if (err instanceof multer.MulterError) {
                if (err.code === "LIMIT_FILE_SIZE") {
                    return res.status(413).json({ error: "업로드 파일 크기가 제한을 초과했습니다." });
                }
                return res.status(400).json({
                    error: `유효하지 않은 업로드 요청입니다. (${err.code})`
                });
            }

            const msg = String(err?.message || "");
            if (isMultipart && /(multipart|unexpected end of form|unexpected field|aborted)/i.test(msg)) {
                return res.status(400).json({ error: "손상되었거나 중단된 업로드 요청입니다." });
            }
            return next(err);
        });

        const DUCKDNS_DOMAIN = process.env.DUCKDNS_DOMAIN;
        const DUCKDNS_TOKEN = process.env.DUCKDNS_TOKEN;
        const CERT_EMAIL = process.env.CERT_EMAIL || 'admin@example.com';

        if (DUCKDNS_DOMAIN && DUCKDNS_TOKEN) {
            console.log('\n' + '='.repeat(80));
            console.log('🔐 HTTPS 모드로 시작합니다.');
            console.log(`   도메인: ${DUCKDNS_DOMAIN}`);
            console.log('='.repeat(80) + '\n');

            try {
                const certData = await certManager.getCertificate(
                    DUCKDNS_DOMAIN,
                    DUCKDNS_TOKEN,
                    CERT_EMAIL
                );

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

                initWebSocketServer(httpsServer, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest, pageSqlPolicy);

                startRateLimitCleanup();

                startInactiveConnectionsCleanup(pool, sanitizeHtmlContent);

                installGracefulShutdownHandlers(httpsServer, pool, sanitizeHtmlContent);

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

                const mustFailClosed = (IS_PRODUCTION || REQUIRE_HTTPS) && !ALLOW_INSECURE_HTTP_FALLBACK;

                if (mustFailClosed) {
                    console.error('🛑 [보안] HTTPS 설정이 실패했으므로 서버 시작을 중단합니다. (HTTP 폴백 금지)');
                    console.error('   - 점검: DUCKDNS_DOMAIN / DUCKDNS_TOKEN / CERT_EMAIL, DNS 레코드, 방화벽/포트(80/443) 개방 여부');
                    console.error('   - 긴급 상황에서만: ALLOW_INSECURE_HTTP_FALLBACK=true 로 명시적으로 HTTP 폴백을 허용할 수 있습니다. (비권장)');
                    process.exit(1);
                }

                console.warn('⚠️  [DEV/OVERRIDE] HTTPS 설정 실패로 HTTP 모드로 폴백합니다. (프로덕션에서는 비권장)');

                const httpServer = app.listen(PORT, () => {
                    console.log(`⚠️  NTEOK 앱이 HTTP로 실행 중: http://localhost:${PORT}`);
                });

                initWebSocketServer(httpServer, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest, pageSqlPolicy);

                startRateLimitCleanup();

                startInactiveConnectionsCleanup(pool, sanitizeHtmlContent);

                installGracefulShutdownHandlers(httpServer, pool, sanitizeHtmlContent);
            }
        } else {
            console.log('\n' + '='.repeat(80));
            console.log('ℹ️  HTTPS 설정이 없습니다. HTTP 모드로 시작합니다.');
            console.log('   HTTPS를 사용하려면 .env 파일에 다음을 추가하세요:');
            console.log('   - DUCKDNS_DOMAIN=your-domain.duckdns.org');
            console.log('   - DUCKDNS_TOKEN=your-duckdns-token');
            console.log('='.repeat(80) + '\n');

            const httpServer = app.listen(PORT, () => {
                console.log(`NTEOK 앱이 HTTP로 실행 중: http://localhost:${PORT}`);
            });

            initWebSocketServer(httpServer, pool, sanitizeHtmlContent, IS_PRODUCTION, BASE_URL, SESSION_COOKIE_NAME, getSessionFromId, getClientIpFromRequest, pageSqlPolicy);

            startRateLimitCleanup();

            startInactiveConnectionsCleanup(pool, sanitizeHtmlContent);

            installGracefulShutdownHandlers(httpServer, pool, sanitizeHtmlContent);
        }

    } catch (error) {
        console.error("서버 시작 중 치명적 오류:", error);
        process.exit(1);
    }
})();
