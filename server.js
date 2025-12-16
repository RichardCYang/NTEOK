require('dotenv').config();

const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");
const DOMPurify = require("isomorphic-dompurify");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const Y = require("yjs");
const https = require("https");
const http = require("http");
const certManager = require("./cert-manager");
const multer = require("multer");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;

// 세션 / 인증 관련 설정
const SESSION_COOKIE_NAME = "nteok_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7일 (idle timeout)
const SESSION_ABSOLUTE_TTL_MS = 1000 * 60 * 60 * 24; // 24시간 (absolute timeout)
const CSRF_COOKIE_NAME = "nteok_csrf";
const IS_PRODUCTION = process.env.NODE_ENV === "production";
const BASE_URL = process.env.BASE_URL || (IS_PRODUCTION ? "https://localhost:3000" : "http://localhost:3000");

// 보안 개선: 기본 관리자 계정 비밀번호를 강제로 변경하도록 경고
// 환경변수로 설정하지 않으면 무작위 비밀번호를 생성하고 콘솔에 출력
const DEFAULT_ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || crypto.randomBytes(16).toString("hex");
const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 12);

// 기본 비밀번호가 환경변수로 설정되지 않았다면 경고 메시지 출력
if (!process.env.ADMIN_PASSWORD) {
    console.warn("\n" + "=".repeat(80));
    console.warn("⚠️  보안 경고: 기본 관리자 비밀번호가 환경변수로 설정되지 않았습니다!");
    console.warn(`   관리자 계정: ${DEFAULT_ADMIN_USERNAME}`);
    console.warn(`   임시 비밀번호: ${DEFAULT_ADMIN_PASSWORD}`);
    console.warn("   첫 로그인 후 반드시 비밀번호를 변경하세요!");
    console.warn("   프로덕션 환경에서는 ADMIN_PASSWORD 환경변수를 반드시 설정하세요.");
    console.warn("=".repeat(80) + "\n");
}

// 프로덕션 환경에서 필수 환경변수 검증
if (IS_PRODUCTION) {
    const requiredEnvVars = ['DB_HOST', 'DB_USER', 'DB_PASSWORD', 'DB_NAME', 'BASE_URL'];
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
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool;
const sessions = new Map();

/**
 * 만료된 세션 정리 작업
 * 주기적으로 실행하여 메모리 누수 방지
 */
function cleanupExpiredSessions() {
    const now = Date.now();
    let cleanedCount = 0;

    sessions.forEach((session, sessionId) => {
        // 임시 세션 (pendingUserId) 정리 - 10분 경과
        if (session.pendingUserId && session.createdAt + 10 * 60 * 1000 < now) {
            sessions.delete(sessionId);
            cleanedCount++;
            return;
        }

        // 정식 세션의 절대 만료 시간 체크
        if (session.absoluteExpiry && session.absoluteExpiry <= now) {
            sessions.delete(sessionId);
            cleanedCount++;
            return;
        }

        // Idle timeout 체크
        if (session.expiresAt && session.expiresAt <= now) {
            sessions.delete(sessionId);
            cleanedCount++;
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
 * Date -> MySQL DATETIME 문자열 (YYYY-MM-DD HH:MM:SS)
 */
function formatDateForDb(date) {
    const pad = (n) => (n < 10 ? "0" + n : "" + n);

    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    const hour = pad(date.getHours());
    const minute = pad(date.getMinutes());
    const second = pad(date.getSeconds());

    return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
}

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
            'table', 'thead', 'tbody', 'tr', 'th', 'td'
        ],
        ALLOWED_ATTR: ['style', 'class', 'href', 'target', 'rel', 'data-type', 'data-latex', 'colspan', 'rowspan', 'colwidth'],
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

    if (!tokenFromHeader || !tokenFromCookie) {
        return false;
    }

    // 타이밍 공격 방지를 위한 상수 시간 비교
    return crypto.timingSafeEqual(
        Buffer.from(tokenFromHeader),
        Buffer.from(tokenFromCookie)
    );
}

/**
 * 세션 생성
 * 보안 개선: idle timeout과 absolute timeout 모두 적용
 */
function createSession(user) {
    const sessionId = crypto.randomBytes(24).toString("hex");
    const now = Date.now();
    const expiresAt = now + SESSION_TTL_MS; // idle timeout
    const absoluteExpiry = now + SESSION_ABSOLUTE_TTL_MS; // absolute timeout

    sessions.set(sessionId, {
        userId: user.id,
        username: user.username,
        expiresAt,
        absoluteExpiry,
        createdAt: now
    });

    return sessionId;
}

/**
 * 요청에서 세션 읽기
 * 보안 개선: idle timeout과 absolute timeout 모두 검증
 */
function getSessionFromRequest(req) {
    if (!req.cookies) {
        return null;
    }

    const sessionId = req.cookies[SESSION_COOKIE_NAME];
    if (!sessionId) {
        return null;
    }

    const session = sessions.get(sessionId);
    if (!session) {
        return null;
    }

    const now = Date.now();

    // 절대 만료 시간 체크 (세션 생성 후 24시간)
    if (session.absoluteExpiry <= now) {
        sessions.delete(sessionId);
        return null;
    }

    // Idle timeout 체크 (마지막 활동 후 7일)
    if (session.expiresAt <= now) {
        sessions.delete(sessionId);
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
        req.path === "/passkey/authenticate/verify") {
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
            encryption_salt VARCHAR(255) NULL,
            created_at DATETIME NOT NULL,
            updated_at DATETIME NOT NULL
        )
    `);

    // 기존 users 테이블에 encryption_salt 컬럼 추가 (없을 경우에만)
    try {
        await pool.execute(`
            ALTER TABLE users ADD COLUMN encryption_salt VARCHAR(255) NULL
        `);
        console.log("users 테이블에 encryption_salt 컬럼 추가 완료");
    } catch (error) {
        // 이미 컬럼이 존재하는 경우 무시
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("encryption_salt 컬럼 추가 중 경고:", error.message);
        }
    }

    // users 테이블에 TOTP 관련 컬럼 추가 (2FA)
    try {
        await pool.execute(`
            ALTER TABLE users ADD COLUMN totp_secret VARCHAR(64) NULL
        `);
        console.log("users 테이블에 totp_secret 컬럼 추가 완료");
    } catch (error) {
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("totp_secret 컬럼 추가 중 경고:", error.message);
        }
    }

    try {
        await pool.execute(`
            ALTER TABLE users ADD COLUMN totp_enabled TINYINT(1) NOT NULL DEFAULT 0
        `);
        console.log("users 테이블에 totp_enabled 컬럼 추가 완료");
    } catch (error) {
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("totp_enabled 컬럼 추가 중 경고:", error.message);
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
            CONSTRAINT fk_collections_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
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
            CONSTRAINT fk_pages_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,
            CONSTRAINT fk_pages_parent
                FOREIGN KEY (parent_id)
                REFERENCES pages(id)
                ON DELETE CASCADE
        )
    `);

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

    // 보안 개선: is_encrypted 플래그 추가 (기본값 0 - 암호화 안 됨)
    try {
        await pool.execute(`
            ALTER TABLE pages ADD COLUMN is_encrypted TINYINT(1) NOT NULL DEFAULT 0
        `);
        console.log("pages 테이블에 is_encrypted 컬럼 추가 완료");
    } catch (error) {
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("pages.is_encrypted 컬럼 추가 중 경고:", error.message);
        }
    }

    // 공유 컬렉션의 암호화 페이지 공유 허용 플래그 추가 (기본값 0 - 공유 불가)
    try {
        await pool.execute(`
            ALTER TABLE pages ADD COLUMN share_allowed TINYINT(1) NOT NULL DEFAULT 0
        `);
        console.log("pages 테이블에 share_allowed 컬럼 추가 완료");
    } catch (error) {
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("pages.share_allowed 컬럼 추가 중 경고:", error.message);
        }
    }

    // 페이지 아이콘 지정 기능 추가 (기본값 NULL - 아이콘 없음)
    try {
        await pool.execute(`
            ALTER TABLE pages ADD COLUMN icon VARCHAR(100) NULL
        `);
        console.log("pages 테이블에 icon 컬럼 추가 완료");
    } catch (error) {
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("pages.icon 컬럼 추가 중 경고:", error.message);
        }
    }

    // 페이지 커버 이미지 추가 (기본값 NULL - 커버 없음)
    try {
        await pool.execute(`
            ALTER TABLE pages ADD COLUMN cover_image VARCHAR(255) NULL
        `);
        console.log("pages 테이블에 cover_image 컬럼 추가 완료");
    } catch (error) {
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("pages.cover_image 컬럼 추가 중 경고:", error.message);
        }
    }

    // 페이지 커버 이미지 위치 추가 (기본값 50 - 중앙)
    try {
        await pool.execute(`
            ALTER TABLE pages ADD COLUMN cover_position INT NOT NULL DEFAULT 50
        `);
        console.log("pages 테이블에 cover_position 컬럼 추가 완료");
    } catch (error) {
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("pages.cover_position 컬럼 추가 중 경고:", error.message);
        }
    }

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
        )
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
        )
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
        )
    `);

    // users 테이블에 passkey_enabled 컬럼 추가 (패스키 2FA)
    try {
        await pool.execute(`
            ALTER TABLE users ADD COLUMN passkey_enabled TINYINT(1) NOT NULL DEFAULT 0
        `);
        console.log("users 테이블에 passkey_enabled 컬럼 추가 완료");
    } catch (error) {
        if (error.code !== 'ER_DUP_FIELDNAME') {
            console.warn("passkey_enabled 컬럼 추가 중 경고:", error.message);
        }
    }

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
        )
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
        )
    `);

    // 컬렉션이 없는 기존 사용자 데이터 마이그레이션
    await backfillCollections();
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
});

// 로그인/회원가입 레이트 리밋 (브루트포스 방지)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 5, // 최대 5번 시도
    message: { error: "너무 많은 로그인 시도가 발생했습니다. 15분 후 다시 시도해 주세요." },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, // 성공한 요청은 카운트하지 않음
});

// TOTP 인증 레이트 리밋 (브루트포스 방지)
const totpLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 10, // 최대 10번 시도
    message: { error: "너무 많은 인증 시도가 발생했습니다. 15분 후 다시 시도해 주세요." },
    standardHeaders: true,
    legacyHeaders: false,
});

// 패스키 인증 레이트 리밋 (브루트포스 방지)
const passkeyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 10, // 최대 10번 시도
    message: { error: "너무 많은 패스키 인증 요청이 발생했습니다. 잠시 후 다시 시도해 주세요." },
    standardHeaders: true,
    legacyHeaders: false,
});

// SSE 연결 레이트 리밋
const sseConnectionLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 50, // 사용자당 최대 50개 연결
    message: { error: "SSE 연결 제한 초과" },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.user?.id?.toString() || 'anonymous'
});

/**
 * ==================== SSE 및 실시간 동기화 ====================
 */

// SSE 연결 풀
const sseConnections = {
    pages: new Map(), // pageId -> Set<{res, userId, username, color}>
    collections: new Map() // collectionId -> Set<{res, userId, permission}>
};

// Yjs 문서 캐시 (메모리 관리)
const yjsDocuments = new Map(); // pageId -> {ydoc, lastAccess, saveTimeout}

// 사용자 색상 (협업 UI용, 10가지 색상 순환)
const USER_COLORS = [
    '#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8',
    '#F7DC6F', '#BB8FCE', '#85C1E2', '#F8B195', '#C06C84'
];

/**
 * 사용자 ID 기반 색상 할당
 */
function getUserColor(userId) {
    return USER_COLORS[userId % USER_COLORS.length];
}

/**
 * SSE 연결 정리 (30분 비활성 시)
 */
function cleanupInactiveConnections() {
    const now = Date.now();
    const TIMEOUT = 30 * 60 * 1000; // 30분

    yjsDocuments.forEach((doc, pageId) => {
        if (now - doc.lastAccess > TIMEOUT) {
            // 마지막 저장 후 메모리에서 제거
            saveYjsDocToDatabase(pageId, doc.ydoc).catch(err => {
                console.error(`[SSE] 비활성 문서 저장 실패 (${pageId}):`, err);
            });
            yjsDocuments.delete(pageId);
        }
    });
}

// 10분마다 비활성 연결 정리
setInterval(cleanupInactiveConnections, 10 * 60 * 1000);

/**
 * Yjs 문서를 데이터베이스에 저장
 */
async function saveYjsDocToDatabase(pageId, ydoc) {
    try {
        const yXmlFragment = ydoc.getXmlFragment('prosemirror');
        const yMetadata = ydoc.getMap('metadata');

        // 메타데이터 추출
        const title = yMetadata.get('title') || '제목 없음';
        const icon = yMetadata.get('icon') || null;
        const sortOrder = yMetadata.get('sortOrder') || 0;
        const parentId = yMetadata.get('parentId') || null;

        const rawContent = extractHtmlFromYDoc(ydoc);
        const content = sanitizeHtmlContent(rawContent);

        await pool.execute(
            `UPDATE pages
             SET title = ?, content = ?, icon = ?, sort_order = ?, parent_id = ?, updated_at = NOW()
             WHERE id = ?`,
            [title, content, icon, sortOrder, parentId, pageId]
        );
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
async function loadOrCreateYjsDoc(pageId) {
    if (yjsDocuments.has(pageId)) {
        const doc = yjsDocuments.get(pageId);
        doc.lastAccess = Date.now();
        return doc.ydoc;
    }

    // 데이터베이스에서 페이지 로드
    const [rows] = await pool.execute(
        'SELECT title, content, icon, sort_order, parent_id FROM pages WHERE id = ?',
        [pageId]
    );

    const ydoc = new Y.Doc();
    const yXmlFragment = ydoc.getXmlFragment('prosemirror');
    const yMetadata = ydoc.getMap('metadata');

    if (rows.length > 0) {
        const page = rows[0];
        yMetadata.set('title', page.title || '제목 없음');
        yMetadata.set('icon', page.icon || null);
        yMetadata.set('sortOrder', page.sort_order || 0);
        yMetadata.set('parentId', page.parent_id || null);
        yMetadata.set('content', page.content || '<p></p>');
    }

    yjsDocuments.set(pageId, {
        ydoc,
        lastAccess: Date.now(),
        saveTimeout: null
    });

    return ydoc;
}

/**
 * SSE 브로드캐스트 (페이지)
 */
function broadcastToPage(pageId, event, data, excludeUserId = null) {
    const connections = sseConnections.pages.get(pageId);
    if (!connections) return;

    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;

    connections.forEach(conn => {
        if (excludeUserId && conn.userId === excludeUserId) return;
        try {
            conn.res.write(message);
        } catch (error) {
            console.error(`[SSE] 브로드캐스트 실패 (userId: ${conn.userId}):`, error);
        }
    });
}

/**
 * SSE 브로드캐스트 (컬렉션)
 */
function broadcastToCollection(collectionId, event, data, excludeUserId = null) {
    const connections = sseConnections.collections.get(collectionId);
    if (!connections) return;

    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;

    connections.forEach(conn => {
        if (excludeUserId && conn.userId === excludeUserId) return;
        try {
            conn.res.write(message);
        } catch (error) {
            console.error(`[SSE] 브로드캐스트 실패 (userId: ${conn.userId}):`, error);
        }
    });
}

/**
 * 미들웨어 설정
 */
app.use(express.json());
app.use(cookieParser());

// 보안 개선: 기본 보안 헤더 추가 (XSS, 클릭재킹 방지 등)
app.use((req, res, next) => {
    // 보안 개선: CSP 강화 - unsafe-inline 제거 권장
    // 참고: 모든 인라인 스타일을 외부 CSS로 이동하면 'unsafe-inline' 제거 가능
    // 또는 nonce 기반 CSP로 전환 가능
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; " +
        "script-src 'self' https://cdn.jsdelivr.net https://esm.sh; " +
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

app.use(express.static(path.join(__dirname, "public"), { index: false }));
app.use('/covers', express.static(path.join(__dirname, 'covers')));

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
        const uniqueName = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}${path.extname(file.originalname)}`;
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

/**
 * 서버 시작 (HTTPS 자동 설정)
 */
(async () => {
    try {
        await initDb();

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
            createCollection,
            getCollectionPermission,
            hasEncryptedPages,
            generateShareToken,
            broadcastToCollection,
            broadcastToPage,
            sseConnections,
            getUserColor,
            loadOrCreateYjsDoc,
            saveYjsDocToDatabase,
            yjsDocuments,
            authLimiter,
            totpLimiter,
            passkeyLimiter,
            sseConnectionLimiter,
            SESSION_COOKIE_NAME,
            CSRF_COOKIE_NAME,
            SESSION_TTL_MS,
            IS_PRODUCTION,
            BCRYPT_SALT_ROUNDS,
            BASE_URL,
            coverUpload,
            path,
            fs
        };

        // 라우트 파일 Import
        const indexRoutes = require('./routes/index')(routeDependencies);
        const authRoutes = require('./routes/auth')(routeDependencies);
        const collectionsRoutes = require('./routes/collections')(routeDependencies);
        const pagesRoutes = require('./routes/pages')(routeDependencies);
        const sharesRoutes = require('./routes/shares')(routeDependencies);
        const syncRoutes = require('./routes/sync')(routeDependencies);
        const totpRoutes = require('./routes/totp')(routeDependencies);
        const passkeyRoutes = require('./routes/passkey')(routeDependencies);

        // 라우트 등록
        app.use('/', indexRoutes);
        app.use('/api/auth', authRoutes);
        app.use('/api/collections', collectionsRoutes);
        app.use('/api/pages', pagesRoutes);
        app.use('/api', sharesRoutes);
        app.use('/api', syncRoutes);
        app.use('/api/totp', totpRoutes);
        app.use('/api/passkey', passkeyRoutes);

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
                app.listen(PORT, () => {
                    console.log(`⚠️  NTEOK 앱이 HTTP로 실행 중: http://localhost:${PORT}`);
                });
            }
        } else {
            // HTTPS 설정이 없는 경우 - HTTP 모드
            console.log('\n' + '='.repeat(80));
            console.log('ℹ️  HTTPS 설정이 없습니다. HTTP 모드로 시작합니다.');
            console.log('   HTTPS를 사용하려면 .env 파일에 다음을 추가하세요:');
            console.log('   - DUCKDNS_DOMAIN=your-domain.duckdns.org');
            console.log('   - DUCKDNS_TOKEN=your-duckdns-token');
            console.log('='.repeat(80) + '\n');

            app.listen(PORT, () => {
                console.log(`NTEOK 앱이 HTTP로 실행 중: http://localhost:${PORT}`);
            });
        }

    } catch (error) {
        console.error("서버 시작 중 치명적 오류:", error);
        process.exit(1);
    }
})();