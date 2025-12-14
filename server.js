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
            'a', 'span', 'div'
        ],
        ALLOWED_ATTR: ['style', 'class', 'href', 'target', 'rel', 'data-type', 'data-latex'],
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
        req.path === "/totp/verify-backup-code") {
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

        // HTML 추출 (간단한 방식)
        const content = extractHtmlFromYDoc(ydoc);

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
    // 초기 HTML이 메타데이터에 저장되어 있으면 사용
    const yMetadata = ydoc.getMap('metadata');
    const initialHtml = yMetadata.get('initialHtml');

    if (initialHtml) {
        return initialHtml;
    }

    // 기본 HTML 반환 (Yjs 변경사항이 적용되지 않을 수 있음)
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
        yMetadata.set('initialHtml', page.content || '<p></p>');
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

/**
 * 로그인 / 메인 화면 라우팅
 */
app.get("/", (req, res) => {
    const session = getSessionFromRequest(req);

    if (!session) {
        return res.redirect("/login");
    }

    return res.sendFile(path.join(__dirname, "public", "index.html"));
});

// 로그인 페이지
app.get("/login", (req, res) => {
    const session = getSessionFromRequest(req);

    if (session) {
        return res.redirect("/");
    }

    return res.sendFile(path.join(__dirname, "public", "login.html"));
});

// 회원가입 페이지
app.get("/register", (req, res) => {
    const session = getSessionFromRequest(req);

    // 이미 로그인 되어 있으면 메인으로
    if (session) {
        return res.redirect("/");
    }

    return res.sendFile(path.join(__dirname, "public", "register.html"));
});

// 앱 아이콘 제공
app.get("/icon.png", (req, res) => {
    return res.sendFile(path.join(__dirname, "icon.png"));
});

/**
 * 간단한 헬스 체크용
 * GET /api/debug/ping
 */
app.get("/api/debug/ping", (req, res) => {
    res.json({
        ok: true,
        time: new Date().toISOString()
    });
});

/**
 * 로그인
 * POST /api/auth/login
 * body: { username: string, password: string }
 */
app.post("/api/auth/login", authLimiter, async (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
    }

    const trimmedUsername = username.trim();

    try {
        const [rows] = await pool.execute(
            `
            SELECT id, username, password_hash, encryption_salt, totp_enabled
            FROM users
            WHERE username = ?
            `,
            [trimmedUsername]
        );

        if (!rows.length) {
            // 보안 개선: 로그에서 사용자명 제거 (정보 노출 방지)
            console.warn("로그인 실패 - 존재하지 않는 사용자 (IP: " + req.ip + ")");
            return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
        }

        const user = rows[0];

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            // 보안 개선: 로그에서 사용자명 제거 (정보 노출 방지)
            console.warn("로그인 실패 - 비밀번호 불일치 (IP: " + req.ip + ")");
            return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
        }

        // 2FA(TOTP) 활성화 확인
        if (user.totp_enabled) {
            // 임시 세션 생성 (2FA 검증 대기)
            const tempSessionId = crypto.randomBytes(32).toString("hex");
            const now = new Date();

            sessions.set(tempSessionId, {
                pendingUserId: user.id,
                createdAt: now.getTime(),
                lastAccessedAt: now.getTime()
            });

            // 2FA 검증 필요 응답
            return res.json({
                ok: false,
                requires2FA: true,
                tempSessionId: tempSessionId
            });
        }

        // TOTP 비활성화 상태 - 정상 로그인 진행
        const sessionId = createSession(user);

        // 보안 개선: 쿠키 보안 설정 강화
        res.cookie(SESSION_COOKIE_NAME, sessionId, {
            httpOnly: true,
            sameSite: "strict",  // CSRF 방어 강화
            secure: IS_PRODUCTION,  // 환경에 따라 설정
            maxAge: SESSION_TTL_MS
        });

        // 보안 개선: 로그인 성공 시 CSRF 토큰 갱신
        const newCsrfToken = generateCsrfToken();
        res.cookie(CSRF_COOKIE_NAME, newCsrfToken, {
            httpOnly: false,
            sameSite: "strict",
            secure: IS_PRODUCTION,
            maxAge: SESSION_TTL_MS
        });

        res.json({
            ok: true,
            user: {
                id: user.id,
                username: user.username
            }
            // 보안 개선: encryptionSalt는 별도 API로 요청 시에만 제공
        });
    } catch (error) {
        logError("POST /api/auth/login", error);
        res.status(500).json({ error: "로그인 처리 중 오류가 발생했습니다." });
    }
});

/**
 * 로그아웃
 * POST /api/auth/logout
 */
app.post("/api/auth/logout", (req, res) => {
    const session = getSessionFromRequest(req);
    if (session) {
        sessions.delete(session.id);
    }

    res.clearCookie(SESSION_COOKIE_NAME, {
        httpOnly: true,
        sameSite: "strict",
        secure: IS_PRODUCTION
    });

    res.json({ ok: true });
});

/**
 * 계정 삭제
 * DELETE /api/auth/account
 * body: { password: string, confirmText: string }
 */
app.delete("/api/auth/account", authMiddleware, async (req, res) => {
    const { password, confirmText } = req.body || {};

    // 입력 검증
    if (typeof password !== "string" || !password.trim()) {
        return res.status(400).json({ error: "비밀번호를 입력해 주세요." });
    }

    if (confirmText !== "계정 삭제") {
        return res.status(400).json({ error: '확인 문구를 정확히 입력해 주세요. "계정 삭제"를 입력하세요.' });
    }

    try {
        // 사용자 정보 조회
        const [rows] = await pool.execute(
            `SELECT id, username, password_hash FROM users WHERE id = ?`,
            [req.user.id]
        );

        if (!rows.length) {
            return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
        }

        const user = rows[0];

        // 비밀번호 검증
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            console.warn("계정 삭제 시도 - 비밀번호 불일치:", req.user.username);
            return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });
        }

        // 계정 삭제 (CASCADE로 연관 데이터 자동 삭제)
        await pool.execute(`DELETE FROM users WHERE id = ?`, [req.user.id]);

        console.log(`계정 삭제 완료: 사용자 ID ${req.user.id} (${req.user.username})`);

        // 세션 무효화
        const session = getSessionFromRequest(req);
        if (session) {
            sessions.delete(session.id);
        }

        // 세션 쿠키 클리어
        res.clearCookie(SESSION_COOKIE_NAME, {
            httpOnly: true,
            sameSite: "strict",
            secure: IS_PRODUCTION
        });

        res.json({ ok: true });
    } catch (error) {
        logError("DELETE /api/auth/account", error);
        res.status(500).json({ error: "계정 삭제 중 오류가 발생했습니다." });
    }
});

/**
 * 회원가입
 * POST /api/auth/register
 * body: { username: string, password: string }
 */
app.post("/api/auth/register", authLimiter, async (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
    }

    const trimmedUsername = username.trim();

    // 기본적인 유효성 검사
    if (trimmedUsername.length < 3 || trimmedUsername.length > 64) {
        return res.status(400).json({ error: "아이디는 3~64자 사이로 입력해 주세요." });
    }

    // 보안 개선: 비밀번호 강도 검증
    const passwordValidation = validatePasswordStrength(password);
    if (!passwordValidation.valid) {
        return res.status(400).json({ error: passwordValidation.error });
    }

    try {
        // 아이디 중복 확인
        const [rows] = await pool.execute(
            `
            SELECT id
            FROM users
            WHERE username = ?
            `,
            [trimmedUsername]
        );

        if (rows.length > 0) {
            return res.status(409).json({ error: "이미 사용 중인 아이디입니다." });
        }

        const now = new Date();
        const nowStr = formatDateForDb(now);

        // 비밀번호 해시
        const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

        // 새 유저 생성
        const [result] = await pool.execute(
            `
            INSERT INTO users (username, password_hash, created_at, updated_at)
            VALUES (?, ?, ?, ?)
            `,
            [trimmedUsername, passwordHash, nowStr, nowStr]
        );

        const user = {
            id: result.insertId,
            username: trimmedUsername
        };

        // 새 사용자 기본 컬렉션 생성
        await createCollection({
            userId: user.id,
            name: "기본 컬렉션"
        });

        // 바로 로그인 상태로 만들어 주기 (세션 생성)
        const sessionId = createSession(user);

        // 보안 개선: 쿠키 보안 설정 강화
        res.cookie(SESSION_COOKIE_NAME, sessionId, {
            httpOnly: true,
            sameSite: "strict",  // CSRF 방어 강화
            secure: IS_PRODUCTION,  // 환경에 따라 설정
            maxAge: SESSION_TTL_MS
        });

        // 보안 개선: 회원가입 성공 시 CSRF 토큰 갱신
        const newCsrfToken = generateCsrfToken();
        res.cookie(CSRF_COOKIE_NAME, newCsrfToken, {
            httpOnly: false,
            sameSite: "strict",
            secure: IS_PRODUCTION,
            maxAge: SESSION_TTL_MS
        });

        return res.status(201).json({
            ok: true,
            user: {
                id: user.id,
                username: user.username
            }
        });
    } catch (error) {
        logError("POST /api/auth/register", error);
        return res.status(500).json({ error: "회원가입 처리 중 오류가 발생했습니다." });
    }
});

/**
 * 현재 로그인한 사용자 정보 확인
 * GET /api/auth/me
 */
app.get("/api/auth/me", authMiddleware, async (req, res) => {
    try {
        const [rows] = await pool.execute(
            `SELECT id, username, encryption_salt FROM users WHERE id = ?`,
            [req.user.id]
        );

        if (!rows.length) {
            return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
        }

        const user = rows[0];
        res.json({
            id: user.id,
            username: user.username,
            encryptionSalt: user.encryption_salt
        });
    } catch (error) {
        logError("GET /api/auth/me", error);
        res.status(500).json({ error: "사용자 정보 조회 중 오류가 발생했습니다." });
    }
});

/**
 * 암호화 Salt 업데이트
 * PUT /api/auth/encryption-salt
 */
app.put("/api/auth/encryption-salt", authMiddleware, async (req, res) => {
    const { encryptionSalt } = req.body;

    if (typeof encryptionSalt !== "string" || !encryptionSalt) {
        return res.status(400).json({ error: "암호화 Salt가 필요합니다." });
    }

    try {
        await pool.execute(
            `UPDATE users SET encryption_salt = ? WHERE id = ?`,
            [encryptionSalt, req.user.id]
        );

        res.json({ ok: true });
    } catch (error) {
        logError("PUT /api/auth/encryption-salt", error);
        res.status(500).json({ error: "암호화 Salt 업데이트 중 오류가 발생했습니다." });
    }
});

/**
 * 비밀번호 재확인 (보안 강화)
 * POST /api/auth/verify-password
 */
app.post("/api/auth/verify-password", authMiddleware, async (req, res) => {
    const { password } = req.body || {};

    if (typeof password !== "string") {
        return res.status(400).json({ error: "비밀번호를 입력해 주세요." });
    }

    try {
        const [rows] = await pool.execute(
            `SELECT id, username, password_hash, encryption_salt FROM users WHERE id = ?`,
            [req.user.id]
        );

        if (!rows.length) {
            return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
        }

        const user = rows[0];

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            console.warn("비밀번호 재확인 실패:", req.user.username);
            return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });
        }

        res.json({
            ok: true,
            encryptionSalt: user.encryption_salt
        });
    } catch (error) {
        logError("POST /api/auth/verify-password", error);
        res.status(500).json({ error: "비밀번호 확인 중 오류가 발생했습니다." });
    }
});

/**
 * 컬렉션 목록 조회 (소유한 컬렉션 + 공유받은 컬렉션)
 * GET /api/collections
 */
app.get("/api/collections", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;

        // 소유한 컬렉션 + 공유받은 컬렉션
        const [rows] = await pool.execute(
            `SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                    c.user_id as owner_id,
                    CASE
                        WHEN c.user_id = ? THEN 'OWNER'
                        ELSE cs.permission
                    END as permission,
                    (SELECT COUNT(*) FROM collection_shares WHERE collection_id = c.id) as share_count
             FROM collections c
             LEFT JOIN collection_shares cs ON c.id = cs.collection_id AND cs.shared_with_user_id = ?
             WHERE c.user_id = ? OR cs.shared_with_user_id IS NOT NULL
             ORDER BY c.sort_order ASC, c.updated_at DESC`,
            [userId, userId, userId]
        );

        const list = rows.map((row) => ({
            id: row.id,
            name: row.name,
            sortOrder: row.sort_order,
            createdAt: toIsoString(row.created_at),
            updatedAt: toIsoString(row.updated_at),
            isOwner: row.owner_id === userId,
            permission: row.permission,
            isShared: row.share_count > 0
        }));

        res.json(list);
    } catch (error) {
        logError("GET /api/collections", error);
        res.status(500).json({ error: "컬렉션 목록을 불러오지 못했습니다." });
    }
});

/**
 * 새 컬렉션 생성
 * POST /api/collections
 * body: { name?: string }
 */
app.post("/api/collections", authMiddleware, async (req, res) => {
    const rawName = typeof req.body.name === "string" ? req.body.name.trim() : "";
    // XSS 방지: HTML 태그 제거
    const name = sanitizeInput(rawName !== "" ? rawName : "새 컬렉션");

    try {
        const userId = req.user.id;
        const collection = await createCollection({ userId, name });
        res.status(201).json(collection);
    } catch (error) {
        logError("POST /api/collections", error);
        res.status(500).json({ error: "컬렉션을 생성하지 못했습니다." });
    }
});

/**
 * 컬렉션 삭제 (소유자만 가능)
 * DELETE /api/collections/:id
 */
app.delete("/api/collections/:id", authMiddleware, async (req, res) => {
    const id = req.params.id;
    const userId = req.user.id;

    try {
        // 소유자만 삭제 가능
        const { isOwner } = await getCollectionPermission(id, userId);
        if (!isOwner) {
            return res.status(403).json({ error: "컬렉션 소유자만 삭제할 수 있습니다." });
        }

        // 컬렉션 삭제 (pages, collection_shares, share_links는 FK CASCADE로 자동 삭제)
        await pool.execute(
            `DELETE FROM collections WHERE id = ?`,
            [id]
        );

        res.json({ ok: true, removedId: id });
    } catch (error) {
        logError("DELETE /api/collections/:id", error);
        res.status(500).json({ error: "컬렉션 삭제에 실패했습니다." });
    }
});

/**
 * 페이지 목록 조회 (소유한 페이지 + 공유받은 컬렉션의 페이지)
 * GET /api/pages
 */
app.get("/api/pages", authMiddleware, async (req, res) => {
    try {
		const userId = req.user.id;
        const collectionId =
            typeof req.query.collectionId === "string" && req.query.collectionId.trim() !== ""
                ? req.query.collectionId.trim()
                : null;

        // 소유한 페이지 + 소유한 컬렉션의 모든 페이지 + 공유받은 컬렉션의 페이지
        // 단, 암호화된 페이지는 공유 허용되었거나 본인이 만든 경우만 표시
        let query = `
            SELECT DISTINCT p.id, p.title, p.updated_at, p.parent_id, p.sort_order, p.collection_id, p.is_encrypted, p.share_allowed, p.user_id, p.icon
            FROM pages p
            LEFT JOIN collections c ON p.collection_id = c.id
            LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
            WHERE (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)
              AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
        `;
        const params = [userId, userId, userId, userId];

        if (collectionId) {
            query += ` AND p.collection_id = ?`;
            params.push(collectionId);
        }

        query += `
            ORDER BY p.collection_id ASC, p.parent_id IS NULL DESC, p.sort_order ASC, p.updated_at DESC
        `;

        const [rows] = await pool.execute(query, params);

        const list = rows.map((row) => ({
            id: row.id,
            title: row.title || "제목 없음",
            updatedAt: toIsoString(row.updated_at),
            parentId: row.parent_id,
            sortOrder: row.sort_order,
            collectionId: row.collection_id,
            isEncrypted: row.is_encrypted ? true : false,
            shareAllowed: row.share_allowed ? true : false,
            userId: row.user_id,
            icon: row.icon || null
        }));

        console.log("GET /api/pages 응답 개수:", list.length);

        res.json(list);
    } catch (error) {
        logError("GET /api/pages", error);
        res.status(500).json({ error: "페이지 목록 불러오기 실패." });
    }
});

/**
 * 단일 페이지 조회 (소유한 페이지 또는 공유받은 컬렉션의 페이지)
 * GET /api/pages/:id
 */
app.get("/api/pages/:id", authMiddleware, async (req, res) => {
    const id = req.params.id;
	const userId = req.user.id;

    try {
        // 소유한 페이지 또는 소유한 컬렉션의 페이지 또는 공유받은 컬렉션의 페이지
        const [rows] = await pool.execute(
            `SELECT p.id, p.title, p.content, p.created_at, p.updated_at, p.parent_id, p.sort_order, p.collection_id, p.is_encrypted, p.share_allowed, p.user_id, p.icon
             FROM pages p
             LEFT JOIN collections c ON p.collection_id = c.id
             LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
             WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)`,
            [userId, id, userId, userId]
        );

        if (!rows.length) {
            console.warn("GET /api/pages/:id - 페이지 없음 또는 권한 없음:", id);
            return res.status(404).json({ error: "Page not found" });
        }

        const row = rows[0];

        const page = {
            id: row.id,
            title: row.title || "제목 없음",
            content: row.content || "<p></p>",
            createdAt: toIsoString(row.created_at),
            updatedAt: toIsoString(row.updated_at),
            parentId: row.parent_id,
            sortOrder: row.sort_order,
            collectionId: row.collection_id,
            isEncrypted: row.is_encrypted ? true : false,
            shareAllowed: row.share_allowed ? true : false,
            userId: row.user_id,
            icon: row.icon || null
        };

        console.log("GET /api/pages/:id 응답:", id);

        res.json(page);
    } catch (error) {
        logError("GET /api/pages/:id", error);
        res.status(500).json({ error: "페이지 불러오기 실패." });
    }
});

/**
 * 새 페이지 생성
 * POST /api/pages
 * body: { title?: string }
 */
app.post("/api/pages", authMiddleware, async (req, res) => {
    const rawTitle = typeof req.body.title === "string" ? req.body.title : "";
    // XSS 방지: HTML 태그 제거
    const title = sanitizeInput(rawTitle.trim() !== "" ? rawTitle.trim() : "제목 없음");

    const now = new Date();
    const id = generatePageId(now);
    const nowStr = formatDateForDb(now);
    // 보안 개선: 클라이언트에서 content를 전달하면 sanitize 후 사용
    const rawContent = typeof req.body.content === "string" ? req.body.content : "<p></p>";
    const content = sanitizeHtmlContent(rawContent);
	const userId = req.user.id;

	// body에서 parentId / sortOrder 받기 (없으면 루트 + sort_order 0)
    const parentId =
        typeof req.body.parentId === "string" && req.body.parentId.trim() !== ""
            ? req.body.parentId.trim()
            : null;
    const sortOrder =
        typeof req.body.sortOrder === "number" && Number.isFinite(req.body.sortOrder)
            ? req.body.sortOrder
            : 0;
    const collectionId =
        typeof req.body.collectionId === "string" && req.body.collectionId.trim() !== ""
            ? req.body.collectionId.trim()
            : null;
    const icon =
        typeof req.body.icon === "string" && req.body.icon.trim() !== ""
            ? req.body.icon.trim()
            : null;

    if (!collectionId) {
        return res.status(400).json({ error: "collectionId가 필요합니다." });
    }

    try {
        // 컬렉션 접근 권한 확인 (EDIT 이상 필요)
        const { permission } = await getCollectionPermission(collectionId, userId);
        if (!permission || permission === 'READ') {
            return res.status(403).json({ error: "페이지를 생성할 권한이 없습니다." });
        }

        if (parentId) {
            // 부모 페이지 접근 권한 확인 (소유한 페이지 또는 소유한/공유받은 컬렉션의 페이지)
            const [parentRows] = await pool.execute(
                `SELECT p.id, p.collection_id
                 FROM pages p
                 LEFT JOIN collections c ON p.collection_id = c.id
                 LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                 WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)`,
                [userId, parentId, userId, userId]
            );

            if (!parentRows.length) {
                return res.status(400).json({ error: "부모 페이지를 찾을 수 없습니다." });
            }

            if (parentRows[0].collection_id !== collectionId) {
                return res.status(400).json({ error: "부모 페이지와 동일한 컬렉션이어야 합니다." });
            }
        }

        await pool.execute(
            `
            INSERT INTO pages (id, user_id, parent_id, title, content, sort_order, created_at, updated_at, collection_id, icon)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [id, userId, parentId, title, content, sortOrder, nowStr, nowStr, collectionId, icon]
        );

        const page = {
            id,
            title,
            content,
            parentId,
            sortOrder,
            collectionId,
            createdAt: now.toISOString(),
            updatedAt: now.toISOString(),
            icon
        };

        console.log("POST /api/pages 생성:", id);

        res.status(201).json(page);
    } catch (error) {
        logError("POST /api/pages", error);
        res.status(500).json({ error: "페이지 생성 실패." });
    }
});

/**
 * 페이지 수정
 * PUT /api/pages/:id
 * body: { title?: string, content?: string }
 */
app.put("/api/pages/:id", authMiddleware, async (req, res) => {
    const id = req.params.id;
	const userId = req.user.id;

    // 보안 개선: XSS 방지 - 제목과 내용 모두 sanitize
    const titleFromBody = typeof req.body.title === "string" ? sanitizeInput(req.body.title.trim()) : null;
    const contentFromBody = typeof req.body.content === "string" ? sanitizeHtmlContent(req.body.content) : null;
    const isEncryptedFromBody = typeof req.body.isEncrypted === "boolean" ? req.body.isEncrypted : null;
    const iconFromBody = typeof req.body.icon === "string" ? req.body.icon.trim() : undefined;

    if (!titleFromBody && !contentFromBody && isEncryptedFromBody === null && iconFromBody === undefined) {
        return res.status(400).json({ error: "수정할 데이터 없음." });
    }

    try {
        // 페이지 조회
        const [rows] = await pool.execute(
            `SELECT id, title, content, created_at, updated_at, parent_id, sort_order, collection_id, is_encrypted, user_id, icon
             FROM pages
             WHERE id = ?`,
            [id]
        );

        if (!rows.length) {
            console.warn("PUT /api/pages/:id - 페이지 없음:", id);
            return res.status(404).json({ error: "Page not found" });
        }

        const existing = rows[0];

        // 컬렉션 접근 권한 확인 (EDIT 이상 필요)
        const { permission } = await getCollectionPermission(existing.collection_id, userId);
        if (!permission || permission === 'READ') {
            return res.status(403).json({ error: "페이지를 수정할 권한이 없습니다." });
        }

        const newTitle = titleFromBody && titleFromBody !== "" ? titleFromBody : existing.title;
        const newContent = contentFromBody !== null ? contentFromBody : existing.content;
        const newIsEncrypted = isEncryptedFromBody !== null ? (isEncryptedFromBody ? 1 : 0) : existing.is_encrypted;
        const newIcon = iconFromBody !== undefined ? (iconFromBody !== "" ? iconFromBody : null) : existing.icon;
        const now = new Date();
        const nowStr = formatDateForDb(now);

        // 암호화 상태가 변경되는 경우 (일반 -> 암호화) user_id를 현재 사용자로 변경
        const isBecomingEncrypted = existing.is_encrypted === 0 && newIsEncrypted === 1;

        if (isBecomingEncrypted) {
            await pool.execute(
                `UPDATE pages
                 SET title = ?, content = ?, is_encrypted = ?, icon = ?, user_id = ?, updated_at = ?
                 WHERE id = ?`,
                [newTitle, newContent, newIsEncrypted, newIcon, userId, nowStr, id]
            );
        } else {
            await pool.execute(
                `UPDATE pages
                 SET title = ?, content = ?, is_encrypted = ?, icon = ?, updated_at = ?
                 WHERE id = ?`,
                [newTitle, newContent, newIsEncrypted, newIcon, nowStr, id]
            );
        }

        const page = {
            id,
            title: newTitle,
            content: newContent,
            parentId: existing.parent_id,
            sortOrder: existing.sort_order,
            collectionId: existing.collection_id,
            createdAt: toIsoString(existing.created_at),
            updatedAt: now.toISOString(),
            icon: newIcon
        };

        console.log("PUT /api/pages/:id 수정 완료:", id);

        // 실시간 메타데이터 변경 브로드캐스트
        if (titleFromBody && titleFromBody !== existing.title) {
            broadcastToCollection(existing.collection_id, 'metadata-change', {
                pageId: id,
                field: 'title',
                value: newTitle
            }, userId);
        }

        if (iconFromBody !== undefined && newIcon !== existing.icon) {
            broadcastToCollection(existing.collection_id, 'metadata-change', {
                pageId: id,
                field: 'icon',
                value: newIcon
            }, userId);
        }

        res.json(page);
    } catch (error) {
        logError("PUT /api/pages/:id", error);
        res.status(500).json({ error: "페이지 수정 실패." });
    }
});

/**
 * 페이지 삭제 (EDIT 이상 권한 필요)
 * DELETE /api/pages/:id
 */
app.delete("/api/pages/:id", authMiddleware, async (req, res) => {
    const id = req.params.id;
	const userId = req.user.id;

    try {
        // 페이지 조회
        const [rows] = await pool.execute(
            `SELECT id, collection_id FROM pages WHERE id = ?`,
            [id]
        );

        if (!rows.length) {
            console.warn("DELETE /api/pages/:id - 페이지 없음:", id);
            return res.status(404).json({ error: "Page not found" });
        }

        const page = rows[0];

        // 컬렉션 접근 권한 확인 (EDIT 이상 필요)
        const { permission } = await getCollectionPermission(page.collection_id, userId);
        if (!permission || permission === 'READ') {
            return res.status(403).json({ error: "페이지를 삭제할 권한이 없습니다." });
        }

        await pool.execute(
            `DELETE FROM pages WHERE id = ?`,
            [id]
        );

        console.log("DELETE /api/pages/:id 삭제:", id);

        res.json({ ok: true, removedId: id });
    } catch (error) {
        logError("DELETE /api/pages/:id", error);
        res.status(500).json({ error: "페이지 삭제 실패." });
    }
});

/**
 * 페이지 공유 허용 설정 업데이트
 * PUT /api/pages/:id/share-permission
 * body: { shareAllowed: boolean }
 */
app.put("/api/pages/:id/share-permission", authMiddleware, async (req, res) => {
    const id = req.params.id;
    const userId = req.user.id;
    const { shareAllowed } = req.body;

    if (typeof shareAllowed !== "boolean") {
        return res.status(400).json({ error: "shareAllowed는 boolean 값이어야 합니다." });
    }

    try {
        // 페이지 조회
        const [rows] = await pool.execute(
            `SELECT id, collection_id, is_encrypted, user_id FROM pages WHERE id = ?`,
            [id]
        );

        if (!rows.length) {
            return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
        }

        const page = rows[0];

        // 암호화된 페이지만 공유 허용 설정 가능
        if (!page.is_encrypted) {
            return res.status(400).json({ error: "암호화된 페이지만 공유 허용 설정이 가능합니다." });
        }

        // 페이지 소유자만 공유 허용 설정 가능
        if (page.user_id !== userId) {
            return res.status(403).json({ error: "페이지 생성자만 공유 허용 설정을 변경할 수 있습니다." });
        }

        // share_allowed 업데이트
        const now = new Date();
        const nowStr = formatDateForDb(now);

        await pool.execute(
            `UPDATE pages SET share_allowed = ?, updated_at = ? WHERE id = ?`,
            [shareAllowed ? 1 : 0, nowStr, id]
        );

        res.json({ ok: true, shareAllowed });
    } catch (error) {
        logError("PUT /api/pages/:id/share-permission", error);
        res.status(500).json({ error: "공유 허용 설정 업데이트 실패." });
    }
});

// ==================== 컬렉션 공유 API ====================

/**
 * 컬렉션을 특정 사용자에게 공유
 * POST /api/collections/:id/shares
 */
app.post("/api/collections/:id/shares", authMiddleware, async (req, res) => {
    const collectionId = req.params.id;
    const { username, permission } = req.body;
    const ownerId = req.user.id;

    // 입력 검증
    if (!username || typeof username !== 'string') {
        return res.status(400).json({ error: "사용자명을 입력해 주세요." });
    }

    if (!['READ', 'EDIT', 'ADMIN'].includes(permission)) {
        return res.status(400).json({ error: "유효하지 않은 권한입니다." });
    }

    try {
        // 1. 컬렉션 소유권 확인
        const { isOwner } = await getCollectionPermission(collectionId, ownerId);
        if (!isOwner) {
            return res.status(403).json({ error: "컬렉션 소유자만 공유할 수 있습니다." });
        }

        // 2. 암호화된 페이지 확인 (share_allowed = 0인 페이지)
        const hasEncrypted = await hasEncryptedPages(collectionId);
        if (hasEncrypted) {
            return res.status(400).json({
                error: "공유가 허용되지 않은 암호화 페이지가 포함되어 있습니다. 해당 페이지의 공유를 허용하거나 삭제한 후 다시 시도해 주세요."
            });
        }

        // 3. 대상 사용자 조회
        const [userRows] = await pool.execute(
            `SELECT id FROM users WHERE username = ?`,
            [username.trim()]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
        }

        const targetUserId = userRows[0].id;

        // 4. 자기 자신에게 공유 방지
        if (targetUserId === ownerId) {
            return res.status(400).json({ error: "자기 자신에게는 공유할 수 없습니다." });
        }

        // 5. 공유 생성 (이미 존재하면 UPDATE)
        const now = new Date();
        const nowStr = formatDateForDb(now);

        await pool.execute(
            `INSERT INTO collection_shares
             (collection_id, owner_user_id, shared_with_user_id, permission, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             permission = VALUES(permission),
             updated_at = VALUES(updated_at)`,
            [collectionId, ownerId, targetUserId, permission, nowStr, nowStr]
        );

        res.status(201).json({
            ok: true,
            share: {
                collectionId,
                username,
                permission,
                createdAt: now.toISOString()
            }
        });
    } catch (error) {
        logError("POST /api/collections/:id/shares", error);
        res.status(500).json({ error: "공유 생성 중 오류가 발생했습니다." });
    }
});

/**
 * 컬렉션 공유 목록 조회
 * GET /api/collections/:id/shares
 */
app.get("/api/collections/:id/shares", authMiddleware, async (req, res) => {
    const collectionId = req.params.id;
    const userId = req.user.id;

    try {
        // 소유자만 공유 목록 조회 가능
        const { isOwner } = await getCollectionPermission(collectionId, userId);
        if (!isOwner) {
            return res.status(403).json({ error: "권한이 없습니다." });
        }

        const [rows] = await pool.execute(
            `SELECT cs.id, u.username, cs.permission, cs.created_at, cs.updated_at
             FROM collection_shares cs
             JOIN users u ON cs.shared_with_user_id = u.id
             WHERE cs.collection_id = ?
             ORDER BY cs.created_at DESC`,
            [collectionId]
        );

        const shares = rows.map(row => ({
            id: row.id,
            username: row.username,
            permission: row.permission,
            createdAt: toIsoString(row.created_at),
            updatedAt: toIsoString(row.updated_at)
        }));

        res.json(shares);
    } catch (error) {
        logError("GET /api/collections/:id/shares", error);
        res.status(500).json({ error: "공유 목록 조회 중 오류가 발생했습니다." });
    }
});

/**
 * 공유 삭제
 * DELETE /api/collections/:id/shares/:shareId
 */
app.delete("/api/collections/:id/shares/:shareId", authMiddleware, async (req, res) => {
    const collectionId = req.params.id;
    const shareId = req.params.shareId;
    const userId = req.user.id;

    try {
        // 소유자만 공유 삭제 가능
        const { isOwner } = await getCollectionPermission(collectionId, userId);
        if (!isOwner) {
            return res.status(403).json({ error: "권한이 없습니다." });
        }

        await pool.execute(
            `DELETE FROM collection_shares WHERE id = ? AND collection_id = ?`,
            [shareId, collectionId]
        );

        res.json({ ok: true });
    } catch (error) {
        logError("DELETE /api/collections/:id/shares/:shareId", error);
        res.status(500).json({ error: "공유 삭제 중 오류가 발생했습니다." });
    }
});

/**
 * 공유 링크 생성
 * POST /api/collections/:id/share-links
 */
app.post("/api/collections/:id/share-links", authMiddleware, async (req, res) => {
    const collectionId = req.params.id;
    const { permission, expiresInDays } = req.body;
    const ownerId = req.user.id;

    if (!['READ', 'EDIT'].includes(permission)) {
        return res.status(400).json({ error: "유효하지 않은 권한입니다. (ADMIN은 링크로 공유 불가)" });
    }

    try {
        const { isOwner } = await getCollectionPermission(collectionId, ownerId);
        if (!isOwner) {
            return res.status(403).json({ error: "컬렉션 소유자만 링크를 생성할 수 있습니다." });
        }

        const hasEncrypted = await hasEncryptedPages(collectionId);
        if (hasEncrypted) {
            return res.status(400).json({
                error: "공유가 허용되지 않은 암호화 페이지가 포함되어 있습니다. 해당 페이지의 공유를 허용하거나 삭제한 후 다시 시도해 주세요."
            });
        }

        const token = generateShareToken();
        const now = new Date();
        const nowStr = formatDateForDb(now);

        let expiresAt = null;
        if (expiresInDays && typeof expiresInDays === 'number' && expiresInDays > 0) {
            const expiry = new Date(now.getTime() + expiresInDays * 24 * 60 * 60 * 1000);
            expiresAt = formatDateForDb(expiry);
        }

        await pool.execute(
            `INSERT INTO share_links
             (token, collection_id, owner_user_id, permission, expires_at, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [token, collectionId, ownerId, permission, expiresAt, nowStr, nowStr]
        );

        res.status(201).json({
            ok: true,
            link: {
                token,
                url: `${BASE_URL}/share/${token}`,
                permission,
                expiresAt: expiresAt ? toIsoString(expiresAt) : null
            }
        });
    } catch (error) {
        logError("POST /api/collections/:id/share-links", error);
        res.status(500).json({ error: "링크 생성 중 오류가 발생했습니다." });
    }
});

/**
 * 컬렉션의 모든 공유 링크 조회
 * GET /api/collections/:id/share-links
 */
app.get("/api/collections/:id/share-links", authMiddleware, async (req, res) => {
    const collectionId = req.params.id;
    const userId = req.user.id;

    try {
        const { isOwner } = await getCollectionPermission(collectionId, userId);
        if (!isOwner) {
            return res.status(403).json({ error: "권한이 없습니다." });
        }

        const [rows] = await pool.execute(
            `SELECT id, token, permission, expires_at, is_active, created_at
             FROM share_links
             WHERE collection_id = ?
             ORDER BY created_at DESC`,
            [collectionId]
        );

        const links = rows.map(row => ({
            id: row.id,
            token: row.token,
            url: `${BASE_URL}/share/${row.token}`,
            permission: row.permission,
            expiresAt: row.expires_at ? toIsoString(row.expires_at) : null,
            isActive: row.is_active ? true : false,
            createdAt: toIsoString(row.created_at)
        }));

        res.json(links);
    } catch (error) {
        logError("GET /api/collections/:id/share-links", error);
        res.status(500).json({ error: "링크 목록 조회 중 오류가 발생했습니다." });
    }
});

/**
 * 공유 링크 삭제
 * DELETE /api/collections/:id/share-links/:linkId
 */
app.delete("/api/collections/:id/share-links/:linkId", authMiddleware, async (req, res) => {
    const collectionId = req.params.id;
    const linkId = req.params.linkId;
    const userId = req.user.id;

    try {
        const { isOwner } = await getCollectionPermission(collectionId, userId);
        if (!isOwner) {
            return res.status(403).json({ error: "권한이 없습니다." });
        }

        await pool.execute(
            `DELETE FROM share_links WHERE id = ? AND collection_id = ?`,
            [linkId, collectionId]
        );

        res.json({ ok: true });
    } catch (error) {
        logError("DELETE /api/collections/:id/share-links/:linkId", error);
        res.status(500).json({ error: "링크 삭제 중 오류가 발생했습니다." });
    }
});

/**
 * 공유 링크로 컬렉션 정보 조회 (인증 불필요)
 * GET /api/share-links/:token
 */
app.get("/api/share-links/:token", async (req, res) => {
    const token = req.params.token;

    try {
        const [rows] = await pool.execute(
            `SELECT sl.collection_id, sl.permission, sl.expires_at, sl.is_active,
                    c.name as collection_name
             FROM share_links sl
             JOIN collections c ON sl.collection_id = c.id
             WHERE sl.token = ?`,
            [token]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "유효하지 않은 공유 링크입니다." });
        }

        const link = rows[0];

        if (!link.is_active) {
            return res.status(403).json({ error: "비활성화된 링크입니다." });
        }

        if (link.expires_at && new Date(link.expires_at) < new Date()) {
            return res.status(403).json({ error: "만료된 링크입니다." });
        }

        res.json({
            collectionId: link.collection_id,
            collectionName: link.collection_name,
            permission: link.permission,
            expiresAt: link.expires_at ? toIsoString(link.expires_at) : null
        });
    } catch (error) {
        logError("GET /api/share-links/:token", error);
        res.status(500).json({ error: "링크 정보 조회 중 오류가 발생했습니다." });
    }
});

// ============================================================================
// SSE 실시간 동기화 API
// ============================================================================

/**
 * 페이지 실시간 동기화 SSE
 * GET /api/pages/:pageId/sync
 */
app.get('/api/pages/:pageId/sync', sseConnectionLimiter, authMiddleware, async (req, res) => {
    const pageId = req.params.pageId;
    const userId = req.user.id;
    const username = req.user.username;

    try {
        // 권한 검증 (EDIT 이상, 암호화 페이지 제외)
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
            return res.status(403).json({ error: '권한이 없거나 암호화된 페이지입니다.' });
        }

        // SSE 헤더 설정
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no'); // Nginx 버퍼링 비활성화
        res.flushHeaders();

        // 연결 등록
        if (!sseConnections.pages.has(pageId)) {
            sseConnections.pages.set(pageId, new Set());
        }

        const userColor = getUserColor(userId);
        const connection = { res, userId, username, color: userColor };
        sseConnections.pages.get(pageId).add(connection);

        // 초기 Yjs 상태 전송
        const ydoc = await loadOrCreateYjsDoc(pageId);
        const stateVector = Y.encodeStateAsUpdate(ydoc);
        const base64State = Buffer.from(stateVector).toString('base64');

        res.write(`event: init\ndata: ${JSON.stringify({
            state: base64State,
            userId,
            username,
            color: userColor
        })}\n\n`);

        // 다른 사용자에게 join 알림
        broadcastToPage(pageId, 'user-joined', { userId, username, color: userColor }, userId);

        // Keep-alive (30초마다 ping)
        const pingInterval = setInterval(() => {
            try {
                res.write(': ping\n\n');
            } catch (error) {
                clearInterval(pingInterval);
            }
        }, 30000);

        // 연결 종료 처리
        req.on('close', async () => {
            clearInterval(pingInterval);
            sseConnections.pages.get(pageId)?.delete(connection);

            if (sseConnections.pages.get(pageId)?.size === 0) {
                sseConnections.pages.delete(pageId);
                // 마지막 사용자가 나가면 문서 저장
                try {
                    await saveYjsDocToDatabase(pageId, ydoc);
                } catch (error) {
                    console.error(`[SSE] 연결 종료 시 저장 실패 (${pageId}):`, error);
                }
            }

            broadcastToPage(pageId, 'user-left', { userId }, userId);
        });

    } catch (error) {
        logError('GET /api/pages/:pageId/sync', error);
        if (!res.headersSent) {
            res.status(500).json({ error: '연결 실패' });
        }
    }
});

/**
 * Yjs 업데이트 수신
 * POST /api/pages/:pageId/sync-update
 */
app.post('/api/pages/:pageId/sync-update',
    express.raw({ type: 'application/octet-stream', limit: '10mb' }),
    authMiddleware,
    async (req, res) => {
    const pageId = req.params.pageId;
    const userId = req.user.id;

    try {
        // 권한 검증
        const [rows] = await pool.execute(
            `SELECT p.id FROM pages p
             LEFT JOIN collections c ON p.collection_id = c.id
             LEFT JOIN collection_shares cs ON c.id = cs.collection_id AND cs.shared_with_user_id = ?
             WHERE p.id = ? AND p.is_encrypted = 0
               AND (c.user_id = ? OR cs.permission IN ('EDIT', 'ADMIN'))`,
            [userId, pageId, userId]
        );

        if (!rows.length) {
            return res.status(403).json({ error: '권한 없음' });
        }

        // raw body는 이미 Buffer로 파싱됨
        const updateData = req.body;

        if (!Buffer.isBuffer(updateData)) {
            console.error('[SSE] 잘못된 데이터 형식:', typeof updateData);
            return res.status(400).json({ error: '잘못된 데이터 형식' });
        }

        // Yjs 업데이트 적용
        const ydoc = await loadOrCreateYjsDoc(pageId);
        Y.applyUpdate(ydoc, updateData);

        // 다른 사용자에게 브로드캐스트
        const base64Update = updateData.toString('base64');
        broadcastToPage(pageId, 'yjs-update', { update: base64Update }, userId);

        // Debounce 저장 (5초)
        const docData = yjsDocuments.get(pageId);
        if (docData) {
            if (docData.saveTimeout) {
                clearTimeout(docData.saveTimeout);
            }
            docData.saveTimeout = setTimeout(() => {
                saveYjsDocToDatabase(pageId, ydoc).catch(err => {
                    console.error(`[SSE] Debounce 저장 실패 (${pageId}):`, err);
                });
            }, 5000);
        }

        res.status(200).json({ success: true });
    } catch (error) {
        logError('POST /api/pages/:pageId/sync-update', error);
        res.status(500).json({ error: '업데이트 실패' });
    }
});

/**
 * 컬렉션 메타데이터 동기화 SSE
 * GET /api/collections/:collectionId/sync
 */
app.get('/api/collections/:collectionId/sync', sseConnectionLimiter, authMiddleware, async (req, res) => {
    const collectionId = req.params.collectionId;
    const userId = req.user.id;

    try {
        // 권한 검증
        const permission = await getCollectionPermission(collectionId, userId);
        if (!permission || !permission.permission) {
            return res.status(403).json({ error: '권한 없음' });
        }

        // SSE 헤더
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        res.setHeader('X-Accel-Buffering', 'no');
        res.flushHeaders();

        // 연결 등록
        if (!sseConnections.collections.has(collectionId)) {
            sseConnections.collections.set(collectionId, new Set());
        }

        const connection = { res, userId, permission: permission.permission };
        sseConnections.collections.get(collectionId).add(connection);

        // Keep-alive
        const pingInterval = setInterval(() => {
            try {
                res.write(': ping\n\n');
            } catch (error) {
                clearInterval(pingInterval);
            }
        }, 30000);

        // 연결 종료
        req.on('close', () => {
            clearInterval(pingInterval);
            sseConnections.collections.get(collectionId)?.delete(connection);

            if (sseConnections.collections.get(collectionId)?.size === 0) {
                sseConnections.collections.delete(collectionId);
            }
        });

    } catch (error) {
        logError('GET /api/collections/:collectionId/sync', error);
        if (!res.headersSent) {
            res.status(500).json({ error: '연결 실패' });
        }
    }
});

// ============================================================================
// TOTP (2단계 인증) API
// ============================================================================

/**
 * TOTP 활성화 상태 확인
 */
app.get("/api/totp/status", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const [rows] = await pool.execute(
            "SELECT totp_enabled FROM users WHERE id = ?",
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
        }

        res.json({ enabled: Boolean(rows[0].totp_enabled) });
    } catch (error) {
        logError("GET /api/totp/status", error);
        res.status(500).json({ error: "TOTP 상태 확인 중 오류가 발생했습니다." });
    }
});

/**
 * TOTP 설정 시작 - 시크릿 생성 및 QR 코드 URL 반환
 */
app.post("/api/totp/setup", authMiddleware, csrfMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const username = req.user.username;

        // TOTP 시크릿 생성
        const secret = speakeasy.generateSecret({
            name: `NTEOK (${username})`,
            length: 32
        });

        // QR 코드 데이터 URL 생성
        const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

        // 시크릿을 세션에 임시 저장 (아직 DB에 저장하지 않음)
        const sessionId = req.cookies[SESSION_COOKIE_NAME];
        const session = sessions.get(sessionId);
        if (!session) {
            return res.status(401).json({ error: "세션이 만료되었습니다." });
        }
        session.totpTempSecret = secret.base32;

        res.json({
            secret: secret.base32,
            qrCode: qrCodeUrl
        });
    } catch (error) {
        logError("POST /api/totp/setup", error);
        res.status(500).json({ error: "TOTP 설정 중 오류가 발생했습니다." });
    }
});

/**
 * TOTP 설정 검증 및 활성화
 */
app.post("/api/totp/verify-setup", authMiddleware, csrfMiddleware, totpLimiter, async (req, res) => {
    try {
        const userId = req.user.id;
        const { token } = req.body;

        if (!token || !/^\d{6}$/.test(token)) {
            return res.status(400).json({ error: "유효한 6자리 코드를 입력하세요." });
        }

        // 세션에서 임시 시크릿 가져오기
        const sessionId = req.cookies[SESSION_COOKIE_NAME];
        const session = sessions.get(sessionId);
        const secret = session?.totpTempSecret;

        if (!secret) {
            return res.status(400).json({ error: "TOTP 설정을 다시 시작하세요." });
        }

        // TOTP 토큰 검증
        const verified = speakeasy.totp.verify({
            secret: secret,
            encoding: 'base32',
            token: token,
            window: 2
        });

        if (!verified) {
            return res.status(400).json({ error: "잘못된 인증 코드입니다." });
        }

        // 백업 코드 10개 생성
        const backupCodes = [];
        const now = new Date();
        const nowStr = formatDateForDb(now);

        for (let i = 0; i < 10; i++) {
            const code = crypto.randomBytes(4).toString('hex'); // 8자리 hex
            backupCodes.push(code);

            // 백업 코드 해시 저장
            const codeHash = await bcrypt.hash(code, BCRYPT_SALT_ROUNDS);
            await pool.execute(
                "INSERT INTO backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
                [userId, codeHash, nowStr]
            );
        }

        // DB에 TOTP 시크릿 저장 및 활성화
        await pool.execute(
            "UPDATE users SET totp_secret = ?, totp_enabled = 1, updated_at = ? WHERE id = ?",
            [secret, nowStr, userId]
        );

        // 세션에서 임시 시크릿 제거
        delete session.totpTempSecret;

        res.json({
            success: true,
            backupCodes: backupCodes
        });
    } catch (error) {
        logError("POST /api/totp/verify-setup", error);
        res.status(500).json({ error: "TOTP 활성화 중 오류가 발생했습니다." });
    }
});

/**
 * TOTP 비활성화
 */
app.post("/api/totp/disable", authMiddleware, csrfMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const { password } = req.body;

        if (!password) {
            return res.status(400).json({ error: "비밀번호를 입력하세요." });
        }

        // 비밀번호 확인
        const [rows] = await pool.execute(
            "SELECT password_hash FROM users WHERE id = ?",
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
        }

        const isPasswordValid = await bcrypt.compare(password, rows[0].password_hash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: "비밀번호가 일치하지 않습니다." });
        }

        // TOTP 비활성화
        const now = new Date();
        const nowStr = formatDateForDb(now);

        await pool.execute(
            "UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = ? WHERE id = ?",
            [nowStr, userId]
        );

        // 백업 코드 삭제
        await pool.execute("DELETE FROM backup_codes WHERE user_id = ?", [userId]);

        res.json({ success: true });
    } catch (error) {
        logError("POST /api/totp/disable", error);
        res.status(500).json({ error: "TOTP 비활성화 중 오류가 발생했습니다." });
    }
});

/**
 * 로그인 시 TOTP 검증
 */
app.post("/api/totp/verify-login", totpLimiter, async (req, res) => {
    try {
        const { token, tempSessionId } = req.body;

        if (!token || !/^\d{6}$/.test(token)) {
            return res.status(400).json({ error: "유효한 6자리 코드를 입력하세요." });
        }

        if (!tempSessionId) {
            return res.status(400).json({ error: "세션 정보가 없습니다." });
        }

        // 임시 세션에서 사용자 정보 가져오기
        const tempSession = sessions.get(tempSessionId);
        if (!tempSession || !tempSession.pendingUserId) {
            return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
        }

        const userId = tempSession.pendingUserId;

        // 사용자 TOTP 시크릿 가져오기
        const [rows] = await pool.execute(
            "SELECT totp_secret, username FROM users WHERE id = ? AND totp_enabled = 1",
            [userId]
        );

        if (rows.length === 0) {
            return res.status(404).json({ error: "TOTP가 활성화되지 않았습니다." });
        }

        const { totp_secret, username } = rows[0];

        // TOTP 토큰 검증
        const verified = speakeasy.totp.verify({
            secret: totp_secret,
            encoding: 'base32',
            token: token,
            window: 2
        });

        if (!verified) {
            return res.status(401).json({ error: "잘못된 인증 코드입니다." });
        }

        // 정식 세션 생성
        const now = new Date();
        const sessionId = crypto.randomBytes(32).toString("hex");
        const csrfToken = generateCsrfToken();

        sessions.set(sessionId, {
            userId: userId,
            username: username,
            csrfToken: csrfToken,
            createdAt: now.getTime(),
            lastAccessedAt: now.getTime()
        });

        // 임시 세션 삭제
        sessions.delete(tempSessionId);

        // 세션 쿠키 설정
        res.cookie(SESSION_COOKIE_NAME, sessionId, {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: "strict",
            maxAge: SESSION_TTL_MS
        });

        res.cookie(CSRF_COOKIE_NAME, csrfToken, {
            httpOnly: false,
            secure: IS_PRODUCTION,
            sameSite: "strict",
            maxAge: SESSION_TTL_MS
        });

        res.json({ success: true });
    } catch (error) {
        logError("POST /api/totp/verify-login", error);
        res.status(500).json({ error: "TOTP 검증 중 오류가 발생했습니다." });
    }
});

/**
 * 백업 코드로 로그인
 */
app.post("/api/totp/verify-backup-code", totpLimiter, async (req, res) => {
    try {
        const { backupCode, tempSessionId } = req.body;

        if (!backupCode) {
            return res.status(400).json({ error: "백업 코드를 입력하세요." });
        }

        if (!tempSessionId) {
            return res.status(400).json({ error: "세션 정보가 없습니다." });
        }

        // 임시 세션에서 사용자 정보 가져오기
        const tempSession = sessions.get(tempSessionId);
        if (!tempSession || !tempSession.pendingUserId) {
            return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
        }

        const userId = tempSession.pendingUserId;

        // 사용되지 않은 백업 코드 가져오기
        const [rows] = await pool.execute(
            "SELECT id, code_hash FROM backup_codes WHERE user_id = ? AND used = 0",
            [userId]
        );

        if (rows.length === 0) {
            return res.status(401).json({ error: "사용 가능한 백업 코드가 없습니다." });
        }

        // 백업 코드 검증
        let validCodeId = null;
        for (const row of rows) {
            const isValid = await bcrypt.compare(backupCode, row.code_hash);
            if (isValid) {
                validCodeId = row.id;
                break;
            }
        }

        if (!validCodeId) {
            return res.status(401).json({ error: "잘못된 백업 코드입니다." });
        }

        // 백업 코드 사용 처리
        const now = new Date();
        const nowStr = formatDateForDb(now);
        await pool.execute(
            "UPDATE backup_codes SET used = 1, used_at = ? WHERE id = ?",
            [nowStr, validCodeId]
        );

        // 사용자 정보 가져오기
        const [userRows] = await pool.execute(
            "SELECT username FROM users WHERE id = ?",
            [userId]
        );

        if (userRows.length === 0) {
            return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
        }

        const username = userRows[0].username;

        // 정식 세션 생성
        const sessionId = crypto.randomBytes(32).toString("hex");
        const csrfToken = generateCsrfToken();

        sessions.set(sessionId, {
            userId: userId,
            username: username,
            csrfToken: csrfToken,
            createdAt: now.getTime(),
            lastAccessedAt: now.getTime()
        });

        // 임시 세션 삭제
        sessions.delete(tempSessionId);

        // 세션 쿠키 설정
        res.cookie(SESSION_COOKIE_NAME, sessionId, {
            httpOnly: true,
            secure: IS_PRODUCTION,
            sameSite: "strict",
            maxAge: SESSION_TTL_MS
        });

        res.cookie(CSRF_COOKIE_NAME, csrfToken, {
            httpOnly: false,
            secure: IS_PRODUCTION,
            sameSite: "strict",
            maxAge: SESSION_TTL_MS
        });

        res.json({ success: true });
    } catch (error) {
        logError("POST /api/totp/verify-backup-code", error);
        res.status(500).json({ error: "백업 코드 검증 중 오류가 발생했습니다." });
    }
});

/**
 * 서버 시작 (HTTPS 자동 설정)
 */
(async () => {
    try {
        await initDb();

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