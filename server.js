const express = require("express");
const path = require("path");
const mysql = require("mysql2/promise");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// 세션 / 인증 관련 설정
const SESSION_COOKIE_NAME = "dwrnote_session";
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7일

// 기본 관리자 계정 (최초 1번만 생성)
const DEFAULT_ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const DEFAULT_ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin";
const BCRYPT_SALT_ROUNDS = Number(process.env.BCRYPT_SALT_ROUNDS || 12);

/**
 * DB 연결 설정 정보
 */
const DB_CONFIG = {
    host: process.env.DB_HOST || "localhost",
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "admin",
    database: process.env.DB_NAME || "dwrnote",
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

let pool;
const sessions = new Map();

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
 * ISO string 기반 페이지 ID 생성
 */
function generatePageId(now) {
    const iso = now.toISOString().replace(/[:.]/g, "-");
    const rand = Math.random().toString(36).slice(2, 8);
    return "page-" + iso + "-" + rand;
}

/**
 * ISO string 기반 컬렉션 ID 생성
 */
function generateCollectionId(now) {
    const iso = now.toISOString().replace(/[:.]/g, "-");
    const rand = Math.random().toString(36).slice(2, 8);
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
 * 세션 생성
 */
function createSession(user) {
    const sessionId = crypto.randomBytes(24).toString("hex");
    const expiresAt = Date.now() + SESSION_TTL_MS;

    sessions.set(sessionId, {
        userId: user.id,
        username: user.username,
        expiresAt
    });

    return sessionId;
}

/**
 * 요청에서 세션 읽기
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

    if (session.expiresAt <= Date.now()) {
        sessions.delete(sessionId);
        return null;
    }

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
            updated_at DATETIME NOT NULL
        )
    `);

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
        updatedAt: now.toISOString()
    };
}

/**
 * 미들웨어 설정
 */
app.use(express.json());
app.use(cookieParser());
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
app.post("/api/auth/login", async (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
    }

    const trimmedUsername = username.trim();

    try {
        const [rows] = await pool.execute(
            `
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            `,
            [trimmedUsername]
        );

        if (!rows.length) {
            console.warn("로그인 실패 - 존재하지 않는 사용자:", trimmedUsername);
            return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
        }

        const user = rows[0];

        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) {
            console.warn("로그인 실패 - 비밀번호 불일치:", trimmedUsername);
            return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
        }

        const sessionId = createSession(user);

        res.cookie(SESSION_COOKIE_NAME, sessionId, {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: SESSION_TTL_MS
        });

        res.json({
            ok: true,
            user: {
                id: user.id,
                username: user.username
            }
        });
    } catch (error) {
        console.error("POST /api/auth/login 오류:", error);
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
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production"
    });

    res.json({ ok: true });
});

/**
 * 회원가입
 * POST /api/auth/register
 * body: { username: string, password: string }
 */
app.post("/api/auth/register", async (req, res) => {
    const { username, password } = req.body || {};

    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
    }

    const trimmedUsername = username.trim();

    // 기본적인 유효성 검사
    if (trimmedUsername.length < 3 || trimmedUsername.length > 64) {
        return res.status(400).json({ error: "아이디는 3~64자 사이로 입력해 주세요." });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: "비밀번호는 6자 이상으로 입력해 주세요." });
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

        res.cookie(SESSION_COOKIE_NAME, sessionId, {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
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
        console.error("POST /api/auth/register 오류:", error);
        return res.status(500).json({ error: "회원가입 처리 중 오류가 발생했습니다." });
    }
});

/**
 * 현재 로그인한 사용자 정보 확인
 * GET /api/auth/me
 */
app.get("/api/auth/me", authMiddleware, (req, res) => {
    res.json({
        id: req.user.id,
        username: req.user.username
    });
});

/**
 * 컬렉션 목록 조회
 * GET /api/collections
 */
app.get("/api/collections", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const [rows] = await pool.execute(
            `
            SELECT id, name, sort_order, created_at, updated_at
            FROM collections
            WHERE user_id = ?
            ORDER BY sort_order ASC, updated_at DESC
            `,
            [userId]
        );

        const list = rows.map((row) => ({
            id: row.id,
            name: row.name,
            sortOrder: row.sort_order,
            createdAt: toIsoString(row.created_at),
            updatedAt: toIsoString(row.updated_at)
        }));

        res.json(list);
    } catch (error) {
        console.error("GET /api/collections 오류:", error);
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
    const name = rawName !== "" ? rawName : "새 컬렉션";

    try {
        const userId = req.user.id;
        const collection = await createCollection({ userId, name });
        res.status(201).json(collection);
    } catch (error) {
        console.error("POST /api/collections 오류:", error);
        res.status(500).json({ error: "컬렉션을 생성하지 못했습니다." });
    }
});

/**
 * 컬렉션 삭제
 * DELETE /api/collections/:id
 */
app.delete("/api/collections/:id", authMiddleware, async (req, res) => {
    const id = req.params.id;
    const userId = req.user.id;

    try {
        const [rows] = await pool.execute(
            `
            SELECT id
            FROM collections
            WHERE id = ? AND user_id = ?
            `,
            [id, userId]
        );

        if (!rows.length) {
            return res.status(404).json({ error: "컬렉션을 찾을 수 없습니다." });
        }

        // 컬렉션 삭제 (pages는 FK CASCADE)
        await pool.execute(
            `
            DELETE FROM collections
            WHERE id = ? AND user_id = ?
            `,
            [id, userId]
        );

        res.json({ ok: true, removedId: id });
    } catch (error) {
        console.error("DELETE /api/collections/:id 오류:", error);
        res.status(500).json({ error: "컬렉션 삭제에 실패했습니다." });
    }
});

/**
 * 페이지 목록 조회
 * GET /api/pages
 */
app.get("/api/pages", authMiddleware, async (req, res) => {
    try {
		const userId = req.user.id;
        const collectionId =
            typeof req.query.collectionId === "string" && req.query.collectionId.trim() !== ""
                ? req.query.collectionId.trim()
                : null;

        let query = `
            SELECT id, title, updated_at, parent_id, sort_order, collection_id
            FROM pages
            WHERE user_id = ?
        `;
        const params = [userId];

        if (collectionId) {
            query += ` AND collection_id = ?`;
            params.push(collectionId);
        }

        query += `
            ORDER BY collection_id ASC, parent_id IS NULL DESC, sort_order ASC, updated_at DESC
        `;

        const [rows] = await pool.execute(query, params);

        const list = rows.map((row) => ({
            id: row.id,
            title: row.title || "제목 없음",
            updatedAt: toIsoString(row.updated_at),
            parentId: row.parent_id,
            sortOrder: row.sort_order,
            collectionId: row.collection_id
        }));

        console.log("GET /api/pages 응답 개수:", list.length);

        res.json(list);
    } catch (error) {
        console.error("GET /api/pages 오류:", error);
        res.status(500).json({ error: "페이지 목록 불러오기 실패." });
    }
});

/**
 * 단일 페이지 조회
 * GET /api/pages/:id
 */
app.get("/api/pages/:id", authMiddleware, async (req, res) => {
    const id = req.params.id;
	const userId = req.user.id;

    try {
        const [rows] = await pool.execute(
            `
            SELECT id, title, content, created_at, updated_at, parent_id, sort_order, collection_id
            FROM pages
            WHERE id = ? AND user_id = ?
            `,
            [id, userId]
        );

        if (!rows.length) {
            console.warn("GET /api/pages/:id - 페이지 없음:", id);
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
            collectionId: row.collection_id
        };

        console.log("GET /api/pages/:id 응답:", id);

        res.json(page);
    } catch (error) {
        console.error("GET /api/pages/:id 오류:", error);
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
    const title = rawTitle.trim() !== "" ? rawTitle.trim() : "제목 없음";

    const now = new Date();
    const id = generatePageId(now);
    const nowStr = formatDateForDb(now);
    const content = "<p></p>";
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

    if (!collectionId) {
        return res.status(400).json({ error: "collectionId가 필요합니다." });
    }

    try {
        // 컬렉션 존재 여부 및 소유권 확인
        const [colRows] = await pool.execute(
            `
            SELECT id FROM collections
            WHERE id = ? AND user_id = ?
            `,
            [collectionId, userId]
        );

        if (!colRows.length) {
            return res.status(404).json({ error: "컬렉션을 찾을 수 없습니다." });
        }

        if (parentId) {
            const [parentRows] = await pool.execute(
                `
                SELECT id, collection_id FROM pages
                WHERE id = ? AND user_id = ?
                `,
                [parentId, userId]
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
            INSERT INTO pages (id, user_id, parent_id, title, content, sort_order, created_at, updated_at, collection_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [id, userId, parentId, title, content, sortOrder, nowStr, nowStr, collectionId]
        );

        const page = {
            id,
            title,
            content,
            parentId,
            sortOrder,
            collectionId,
            createdAt: now.toISOString(),
            updatedAt: now.toISOString()
        };

        console.log("POST /api/pages 생성:", id);

        res.status(201).json(page);
    } catch (error) {
        console.error("POST /api/pages 오류:", error);
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

    const titleFromBody = typeof req.body.title === "string" ? req.body.title.trim() : null;
    const contentFromBody = typeof req.body.content === "string" ? req.body.content : null;

    if (!titleFromBody && !contentFromBody) {
        return res.status(400).json({ error: "수정할 데이터 없음." });
    }

    try {
        const [rows] = await pool.execute(
            `
            SELECT id, title, content, created_at, updated_at, parent_id, sort_order, collection_id
            FROM pages
            WHERE id = ? AND user_id = ?
            `,
            [id, userId]
        );

        if (!rows.length) {
            console.warn("PUT /api/pages/:id - 페이지 없음:", id);
            return res.status(404).json({ error: "Page not found" });
        }

        const existing = rows[0];

        const newTitle = titleFromBody && titleFromBody !== "" ? titleFromBody : existing.title;
        const newContent = contentFromBody !== null ? contentFromBody : existing.content;
        const now = new Date();
        const nowStr = formatDateForDb(now);

        await pool.execute(
            `
            UPDATE pages
            SET title = ?, content = ?, updated_at = ?
            WHERE id = ? AND user_id = ?
            `,
            [newTitle, newContent, nowStr, id, userId]
        );

        const page = {
            id,
            title: newTitle,
            content: newContent,
            parentId: existing.parent_id,
            sortOrder: existing.sort_order,
            collectionId: existing.collection_id,
            createdAt: toIsoString(existing.created_at),
            updatedAt: now.toISOString()
        };

        console.log("PUT /api/pages/:id 수정 완료:", id);

        res.json(page);
    } catch (error) {
        console.error("PUT /api/pages/:id 오류:", error);
        res.status(500).json({ error: "페이지 수정 실패." });
    }
});

/**
 * 페이지 삭제
 * DELETE /api/pages/:id
 */
app.delete("/api/pages/:id", authMiddleware, async (req, res) => {
    const id = req.params.id;
	const userId = req.user.id;

    try {
        const [rows] = await pool.execute(
            `
            SELECT id
            FROM pages
            WHERE id = ? AND user_id = ?
            `,
            [id, userId]
        );

        if (!rows.length) {
            console.warn("DELETE /api/pages/:id - 페이지 없음:", id);
            return res.status(404).json({ error: "Page not found" });
        }

        await pool.execute(
            `
            DELETE FROM pages
            WHERE id = ? AND user_id = ?
            `,
            [id, userId]
        );

        console.log("DELETE /api/pages/:id 삭제:", id);

        res.json({ ok: true, removedId: id });
    } catch (error) {
        console.error("DELETE /api/pages/:id 오류:", error);
        res.status(500).json({ error: "페이지 삭제 실패." });
    }
});

/**
 * 서버 시작
 */
(async () => {
    try {
        await initDb();
        app.listen(PORT, () => {
            console.log(`DWRNote 앱이 http://localhost:${PORT} 에서 실행 중.`);
        });
    } catch (error) {
        console.error("서버 시작 중 치명적 오류:", error);
        process.exit(1);
    }
})();