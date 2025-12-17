const express = require('express');
const router = express.Router();

/**
 * Authentication Routes
 *
 * 이 파일은 인증 관련 라우트를 처리합니다.
 * - 로그인, 로그아웃, 회원가입
 * - 계정 삭제
 * - 현재 사용자 정보 조회
 * - 암호화 Salt 업데이트
 * - 비밀번호 재확인
 */

module.exports = (dependencies) => {
    const {
        pool,
        bcrypt,
        crypto,
        sessions,
        userSessions,
        createSession,
        generateCsrfToken,
        formatDateForDb,
        validatePasswordStrength,
        logError,
        SESSION_COOKIE_NAME,
        CSRF_COOKIE_NAME,
        SESSION_TTL_MS,
        IS_PRODUCTION,
        BCRYPT_SALT_ROUNDS,
        createCollection,
        authMiddleware,
        authLimiter
    } = dependencies;

    /**
     * 로그인
     * POST /api/auth/login
     * body: { username: string, password: string }
     */
    router.post("/login", authLimiter, async (req, res) => {
        const { username, password } = req.body || {};

        if (typeof username !== "string" || typeof password !== "string") {
            return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
        }

        const trimmedUsername = username.trim();

        try {
            const [rows] = await pool.execute(
                `
                SELECT id, username, password_hash, encryption_salt, totp_enabled, passkey_enabled, block_duplicate_login
                FROM users
                WHERE username = ?
                `,
                [trimmedUsername]
            );

            if (!rows.length) {
                console.warn("로그인 실패 - 존재하지 않는 사용자 (IP: " + req.ip + ")");
                return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
            }

            const user = rows[0];

            const ok = await bcrypt.compare(password, user.password_hash);
            if (!ok) {
                console.warn("로그인 실패 - 비밀번호 불일치 (IP: " + req.ip + ")");
                return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
            }

            // 2FA(TOTP 또는 패스키) 활성화 확인
            if (user.totp_enabled || user.passkey_enabled) {
                // 임시 세션 생성 (2FA 검증 대기)
                const tempSessionId = crypto.randomBytes(32).toString("hex");
                const now = new Date();

                sessions.set(tempSessionId, {
                    pendingUserId: user.id,
                    createdAt: now.getTime(),
                    lastAccessedAt: now.getTime()
                });

                // 사용 가능한 2FA 방법 목록
                const availableMethods = [];
                if (user.totp_enabled) availableMethods.push('totp');
                if (user.passkey_enabled) availableMethods.push('passkey');

                // 2FA 검증 필요 응답
                return res.json({
                    ok: false,
                    requires2FA: true,
                    availableMethods: availableMethods,
                    tempSessionId: tempSessionId
                });
            }

            // TOTP 비활성화 상태 - 정상 로그인 진행
            const sessionResult = createSession({
                id: user.id,
                username: user.username,
                blockDuplicateLogin: user.block_duplicate_login
            });

            // 중복 로그인 차단 모드에서 거부된 경우
            if (!sessionResult.success) {
                return res.status(409).json({
                    error: sessionResult.error,
                    code: 'DUPLICATE_LOGIN_BLOCKED'
                });
            }

            const sessionId = sessionResult.sessionId;

            res.cookie(SESSION_COOKIE_NAME, sessionId, {
                httpOnly: true,
                sameSite: "strict",
                secure: IS_PRODUCTION,
                maxAge: SESSION_TTL_MS
            });

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
    router.post("/logout", (req, res) => {
        const { getSessionFromRequest } = dependencies;
        const session = getSessionFromRequest(req);
        if (session) {
            sessions.delete(session.id);

            // userSessions에서도 제거
            if (session.userId) {
                const userSessionSet = userSessions.get(session.userId);
                if (userSessionSet) {
                    userSessionSet.delete(session.id);
                    if (userSessionSet.size === 0) {
                        userSessions.delete(session.userId);
                    }
                }
            }
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
    router.delete("/account", authMiddleware, async (req, res) => {
        const { password, confirmText } = req.body || {};

        if (typeof password !== "string" || !password.trim()) {
            return res.status(400).json({ error: "비밀번호를 입력해 주세요." });
        }

        if (confirmText !== "계정 삭제") {
            return res.status(400).json({ error: '확인 문구를 정확히 입력해 주세요. "계정 삭제"를 입력하세요.' });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, username, password_hash FROM users WHERE id = ?`,
                [req.user.id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const user = rows[0];

            const ok = await bcrypt.compare(password, user.password_hash);
            if (!ok) {
                console.warn("계정 삭제 시도 - 비밀번호 불일치:", req.user.username);
                return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });
            }

            await pool.execute(`DELETE FROM users WHERE id = ?`, [req.user.id]);

            console.log(`계정 삭제 완료: 사용자 ID ${req.user.id} (${req.user.username})`);

            const { getSessionFromRequest } = dependencies;
            const session = getSessionFromRequest(req);
            if (session) {
                sessions.delete(session.id);

                // userSessions에서도 제거
                if (session.userId) {
                    const userSessionSet = userSessions.get(session.userId);
                    if (userSessionSet) {
                        userSessionSet.delete(session.id);
                        if (userSessionSet.size === 0) {
                            userSessions.delete(session.userId);
                        }
                    }
                }
            }

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
    router.post("/register", authLimiter, async (req, res) => {
        const { username, password } = req.body || {};

        if (typeof username !== "string" || typeof password !== "string") {
            return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
        }

        const trimmedUsername = username.trim();

        if (trimmedUsername.length < 3 || trimmedUsername.length > 64) {
            return res.status(400).json({ error: "아이디는 3~64자 사이로 입력해 주세요." });
        }

        const passwordValidation = validatePasswordStrength(password);
        if (!passwordValidation.valid) {
            return res.status(400).json({ error: passwordValidation.error });
        }

        try {
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

            const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);

            const [result] = await pool.execute(
                `
                INSERT INTO users (username, password_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                `,
                [trimmedUsername, passwordHash, nowStr, nowStr]
            );

            const user = {
                id: result.insertId,
                username: trimmedUsername,
                blockDuplicateLogin: false // 신규 가입자는 기본값 false
            };

            await createCollection({
                userId: user.id,
                name: "기본 컬렉션"
            });

            const sessionResult = createSession(user);

            // 회원가입 시에는 중복 로그인이 발생할 수 없지만 방어적 코딩
            if (!sessionResult.success) {
                return res.status(409).json({
                    error: sessionResult.error,
                    code: 'DUPLICATE_LOGIN_BLOCKED'
                });
            }

            const sessionId = sessionResult.sessionId;

            res.cookie(SESSION_COOKIE_NAME, sessionId, {
                httpOnly: true,
                sameSite: "strict",
                secure: IS_PRODUCTION,
                maxAge: SESSION_TTL_MS
            });

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
    router.get("/me", authMiddleware, async (req, res) => {
        try {
            const [rows] = await pool.execute(
                `SELECT id, username, encryption_salt, master_key_salt FROM users WHERE id = ?`,
                [req.user.id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const user = rows[0];
            res.json({
                id: user.id,
                username: user.username,
                encryptionSalt: user.encryption_salt,
                masterKeySalt: user.master_key_salt // E2EE 시스템 재설계
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
    router.put("/encryption-salt", authMiddleware, async (req, res) => {
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
     * 마스터 키 Salt 설정 (E2EE 시스템 재설계)
     * PUT /api/auth/master-key-salt
     */
    router.put("/master-key-salt", authMiddleware, async (req, res) => {
        const { masterKeySalt } = req.body;

        if (typeof masterKeySalt !== "string" || !masterKeySalt) {
            return res.status(400).json({ error: "마스터 키 Salt가 필요합니다." });
        }

        try {
            await pool.execute(
                `UPDATE users SET master_key_salt = ? WHERE id = ?`,
                [masterKeySalt, req.user.id]
            );

            res.json({ ok: true });
        } catch (error) {
            logError("PUT /api/auth/master-key-salt", error);
            res.status(500).json({ error: "마스터 키 Salt 업데이트 중 오류가 발생했습니다." });
        }
    });

    /**
     * 비밀번호 재확인 (보안 강화)
     * POST /api/auth/verify-password
     */
    router.post("/verify-password", authMiddleware, async (req, res) => {
        const { password } = req.body || {};

        if (typeof password !== "string") {
            return res.status(400).json({ error: "비밀번호를 입력해 주세요." });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, username, password_hash, encryption_salt, master_key_salt FROM users WHERE id = ?`,
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
                encryptionSalt: user.encryption_salt,
                masterKeySalt: user.master_key_salt // E2EE 시스템 재설계
            });
        } catch (error) {
            logError("POST /api/auth/verify-password", error);
            res.status(500).json({ error: "비밀번호 확인 중 오류가 발생했습니다." });
        }
    });

    /**
     * 보안 설정 조회
     * GET /api/auth/security-settings
     */
    router.get("/security-settings", authMiddleware, async (req, res) => {
        try {
            const [rows] = await pool.execute(
                `SELECT block_duplicate_login FROM users WHERE id = ?`,
                [req.user.id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            res.json({
                blockDuplicateLogin: rows[0].block_duplicate_login === 1
            });
        } catch (error) {
            logError("GET /api/auth/security-settings", error);
            res.status(500).json({ error: "보안 설정 조회 중 오류가 발생했습니다." });
        }
    });

    /**
     * 보안 설정 업데이트
     * PUT /api/auth/security-settings
     * body: { blockDuplicateLogin: boolean }
     */
    router.put("/security-settings", authMiddleware, async (req, res) => {
        const { blockDuplicateLogin } = req.body;

        if (typeof blockDuplicateLogin !== "boolean") {
            return res.status(400).json({ error: "올바른 설정 값이 아닙니다." });
        }

        try {
            await pool.execute(
                `UPDATE users SET block_duplicate_login = ? WHERE id = ?`,
                [blockDuplicateLogin ? 1 : 0, req.user.id]
            );

            console.log(`[보안 설정] 사용자 ID ${req.user.id} (${req.user.username}): 중복 로그인 차단 = ${blockDuplicateLogin}`);

            res.json({
                ok: true,
                blockDuplicateLogin: blockDuplicateLogin
            });
        } catch (error) {
            logError("PUT /api/auth/security-settings", error);
            res.status(500).json({ error: "보안 설정 업데이트 중 오류가 발생했습니다." });
        }
    });

    return router;
};
