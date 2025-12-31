const express = require('express');
const router = express.Router();

/**
 * TOTP (2FA) Routes
 *
 * 이 파일은 2단계 인증(TOTP) 관련 라우트를 처리합니다.
 * - TOTP 활성화 상태 확인
 * - TOTP 설정 시작 (QR 코드 생성)
 * - TOTP 설정 검증 및 활성화
 * - TOTP 비활성화
 * - 로그인 시 TOTP 검증
 * - 백업 코드로 로그인
 */

module.exports = (dependencies) => {
    const {
        pool,
        bcrypt,
        crypto,
        speakeasy,
        QRCode,
        authMiddleware,
        csrfMiddleware,
        totpLimiter,
        sessions,
        createSession,
        generateCsrfToken,
        formatDateForDb,
        SESSION_COOKIE_NAME,
        CSRF_COOKIE_NAME,
        SESSION_TTL_MS,
        IS_PRODUCTION,
        BCRYPT_SALT_ROUNDS,
        logError,
        recordLoginAttempt,
        checkCountryWhitelist
    } = dependencies;

    /**
     * TOTP 활성화 상태 확인
     * GET /api/totp/status
     */
    router.get("/status", authMiddleware, async (req, res) => {
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
     * POST /api/totp/setup
     */
    router.post("/setup", authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const username = req.user.username;

            const secret = speakeasy.generateSecret({
                name: `NTEOK (${username})`,
                length: 32
            });

            const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

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
     * POST /api/totp/verify-setup
     */
    router.post("/verify-setup", authMiddleware, csrfMiddleware, totpLimiter, async (req, res) => {
        try {
            const userId = req.user.id;
            const { token } = req.body;

            if (!token || !/^\d{6}$/.test(token)) {
                return res.status(400).json({ error: "유효한 6자리 코드를 입력하세요." });
            }

            const sessionId = req.cookies[SESSION_COOKIE_NAME];
            const session = sessions.get(sessionId);
            const secret = session?.totpTempSecret;

            if (!secret) {
                return res.status(400).json({ error: "TOTP 설정을 다시 시작하세요." });
            }

            const verified = speakeasy.totp.verify({
                secret: secret,
                encoding: 'base32',
                token: token,
                window: 2
            });

            if (!verified) {
                return res.status(400).json({ error: "잘못된 인증 코드입니다." });
            }

            const backupCodes = [];
            const now = new Date();
            const nowStr = formatDateForDb(now);

            for (let i = 0; i < 10; i++) {
                const code = crypto.randomBytes(4).toString('hex');
                backupCodes.push(code);

                const codeHash = await bcrypt.hash(code, BCRYPT_SALT_ROUNDS);
                await pool.execute(
                    "INSERT INTO backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
                    [userId, codeHash, nowStr]
                );
            }

            await pool.execute(
                "UPDATE users SET totp_secret = ?, totp_enabled = 1, updated_at = ? WHERE id = ?",
                [secret, nowStr, userId]
            );

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
     * POST /api/totp/disable
     */
    router.post("/disable", authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const { password } = req.body;

            if (!password) {
                return res.status(400).json({ error: "비밀번호를 입력하세요." });
            }

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

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                "UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = ? WHERE id = ?",
                [nowStr, userId]
            );

            await pool.execute("DELETE FROM backup_codes WHERE user_id = ?", [userId]);

            res.json({ success: true });
        } catch (error) {
            logError("POST /api/totp/disable", error);
            res.status(500).json({ error: "TOTP 비활성화 중 오류가 발생했습니다." });
        }
    });

    /**
     * 로그인 시 TOTP 검증
     * POST /api/totp/verify-login
     */
    router.post("/verify-login", totpLimiter, async (req, res) => {
        try {
            const { token, tempSessionId } = req.body;

            if (!token || !/^\d{6}$/.test(token)) {
                return res.status(400).json({ error: "유효한 6자리 코드를 입력하세요." });
            }

            if (!tempSessionId) {
                return res.status(400).json({ error: "세션 정보가 없습니다." });
            }

            const tempSession = sessions.get(tempSessionId);
            if (!tempSession || !tempSession.pendingUserId) {
                return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
            }

            const userId = tempSession.pendingUserId;

            const [rows] = await pool.execute(
                "SELECT totp_secret, username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries FROM users WHERE id = ? AND totp_enabled = 1",
                [userId]
            );

            if (rows.length === 0) {
                return res.status(404).json({ error: "TOTP가 활성화되지 않았습니다." });
            }

            const { totp_secret, username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries } = rows[0];

            const verified = speakeasy.totp.verify({
                secret: totp_secret,
                encoding: 'base32',
                token: token,
                window: 2
            });

            if (!verified) {
                // 로그인 로그 기록
                await recordLoginAttempt(pool, {
                    userId: userId,
                    username: username,
                    ipAddress: req.ip || req.connection.remoteAddress,
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: 'TOTP 인증 실패',
                    userAgent: req.headers['user-agent'] || null
                });

                return res.status(401).json({ error: "잘못된 인증 코드입니다." });
            }

            // 국가 화이트리스트 체크
            const countryCheck = checkCountryWhitelist(
                {
                    country_whitelist_enabled: country_whitelist_enabled,
                    allowed_login_countries: allowed_login_countries
                },
                req.ip || req.connection.remoteAddress
            );

            if (!countryCheck.allowed) {
                await recordLoginAttempt(pool, {
                    userId: userId,
                    username: username,
                    ipAddress: req.ip || req.connection.remoteAddress,
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: countryCheck.reason,
                    userAgent: req.headers['user-agent'] || null
                });

                console.warn(`[로그인 실패] IP: ${req.ip}, 사유: ${countryCheck.reason}`);
                sessions.delete(tempSessionId);
                return res.status(403).json({
                    error: "현재 위치에서는 로그인할 수 없습니다. 계정 보안 설정을 확인하세요."
                });
            }

            // 세션 생성
            const sessionResult = createSession({
                id: userId,
                username: username,
                blockDuplicateLogin: block_duplicate_login
            });

            // 중복 로그인 차단 모드에서 거부된 경우
            if (!sessionResult.success) {
                sessions.delete(tempSessionId);
                return res.status(409).json({
                    error: sessionResult.error,
                    code: 'DUPLICATE_LOGIN_BLOCKED'
                });
            }

            const sessionId = sessionResult.sessionId;

            // 임시 세션 삭제
            sessions.delete(tempSessionId);

            res.cookie(SESSION_COOKIE_NAME, sessionId, {
                httpOnly: true,
                secure: IS_PRODUCTION,
                sameSite: "strict",
                maxAge: SESSION_TTL_MS
            });

            const csrfToken = generateCsrfToken();
            res.cookie(CSRF_COOKIE_NAME, csrfToken, {
                httpOnly: false,
                secure: IS_PRODUCTION,
                sameSite: "strict",
                maxAge: SESSION_TTL_MS
            });

            res.json({ success: true });

            // 로그인 로그 기록 (비동기, 응답 후)
            recordLoginAttempt(pool, {
                userId: userId,
                username: username,
                ipAddress: req.ip || req.connection.remoteAddress,
                port: req.connection.remotePort || 0,
                success: true,
                failureReason: null,
                userAgent: req.headers['user-agent'] || null
            });
        } catch (error) {
            logError("POST /api/totp/verify-login", error);
            res.status(500).json({ error: "TOTP 검증 중 오류가 발생했습니다." });
        }
    });

    /**
     * 백업 코드로 로그인
     * POST /api/totp/verify-backup-code
     */
    router.post("/verify-backup-code", totpLimiter, async (req, res) => {
        try {
            const { backupCode, tempSessionId } = req.body;

            if (!backupCode) {
                return res.status(400).json({ error: "백업 코드를 입력하세요." });
            }

            if (!tempSessionId) {
                return res.status(400).json({ error: "세션 정보가 없습니다." });
            }

            const tempSession = sessions.get(tempSessionId);
            if (!tempSession || !tempSession.pendingUserId) {
                return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
            }

            const userId = tempSession.pendingUserId;

            const [rows] = await pool.execute(
                "SELECT id, code_hash FROM backup_codes WHERE user_id = ? AND used = 0",
                [userId]
            );

            if (rows.length === 0) {
                return res.status(401).json({ error: "사용 가능한 백업 코드가 없습니다." });
            }

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

            const now = new Date();
            const nowStr = formatDateForDb(now);
            await pool.execute(
                "UPDATE backup_codes SET used = 1, used_at = ? WHERE id = ?",
                [nowStr, validCodeId]
            );

            const [userRows] = await pool.execute(
                "SELECT username, block_duplicate_login FROM users WHERE id = ?",
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const { username, block_duplicate_login } = userRows[0];

            // 세션 생성
            const sessionResult = createSession({
                id: userId,
                username: username,
                blockDuplicateLogin: block_duplicate_login
            });

            // 중복 로그인 차단 모드에서 거부된 경우
            if (!sessionResult.success) {
                sessions.delete(tempSessionId);
                return res.status(409).json({
                    error: sessionResult.error,
                    code: 'DUPLICATE_LOGIN_BLOCKED'
                });
            }

            const sessionId = sessionResult.sessionId;

            // 임시 세션 삭제
            sessions.delete(tempSessionId);

            res.cookie(SESSION_COOKIE_NAME, sessionId, {
                httpOnly: true,
                secure: IS_PRODUCTION,
                sameSite: "strict",
                maxAge: SESSION_TTL_MS
            });

            const csrfToken = generateCsrfToken();
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

    return router;
};
