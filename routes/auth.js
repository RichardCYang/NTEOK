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
        BASE_URL,
        BCRYPT_SALT_ROUNDS,
        createCollection,
        authMiddleware,
        authLimiter,
        recordLoginAttempt,
        maskIPAddress,
        checkCountryWhitelist
	} = dependencies;

    /**
    * Login CSRF 방지: 로그인/회원가입은 CSRF 토큰이 없더라도 호출되기 쉬우므로,
    * Origin/Referer + Sec-Fetch-Site 기반으로 동일 출처 요청만 허용합니다.
    *
    * 참고: BASE_URL은 server.js에서 주입됩니다.
    */
    function requireSameOriginForAuth(req, res, next) {
        try {
            const allowedOrigins = new Set(
                String(process.env.ALLOWED_ORIGINS || BASE_URL || "")
                    .split(",")
                    .map(s => s.trim())
                    .filter(Boolean)
                    .map(u => new URL(u).origin)
            );

            // Sec-Fetch-Site: modern browsers (recommended hardening)
            const sfs = req.headers["sec-fetch-site"];
            if (typeof sfs === "string" && sfs && sfs !== "same-origin" && sfs !== "same-site") {
                return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
            }

            const origin = req.headers.origin;
            const referer = req.headers.referer;

            let reqOrigin = null;
            if (typeof origin === "string" && origin) {
                reqOrigin = origin;
            } else if (typeof referer === "string" && referer) {
                reqOrigin = new URL(referer).origin;
            }

            // Origin/Referer가 없으면 차단 (Login CSRF 방지)
            if (!reqOrigin)
                return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });

            if (!allowedOrigins.has(reqOrigin))
                return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });

            return next();
        } catch (e) {
            return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
        }
    }

    /**
     * 로그인
     * POST /api/auth/login
     * body: { username: string, password: string }
     */
    router.post("/login", authLimiter, requireSameOriginForAuth, async (req, res) => {
        const { username, password } = req.body || {};

        if (typeof username !== "string" || typeof password !== "string") {
            return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
        }

        const trimmedUsername = username.trim();

        try {
            const [rows] = await pool.execute(
                `
                SELECT id, username, password_hash, totp_enabled, passkey_enabled, block_duplicate_login,
                       country_whitelist_enabled, allowed_login_countries
                FROM users
                WHERE username = ?
                `,
                [trimmedUsername]
            );

            if (!rows.length) {
                // 로그인 로그 기록
                await recordLoginAttempt(pool, {
                    userId: null,
                    username: trimmedUsername,
                    ipAddress: req.ip || req.connection.remoteAddress,
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: '존재하지 않는 사용자',
                    userAgent: req.headers['user-agent'] || null
                });

                // 보안: 사용자 존재 여부를 노출하지 않도록 통일된 메시지 사용
                console.warn(`[로그인 실패] IP: ${req.ip}, 사유: 인증 실패`);
                return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
            }

            const user = rows[0];

            const ok = await bcrypt.compare(password, user.password_hash);
            if (!ok) {
                // 로그인 로그 기록
                await recordLoginAttempt(pool, {
                    userId: user.id,
                    username: user.username,
                    ipAddress: req.ip || req.connection.remoteAddress,
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: '비밀번호 불일치',
                    userAgent: req.headers['user-agent'] || null
                });

                // 보안: 사용자 존재 여부를 노출하지 않도록 통일된 메시지 사용
                console.warn(`[로그인 실패] IP: ${req.ip}, 사유: 인증 실패`);
                return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
            }

            // 국가 화이트리스트 체크
            const countryCheck = checkCountryWhitelist(
                {
                    country_whitelist_enabled: user.country_whitelist_enabled,
                    allowed_login_countries: user.allowed_login_countries
                },
                req.ip || req.connection.remoteAddress
            );

            if (!countryCheck.allowed) {
                await recordLoginAttempt(pool, {
                    userId: user.id,
                    username: user.username,
                    ipAddress: req.ip || req.connection.remoteAddress,
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: countryCheck.reason,
                    userAgent: req.headers['user-agent'] || null
                });

                console.warn(`[로그인 실패] IP: ${req.ip}, 사유: ${countryCheck.reason}`);
                return res.status(403).json({
                    error: "현재 위치에서는 로그인할 수 없습니다. 계정 보안 설정을 확인하세요."
                });
            }

            // 2FA(TOTP 또는 패스키) 활성화 확인
            if (user.totp_enabled || user.passkey_enabled) {
                // 임시 세션 생성 (2FA 검증 대기)
                const tempSessionId = crypto.randomBytes(32).toString("hex");
                const now = new Date();

                sessions.set(tempSessionId, {
                	type: "2fa",
                    pendingUserId: user.id,
                    createdAt: now.getTime(),
                    expiresAt: 10 * 60 * 1000, // 2단계 인증을 위한 임시 세션 만료 시간 : 10분
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

            // 로그인 로그 기록 (비동기, 응답 후)
            recordLoginAttempt(pool, {
                userId: user.id,
                username: user.username,
                ipAddress: req.ip || req.connection.remoteAddress,
                port: req.connection.remotePort || 0,
                success: true,
                failureReason: null,
                userAgent: req.headers['user-agent'] || null
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
                // 보안: 민감 정보 마스킹 (사용자명 일부만 표시)
                const maskedUsername = req.user.username.substring(0, 2) + '***';
                console.warn(`[계정 삭제 실패] 사용자: ${maskedUsername}, IP: ${req.ip}, 사유: 비밀번호 불일치`);
                return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });
            }

            await pool.execute(`DELETE FROM users WHERE id = ?`, [req.user.id]);

            // 보안: 민감 정보 마스킹 (사용자명 일부만 표시)
            const maskedUsername = req.user.username.substring(0, 2) + '***';
            console.log(`[계정 삭제 완료] 사용자 ID: ${req.user.id}, 사용자명: ${maskedUsername}`);

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
    router.post("/register", authLimiter, requireSameOriginForAuth, async (req, res) => {
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
                `SELECT id, username FROM users WHERE id = ?`,
                [req.user.id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const user = rows[0];
            res.json({
                id: user.id,
                username: user.username
            });
        } catch (error) {
            logError("GET /api/auth/me", error);
            res.status(500).json({ error: "사용자 정보 조회 중 오류가 발생했습니다." });
        }
    });

    // ==================== 마스터 키 시스템 제거됨 ====================
    // encryption-salt, master-key-salt, verify-password 엔드포인트 제거됨 (선택적 암호화 시스템으로 변경)

    /**
     * 보안 설정 조회
     * GET /api/auth/security-settings
     */
    router.get("/security-settings", authMiddleware, async (req, res) => {
        try {
            const [rows] = await pool.execute(
                `SELECT block_duplicate_login, country_whitelist_enabled, allowed_login_countries FROM users WHERE id = ?`,
                [req.user.id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            let allowedCountries = [];
            if (rows[0].allowed_login_countries) {
                try {
                    allowedCountries = JSON.parse(rows[0].allowed_login_countries);
                } catch (e) {
                    console.error('화이트리스트 파싱 오류:', e);
                }
            }

            res.json({
                blockDuplicateLogin: rows[0].block_duplicate_login === 1,
                countryWhitelistEnabled: rows[0].country_whitelist_enabled === 1,
                allowedLoginCountries: allowedCountries
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
        const { blockDuplicateLogin, countryWhitelistEnabled, allowedLoginCountries } = req.body;

        // 유효성 검증
        if (blockDuplicateLogin !== undefined && typeof blockDuplicateLogin !== "boolean") {
            return res.status(400).json({ error: "올바른 설정 값이 아닙니다." });
        }

        if (countryWhitelistEnabled !== undefined && typeof countryWhitelistEnabled !== "boolean") {
            return res.status(400).json({ error: "올바른 설정 값이 아닙니다." });
        }

        if (allowedLoginCountries !== undefined) {
            if (!Array.isArray(allowedLoginCountries)) {
                return res.status(400).json({ error: "허용 국가 목록은 배열이어야 합니다." });
            }

            // 국가 코드 형식 검증 (ISO 3166-1 alpha-2: 2자리 대문자)
            const invalidCountry = allowedLoginCountries.find(
                code => typeof code !== 'string' || !/^[A-Z]{2}$/.test(code)
            );
            if (invalidCountry) {
                return res.status(400).json({ error: "유효하지 않은 국가 코드가 포함되어 있습니다." });
            }
        }

        try {
            // 동적 UPDATE 쿼리 생성
            const updates = [];
            const values = [];

            if (blockDuplicateLogin !== undefined) {
                updates.push('block_duplicate_login = ?');
                values.push(blockDuplicateLogin ? 1 : 0);
            }

            if (countryWhitelistEnabled !== undefined) {
                updates.push('country_whitelist_enabled = ?');
                values.push(countryWhitelistEnabled ? 1 : 0);
            }

            if (allowedLoginCountries !== undefined) {
                updates.push('allowed_login_countries = ?');
                values.push(JSON.stringify(allowedLoginCountries));
            }

            if (updates.length === 0) {
                return res.status(400).json({ error: "업데이트할 설정이 없습니다." });
            }

            values.push(req.user.id);

            await pool.execute(
                `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
                values
            );

            // 보안: 사용자명 일부만 표시
            const maskedUsername = req.user.username.substring(0, 2) + '***';
            console.log(`[보안 설정] 사용자 ID ${req.user.id} (${maskedUsername}): 설정 업데이트 완료`);

            res.json({ ok: true });
        } catch (error) {
            logError("PUT /api/auth/security-settings", error);
            res.status(500).json({ error: "보안 설정 업데이트 중 오류가 발생했습니다." });
        }
    });

    /**
     * 로그인 로그 조회
     * GET /api/auth/login-logs
     * query: { limit?: number, offset?: number }
     */
    router.get("/login-logs", authMiddleware, async (req, res) => {
        try {
            const limit = Math.min(parseInt(req.query.limit) || 100, 500);
            const offset = parseInt(req.query.offset) || 0;

            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            const thirtyDaysAgoStr = formatDateForDb(thirtyDaysAgo);

            const [rows] = await pool.execute(
                `SELECT id, ip_address, port, country, region, city, timezone,
                        user_agent, success, failure_reason, created_at
                 FROM login_logs
                 WHERE user_id = ? AND created_at >= ?
                 ORDER BY created_at DESC
                 LIMIT ? OFFSET ?`,
                [req.user.id, thirtyDaysAgoStr, limit, offset]
            );

            const [countRows] = await pool.execute(
                `SELECT COUNT(*) as total FROM login_logs
                 WHERE user_id = ? AND created_at >= ?`,
                [req.user.id, thirtyDaysAgoStr]
            );

            const logs = rows.map(log => ({
                ...log,
                ip_address: maskIPAddress(log.ip_address),
                success: log.success === 1
            }));

            res.json({
                logs: logs,
                total: countRows[0].total,
                limit: limit,
                offset: offset
            });
        } catch (error) {
            logError("GET /api/auth/login-logs", error);
            res.status(500).json({ error: "로그인 로그 조회 중 오류가 발생했습니다." });
        }
    });

    /**
     * 로그인 로그 통계 조회
     * GET /api/auth/login-logs/stats
     */
    router.get("/login-logs/stats", authMiddleware, async (req, res) => {
        try {
            const thirtyDaysAgo = new Date();
            thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
            const thirtyDaysAgoStr = formatDateForDb(thirtyDaysAgo);

            const [successRows] = await pool.execute(
                `SELECT success, COUNT(*) as count FROM login_logs
                 WHERE user_id = ? AND created_at >= ?
                 GROUP BY success`,
                [req.user.id, thirtyDaysAgoStr]
            );

            const stats = { successCount: 0, failureCount: 0, totalCount: 0 };
            successRows.forEach(row => {
                if (row.success === 1) stats.successCount = row.count;
                else stats.failureCount = row.count;
                stats.totalCount += row.count;
            });

            const [ipRows] = await pool.execute(
                `SELECT COUNT(DISTINCT ip_address) as unique_ips FROM login_logs
                 WHERE user_id = ? AND created_at >= ?`,
                [req.user.id, thirtyDaysAgoStr]
            );
            stats.uniqueIPs = ipRows[0].unique_ips;

            const [lastLoginRows] = await pool.execute(
                `SELECT created_at FROM login_logs
                 WHERE user_id = ? AND success = 1 AND created_at >= ?
                 ORDER BY created_at DESC LIMIT 1`,
                [req.user.id, thirtyDaysAgoStr]
            );
            stats.lastLoginAt = lastLoginRows.length > 0 ? lastLoginRows[0].created_at : null;

            res.json(stats);
        } catch (error) {
            logError("GET /api/auth/login-logs/stats", error);
            res.status(500).json({ error: "로그인 로그 통계 조회 중 오류가 발생했습니다." });
        }
    });

    /**
     * 국가 목록 조회
     * GET /api/auth/countries
     */
    router.get("/countries", authMiddleware, (req, res) => {
        const countries = [
            { code: 'KR', name: '대한민국' },
            { code: 'US', name: '미국' },
            { code: 'JP', name: '일본' },
            { code: 'CN', name: '중국' },
            { code: 'GB', name: '영국' },
            { code: 'DE', name: '독일' },
            { code: 'FR', name: '프랑스' },
            { code: 'CA', name: '캐나다' },
            { code: 'AU', name: '호주' },
            { code: 'SG', name: '싱가포르' },
            { code: 'HK', name: '홍콩' },
            { code: 'TW', name: '대만' },
            { code: 'IN', name: '인도' },
            { code: 'RU', name: '러시아' },
            { code: 'BR', name: '브라질' },
            { code: 'MX', name: '멕시코' },
            { code: 'IT', name: '이탈리아' },
            { code: 'ES', name: '스페인' },
            { code: 'NL', name: '네덜란드' },
            { code: 'SE', name: '스웨덴' },
            { code: 'CH', name: '스위스' },
            { code: 'PL', name: '폴란드' },
            { code: 'BE', name: '벨기에' },
            { code: 'AT', name: '오스트리아' },
            { code: 'NO', name: '노르웨이' },
            { code: 'DK', name: '덴마크' },
            { code: 'FI', name: '핀란드' },
            { code: 'IE', name: '아일랜드' },
            { code: 'NZ', name: '뉴질랜드' },
            { code: 'TH', name: '태국' },
            { code: 'VN', name: '베트남' },
            { code: 'MY', name: '말레이시아' },
            { code: 'PH', name: '필리핀' },
            { code: 'ID', name: '인도네시아' }
        ];

        res.json({ countries });
    });

    return router;
};
