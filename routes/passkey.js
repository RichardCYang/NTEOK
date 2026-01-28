const express = require('express');
const router = express.Router();

module.exports = (dependencies) => {
    const {
        pool,
        crypto,
        authMiddleware,
        csrfMiddleware,
        passkeyLimiter,
        sessions,
        createSession,
        generateCsrfToken,
        formatDateForDb,
        SESSION_COOKIE_NAME,
        CSRF_COOKIE_NAME,
        SESSION_TTL_MS,
        IS_PRODUCTION,
        BASE_URL,
        logError,
        recordLoginAttempt,
		checkCountryWhitelist,
        getClientIpFromRequest
	} = dependencies;

    // auth.js와 동일한 방식으로 IP 추출 통일
    function getClientIp(req) {
        return (
            req.clientIp ||
            (typeof getClientIpFromRequest === 'function' ? getClientIpFromRequest(req) : null) ||
            req.ip ||
            req.connection?.remoteAddress ||
            req.socket?.remoteAddress ||
            'unknown'
        );
    }

    const {
        generateRegistrationOptions,
        verifyRegistrationResponse,
        generateAuthenticationOptions,
        verifyAuthenticationResponse,
    } = require('@simplewebauthn/server');

    // RP (Relying Party) 설정
    const rpID = new URL(BASE_URL).hostname;
    const rpName = 'NTEOK';
    const expectedOrigin = BASE_URL;

    /**
     * 패스키 활성화 상태 및 등록된 패스키 목록 조회
     * GET /api/passkey/status
     */
    router.get("/status", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;

            const [userRows] = await pool.execute(
                "SELECT passkey_enabled FROM users WHERE id = ?",
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const [passkeys] = await pool.execute(
                "SELECT id, device_name, last_used_at, created_at FROM passkeys WHERE user_id = ? ORDER BY created_at DESC",
                [userId]
            );

            res.json({
                enabled: Boolean(userRows[0].passkey_enabled),
                passkeys: passkeys.map(pk => ({
                    id: pk.id,
                    deviceName: pk.device_name || '알 수 없는 디바이스',
                    lastUsed: pk.last_used_at,
                    createdAt: pk.created_at
                }))
            });
        } catch (error) {
            logError("GET /api/passkey/status", error);
            res.status(500).json({ error: "패스키 상태 확인 중 오류가 발생했습니다." });
        }
    });

    /**
     * 패스키 등록 시작 - 챌린지 생성
     * POST /api/passkey/register/options
     */
    router.post("/register/options", authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const username = req.user.username;

            // 기존 패스키 조회 (excludeCredentials 용도)
            const [existingPasskeys] = await pool.execute(
                "SELECT credential_id FROM passkeys WHERE user_id = ?",
                [userId]
            );

            // userID를 Buffer로 변환 (SimpleWebAuthn v9+ 요구사항)
            const userIdBuffer = Buffer.from(userId.toString());

            const options = await generateRegistrationOptions({
                rpName: rpName,
                rpID: rpID,
                userID: userIdBuffer,
                userName: username,
                userDisplayName: username,
                timeout: 60000,
                attestationType: 'none',
                excludeCredentials: existingPasskeys.map(pk => ({
                    id: pk.credential_id, // 이미 base64url 문자열이므로 그대로 사용
                    type: 'public-key',
                    transports: ['usb', 'ble', 'nfc', 'internal', 'hybrid']
                })),
                authenticatorSelection: {
                    residentKey: 'preferred',
					// UV(User Verification)를 강제해서(생체/PIN 등) UP-only(터치만) 다운그레이드를 방지
					// WebAuthn 스펙상 userVerification='required'이면 UV 불가능한 인증기는 선택 단계에서 제외됨
					userVerification: 'required'
                    // authenticatorAttachment 제거: 모든 인증기 유형(플랫폼/외부 보안키/스마트폰) 허용
                }
            });

            // 챌린지를 데이터베이스에 저장
            const now = new Date();
            const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
            const sessionId = req.cookies[SESSION_COOKIE_NAME];

            await pool.execute(
                `INSERT INTO webauthn_challenges
                 (user_id, session_id, challenge, operation, created_at, expires_at)
                 VALUES (?, ?, ?, 'registration', ?, ?)`,
                [userId, sessionId, options.challenge, formatDateForDb(now), formatDateForDb(expiresAt)]
            );

            res.json(options);
        } catch (error) {
            logError("POST /api/passkey/register/options", error);
            res.status(500).json({ error: "패스키 등록 옵션 생성 중 오류가 발생했습니다." });
        }
    });

    /**
     * 패스키 등록 완료 - 검증 및 저장
     * POST /api/passkey/register/verify
     */
    router.post("/register/verify", authMiddleware, csrfMiddleware, passkeyLimiter, async (req, res) => {
        try {
            const userId = req.user.id;
            const { credential, deviceName } = req.body;
            const sessionId = req.cookies[SESSION_COOKIE_NAME];

            if (!credential) {
                return res.status(400).json({ error: "인증 정보가 없습니다." });
            }

            // 챌린지 조회 및 검증
            const [challenges] = await pool.execute(
                `SELECT challenge FROM webauthn_challenges
                 WHERE user_id = ? AND session_id = ? AND operation = 'registration'
                 AND expires_at > NOW()
                 ORDER BY created_at DESC LIMIT 1`,
                [userId, sessionId]
            );

            if (challenges.length === 0) {
                return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
            }

            const expectedChallenge = challenges[0].challenge;

            // 패스키 검증
            const verification = await verifyRegistrationResponse({
                response: credential,
                expectedChallenge: expectedChallenge,
                expectedOrigin: expectedOrigin,
                expectedRPID: rpID,
				// 서버에서 UV를 강제(= uv flag must be true). UV 없으면 passkey를 MFA급으로 볼 수 없음.
				requireUserVerification: true
            });

            if (!verification.verified || !verification.registrationInfo) {
                return res.status(400).json({ error: "패스키 등록 검증에 실패했습니다." });
            }

            // SimpleWebAuthn v10+: credential 객체에서 정보 추출
            const { credential: registeredCredential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
            const credentialID = registeredCredential.id;
            const credentialPublicKey = registeredCredential.publicKey;
            const counter = registeredCredential.counter;

            // 패스키를 데이터베이스에 저장
            const now = new Date();
            const nowStr = formatDateForDb(now);

            // credential.id는 이미 base64url 문자열이므로 직접 사용
            const credentialIdBase64 = credentialID;
            // credential.publicKey는 Uint8Array이므로 Buffer로 변환
            const publicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64');

            await pool.execute(
                `INSERT INTO passkeys
                 (user_id, credential_id, public_key, counter, device_name, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [userId, credentialIdBase64, publicKeyBase64, counter, deviceName || '알 수 없는 디바이스', nowStr]
            );

            // users 테이블 passkey_enabled 플래그 활성화
            await pool.execute(
                "UPDATE users SET passkey_enabled = 1, updated_at = ? WHERE id = ?",
                [nowStr, userId]
            );

            // 사용된 챌린지 삭제
            await pool.execute(
                "DELETE FROM webauthn_challenges WHERE user_id = ? AND session_id = ? AND operation = 'registration'",
                [userId, sessionId]
            );

            res.json({ success: true });
        } catch (error) {
            logError("POST /api/passkey/register/verify", error);
            res.status(500).json({ error: "패스키 등록 중 오류가 발생했습니다." });
        }
    });

    /**
     * 패스키 직접 로그인 시작 (아이디 입력 없이) - Discoverable Credentials
     * POST /api/passkey/login/userless/options
     */
    router.post("/login/userless/options", async (req, res) => {
        try {
            // allowCredentials를 비워두면 브라우저가 디바이스의 모든 패스키를 표시
            const options = await generateAuthenticationOptions({
                rpID: rpID,
                timeout: 60000,
				// userless(passkey discoverable) 로그인에서는 UV 강제가 특히 중요
				userVerification: 'required'
                // allowCredentials를 제공하지 않음 -> userless 인증
            });

            // 챌린지를 데이터베이스에 저장 (user_id 없이)
            const now = new Date();
            const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

            // 임시 세션 ID 생성 (패스키 로그인용)
            const tempSessionId = crypto.randomBytes(32).toString('hex');

            await pool.execute(
                `INSERT INTO webauthn_challenges
                 (session_id, challenge, operation, created_at, expires_at)
                 VALUES (?, ?, 'userless_login', ?, ?)`,
                [tempSessionId, options.challenge, formatDateForDb(now), formatDateForDb(expiresAt)]
            );

            res.json({
                ...options,
                tempSessionId: tempSessionId
            });
        } catch (error) {
            logError("POST /api/passkey/login/userless/options", error);
            res.status(500).json({ error: "패스키 로그인 옵션 생성 중 오류가 발생했습니다." });
        }
    });

    /**
     * 패스키 직접 로그인 완료 (아이디 입력 없이) - Discoverable Credentials
     * POST /api/passkey/login/userless/verify
     */
    router.post("/login/userless/verify", passkeyLimiter, async (req, res) => {
        try {
            const { credential, tempSessionId } = req.body;

            if (!credential || !tempSessionId) {
                return res.status(400).json({ error: "인증 정보가 없습니다." });
            }

            // 챌린지 조회
            const [challenges] = await pool.execute(
                `SELECT challenge FROM webauthn_challenges
                 WHERE session_id = ? AND operation = 'userless_login'
                 AND expires_at > NOW()
                 ORDER BY created_at DESC LIMIT 1`,
                [tempSessionId]
            );

            if (challenges.length === 0) {
                return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
            }

            const expectedChallenge = challenges[0].challenge;

            // credential_id로 패스키 조회 (user_id 없이)
            const credentialIdBase64 = credential.id;
            const [passkeys] = await pool.execute(
                "SELECT id, user_id, public_key, counter, transports FROM passkeys WHERE credential_id = ?",
                [credentialIdBase64]
            );

            if (passkeys.length === 0) {
                return res.status(404).json({ error: "등록되지 않은 패스키입니다." });
            }

            const passkey = passkeys[0];
            const userId = passkey.user_id;
            const publicKey = Buffer.from(passkey.public_key, 'base64');

            // 패스키 검증
            const verification = await verifyAuthenticationResponse({
                response: credential,
                expectedChallenge: expectedChallenge,
                expectedOrigin: expectedOrigin,
                expectedRPID: rpID,
                credential: {
                    id: credentialIdBase64,
                    publicKey: publicKey,
                    counter: passkey.counter,
                    transports: passkey.transports ? passkey.transports.split(',') : []
                },
				// UV flag 강제
				requireUserVerification: true
            });

            if (!verification.verified) {
                // 사용자 정보 조회하여 로그 기록
                const [userRows] = await pool.execute(
                    "SELECT username FROM users WHERE id = ?",
                    [userId]
                );
                const username = userRows.length > 0 ? userRows[0].username : '알 수 없음';

                // 로그인 로그 기록
                await recordLoginAttempt(pool, {
                    userId: userId,
                    username: username,
                    ipAddress: req.ip || req.connection.remoteAddress,
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: '패스키 userless 로그인 인증 실패',
                    userAgent: req.headers['user-agent'] || null
                });

                return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
            }

            // Counter 업데이트
            const newCounter = verification.authenticationInfo.newCounter;
            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                "UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?",
                [newCounter, nowStr, passkey.id]
            );

            // 정식 세션 생성
            const [userRows] = await pool.execute(
                "SELECT username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries FROM users WHERE id = ?",
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const { username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries } = userRows[0];

            // 국가 화이트리스트 체크
            const countryCheck = checkCountryWhitelist(
                {
                    country_whitelist_enabled: country_whitelist_enabled,
                    allowed_login_countries: allowed_login_countries
                },
                getClientIp(req)
            );

            if (!countryCheck.allowed) {
                await recordLoginAttempt(pool, {
                    userId: userId,
                    username: username,
                    ipAddress: getClientIp(req),
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: countryCheck.reason,
                    userAgent: req.headers['user-agent'] || null
                });

                console.warn(`[로그인 실패] IP: ${getClientIp(req)}, 사유: ${countryCheck.reason}`);
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
                return res.status(409).json({
                    error: sessionResult.error,
                    code: 'DUPLICATE_LOGIN_BLOCKED'
                });
            }

            const sessionId = sessionResult.sessionId;

            // 사용된 챌린지 삭제
            await pool.execute(
                "DELETE FROM webauthn_challenges WHERE session_id = ? AND operation = 'userless_login'",
                [tempSessionId]
            );

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
                ipAddress: getClientIp(req),
                port: req.connection.remotePort || 0,
                success: true,
                failureReason: null,
                userAgent: req.headers['user-agent'] || null
            });
        } catch (error) {
            logError("POST /api/passkey/login/userless/verify", error);
            res.status(500).json({ error: "패스키 로그인 중 오류가 발생했습니다." });
        }
    });

    /**
     * 패스키 직접 로그인 시작 - 챌린지 생성 (비밀번호 없이)
     * POST /api/passkey/login/options
     */
    router.post("/login/options", async (req, res) => {
        try {
            const { username } = req.body;

            if (!username) {
                return res.status(400).json({ error: "아이디를 입력해주세요." });
            }

            // 사용자 조회
            const [userRows] = await pool.execute(
                "SELECT id, passkey_enabled FROM users WHERE username = ?",
                [username]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ error: "존재하지 않는 아이디입니다." });
            }

            const user = userRows[0];

            if (!user.passkey_enabled) {
                return res.status(400).json({ error: "패스키가 등록되지 않은 계정입니다." });
            }

            // 사용자의 등록된 패스키 조회
            const [passkeys] = await pool.execute(
                "SELECT credential_id, transports FROM passkeys WHERE user_id = ?",
                [user.id]
            );

            if (passkeys.length === 0) {
                return res.status(404).json({ error: "등록된 패스키가 없습니다." });
            }

            const options = await generateAuthenticationOptions({
                rpID: rpID,
                timeout: 60000,
                allowCredentials: passkeys.map(pk => ({
                    id: pk.credential_id,
                    type: 'public-key',
                    transports: pk.transports ? pk.transports.split(',') : ['usb', 'ble', 'nfc', 'internal', 'hybrid']
                })),
				// 로컬 사용자 검증(생체/PIN) 강제
				userVerification: 'required'
            });

            // 챌린지를 데이터베이스에 저장 (user_id와 함께)
            const now = new Date();
            const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

            // 임시 세션 ID 생성 (패스키 로그인용)
            const tempSessionId = crypto.randomBytes(32).toString('hex');

            await pool.execute(
                `INSERT INTO webauthn_challenges
                 (user_id, session_id, challenge, operation, created_at, expires_at)
                 VALUES (?, ?, ?, 'passkey_login', ?, ?)`,
                [user.id, tempSessionId, options.challenge, formatDateForDb(now), formatDateForDb(expiresAt)]
            );

            res.json({
                ...options,
                tempSessionId: tempSessionId
            });
        } catch (error) {
            logError("POST /api/passkey/login/options", error);
            res.status(500).json({ error: "패스키 로그인 옵션 생성 중 오류가 발생했습니다." });
        }
    });

    /**
     * 패스키 직접 로그인 완료 - 검증 및 세션 생성 (비밀번호 없이)
     * POST /api/passkey/login/verify
     */
    router.post("/login/verify", passkeyLimiter, async (req, res) => {
        try {
            const { credential, tempSessionId } = req.body;

            if (!credential || !tempSessionId) {
                return res.status(400).json({ error: "인증 정보가 없습니다." });
            }

            // 챌린지 조회
            const [challenges] = await pool.execute(
                `SELECT user_id, challenge FROM webauthn_challenges
                 WHERE session_id = ? AND operation = 'passkey_login'
                 AND expires_at > NOW()
                 ORDER BY created_at DESC LIMIT 1`,
                [tempSessionId]
            );

            if (challenges.length === 0) {
                return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
            }

            const expectedChallenge = challenges[0].challenge;
            const userId = challenges[0].user_id;

            // credential_id로 패스키 조회
            const credentialIdBase64 = credential.id;
            const [passkeys] = await pool.execute(
                "SELECT id, public_key, counter, transports FROM passkeys WHERE credential_id = ? AND user_id = ?",
                [credentialIdBase64, userId]
            );

            if (passkeys.length === 0) {
                return res.status(404).json({ error: "등록되지 않은 패스키입니다." });
            }

            const passkey = passkeys[0];
            const publicKey = Buffer.from(passkey.public_key, 'base64');

            // 패스키 검증
            const verification = await verifyAuthenticationResponse({
                response: credential,
                expectedChallenge: expectedChallenge,
                expectedOrigin: expectedOrigin,
                expectedRPID: rpID,
                credential: {
                    id: credentialIdBase64,
                    publicKey: publicKey,
                    counter: passkey.counter,
                    transports: passkey.transports ? passkey.transports.split(',') : []
                },
                // uv flag 강제
                requireUserVerification: true
            });

            if (!verification.verified) {
                // 사용자 정보 조회하여 로그 기록
                const [userRows] = await pool.execute(
                    "SELECT username FROM users WHERE id = ?",
                    [userId]
                );
                const username = userRows.length > 0 ? userRows[0].username : '알 수 없음';

                // 로그인 로그 기록
                await recordLoginAttempt(pool, {
                    userId: userId,
                    username: username,
                    ipAddress: req.ip || req.connection.remoteAddress,
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: '패스키 로그인 인증 실패',
                    userAgent: req.headers['user-agent'] || null
                });

                return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
            }

            // Counter 업데이트
            const newCounter = verification.authenticationInfo.newCounter;
            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                "UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?",
                [newCounter, nowStr, passkey.id]
            );

            // 정식 세션 생성
            const [userRows] = await pool.execute(
                "SELECT username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries FROM users WHERE id = ?",
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const { username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries } = userRows[0];

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
                return res.status(409).json({
                    error: sessionResult.error,
                    code: 'DUPLICATE_LOGIN_BLOCKED'
                });
            }

            const sessionId = sessionResult.sessionId;

            // 사용된 챌린지 삭제
            await pool.execute(
                "DELETE FROM webauthn_challenges WHERE user_id = ? AND session_id = ? AND operation = 'passkey_login'",
                [userId, tempSessionId]
            );

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
            logError("POST /api/passkey/login/verify", error);
            res.status(500).json({ error: "패스키 로그인 중 오류가 발생했습니다." });
        }
    });

    /**
     * 패스키 로그인 인증 시작 - 챌린지 생성
     * POST /api/passkey/authenticate/options
     */
    router.post("/authenticate/options", async (req, res) => {
        try {
            const { tempSessionId } = req.body;

            if (!tempSessionId) {
                return res.status(400).json({ error: "세션 정보가 없습니다." });
            }

            const tempSession = sessions.get(tempSessionId);
            if (!tempSession || !tempSession.pendingUserId) {
                return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
            }

            const userId = tempSession.pendingUserId;

            // 사용자의 등록된 패스키 조회
            const [passkeys] = await pool.execute(
                "SELECT credential_id, transports FROM passkeys WHERE user_id = ?",
                [userId]
            );

            if (passkeys.length === 0) {
                return res.status(404).json({ error: "등록된 패스키가 없습니다." });
            }

            const options = await generateAuthenticationOptions({
                rpID: rpID,
                timeout: 60000,
                allowCredentials: passkeys.map(pk => ({
                    id: pk.credential_id, // 이미 base64url 문자열이므로 그대로 사용
                    type: 'public-key',
                    transports: pk.transports ? pk.transports.split(',') : ['usb', 'ble', 'nfc', 'internal', 'hybrid']
                })),
				// 중요한 작업 재인증(reauth)도 UV 강제 권장
				userVerification: 'required'
            });

            // 챌린지를 데이터베이스에 저장
            const now = new Date();
            const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);

            await pool.execute(
                `INSERT INTO webauthn_challenges
                 (user_id, session_id, challenge, operation, created_at, expires_at)
                 VALUES (?, ?, ?, 'authentication', ?, ?)`,
                [userId, tempSessionId, options.challenge, formatDateForDb(now), formatDateForDb(expiresAt)]
            );

            res.json(options);
        } catch (error) {
            logError("POST /api/passkey/authenticate/options", error);
            res.status(500).json({ error: "패스키 인증 옵션 생성 중 오류가 발생했습니다." });
        }
    });

    /**
     * 패스키 로그인 인증 완료 - 검증 및 세션 생성
     * POST /api/passkey/authenticate/verify
     */
    router.post("/authenticate/verify", passkeyLimiter, async (req, res) => {
        try {
            const { credential, tempSessionId } = req.body;

            if (!credential || !tempSessionId) {
                return res.status(400).json({ error: "인증 정보가 없습니다." });
            }

            const tempSession = sessions.get(tempSessionId);
            if (!tempSession || !tempSession.pendingUserId) {
                return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
            }

            const userId = tempSession.pendingUserId;

            // 챌린지 조회
            const [challenges] = await pool.execute(
                `SELECT challenge FROM webauthn_challenges
                 WHERE user_id = ? AND session_id = ? AND operation = 'authentication'
                 AND expires_at > NOW()
                 ORDER BY created_at DESC LIMIT 1`,
                [userId, tempSessionId]
            );

            if (challenges.length === 0) {
                return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
            }

            const expectedChallenge = challenges[0].challenge;

            // credential_id로 패스키 조회
            // credential.id는 이미 base64url 문자열이므로 그대로 사용
            const credentialIdBase64 = credential.id;
            const [passkeys] = await pool.execute(
                "SELECT id, public_key, counter, transports FROM passkeys WHERE credential_id = ? AND user_id = ?",
                [credentialIdBase64, userId]
            );

            if (passkeys.length === 0) {
                return res.status(404).json({ error: "등록되지 않은 패스키입니다." });
            }

            const passkey = passkeys[0];
            const publicKey = Buffer.from(passkey.public_key, 'base64');

            // 패스키 검증 (SimpleWebAuthn v10)
            const verification = await verifyAuthenticationResponse({
                response: credential,
                expectedChallenge: expectedChallenge,
                expectedOrigin: expectedOrigin,
                expectedRPID: rpID,
                credential: {
                    id: credentialIdBase64,
                    publicKey: publicKey,
                    counter: passkey.counter,
                    transports: passkey.transports ? passkey.transports.split(',') : []
                },
                // UV flag 강제
                requireUserVerification: true
            });

            if (!verification.verified) {
                // 사용자 정보 조회하여 로그 기록
                const [userRows] = await pool.execute(
                    "SELECT username FROM users WHERE id = ?",
                    [userId]
                );
                const username = userRows.length > 0 ? userRows[0].username : '알 수 없음';

                // 로그인 로그 기록
                await recordLoginAttempt(pool, {
                    userId: userId,
                    username: username,
                    ipAddress: req.ip || req.connection.remoteAddress,
                    port: req.connection.remotePort || 0,
                    success: false,
                    failureReason: '패스키 인증 실패',
                    userAgent: req.headers['user-agent'] || null
                });

                return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
            }

            // Counter 업데이트 (재생 공격 방지)
            const newCounter = verification.authenticationInfo.newCounter;
            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                "UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?",
                [newCounter, nowStr, passkey.id]
            );

            // 정식 세션 생성
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

            // 사용된 챌린지 삭제
            await pool.execute(
                "DELETE FROM webauthn_challenges WHERE user_id = ? AND session_id = ? AND operation = 'authentication'",
                [userId, tempSessionId]
            );

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
            logError("POST /api/passkey/authenticate/verify", error);
            res.status(500).json({ error: "패스키 인증 중 오류가 발생했습니다." });
        }
    });

    /**
     * 특정 패스키 삭제
     * DELETE /api/passkey/:id
     */
    router.delete("/:id", authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const passkeyId = parseInt(req.params.id);

            if (isNaN(passkeyId)) {
                return res.status(400).json({ error: "잘못된 패스키 ID입니다." });
            }

            // 본인의 패스키인지 확인
            const [passkeys] = await pool.execute(
                "SELECT id FROM passkeys WHERE id = ? AND user_id = ?",
                [passkeyId, userId]
            );

            if (passkeys.length === 0) {
                return res.status(404).json({ error: "패스키를 찾을 수 없습니다." });
            }

            await pool.execute("DELETE FROM passkeys WHERE id = ?", [passkeyId]);

            // 남은 패스키가 없으면 passkey_enabled 플래그 비활성화
            const [remainingPasskeys] = await pool.execute(
                "SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?",
                [userId]
            );

            if (remainingPasskeys[0].count === 0) {
                const nowStr = formatDateForDb(new Date());
                await pool.execute(
                    "UPDATE users SET passkey_enabled = 0, updated_at = ? WHERE id = ?",
                    [nowStr, userId]
                );
            }

            res.json({ success: true });
        } catch (error) {
            logError("DELETE /api/passkey/:id", error);
            res.status(500).json({ error: "패스키 삭제 중 오류가 발생했습니다." });
        }
    });

    return router;
};
