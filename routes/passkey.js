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
        formatDateForDb,
        SESSION_COOKIE_NAME,
        CSRF_COOKIE_NAME,
        SESSION_TTL_MS,
        IS_PRODUCTION,
        BASE_URL,
        logError
    } = dependencies;

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
                    userVerification: 'preferred'
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
                requireUserVerification: false
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
                userVerification: 'preferred'
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
                requireUserVerification: false
            });

            if (!verification.verified) {
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

            // 정식 세션 생성 (TOTP와 동일한 로직)
            const [userRows] = await pool.execute(
                "SELECT username FROM users WHERE id = ?",
                [userId]
            );

            if (userRows.length === 0) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const username = userRows[0].username;
            const sessionId = crypto.randomBytes(32).toString("hex");
            const csrfToken = crypto.randomBytes(24).toString("hex");

            sessions.set(sessionId, {
                userId: userId,
                username: username,
                csrfToken: csrfToken,
                createdAt: now.getTime(),
                lastAccessedAt: now.getTime(),
                expiresAt: now.getTime() + SESSION_TTL_MS,
                absoluteExpiry: now.getTime() + (24 * 60 * 60 * 1000)
            });

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

            res.cookie(CSRF_COOKIE_NAME, csrfToken, {
                httpOnly: false,
                secure: IS_PRODUCTION,
                sameSite: "strict",
                maxAge: SESSION_TTL_MS
            });

            res.json({ success: true });
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
