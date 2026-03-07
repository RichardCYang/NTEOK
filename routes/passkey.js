const express = require('express');
const router = express.Router();

const DEVICE_NAME_MAX_LEN = 80;

function sanitizeDeviceName(input) {
	if (typeof input !== 'string') return '알 수 없는 디바이스';
	const cleaned = input
		.normalize('NFKC')
		.replace(/[\u0000-\u001F\u007F]/g, '')
		.replace(/[<>&"'`]/g, '')
		.trim();
	return (cleaned || '알 수 없는 디바이스').slice(0, DEVICE_NAME_MAX_LEN);
}

module.exports = (dependencies) => {
	const {
		pool,
		crypto,
		authMiddleware,
		csrfMiddleware,
		passkeyLimiter,
		createSession,
		generateCsrfToken,
		generateCsrfTokenForSession,
		verifyPreAuthCsrfToken,
		PREAUTH_CSRF_COOKIE_NAME,
		formatDateForDb,
		SESSION_COOKIE_NAME,
		CSRF_COOKIE_NAME,
		SESSION_TTL_MS,
		IS_PRODUCTION,
		COOKIE_SECURE,
		BASE_URL,
		logError,
		recordLoginAttempt,
		checkCountryWhitelist,
		getClientIpFromRequest,
		getSession,
		saveSession,
		revokeSession,
		requireRecentReauth
	} = dependencies;

	const TWO_FA_COOKIE_NAME = COOKIE_SECURE ? '__Host-nteok_2fa' : 'nteok_2fa';
	const TWO_FA_COOKIE_OPTS = {
		httpOnly: true,
		sameSite: 'strict',
		secure: COOKIE_SECURE,
		path: '/'
	};

	function get2faCookie(req) {
		return req.cookies?.[TWO_FA_COOKIE_NAME] || '';
	}

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

	function requireSameOriginForAuth(req, res, next) {
		try {
			const allowedOrigins = new Set(
				String(process.env.ALLOWED_ORIGINS || BASE_URL || "")
					.split(",")
					.map(s => s.trim())
					.filter(Boolean)
					.map(u => new URL(u).origin)
			);
			const sfs = req.headers["sec-fetch-site"];
			if (typeof sfs === "string" && sfs && sfs !== "same-origin" && sfs !== "same-site") return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
			const origin = req.headers.origin;
			const referer = req.headers.referer;
			let reqOrigin = null;
			if (typeof origin === "string" && origin) reqOrigin = origin;
			else if (typeof referer === "string" && referer) reqOrigin = new URL(referer).origin;
			if (!reqOrigin || !allowedOrigins.has(reqOrigin)) return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
			return next();
		} catch (e) {
			return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
		}
	}

	async function getValid2FATempSession(req, tempSessionId) {
		const s = await getSession(tempSessionId);
		if (!s || s.type !== "2fa" || !s.pendingUserId) return null;
		const now = Date.now();
		if (s.expiresAt && s.expiresAt <= now) {
			await revokeSession(tempSessionId, "2fa-expired");
			return null;
		}
		const ipNow = getClientIp(req);
		if (s.ipKey && ipNow && s.ipKey !== ipNow) {
			await revokeSession(tempSessionId, "2fa-ip-mismatch");
			return null;
		}
		const uaNow = req.headers["user-agent"] || "";
		const uaHashNow = crypto.createHash("sha256").update(uaNow).digest("hex");
		if (s.uaHash && s.uaHash !== uaHashNow) {
			await revokeSession(tempSessionId, "2fa-ua-mismatch");
			return null;
		}
		s.lastAccessedAt = now;
		await saveSession(tempSessionId, s, 10 * 60 * 1000);
		return s;
	}

	const {
		generateRegistrationOptions,
		verifyRegistrationResponse,
		generateAuthenticationOptions,
		verifyAuthenticationResponse,
	} = require('@simplewebauthn/server');

	const rpID = new URL(BASE_URL).hostname;
	const rpName = 'NTEOK';
	const expectedOrigin = BASE_URL;

	router.get("/status", authMiddleware, async (req, res) => {
		try {
			const userId = req.user.id;
			const [userRows] = await pool.execute("SELECT passkey_enabled FROM users WHERE id = ?", [userId]);
			if (userRows.length === 0) return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
			const [passkeys] = await pool.execute("SELECT id, device_name, last_used_at, created_at FROM passkeys WHERE user_id = ? ORDER BY created_at DESC", [userId]);
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

	router.post("/register/options", authMiddleware, csrfMiddleware, requireRecentReauth(5 * 60 * 1000), async (req, res) => {
		try {
			const userId = req.user.id;
			const username = req.user.username;
			const [existingPasskeys] = await pool.execute("SELECT credential_id FROM passkeys WHERE user_id = ?", [userId]);
			const userIdBuffer = Buffer.from(userId.toString());
			const options = await generateRegistrationOptions({
				rpName: rpName,
				rpID: rpID,
				userID: userIdBuffer,
				userName: username,
				userDisplayName: username,
				timeout: 60000,
				attestationType: 'none',
				excludeCredentials: existingPasskeys.map(pk => ({ id: pk.credential_id, type: 'public-key', transports: ['usb', 'ble', 'nfc', 'internal', 'hybrid'] })),
				authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }
			});
			const now = new Date();
			const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
			const sessionId = req.cookies[SESSION_COOKIE_NAME];
			await pool.execute(`INSERT INTO webauthn_challenges (user_id, session_id, challenge, operation, created_at, expires_at) VALUES (?, ?, ?, 'registration', ?, ?)`, [userId, sessionId, options.challenge, formatDateForDb(now), formatDateForDb(expiresAt)]);
			res.json(options);
		} catch (error) {
			logError("POST /api/passkey/register/options", error);
			res.status(500).json({ error: "패스키 등록 옵션 생성 중 오류가 발생했습니다." });
		}
	});

	router.post("/register/verify", authMiddleware, csrfMiddleware, requireRecentReauth(5 * 60 * 1000), passkeyLimiter, async (req, res) => {
		try {
			const userId = req.user.id;
			const { credential } = req.body;
			const deviceName = sanitizeDeviceName(req.body?.deviceName);
			const sessionId = req.cookies[SESSION_COOKIE_NAME];
			if (!credential) return res.status(400).json({ error: "인증 정보가 없습니다." });
			const [challenges] = await pool.execute(`SELECT challenge FROM webauthn_challenges WHERE user_id = ? AND session_id = ? AND operation = 'registration' AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`, [userId, sessionId]);
			if (challenges.length === 0) return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
			const expectedChallenge = challenges[0].challenge;
			const verification = await verifyRegistrationResponse({ response: credential, expectedChallenge: expectedChallenge, expectedOrigin: expectedOrigin, expectedRPID: rpID, requireUserVerification: true });
			if (!verification.verified || !verification.registrationInfo) return res.status(400).json({ error: "패스키 등록 검증에 실패했습니다." });
			const { credential: registeredCredential, counter } = verification.registrationInfo;
			const credentialID = registeredCredential.id;
			const credentialPublicKey = registeredCredential.publicKey;
			const now = new Date();
			const nowStr = formatDateForDb(now);
			const credentialIdBase64 = credentialID;
			const publicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64');
			await pool.execute(`INSERT INTO passkeys (user_id, credential_id, public_key, counter, device_name, created_at) VALUES (?, ?, ?, ?, ?, ?)`, [userId, credentialIdBase64, publicKeyBase64, counter, deviceName, nowStr]);
			await pool.execute("UPDATE users SET passkey_enabled = 1, updated_at = ? WHERE id = ?", [nowStr, userId]);
			await pool.execute("DELETE FROM webauthn_challenges WHERE user_id = ? AND session_id = ? AND operation = 'registration'", [userId, sessionId]);
			res.json({ success: true });
		} catch (error) {
			logError("POST /api/passkey/register/verify", error);
			res.status(500).json({ error: "패스키 등록 중 오류가 발생했습니다." });
		}
	});

	router.post("/login/userless/options", passkeyLimiter, requireSameOriginForAuth, async (req, res) => {
		try {
			const options = await generateAuthenticationOptions({ rpID: rpID, timeout: 60000, userVerification: 'required' });
			const now = new Date();
			const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
			const tempSessionId = crypto.randomBytes(32).toString('hex');
			await pool.execute(`INSERT INTO webauthn_challenges (session_id, challenge, operation, created_at, expires_at) VALUES (?, ?, 'userless_login', ?, ?)`, [tempSessionId, options.challenge, formatDateForDb(now), formatDateForDb(expiresAt)]);
			res.cookie(TWO_FA_COOKIE_NAME, tempSessionId, { ...TWO_FA_COOKIE_OPTS, maxAge: 5 * 60 * 1000 });
			res.json({ ...options });
		} catch (error) {
			logError("POST /api/passkey/login/userless/options", error);
			res.status(500).json({ error: "패스키 로그인 옵션 생성 중 오류가 발생했습니다." });
		}
	});

	router.post("/login/userless/verify", passkeyLimiter, requireSameOriginForAuth, async (req, res) => {
		if (!verifyPreAuthCsrfToken(req)) return res.status(403).json({ error: "유효하지 않은 요청입니다." });
		try {
			const { credential } = req.body;
			const tempSessionId = get2faCookie(req);
			if (typeof tempSessionId !== 'string' || !/^[a-f0-9]{64}$/i.test(tempSessionId)) return res.status(400).json({ error: "세션 정보가 올바르지 않습니다." });
			if (typeof credential !== 'object' || credential === null || typeof credential.id !== 'string') return res.status(400).json({ error: "credential 형식이 올바르지 않습니다." });
			if (credential.id.length < 10 || credential.id.length > 512 || !/^[A-Za-z0-9_-]+$/.test(credential.id)) return res.status(400).json({ error: "credential.id 형식이 올바르지 않습니다." });
			const [challenges] = await pool.execute(`SELECT challenge FROM webauthn_challenges WHERE session_id = ? AND operation = 'userless_login' AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`, [tempSessionId]);
			if (challenges.length === 0) return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
			const expectedChallenge = challenges[0].challenge;
			const credentialIdBase64 = credential.id;
			const [passkeys] = await pool.execute("SELECT id, user_id, public_key, counter, transports FROM passkeys WHERE credential_id = ?", [credentialIdBase64]);
			if (passkeys.length === 0) return res.status(404).json({ error: "등록되지 않은 패스키입니다." });
			const passkey = passkeys[0];
			const userId = passkey.user_id;
			const publicKey = Buffer.from(passkey.public_key, 'base64');
			const verification = await verifyAuthenticationResponse({ response: credential, expectedChallenge: expectedChallenge, expectedOrigin: expectedOrigin, expectedRPID: rpID, credential: { id: credentialIdBase64, publicKey: publicKey, counter: passkey.counter, transports: passkey.transports ? passkey.transports.split(',') : [] }, requireUserVerification: true });
			if (!verification.verified) {
				const [userRows] = await pool.execute("SELECT username FROM users WHERE id = ?", [userId]);
				const username = userRows.length > 0 ? userRows[0].username : '알 수 없음';
				await recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: false, failureReason: '패스키 userless 로그인 인증 실패', userAgent: req.headers['user-agent'] || null });
				return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
			}
			const newCounter = verification.authenticationInfo.newCounter;
			const now = new Date();
			const nowStr = formatDateForDb(now);
			await pool.execute("UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?", [newCounter, nowStr, passkey.id]);
			const [userRows] = await pool.execute("SELECT username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries FROM users WHERE id = ?", [userId]);
			if (userRows.length === 0) return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
			const { username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries } = userRows[0];
			const countryCheck = checkCountryWhitelist({ country_whitelist_enabled: country_whitelist_enabled, allowed_login_countries: allowed_login_countries }, getClientIp(req));
			if (!countryCheck.allowed) {
				await recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: false, failureReason: countryCheck.reason, userAgent: req.headers['user-agent'] || null });
				return res.status(403).json({ error: "현재 위치에서는 로그인할 수 없습니다." });
			}
			const sessionResult = await createSession({ id: userId, username: username, blockDuplicateLogin: block_duplicate_login }, { userAgent: req.headers["user-agent"] || "" });
			if (!sessionResult.success) return res.status(409).json({ error: sessionResult.error, code: 'DUPLICATE_LOGIN_BLOCKED' });
			const sessionId = sessionResult.sessionId;
			await pool.execute("DELETE FROM webauthn_challenges WHERE session_id = ? AND operation = 'userless_login'", [tempSessionId]);
			res.clearCookie(TWO_FA_COOKIE_NAME, TWO_FA_COOKIE_OPTS);
			res.clearCookie(PREAUTH_CSRF_COOKIE_NAME, { path: "/", secure: COOKIE_SECURE });
			res.cookie(SESSION_COOKIE_NAME, sessionId, { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.cookie(CSRF_COOKIE_NAME, generateCsrfTokenForSession(sessionId, "api"), { httpOnly: false, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.json({ success: true });
			recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: true, failureReason: null, userAgent: req.headers['user-agent'] || null });
		} catch (error) {
			logError("POST /api/passkey/login/userless/verify", error);
			res.status(500).json({ error: "패스키 로그인 중 오류가 발생했습니다." });
		}
	});

	router.post("/login/options", passkeyLimiter, requireSameOriginForAuth, async (req, res) => {
		try {
			const { username } = req.body;
			if (!username) return res.status(400).json({ error: "아이디를 입력해주세요." });
			const [userRows] = await pool.execute("SELECT id, passkey_enabled FROM users WHERE username = ?", [username]);
			const challengeUserId = (userRows.length > 0 && userRows[0].passkey_enabled) ? userRows[0].id : 0;
			const options = await generateAuthenticationOptions({ rpID: rpID, timeout: 60000, userVerification: 'required' });
			const now = new Date();
			const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
			const tempSessionId = crypto.randomBytes(32).toString('hex');
			await pool.execute(`INSERT INTO webauthn_challenges (user_id, session_id, challenge, operation, created_at, expires_at) VALUES (?, ?, ?, 'passkey_login', ?, ?)`, [challengeUserId, tempSessionId, options.challenge, formatDateForDb(now), formatDateForDb(expiresAt)]);
			res.cookie(TWO_FA_COOKIE_NAME, tempSessionId, { ...TWO_FA_COOKIE_OPTS, maxAge: 5 * 60 * 1000 });
			res.json({ ...options });
		} catch (error) {
			logError("POST /api/passkey/login/options", error);
			res.status(500).json({ error: "패스키 로그인 옵션 생성 중 오류가 발생했습니다." });
		}
	});

	router.post("/login/verify", passkeyLimiter, requireSameOriginForAuth, async (req, res) => {
		if (!verifyPreAuthCsrfToken(req)) return res.status(403).json({ error: "유효하지 않은 요청입니다." });
		try {
			const { credential } = req.body;
			const tempSessionId = get2faCookie(req);
			if (!credential || !tempSessionId) return res.status(400).json({ error: "인증 정보가 없습니다." });
			const [challenges] = await pool.execute(`SELECT user_id, challenge FROM webauthn_challenges WHERE session_id = ? AND operation = 'passkey_login' AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`, [tempSessionId]);
			if (challenges.length === 0) return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
			const expectedChallenge = challenges[0].challenge;
			const userId = challenges[0].user_id;
			if (!userId || userId <= 0) {
				await pool.execute("DELETE FROM webauthn_challenges WHERE session_id = ? AND operation = 'passkey_login'", [tempSessionId]);
				return res.status(401).json({ error: "인증에 실패했습니다." });
			}
			const credentialIdBase64 = credential.id;
			const [passkeys] = await pool.execute("SELECT id, public_key, counter, transports FROM passkeys WHERE credential_id = ? AND user_id = ?", [credentialIdBase64, userId]);
			if (passkeys.length === 0) return res.status(404).json({ error: "등록되지 않은 패스키입니다." });
			const passkey = passkeys[0];
			const publicKey = Buffer.from(passkey.public_key, 'base64');
			const verification = await verifyAuthenticationResponse({ response: credential, expectedChallenge: expectedChallenge, expectedOrigin: expectedOrigin, expectedRPID: rpID, credential: { id: credentialIdBase64, publicKey: publicKey, counter: passkey.counter, transports: passkey.transports ? passkey.transports.split(',') : [] }, requireUserVerification: true });
			if (!verification.verified) {
				const [userRows] = await pool.execute("SELECT username FROM users WHERE id = ?", [userId]);
				const username = userRows.length > 0 ? userRows[0].username : '알 수 없음';
				await recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: false, failureReason: '패스키 로그인 인증 실패', userAgent: req.headers['user-agent'] || null });
				return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
			}
			const newCounter = verification.authenticationInfo.newCounter;
			const now = new Date();
			const nowStr = formatDateForDb(now);
			await pool.execute("UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?", [newCounter, nowStr, passkey.id]);
			const [userRows] = await pool.execute("SELECT username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries FROM users WHERE id = ?", [userId]);
			if (userRows.length === 0) return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
			const { username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries } = userRows[0];
			const countryCheck = checkCountryWhitelist({ country_whitelist_enabled: country_whitelist_enabled, allowed_login_countries: allowed_login_countries }, getClientIp(req));
			if (!countryCheck.allowed) {
				await recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: false, failureReason: countryCheck.reason, userAgent: req.headers['user-agent'] || null });
				return res.status(403).json({ error: "현재 위치에서는 로그인할 수 없습니다." });
			}
			const sessionResult = await createSession({ id: userId, username: username, blockDuplicateLogin: block_duplicate_login }, { userAgent: req.headers["user-agent"] || "" });
			if (!sessionResult.success) return res.status(409).json({ error: sessionResult.error, code: 'DUPLICATE_LOGIN_BLOCKED' });
			const sessionId = sessionResult.sessionId;
			await pool.execute("DELETE FROM webauthn_challenges WHERE user_id = ? AND session_id = ? AND operation = 'passkey_login'", [userId, tempSessionId]);
			res.clearCookie(TWO_FA_COOKIE_NAME, TWO_FA_COOKIE_OPTS);
			res.clearCookie(PREAUTH_CSRF_COOKIE_NAME, { path: "/", secure: COOKIE_SECURE });
			res.cookie(SESSION_COOKIE_NAME, sessionId, { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.cookie(CSRF_COOKIE_NAME, generateCsrfTokenForSession(sessionId, "api"), { httpOnly: false, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.json({ success: true });
			recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: true, failureReason: null, userAgent: req.headers['user-agent'] || null });
		} catch (error) {
			logError("POST /api/passkey/login/verify", error);
			res.status(500).json({ error: "패스키 로그인 중 오류가 발생했습니다." });
		}
	});

	router.post("/authenticate/options", requireSameOriginForAuth, async (req, res) => {
		try {
			const tempSessionId = get2faCookie(req);
			if (!tempSessionId) return res.status(400).json({ error: "세션 정보가 없습니다." });
			const tempSession = await getValid2FATempSession(req, tempSessionId);
			if (!tempSession) return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
			const userId = tempSession.pendingUserId;
			const [passkeys] = await pool.execute("SELECT credential_id, transports FROM passkeys WHERE user_id = ?", [userId]);
			if (passkeys.length === 0) return res.status(404).json({ error: "등록된 패스키가 없습니다." });
			const options = await generateAuthenticationOptions({
				rpID: rpID,
				timeout: 60000,
				allowCredentials: passkeys.map(pk => ({ id: pk.credential_id, type: 'public-key', transports: pk.transports ? pk.transports.split(',') : ['usb', 'ble', 'nfc', 'internal', 'hybrid'] })),
				userVerification: 'required'
			});
			const now = new Date();
			const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
			await pool.execute(`INSERT INTO webauthn_challenges (user_id, session_id, challenge, operation, created_at, expires_at) VALUES (?, ?, ?, 'authentication', ?, ?)`, [userId, tempSessionId, options.challenge, formatDateForDb(now), formatDateForDb(expiresAt)]);
			res.json(options);
		} catch (error) {
			logError("POST /api/passkey/authenticate/options", error);
			res.status(500).json({ error: "패스키 인증 옵션 생성 중 오류가 발생했습니다." });
		}
	});

	router.post("/authenticate/verify", passkeyLimiter, requireSameOriginForAuth, async (req, res) => {
		if (!verifyPreAuthCsrfToken(req)) return res.status(403).json({ error: "유효하지 않은 요청입니다." });
		try {
			const { credential } = req.body;
			const tempSessionId = get2faCookie(req);
			if (!credential || !tempSessionId) return res.status(400).json({ error: "인증 정보가 없습니다." });
			const tempSession = await getValid2FATempSession(req, tempSessionId);
			if (!tempSession) return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
			const userId = tempSession.pendingUserId;
			const [challenges] = await pool.execute(`SELECT challenge FROM webauthn_challenges WHERE user_id = ? AND session_id = ? AND operation = 'authentication' AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1`, [userId, tempSessionId]);
			if (challenges.length === 0) return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
			const expectedChallenge = challenges[0].challenge;
			const credentialIdBase64 = credential.id;
			const [passkeys] = await pool.execute("SELECT id, public_key, counter, transports FROM passkeys WHERE credential_id = ? AND user_id = ?", [credentialIdBase64, userId]);
			if (passkeys.length === 0) return res.status(404).json({ error: "등록되지 않은 패스키입니다." });
			const passkey = passkeys[0];
			const publicKey = Buffer.from(passkey.public_key, 'base64');
			const verification = await verifyAuthenticationResponse({ response: credential, expectedChallenge: expectedChallenge, expectedOrigin: expectedOrigin, expectedRPID: rpID, credential: { id: credentialIdBase64, publicKey: publicKey, counter: passkey.counter, transports: passkey.transports ? passkey.transports.split(',') : [] }, requireUserVerification: true });
			if (!verification.verified) {
				const [userRows] = await pool.execute("SELECT username FROM users WHERE id = ?", [userId]);
				const username = userRows.length > 0 ? userRows[0].username : '알 수 없음';
				await recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: false, failureReason: '패스키 인증 실패', userAgent: req.headers['user-agent'] || null });
				return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
			}
			const newCounter = verification.authenticationInfo.newCounter;
			const now = new Date();
			const nowStr = formatDateForDb(now);
			await pool.execute("UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?", [newCounter, nowStr, passkey.id]);
			const [userRows] = await pool.execute("SELECT username, block_duplicate_login FROM users WHERE id = ?", [userId]);
			if (userRows.length === 0) return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
			const { username, block_duplicate_login } = userRows[0];
			const sessionResult = await createSession({ id: userId, username: username, blockDuplicateLogin: block_duplicate_login }, { userAgent: req.headers["user-agent"] || "" });
			if (!sessionResult.success) {
				await revokeSession(tempSessionId, "duplicate-login-blocked");
				return res.status(409).json({ error: sessionResult.error, code: 'DUPLICATE_LOGIN_BLOCKED' });
			}
			const sessionId = sessionResult.sessionId;
			await revokeSession(tempSessionId, "login-complete");
			res.clearCookie(TWO_FA_COOKIE_NAME, TWO_FA_COOKIE_OPTS);
			res.clearCookie(PREAUTH_CSRF_COOKIE_NAME, { path: "/", secure: COOKIE_SECURE });
			await pool.execute("DELETE FROM webauthn_challenges WHERE user_id = ? AND session_id = ? AND operation = 'authentication'", [userId, tempSessionId]);
			res.cookie(SESSION_COOKIE_NAME, sessionId, { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.cookie(CSRF_COOKIE_NAME, generateCsrfTokenForSession(sessionId, "api"), { httpOnly: false, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.json({ success: true });
			recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: true, failureReason: null, userAgent: req.headers['user-agent'] || null });
		} catch (error) {
			logError("POST /api/passkey/authenticate/verify", error);
			res.status(500).json({ error: "패스키 인증 중 오류가 발생했습니다." });
		}
	});

	router.delete("/:id", authMiddleware, csrfMiddleware, requireRecentReauth(5 * 60 * 1000), async (req, res) => {
		try {
			const userId = req.user.id;
			const passkeyId = parseInt(req.params.id);
			if (isNaN(passkeyId)) return res.status(400).json({ error: "잘못된 패스키 ID입니다." });
			const [passkeys] = await pool.execute("SELECT id FROM passkeys WHERE id = ? AND user_id = ?", [passkeyId, userId]);
			if (passkeys.length === 0) return res.status(404).json({ error: "패스키를 찾을 수 없습니다." });
			await pool.execute("DELETE FROM passkeys WHERE id = ?", [passkeyId]);
			const [remainingPasskeys] = await pool.execute("SELECT COUNT(*) as count FROM passkeys WHERE user_id = ?", [userId]);
			if (remainingPasskeys[0].count === 0) {
				const nowStr = formatDateForDb(new Date());
				await pool.execute("UPDATE users SET passkey_enabled = 0, updated_at = ? WHERE id = ?", [nowStr, userId]);
			}
			res.json({ success: true });
		} catch (error) {
			logError("DELETE /api/passkey/:id", error);
			res.status(500).json({ error: "패스키 삭제 중 오류가 발생했습니다." });
		}
	});

	return router;
};
