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
        buildSessionContextFromReq,
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
		redis,
		getSession,
		saveSession,
		revokeSession,
		listUserSessions,
requireRecentReauth,
		requireStrongStepUp
	} = dependencies;

	async function revokeOtherSessions(userId, keepSessionId, reason) {
		const ids = await listUserSessions(userId);
		if (ids && ids.length > 0) {
			const otherIds = ids.filter(id => id && String(id) !== String(keepSessionId));
			await Promise.all(otherIds.map(id => revokeSession(id, reason)));
		}
	}

	async function finalizeInteractiveLogin(conn, req, {
		userId,
		tempSessionId,
		revokeReasonOnSuccess
	}) {
		const [userRows] = await conn.execute(
			`SELECT username,
					block_duplicate_login,
					country_whitelist_enabled,
					allowed_login_countries
			   FROM users
			  WHERE id = ?`,
			[userId]
		);
		if (userRows.length === 0) return { ok: false, type: 'auth' };

		const {
			username,
			block_duplicate_login,
			country_whitelist_enabled,
			allowed_login_countries
		} = userRows[0];

		const clientIp = getClientIp(req);
		const countryCheck = checkCountryWhitelist(
			{ country_whitelist_enabled, allowed_login_countries },
			clientIp
		);
		if (!countryCheck.allowed) {
			await recordLoginAttempt(pool, {
				userId,
				username,
				ipAddress: clientIp,
				port: req.connection.remotePort || 0,
				success: false,
				failureReason: countryCheck.reason,
				userAgent: req.headers['user-agent'] || null
			});
			if (tempSessionId) await revokeSession(tempSessionId, "country-check-failed");
			return { ok: false, type: 'country' };
		}

		const sessionResult = await createSession(
			{ id: userId, username, blockDuplicateLogin: block_duplicate_login },
			buildSessionContextFromReq(req, getClientIp),
			{ markStepUp: true, stepUpMethod: "mfa", accountHasMfa: true }
		);
		if (!sessionResult.success) {
			if (tempSessionId) await revokeSession(tempSessionId, "duplicate-login-blocked");
			return { ok: false, type: 'duplicate', error: sessionResult.error };
		}

		if (tempSessionId) await revokeSession(tempSessionId, revokeReasonOnSuccess);
		return { ok: true, sessionId: sessionResult.sessionId, username };
	}

	async function assertPasskeyLocked(redis, accountKey, ipKey) {
		const uKey = `passkey-lock:user:${accountKey}`;
		const iKey = `passkey-lock:ip:${ipKey}`;
		const [uRaw, iRaw] = await Promise.all([redis.get(uKey), redis.get(iKey)]);
		const now = Date.now();
		if (uRaw) {
			const st = JSON.parse(uRaw);
			if (st.lockedUntil && now < st.lockedUntil) return { ok: false, retryAfterMs: st.lockedUntil - now };
		}
		if (iRaw) {
			const st = JSON.parse(iRaw);
			if (st.lockedUntil && now < st.lockedUntil) return { ok: false, retryAfterMs: st.lockedUntil - now };
		}
		return { ok: true };
	}

	async function recordPasskeyFailure(redis, accountKey, ipKey) {
		const PASSKEY_MAX_FAILS_USER = Number(process.env.PASSKEY_MAX_FAILS_USER || 8);
		const PASSKEY_MAX_FAILS_IP = Number(process.env.PASSKEY_MAX_FAILS_IP || 20);
		const PASSKEY_LOCK_MS = Number(process.env.PASSKEY_LOCK_MS || (10 * 60 * 1000));
		const now = Date.now();
		const incr = async (key, max) => {
			const raw = await redis.get(key);
			const cur = raw ? JSON.parse(raw) : { failCount: 0, lockedUntil: 0 };
			cur.failCount += 1;
			if (cur.failCount >= max) {
				cur.lockedUntil = now + PASSKEY_LOCK_MS;
				cur.failCount = 0;
			}
			await redis.set(key, JSON.stringify(cur), { PX: PASSKEY_LOCK_MS * 2 });
		};
		await Promise.all([
			incr(`passkey-lock:user:${accountKey}`, PASSKEY_MAX_FAILS_USER),
			incr(`passkey-lock:ip:${ipKey}`, PASSKEY_MAX_FAILS_IP)
		]);
	}

	async function clearPasskeyFailures(redis, accountKey, ipKey) {
		await Promise.all([
			redis.del(`passkey-lock:user:${accountKey}`),
			redis.del(`passkey-lock:ip:${ipKey}`)
		]);
	}

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
			if (typeof sfs === "string" && sfs && sfs !== "same-origin") return res.status(403).json({ error: "요청 출처가 유효하지 않습니다." });
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

	async function genericPasskeyFailure(res) {
		await new Promise(resolve => setTimeout(resolve, 180));
		return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
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

	const USERLESS_PASSKEY_TTL_MS = 5 * 60 * 1000;

	async function createUserlessPasskeyTempSession(req) {
		const tempSessionId = crypto.randomBytes(32).toString("hex");
		const now = Date.now();
		const tempSession = {
			type: "userless-passkey",
			createdAt: now,
			expiresAt: now + USERLESS_PASSKEY_TTL_MS,
			lastAccessedAt: now,
			ipKey: getClientIp(req),
			uaHash: crypto.createHash("sha256").update(req.headers["user-agent"] || "").digest("hex")
		};
		await saveSession(tempSessionId, tempSession, USERLESS_PASSKEY_TTL_MS);
		return tempSessionId;
	}

	async function getValidUserlessPasskeySession(req, tempSessionId) {
		const s = await getSession(tempSessionId);
		if (!s || s.type !== "userless-passkey") return null;
		const now = Date.now();
		if (s.expiresAt && s.expiresAt <= now) {
			await revokeSession(tempSessionId, "userless-passkey-expired");
			return null;
		}
		const ipNow = getClientIp(req);
		if (s.ipKey && ipNow && s.ipKey !== ipNow) {
			await revokeSession(tempSessionId, "userless-passkey-ip-mismatch");
			return null;
		}
		const uaHashNow = crypto.createHash("sha256").update(req.headers["user-agent"] || "").digest("hex");
		if (s.uaHash && s.uaHash !== uaHashNow) {
			await revokeSession(tempSessionId, "userless-passkey-ua-mismatch");
			return null;
		}
		s.lastAccessedAt = now;
		await saveSession(tempSessionId, s, USERLESS_PASSKEY_TTL_MS);
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

	async function consumeChallengeTx(conn, { userId = null, sessionId, operation }) {
		const params = [];
		let sql = `
			SELECT id, challenge
			  FROM webauthn_challenges
			 WHERE session_id = ?
			   AND operation = ?
			   AND used_at IS NULL
			   AND expires_at > NOW()
		`;
		params.push(sessionId, operation);
		if (userId !== null) {
			sql += ` AND user_id = ?`;
			params.push(userId);
		}
		sql += ` ORDER BY created_at DESC LIMIT 1 FOR UPDATE`;

		const [rows] = await conn.execute(sql, params);
		if (!rows.length) return null;
		return rows[0];
	}

	async function markChallengeUsed(conn, id) {
		const [r] = await conn.execute(
			`UPDATE webauthn_challenges
				SET used_at = NOW()
			  WHERE id = ? AND used_at IS NULL`,
			[id]
		);
		return Number(r.affectedRows) === 1;
	}

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

	router.post("/register/options", authMiddleware, csrfMiddleware, requireStrongStepUp({ maxAgeMs: 5 * 60 * 1000, requireMfaIfEnabled: true }), async (req, res) => {
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

	router.post("/register/verify", authMiddleware, csrfMiddleware, requireStrongStepUp({ maxAgeMs: 5 * 60 * 1000, requireMfaIfEnabled: true }), passkeyLimiter, async (req, res) => {
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			const userId = req.user.id;
			const { credential } = req.body;
			const deviceName = sanitizeDeviceName(req.body?.deviceName);
			const sessionId = req.cookies[SESSION_COOKIE_NAME];
			if (!credential) {
				await conn.rollback();
				return res.status(400).json({ error: "인증 정보가 없습니다." });
			}
			const challengeRow = await consumeChallengeTx(conn, { userId, sessionId, operation: 'registration' });
			if (!challengeRow) {
				await conn.rollback();
				return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
			}
			const expectedChallenge = challengeRow.challenge;
			const verification = await verifyRegistrationResponse({ response: credential, expectedChallenge: expectedChallenge, expectedOrigin: expectedOrigin, expectedRPID: rpID, requireUserVerification: true });
			if (!verification.verified || !verification.registrationInfo) {
				await markChallengeUsed(conn, challengeRow.id);
				await conn.commit();
				return res.status(400).json({ error: "패스키 등록 검증에 실패했습니다." });
			}

			const consumed = await markChallengeUsed(conn, challengeRow.id);
			if (!consumed) {
				await conn.rollback();
				return res.status(409).json({ error: "챌린지가 이미 사용되었습니다. 다시 시도해 주세요." });
			}

			const { credential: registeredCredential, counter } = verification.registrationInfo;
			const credentialID = registeredCredential.id;
			const credentialPublicKey = registeredCredential.publicKey;
			const now = new Date();
			const nowStr = formatDateForDb(now);
			const credentialIdBase64 = credentialID;
			const publicKeyBase64 = Buffer.from(credentialPublicKey).toString('base64');
			await conn.execute(`INSERT INTO passkeys (user_id, credential_id, public_key, counter, device_name, created_at) VALUES (?, ?, ?, ?, ?, ?)`, [userId, credentialIdBase64, publicKeyBase64, counter, deviceName, nowStr]);
			await conn.execute("UPDATE users SET passkey_enabled = 1, updated_at = ? WHERE id = ?", [nowStr, userId]);
			
			const session = await getSession(sessionId);
			if (session) {
				session.lastStepUpAt = now.getTime();
				session.lastSensitiveStepUpAt = now.getTime();
				session.lastStepUpMethod = 'mfa';
				session.accountHasMfa = true;
				await saveSession(sessionId, session, SESSION_TTL_MS);
			}

			await conn.commit();
			await revokeOtherSessions(userId, sessionId, "passkey-added");
			res.json({ success: true });
		} catch (error) {
			try { await conn.rollback(); } catch (_) {}
			logError("POST /api/passkey/register/verify", error);
			res.status(500).json({ error: "패스키 등록 중 오류가 발생했습니다." });
		} finally {
			conn.release();
		}
	});

	router.post("/login/userless/options", passkeyLimiter, requireSameOriginForAuth, async (req, res) => {
		if (!verifyPreAuthCsrfToken(req)) return res.status(403).json({ error: "유효하지 않은 요청입니다." });
		try {
			const options = await generateAuthenticationOptions({ rpID: rpID, timeout: 60000, userVerification: 'required' });
			const now = new Date();
			const expiresAt = new Date(now.getTime() + 5 * 60 * 1000);
			const tempSessionId = await createUserlessPasskeyTempSession(req);
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
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			const { credential } = req.body;
			const tempSessionId = get2faCookie(req);
			const tempSession = await getValidUserlessPasskeySession(req, tempSessionId);
			if (!tempSession) {
				await conn.rollback();
				return res.status(400).json({ error: "세션이 만료되었거나 유효하지 않습니다. 다시 시도해 주세요." });
			}
			if (typeof credential !== 'object' || credential === null || typeof credential.id !== 'string') {
				await conn.rollback();
				return res.status(400).json({ error: "credential 형식이 올바르지 않습니다." });
			}
			if (credential.id.length < 10 || credential.id.length > 512 || !/^[A-Za-z0-9_-]+$/.test(credential.id)) {
				await conn.rollback();
				return res.status(400).json({ error: "credential.id 형식이 올바르지 않습니다." });
			}
			const challengeRow = await consumeChallengeTx(conn, { sessionId: tempSessionId, operation: 'userless_login' });
			if (!challengeRow) {
				await conn.rollback();
				return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
			}
			const expectedChallenge = challengeRow.challenge;
			const credentialIdBase64 = credential.id;
			const [passkeys] = await conn.execute("SELECT id, user_id, public_key, counter, transports FROM passkeys WHERE credential_id = ?", [credentialIdBase64]);
			if (passkeys.length === 0) {
				await markChallengeUsed(conn, challengeRow.id);
				await conn.commit();
				return genericPasskeyFailure(res);
			}
			const passkey = passkeys[0];
			const userId = passkey.user_id;
			const ip = getClientIp(req);
			const ipKey = crypto.createHash('sha256').update(ip).digest('hex');
			const lock = await assertPasskeyLocked(redis, `uid:${userId}`, ipKey);
			if (!lock.ok) {
				await conn.rollback();
				return res.status(429).json({ error: "인증 실패가 누적되어 잠시 잠금되었습니다.", retryAfterMs: lock.retryAfterMs });
			}
			const publicKey = Buffer.from(passkey.public_key, 'base64');
			const verification = await verifyAuthenticationResponse({ response: credential, expectedChallenge: expectedChallenge, expectedOrigin: expectedOrigin, expectedRPID: rpID, credential: { id: credentialIdBase64, publicKey: publicKey, counter: passkey.counter, transports: passkey.transports ? passkey.transports.split(',') : [] }, requireUserVerification: true });
			if (!verification.verified) {
				await markChallengeUsed(conn, challengeRow.id);
				await conn.commit();
				await recordPasskeyFailure(redis, `uid:${userId}`, ipKey);
				const [userRows] = await pool.execute("SELECT username FROM users WHERE id = ?", [userId]);
				const username = userRows.length > 0 ? userRows[0].username : '알 수 없음';
				await recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: false, failureReason: '패스키 userless 로그인 인증 실패', userAgent: req.headers['user-agent'] || null });
				return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
			}

			const consumed = await markChallengeUsed(conn, challengeRow.id);
			if (!consumed) {
				await conn.rollback();
				return res.status(409).json({ error: "챌린지가 이미 사용되었습니다. 다시 시도해 주세요." });
			}

			await clearPasskeyFailures(redis, `uid:${userId}`, ipKey);
			const newCounter = verification.authenticationInfo.newCounter;
			const now = new Date();
			const nowStr = formatDateForDb(now);
			await conn.execute("UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?", [newCounter, nowStr, passkey.id]);
			const [userRows] = await conn.execute("SELECT username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries FROM users WHERE id = ?", [userId]);
			if (userRows.length === 0) {
				await conn.commit();
				return genericPasskeyFailure(res);
			}
			const { username, block_duplicate_login, country_whitelist_enabled, allowed_login_countries } = userRows[0];
			const countryCheck = checkCountryWhitelist({ country_whitelist_enabled: country_whitelist_enabled, allowed_login_countries: allowed_login_countries }, getClientIp(req));
			if (!countryCheck.allowed) {
				await conn.commit();
				await recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: false, failureReason: countryCheck.reason, userAgent: req.headers['user-agent'] || null });
				return res.status(403).json({ error: "현재 위치에서는 로그인할 수 없습니다." });
			}
			const sessionResult = await createSession(
				{ id: userId, username: username, blockDuplicateLogin: block_duplicate_login },
				buildSessionContextFromReq(req, getClientIp),
				{ markStepUp: true, stepUpMethod: "mfa", accountHasMfa: true }
			);
			if (!sessionResult.success) {
				await conn.commit();
				return res.status(409).json({ error: sessionResult.error, code: 'DUPLICATE_LOGIN_BLOCKED' });
			}
			const sessionId = sessionResult.sessionId;
			await conn.commit();
			await revokeSession(tempSessionId, "userless-passkey-complete");
			res.clearCookie(TWO_FA_COOKIE_NAME, TWO_FA_COOKIE_OPTS);
			res.clearCookie(PREAUTH_CSRF_COOKIE_NAME, { path: "/", secure: COOKIE_SECURE });
			res.cookie(SESSION_COOKIE_NAME, sessionId, { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.cookie(CSRF_COOKIE_NAME, generateCsrfTokenForSession(sessionId, "api"), { httpOnly: false, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.json({ success: true });
			recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: true, failureReason: null, userAgent: req.headers['user-agent'] || null });
		} catch (error) {
			try { await conn.rollback(); } catch (_) {}
			logError("POST /api/passkey/login/verify", error);
			res.status(500).json({ error: "패스키 로그인 중 오류가 발생했습니다." });
		} finally {
			conn.release();
		}
	});

	router.post("/authenticate/options", passkeyLimiter, requireSameOriginForAuth, async (req, res) => {
		if (!verifyPreAuthCsrfToken(req)) return res.status(403).json({ error: "유효하지 않은 요청입니다." });
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
		const conn = await pool.getConnection();
		try {
			await conn.beginTransaction();
			const { credential } = req.body;
			const tempSessionId = get2faCookie(req);
			if (!credential || !tempSessionId) {
				await conn.rollback();
				return res.status(400).json({ error: "인증 정보가 없습니다." });
			}
			const tempSession = await getValid2FATempSession(req, tempSessionId);
			if (!tempSession) {
				await conn.rollback();
				return res.status(400).json({ error: "세션이 만료되었습니다. 다시 로그인하세요." });
			}
			const userId = tempSession.pendingUserId;
			const challengeRow = await consumeChallengeTx(conn, { userId, sessionId: tempSessionId, operation: 'authentication' });
			if (!challengeRow) {
				await conn.rollback();
				return res.status(400).json({ error: "유효한 챌린지를 찾을 수 없습니다. 다시 시도해 주세요." });
			}
			const expectedChallenge = challengeRow.challenge;
			const credentialIdBase64 = credential.id;
			const [passkeys] = await conn.execute("SELECT id, public_key, counter, transports FROM passkeys WHERE credential_id = ? AND user_id = ?", [credentialIdBase64, userId]);
			if (passkeys.length === 0) {
				await markChallengeUsed(conn, challengeRow.id);
				await conn.commit();
				return genericPasskeyFailure(res);
			}
			const passkey = passkeys[0];
			const ip = getClientIp(req);
			const ipKey = crypto.createHash('sha256').update(ip).digest('hex');
			const lock = await assertPasskeyLocked(redis, `uid:${userId}`, ipKey);
			if (!lock.ok) {
				await conn.rollback();
				return res.status(429).json({ error: "인증 실패가 누적되어 잠시 잠금되었습니다.", retryAfterMs: lock.retryAfterMs });
			}
			const publicKey = Buffer.from(passkey.public_key, 'base64');
			const verification = await verifyAuthenticationResponse({ response: credential, expectedChallenge: expectedChallenge, expectedOrigin: expectedOrigin, expectedRPID: rpID, credential: { id: credentialIdBase64, publicKey: publicKey, counter: passkey.counter, transports: passkey.transports ? passkey.transports.split(',') : [] }, requireUserVerification: true });
			if (!verification.verified) {
				await markChallengeUsed(conn, challengeRow.id);
				await conn.commit();
				await recordPasskeyFailure(redis, `uid:${userId}`, ipKey);
				const [userRows] = await pool.execute("SELECT username FROM users WHERE id = ?", [userId]);
				const username = userRows.length > 0 ? userRows[0].username : '알 수 없음';
				await recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: false, failureReason: '패스키 인증 실패', userAgent: req.headers['user-agent'] || null });
				return res.status(401).json({ error: "패스키 인증에 실패했습니다." });
			}

			const consumed = await markChallengeUsed(conn, challengeRow.id);
			if (!consumed) {
				await conn.rollback();
				return res.status(409).json({ error: "챌린지가 이미 사용되었습니다. 다시 시도해 주세요." });
			}

			await clearPasskeyFailures(redis, `uid:${userId}`, ipKey);
			const newCounter = verification.authenticationInfo.newCounter;
			const now = new Date();
			const nowStr = formatDateForDb(now);
			await conn.execute("UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?", [newCounter, nowStr, passkey.id]);
			const finalizeResult = await finalizeInteractiveLogin(conn, req, {
				userId,
				tempSessionId,
				revokeReasonOnSuccess: "login-complete"
			});
			if (!finalizeResult.ok) {
				await conn.commit();
				if (finalizeResult.type === 'country') return res.status(403).json({ error: "현재 위치에서는 로그인할 수 없습니다." });
				if (finalizeResult.type === 'duplicate') return res.status(409).json({ error: finalizeResult.error, code: 'DUPLICATE_LOGIN_BLOCKED' });
				return genericPasskeyFailure(res);
			}
			const { sessionId, username } = finalizeResult;
			await conn.commit();
			await revokeSession(tempSessionId, "login-complete");
			res.clearCookie(TWO_FA_COOKIE_NAME, TWO_FA_COOKIE_OPTS);
			res.clearCookie(PREAUTH_CSRF_COOKIE_NAME, { path: "/", secure: COOKIE_SECURE });
			res.cookie(SESSION_COOKIE_NAME, sessionId, { httpOnly: true, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.cookie(CSRF_COOKIE_NAME, generateCsrfTokenForSession(sessionId, "api"), { httpOnly: false, secure: COOKIE_SECURE, sameSite: "strict", path: "/", maxAge: SESSION_TTL_MS });
			res.json({ success: true });
			recordLoginAttempt(pool, { userId: userId, username: username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: true, failureReason: null, userAgent: req.headers['user-agent'] || null });
		} catch (error) {
			try { await conn.rollback(); } catch (_) {}
			logError("POST /api/passkey/authenticate/verify", error);
			res.status(500).json({ error: "패스키 인증 중 오류가 발생했습니다." });
		} finally {
			conn.release();
		}
	});

	router.delete("/:id", authMiddleware, csrfMiddleware, requireStrongStepUp({ maxAgeMs: 5 * 60 * 1000, requireMfaIfEnabled: true }), async (req, res) => {
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
			await revokeOtherSessions(userId, req.cookies[SESSION_COOKIE_NAME], "passkey-removed");
			res.json({ success: true });
		} catch (error) {
			logError("DELETE /api/passkey/:id", error);
			res.status(500).json({ error: "패스키 삭제 중 오류가 발생했습니다." });
		}
	});

	return router;
};
