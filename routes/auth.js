const express = require('express');
const router = express.Router();


module.exports = (dependencies) => {
	const {
		pool,
		storagesRepo,
		bcrypt,
		crypto,
		createSession,
		generateCsrfToken,
		generateCsrfTokenForSession,
		verifyCsrfTokenForSession,
		generatePreAuthCsrfToken,
		verifyPreAuthCsrfToken,
		PREAUTH_CSRF_COOKIE_NAME,
		formatDateForDb,
		validatePasswordStrength,
		logError,
		SESSION_COOKIE_NAME,
		CSRF_COOKIE_NAME,
		SESSION_TTL_MS,
		IS_PRODUCTION,
		COOKIE_SECURE,
		BASE_URL,
		BCRYPT_SALT_ROUNDS,
		authMiddleware,
		authLimiter,
		recordLoginAttempt,
		maskIPAddress,
		checkCountryWhitelist,
		getClientIpFromRequest,
		redis,
		assertLoginNotLocked,
		recordLoginFailure,
		clearLoginFailures,
		requireRecentReauth,
		csrfMiddleware,
		saveSession,
		getSession,
		revokeSession,
		listUserSessions
	} = dependencies;

	const TWO_FA_COOKIE_NAME = COOKIE_SECURE ? '__Host-nteok_2fa' : 'nteok_2fa';
	const TWO_FA_COOKIE_OPTS = {
		httpOnly: true,
		sameSite: 'strict',
		secure: COOKIE_SECURE,
		path: '/',
		maxAge: 10 * 60 * 1000
	};

	const PASSWORD_CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;

	let USERNAME_SAFE_RE;
	try {
		USERNAME_SAFE_RE = new RegExp('^[\\p{L}\\p{N}._-]{3,64}$', 'u');
	} catch (_) {
		USERNAME_SAFE_RE = /^[A-Za-z0-9._-]{3,64}$/;
	}
	const USERNAME_CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;

	const DUMMY_LOGIN_BCRYPT_HASH =
		process.env.DUMMY_LOGIN_BCRYPT_HASH ||
		'$2b$12$IfuyBUTMgc9Y2heW2QrSjuqKjPP3nkXvKvTnSxfpVNIVqdzuXvbsS';
	async function consumeBcryptCostForTiming(password) {
		try {
			await bcrypt.compare(password, DUMMY_LOGIN_BCRYPT_HASH);
		} catch (_) {
		}
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

	router.get("/csrf", (req, res) => {
		const token = generatePreAuthCsrfToken();
		res.cookie(PREAUTH_CSRF_COOKIE_NAME, token, {
			httpOnly: false,
			sameSite: "strict",
			secure: COOKIE_SECURE,
			path: "/",
			maxAge: 30 * 60 * 1000
		});
		res.json({ ok: true, token });
	});

	router.post("/login", authLimiter, requireSameOriginForAuth, async (req, res) => {
		if (!verifyPreAuthCsrfToken(req)) return res.status(403).json({ error: "유효하지 않은 요청입니다." });
		const { username, password } = req.body || {};
		if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
		if (PASSWORD_CONTROL_CHARS_RE.test(password)) return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
		const trimmedUsername = username.trim();
		const clientIp = getClientIp(req);
		const lockStatus = await assertLoginNotLocked(redis, trimmedUsername, clientIp);
		if (!lockStatus.ok) return res.status(423).json({ error: `너무 많은 로그인 시도로 인해 계정이 잠겼습니다. ${Math.ceil(lockStatus.retryAfterMs / 60000)}분 후 다시 시도해 주세요.` });

		try {
			const [rows] = await pool.execute(
				`SELECT id, username, password_hash, totp_enabled, passkey_enabled, block_duplicate_login, country_whitelist_enabled, allowed_login_countries FROM users WHERE username = ?`,
				[trimmedUsername]
			);

			if (!rows.length) {
				await consumeBcryptCostForTiming(password);
				await recordLoginFailure(redis, trimmedUsername, clientIp);
				await recordLoginAttempt(pool, { userId: null, username: trimmedUsername, ipAddress: clientIp, port: req.connection.remotePort || 0, success: false, failureReason: '로그인 실패', userAgent: req.headers['user-agent'] || null });
				return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
			}

			const user = rows[0];
			const ok = await bcrypt.compare(password, user.password_hash);
			if (!ok) {
				await recordLoginFailure(redis, trimmedUsername, clientIp);
				await recordLoginAttempt(pool, { userId: user.id, username: user.username, ipAddress: clientIp, port: req.connection.remotePort || 0, success: false, failureReason: '로그인 실패', userAgent: req.headers['user-agent'] || null });
				return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
			}

			const countryCheck = checkCountryWhitelist({ country_whitelist_enabled: user.country_whitelist_enabled, allowed_login_countries: user.allowed_login_countries }, getClientIp(req));
			if (!countryCheck.allowed) {
				await recordLoginAttempt(pool, { userId: user.id, username: user.username, ipAddress: clientIp, port: req.connection.remotePort || 0, success: false, failureReason: countryCheck.reason, userAgent: req.headers['user-agent'] || null });
				return res.status(403).json({ error: "현재 위치에서는 로그인할 수 없습니다." });
			}

			await clearLoginFailures(redis, trimmedUsername, clientIp);
			if (user.totp_enabled || user.passkey_enabled) {
				const tempSessionId = crypto.randomBytes(32).toString("hex");
				const now = Date.now();
				const tempSession = { type: "2fa", pendingUserId: user.id, createdAt: now, expiresAt: now + 10 * 60 * 1000, lastAccessedAt: now, ipKey: getClientIp(req), uaHash: crypto.createHash("sha256").update(req.headers["user-agent"] || "").digest("hex") };
				await saveSession(tempSessionId, tempSession, 10 * 60 * 1000);
				res.cookie(TWO_FA_COOKIE_NAME, tempSessionId, TWO_FA_COOKIE_OPTS);
				return res.json({ ok: false, requires2FA: true, availableMethods: [user.totp_enabled && 'totp', user.passkey_enabled && 'passkey'].filter(Boolean) });
			}

			const sessionResult = await createSession({ id: user.id, username: user.username, blockDuplicateLogin: user.block_duplicate_login }, { userAgent: req.headers["user-agent"] || "" });
			if (!sessionResult.success) return res.status(409).json({ error: sessionResult.error, code: 'DUPLICATE_LOGIN_BLOCKED' });

			res.clearCookie(PREAUTH_CSRF_COOKIE_NAME, { path: "/", secure: COOKIE_SECURE });
			res.cookie(SESSION_COOKIE_NAME, sessionResult.sessionId, { httpOnly: true, sameSite: "strict", secure: COOKIE_SECURE, path: "/", maxAge: SESSION_TTL_MS });
			res.cookie(CSRF_COOKIE_NAME, generateCsrfTokenForSession(sessionResult.sessionId, "api"), { httpOnly: false, sameSite: "strict", secure: COOKIE_SECURE, path: "/", maxAge: SESSION_TTL_MS });
			res.json({ ok: true, user: { id: user.id, username: user.username } });
			recordLoginAttempt(pool, { userId: user.id, username: user.username, ipAddress: getClientIp(req), port: req.connection.remotePort || 0, success: true, failureReason: null, userAgent: req.headers['user-agent'] || null });
		} catch (error) {
			logError("POST /api/auth/login", error);
			res.status(500).json({ error: "로그인 처리 중 오류가 발생했습니다." });
		}
	});

	router.post("/reauth", authMiddleware, csrfMiddleware, async (req, res) => {
		const { password } = req.body || {};
		if (typeof password !== "string") return res.status(400).json({ error: "비밀번호를 입력해 주세요." });
		try {
			const [rows] = await pool.execute(`SELECT password_hash FROM users WHERE id = ?`, [req.user.id]);
			if (!rows.length) return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
			if (!(await bcrypt.compare(password, rows[0].password_hash))) return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });
			const oldSessionId = req.cookies[SESSION_COOKIE_NAME];
			const session = await getSession(oldSessionId);
			if (session) {
				const now = Date.now();
				const newSessionId = crypto.randomBytes(24).toString("hex");
				const rotatedSession = { ...session, lastStrongAuthAt: now, reauthenticatedAt: now };
				const remainingTtl = session.absoluteExpiry ? Math.max(1000, session.absoluteExpiry - now) : SESSION_TTL_MS;
				await saveSession(newSessionId, rotatedSession, remainingTtl);
				await revokeSession(oldSessionId, "reauth-rotate");
				res.cookie(SESSION_COOKIE_NAME, newSessionId, { httpOnly: true, sameSite: "strict", secure: COOKIE_SECURE, path: "/", maxAge: Math.min(SESSION_TTL_MS, remainingTtl) });
				res.cookie(CSRF_COOKIE_NAME, generateCsrfTokenForSession(newSessionId, "api"), { httpOnly: false, sameSite: "strict", secure: COOKIE_SECURE, path: "/", maxAge: Math.min(SESSION_TTL_MS, remainingTtl) });
			}
			res.json({ ok: true });
		} catch (error) {
			logError("POST /api/auth/reauth", error);
			res.status(500).json({ error: "재인증 중 오류가 발생했습니다." });
		}
	});

	router.post("/logout", async (req, res) => {
		const { getSessionFromRequest, wsCloseConnectionsForSession } = dependencies;

		const session = await getSessionFromRequest(req);

		if (session) {
			const tokenFromHeader = req.headers['x-csrf-token'];
			const tokenFromCookie = req.cookies?.[CSRF_COOKIE_NAME];

			if (typeof tokenFromHeader !== 'string' || typeof tokenFromCookie !== 'string') {
				console.warn('CSRF 토큰 누락: /auth/logout');
				return res.status(403).json({ error: 'CSRF 토큰이 유효하지 않습니다.' });
			}

			if (tokenFromHeader !== tokenFromCookie) {
				console.warn('CSRF 토큰 불일치: /auth/logout');
				return res.status(403).json({ error: 'CSRF 토큰이 유효하지 않습니다.' });
			}

			if (!verifyCsrfTokenForSession(session.id, tokenFromHeader, 'api')) {
				console.warn('CSRF 토큰 서명 검증 실패: /auth/logout');
				return res.status(403).json({ error: 'CSRF 토큰이 유효하지 않습니다.' });
			}

			try { wsCloseConnectionsForSession(session.id, 1008, 'Logout'); } catch (e) {}
			await revokeSession(session.id, 'logout');
		}

		res.clearCookie(SESSION_COOKIE_NAME, {
			httpOnly: true,
			sameSite: 'strict',
			path: '/',
			secure: COOKIE_SECURE
		});

		res.json({ ok: true });
	});

	router.delete("/account", authMiddleware, csrfMiddleware, requireRecentReauth(10 * 60 * 1000), async (req, res) => {
		const { password, confirmText } = req.body || {};

		if (typeof password !== "string" || !password.trim()) return res.status(400).json({ error: "비밀번호를 입력해 주세요." });

		if (PASSWORD_CONTROL_CHARS_RE.test(password)) return res.status(400).json({ error: "비밀번호 형식이 올바르지 않습니다." });

		if (confirmText !== "계정 삭제") return res.status(400).json({ error: '확인 문구를 정확히 입력해 주세요. "계정 삭제"를 입력하세요.' });

		try {
			const [rows] = await pool.execute(
				`SELECT id, username, password_hash FROM users WHERE id = ?`,
				[req.user.id]
			);

			if (!rows.length) return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });

			const user = rows[0];

			const ok = await bcrypt.compare(password, user.password_hash);
			if (!ok) {
				const maskedUsername = req.user.username.substring(0, 2) + '***';
				console.warn(`[계정 삭제 실패] 사용자: ${maskedUsername}, IP: ${getClientIp(req)}, 사유: 비밀번호 불일치`);
				return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });
			}

			try {
				if (storagesRepo && typeof storagesRepo.safeDeleteAllOwnedStoragesPreservingCollaborators === 'function') {
					await storagesRepo.safeDeleteAllOwnedStoragesPreservingCollaborators(req.user.id);
				}
			} catch (e) {
				logError('DELETE /api/auth/account (pre-delete transfer)', e);
				return res.status(500).json({ error: '계정 삭제 전 데이터 이관에 실패했습니다. 잠시 후 다시 시도해 주세요.' });
			}

			await pool.execute(`DELETE FROM users WHERE id = ?`, [req.user.id]);

			const maskedUsername = req.user.username.substring(0, 2) + '***';
			console.log(`[계정 삭제 완료] 사용자 ID: ${req.user.id}, 사용자명: ${maskedUsername}`);

			const { wsCloseConnectionsForSession } = dependencies;
			const userId = req.user.id;
			const sessionIds = await listUserSessions(userId);
			if (sessionIds && sessionIds.length > 0) {
				for (const sessionId of sessionIds) {
					try { wsCloseConnectionsForSession(sessionId, 1008, 'Account deleted'); } catch (e) {}
					await revokeSession(sessionId, "account-deleted");
				}
			}

			res.clearCookie(SESSION_COOKIE_NAME, {
				httpOnly: true,
				sameSite: "strict",
				path: "/",
				secure: COOKIE_SECURE
			});

			res.json({ ok: true });
		} catch (error) {
			logError("DELETE /api/auth/account", error);
			res.status(500).json({ error: "계정 삭제 중 오류가 발생했습니다." });
		}
	});

	router.post("/register", authLimiter, requireSameOriginForAuth, async (req, res) => {
		if (!verifyPreAuthCsrfToken(req)) return res.status(403).json({ error: "유효하지 않은 요청입니다." });
		const { username, password } = req.body || {};
		if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "아이디와 비밀번호를 모두 입력해 주세요." });
		const trimmedUsername = username.trim();
		if (trimmedUsername.length < 3 || trimmedUsername.length > 64) return res.status(400).json({ error: "아이디는 3~64자 사이로 입력해 주세요." });
		if (USERNAME_CONTROL_CHARS_RE.test(trimmedUsername) || !USERNAME_SAFE_RE.test(trimmedUsername)) return res.status(400).json({ error: "아이디 형식이 올바르지 않습니다." });
		const passwordValidation = validatePasswordStrength(password);
		if (!passwordValidation.valid) return res.status(400).json({ error: passwordValidation.error });

		try {
			const now = new Date();
			const nowStr = formatDateForDb(now);
			const passwordHash = await bcrypt.hash(password, BCRYPT_SALT_ROUNDS);
			let result;
			try {
				[result] = await pool.execute(`INSERT INTO users (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`, [trimmedUsername, passwordHash, nowStr, nowStr]);
			} catch (dbErr) {
				if (dbErr && (dbErr.code === 'ER_DUP_ENTRY' || dbErr.errno === 1062)) {
					await consumeBcryptCostForTiming(password);
					return res.status(400).json({ error: "회원가입을 완료할 수 없습니다. 입력값을 확인해 주세요." });
				}
				throw dbErr;
			}
			const user = { id: result.insertId, username: trimmedUsername, blockDuplicateLogin: false };
			const storageId = 'stg-' + now.getTime() + '-' + crypto.randomBytes(4).toString('hex');
			await storagesRepo.createStorage({ userId: user.id, id: storageId, name: "기본 저장소", sortOrder: 0, createdAt: nowStr, updatedAt: nowStr });
			const sessionResult = await createSession(user, { userAgent: req.headers["user-agent"] || "" });
			if (!sessionResult.success) return res.status(409).json({ error: sessionResult.error, code: 'DUPLICATE_LOGIN_BLOCKED' });

			res.clearCookie(PREAUTH_CSRF_COOKIE_NAME, { path: "/", secure: COOKIE_SECURE });
			res.cookie(SESSION_COOKIE_NAME, sessionResult.sessionId, { httpOnly: true, sameSite: "strict", secure: COOKIE_SECURE, path: "/", maxAge: SESSION_TTL_MS });
			res.cookie(CSRF_COOKIE_NAME, generateCsrfTokenForSession(sessionResult.sessionId, "api"), { httpOnly: false, sameSite: "strict", secure: COOKIE_SECURE, path: "/", maxAge: SESSION_TTL_MS });
			return res.status(201).json({ ok: true, user: { id: user.id, username: user.username } });
		} catch (error) {
			logError("POST /api/auth/register", error);
			return res.status(500).json({ error: "회원가입 처리 중 오류가 발생했습니다." });
		}
	});

    router.get("/me", authMiddleware, async (req, res) => {
        try {
            const [rows] = await pool.execute(
                `SELECT id, username, theme, sticky_header FROM users WHERE id = ?`,
                [req.user.id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "사용자를 찾을 수 없습니다." });
            }

            const user = rows[0];
            res.json({
                id: user.id,
                username: user.username,
                theme: user.theme,
                stickyHeader: user.sticky_header === 1
            });
        } catch (error) {
            logError("GET /api/auth/me", error);
            res.status(500).json({ error: "사용자 정보 조회 중 오류가 발생했습니다." });
        }
    });


    router.put("/settings", authMiddleware, csrfMiddleware, async (req, res) => {
        const { stickyHeader } = req.body;

        if (stickyHeader !== undefined && typeof stickyHeader !== "boolean") {
            return res.status(400).json({ error: "올바른 설정 값이 아닙니다." });
        }

        try {
            const updates = [];
            const values = [];

            if (stickyHeader !== undefined) {
                updates.push('sticky_header = ?');
                values.push(stickyHeader ? 1 : 0);
            }

            if (updates.length === 0) {
                return res.status(400).json({ error: "업데이트할 설정이 없습니다." });
            }

            values.push(req.user.id);

            await pool.execute(
                `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
                values
            );

            res.json({ ok: true });
        } catch (error) {
            logError("PUT /api/auth/settings", error);
            res.status(500).json({ error: "설정 업데이트 중 오류가 발생했습니다." });
        }
    });

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

    router.put("/security-settings", authMiddleware, csrfMiddleware, requireRecentReauth(10 * 60 * 1000), async (req, res) => {
        const { blockDuplicateLogin, countryWhitelistEnabled, allowedLoginCountries } = req.body;

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

            const invalidCountry = allowedLoginCountries.find(
                code => typeof code !== 'string' || !/^[A-Z]{2}$/.test(code)
            );
            if (invalidCountry) {
                return res.status(400).json({ error: "유효하지 않은 국가 코드가 포함되어 있습니다." });
            }
        }

        try {
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

            const maskedUsername = req.user.username.substring(0, 2) + '***';
            console.log(`[보안 설정] 사용자 ID ${req.user.id} (${maskedUsername}): 설정 업데이트 완료`);

            res.json({ ok: true });
        } catch (error) {
            logError("PUT /api/auth/security-settings", error);
            res.status(500).json({ error: "보안 설정 업데이트 중 오류가 발생했습니다." });
        }
    });

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
