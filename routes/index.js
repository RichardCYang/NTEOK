const express = require('express');
const path = require('path');
const router = express.Router();
const fsNative = require('fs');

module.exports = (dependencies) => {
	const { getSessionFromRequest, fs, pool, logError, getClientIpFromRequest, sanitizeHtmlContent, redis } = dependencies;

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

	function sendHtmlWithNonce(res, filename, theme = 'default') {
		const filePath = path.join(__dirname, "..", "public", filename);
		fs.readFile(filePath, "utf8", (err, html) => {
			if (err) return res.status(500).send("Failed to load page");
			const nonce = res.locals?.cspNonce || "";
			let loadingStyle = theme === 'dark' 
				? `<style nonce="${nonce}">.loading-overlay { background: #121212 !important; } .loading-spinner { border-color: rgba(255,255,255,0.1) !important; border-left-color: #5d9cec !important; }</style>`
				: `<style nonce="${nonce}">.loading-overlay { background: #f5f2ed !important; } .loading-spinner { border-color: rgba(0,0,0,0.1) !important; border-left-color: #2d5f5d !important; }</style>`;
			let out = html.replace(/__CSP_NONCE__/g, nonce);
			out = out.replace(/<script\b(?![^>]*\bnonce=)([^>]*?)>/gi, `<script nonce="${nonce}"$1>`);
			if (out.includes("__IMPORTMAP_INTEGRITY__")) {
				try {
					const integrityPath = path.join(__dirname, "..", "public", "importmap-integrity.json");
					const raw = fsNative.readFileSync(integrityPath, "utf8");
					out = out.replace(/__IMPORTMAP_INTEGRITY__/g, (raw && raw.trim()) ? raw.trim() : "{}");
				} catch (e) { out = out.replace(/__IMPORTMAP_INTEGRITY__/g, "{}"); }
			}
			out = out.replace('</head>', `${loadingStyle}</head>`);
			res.setHeader("Content-Type", "text/html; charset=utf-8");
			res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
			res.setHeader("Pragma", "no-cache");
			res.send(out);
		});
	}

	router.get("/", async (req, res) => {
		const session = await getSessionFromRequest(req);
		if (!session) return res.redirect("/login");
		try {
			const [rows] = await pool.execute('SELECT theme FROM users WHERE id = ?', [session.userId]);
			return sendHtmlWithNonce(res, "index.html", rows[0]?.theme || 'default');
		} catch (error) { return sendHtmlWithNonce(res, "index.html"); }
	});

	router.get("/login", async (req, res) => {
		if (await getSessionFromRequest(req)) return res.redirect("/");
		return sendHtmlWithNonce(res, "login.html");
	});

	router.get("/register", async (req, res) => {
		if (await getSessionFromRequest(req)) return res.redirect("/");
		return sendHtmlWithNonce(res, "register.html");
	});

	router.get("/icon.png", (req, res) => res.sendFile(path.join(__dirname, "..", "icon.png")));

	router.get("/api/debug/ping", (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

	async function checkSharedPageAccess(clientIp, token, isValid) {
		const key = `shared-page-access:${clientIp}`;
		const raw = await redis.get(key);
		const SHARED_PAGE_RATE_LIMIT_WINDOW = 60 * 1000;
		const SHARED_PAGE_MAX_ATTEMPTS = 20;
		const SHARED_PAGE_MAX_FAILED_TOKENS = 5;
		let attempts = raw ? JSON.parse(raw) : { count: 0, tokens: [] };
		attempts.count++;
		if (!isValid && !attempts.tokens.includes(token)) attempts.tokens.push(token);
		await redis.set(key, JSON.stringify(attempts), { PX: SHARED_PAGE_RATE_LIMIT_WINDOW });
		if (attempts.count > SHARED_PAGE_MAX_ATTEMPTS || attempts.tokens.length > SHARED_PAGE_MAX_FAILED_TOKENS) return false;
		return true;
	}

	router.post("/api/shared/page/exchange", async (req, res) => {
		const { token } = req.body;
		if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) return res.status(404).json({ error: "Invalid token" });
		const tokenHash = dependencies.hashToken(token);
		const clientIp = getClientIp(req);
		try {
			const [rows] = await pool.execute(`SELECT 1 FROM page_publish_links ppl JOIN pages p ON p.id = ppl.page_id WHERE ppl.token = ? AND ppl.is_active = 1 AND p.is_encrypted = 0 AND p.deleted_at IS NULL AND (ppl.expires_at IS NULL OR ppl.expires_at > NOW()) LIMIT 1`, [tokenHash]);
			const isValid = rows.length > 0;
			if (!(await checkSharedPageAccess(clientIp, token, isValid))) return res.status(429).json({ error: "Too many requests" });
			if (!isValid) return res.status(404).json({ error: "Page not found" });
			const cookieName = `shared_page_token_${tokenHash.substring(0, 16)}`;
			res.cookie(cookieName, token, { httpOnly: true, secure: process.env.COOKIE_SECURE === 'true', sameSite: 'Lax', maxAge: 3600000 });
			res.json({ ok: true, cookieName });
		} catch (error) { logError("POST /api/shared/page/exchange", error); res.status(500).json({ error: "Exchange failed" }); }
	});

	router.get("/api/shared/page", async (req, res) => {
		const { cookieName } = req.query;
		if (!cookieName || !cookieName.startsWith('shared_page_token_')) return res.status(400).json({ error: "Missing cookieName" });
		const token = req.cookies?.[cookieName];
		if (!token) return res.status(401).json({ error: "Token expired or missing" });
		const tokenHash = dependencies.hashToken(token);
		if (cookieName !== `shared_page_token_${tokenHash.substring(0, 16)}`) return res.status(403).json({ error: "Invalid exchange" });
		try {
			const [pageRows] = await pool.execute(`SELECT p.id, p.title, p.content, p.icon, p.cover_image, p.cover_position FROM page_publish_links ppl JOIN pages p ON p.id = ppl.page_id WHERE ppl.token = ? AND ppl.is_active = 1 AND p.is_encrypted = 0 AND p.deleted_at IS NULL AND (ppl.expires_at IS NULL OR ppl.expires_at > NOW()) LIMIT 1`, [tokenHash]);
			if (pageRows.length === 0) return res.status(404).json({ error: "Page not found" });
			const page = pageRows[0];
			res.json({ id: page.id, title: page.title || "제목 없음", content: sanitizeHtmlContent(page.content || "<p></p>", { profile: "shared" }), icon: page.icon || null, coverImage: page.cover_image || null, coverPosition: page.cover_position || 50 });
		} catch (error) { logError("GET /api/shared/page", error); res.status(500).json({ error: "Failed to load page" }); }
	});

	return router;
};
