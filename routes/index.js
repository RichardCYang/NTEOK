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

	router.get("/shared/page/:token", (req, res) => {
		const token = req.params.token;
		if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) return res.status(404).send("페이지를 찾을 수 없습니다.");
		return sendHtmlWithNonce(res, "shared-page.html");
	});

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

	router.get("/api/shared/page/:token", async (req, res) => {
		const token = req.params.token;
		if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
		const tokenHash = dependencies.hashToken(token);
		const clientIp = getClientIp(req);
		try {
			const [pageRows] = await pool.execute(`SELECT p.id, p.title, p.content, p.icon, p.cover_image, p.cover_position FROM page_publish_links ppl JOIN pages p ON p.id = ppl.page_id WHERE ppl.token = ? AND ppl.is_active = 1 AND p.is_encrypted = 0 AND p.deleted_at IS NULL AND (ppl.expires_at IS NULL OR ppl.expires_at > NOW()) LIMIT 1`, [tokenHash]);
			const isValid = pageRows.length > 0;
			if (!(await checkSharedPageAccess(clientIp, token, isValid))) return res.status(429).json({ error: "너무 많은 요청입니다. 잠시 후 다시 시도해주세요." });
			if (!isValid) return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
			const page = pageRows[0];
			res.json({
			    id: page.id,
			    title: page.title || "제목 없음",
			    content: sanitizeHtmlContent(page.content || "<p></p>", { profile: "shared" }),
			    icon: page.icon || null,
			    coverImage: page.cover_image || null,
			    coverPosition: page.cover_position || 50
			});		} catch (error) {
			logError("GET /api/shared/page/:token", error);
			res.status(500).json({ error: "페이지 로드 실패" });
		}
	});

	return router;
};
