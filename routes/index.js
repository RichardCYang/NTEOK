const express = require("express");
const path = require("path");
const crypto = require("crypto");
const { JSDOM } = require("jsdom");
const erl = require("express-rate-limit");
const { ipKeyGenerator } = erl;
const router = express.Router();
const fsNative = require("fs");

module.exports = (dependencies) => {
    const { getSessionFromRequest, fs, pool, logError, getClientIpFromRequest, sanitizeHtmlContent, redis, COOKIE_SECURE } = dependencies;

    const RATE_LIMIT_IPV6_SUBNET = (() => {
        const n = Number(process.env.RATE_LIMIT_IPV6_SUBNET ?? 56);
        if (!Number.isFinite(n)) return 56;
        return Math.max(32, Math.min(64, n));
    })();

    function getClientIp(req) {
        return (
            req.clientIp ||
            (typeof getClientIpFromRequest === "function" ? getClientIpFromRequest(req) : null) ||
            req.ip ||
            req.connection?.remoteAddress ||
            req.socket?.remoteAddress ||
            "unknown"
        );
    }

    function rateLimitIpKey(rawIp) {
        return ipKeyGenerator(rawIp || "0.0.0.0", RATE_LIMIT_IPV6_SUBNET);
    }

    function tokenFingerprint(token) {
        return crypto.createHash("sha256").update(String(token)).digest("hex").slice(0, 16);
    }

    function sendHtmlWithNonce(res, filename, theme = "default") {
        const filePath = path.join(__dirname, "..", "public", filename);
        fs.readFile(filePath, "utf8", (err, html) => {
            if (err) return res.status(500).send("페이지 로드 실패");
            const nonce = res.locals?.cspNonce || "";
            let loadingStyle = theme === "dark"
                ? `<style nonce="${nonce}">.loading-overlay { background: #121212 !important; } .loading-spinner { border-color: rgba(255,255,255,0.1) !important; border-left-color: #5d9cec !important; }</style>`
                : `<style nonce="${nonce}">.loading-overlay { background: #f5f2ed !important; } .loading-spinner { border-color: rgba(0,0,0,0.1) !important; border-left-color: #2d5f5d !important; }</style>`;
            let out = html.replace(/__CSP_NONCE__/g, nonce);
            out = out.replace(/<script\b(?![^>]*\bnonce=)([^>]*?)>/gi, `<script nonce="${nonce}"$1>`);
            if (out.includes("__IMPORTMAP_INTEGRITY__")) {
                try {
                    const integrityPath = path.join(__dirname, "..", "public", "importmap-integrity.json");
                    const raw = fsNative.readFileSync(integrityPath, "utf8");
                    out = out.replace(/__IMPORTMAP_INTEGRITY__/g, (raw && raw.trim()) ? raw.trim() : "{}");
                } catch (e) {
                    out = out.replace(/__IMPORTMAP_INTEGRITY__/g, "{}");
                }
            }
            out = out.replace("</head>", `${loadingStyle}</head>`);
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
            const [rows] = await pool.execute("SELECT theme FROM users WHERE id = ?", [session.userId]);
            return sendHtmlWithNonce(res, "index.html", rows[0]?.theme || "default");
        } catch (error) {
            return sendHtmlWithNonce(res, "index.html");
        }
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

    const SHARED_PAGE_RATE_LIMIT_WINDOW = 60 * 1000;
    const SHARED_PAGE_MAX_ATTEMPTS = 20;
    const SHARED_PAGE_MAX_FAILED_TOKENS = 5;

    async function loadSharedPageBudget(clientIp) {
        const ipKey = rateLimitIpKey(clientIp);
        const key = `shared-page-access:${ipKey}`;
        const raw = await redis.get(key);
        let attempts;
        try {
            attempts = raw ? JSON.parse(raw) : { count: 0, tokens: [], invalidByToken: {} };
        } catch (_) {
            attempts = { count: 0, tokens: [], invalidByToken: {} };
        }
        if (!Array.isArray(attempts.tokens)) attempts.tokens = [];
        if (!attempts.invalidByToken || typeof attempts.invalidByToken !== "object") attempts.invalidByToken = {};
        return { key, attempts };
    }

    async function reserveSharedPageAttempt(clientIp) {
        const { key, attempts } = await loadSharedPageBudget(clientIp);
        if (attempts.count >= SHARED_PAGE_MAX_ATTEMPTS) return false;
        attempts.count += 1;
        await redis.set(key, JSON.stringify(attempts), { PX: SHARED_PAGE_RATE_LIMIT_WINDOW });
        return true;
    }

    async function registerSharedPageValidation(clientIp, token, isValid) {
        const fp = tokenFingerprint(token);
        const { key, attempts } = await loadSharedPageBudget(clientIp);
        if (!isValid) {
            if (!attempts.tokens.includes(fp)) attempts.tokens.push(fp);
            attempts.invalidByToken[fp] = (attempts.invalidByToken[fp] || 0) + 1;
        }
        await redis.set(key, JSON.stringify(attempts), { PX: SHARED_PAGE_RATE_LIMIT_WINDOW });
        if (attempts.tokens.length > SHARED_PAGE_MAX_FAILED_TOKENS) return false;
        if (!isValid && (attempts.invalidByToken[fp] || 0) > 3) return false;
        return true;
    }

    function normalizeLocalAssetPath(raw) {
        try {
            return new URL(String(raw || ""), "https://shared.local").pathname;
        } catch (_) {
            return String(raw || "");
        }
    }

    function isPublisherOwnedSharedAsset(raw, ownerUserId, coverImage) {
        const pathname = normalizeLocalAssetPath(raw);
        if (!pathname.startsWith("/")) return true;
        if (pathname.startsWith("/covers/default/")) return true;
        const m = pathname.match(/^\/(imgs|paperclip|covers)\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/);
        if (!m) return true;
        const [, kind, ns] = m;
        if (String(ns) !== String(ownerUserId)) return false;
        if (kind === "covers") return Boolean(coverImage) && pathname === `/covers/${coverImage}`;
        return true;
    }

    function stripCrossOwnerSharedAssets(html, { ownerUserId, coverImage }) {
        const dom = new JSDOM(`<body>${html || ""}</body>`);
        const doc = dom.window.document;
        for (const el of doc.querySelectorAll("[src],[href],[data-src],[data-favicon]")) {
            for (const attr of ["src", "href", "data-src", "data-favicon"]) {
                if (!el.hasAttribute(attr)) continue;
                const value = el.getAttribute(attr);
                if (!isPublisherOwnedSharedAsset(value, ownerUserId, coverImage)) el.removeAttribute(attr);
            }
        }
        return doc.body.innerHTML;
    }

    router.post("/api/shared/page", async (req, res) => {
        const token = String(req.get("X-Share-Token") || req.body?.token || "").trim();
        if (token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
        const tokenHash = dependencies.hashToken(token);
        const clientIp = getClientIp(req);
        if (!(await reserveSharedPageAttempt(clientIp))) return res.status(429).json({ error: "요청이 너무 많습니다." });
        try {
            const [rows] = await pool.execute(`SELECT p.id, p.user_id, p.title, p.content, p.icon, p.cover_image, p.cover_position FROM page_publish_links ppl JOIN pages p ON p.id = ppl.page_id WHERE ppl.token = ? AND ppl.is_active = 1 AND p.is_encrypted = 0 AND p.deleted_at IS NULL AND (ppl.expires_at IS NULL OR ppl.expires_at > NOW()) LIMIT 1`, [tokenHash]);
            const isValid = rows.length > 0;
            if (!(await registerSharedPageValidation(clientIp, token, isValid))) return res.status(429).json({ error: "요청이 너무 많습니다." });
            if (!isValid) {
                await new Promise(r => setTimeout(r, 150));
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }
            const page = rows[0];
            const sharedHtml = sanitizeHtmlContent(page.content || "<p></p>", { profile: "shared" });
            const ownerBoundHtml = stripCrossOwnerSharedAssets(sharedHtml, { ownerUserId: page.user_id, coverImage: page.cover_image || null });
            res.set("Cache-Control", "private, no-store");
            res.json({ id: page.id, title: page.title || "제목 없음", content: ownerBoundHtml, icon: page.icon || null, coverImage: page.cover_image || null, coverPosition: page.cover_position || 50 });
        } catch (error) {
            logError("POST /api/shared/page", error);
            res.status(500).json({ error: "페이지 로드 실패" });
        }
    });

    return router;
};