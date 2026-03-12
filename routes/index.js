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

    return router;
};