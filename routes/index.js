const express = require('express');
const path = require('path');
const router = express.Router();
const fsNative = require('fs');


module.exports = (dependencies) => {
	const { getSessionFromRequest, fs, pool, logError, getClientIpFromRequest, sanitizeHtmlContent } = dependencies;

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
            if (err) {
                console.error("[HTML] load error:", err);
                return res.status(500).send("Failed to load page");
            }

            const nonce = res.locals?.cspNonce || "";

            let loadingStyle = '';
            if (theme === 'dark') {
                loadingStyle = `
                    <style nonce="${nonce}">
                        .loading-overlay { background: #121212 !important; }
                        .loading-spinner { border-color: rgba(255,255,255,0.1) !important; border-left-color: #5d9cec !important; }
                    </style>
                `;
            } else {
                loadingStyle = `
                    <style nonce="${nonce}">
                        .loading-overlay { background: #f5f2ed !important; }
                        .loading-spinner { border-color: rgba(0,0,0,0.1) !important; border-left-color: #2d5f5d !important; }
                    </style>
                `;
            }

			let out = html.replace(/__CSP_NONCE__/g, nonce);

			out = out.replace(/<script\b(?![^>]*\bnonce=)([^>]*?)>/gi, `<script nonce="${nonce}"$1>`);

            if (out.includes("__IMPORTMAP_INTEGRITY__")) {
                try {
                    const integrityPath = path.join(__dirname, "..", "public", "importmap-integrity.json");
                    const raw = fsNative.readFileSync(integrityPath, "utf8");
                    const integrityJson = (raw && raw.trim()) ? raw.trim() : "{}";
                    out = out.replace(/__IMPORTMAP_INTEGRITY__/g, integrityJson);
                } catch (e) {
                    out = out.replace(/__IMPORTMAP_INTEGRITY__/g, "{}");
                }
            }

            out = out.replace('</head>', `${loadingStyle}</head>`);

            res.setHeader("Content-Type", "text/html; charset=utf-8");
            res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            res.setHeader("Pragma", "no-cache");
            res.send(out);
        });
    }

    router.get("/", async (req, res) => {
        const session = getSessionFromRequest(req);

        if (!session) {
            return res.redirect("/login");
        }

        try {
            const [rows] = await pool.execute('SELECT theme FROM users WHERE id = ?', [session.userId]);
            const theme = rows[0]?.theme || 'default';
            return sendHtmlWithNonce(res, "index.html", theme);
        } catch (error) {
            console.error("Error fetching user theme:", error);
            return sendHtmlWithNonce(res, "index.html");
        }
    });

    router.get("/login", (req, res) => {
        const session = getSessionFromRequest(req);

        if (session) {
            return res.redirect("/");
        }

        return sendHtmlWithNonce(res, "login.html");
    });

    router.get("/register", (req, res) => {
        const session = getSessionFromRequest(req);

        if (session) {
            return res.redirect("/");
        }

        return sendHtmlWithNonce(res, "register.html");
    });

    router.get("/icon.png", (req, res) => {
        return res.sendFile(path.join(__dirname, "..", "icon.png"));
    });

    router.get("/api/debug/ping", (req, res) => {
        res.json({
            ok: true,
            time: new Date().toISOString()
        });
    });

    router.get("/shared/page/:token", (req, res) => {
        const token = req.params.token;
        if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) {
            return res.status(404).send("페이지를 찾을 수 없습니다.");
        }
    	return sendHtmlWithNonce(res, "shared-page.html");
    });

    const sharedPageAccessAttempts = new Map(); 
    const SHARED_PAGE_RATE_LIMIT_WINDOW = 60 * 1000; 
    const SHARED_PAGE_MAX_ATTEMPTS = 20; 
    const SHARED_PAGE_MAX_FAILED_TOKENS = 5; 

    function checkSharedPageAccess(clientIp, token, isValid) {
        const now = Date.now();
        let attempts = sharedPageAccessAttempts.get(clientIp);

        if (attempts) {
            if (now < attempts.resetTime) {
                attempts.count++;

                if (!isValid) {
                    attempts.tokens.add(token);
                }

                if (attempts.count > SHARED_PAGE_MAX_ATTEMPTS) {
                    console.warn(`[공개 페이지 보안] IP ${clientIp}의 과도한 접근 시도 차단 (${attempts.count}회)`);
                    return false;
                }

                if (attempts.tokens.size > SHARED_PAGE_MAX_FAILED_TOKENS) {
                    console.warn(`[공개 페이지 보안] IP ${clientIp}의 브루트포스 시도 감지 (${attempts.tokens.size}개의 잘못된 토큰)`);
                    return false;
                }
            } else {
                sharedPageAccessAttempts.set(clientIp, {
                    count: 1,
                    resetTime: now + SHARED_PAGE_RATE_LIMIT_WINDOW,
                    tokens: isValid ? new Set() : new Set([token])
                });
            }
        } else {
            sharedPageAccessAttempts.set(clientIp, {
                count: 1,
                resetTime: now + SHARED_PAGE_RATE_LIMIT_WINDOW,
                tokens: isValid ? new Set() : new Set([token])
            });
        }

        return true;
    }

    setInterval(() => {
        const now = Date.now();
        for (const [ip, attempts] of sharedPageAccessAttempts.entries()) {
            if (now > attempts.resetTime) {
                sharedPageAccessAttempts.delete(ip);
            }
        }
    }, 5 * 60 * 1000);

    router.get("/api/shared/page/:token", async (req, res) => {
        const token = req.params.token;
        if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) {
            return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
        }
        const clientIp = getClientIp(req);

        try {
            const [pageRows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.icon, p.cover_image, p.cover_position
                 FROM page_publish_links ppl
                 JOIN pages p ON p.id = ppl.page_id
                 WHERE ppl.token = ?
                   AND ppl.is_active = 1
                   AND p.is_encrypted = 0
                   AND p.deleted_at IS NULL
                 LIMIT 1`,
                [token]
            );

            const isValid = pageRows.length > 0;

            if (!checkSharedPageAccess(clientIp, token, isValid)) {
                return res.status(429).json({ error: "너무 많은 요청입니다. 잠시 후 다시 시도해주세요." });
            }

            if (!isValid) {
                console.log(`[공개 페이지 접근] 실패 - 토큰: ${token.substring(0, 8)}..., IP: ${clientIp}`);
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];

            console.log(`[공개 페이지 접근] 성공 - 페이지: ${page.title}, 토큰: ${token.substring(0, 8)}..., IP: ${clientIp}`);

            res.json({
                id: page.id,
                title: page.title || "제목 없음",
                content: sanitizeHtmlContent(page.content || "<p></p>"),
                icon: page.icon || null,
                coverImage: page.cover_image || null,
                coverPosition: page.cover_position || 50
            });

        } catch (error) {
            logError("GET /api/shared/page/:token", error);
            res.status(500).json({ error: "페이지 로드 실패" });
        }
    });

    return router;
};
