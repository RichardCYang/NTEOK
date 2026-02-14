const express = require('express');
const path = require('path');
const router = express.Router();
const fsNative = require('fs');

/**
 * Static & Debug Routes
 *
 * 이 파일은 정적 페이지 및 디버그 라우트를 처리합니다.
 * - 메인 페이지, 로그인 페이지, 회원가입 페이지
 * - 앱 아이콘
 * - 헬스 체크 API
 */

module.exports = (dependencies) => {
	const { getSessionFromRequest, fs, pool, logError, getClientIpFromRequest, sanitizeHtmlContent } = dependencies;

    function sendHtmlWithNonce(res, filename, theme = 'default') {
        const filePath = path.join(__dirname, "..", "public", filename);
        fs.readFile(filePath, "utf8", (err, html) => {
            if (err) {
                console.error("[HTML] load error:", err);
                return res.status(500).send("Failed to load page");
            }

            const nonce = res.locals?.cspNonce || "";

            // 테마별 로딩 오버레이 스타일 정의
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

			// 보안: 모든 <script> 태그에 nonce 자동 부여
			// - HTML 파일에 nonce가 누락되어도 CSP에 의해 차단되지 않도록 서버에서 일괄 주입
			// - 이미 nonce가 있는 <script> (예: importmap)는 그대로 유지
			out = out.replace(/<script\b(?![^>]*\bnonce=)([^>]*?)>/gi, `<script nonce="${nonce}"$1>`);

			// Importmap integrity 주입: HTML 내 __IMPORTMAP_INTEGRITY__ 플레이스홀더를
            // public/importmap-integrity.json 내용으로 치환 (없으면 빈 객체)
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

            // </head> 바로 앞에 테마 스타일 주입
            out = out.replace('</head>', `${loadingStyle}</head>`);

            // HTML은 캐시 비권장 (nonce/보안/업데이트)
            res.setHeader("Content-Type", "text/html; charset=utf-8");
            res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
            res.setHeader("Pragma", "no-cache");
            res.send(out);
        });
    }

    /**
     * 메인 화면
     * GET /
     */
    router.get("/", async (req, res) => {
        const session = getSessionFromRequest(req);

        if (!session) {
            return res.redirect("/login");
        }

        try {
            // 사용자의 테마 설정을 DB에서 조회
            const [rows] = await pool.execute('SELECT theme FROM users WHERE id = ?', [session.userId]);
            const theme = rows[0]?.theme || 'default';
            return sendHtmlWithNonce(res, "index.html", theme);
        } catch (error) {
            console.error("Error fetching user theme:", error);
            return sendHtmlWithNonce(res, "index.html");
        }
    });

    /**
     * 로그인 페이지
     * GET /login
     */
    router.get("/login", (req, res) => {
        const session = getSessionFromRequest(req);

        if (session) {
            return res.redirect("/");
        }

        return sendHtmlWithNonce(res, "login.html");
    });

    /**
     * 회원가입 페이지
     * GET /register
     */
    router.get("/register", (req, res) => {
        const session = getSessionFromRequest(req);

        if (session) {
            return res.redirect("/");
        }

        return sendHtmlWithNonce(res, "register.html");
    });

    /**
     * 앱 아이콘
     * GET /icon.png
     */
    router.get("/icon.png", (req, res) => {
        return res.sendFile(path.join(__dirname, "..", "icon.png"));
    });

    /**
     * 헬스 체크 API
     * GET /api/debug/ping
     */
    router.get("/api/debug/ping", (req, res) => {
        res.json({
            ok: true,
            time: new Date().toISOString()
        });
    });

    /**
     * 발행된 페이지 공개 뷰 (HTML)
     * GET /shared/page/:token
     */
    router.get("/shared/page/:token", (req, res) => {
        const token = req.params.token;
        if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) {
            return res.status(404).send("페이지를 찾을 수 없습니다.");
        }
    	return sendHtmlWithNonce(res, "shared-page.html");
    });

    /**
     * 공개 페이지 접근 시도 추적 (브루트포스 방지)
     */
    const sharedPageAccessAttempts = new Map(); // IP -> { count, resetTime, tokens: Set }
    const SHARED_PAGE_RATE_LIMIT_WINDOW = 60 * 1000; // 1분
    const SHARED_PAGE_MAX_ATTEMPTS = 20; // 분당 최대 20회 시도
    const SHARED_PAGE_MAX_FAILED_TOKENS = 5; // 서로 다른 잘못된 토큰 최대 5개

    function checkSharedPageAccess(clientIp, token, isValid) {
        const now = Date.now();
        let attempts = sharedPageAccessAttempts.get(clientIp);

        if (attempts) {
            if (now < attempts.resetTime) {
                // 시간 윈도우 내
                attempts.count++;

                if (!isValid) {
                    attempts.tokens.add(token);
                }

                // Rate limit 체크
                if (attempts.count > SHARED_PAGE_MAX_ATTEMPTS) {
                    console.warn(`[공개 페이지 보안] IP ${clientIp}의 과도한 접근 시도 차단 (${attempts.count}회)`);
                    return false;
                }

                // 여러 잘못된 토큰 시도 체크
                if (attempts.tokens.size > SHARED_PAGE_MAX_FAILED_TOKENS) {
                    console.warn(`[공개 페이지 보안] IP ${clientIp}의 브루트포스 시도 감지 (${attempts.tokens.size}개의 잘못된 토큰)`);
                    return false;
                }
            } else {
                // 시간 윈도우가 지났으므로 리셋
                sharedPageAccessAttempts.set(clientIp, {
                    count: 1,
                    resetTime: now + SHARED_PAGE_RATE_LIMIT_WINDOW,
                    tokens: isValid ? new Set() : new Set([token])
                });
            }
        } else {
            // 첫 시도
            sharedPageAccessAttempts.set(clientIp, {
                count: 1,
                resetTime: now + SHARED_PAGE_RATE_LIMIT_WINDOW,
                tokens: isValid ? new Set() : new Set([token])
            });
        }

        return true;
    }

    // 5분마다 만료된 접근 시도 기록 정리
    setInterval(() => {
        const now = Date.now();
        for (const [ip, attempts] of sharedPageAccessAttempts.entries()) {
            if (now > attempts.resetTime) {
                sharedPageAccessAttempts.delete(ip);
            }
        }
    }, 5 * 60 * 1000);

    /**
     * 발행된 페이지 데이터 API
     * GET /api/shared/page/:token
     */
    router.get("/api/shared/page/:token", async (req, res) => {
        const token = req.params.token;
        // 형식이 명백히 이상한 값은 조기 차단
        if (typeof token !== 'string' || token.length !== 64 || !/^[a-f0-9]{64}$/i.test(token)) {
            return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
        }
        const clientIp = typeof getClientIpFromRequest === 'function' ? getClientIpFromRequest(req) : (req.ip || req.socket?.remoteAddress || 'unknown');

        try {
            const [publishRows] = await pool.execute(
                `SELECT page_id FROM page_publish_links
                 WHERE token = ? AND is_active = 1`,
                [token]
            );

            const isValid = publishRows.length > 0;

            // Rate Limiting 체크
            if (!checkSharedPageAccess(clientIp, token, isValid)) {
                return res.status(429).json({ error: "너무 많은 요청입니다. 잠시 후 다시 시도해주세요." });
            }

            if (!isValid) {
                console.log(`[공개 페이지 접근] 실패 - 토큰: ${token.substring(0, 8)}..., IP: ${clientIp}`);
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const pageId = publishRows[0].page_id;

            const [pageRows] = await pool.execute(
                `SELECT id, title, content, icon, cover_image, cover_position
                 FROM pages
                 WHERE id = ? AND is_encrypted = 0`,
                [pageId]
            );

            if (!pageRows.length) {
                console.log(`[공개 페이지 접근] 실패 - 페이지 없음, 토큰: ${token.substring(0, 8)}..., IP: ${clientIp}`);
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];

            // 성공 로깅
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
