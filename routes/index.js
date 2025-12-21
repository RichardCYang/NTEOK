const express = require('express');
const path = require('path');
const router = express.Router();

/**
 * Static & Debug Routes
 *
 * 이 파일은 정적 페이지 및 디버그 라우트를 처리합니다.
 * - 메인 페이지, 로그인 페이지, 회원가입 페이지
 * - 앱 아이콘
 * - 헬스 체크 API
 */

module.exports = (dependencies) => {
    const { getSessionFromRequest, pool, logError, toIsoString } = dependencies;

    /**
     * 메인 화면
     * GET /
     */
    router.get("/", (req, res) => {
        const session = getSessionFromRequest(req);

        if (!session) {
            return res.redirect("/login");
        }

        return res.sendFile(path.join(__dirname, "..", "public", "index.html"));
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

        return res.sendFile(path.join(__dirname, "..", "public", "login.html"));
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

        return res.sendFile(path.join(__dirname, "..", "public", "register.html"));
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
        return res.sendFile(path.join(__dirname, "..", "public", "shared-page.html"));
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
        const clientIp = req.ip || req.socket.remoteAddress || req.headers['x-forwarded-for'] || 'unknown';

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
                content: page.content || "<p></p>",
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
