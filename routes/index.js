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
     * 발행된 페이지 데이터 API
     * GET /api/shared/page/:token
     */
    router.get("/api/shared/page/:token", async (req, res) => {
        const token = req.params.token;

        try {
            const [publishRows] = await pool.execute(
                `SELECT page_id FROM page_publish_links
                 WHERE token = ? AND is_active = 1`,
                [token]
            );

            if (!publishRows.length) {
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
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];

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
