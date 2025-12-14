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
    const { getSessionFromRequest } = dependencies;

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

    return router;
};
