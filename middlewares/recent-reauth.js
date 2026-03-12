module.exports = ({ getSessionFromRequest }) => {
    function requireRecentReauth(maxAgeMs = 10 * 60 * 1000) {
        return async (req, res, next) => {
            const session = await getSessionFromRequest(req);
            if (!session) return res.status(401).json({ error: "인증이 필요합니다." });
            if (!session.lastStepUpAt || (Date.now() - session.lastStepUpAt) > maxAgeMs) {
                return res.status(403).json({
                    error: "민감한 작업 전 최근 재인증이 필요합니다.",
                    code: "RECENT_REAUTH_REQUIRED"
                });
            }
            req.currentSession = session;
            next();
        };
    }
    return { requireRecentReauth };
};
