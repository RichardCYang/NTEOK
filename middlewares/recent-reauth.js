module.exports = ({ getSessionFromRequest }) => {
    function requireRecentReauth(maxAgeMs = 10 * 60 * 1000) {
        return async (req, res, next) => {
            const session = await getSessionFromRequest(req);
            if (!session) return res.status(401).json({ error: "인증이 필요합니다." });
            const effectiveStepUpAt = session.lastSensitiveStepUpAt || session.lastStepUpAt || 0;
            if (!effectiveStepUpAt || (Date.now() - effectiveStepUpAt) > maxAgeMs) {
                return res.status(403).json({
                    error: "민감한 작업 전 최근 재인증이 필요합니다.",
                    code: "RECENT_REAUTH_REQUIRED"
                });
            }
            req.currentSession = session;
            next();
        };
    }

    function requireSensitiveStepUp({ maxAgeMs = 5 * 60 * 1000, requireMfaIfEnabled = true } = {}) {
        return async (req, res, next) => {
            const session = await getSessionFromRequest(req);
            if (!session) return res.status(401).json({ error: "인증이 필요합니다." });

            const sensitiveStepUpAt = session.lastSensitiveStepUpAt || 0;
            const tooOld = !sensitiveStepUpAt || (Date.now() - sensitiveStepUpAt) > maxAgeMs;
            const weakForMfaAccount =
                requireMfaIfEnabled &&
                session.accountHasMfa === true &&
                session.lastStepUpMethod !== 'mfa';

            if (tooOld || weakForMfaAccount) {
                return res.status(403).json({
                    error: "민감한 작업 전 명시적 재인증이 필요합니다.",
                    code: "SENSITIVE_STEP_UP_REQUIRED"
                });
            }

            req.currentSession = session;
            next();
        };
    }

    function requireStrongStepUp({ maxAgeMs = 10 * 60 * 1000, requireMfaIfEnabled = true } = {}) {
        return async (req, res, next) => {
            const session = await getSessionFromRequest(req);
            if (!session) return res.status(401).json({ error: "인증이 필요합니다." });
            const effectiveStepUpAt = session.lastSensitiveStepUpAt || session.lastStepUpAt || 0;
            const tooOld = !effectiveStepUpAt || (Date.now() - effectiveStepUpAt) > maxAgeMs;
            const weakForMfaAccount =
                requireMfaIfEnabled &&
                session.accountHasMfa === true &&
                session.lastStepUpMethod !== 'mfa';

            if (tooOld || weakForMfaAccount) {
                return res.status(403).json({
                    error: "더 강한 재인증이 필요합니다.",
                    code: "STRONG_STEP_UP_REQUIRED"
                });
            }
            req.currentSession = session;
            next();
        };
    }
    return { requireRecentReauth, requireSensitiveStepUp, requireStrongStepUp };
};
