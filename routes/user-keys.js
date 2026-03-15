const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const erl = require('express-rate-limit');
const rateLimit = erl.rateLimit || erl;

const SENSITIVE_EXPORT_MAX_AGE_MS = 20 * 1000;

const privateKeyExportLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 5,
    standardHeaders: true,
    legacyHeaders: false
});

module.exports = (dependencies) => {
    const {
        userKeysRepo,
        storagesRepo,
        authMiddleware,
        csrfMiddleware,
        formatDateForDb,
        logError,
        requireRecentReauth,
        requireSensitiveStepUp,
        requireStrongStepUp
    } = dependencies;

    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

    function isValidBase64(str) {
        try {
            return Buffer.from(str, 'base64').toString('base64') === str;
        } catch (e) {
            return false;
        }
    }

    router.get('/me', authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const keyPairs = await userKeysRepo.listMyKeyPairs(userId);
            res.setHeader('Cache-Control', 'no-store');
            res.json(
                keyPairs.map(({ encrypted_private_key, key_wrap_salt, ...rest }) => ({
                    ...rest,
                    hasEncryptedPrivateKey: Boolean(encrypted_private_key),
                }))
            );
        } catch (error) {
            logError('GET /api/user-keys/me', error);
            res.status(500).json({ error: '키 쌍 조회에 실패했습니다.' });
        }
    });

    router.post('/:kid/export-ticket', authMiddleware, csrfMiddleware, requireStrongStepUp({ maxAgeMs: SENSITIVE_EXPORT_MAX_AGE_MS, requireMfaIfEnabled: true }), privateKeyExportLimiter, async (req, res) => {
        try {
            const { issueActionTicket, getSessionFromRequest } = dependencies;
            const userId = req.user.id;
            const kid = req.params.kid;
            if (!UUID_REGEX.test(kid)) return res.status(400).json({ error: 'kid 은 유효한 UUID 형식이어야 합니다.' });

            const keyPair = await userKeysRepo.getKeyPairByKid(kid);
            if (!keyPair) return res.status(404).json({ error: '키 쌍을 찾을 수 없습니다.' });
            if (Number(keyPair.user_id) !== Number(userId)) return res.status(403).json({ error: '이 키 쌍을 조회할 권한이 없습니다.' });

            const session = await getSessionFromRequest(req);
            if (!session) return res.status(401).json({ error: '세션이 만료되었습니다.' });

            const ticket = await issueActionTicket(session.id, 'export-private-key', kid, {
    userAgent: req.headers['user-agent'] || '',
    clientIp: getClientIpFromRequest(req)
});
            res.json({ ok: true, ticket });
        } catch (error) {
            logError('POST /api/user-keys/:kid/export-ticket', error);
            res.status(500).json({ error: '티켓 발급에 실패했습니다.' });
        }
    });

    router.post('/:kid/export-private', authMiddleware, csrfMiddleware, requireStrongStepUp({ maxAgeMs: SENSITIVE_EXPORT_MAX_AGE_MS, requireMfaIfEnabled: true }), async (req, res) => {
        try {
            const { consumeActionTicket, getSessionFromRequest } = dependencies;
            const userId = req.user.id;
            const kid = req.params.kid;
            const { ticket } = req.body;

            if (!ticket) return res.status(400).json({ error: '티켓이 필요합니다.' });
            if (!UUID_REGEX.test(kid)) return res.status(400).json({ error: 'kid 은 유효한 UUID 형식이어야 합니다.' });

            const session = await getSessionFromRequest(req);
            if (!session) return res.status(401).json({ error: '세션이 만료되었습니다.' });

            const valid = await consumeActionTicket(session.id, 'export-private-key', kid, ticket, {
    userAgent: req.headers['user-agent'] || '',
    clientIp: getClientIpFromRequest(req)
});
            if (!valid) return res.status(403).json({ error: '유효하지 않거나 만료된 티켓입니다.' });

            const keyPair = await userKeysRepo.getKeyPairByKid(kid);
            if (!keyPair) return res.status(404).json({ error: '키 쌍을 찾을 수 없습니다.' });
            if (Number(keyPair.user_id) !== Number(userId)) return res.status(403).json({ error: '이 키 쌍을 조회할 권한이 없습니다.' });

            res.setHeader('Cache-Control', 'no-store');
            return res.json({
                kid: keyPair.kid,
                encryptedPrivateKey: keyPair.encrypted_private_key,
                keyWrapSalt: keyPair.key_wrap_salt,
            });
        } catch (error) {
            logError('POST /api/user-keys/:kid/export-private', error);
            res.status(500).json({ error: '개인키 export 에 실패했습니다.' });
        }
    });

    router.get('/public/:userId', authMiddleware, requireSensitiveStepUp({ maxAgeMs: 5 * 60 * 1000, requireMfaIfEnabled: true }), async (req, res) => {
        try {
            const targetUserId = req.params.userId;
            const storageId = req.query.storageId;
            const limit = req.query.limit || 1;
            if (!storageId) return res.status(400).json({ error: 'storageId 가 필요합니다.' });

            const storage = await storagesRepo.getStorageByIdForUser(req.user.id, storageId);
            if (!storage) return res.status(404).json({ error: '저장소를 찾을 수 없거나 권한이 없습니다.' });
            if (!storage.is_owner) return res.status(403).json({ error: '저장소 소유자만 공개키를 조회할 수 있습니다.' });

            const targetStorage = await storagesRepo.getStorageByIdForUser(targetUserId, storageId);
            if (!targetStorage) return res.status(404).json({ error: '해당 사용자는 이 저장소의 협업 대상이 아닙니다.' });

            const publicKeys = await userKeysRepo.listLimitedPublicKeysByUserId(targetUserId, limit);
            res.setHeader('Cache-Control', 'no-store');
            res.json(publicKeys.map(k => ({
                kid: k.kid,
                publicKeySpki: k.public_key_spki
            })));
        } catch (error) {
            logError('GET /api/user-keys/public/:userId', error);
            res.status(500).json({ error: '공개키 조회에 실패했습니다.' });
        }
    });

    router.post('/', authMiddleware, csrfMiddleware, requireSensitiveStepUp({ maxAgeMs: 5 * 60 * 1000, requireMfaIfEnabled: true }), async (req, res) => {
        try {
            const userId = req.user.id;
            const { kid, publicKeySpki, encryptedPrivateKey, keyWrapSalt, deviceLabel } = req.body;

            if (!kid || typeof kid !== 'string' || !UUID_REGEX.test(kid)) return res.status(400).json({ error: 'kid은 유효한 UUID 형식이어야 합니다.' });
            if (!publicKeySpki || typeof publicKeySpki !== 'string' || !isValidBase64(publicKeySpki) || publicKeySpki.length > 4096) return res.status(400).json({ error: 'publicKeySpki 가 유효하지 않습니다.' });
            if (!encryptedPrivateKey || typeof encryptedPrivateKey !== 'string' || !isValidBase64(encryptedPrivateKey) || encryptedPrivateKey.length > 8192) return res.status(400).json({ error: 'encryptedPrivateKey 가 유효하지 않습니다.' });
            if (!keyWrapSalt || typeof keyWrapSalt !== 'string' || !isValidBase64(keyWrapSalt) || keyWrapSalt.length > 256) return res.status(400).json({ error: 'keyWrapSalt 가 유효하지 않습니다.' });
            if (deviceLabel && (typeof deviceLabel !== 'string' || deviceLabel.length > 100)) return res.status(400).json({ error: 'deviceLabel 이 너무 깁니다.' });

            const existing = await userKeysRepo.getKeyPairByKid(kid);
            if (existing) return res.status(409).json({ error: '이미 존재하는 kid입니다.' });

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await userKeysRepo.createKeyPair({
                kid,
                userId,
                publicKeySpki,
                encryptedPrivateKey,
                keyWrapSalt,
                deviceLabel: deviceLabel || null,
                createdAt: nowStr
            });

            res.setHeader('Cache-Control', 'no-store');
            res.status(201).json({ success: true, kid });
        } catch (error) {
            logError('POST /api/user-keys', error);
            res.status(500).json({ error: '키 쌍 등록에 실패했습니다.' });
        }
    });

    router.delete('/:kid', authMiddleware, csrfMiddleware, requireSensitiveStepUp({ maxAgeMs: 5 * 60 * 1000, requireMfaIfEnabled: true }), async (req, res) => {
        try {
            const userId = req.user.id;
            const kid = req.params.kid;
            if (!UUID_REGEX.test(kid)) return res.status(400).json({ error: 'kid은 유효한 UUID 형식이어야 합니다.' });

            const keyPair = await userKeysRepo.getKeyPairByKid(kid);
            if (!keyPair) return res.status(404).json({ error: '키 쌍을 찾을 수 없습니다.' });
            if (Number(keyPair.user_id) !== Number(userId)) return res.status(403).json({ error: '이 키 쌍을 삭제할 권한이 없습니다.' });

            await userKeysRepo.deleteKeyPair(userId, kid);
            res.json({ success: true });
        } catch (error) {
            logError('DELETE /api/user-keys/:kid', error);
            res.status(500).json({ error: '키 쌍 삭제에 실패했습니다.' });
        }
    });

    return router;
};
