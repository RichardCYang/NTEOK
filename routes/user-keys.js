const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const erl = require('express-rate-limit');
const rateLimit = erl.rateLimit || erl;

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
        requireRecentReauth
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

    router.post('/:kid/export-private', authMiddleware, csrfMiddleware, requireRecentReauth(5 * 60 * 1000), privateKeyExportLimiter, async (req, res) => {
        try {
            const userId = req.user.id;
            const kid = req.params.kid;
            if (!UUID_REGEX.test(kid)) return res.status(400).json({ error: 'kid 은 유효한 UUID 형식이어야 합니다.' });

            const keyPair = await userKeysRepo.getKeyPairByKid(kid);
            if (!keyPair) return res.status(404).json({ error: '키 쌍을 찾을 수 없습니다.' });
            if (Number(keyPair.user_id) !== Number(userId)) return res.status(403).json({ error: '이 키 쌍을 조회할 권한이 없습니다.' });

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

    router.get('/public/:userId', authMiddleware, async (req, res) => {
        try {
            const targetUserId = req.params.userId;
            const storageId = req.query.storageId;
            if (!storageId) return res.status(400).json({ error: 'storageId 가 필요합니다.' });

            const storage = await storagesRepo.getStorageByIdForUser(req.user.id, storageId);
            if (!storage) return res.status(404).json({ error: '저장소를 찾을 수 없거나 권한이 없습니다.' });
            if (!storage.is_owner && storage.permission !== 'ADMIN') return res.status(403).json({ error: '저장소 소유자 또는 관리자만 공개키를 조회할 수 있습니다.' });

            const publicKeys = await userKeysRepo.listPublicKeysByUserId(targetUserId);
            res.json(publicKeys.map(k => ({
                kid: k.kid,
                publicKeySpki: k.public_key_spki,
                deviceLabel: k.device_label
            })));
        } catch (error) {
            logError('GET /api/user-keys/public/:userId', error);
            res.status(500).json({ error: '공개키 조회에 실패했습니다.' });
        }
    });

    router.post('/', authMiddleware, csrfMiddleware, async (req, res) => {
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

            res.status(201).json({ success: true, kid });
        } catch (error) {
            logError('POST /api/user-keys', error);
            res.status(500).json({ error: '키 쌍 등록에 실패했습니다.' });
        }
    });

    router.delete('/:kid', authMiddleware, csrfMiddleware, async (req, res) => {
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
