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
            if (!UUID_REGEX.test(kid)) {
                return res.status(400).json({ error: 'kid 은 유효한 UUID 형식이어야 합니다.' });
            }

            const keyPair = await userKeysRepo.getKeyPairByKid(kid);
            if (!keyPair) return res.status(404).json({ error: '키 쌍을 찾을 수 없습니다.' });
            if (Number(keyPair.user_id) !== Number(userId)) {
                return res.status(403).json({ error: '이 키 쌍을 조회할 권한이 없습니다.' });
            }

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

module.exports = (dependencies) => {
    const {
        userKeysRepo,
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
            if (!UUID_REGEX.test(kid)) {
                return res.status(400).json({ error: 'kid 은 유효한 UUID 형식이어야 합니다.' });
            }

            const keyPair = await userKeysRepo.getKeyPairByKid(kid);
            if (!keyPair) return res.status(404).json({ error: '키 쌍을 찾을 수 없습니다.' });
            if (Number(keyPair.user_id) !== Number(userId)) {
                return res.status(403).json({ error: '이 키 쌍을 조회할 권한이 없습니다.' });
            }

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

    // GET /api/user-keys/public/:userId - Get public keys for another user
    router.get('/public/:userId', authMiddleware, async (req, res) => {
        try {
            const targetUserId = req.params.userId;
            const publicKeys = await userKeysRepo.listPublicKeysByUserId(targetUserId);
            res.json(publicKeys);
        } catch (error) {
            logError('GET /api/user-keys/public/:userId', error);
            res.status(500).json({ error: '공개키 조회에 실패했습니다.' });
        }
    });

    // POST /api/user-keys - Create a new key pair
    router.post('/', authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const { kid, publicKeySpki, encryptedPrivateKey, keyWrapSalt, deviceLabel } = req.body;

            // Input validation
            if (!kid || typeof kid !== 'string' || !UUID_REGEX.test(kid)) {
                return res.status(400).json({ error: 'kid은 유효한 UUID 형식이어야 합니다.' });
            }

            if (!publicKeySpki || typeof publicKeySpki !== 'string') {
                return res.status(400).json({ error: 'publicKeySpki는 필수입니다.' });
            }
            if (!isValidBase64(publicKeySpki) || publicKeySpki.length > 4096) {
                return res.status(400).json({ error: 'publicKeySpki는 Base64 형식이고 4096자 이하여야 합니다.' });
            }

            if (!encryptedPrivateKey || typeof encryptedPrivateKey !== 'string') {
                return res.status(400).json({ error: 'encryptedPrivateKey는 필수입니다.' });
            }
            if (!isValidBase64(encryptedPrivateKey) || encryptedPrivateKey.length > 8192) {
                return res.status(400).json({ error: 'encryptedPrivateKey는 Base64 형식이고 8192자 이하여야 합니다.' });
            }

            if (!keyWrapSalt || typeof keyWrapSalt !== 'string') {
                return res.status(400).json({ error: 'keyWrapSalt는 필수입니다.' });
            }
            if (!isValidBase64(keyWrapSalt) || keyWrapSalt.length > 256) {
                return res.status(400).json({ error: 'keyWrapSalt는 Base64 형식이고 256자 이하여야 합니다.' });
            }

            if (deviceLabel && (typeof deviceLabel !== 'string' || deviceLabel.length > 100)) {
                return res.status(400).json({ error: 'deviceLabel은 문자열이고 100자 이하여야 합니다.' });
            }

            // Check if kid already exists
            const existing = await userKeysRepo.getKeyPairByKid(kid);
            if (existing) {
                return res.status(409).json({ error: '이미 존재하는 kid입니다.' });
            }

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

    // DELETE /api/user-keys/:kid - Delete a key pair (must be owner)
    router.delete('/:kid', authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const kid = req.params.kid;

            // Validate kid format
            if (!UUID_REGEX.test(kid)) {
                return res.status(400).json({ error: 'kid은 유효한 UUID 형식이어야 합니다.' });
            }

            // Check if key exists and belongs to user
            const keyPair = await userKeysRepo.getKeyPairByKid(kid);
            if (!keyPair) {
                return res.status(404).json({ error: '키 쌍을 찾을 수 없습니다.' });
            }
            if (Number(keyPair.user_id) !== Number(userId)) {
                return res.status(403).json({ error: '이 키 쌍을 삭제할 권한이 없습니다.' });
            }

            await userKeysRepo.deleteKeyPair(userId, kid);
            res.json({ success: true });
        } catch (error) {
            logError('DELETE /api/user-keys/:kid', error);
            res.status(500).json({ error: '키 쌍 삭제에 실패했습니다.' });
        }
    });

    return router;
};
