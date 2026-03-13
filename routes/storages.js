'use strict';

const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const erl = require('express-rate-limit');
const rateLimit = erl.rateLimit || erl;
const { ipKeyGenerator } = erl;

const wrappedDekExportLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false
});

module.exports = (dependencies) => {
    const {
        pool,
        storagesRepo,
        bootstrapRepo,
        userKeysRepo,
        storageShareKeysRepo,
        authMiddleware,
        csrfMiddleware,
        toIsoString,
        logError,
        formatDateForDb,
        wsKickUserFromStorage,
        getClientIpFromRequest,
        requireRecentReauth
    } = dependencies;

    const USER_SEARCH_CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
    const USER_SEARCH_SAFE_RE = /^[가-힣A-Za-z0-9._-]+$/u;

    function isValidBase64(s, maxLen = 4096) {
        if (typeof s !== 'string' || !s) return false;
        if (s.length > maxLen) return false;
        return /^[A-Za-z0-9+/=_-]+$/.test(s);
    }

    function normalizeUserSearchQuery(input) {
        if (typeof input !== 'string') return null;

        const normalized = (typeof input.normalize === 'function'
            ? input.normalize('NFKC')
            : input
        ).trim();

        if (normalized.length < 3 || normalized.length > 64) return null;
        if (USER_SEARCH_CONTROL_CHARS_RE.test(normalized)) return null;
        if (!USER_SEARCH_SAFE_RE.test(normalized)) return null;

        return normalized;
    }

    function userAndIpRateKey(req) {
        const rawIp = (typeof getClientIpFromRequest === 'function' ? getClientIpFromRequest(req) : (req.ip || '')) || '0.0.0.0';
        const ipPart = ipKeyGenerator(rawIp);
        const userPart = req.user?.id ? String(req.user.id) : 'anon';
        return `${userPart}:${ipPart}`;
    }

    const collaboratorUserSearchLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 30,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: userAndIpRateKey,
        message: { error: '사용자 검색 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.' }
    });

    const collaboratorMutationLimiter = rateLimit({
        windowMs: 10 * 60 * 1000,
        max: 20,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: userAndIpRateKey,
        message: { error: '협업 권한 변경 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.' }
    });

    const destructiveStorageLimiter = rateLimit({
        windowMs: 10 * 60 * 1000,
        max: 10,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: userAndIpRateKey,
        message: { error: '민감한 저장소 변경 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.' }
    });

    const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
    const HTML_META_CHARS_RE = /[<>&]/;
    function validateStorageName(name) {
        if (typeof name !== 'string') return null;
        const trimmed = name.trim();
        if (!trimmed) return null;
        if (trimmed.length > 128) return { ok: false, error: '저장소 이름은 128자 이내로 입력해주세요.' };
        if (CONTROL_CHARS_RE.test(trimmed) || HTML_META_CHARS_RE.test(trimmed)) return { ok: false, error: '저장소 이름에 <, >, &, 제어문자는 사용할 수 없습니다.' };
        return { ok: true, value: trimmed };
    }

    function requireStorageOwner(storage, res, actionText = '참여자를 관리할') {
        if (!storage) {
            res.status(404).json({ error: '저장소를 찾을 수 없습니다.' });
            return false;
        }
        if (!storage.is_owner) {
            res.status(403).json({ error: `저장소 소유자만 ${actionText} 권한이 있습니다.` });
            return false;
        }
        return true;
    }

    async function validateStorageRekeyShares(storageId, ownerUserId, shares, excludedUserId = null) {
        const collaborators = await storagesRepo.listCollaborators(storageId);
        const activeUserIds = new Set();
        activeUserIds.add(Number(ownerUserId));
        for (const c of collaborators) {
            const uid = Number(c.user_id);
            if (excludedUserId && uid === Number(excludedUserId)) continue;
            activeUserIds.add(uid);
        }

        const shareUserIds = new Set(shares.map(s => Number(s.userId)));
        
        for (const uid of activeUserIds) {
            if (!shareUserIds.has(uid)) return { ok: false, error: `사용자 ID ${uid}에 대한 공유 키가 누락되었습니다.` };
        }
        
        if (shareUserIds.size !== activeUserIds.size) return { ok: false, error: '공유 키 목록에 허용되지 않은 사용자가 포함되어 있습니다.' };

        for (const s of shares) {
            const uid = Number(s.userId);
            const keyPair = await userKeysRepo.getKeyPairByKid(s.wrappingKid);
            if (!keyPair || Number(keyPair.user_id) !== uid) return { ok: false, error: `사용자 ID ${uid}의 wrappingKid가 올바르지 않습니다.` };
        }

        return { ok: true };
    }

    router.get('/', authMiddleware, async (req, res) => {
        try {
            const storages = await storagesRepo.listStoragesForUser(req.user.id);
            res.json(storages.map(s => ({
                id: s.id,
                name: s.name,
                sortOrder: s.sort_order,
                is_owner: s.is_owner,
                permission: s.permission,
                owner_name: s.owner_name,
                is_encrypted: s.is_encrypted,
                dek_version: s.dek_version,
                createdAt: toIsoString(s.created_at),
                updatedAt: toIsoString(s.updated_at)
            })));
        } catch (error) {
            logError('GET /api/storages', error);
            res.status(500).json({ error: '저장소 목록을 불러오지 못했습니다.' });
        }
    });

    router.get('/:id/data', authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!storage) return res.status(404).json({ error: '저장소를 찾을 수 없거나 권한이 없습니다.' });

            const { pageRows } = await bootstrapRepo.getStorageData(userId, storageId);

            const pages = (pageRows || []).map((row) => ({
                id: row.id,
                title: row.title || "제목 없음",
                updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id,
                sortOrder: row.sort_order,
                storageId: row.storage_id,
                isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id,
                icon: row.icon || null,
                coverImage: row.cover_image || null,
                coverPosition: row.cover_position || 50,
                horizontalPadding: row.horizontal_padding || null
            }));

            res.json({ pages });
        } catch (error) {
            logError('GET /api/storages/:id/data', error);
            res.status(500).json({ error: '저장소 데이터를 불러오지 못했습니다.' });
        }
    });

    router.post('/', authMiddleware, csrfMiddleware, async (req, res) => {
        let connection;
        try {
            const { name, isEncrypted, encryptionSalt, dekVersion, wrappedDek, wrappingKid } = req.body;
            const check = validateStorageName(name);
            if (!check) return res.status(400).json({ error: '저장소 이름을 입력해주세요.' });
            if (!check.ok) return res.status(400).json({ error: check.error });
            const storageName = check.value;

            const useDekV1 = isEncrypted && Number(dekVersion) === 1;

            if (isEncrypted) {
                if (!useDekV1) return res.status(400).json({ error: '레거시 암호화 저장소는 더 이상 생성할 수 없습니다.' });
                if (!isValidBase64(encryptionSalt, 64)) return res.status(400).json({ error: '유효하지 않은 encryptionSalt 입니다.' });
                if (!isValidBase64(wrappedDek, 4096) || !wrappingKid) return res.status(400).json({ error: '암호화 저장소 생성 정보가 부족하거나 올바르지 않습니다.' });

                const keyPair = await userKeysRepo.getKeyPairByKid(wrappingKid);
                if (!keyPair || Number(keyPair.user_id) !== Number(req.user.id)) return res.status(400).json({ error: '유효하지 않은 wrappingKid 입니다.' });
            }

            const userId = req.user.id;
            const now = new Date();
            const nowStr = formatDateForDb(now);
            const id = 'stg-' + now.getTime() + '-' + crypto.randomBytes(4).toString('hex');
            const sortOrder = await storagesRepo.getNextSortOrder(userId);

            connection = await pool.getConnection();
            await connection.beginTransaction();

            const storage = await storagesRepo.createStorage({
                userId,
                id,
                name: storageName,
                sortOrder,
                createdAt: nowStr,
                updatedAt: nowStr,
                isEncrypted: isEncrypted ? 1 : 0,
                encryptionSalt: isEncrypted ? encryptionSalt : null,
                encryptionCheck: null,
                dekVersion: useDekV1 ? 1 : 0
            }, connection);

            if (useDekV1) {
                await storageShareKeysRepo.upsertWrappedDek({
                    storageId: id,
                    sharedWithUserId: userId,
                    wrappedDek,
                    wrappingKid,
                    ephemeralPublicKey: null,
                    createdAt: nowStr
                }, connection);
            }

            await connection.commit();

            res.json({
                ...storage,
                is_encrypted: isEncrypted ? 1 : 0,
                encryption_salt: isEncrypted ? encryptionSalt : null,
                encryption_check: null,
                dek_version: useDekV1 ? 1 : 0,
                is_owner: 1,
                owner_name: req.user.username,
                createdAt: now.toISOString(),
                updatedAt: now.toISOString()
            });
        } catch (error) {
            if (connection) await connection.rollback();
            logError('POST /api/storages', error);
            res.status(500).json({ error: '저장소 생성에 실패했습니다.' });
        } finally {
            if (connection) connection.release();
        }
    });

    router.put('/:id', authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!requireStorageOwner(storage, res, '수정할')) return;

            const { name } = req.body;
            const check = validateStorageName(name);
            if (!check) return res.status(400).json({ error: '저장소 이름을 입력해주세요.' });
            if (!check.ok) return res.status(400).json({ error: check.error });
            const storageName = check.value;

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await storagesRepo.updateStorage(userId, storageId, {
                name: storageName,
                updatedAt: nowStr
            });

            res.json({ success: true });
        } catch (error) {
            logError('PUT /api/storages/:id', error);
            res.status(500).json({ error: '저장소 수정에 실패했습니다.' });
        }
    });

    router.delete('/:id', authMiddleware, csrfMiddleware, requireRecentReauth(10 * 60 * 1000), destructiveStorageLimiter, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;

            const storages = await storagesRepo.listStoragesForUser(userId);
            const ownedStorages = storages.filter(s => s.is_owner);

            const storageToDelete = storages.find(s => s.id === storageId);
            if (storageToDelete && storageToDelete.is_owner && ownedStorages.length <= 1) return res.status(400).json({ error: '최소 하나의 소유한 저장소는 유지해야 합니다.' });

            if (storageToDelete && !storageToDelete.is_owner) {
                await storagesRepo.removeCollaborator(storageId, userId);
                res.json({ success: true });
            } else {
                const result = await storagesRepo.safeDeleteStoragePreservingCollaborators(userId, storageId);
                if (!result?.ok) return res.status(404).json({ error: '저장소를 찾을 수 없거나 권한이 없습니다.' });
                res.json({ success: true, transferred: result.transferred });
            }
        } catch (error) {
            logError('DELETE /api/storages/:id', error);
            res.status(500).json({ error: '저장소 삭제에 실패했습니다.' });
        }
    });

    router.get('/:id/users/search', authMiddleware, collaboratorUserSearchLimiter, async (req, res) => {
        try {
            const storageId = req.params.id;
            const storage = await storagesRepo.getStorageByIdForUser(req.user.id, storageId);
            if (!requireStorageOwner(storage, res)) return;

            const normalizedQuery = normalizeUserSearchQuery(req.query.q);
            if (!normalizedQuery) return res.json([]);

            const user = await dependencies.usersRepo.findUserByExactUsername(
                normalizedQuery,
                req.user.id
            );
            res.json(user ? [user] : []);
        } catch (error) {
            logError('GET /api/storages/:id/users/search', error);
            res.status(500).json({ error: '사용자 검색 중 오류가 발생했습니다.' });
        }
    });

    router.get('/:id/collaborators', authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!requireStorageOwner(storage, res, '참여자 목록을 조회할')) return;

            const collaborators = await storagesRepo.listCollaborators(storageId);
            res.json(collaborators);
        } catch (error) {
            logError('GET /api/storages/:id/collaborators', error);
            res.status(500).json({ error: '참여자 목록을 불러오지 못했습니다.' });
        }
    });

    router.post('/:id/my-wrapped-dek', authMiddleware, csrfMiddleware, requireRecentReauth(5 * 60 * 1000), wrappedDekExportLimiter, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;
            const { purpose } = req.body || {};

            if (purpose !== 'unlock-storage') return res.status(400).json({ error: 'purpose=unlock-storage 가 필요합니다.' });

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!storage) return res.status(404).json({ error: '저장소를 찾을 수 없습니다.' });

            if (Number(storage.is_encrypted) !== 1 || Number(storage.dek_version) !== 1) return res.status(400).json({ error: '이 저장소는 DEK v1 암호화를 사용하지 않습니다.' });

            const wrappedDekRecord = await storageShareKeysRepo.getWrappedDek(storageId, userId);
            if (!wrappedDekRecord) return res.status(404).json({ error: '이 저장소에 대한 wrapped DEK 를 찾을 수 없습니다.' });

            res.setHeader('Cache-Control', 'no-store');
            res.json({
                wrappedDek: wrappedDekRecord.wrapped_dek,
                wrappingKid: wrappedDekRecord.wrapping_kid,
                ephemeralPublicKey: wrappedDekRecord.ephemeral_public_key,
                encryptionSalt: storage.encryption_salt
            });
        } catch (error) {
            logError('POST /api/storages/:id/my-wrapped-dek', error);
            res.status(500).json({ error: 'wrapped DEK 를 불러오지 못했습니다.' });
        }
    });

    router.post('/:id/collaborators', authMiddleware, csrfMiddleware, requireRecentReauth(5 * 60 * 1000), collaboratorMutationLimiter, async (req, res) => {
        let connection = null;
        try {
            const userId = req.user.id;
            const storageId = req.params.id;
            const { targetUserId, permission, wrappedDek, wrappingKid, ephemeralPublicKey } = req.body;

            if (!targetUserId) return res.status(400).json({ error: '참여할 사용자를 지정해주세요.' });

            const normalizedPermission = String(permission || 'READ').toUpperCase();
            if (!['READ', 'EDIT', 'ADMIN'].includes(normalizedPermission)) return res.status(400).json({ error: '유효하지 않은 권한입니다. (READ, EDIT 또는 ADMIN)' });

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!requireStorageOwner(storage, res)) return;

            if (Number(storage.is_encrypted) === 1 && Number(storage.dek_version) !== 1) return res.status(400).json({ error: '이 암호화 저장소는 공유를 지원하지 않습니다.' });

            if (String(targetUserId) === String(storage.owner_id)) return res.status(400).json({ error: '저장소 소유자는 별도 참여자로 추가할 수 없습니다.' });
            if (String(targetUserId) === String(userId)) return res.status(400).json({ error: '자기 자신에게 협업 권한을 다시 부여할 수 없습니다.' });

            if (Number(storage.is_encrypted) === 1 && Number(storage.dek_version) === 1) {
                if (!wrappedDek || !wrappingKid) return res.status(400).json({ error: '암호화 저장소 협업에 필요한 키 정보가 부족합니다.' });
                if (typeof wrappedDek !== 'string' || typeof wrappingKid !== 'string') return res.status(400).json({ error: '키 정보 형식이 올바르지 않습니다.' });

                const keyPair = await userKeysRepo.getKeyPairByKid(wrappingKid);
                if (!keyPair || Number(keyPair.user_id) !== Number(targetUserId)) return res.status(400).json({ error: 'wrappingKid가 대상 사용자 키가 아닙니다.' });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            connection = await pool.getConnection();
            await connection.beginTransaction();

            await storagesRepo.addCollaborator({
                storageId,
                ownerUserId: storage.owner_id,
                sharedWithUserId: targetUserId,
                permission: normalizedPermission,
                createdAt: nowStr,
                updatedAt: nowStr
            }, connection);

            if (Number(storage.is_encrypted) === 1 && Number(storage.dek_version) === 1) {
                await storageShareKeysRepo.upsertWrappedDek({
                    storageId,
                    sharedWithUserId: targetUserId,
                    wrappedDek,
                    wrappingKid,
                    ephemeralPublicKey: ephemeralPublicKey || null,
                    createdAt: nowStr
                }, connection);
            }

            await connection.commit();

            try { if (typeof wsKickUserFromStorage === 'function') wsKickUserFromStorage(storageId, targetUserId, 1008, '저장소 권한이 변경되었습니다.'); } catch (e) {}

            res.json({ success: true });
        } catch (error) {
            try { if (connection) await connection.rollback(); } catch (_) {}
            logError('POST /api/storages/:id/collaborators', error);
            res.status(500).json({ error: '참여자 추가에 실패했습니다.' });
        } finally {
            try { if (connection) connection.release(); } catch (_) {}
        }
    });

    router.delete('/:id/collaborators/:targetUserId', authMiddleware, csrfMiddleware, requireRecentReauth(5 * 60 * 1000), collaboratorMutationLimiter, async (req, res) => {
        let connection = null;
        try {
            const userId = req.user.id;
            const storageId = req.params.id;
            const targetUserId = req.params.targetUserId;
            const { encryptionSalt, dekVersion, shares } = req.body || {};

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!requireStorageOwner(storage, res)) return;

            if (String(targetUserId) === String(storage.owner_id)) return res.status(400).json({ error: '저장소 소유자는 제거할 수 없습니다.' });
            if (String(targetUserId) === String(userId)) return res.status(400).json({ error: '저장소 소유자는 자기 자신을 제거할 수 없습니다.' });

            connection = await pool.getConnection();
            await connection.beginTransaction();

            await storagesRepo.removeCollaborator(storageId, targetUserId, connection);

            if (Number(storage.is_encrypted) === 1 && Number(storage.dek_version) === 1) {
                if (!isValidBase64(encryptionSalt, 64) || Number(dekVersion) !== 1 || !Array.isArray(shares) || shares.length === 0) {
                    await connection.rollback();
                    return res.status(409).json({ error: '암호화 저장소의 협업 해제에는 재암호화(rekey) 정보가 필요합니다.' });
                }

                const filteredShares = shares.filter(s => Number(s.userId) !== Number(targetUserId));
                const v = await validateStorageRekeyShares(storageId, storage.owner_id, filteredShares, targetUserId);
                if (!v.ok) {
                    await connection.rollback();
                    return res.status(400).json({ error: v.error });
                }

                await storagesRepo.rekeyStorage({
                    userId,
                    storageId,
                    encryptionSalt,
                    dekVersion,
                    shares: filteredShares
                }, connection);
            } else {
                await connection.execute(
                    `DELETE FROM storage_share_keys WHERE storage_id = ? AND shared_with_user_id = ?`,
                    [storageId, targetUserId]
                );
            }

            await connection.commit();

            try { if (typeof wsKickUserFromStorage === 'function') wsKickUserFromStorage(storageId, targetUserId, 1008, '저장소 접근 권한이 회수되었습니다.'); } catch (e) {}

            res.json({ success: true });
        } catch (error) {
            try { if (connection) await connection.rollback(); } catch (_) {}
            logError('DELETE /api/storages/:id/collaborators/:targetUserId', error);
            res.status(500).json({ error: '참여자 삭제에 실패했습니다.' });
        } finally {
            try { if (connection) connection.release(); } catch (_) {}
        }
    });

    router.post('/:id/rekey', authMiddleware, csrfMiddleware, requireRecentReauth(5 * 60 * 1000), destructiveStorageLimiter, async (req, res) => {
        let connection = null;
        try {
            const userId = req.user.id;
            const storageId = req.params.id;
            const { encryptionSalt, dekVersion, shares } = req.body;

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!requireStorageOwner(storage, res, '재암호화할')) return;

            if (Number(storage.is_encrypted) !== 1) return res.status(400).json({ error: '암호화되지 않은 저장소는 재암호화할 수 없습니다.' });
            if (Number(dekVersion) !== 1) return res.status(400).json({ error: 'DEK v1 버전으로만 재암호화가 가능합니다.' });
            if (!isValidBase64(encryptionSalt, 64)) return res.status(400).json({ error: '유효하지 않은 encryptionSalt 입니다.' });

            if (!Array.isArray(shares)) return res.status(400).json({ error: '공유 키 정보(shares)가 필요합니다.' });
            const v = await validateStorageRekeyShares(storageId, storage.owner_id, shares);
            if (!v.ok) return res.status(400).json({ error: v.error });

            for (const s of shares) {
                if (!s.userId || !isValidBase64(s.wrappedDek, 4096) || !s.wrappingKid) {
                    return res.status(400).json({ error: '유효하지 않은 공유 키 정보가 포함되어 있습니다.' });
                }
            }

            connection = await pool.getConnection();
            await connection.beginTransaction();

            await storagesRepo.rekeyStorage({
                userId,
                storageId,
                encryptionSalt,
                dekVersion: Number(dekVersion),
                shares
            }, connection);

            await connection.commit();
            res.json({ success: true });
        } catch (error) {
            if (connection) await connection.rollback();
            logError('POST /api/storages/:id/rekey', error);
            res.status(500).json({ error: '저장소 재암호화에 실패했습니다.' });
        } finally {
            if (connection) connection.release();
        }
    });

    return router;
};
