const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const erl = require('express-rate-limit');
const rateLimit = erl.rateLimit || erl;
const { ipKeyGenerator } = erl;

module.exports = (dependencies) => {
    const {
        storagesRepo,
        bootstrapRepo,
        authMiddleware,
        csrfMiddleware,
        toIsoString,
        logError,
        formatDateForDb,
        wsKickUserFromStorage,
        getClientIpFromRequest
    } = dependencies;

    const USER_SEARCH_CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
    const USER_SEARCH_SAFE_RE = /^[가-힣A-Za-z0-9._-]+$/u;

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

    const collaboratorUserSearchLimiter = rateLimit({
        windowMs: 60 * 1000, 
        max: 30,             
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req) => {
            const rawIp = (typeof getClientIpFromRequest === 'function'
                ? getClientIpFromRequest(req)
                : (req.ip || '')
            ) || '0.0.0.0';

            const ipPart = ipKeyGenerator(rawIp);
            const userPart = req.user?.id ? String(req.user.id) : 'anon';
            return `${userPart}:${ipPart}`;
        },
        message: {
            error: '사용자 검색 요청이 너무 많습니다. 잠시 후 다시 시도해 주세요.'
        }
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

    router.get('/', authMiddleware, async (req, res) => {
        try {
            const storages = await storagesRepo.listStoragesForUser(req.user.id);
            res.json(storages.map(s => ({
                ...s,
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
        try {
            const { name, isEncrypted, encryptionSalt, encryptionCheck } = req.body;
            const check = validateStorageName(name);
            if (!check) return res.status(400).json({ error: '저장소 이름을 입력해주세요.' });
            if (!check.ok) return res.status(400).json({ error: check.error });
            const storageName = check.value;

            if (isEncrypted) {
                if (!encryptionSalt || !encryptionCheck) return res.status(400).json({ error: '암호화 저장소 생성에 필요한 정보가 부족합니다.' });
                if (typeof encryptionSalt !== 'string' || typeof encryptionCheck !== 'string') return res.status(400).json({ error: '암호화 정보 형식이 올바르지 않습니다.' });
            }

            const userId = req.user.id;
            const now = new Date();
            const nowStr = formatDateForDb(now);
            const id = 'stg-' + now.getTime() + '-' + crypto.randomBytes(4).toString('hex');
            const sortOrder = await storagesRepo.getNextSortOrder(userId);

            const storage = await storagesRepo.createStorage({
                userId,
                id,
                name: storageName,
                sortOrder,
                createdAt: nowStr,
                updatedAt: nowStr,
                isEncrypted: isEncrypted ? 1 : 0,
                encryptionSalt: isEncrypted ? encryptionSalt : null,
                encryptionCheck: isEncrypted ? encryptionCheck : null
            });

            res.json({
                ...storage,
                is_encrypted: isEncrypted ? 1 : 0,
                isEncrypted: isEncrypted ? 1 : 0, 
                encryption_salt: isEncrypted ? encryptionSalt : null,
                encryption_check: isEncrypted ? encryptionCheck : null,
                is_owner: 1,
                owner_name: req.user.username,
                createdAt: now.toISOString(),
                updatedAt: now.toISOString()
            });
        } catch (error) {
            logError('POST /api/storages', error);
            res.status(500).json({ error: '저장소 생성에 실패했습니다.' });
        }
    });

    router.put('/:id', authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const { name } = req.body;
            const check = validateStorageName(name);
            if (!check) return res.status(400).json({ error: '저장소 이름을 입력해주세요.' });
            if (!check.ok) return res.status(400).json({ error: check.error });
            const storageName = check.value;

            const userId = req.user.id;
            const storageId = req.params.id;
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

    router.delete('/:id', authMiddleware, csrfMiddleware, async (req, res) => {
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

    router.get('/users/search', authMiddleware, collaboratorUserSearchLimiter, async (req, res) => {
        try {
            const normalizedQuery = normalizeUserSearchQuery(req.query.q);
            if (!normalizedQuery) return res.json([]);

            const users = await dependencies.usersRepo.searchUsers(
                normalizedQuery,
                req.user.id
            );
            res.json(users);
        } catch (error) {
            logError('GET /api/storages/users/search', error);
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

    router.post('/:id/collaborators', authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;
            const { targetUserId, permission } = req.body;

            if (!targetUserId) return res.status(400).json({ error: '참여할 사용자를 지정해주세요.' });

            const normalizedPermission = String(permission || 'READ').toUpperCase();
            if (!['READ', 'EDIT', 'ADMIN'].includes(normalizedPermission)) return res.status(400).json({ error: '유효하지 않은 권한입니다. (READ, EDIT 또는 ADMIN)' });

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!requireStorageOwner(storage, res)) return;

            if (Number(storage.is_encrypted) === 1) return res.status(400).json({ error: '암호화 저장소 협업은 현재 보안상 비활성화되었습니다.' });

            if (String(targetUserId) === String(storage.owner_id)) return res.status(400).json({ error: '저장소 소유자는 별도 참여자로 추가할 수 없습니다.' });
            if (String(targetUserId) === String(userId)) return res.status(400).json({ error: '자기 자신에게 협업 권한을 다시 부여할 수 없습니다.' });

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await storagesRepo.addCollaborator({
                storageId,
                ownerUserId: storage.owner_id,
                sharedWithUserId: targetUserId,
                permission: normalizedPermission,
                createdAt: nowStr,
                updatedAt: nowStr
            });

            try {
                if (typeof wsKickUserFromStorage === 'function') wsKickUserFromStorage(storageId, targetUserId, 1008, 'Storage permission changed');
            } catch (e) {}

            res.json({ success: true });
        } catch (error) {
            logError('POST /api/storages/:id/collaborators', error);
            res.status(500).json({ error: '참여자 추가에 실패했습니다.' });
        }
    });

    router.delete('/:id/collaborators/:targetUserId', authMiddleware, csrfMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;
            const targetUserId = req.params.targetUserId;

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!requireStorageOwner(storage, res)) return;

            if (String(targetUserId) === String(storage.owner_id)) return res.status(400).json({ error: '저장소 소유자는 제거할 수 없습니다.' });
            if (String(targetUserId) === String(userId)) return res.status(400).json({ error: '저장소 소유자는 자기 자신을 제거할 수 없습니다.' });

            await storagesRepo.removeCollaborator(storageId, targetUserId);

            try {
                if (typeof wsKickUserFromStorage === 'function') wsKickUserFromStorage(storageId, targetUserId, 1008, 'Storage access revoked');
            } catch (e) {}

            res.json({ success: true });
        } catch (error) {
            logError('DELETE /api/storages/:id/collaborators/:targetUserId', error);
            res.status(500).json({ error: '참여자 삭제에 실패했습니다.' });
        }
    });

    return router;
};
