const express = require('express');
const router = express.Router();
const crypto = require('crypto');

module.exports = (dependencies) => {
    const { storagesRepo, bootstrapRepo, authMiddleware, toIsoString, logError, formatDateForDb } = dependencies;

    // 저장형 XSS/HTML 엔티티 우회 방어:
    // storage 이름은 여러 화면에서 표시되므로, < > & 및 제어문자를 금지하고 길이를 제한
    const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
    const HTML_META_CHARS_RE = /[<>&]/;
    function validateStorageName(name) {
        if (typeof name !== 'string') return null;
        const trimmed = name.trim();
        if (!trimmed) return null;
        if (trimmed.length > 128) {
            return { ok: false, error: '저장소 이름은 128자 이내로 입력해주세요.' };
        }
        if (CONTROL_CHARS_RE.test(trimmed) || HTML_META_CHARS_RE.test(trimmed)) {
            return { ok: false, error: '저장소 이름에 <, >, &, 제어문자는 사용할 수 없습니다.' };
        }
        return { ok: true, value: trimmed };
    }

    /**
     * 저장소 목록 조회
     */
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

    /**
     * 특정 저장소의 데이터(페이지) 조회
     */
    router.get('/:id/data', authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;

            // 저장소 소유 확인
            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!storage) {
                return res.status(404).json({ error: '저장소를 찾을 수 없거나 권한이 없습니다.' });
            }

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

    /**
     * 저장소 생성
     */
    router.post('/', authMiddleware, async (req, res) => {
        try {
            const { name } = req.body;
            const check = validateStorageName(name);
            if (!check) {
                return res.status(400).json({ error: '저장소 이름을 입력해주세요.' });
            }
            if (!check.ok) {
                return res.status(400).json({ error: check.error });
            }
            const storageName = check.value;

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
                updatedAt: nowStr
            });

            res.json({
                ...storage,
                createdAt: now.toISOString(),
                updatedAt: now.toISOString()
            });
        } catch (error) {
            logError('POST /api/storages', error);
            res.status(500).json({ error: '저장소 생성에 실패했습니다.' });
        }
    });

    /**
     * 저장소 이름 수정
     */
    router.put('/:id', authMiddleware, async (req, res) => {
        try {
            const { name } = req.body;
            const check = validateStorageName(name);
            if (!check) {
                return res.status(400).json({ error: '저장소 이름을 입력해주세요.' });
            }
            if (!check.ok) {
                return res.status(400).json({ error: check.error });
            }
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

    /**
     * 저장소 삭제
     */
    router.delete('/:id', authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;

            // 최소 하나는 남겨둬야 함 (선택사항이지만 안전을 위해)
            const storages = await storagesRepo.listStoragesForUser(userId);
            // 소유한 저장소만 카운트
            const ownedStorages = storages.filter(s => s.is_owner);
            
            // 삭제하려는 저장소가 소유한 것이고, 소유한 게 하나뿐이라면 삭제 방지
            const storageToDelete = storages.find(s => s.id === storageId);
            if (storageToDelete && storageToDelete.is_owner && ownedStorages.length <= 1) {
                return res.status(400).json({ error: '최소 하나의 소유한 저장소는 유지해야 합니다.' });
            }

            // 만약 공유받은 저장소라면 참여자 목록에서 삭제
            if (storageToDelete && !storageToDelete.is_owner) {
                await storagesRepo.removeCollaborator(storageId, userId);
            } else {
                await storagesRepo.deleteStorage(userId, storageId);
            }

            res.json({ success: true });
        } catch (error) {
            logError('DELETE /api/storages/:id', error);
            res.status(500).json({ error: '저장소 삭제에 실패했습니다.' });
        }
    });

    /**
     * 참여자 추가를 위한 사용자 검색
     */
    router.get('/users/search', authMiddleware, async (req, res) => {
        try {
            const query = req.query.q;
            if (!query || query.trim().length < 2) {
                return res.json([]);
            }

            const users = await dependencies.usersRepo.searchUsers(query.trim(), req.user.id);
            res.json(users);
        } catch (error) {
            logError('GET /api/storages/users/search', error);
            res.status(500).json({ error: '사용자 검색 중 오류가 발생했습니다.' });
        }
    });

    /**
     * 저장소 참여자 목록 조회
     */
    router.get('/:id/collaborators', authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!storage) {
                return res.status(404).json({ error: '저장소를 찾을 수 없습니다.' });
            }

            const collaborators = await storagesRepo.listCollaborators(storageId);
            res.json(collaborators);
        } catch (error) {
            logError('GET /api/storages/:id/collaborators', error);
            res.status(500).json({ error: '참여자 목록을 불러오지 못했습니다.' });
        }
    });

    /**
     * 저장소 참여자 추가
     */
    router.post('/:id/collaborators', authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;
            const { targetUserId, permission } = req.body;

            if (!targetUserId) {
                return res.status(400).json({ error: '참여할 사용자를 지정해주세요.' });
            }

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!storage || !storage.is_owner) {
                return res.status(403).json({ error: '참여자를 관리할 권한이 없습니다.' });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await storagesRepo.addCollaborator({
                storageId,
                ownerUserId: userId,
                sharedWithUserId: targetUserId,
                permission: permission || 'READ',
                createdAt: nowStr,
                updatedAt: nowStr
            });

            res.json({ success: true });
        } catch (error) {
            logError('POST /api/storages/:id/collaborators', error);
            res.status(500).json({ error: '참여자 추가에 실패했습니다.' });
        }
    });

    /**
     * 저장소 참여자 삭제
     */
    router.delete('/:id/collaborators/:targetUserId', authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = req.params.id;
            const targetUserId = req.params.targetUserId;

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!storage || !storage.is_owner) {
                return res.status(403).json({ error: '참여자를 관리할 권한이 없습니다.' });
            }

            await storagesRepo.removeCollaborator(storageId, targetUserId);
            res.json({ success: true });
        } catch (error) {
            logError('DELETE /api/storages/:id/collaborators/:targetUserId', error);
            res.status(500).json({ error: '참여자 삭제에 실패했습니다.' });
        }
    });

    return router;
};
