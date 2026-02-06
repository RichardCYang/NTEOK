const express = require('express');
const router = express.Router();
const crypto = require('crypto');

module.exports = (dependencies) => {
    const { storagesRepo, bootstrapRepo, authMiddleware, toIsoString, logError, formatDateForDb } = dependencies;

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
            if (!name || !name.trim()) {
                return res.status(400).json({ error: '저장소 이름을 입력해주세요.' });
            }

            const userId = req.user.id;
            const now = new Date();
            const nowStr = formatDateForDb(now);
            const id = 'stg-' + now.getTime() + '-' + crypto.randomBytes(4).toString('hex');
            const sortOrder = await storagesRepo.getNextSortOrder(userId);

            const storage = await storagesRepo.createStorage({
                userId,
                id,
                name: name.trim(),
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
            if (!name || !name.trim()) {
                return res.status(400).json({ error: '저장소 이름을 입력해주세요.' });
            }

            const userId = req.user.id;
            const storageId = req.params.id;
            const now = new Date();
            const nowStr = formatDateForDb(now);

            await storagesRepo.updateStorage(userId, storageId, {
                name: name.trim(),
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
            if (storages.length <= 1) {
                return res.status(400).json({ error: '최소 하나의 저장소는 유지해야 합니다.' });
            }

            await storagesRepo.deleteStorage(userId, storageId);
            res.json({ success: true });
        } catch (error) {
            logError('DELETE /api/storages/:id', error);
            res.status(500).json({ error: '저장소 삭제에 실패했습니다.' });
        }
    });

    return router;
};
