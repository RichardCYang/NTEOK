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
        toIsoString,
        logError,
        formatDateForDb,
        wsKickUserFromStorage,
        getClientIpFromRequest
    } = dependencies;

    // 회원가입 username 정책과 유사하게 검색어도 제한 (검색 오용/열거 완화)
    const USER_SEARCH_CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
    const USER_SEARCH_SAFE_RE = /^[가-힣A-Za-z0-9._-]+$/u;

    function normalizeUserSearchQuery(input) {
        if (typeof input !== 'string') return null;

        // 유니코드 정규화로 혼동 문자/우회 가능성 축소
        const normalized = (typeof input.normalize === 'function'
            ? input.normalize('NFKC')
            : input
        ).trim();

        // 기존 2자 -> 3자로 상향 (열거 난이도 증가)
        if (normalized.length < 3 || normalized.length > 64) return null;
        if (USER_SEARCH_CONTROL_CHARS_RE.test(normalized)) return null;
        if (!USER_SEARCH_SAFE_RE.test(normalized)) return null;

        return normalized;
    }

    // 참여자 검색 API 전용 rate limit
    // - 인증 사용자라도 자동화로 전체 계정 수집/대량 스캔 방지
    const collaboratorUserSearchLimiter = rateLimit({
        windowMs: 60 * 1000, // 1분
        max: 30,             // 사용자+IP 기준 분당 30회
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
    router.get('/users/search', authMiddleware, collaboratorUserSearchLimiter, async (req, res) => {
        try {
            const normalizedQuery = normalizeUserSearchQuery(req.query.q);
            if (!normalizedQuery) {
                return res.json([]);
            }

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

            if (!targetUserId)
                return res.status(400).json({ error: '참여할 사용자를 지정해주세요.' });

            // 권한값 방어적 검증/정규화 (권한 오타/임의 문자열 저장 방지)
            const normalizedPermission = String(permission || 'READ').toUpperCase();
            if (!['READ', 'EDIT'].includes(normalizedPermission))
                return res.status(400).json({ error: '유효하지 않은 권한입니다. (READ 또는 EDIT)' });

            const storage = await storagesRepo.getStorageByIdForUser(userId, storageId);
            if (!storage || !storage.is_owner)
                return res.status(403).json({ error: '참여자를 관리할 권한이 없습니다.' });

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await storagesRepo.addCollaborator({
                storageId,
                ownerUserId: userId,
                sharedWithUserId: targetUserId,
                permission: normalizedPermission,
                createdAt: nowStr,
                updatedAt: nowStr
            });

            // 보안: addCollaborator는 ON DUPLICATE KEY UPDATE를 사용하므로
            // 참여자 추가뿐 아니라 권한 변경(예: EDIT -> READ)도 담당
            // 기존 WebSocket 연결이 살아 있으면 권한 캐시/지연 반영으로 쓰기 지속이 가능하므로
            // 즉시 연결을 끊어 재연결 + 재권한 검사 강제
            try {
                if (typeof wsKickUserFromStorage === 'function')
                    wsKickUserFromStorage(storageId, targetUserId, 1008, 'Storage permission changed');
            } catch (e) {}

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

            // 권한 회수 즉시 반영: 기존 WebSocket 구독(열려 있는 실시간 연결) 강제 해제
            try {
                if (typeof wsKickUserFromStorage === 'function') {
                    wsKickUserFromStorage(storageId, targetUserId, 1008, 'Storage access revoked');
                }
            } catch (e) {}

            res.json({ success: true });
        } catch (error) {
            logError('DELETE /api/storages/:id/collaborators/:targetUserId', error);
            res.status(500).json({ error: '참여자 삭제에 실패했습니다.' });
        }
    });

    return router;
};
