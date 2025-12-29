const express = require('express');
const router = express.Router();
const crypto = require('crypto');

/**
 * Pages Routes
 *
 * 이 파일은 페이지 관련 라우트를 처리합니다.
 * - 페이지 목록 조회
 * - 단일 페이지 조회
 * - 페이지 생성
 * - 페이지 수정
 * - 페이지 삭제
 * - 페이지 공유 허용 설정
 */

module.exports = (dependencies) => {
    const {
        pool,
        authMiddleware,
        toIsoString,
        sanitizeInput,
        sanitizeHtmlContent,
        generatePageId,
        formatDateForDb,
        getCollectionPermission,
        wsBroadcastToCollection,
        logError,
        generatePublishToken,
        coverUpload,
        editorImageUpload,
        path,
        fs
    } = dependencies;

    /**
     * 사용자 업로드 커버 이미지 목록 조회
     * GET /api/pages/covers/user
     */
    router.get("/covers/user", authMiddleware, async (req, res) => {
        const userId = req.user.id;

        try {
            const userCoversDir = path.join(__dirname, '..', 'covers', String(userId));

            // 사용자 폴더가 없으면 빈 배열 반환
            if (!fs.existsSync(userCoversDir)) {
                return res.json([]);
            }

            // 디렉토리 내 파일 목록 읽기
            const files = fs.readdirSync(userCoversDir);

            // 이미지 파일만 필터링
            const imageFiles = files.filter(file => {
                const ext = path.extname(file).toLowerCase();
                return ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext);
            });

            // 파일 정보 조회 (생성일자 기준 정렬)
            const covers = imageFiles.map(file => {
                const filePath = path.join(userCoversDir, file);
                const stats = fs.statSync(filePath);
                return {
                    path: `${userId}/${file}`,
                    filename: file,
                    uploadedAt: stats.birthtime.toISOString()
                };
            }).sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

            res.json(covers);
        } catch (error) {
            logError("GET /api/pages/covers/user", error);
            res.status(500).json({ error: "커버 목록 조회 실패" });
        }
    });

    /**
     * 사용자 업로드 커버 이미지 삭제
     * DELETE /api/pages/covers/:filename
     */
    router.delete("/covers/:filename", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        const filename = req.params.filename;

        try {
            const coverPath = `${userId}/${filename}`;
            const filePath = path.join(__dirname, '..', 'covers', coverPath);

            // 파일 존재 확인
            if (!fs.existsSync(filePath)) {
                return res.status(404).json({ error: "파일을 찾을 수 없습니다." });
            }

            // 해당 커버를 사용 중인 페이지가 있는지 확인
            const [pages] = await pool.execute(
                `SELECT id FROM pages WHERE cover_image = ? AND user_id = ?`,
                [coverPath, userId]
            );

            if (pages.length > 0) {
                return res.status(400).json({
                    error: "해당 커버를 사용 중인 페이지가 있습니다. 먼저 페이지의 커버를 변경해주세요."
                });
            }

            // 파일 삭제
            fs.unlinkSync(filePath);

            console.log("DELETE /api/pages/covers/:filename 삭제 완료:", coverPath);
            res.json({ success: true });
        } catch (error) {
            logError("DELETE /api/pages/covers/:filename", error);
            res.status(500).json({ error: "커버 삭제 실패" });
        }
    });

    /**
     * 페이지 목록 조회 (소유한 페이지 + 공유받은 컬렉션의 페이지)
     * GET /api/pages
     *
     * 성능 최적화:
     * - DISTINCT 제거, UNION ALL로 분리하여 인덱스 활용 극대화
     * - 각 쿼리가 독립적인 인덱스 사용
     * - 중복 제거 필요 없음 (두 쿼리가 겹치지 않음)
     */
    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const collectionId =
                typeof req.query.collectionId === "string" && req.query.collectionId.trim() !== ""
                    ? req.query.collectionId.trim()
                    : null;

            // 성능 최적화: 쿼리를 UNION ALL로 분리 (DISTINCT 제거)
            // 1. 본인 소유 페이지 (인덱스: idx_pages_collection_user)
            // 2. 공유받은 컬렉션의 페이지 (인덱스: idx_shared_with_user)
            let query = `
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.collection_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    INNER JOIN collections c ON p.collection_id = c.id
                    WHERE c.user_id = ?
                    ${collectionId ? 'AND p.collection_id = ?' : ''}
                )
                UNION ALL
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.collection_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    INNER JOIN collection_shares cs ON p.collection_id = cs.collection_id
                    WHERE cs.shared_with_user_id = ?
                      AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
                    ${collectionId ? 'AND p.collection_id = ?' : ''}
                )
                ORDER BY collection_id ASC, parent_id IS NULL DESC, sort_order ASC, updated_at DESC
            `;

            const params = collectionId
                ? [userId, collectionId, userId, userId, collectionId]
                : [userId, userId, userId];

            const [rows] = await pool.execute(query, params);

            const list = rows.map((row) => ({
                id: row.id,
                title: row.title || "제목 없음",
                updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id,
                sortOrder: row.sort_order,
                collectionId: row.collection_id,
                isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id,
                icon: row.icon || null,
                coverImage: row.cover_image || null,
                coverPosition: row.cover_position || 50,
                horizontalPadding: row.horizontal_padding || null
            }));

            console.log("GET /api/pages 응답 개수:", list.length, "(최적화된 UNION 쿼리)");

            res.json(list);
        } catch (error) {
            logError("GET /api/pages", error);
            res.status(500).json({ error: "페이지 목록 불러오기 실패." });
        }
    });

    /**
     * 단일 페이지 조회 (소유한 페이지 또는 공유받은 컬렉션의 페이지)
     * GET /api/pages/:id
     */
    router.get("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.collection_id,
                        p.is_encrypted, p.share_allowed, p.user_id, p.icon, p.cover_image, p.cover_position,
                        p.horizontal_padding
                 FROM pages p
                 LEFT JOIN collections c ON p.collection_id = c.id
                 LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                 WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)`,
                [userId, id, userId, userId]
            );

            if (!rows.length) {
                console.warn("GET /api/pages/:id - 페이지 없음 또는 권한 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const row = rows[0];

            const page = {
                id: row.id,
                title: row.title || "제목 없음",
                content: row.content || "<p></p>",
                encryptionSalt: row.encryption_salt || null,
                encryptedContent: row.encrypted_content || null,
                createdAt: toIsoString(row.created_at),
                updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id,
                sortOrder: row.sort_order,
                collectionId: row.collection_id,
                isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id,
                icon: row.icon || null,
                coverImage: row.cover_image || null,
                coverPosition: row.cover_position || 50,
                horizontalPadding: row.horizontal_padding || null
            };

            console.log("GET /api/pages/:id 응답:", id);

            res.json(page);
        } catch (error) {
            logError("GET /api/pages/:id", error);
            res.status(500).json({ error: "페이지 불러오기 실패." });
        }
    });

    /**
     * 새 페이지 생성
     * POST /api/pages
     * body: { title?: string, content?: string, parentId?: string, sortOrder?: number, collectionId: string, icon?: string }
     */
    router.post("/", authMiddleware, async (req, res) => {
        const rawTitle = typeof req.body.title === "string" ? req.body.title : "";
        const title = sanitizeInput(rawTitle.trim() !== "" ? rawTitle.trim() : "제목 없음");

        const now = new Date();
        const id = generatePageId(now);
        const nowStr = formatDateForDb(now);
        const rawContent = typeof req.body.content === "string" ? req.body.content : "<p></p>";
        const content = sanitizeHtmlContent(rawContent);
        const userId = req.user.id;

        const parentId =
            typeof req.body.parentId === "string" && req.body.parentId.trim() !== ""
                ? req.body.parentId.trim()
                : null;
        const sortOrder =
            typeof req.body.sortOrder === "number" && Number.isFinite(req.body.sortOrder)
                ? req.body.sortOrder
                : 0;
        const collectionId =
            typeof req.body.collectionId === "string" && req.body.collectionId.trim() !== ""
                ? req.body.collectionId.trim()
                : null;
        const icon =
            typeof req.body.icon === "string" && req.body.icon.trim() !== ""
                ? req.body.icon.trim()
                : null;

        if (!collectionId) {
            return res.status(400).json({ error: "collectionId가 필요합니다." });
        }

        try {
            const { permission } = await getCollectionPermission(collectionId, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 생성할 권한이 없습니다." });
            }

            if (parentId) {
                const [parentRows] = await pool.execute(
                    `SELECT p.id, p.collection_id
                     FROM pages p
                     LEFT JOIN collections c ON p.collection_id = c.id
                     LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                     WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)`,
                    [userId, parentId, userId, userId]
                );

                if (!parentRows.length) {
                    return res.status(400).json({ error: "부모 페이지를 찾을 수 없습니다." });
                }

                if (parentRows[0].collection_id !== collectionId) {
                    return res.status(400).json({ error: "부모 페이지와 동일한 컬렉션이어야 합니다." });
                }
            }

            await pool.execute(
                `
                INSERT INTO pages (id, user_id, parent_id, title, content, sort_order, created_at, updated_at, collection_id, icon)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [id, userId, parentId, title, content, sortOrder, nowStr, nowStr, collectionId, icon]
            );

            const page = {
                id,
                title,
                content,
                parentId,
                sortOrder,
                collectionId,
                createdAt: now.toISOString(),
                updatedAt: now.toISOString(),
                icon
            };

            console.log("POST /api/pages 생성:", id);

            res.status(201).json(page);
        } catch (error) {
            logError("POST /api/pages", error);
            res.status(500).json({ error: "페이지 생성 실패." });
        }
    });

    /**
     * 페이지 수정
     * PUT /api/pages/:id
     * body: { title?: string, content?: string, isEncrypted?: boolean, icon?: string }
     */
    router.put("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        // 평문 필드
        const titleFromBody = typeof req.body.title === "string" ? sanitizeInput(req.body.title.trim()) : null;
        const contentFromBody = typeof req.body.content === "string" ? sanitizeHtmlContent(req.body.content) : null;
        const isEncryptedFromBody = typeof req.body.isEncrypted === "boolean" ? req.body.isEncrypted : null;
        const iconFromBody = typeof req.body.icon === "string" ? req.body.icon.trim() : undefined;
        const horizontalPaddingFromBody = typeof req.body.horizontalPadding === 'number' ?
            Math.max(0, Math.min(300, req.body.horizontalPadding)) : (req.body.horizontalPadding === null ? null : undefined);

        // 암호화 필드 (선택적 암호화)
        const encryptionSaltFromBody = typeof req.body.encryptionSalt === "string" ? req.body.encryptionSalt : null;
        const encryptedContentFromBody = typeof req.body.encryptedContent === "string" ? req.body.encryptedContent : null;

        if (!titleFromBody && !contentFromBody && isEncryptedFromBody === null && iconFromBody === undefined &&
            !encryptionSaltFromBody && !encryptedContentFromBody && horizontalPaddingFromBody === undefined) {
            return res.status(400).json({ error: "수정할 데이터 없음." });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, title, content, encryption_salt, encrypted_content,
                        created_at, updated_at, parent_id, sort_order, collection_id, is_encrypted, user_id, icon,
                        horizontal_padding
                 FROM pages
                 WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                console.warn("PUT /api/pages/:id - 페이지 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const existing = rows[0];

            const { permission } = await getCollectionPermission(existing.collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 수정할 권한이 없습니다." });
            }

            // 암호화 여부 결정
            const newIsEncrypted = isEncryptedFromBody !== null ? (isEncryptedFromBody ? 1 : 0) : existing.is_encrypted;

            // 제목은 항상 평문으로 저장
            const newTitle = titleFromBody && titleFromBody !== "" ? titleFromBody : existing.title;

            // 내용 처리
            let newContent;
            if (newIsEncrypted === 1) {
                // 암호화된 페이지: content는 빈 문자열 (암호화됨)
                newContent = '';
            } else {
                // 평문 페이지: content도 평문 저장
                newContent = contentFromBody !== null ? contentFromBody : existing.content;
            }

            const newIcon = iconFromBody !== undefined ? (iconFromBody !== "" ? iconFromBody : null) : existing.icon;
            const newHorizontalPadding = horizontalPaddingFromBody !== undefined ? horizontalPaddingFromBody : existing.horizontal_padding;

            // 암호화 필드 업데이트
            const newEncryptionSalt = encryptionSaltFromBody !== null ? encryptionSaltFromBody : existing.encryption_salt;
            const newEncryptedContent = encryptedContentFromBody !== null ? encryptedContentFromBody : existing.encrypted_content;

            const now = new Date();
            const nowStr = formatDateForDb(now);

            const isBecomingEncrypted = existing.is_encrypted === 0 && newIsEncrypted === 1;

            if (isBecomingEncrypted) {
                await pool.execute(
                    `UPDATE pages
                     SET title = ?, content = ?, encryption_salt = ?, encrypted_content = ?,
                         is_encrypted = ?, icon = ?, horizontal_padding = ?, user_id = ?, updated_at = ?
                     WHERE id = ?`,
                    [newTitle, newContent, newEncryptionSalt, newEncryptedContent,
                     newIsEncrypted, newIcon, newHorizontalPadding, userId, nowStr, id]
                );
            } else {
                await pool.execute(
                    `UPDATE pages
                     SET title = ?, content = ?, encryption_salt = ?, encrypted_content = ?,
                         is_encrypted = ?, icon = ?, horizontal_padding = ?, updated_at = ?
                     WHERE id = ?`,
                    [newTitle, newContent, newEncryptionSalt, newEncryptedContent,
                     newIsEncrypted, newIcon, newHorizontalPadding, nowStr, id]
                );
            }

            const page = {
                id,
                title: newTitle,
                content: newContent,
                encryptionSalt: newEncryptionSalt,
                encryptedContent: newEncryptedContent,
                parentId: existing.parent_id,
                sortOrder: existing.sort_order,
                collectionId: existing.collection_id,
                createdAt: toIsoString(existing.created_at),
                updatedAt: now.toISOString(),
                icon: newIcon
            };

            console.log("PUT /api/pages/:id 수정 완료:", id);

            if (titleFromBody && titleFromBody !== existing.title) {
                wsBroadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'title',
                    value: newTitle
                }, userId);
            }

            if (iconFromBody !== undefined && newIcon !== existing.icon) {
                wsBroadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'icon',
                    value: newIcon
                }, userId);
            }

            if (horizontalPaddingFromBody !== undefined && newHorizontalPadding !== existing.horizontal_padding) {
                wsBroadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'horizontalPadding',
                    value: newHorizontalPadding
                }, userId);
            }

            res.json(page);
        } catch (error) {
            logError("PUT /api/pages/:id", error);
            res.status(500).json({ error: "페이지 수정 실패." });
        }
    });

    /**
     * 페이지 순서 변경 (같은 컬렉션 내)
     * PATCH /api/pages/reorder
     * body: { collectionId: string, pageIds: string[], parentId: string | null }
     */
    router.patch("/reorder", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        const { collectionId, pageIds, parentId } = req.body;

        if (!collectionId || !Array.isArray(pageIds) || pageIds.length === 0) {
            return res.status(400).json({ error: "collectionId와 pageIds 배열이 필요합니다." });
        }

        const conn = await pool.getConnection();
        try {
            // 권한 확인
            const { permission } = await getCollectionPermission(collectionId, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지 순서를 변경할 권한이 없습니다." });
            }

            await conn.beginTransaction();

            // 모든 페이지가 같은 컬렉션, 같은 부모에 속하는지 확인
            const parentIdCondition = parentId ? `parent_id = ?` : `parent_id IS NULL`;
            const placeholders = pageIds.map(() => '?').join(',');
            const params = parentId
                ? [collectionId, parentId, ...pageIds]
                : [collectionId, ...pageIds];

            const [rows] = await conn.execute(
                `SELECT id FROM pages WHERE collection_id = ? AND ${parentIdCondition} AND id IN (${placeholders})`,
                params
            );

            if (rows.length !== pageIds.length) {
                await conn.rollback();
                return res.status(400).json({ error: "일부 페이지가 조건에 맞지 않습니다." });
            }

            // 순서 업데이트
            for (let i = 0; i < pageIds.length; i++) {
                await conn.execute(
                    `UPDATE pages SET sort_order = ?, updated_at = NOW() WHERE id = ?`,
                    [i * 10, pageIds[i]]
                );
            }

            await conn.commit();
            console.log(`[Reorder] 페이지 순서 변경 완료: ${pageIds.length}개`);

            // WebSocket 브로드캐스트
            wsBroadcastToCollection(collectionId, 'pages-reordered', {
                parentId,
                pageIds
            }, userId);

            res.json({ ok: true, updated: pageIds.length });

        } catch (error) {
            await conn.rollback();
            logError("PATCH /api/pages/reorder", error);
            res.status(500).json({ error: "순서 변경 실패" });
        } finally {
            conn.release();
        }
    });

    /**
     * 페이지 이동 (다른 컬렉션으로)
     * PATCH /api/pages/:id/move
     * body: { targetCollectionId: string, targetParentId: string | null, sortOrder: number }
     */
    router.patch("/:id/move", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;
        const { targetCollectionId, targetParentId, sortOrder } = req.body;

        if (!targetCollectionId) {
            return res.status(400).json({ error: "targetCollectionId가 필요합니다." });
        }

        try {
            // 현재 페이지 정보 조회
            const [pageRows] = await pool.execute(
                `SELECT id, collection_id, parent_id, is_encrypted FROM pages WHERE id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const currentCollectionId = pageRows[0].collection_id;
            const isEncrypted = pageRows[0].is_encrypted;

            // 같은 컬렉션으로 이동 시 거부
            if (currentCollectionId === targetCollectionId) {
                return res.status(400).json({ error: "같은 컬렉션으로 이동할 수 없습니다. 순서 변경은 /reorder API를 사용하세요." });
            }

            // 암호화된 페이지는 이동 불가
            if (isEncrypted) {
                return res.status(400).json({ error: "암호화된 페이지는 다른 컬렉션으로 이동할 수 없습니다." });
            }

            // 출발 컬렉션 권한 확인
            const { permission: sourcePerm } = await getCollectionPermission(currentCollectionId, userId);
            if (!sourcePerm || sourcePerm === 'READ') {
                return res.status(403).json({ error: "페이지를 이동할 권한이 없습니다." });
            }

            // 도착 컬렉션 권한 확인
            const { permission: targetPerm } = await getCollectionPermission(targetCollectionId, userId);
            if (!targetPerm || targetPerm === 'READ') {
                return res.status(403).json({ error: "대상 컬렉션에 페이지를 추가할 권한이 없습니다." });
            }

            // 페이지 이동 (최상위로, 계층 구조 제거)
            const newSortOrder = typeof sortOrder === 'number' ? sortOrder : 0;
            await pool.execute(
                `UPDATE pages SET collection_id = ?, parent_id = ?, sort_order = ?, updated_at = NOW() WHERE id = ?`,
                [targetCollectionId, targetParentId || null, newSortOrder, pageId]
            );

            console.log(`[Move] 페이지 이동: ${pageId} (${currentCollectionId} → ${targetCollectionId})`);

            // 실시간 동기화: 출발/도착 컬렉션 모두 알림
            wsBroadcastToCollection(currentCollectionId, 'page-moved-out', {
                pageId,
                targetCollectionId
            }, userId);
            wsBroadcastToCollection(targetCollectionId, 'page-moved-in', {
                pageId,
                sourceCollectionId: currentCollectionId
            }, userId);

            res.json({ ok: true, pageId, newCollectionId: targetCollectionId });

        } catch (error) {
            logError("PATCH /api/pages/:id/move", error);
            res.status(500).json({ error: "페이지 이동 실패" });
        }
    });

    /**
     * 페이지 제목만 수정
     * PATCH /api/pages/:id
     * body: { title: string }
     */
    router.patch("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { title } = req.body;

        if (!title || typeof title !== "string") {
            return res.status(400).json({ error: "제목이 필요합니다." });
        }

        const sanitizedTitle = sanitizeInput(title.trim());

        try {
            const [rows] = await pool.execute(
                `SELECT collection_id FROM pages WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const collectionId = rows[0].collection_id;
            const { permission } = await getCollectionPermission(collectionId, userId);

            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 수정할 권한이 없습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `UPDATE pages SET title = ?, updated_at = ? WHERE id = ?`,
                [sanitizedTitle, nowStr, id]
            );

            // 실시간 동기화
            wsBroadcastToCollection(collectionId, 'metadata-change', {
                pageId: id,
                field: 'title',
                value: sanitizedTitle
            }, userId);

            res.json({ success: true, title: sanitizedTitle });
        } catch (error) {
            logError("PATCH /api/pages/:id", error);
            res.status(500).json({ error: "제목 수정 실패." });
        }
    });

    /**
     * 페이지에서 이미지 URL 추출
     * @param {Object} page - 페이지 객체 (content, cover_image 포함)
     * @returns {Array<string>} - 이미지 경로 배열 (예: ["1/abc.jpg", "1/xyz.png"])
     */
    function extractImagesFromPage(page) {
        const images = [];

        // 1. content에서 <img> 태그의 src 추출
        if (page.content) {
            const imgRegex = /<img[^>]+src=["']\/imgs\/([^"']+)["']/g;
            let match;
            while ((match = imgRegex.exec(page.content)) !== null) {
                images.push(match[1]); // "userId/filename.jpg"
            }
        }

        // 2. cover_image 추가
        if (page.cover_image) {
            images.push(page.cover_image); // "userId/filename.jpg"
        }

        return images;
    }

    /**
     * 고립된 이미지 삭제 (다른 페이지에서 참조하지 않는 이미지만)
     * @param {Array<string>} imageUrls - 이미지 경로 배열
     * @param {number} userId - 사용자 ID
     */
    async function cleanupOrphanedImages(imageUrls, userId) {
        if (!imageUrls || imageUrls.length === 0) return;

        for (const imageUrl of imageUrls) {
            try {
                // 이미지 경로에서 userId와 filename 추출
                const parts = imageUrl.split('/');
                if (parts.length !== 2) continue;

                const [imgUserId, filename] = parts;

                // 해당 이미지를 참조하는 다른 페이지가 있는지 확인
                const [contentRows] = await pool.execute(
                    `SELECT COUNT(*) as count FROM pages WHERE user_id = ? AND content LIKE ?`,
                    [userId, `%/imgs/${imageUrl}%`]
                );

                const [coverRows] = await pool.execute(
                    `SELECT COUNT(*) as count FROM pages WHERE user_id = ? AND cover_image = ?`,
                    [userId, imageUrl]
                );

                const totalReferences = contentRows[0].count + coverRows[0].count;

                // 참조가 없으면 물리적 파일 삭제
                if (totalReferences === 0) {
                    // imgs 폴더에서 삭제 시도
                    const imgPath = path.join(__dirname, '..', 'imgs', imgUserId, filename);
                    if (fs.existsSync(imgPath)) {
                        fs.unlinkSync(imgPath);
                        console.log(`이미지 삭제됨: ${imgPath}`);
                    }

                    // covers 폴더에서도 삭제 시도 (커버 이미지인 경우)
                    const coverPath = path.join(__dirname, '..', 'covers', imgUserId, filename);
                    if (fs.existsSync(coverPath)) {
                        fs.unlinkSync(coverPath);
                        console.log(`커버 이미지 삭제됨: ${coverPath}`);
                    }
                }
            } catch (err) {
                console.error(`이미지 정리 중 오류 (${imageUrl}):`, err);
                // 개별 이미지 정리 실패는 무시하고 계속 진행
            }
        }
    }

    /**
     * 페이지 삭제 (EDIT 이상 권한 필요)
     * DELETE /api/pages/:id
     */
    router.delete("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            // 페이지 정보 조회 (이미지 정리를 위해 content와 cover_image도 가져옴)
            const [rows] = await pool.execute(
                `SELECT id, collection_id, content, cover_image FROM pages WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                console.warn("DELETE /api/pages/:id - 페이지 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const page = rows[0];

            const { permission } = await getCollectionPermission(page.collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 삭제할 권한이 없습니다." });
            }

            // 페이지에서 사용된 이미지 추출
            const imageUrls = extractImagesFromPage(page);

            // 페이지 삭제
            await pool.execute(
                `DELETE FROM pages WHERE id = ?`,
                [id]
            );

            console.log("DELETE /api/pages/:id 삭제:", id);

            // 고립된 이미지 정리 (비동기로 실행하여 응답 지연 방지)
            if (imageUrls.length > 0) {
                cleanupOrphanedImages(imageUrls, userId).catch(err => {
                    console.error("이미지 정리 중 오류:", err);
                });
            }

            res.json({ ok: true, removedId: id });
        } catch (error) {
            logError("DELETE /api/pages/:id", error);
            res.status(500).json({ error: "페이지 삭제 실패." });
        }
    });

    /**
     * 페이지 공유 허용 설정 업데이트
     * PUT /api/pages/:id/share-permission
     * body: { shareAllowed: boolean }
     */
    router.put("/:id/share-permission", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { shareAllowed } = req.body;

        if (typeof shareAllowed !== "boolean") {
            return res.status(400).json({ error: "shareAllowed는 boolean 값이어야 합니다." });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, collection_id, is_encrypted, user_id FROM pages WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = rows[0];

            if (!page.is_encrypted) {
                return res.status(400).json({ error: "암호화된 페이지만 공유 허용 설정이 가능합니다." });
            }

            if (page.user_id !== userId) {
                return res.status(403).json({ error: "페이지 생성자만 공유 허용 설정을 변경할 수 있습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `UPDATE pages SET share_allowed = ?, updated_at = ? WHERE id = ?`,
                [shareAllowed ? 1 : 0, nowStr, id]
            );

            res.json({ ok: true, shareAllowed });
        } catch (error) {
            logError("PUT /api/pages/:id/share-permission", error);
            res.status(500).json({ error: "공유 허용 설정 업데이트 실패." });
        }
    });

    /**
     * 커버 이미지 업로드
     * POST /api/pages/:id/cover
     */
    router.post("/:id/cover", authMiddleware, coverUpload.single('cover'), async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id, p.cover_image FROM pages p WHERE p.id = ?`,
                [id]
            );
            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // DB 업데이트
            const coverPath = `${userId}/${req.file.filename}`;
            await pool.execute(
                `UPDATE pages SET cover_image = ?, updated_at = NOW() WHERE id = ?`,
                [coverPath, id]
            );

            // WebSocket 브로드캐스트
            wsBroadcastToCollection(rows[0].collection_id, 'metadata-change', {
                pageId: id,
                field: 'coverImage',
                value: coverPath
            }, userId);

            console.log("POST /api/pages/:id/cover 업로드 완료:", coverPath);
            res.json({ coverImage: coverPath });
        } catch (error) {
            logError("POST /api/pages/:id/cover", error);
            res.status(500).json({ error: "커버 업로드 실패" });
        }
    });

    /**
     * 커버 이미지 선택/위치 조정
     * PUT /api/pages/:id/cover
     * body: { coverImage?: string, coverPosition?: number }
     */
    router.put("/:id/cover", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { coverImage, coverPosition } = req.body;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id, p.cover_image FROM pages p WHERE p.id = ?`,
                [id]
            );
            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // 업데이트할 필드 결정
            const updates = [];
            const values = [];

            if (coverImage !== undefined) {
                updates.push('cover_image = ?');
                values.push(coverImage);
            }

            if (typeof coverPosition === 'number') {
                updates.push('cover_position = ?');
                values.push(Math.max(0, Math.min(100, coverPosition)));
            }

            if (updates.length === 0) {
                return res.status(400).json({ error: "업데이트할 데이터 없음" });
            }

            updates.push('updated_at = NOW()');
            values.push(id);

            await pool.execute(
                `UPDATE pages SET ${updates.join(', ')} WHERE id = ?`,
                values
            );

            // WebSocket 브로드캐스트
            if (coverImage !== undefined) {
                wsBroadcastToCollection(rows[0].collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'coverImage',
                    value: coverImage
                }, userId);
            }
            if (typeof coverPosition === 'number') {
                wsBroadcastToCollection(rows[0].collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'coverPosition',
                    value: Math.max(0, Math.min(100, coverPosition))
                }, userId);
            }

            console.log("PUT /api/pages/:id/cover 업데이트 완료");
            res.json({ success: true });
        } catch (error) {
            logError("PUT /api/pages/:id/cover", error);
            res.status(500).json({ error: "커버 업데이트 실패" });
        }
    });

    /**
     * 커버 이미지 제거
     * DELETE /api/pages/:id/cover
     */
    router.delete("/:id/cover", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id, p.cover_image FROM pages p WHERE p.id = ?`,
                [id]
            );
            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // DB 업데이트 (파일은 삭제하지 않고 사용자 이미지 탭에 유지)
            await pool.execute(
                `UPDATE pages SET cover_image = NULL, cover_position = 50, updated_at = NOW() WHERE id = ?`,
                [id]
            );

            // WebSocket 브로드캐스트
            wsBroadcastToCollection(rows[0].collection_id, 'metadata-change', {
                pageId: id,
                field: 'coverImage',
                value: null
            }, userId);

            console.log("DELETE /api/pages/:id/cover 제거 완료");
            res.json({ success: true });
        } catch (error) {
            logError("DELETE /api/pages/:id/cover", error);
            res.status(500).json({ error: "커버 제거 실패" });
        }
    });

    /**
     * 파일 해시 계산
     */
    function calculateFileHash(filePath) {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash('md5');
            const stream = fs.createReadStream(filePath);

            stream.on('data', (data) => hash.update(data));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', (err) => reject(err));
        });
    }

    /**
     * 사용자 폴더에서 같은 해시의 파일 찾기
     */
    async function findDuplicateImage(userImgDir, newFileHash, newFilePath) {
        try {
            const files = fs.readdirSync(userImgDir);

            for (const file of files) {
                const filePath = path.join(userImgDir, file);

                // 새로 업로드된 파일은 제외
                if (filePath === newFilePath) continue;

                // 파일인지 확인
                const stat = fs.statSync(filePath);
                if (!stat.isFile()) continue;

                // 해시 비교
                const existingFileHash = await calculateFileHash(filePath);
                if (existingFileHash === newFileHash) {
                    return file; // 중복 파일명 반환
                }
            }

            return null; // 중복 없음
        } catch (error) {
            console.error('중복 파일 검사 오류:', error);
            return null;
        }
    }

    /**
     * 에디터 이미지 업로드
     * POST /api/pages/:id/editor-image
     */
    router.post("/:id/editor-image", authMiddleware, editorImageUpload.single('image'), async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id FROM pages p WHERE p.id = ?`,
                [id]
            );
            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // 업로드된 파일 정보
            const uploadedFilePath = req.file.path;
            const uploadedFileName = req.file.filename;
            const userImgDir = path.dirname(uploadedFilePath);

            // 파일 해시 계산
            const fileHash = await calculateFileHash(uploadedFilePath);

            // 중복 파일 확인
            const duplicateFileName = await findDuplicateImage(userImgDir, fileHash, uploadedFilePath);

            let finalFileName;

            if (duplicateFileName) {
                // 중복 파일이 있으면 새 파일 삭제
                fs.unlinkSync(uploadedFilePath);
                finalFileName = duplicateFileName;
                console.log("POST /api/pages/:id/editor-image 중복 이미지 발견, 기존 파일 사용:", finalFileName);
            } else {
                // 중복이 없으면 새 파일 사용
                finalFileName = uploadedFileName;
                console.log("POST /api/pages/:id/editor-image 새 이미지 업로드 완료:", finalFileName);
            }

            // 이미지 경로 반환
            const imagePath = `${userId}/${finalFileName}`;
            const imageUrl = `/imgs/${imagePath}`;

            res.json({ url: imageUrl });
        } catch (error) {
            logError("POST /api/pages/:id/editor-image", error);
            res.status(500).json({ error: "이미지 업로드 실패" });
        }
    });

    /**
     * 북마크 메타데이터 추출
     * POST /api/pages/:id/bookmark-metadata
     */
    router.post("/:id/bookmark-metadata", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;
        const { url } = req.body;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id FROM pages p WHERE p.id = ? AND p.user_id = ?`,
                [pageId, userId]
            );
            if (!rows.length) {
                return res.status(404).json({ success: false, error: "페이지를 찾을 수 없습니다." });
            }

            // URL 유효성 검사
            if (!url || typeof url !== 'string') {
                return res.status(400).json({ success: false, error: "유효한 URL을 입력해주세요." });
            }

            let parsedUrl;
            try {
                parsedUrl = new URL(url);
                if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
                    throw new Error('HTTP/HTTPS URL만 지원합니다.');
                }
            } catch (error) {
                return res.status(400).json({ success: false, error: "유효하지 않은 URL입니다." });
            }

            // SSRF 방지: 내부 IP 주소 차단
            const hostname = parsedUrl.hostname.toLowerCase();
            const blockedPatterns = [
                /^localhost$/,
                /^127\./,
                /^192\.168\./,
                /^10\./,
                /^172\.(1[6-9]|2[0-9]|3[01])\./,
                /^0\.0\.0\.0$/,
                /^::1$/,  // IPv6 localhost
                /^fc00:/,  // IPv6 private
                /^fe80:/   // IPv6 link-local
            ];

            if (blockedPatterns.some(pattern => pattern.test(hostname))) {
                return res.status(400).json({
                    success: false,
                    error: "내부 네트워크 주소는 사용할 수 없습니다."
                });
            }

            // URL에서 HTML 가져오기
            const axios = require('axios');
            const cheerio = require('cheerio');

            let response;
            try {
                response = await axios.get(url, {
                    timeout: 10000, // 10초 타임아웃
                    maxRedirects: 5,
                    headers: {
                        // 페이스북 봇인 척 위장 (해당 방법이 가장 호환성이 좋음) -> Reddit과 같은 클라이언트 측 렌더링(CSR) 페이지 우회용
                        // Reddit과 같은 클라이언트 측 렌더링(CSR) 페이지들은 User-Agent를 봇으로 속이면, CSR용 빈 HTML을 제공하는 것이 아니라, 실제 데이터(og:title 등)를 바로 넘겨줌
                        'User-Agent': 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'
                        // 또는 트위터 봇: 'Twitterbot/1.0' -> (페이스북 봇이 안 통할 시)
                        // 또는 구글 봇: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -> (페이스북, 트위터 봇 둘 다 안 통할 시)
                    },
                    maxContentLength: 5 * 1024 * 1024 // 5MB 제한
                });
            } catch (error) {
                console.error('[BookmarkAPI] URL 가져오기 실패:', error.message);
                return res.status(400).json({
                    success: false,
                    error: "URL에 접근할 수 없습니다. CORS 또는 네트워크 오류일 수 있습니다."
                });
            }

            // HTML 파싱
            const $ = cheerio.load(response.data);

            // 메타데이터 추출 (우선순위: Open Graph > Twitter Card > 기본 메타태그)
            const ogTitle = $('meta[property="og:title"]').attr('content');
            const twitterTitle = $('meta[name="twitter:title"]').attr('content');
            const pageTitle = $('title').text();

            const ogDesc = $('meta[property="og:description"]').attr('content');
            const twitterDesc = $('meta[name="twitter:description"]').attr('content');
            const metaDesc = $('meta[name="description"]').attr('content');

            const ogImage = $('meta[property="og:image"]').attr('content');
            const twitterImage = $('meta[name="twitter:image"]').attr('content');

            const metadata = {
                url: url,
                title: pageTitle || ogTitle || twitterTitle || '제목 없음',
                description: ogDesc || twitterDesc || metaDesc || '',
                thumbnail: ogImage || twitterImage || ''
            };

            // 상대 URL을 절대 URL로 변환
            if (metadata.thumbnail && !metadata.thumbnail.startsWith('http')) {
                try {
                    metadata.thumbnail = new URL(metadata.thumbnail, parsedUrl.origin).href;
                } catch (error) {
                    metadata.thumbnail = '';
                }
            }

            // 제목/설명 길이 제한
            if (metadata.title && metadata.title.length > 200) {
                metadata.title = metadata.title.substring(0, 197) + '...';
            }
            if (metadata.description && metadata.description.length > 300) {
                metadata.description = metadata.description.substring(0, 297) + '...';
            }

            res.json({ success: true, metadata });

        } catch (error) {
            logError("POST /api/pages/:id/bookmark-metadata", error);
            res.status(500).json({ success: false, error: "메타데이터 추출 실패" });
        }
    });

    /**
     * 북마크 이미지 프록시 (CSP 정책 우회)
     * GET /api/pages/proxy/image?url=...
     */
    router.get("/proxy/image", authMiddleware, async (req, res) => {
        const { url } = req.query;

        try {
            // URL 유효성 검사
            if (!url || typeof url !== 'string') {
                return res.status(400).json({ error: "유효한 URL을 입력해주세요." });
            }

            let parsedUrl;
            try {
                parsedUrl = new URL(url);
                if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
                    throw new Error('HTTP/HTTPS URL만 지원합니다.');
                }
            } catch (error) {
                return res.status(400).json({ error: "유효하지 않은 URL입니다." });
            }

            // SSRF 방지: 내부 IP 주소 차단
            const hostname = parsedUrl.hostname.toLowerCase();
            const blockedPatterns = [
                /^localhost$/,
                /^127\./,
                /^192\.168\./,
                /^10\./,
                /^172\.(1[6-9]|2[0-9]|3[01])\./,
                /^0\.0\.0\.0$/,
                /^::1$/,
                /^fc00:/,
                /^fe80:/
            ];

            if (blockedPatterns.some(pattern => pattern.test(hostname))) {
                return res.status(400).json({ error: "내부 네트워크 주소는 사용할 수 없습니다." });
            }

            // 이미지 가져오기
            const axios = require('axios');

            let response;
            try {
                response = await axios.get(url, {
                    timeout: 10000,
                    maxRedirects: 5,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (compatible; NTEOK-Bot/1.0)'
                    },
                    maxContentLength: 5 * 1024 * 1024, // 5MB 제한
                    responseType: 'arraybuffer' // 바이너리로 받기
                });
            } catch (error) {
                console.error('[ProxyImage] 이미지 가져오기 실패:', error.message);
                return res.status(400).json({ error: "이미지를 가져올 수 없습니다." });
            }

            // 이미지 타입 검증
            let contentType = response.headers['content-type'] || 'image/jpeg';

            // Content-Type이 이미지 타입인지 확인 (jpeg_s2, jpeg_s1 등 특수 확장자도 포함)
            if (!contentType.startsWith('image/')) {
                // 이미지 타입이 아니면, 버퍼의 매직 넘버로 확인
                const buffer = response.data;
                let detectedType = null;

                // JPEG 매직 넘버: FF D8 FF
                if (buffer[0] === 0xFF && buffer[1] === 0xD8 && buffer[2] === 0xFF) {
                    detectedType = 'image/jpeg';
                }
                // PNG 매직 넘버: 89 50 4E 47
                else if (buffer[0] === 0x89 && buffer[1] === 0x50 && buffer[2] === 0x4E && buffer[3] === 0x47) {
                    detectedType = 'image/png';
                }
                // GIF 매직 넘버: 47 49 46
                else if (buffer[0] === 0x47 && buffer[1] === 0x49 && buffer[2] === 0x46) {
                    detectedType = 'image/gif';
                }
                // WebP 매직 넘버: 52 49 46 46 ... 57 45 42 50
                else if (buffer[0] === 0x52 && buffer[1] === 0x49 && buffer[2] === 0x46 && buffer[3] === 0x46 &&
                         buffer[8] === 0x57 && buffer[9] === 0x45 && buffer[10] === 0x42 && buffer[11] === 0x50) {
                    detectedType = 'image/webp';
                }

                if (detectedType) {
                    contentType = detectedType;
                    console.log(`[ProxyImage] Content-Type 자동 감지: ${contentType}`);
                } else {
                    return res.status(400).json({ error: "지원하지 않는 이미지 형식입니다." });
                }
            } else {
                // Content-Type이 image/로 시작하면 그대로 사용
                console.log(`[ProxyImage] Content-Type: ${contentType}`);
            }

            // 캐시 헤더 설정 (1시간)
            res.set('Cache-Control', 'public, max-age=3600');
            res.set('Content-Type', contentType);

            res.send(response.data);

        } catch (error) {
            logError("GET /api/pages/proxy/image", error);
            res.status(500).json({ error: "이미지 프록시 실패" });
        }
    });

    /**
     * 페이지 발행 상태 확인
     * GET /api/pages/:id/publish
     */
    router.get("/:id/publish", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;

        try {
            const [pageRows] = await pool.execute(
                `SELECT p.id, p.user_id, p.collection_id, p.is_encrypted
                 FROM pages p WHERE p.id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];
            const { permission } = await getCollectionPermission(page.collection_id, userId);
            if (!permission) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            const [publishRows] = await pool.execute(
                `SELECT token, created_at FROM page_publish_links
                 WHERE page_id = ? AND is_active = 1`,
                [pageId]
            );

            if (publishRows.length === 0) {
                return res.json({ published: false });
            }

            const publish = publishRows[0];

            res.json({
                published: true,
                token: publish.token,
                url: `${process.env.BASE_URL || "https://localhost:3000"}/shared/page/${publish.token}`,
                createdAt: toIsoString(publish.created_at)
            });

        } catch (error) {
            logError("GET /api/pages/:id/publish", error);
            res.status(500).json({ error: "발행 상태 확인 실패" });
        }
    });

    /**
     * 페이지 발행
     * POST /api/pages/:id/publish
     */
    router.post("/:id/publish", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;

        try {
            const [pageRows] = await pool.execute(
                `SELECT id, user_id, is_encrypted FROM pages WHERE id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];

            if (page.user_id !== userId) {
                return res.status(403).json({ error: "페이지 소유자만 발행할 수 있습니다." });
            }

            if (page.is_encrypted === 1) {
                return res.status(400).json({
                    error: "암호화된 페이지는 발행할 수 없습니다."
                });
            }

            // 이미 발행된 경우 기존 토큰 반환
            const [existingRows] = await pool.execute(
                `SELECT token FROM page_publish_links
                 WHERE page_id = ? AND is_active = 1`,
                [pageId]
            );

            if (existingRows.length > 0) {
                const token = existingRows[0].token;
                const url = `${process.env.BASE_URL || "https://localhost:3000"}/shared/page/${token}`;
                return res.json({ ok: true, token, url });
            }

            // 새 토큰 생성
            const token = generatePublishToken();
            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `INSERT INTO page_publish_links
                 (token, page_id, owner_user_id, is_active, created_at, updated_at)
                 VALUES (?, ?, ?, 1, ?, ?)`,
                [token, pageId, userId, nowStr, nowStr]
            );

            const url = `${process.env.BASE_URL || "https://localhost:3000"}/shared/page/${token}`;
            // 보안: 토큰 일부만 표시
            console.log(`POST /api/pages/:id/publish 발행 완료: ${pageId}, 토큰: ${token.substring(0, 8)}...`);

            res.json({ ok: true, token, url });

        } catch (error) {
            logError("POST /api/pages/:id/publish", error);
            res.status(500).json({ error: "페이지 발행 실패" });
        }
    });

    /**
     * 페이지 발행 취소
     * DELETE /api/pages/:id/publish
     */
    router.delete("/:id/publish", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;

        try {
            const [pageRows] = await pool.execute(
                `SELECT id, user_id FROM pages WHERE id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            if (pageRows[0].user_id !== userId) {
                return res.status(403).json({ error: "페이지 소유자만 발행을 취소할 수 있습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `UPDATE page_publish_links
                 SET is_active = 0, updated_at = ?
                 WHERE page_id = ? AND is_active = 1`,
                [nowStr, pageId]
            );

            console.log("DELETE /api/pages/:id/publish 발행 취소 완료:", pageId);
            res.json({ ok: true });

        } catch (error) {
            logError("DELETE /api/pages/:id/publish", error);
            res.status(500).json({ error: "발행 취소 실패" });
        }
    });

    return router;
};
