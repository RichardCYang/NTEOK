const express = require('express');
const router = express.Router();

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
        broadcastToCollection,
        logError,
        coverUpload,
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
     */
    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const collectionId =
                typeof req.query.collectionId === "string" && req.query.collectionId.trim() !== ""
                    ? req.query.collectionId.trim()
                    : null;

            let query = `
                SELECT DISTINCT p.id, p.title, p.updated_at, p.parent_id, p.sort_order, p.collection_id, p.is_encrypted, p.share_allowed, p.user_id, p.icon, p.cover_image, p.cover_position
                FROM pages p
                LEFT JOIN collections c ON p.collection_id = c.id
                LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                WHERE (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)
                  AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
            `;
            const params = [userId, userId, userId, userId];

            if (collectionId) {
                query += ` AND p.collection_id = ?`;
                params.push(collectionId);
            }

            query += `
                ORDER BY p.collection_id ASC, p.parent_id IS NULL DESC, p.sort_order ASC, p.updated_at DESC
            `;

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
                coverPosition: row.cover_position || 50
            }));

            console.log("GET /api/pages 응답 개수:", list.length);

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
                `SELECT p.id, p.title, p.content, p.title_encrypted, p.content_encrypted, p.search_index_encrypted,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.collection_id,
                        p.is_encrypted, p.share_allowed, p.user_id, p.icon, p.cover_image, p.cover_position
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
                titleEncrypted: row.title_encrypted || null,  // E2EE 시스템 재설계
                contentEncrypted: row.content_encrypted || null,  // E2EE 시스템 재설계
                searchIndexEncrypted: row.search_index_encrypted || null,  // E2EE 시스템 재설계
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
                coverPosition: row.cover_position || 50
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

        // 평문 필드 (공유 컬렉션용)
        const titleFromBody = typeof req.body.title === "string" ? sanitizeInput(req.body.title.trim()) : null;
        const contentFromBody = typeof req.body.content === "string" ? sanitizeHtmlContent(req.body.content) : null;
        const isEncryptedFromBody = typeof req.body.isEncrypted === "boolean" ? req.body.isEncrypted : null;
        const iconFromBody = typeof req.body.icon === "string" ? req.body.icon.trim() : undefined;

        // 암호화 필드 (개인 페이지용) - E2EE 시스템 재설계
        const titleEncryptedFromBody = typeof req.body.titleEncrypted === "string" ? req.body.titleEncrypted : null;
        const contentEncryptedFromBody = typeof req.body.contentEncrypted === "string" ? req.body.contentEncrypted : null;
        const searchIndexEncryptedFromBody = typeof req.body.searchIndexEncrypted === "string" ? req.body.searchIndexEncrypted : null;

        if (!titleFromBody && !contentFromBody && isEncryptedFromBody === null && iconFromBody === undefined &&
            !titleEncryptedFromBody && !contentEncryptedFromBody && !searchIndexEncryptedFromBody) {
            return res.status(400).json({ error: "수정할 데이터 없음." });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, title, content, title_encrypted, content_encrypted, search_index_encrypted,
                        created_at, updated_at, parent_id, sort_order, collection_id, is_encrypted, user_id, icon
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

            // E2EE: 제목은 평문 유지 (검색/목록 표시용), 내용만 암호화
            let newTitle, newContent;
            // 제목은 항상 평문으로 저장
            newTitle = titleFromBody && titleFromBody !== "" ? titleFromBody : existing.title;

            if (newIsEncrypted === 1) {
                // 암호화된 페이지: content는 빈 문자열 (암호화됨)
                newContent = '';
            } else {
                // 평문 페이지: content도 평문 저장
                newContent = contentFromBody !== null ? contentFromBody : existing.content;
            }

            const newIcon = iconFromBody !== undefined ? (iconFromBody !== "" ? iconFromBody : null) : existing.icon;

            // 암호화 필드 업데이트 - E2EE 시스템 재설계
            const newTitleEncrypted = titleEncryptedFromBody !== null ? titleEncryptedFromBody : existing.title_encrypted;
            const newContentEncrypted = contentEncryptedFromBody !== null ? contentEncryptedFromBody : existing.content_encrypted;
            const newSearchIndexEncrypted = searchIndexEncryptedFromBody !== null ? searchIndexEncryptedFromBody : existing.search_index_encrypted;

            const now = new Date();
            const nowStr = formatDateForDb(now);

            const isBecomingEncrypted = existing.is_encrypted === 0 && newIsEncrypted === 1;

            if (isBecomingEncrypted) {
                await pool.execute(
                    `UPDATE pages
                     SET title = ?, content = ?, title_encrypted = ?, content_encrypted = ?, search_index_encrypted = ?,
                         is_encrypted = ?, icon = ?, user_id = ?, updated_at = ?
                     WHERE id = ?`,
                    [newTitle, newContent, newTitleEncrypted, newContentEncrypted, newSearchIndexEncrypted,
                     newIsEncrypted, newIcon, userId, nowStr, id]
                );
            } else {
                await pool.execute(
                    `UPDATE pages
                     SET title = ?, content = ?, title_encrypted = ?, content_encrypted = ?, search_index_encrypted = ?,
                         is_encrypted = ?, icon = ?, updated_at = ?
                     WHERE id = ?`,
                    [newTitle, newContent, newTitleEncrypted, newContentEncrypted, newSearchIndexEncrypted,
                     newIsEncrypted, newIcon, nowStr, id]
                );
            }

            const page = {
                id,
                title: newTitle,
                content: newContent,
                titleEncrypted: newTitleEncrypted,  // E2EE 시스템 재설계
                contentEncrypted: newContentEncrypted,  // E2EE 시스템 재설계
                searchIndexEncrypted: newSearchIndexEncrypted,  // E2EE 시스템 재설계
                parentId: existing.parent_id,
                sortOrder: existing.sort_order,
                collectionId: existing.collection_id,
                createdAt: toIsoString(existing.created_at),
                updatedAt: now.toISOString(),
                icon: newIcon
            };

            console.log("PUT /api/pages/:id 수정 완료:", id);

            if (titleFromBody && titleFromBody !== existing.title) {
                broadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'title',
                    value: newTitle
                }, userId);
            }

            if (iconFromBody !== undefined && newIcon !== existing.icon) {
                broadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'icon',
                    value: newIcon
                }, userId);
            }

            res.json(page);
        } catch (error) {
            logError("PUT /api/pages/:id", error);
            res.status(500).json({ error: "페이지 수정 실패." });
        }
    });

    /**
     * 페이지 삭제 (EDIT 이상 권한 필요)
     * DELETE /api/pages/:id
     */
    router.delete("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const [rows] = await pool.execute(
                `SELECT id, collection_id FROM pages WHERE id = ?`,
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

            await pool.execute(
                `DELETE FROM pages WHERE id = ?`,
                [id]
            );

            console.log("DELETE /api/pages/:id 삭제:", id);

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

            // SSE 브로드캐스트
            broadcastToCollection(rows[0].collection_id, 'metadata-change', {
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

            // SSE 브로드캐스트
            if (coverImage !== undefined) {
                broadcastToCollection(rows[0].collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'coverImage',
                    value: coverImage
                }, userId);
            }
            if (typeof coverPosition === 'number') {
                broadcastToCollection(rows[0].collection_id, 'metadata-change', {
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

            // SSE 브로드캐스트
            broadcastToCollection(rows[0].collection_id, 'metadata-change', {
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

    return router;
};
