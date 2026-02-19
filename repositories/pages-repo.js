/**
 * 페이지 저장소
 * - DB pages 테이블 접근
 * - 페이지 접근 권한 정책을 중앙에서 강제 (pageSqlPolicy)
 */

module.exports = ({ pool, pageSqlPolicy }) => {
    if (!pool) throw new Error("pool 필요");
    if (!pageSqlPolicy) throw new Error("pageSqlPolicy 필요");

    // ====== subtree mutation helpers (access control safe) ======
    const SUBTREE_BATCH_SIZE = (() => {
        const n = Number.parseInt(process.env.PAGE_SUBTREE_BATCH_SIZE || "500", 10);
        if (!Number.isFinite(n)) return 500;
        return Math.max(50, Math.min(2000, n));
    })();

    function chunkArray(arr, size) {
        const out = [];
        for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
        return out;
    }

    function buildChildrenIndex(rows) {
        const map = new Map();
        for (const r of rows) {
            const p = r.parent_id || null;
            if (!map.has(p)) map.set(p, []);
            map.get(p).push(r);
        }
        return map;
    }

    function collectSubtreeIds(rows, rootId) {
        const byParent = buildChildrenIndex(rows);
        const seen = new Set();
        const order = [];
        const stack = [rootId];
        while (stack.length) {
            const id = stack.pop();
            if (seen.has(id)) continue;
            seen.add(id);
            order.push(id);
            const children = byParent.get(id) || [];
            for (const c of children) stack.push(c.id);
        }
        return order;
    }

    function splitIdsByPermission(rowsById, ids, actorUserId, isAdmin) {
        const allowed = [];
        const disallowed = [];
        for (const id of ids) {
            const row = rowsById.get(id);
            if (!row) continue;
            if (isAdmin || Number(row.user_id) === Number(actorUserId)) allowed.push(id);
            else disallowed.push(id);
        }
        return { allowed, disallowed };
    }

    async function updateByIdInBatches(sqlPrefixWhereIdIn, ids, paramsBeforeIds = []) {
        if (!Array.isArray(ids) || ids.length === 0) return;
        for (const chunk of chunkArray(ids, SUBTREE_BATCH_SIZE)) {
            const placeholders = chunk.map(() => '?').join(',');
            const sql = `${sqlPrefixWhereIdIn} (${placeholders})`;
            await pool.execute(sql, [...paramsBeforeIds, ...chunk]);
        }
    }

    return {
        /**
         * 페이지 목록 조회 (특정 저장소의 페이지: 소유한 페이지 + 공유받은 페이지)
         */
        async listPagesForUser({ userId, storageId = null }) {
            // storageId가 없으면 빈 목록 반환 (저장소별 격리 강제)
            if (!storageId) return [];

            const visOwner = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const visShared = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });

            const query = `
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.storage_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    WHERE p.user_id = ?
                    AND p.storage_id = ?
                    AND p.deleted_at IS NULL
                    ${visOwner.sql}
                )
                UNION ALL
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.storage_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    INNER JOIN storage_shares ss ON p.storage_id = ss.storage_id
                    WHERE ss.shared_with_user_id = ?
                    AND p.storage_id = ?
                    AND p.deleted_at IS NULL
                    ${visShared.sql}
                )
                ORDER BY parent_id IS NULL DESC, sort_order ASC, updated_at DESC
            `;

            const params = [
                userId, storageId, ...visOwner.params,
                userId, storageId, ...visShared.params
            ];

            const [rows] = await pool.execute(query, params);
            return rows || [];
        },

        /**
         * 단일 페이지 조회
         */
        async getPageByIdForUser({ userId, pageId, includeDeleted = false }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            let sql = `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.storage_id,
                        p.is_encrypted, p.share_allowed, p.user_id, p.icon, p.cover_image, p.cover_position,
                        p.horizontal_padding, p.deleted_at
                 FROM pages p
                 LEFT JOIN storage_shares ss ON p.storage_id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE p.id = ? AND (p.user_id = ? OR ss.storage_id IS NOT NULL)
                 ${vis.sql}`;
            
            if (!includeDeleted) {
                sql += ` AND p.deleted_at IS NULL`;
            }

            const [rows] = await pool.execute(sql, [userId, pageId, userId, ...vis.params]);

            return rows?.[0] || null;
        },

        /**
         * 휴지통 목록 조회
         */
        async listTrashedPagesForUser({ userId, storageId }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.updated_at, p.deleted_at, p.storage_id, p.user_id
                 FROM pages p
                 LEFT JOIN storage_shares ss ON p.storage_id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE (p.user_id = ? OR ss.storage_id IS NOT NULL)
                 AND p.storage_id = ?
                 AND p.deleted_at IS NULL = 0
                 ${vis.sql}
                 ORDER BY p.deleted_at DESC`,
                [userId, userId, storageId, ...vis.params]
            );
            return rows || [];
        },

        /**
         * 페이지 복구
         */
        async restorePage(pageId, userId) {
            // 권한 체크: 본인 소유이거나 저장소 관리 권한이 있어야 함 (단순하게 소유자만 가능하게 하거나, 저장소 권한 연동)
            // 여기서는 페이지 작성자 혹은 저장소 소유자만 복구 가능하게 함
            await pool.execute(
                `UPDATE pages SET deleted_at = NULL WHERE id = ? AND (user_id = ? OR storage_id IN (SELECT id FROM storages WHERE user_id = ?))`,
                [pageId, userId, userId]
            );
        },

        /**
         * 페이지 및 모든 하위 페이지 복구
         * 보안: 하위 트리 업데이트는 반드시 객체 단위 권한(Object-level auth)을 강제해야 함
         * - ADMIN: 서브트리 전체 복구
         * - EDIT : 본인 소유 페이지(및 그 하위 중 본인 소유)만 복구
         */
        async restorePageAndDescendants({ rootPageId, storageId, actorUserId, isAdmin = false }) {
            if (!rootPageId || !storageId) return;

            const [allPages] = await pool.execute(
                `SELECT id, parent_id, user_id FROM pages WHERE storage_id = ?`,
                [storageId]
            );

            const rowsById = new Map((allPages || []).map(r => [r.id, r]));
            if (!rowsById.has(rootPageId)) return;

            const subtreeIds = collectSubtreeIds(allPages || [], rootPageId);
            const { allowed: restorableIds } = splitIdsByPermission(rowsById, subtreeIds, actorUserId, isAdmin);

            // 복구할 대상이 없으면 종료
            if (!restorableIds || restorableIds.length === 0) return;

            await updateByIdInBatches(
                `UPDATE pages SET deleted_at = NULL WHERE id IN`,
                restorableIds
            );
        },

        /**
         * 페이지 영구 삭제
         */
        async permanentlyDeletePage(pageId, userId) {
            await pool.execute(
                `DELETE FROM pages WHERE id = ? AND (user_id = ? OR storage_id IN (SELECT id FROM storages WHERE user_id = ?))`,
                [pageId, userId, userId]
            );
        },

        /**
         * 페이지 및 모든 하위 페이지 휴지통으로 이동
         * 보안: 내가 삭제할 수 있는 페이미만 soft-delete 해야 함
         * - ADMIN: 서브트리 전체 삭제
         * - EDIT : 본인 소유 페이미만 삭제(다른 사용자의 하위 페이지는 삭제하지 않고 부모를 재연결)
         */
        async softDeletePageAndDescendants({ rootPageId, storageId, rootParentId = null, actorUserId, isAdmin = false }) {
            if (!rootPageId || !storageId) return;

            const [allPages] = await pool.execute(
                `SELECT id, parent_id, user_id FROM pages WHERE storage_id = ?`,
                [storageId]
            );

            const rowsById = new Map((allPages || []).map(r => [r.id, r]));
            if (!rowsById.has(rootPageId)) return;

            const subtreeIds = collectSubtreeIds(allPages || [], rootPageId);

            const { allowed: deletableIds, disallowed: keptIds } =
                splitIdsByPermission(rowsById, subtreeIds, actorUserId, isAdmin);

            if (!isAdmin && keptIds && keptIds.length > 0) {
                const safeParentId = rootParentId || null;
                await updateByIdInBatches(
                    `UPDATE pages SET parent_id = ?, updated_at = NOW() WHERE id IN`,
                    keptIds,
                    [safeParentId]
                );
            }

            if (!deletableIds || deletableIds.length === 0) return;

            await updateByIdInBatches(
                `UPDATE pages SET deleted_at = NOW() WHERE id IN`,
                deletableIds
            );

            // 보안: 휴지통 이동 시 기존 공개 발행 링크(베어러 토큰)가 남아있으면
            // 삭제된 페이지가 계속 외부에 노출될 수 있으므로 즉시 비활성화
            // (하위 페이지들도 동일 적용)
            await updateByIdInBatches(
                `UPDATE page_publish_links SET is_active = 0, updated_at = NOW() WHERE is_active = 1 AND page_id IN`,
                deletableIds
            );
        },

        /**
         * 백업 내보내기: 내 저장소에 속한 모든 페이지
         */
        async listPagesForBackupExport({ userId }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.storage_id,
                        p.is_encrypted, p.share_allowed, p.icon, p.cover_image, p.cover_position
                 FROM pages p
                 WHERE p.storage_id IN (SELECT id FROM storages WHERE user_id = ?)
                 AND p.deleted_at IS NULL
                 ${vis.sql}
                 ORDER BY p.storage_id ASC, p.parent_id IS NULL DESC, p.sort_order ASC`,
                [userId, ...vis.params]
            );
                        return rows || [];
                    },
            
                    /**
                     * 업데이트 히스토리 기록
                     */
                    async recordUpdateHistory({ userId, storageId, pageId, action, details }) {
                        const detailsStr = details ? JSON.stringify(details) : null;
                        await pool.execute(
                            `INSERT INTO updates_history (user_id, storage_id, page_id, action, details, created_at)
                             VALUES (?, ?, ?, ?, ?, NOW())`,
                            [userId, storageId, pageId, action, detailsStr]
                        );
                    },
            
                    /**
                     * 업데이트 히스토리 조회
                     */
                    async getUpdateHistory({ userId, storageId, limit = 50 }) {
                        // 내가 접근 가능한 저장소의 히스토리만 조회 (소유 또는 공유)
                        const [rows] = await pool.execute(
                            `SELECT h.*, u.username, p.title as page_title
                             FROM updates_history h
                             INNER JOIN users u ON h.user_id = u.id
                             LEFT JOIN pages p ON h.page_id = p.id
                             LEFT JOIN storage_shares ss ON h.storage_id = ss.storage_id AND ss.shared_with_user_id = ?
                             INNER JOIN storages s ON h.storage_id = s.id
                             WHERE h.storage_id = ? AND (s.user_id = ? OR ss.storage_id IS NOT NULL)
                             ORDER BY h.created_at DESC
                             LIMIT ?`,
                            [userId, storageId, userId, limit]
                        );
                        return rows || [];
                    }
                };
            };
            