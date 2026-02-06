/**
 * 페이지 저장소
 * - DB pages 테이블 접근
 * - 페이지 접근 권한 정책을 중앙에서 강제 (pageSqlPolicy)
 */

module.exports = ({ pool, pageSqlPolicy }) => {
    if (!pool) throw new Error("pool 필요");
    if (!pageSqlPolicy) throw new Error("pageSqlPolicy 필요");

    return {
        /**
         * 페이지 목록 조회 (소유한 페이지 + 공유받은 저장소의 페이지)
         */
        async listPagesForUser({ userId, storageId = null }) {
            const visOwner = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const visShared = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });

            const query = `
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.storage_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    WHERE p.user_id = ?
                    ${storageId ? 'AND p.storage_id = ?' : ''}
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
                    ${storageId ? 'AND p.storage_id = ?' : ''}
                    ${visShared.sql}
                )
                ORDER BY parent_id IS NULL DESC, sort_order ASC, updated_at DESC
            `;

            const params = [];
            
            // First part of UNION
            params.push(userId);
            if (storageId) params.push(storageId);
            params.push(...visOwner.params);

            // Second part of UNION
            params.push(userId);
            if (storageId) params.push(storageId);
            params.push(...visShared.params);

            const [rows] = await pool.execute(query, params);
            return rows || [];
        },

        /**
         * 단일 페이지 조회
         */
        async getPageByIdForUser({ userId, pageId }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.storage_id,
                        p.is_encrypted, p.share_allowed, p.user_id, p.icon, p.cover_image, p.cover_position,
                        p.horizontal_padding
                 FROM pages p
                 LEFT JOIN storage_shares ss ON p.storage_id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE p.id = ? AND (p.user_id = ? OR ss.storage_id IS NOT NULL)
                 ${vis.sql}`,
                [userId, pageId, userId, ...vis.params]
            );

            return rows?.[0] || null;
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
                 ${vis.sql}
                 ORDER BY p.storage_id ASC, p.parent_id IS NULL DESC, p.sort_order ASC`,
                [userId, ...vis.params]
            );
            return rows || [];
        }
    };
};