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
         * 페이지 목록 조회 (소유한 페이지 + 공유받은 컬렉션의 페이지)
         * - routes/pages.js 및 routes/bootstrap.js 의 기존 UNION ALL 쿼리...
         */
        async listPagesForUser({ userId, collectionId = null }) {
            const visOwner = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const visShared = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });

            const query = `
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.collection_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    INNER JOIN collections c ON p.collection_id = c.id
                    WHERE c.user_id = ?
                    ${visOwner.sql}
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
                    ${visShared.sql}
                    ${collectionId ? 'AND p.collection_id = ?' : ''}
                )
                ORDER BY collection_id ASC, parent_id IS NULL DESC, sort_order ASC, updated_at DESC
            `;

            const params = collectionId
                ? [
                    userId,
                    ...visOwner.params,
                    collectionId,
                    userId,
                    ...visShared.params,
                    collectionId
                ]
                : [
                    userId,
                    ...visOwner.params,
                    userId,
                    ...visShared.params
                ];

            const [rows] = await pool.execute(query, params);
            return rows || [];
        },

        /**
         * 단일 페이지 조회 (소유한 페이지 또는 공유받은 컬렉션의 페이지)
         */
        async getPageByIdForUser({ userId, pageId }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.collection_id,
                        p.is_encrypted, p.share_allowed, p.user_id, p.icon, p.cover_image, p.cover_position,
                        p.horizontal_padding
                 FROM pages p
                 LEFT JOIN collections c ON p.collection_id = c.id
                 LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                 WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)
                 ${vis.sql}`,
                [userId, pageId, userId, userId, ...vis.params]
            );

            return rows?.[0] || null;
        },

        /**
         * 백업 내보내기: 내 컬렉션에 속한 모든 페이지(암호화 필드 포함)
         * - 단, pageSqlPolicy를 적용하여 암호화 + 공유불가 페이지는 작성자 본인만 포함되도록 함
         */
        async listPagesForBackupExport({ userId }) {
            const vis = pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId });
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.collection_id,
                        p.is_encrypted, p.share_allowed, p.icon, p.cover_image, p.cover_position
                 FROM pages p
                 WHERE p.collection_id IN (SELECT id FROM collections WHERE user_id = ?)
                 ${vis.sql}
                 ORDER BY p.collection_id ASC, p.parent_id IS NULL DESC, p.sort_order ASC`,
                [userId, ...vis.params]
            );
            return rows || [];
        }
    };
};