/**
 * 컬렉션 공유 저장소
 * - DB ollection_shares 테이블 접근
 */

module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    function buildInClausePlaceholders(ids) {
        return ids.map(() => '?').join(',');
    }

    return {
        /**
         * 부트스트랩: 컬렉션별 공유 횟수 (isShared 계산용)
         */
        async getShareCountMapForCollectionIds(collectionIds) {
            if (!Array.isArray(collectionIds) || collectionIds.length === 0)
                return {};

            const placeholders = buildInClausePlaceholders(collectionIds);
            const [rows] = await pool.execute(
                `SELECT collection_id, COUNT(*) as share_count
                 FROM collection_shares
                 WHERE collection_id IN (${placeholders})
                 GROUP BY collection_id`,
                collectionIds
            );

            return (rows || []).reduce((map, row) => {
                map[row.collection_id] = row.share_count;
                return map;
            }, {});
        },

        /**
         * 백업 내보내기: 컬렉션 공유 정보(상대 유저명 포함)
         */
        async listSharesForCollectionIds(collectionIds) {
            if (!Array.isArray(collectionIds) || collectionIds.length === 0)
                return [];

            const placeholders = buildInClausePlaceholders(collectionIds);
            const [rows] = await pool.execute(
                `SELECT cs.collection_id, cs.shared_with_user_id, cs.permission,
                        u.username as shared_with_username
                 FROM collection_shares cs
                 JOIN users u ON cs.shared_with_user_id = u.id
                 WHERE cs.collection_id IN (${placeholders})`,
                collectionIds
            );
            return rows || [];
        }
    };
};