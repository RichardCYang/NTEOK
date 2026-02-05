/**
 * 페이지 발행 링크 저장소
 * - DB page_publish_links 테이블 접근
 */

module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    function buildInClausePlaceholders(ids) {
        return ids.map(() => '?').join(',');
    }

    return {
        /**
         * 백업 내보내기: 활성화된 발행 링크 조회
         */
        async listActiveLinksForPageIds(pageIds) {
            if (!Array.isArray(pageIds) || pageIds.length === 0) {
                return [];
            }

            const placeholders = buildInClausePlaceholders(pageIds);
            const [rows] = await pool.execute(
                `SELECT page_id, token, created_at
                 FROM page_publish_links
                 WHERE page_id IN (${placeholders}) AND is_active = 1`,
                pageIds
            );

            return rows || [];
        }
    };
};