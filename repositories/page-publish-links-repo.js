
module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    function buildInClausePlaceholders(ids) {
        return ids.map(() => '?').join(',');
    }

    return {
        async listActiveLinksForPageIds(pageIds) {
            if (!Array.isArray(pageIds) || pageIds.length === 0) {
                return [];
            }

            const placeholders = buildInClausePlaceholders(pageIds);
            const [rows] = await pool.execute(
                `SELECT page_id, token, created_at, allow_comments
                 FROM page_publish_links
                 WHERE page_id IN (${placeholders}) AND is_active = 1`,
                pageIds
            );

            return rows || [];
        }
    };
};