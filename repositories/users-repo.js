
module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    function escapeLikePattern(input) {
        return String(input ?? '').replace(/[\\%_]/g, (ch) => `\\${ch}`);
    }

    return {
        async getBootstrapUserById(userId) {
            const [rows] = await pool.execute(
                `SELECT id, username, theme, sticky_header FROM users WHERE id = ?`,
                [userId]
            );
            return rows?.[0] || null;
        },

        async searchUsers(query, excludeUserId) {
            const q = String(query ?? '').trim();
            if (!q) return [];

            const escaped = escapeLikePattern(q);

            const [rows] = await pool.execute(
                `SELECT id, username FROM users 
                 WHERE username LIKE ? ESCAPE '\\\\'
                   AND id != ?
                 ORDER BY username ASC
                 LIMIT 10`,
                [`${escaped}%`, excludeUserId]
            );
            return rows;
        },

        async getUserById(userId) {
            const [rows] = await pool.execute(
                `SELECT id, username FROM users WHERE id = ?`,
                [userId]
            );
            return rows?.[0] || null;
        }
    };
};