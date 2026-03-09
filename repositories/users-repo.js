
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

        async findUserByExactUsername(username, excludeUserId) {
            if (!username) return null;
            const [rows] = await pool.execute(
                `SELECT id, username FROM users WHERE username = ? AND id != ?`,
                [username, excludeUserId]
            );
            return rows[0] || null;
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