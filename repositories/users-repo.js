/**
 * 사용자 저장소
 * - DB users 테이블 접근
 */

module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    return {
        /**
         * 부트스트랩 용 사용자 프로필(최소 필드)
         */
        async getBootstrapUserById(userId) {
            const [rows] = await pool.execute(
                `SELECT id, username, theme, sticky_header FROM users WHERE id = ?`,
                [userId]
            );
            return rows?.[0] || null;
        },

        /**
         * 사용자 검색 (참여자 추가용)
         */
        async searchUsers(query, excludeUserId) {
            const [rows] = await pool.execute(
                `SELECT id, username FROM users 
                 WHERE username LIKE ? AND id != ?
                 LIMIT 10`,
                [`%${query}%`, excludeUserId]
            );
            return rows;
        },

        /**
         * 사용자 ID로 사용자 조회
         */
        async getUserById(userId) {
            const [rows] = await pool.execute(
                `SELECT id, username FROM users WHERE id = ?`,
                [userId]
            );
            return rows?.[0] || null;
        }
    };
};