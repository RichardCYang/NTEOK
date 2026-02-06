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
        }
    };
};