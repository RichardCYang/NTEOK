/**
 * 사용자 저장소
 * - DB users 테이블 접근
 */

module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    // SQL LIKE 패턴용 이스케이프
    // % , _ , \ 를 literal 문자로 검색되게 변환
    function escapeLikePattern(input) {
        return String(input ?? '').replace(/[\\%_]/g, (ch) => `\\${ch}`);
    }

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
            const q = String(query ?? '').trim();
            if (!q) return [];

            const escaped = escapeLikePattern(q);

            const [rows] = await pool.execute(
                `SELECT id, username FROM users 
                 WHERE username LIKE ? ESCAPE '\\\\'
                   AND id != ?
                 ORDER BY username ASC
                 LIMIT 10`,
                // substring 검색('%term%') 대신 prefix 검색('term%')로 변경
                // - 인덱스 효율 개선
                // - 대량 스캔 비용 완화
                [`${escaped}%`, excludeUserId]
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