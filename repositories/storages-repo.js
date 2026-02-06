/**
 * 저장소(Storage) 저장소
 * - DB storages 테이블 접근
 */

module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    return {
        /**
         * 사용자가 소유한 저장소 목록 조회
         */
        async listStoragesForUser(userId) {
            const [rows] = await pool.execute(
                `SELECT id, name, sort_order, created_at, updated_at
                 FROM storages
                 WHERE user_id = ?
                 ORDER BY sort_order ASC, updated_at DESC`,
                [userId]
            );
            return rows || [];
        },

        /**
         * 단일 저장소 조회
         */
        async getStorageByIdForUser(userId, storageId) {
            const [rows] = await pool.execute(
                `SELECT id, name, sort_order, created_at, updated_at
                 FROM storages
                 WHERE id = ? AND user_id = ?`,
                [storageId, userId]
            );
            return rows?.[0] || null;
        },

        /**
         * 저장소 생성
         */
        async createStorage({ userId, id, name, sortOrder, createdAt, updatedAt }) {
            await pool.execute(
                `INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [id, userId, name, sortOrder, createdAt, updatedAt]
            );
            return { id, userId, name, sortOrder, createdAt, updatedAt };
        },

        /**
         * 저장소 업데이트
         */
        async updateStorage(userId, storageId, { name, updatedAt }) {
            await pool.execute(
                `UPDATE storages SET name = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
                [name, updatedAt, storageId, userId]
            );
        },

        /**
         * 저장소 삭제
         */
        async deleteStorage(userId, storageId) {
            await pool.execute(
                `DELETE FROM storages WHERE id = ? AND user_id = ?`,
                [storageId, userId]
            );
        },

        /**
         * 다음 정렬 순서 조회
         */
        async getNextSortOrder(userId) {
            const [rows] = await pool.execute(
                `SELECT COALESCE(MAX(sort_order), -1) AS maxOrder FROM storages WHERE user_id = ?`,
                [userId]
            );
            return Number(rows[0].maxOrder) + 1;
        }
    };
};
