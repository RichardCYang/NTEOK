/**
 * 저장소(Storage) 저장소
 * - DB storages 테이블 접근
 */

module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    return {
        /**
         * 사용자가 소유하거나 공유받은 저장소 목록 조회
         */
        async listStoragesForUser(userId) {
            const [rows] = await pool.execute(
                `SELECT s.id, s.name, s.sort_order, s.created_at, s.updated_at, s.user_id as owner_id,
                        s.is_encrypted, s.encryption_salt, s.encryption_check,
                        u.username as owner_name,
                        CASE WHEN s.user_id = ? THEN 1 ELSE 0 END as is_owner,
                        ss.permission
                 FROM storages s
                 LEFT JOIN users u ON s.user_id = u.id
                 LEFT JOIN storage_shares ss ON s.id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE s.user_id = ? OR ss.shared_with_user_id = ?
                 ORDER BY is_owner DESC, s.sort_order ASC, s.updated_at DESC`,
                [userId, userId, userId, userId]
            );
            return rows || [];
        },

        /**
         * 단일 저장소 조회 (소유 또는 공유 권한 확인)
         */
        async getStorageByIdForUser(userId, storageId) {
            const [rows] = await pool.execute(
                `SELECT s.id, s.name, s.sort_order, s.created_at, s.updated_at, s.user_id as owner_id,
                        s.is_encrypted, s.encryption_salt, s.encryption_check,
                        CASE WHEN s.user_id = ? THEN 1 ELSE 0 END as is_owner,
                        ss.permission
                 FROM storages s
                 LEFT JOIN storage_shares ss ON s.id = ss.storage_id AND ss.shared_with_user_id = ?
                 WHERE s.id = ? AND (s.user_id = ? OR ss.shared_with_user_id = ?)`,
                [userId, userId, storageId, userId, userId]
            );
            return rows?.[0] || null;
        },

        /**
         * 저장소 참여자 목록 조회
         */
        async listCollaborators(storageId) {
            const [rows] = await pool.execute(
                `SELECT ss.shared_with_user_id as id, u.username, ss.permission
                 FROM storage_shares ss
                 JOIN users u ON ss.shared_with_user_id = u.id
                 WHERE ss.storage_id = ?
                 ORDER BY u.username ASC`,
                [storageId]
            );
            return rows;
        },

        /**
         * 저장소 참여자 추가
         */
        async addCollaborator({ storageId, ownerUserId, sharedWithUserId, permission, createdAt, updatedAt }) {
            await pool.execute(
                `INSERT INTO storage_shares (storage_id, owner_user_id, shared_with_user_id, permission, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE permission = ?, updated_at = ?`,
                [storageId, ownerUserId, sharedWithUserId, permission, createdAt, updatedAt, permission, updatedAt]
            );
        },

        /**
         * 저장소 참여자 삭제
         */
        async removeCollaborator(storageId, userId) {
            await pool.execute(
                `DELETE FROM storage_shares WHERE storage_id = ? AND shared_with_user_id = ?`,
                [storageId, userId]
            );
        },

        /**
         * 사용자의 저장소 권한 조회
         */
        async getPermission(userId, storageId) {
            const storage = await this.getStorageByIdForUser(userId, storageId);
            if (!storage) return null;
            if (storage.is_owner) return 'ADMIN';
            return storage.permission || null;
        },

        /**
         * 저장소 생성
         */
        async createStorage({ userId, id, name, sortOrder, createdAt, updatedAt, isEncrypted, encryptionSalt, encryptionCheck }) {
            await pool.execute(
                `INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at, is_encrypted, encryption_salt, encryption_check)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, userId, name, sortOrder, createdAt, updatedAt, isEncrypted || 0, encryptionSalt || null, encryptionCheck || null]
            );
            return { id, userId, name, sortOrder, createdAt, updatedAt, isEncrypted, encryptionSalt, encryptionCheck };
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
