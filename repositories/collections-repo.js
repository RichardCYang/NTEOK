/**
 * 컬렉션 저장소
 * - DB collections 테이블 접근
 */

module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    return {
        /**
         * 특정 저장소의 컬렉션 목록 조회 (소유한 컬렉션 + 공유받은 컬렉션)
         */
        async listCollectionsForStorage(userId, storageId) {
            const [rows] = await pool.execute(
                `(
                    SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                           c.user_id as owner_id, c.is_encrypted,
                           c.default_encryption, c.enforce_encryption,
                           'OWNER' as permission
                    FROM collections c
                    WHERE c.user_id = ? AND c.storage_id = ?
                )
                UNION ALL
                (
                    SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                           c.user_id as owner_id, c.is_encrypted,
                           c.default_encryption, c.enforce_encryption,
                           cs.permission as permission
                    FROM collections c
                    INNER JOIN collection_shares cs ON c.id = cs.collection_id
                    WHERE cs.shared_with_user_id = ? AND c.storage_id = ?
                )
                ORDER BY sort_order ASC, updated_at DESC`,
                [userId, storageId, userId, storageId]
            );
            return rows || [];
        },

        /**
         * 부트스트랩: 소유한 컬렉션 + 공유받은 컬렉션을 한 번에 조회
         * (이제 저장소 기반으로 바뀌었으므로, 하위 호환성을 위해 유지하거나 제거 가능)
         */
        async listCollectionsForBootstrap(userId) {
            const [rows] = await pool.execute(
                `(
                    SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                           c.user_id as owner_id, c.is_encrypted,
                           c.default_encryption, c.enforce_encryption,
                           'OWNER' as permission
                    FROM collections c
                    WHERE c.user_id = ?
                )
                UNION ALL
                (
                    SELECT c.id, c.name, c.sort_order, c.created_at, c.updated_at,
                           c.user_id as owner_id, c.is_encrypted,
                           c.default_encryption, c.enforce_encryption,
                           cs.permission as permission
                    FROM collections c
                    INNER JOIN collection_shares cs ON c.id = cs.collection_id
                    WHERE cs.shared_with_user_id = ?
                )
                ORDER BY sort_order ASC, updated_at DESC`,
                [userId, userId]
            );
            return rows || [];
        },

        /**
         * 백업 내보내기: 해당 유저가 소유한 모든 컬렉션(암호화 관련 필드 포함)
         */
        async listCollectionsOwnedByUser(userId) {
            const [rows] = await pool.execute(
                `SELECT id, name, sort_order, created_at, updated_at,
                        is_encrypted, default_encryption, enforce_encryption
                 FROM collections
                 WHERE user_id = ?
                 ORDER BY sort_order ASC`,
                [userId]
            );
            return rows || [];
        }
    };
};