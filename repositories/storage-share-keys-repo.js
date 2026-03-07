module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    return {
        async getWrappedDek(storageId, userId) {
            const [rows] = await pool.execute(
                `SELECT id, storage_id, shared_with_user_id, wrapped_dek, wrapping_kid, ephemeral_public_key, created_at
                 FROM storage_share_keys
                 WHERE storage_id = ? AND shared_with_user_id = ?`,
                [storageId, userId]
            );
            return rows?.[0] || null;
        },

        async upsertWrappedDek({ storageId, sharedWithUserId, wrappedDek, wrappingKid, ephemeralPublicKey, createdAt }) {
            await pool.execute(
                `INSERT INTO storage_share_keys (storage_id, shared_with_user_id, wrapped_dek, wrapping_kid, ephemeral_public_key, created_at)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE
                    wrapped_dek = ?,
                    wrapping_kid = ?,
                    ephemeral_public_key = ?,
                    created_at = ?`,
                [storageId, sharedWithUserId, wrappedDek, wrappingKid, ephemeralPublicKey || null, createdAt,
                 wrappedDek, wrappingKid, ephemeralPublicKey || null, createdAt]
            );
        },

        async deleteWrappedDek(storageId, userId) {
            await pool.execute(
                `DELETE FROM storage_share_keys WHERE storage_id = ? AND shared_with_user_id = ?`,
                [storageId, userId]
            );
        }
    };
};
