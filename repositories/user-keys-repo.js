module.exports = ({ pool }) => {
    if (!pool) throw new Error("pool 필요");

    return {
        async getKeyPairByKid(kid) {
            const [rows] = await pool.execute(
                `SELECT kid, user_id, public_key_spki, encrypted_private_key, key_wrap_salt, device_label, created_at
                 FROM user_key_pairs
                 WHERE kid = ?`,
                [kid]
            );
            return rows?.[0] || null;
        },

        async listPublicKeysByUserId(userId) {
            const [rows] = await pool.execute(
                `SELECT kid, user_id, public_key_spki, device_label, created_at
                 FROM user_key_pairs
                 WHERE user_id = ?
                 ORDER BY created_at DESC`,
                [userId]
            );
            return rows || [];
        },

        async listMyKeyPairs(userId) {
            const [rows] = await pool.execute(
                `SELECT kid, user_id, public_key_spki, encrypted_private_key, key_wrap_salt, device_label, created_at
                 FROM user_key_pairs
                 WHERE user_id = ?
                 ORDER BY created_at DESC`,
                [userId]
            );
            return rows || [];
        },

        async createKeyPair({ kid, userId, publicKeySpki, encryptedPrivateKey, keyWrapSalt, deviceLabel, createdAt }) {
            await pool.execute(
                `INSERT INTO user_key_pairs (kid, user_id, public_key_spki, encrypted_private_key, key_wrap_salt, device_label, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [kid, userId, publicKeySpki, encryptedPrivateKey, keyWrapSalt, deviceLabel || null, createdAt]
            );
        },

        async deleteKeyPair(userId, kid) {
            await pool.execute(
                `DELETE FROM user_key_pairs WHERE kid = ? AND user_id = ?`,
                [kid, userId]
            );
        }
    };
};
