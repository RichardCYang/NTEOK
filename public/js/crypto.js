
class CryptoManager {
    constructor() {
        this.encryptionKey = null;
        this.salt = null;

        this.storageKey = null;
        this.storageSalt = null;

        this.inactivityTimer = null;
        this.INACTIVITY_TIMEOUT = 15 * 60 * 1000;

        this._extractableDek = null;
        this._myEcdhPrivateKey = null;
    }

    async verifyAndSetStorageKey(password, saltBase64, checkBase64) {
        try {
            const salt = new Uint8Array(this.base64ToArrayBuffer(saltBase64));
            const { key } = await this.deriveKeyFromPassword(password, salt);
            
            const decrypted = await this.decryptWithKey(checkBase64, key);
            if (decrypted !== "VALID") {
                return false;
            }

            this.storageKey = key;
            this.storageSalt = salt;
            return true;
        } catch (e) {
            console.error("Storage key verification failed:", e);
            return false;
        }
    }

    async createStorageEncryptionData(password) {
        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const { key } = await this.deriveKeyFromPassword(password, salt);
        
        const checkBase64 = await this.encryptWithKey("VALID", key);
        const saltBase64 = this.arrayBufferToBase64(salt.buffer);
        
        return {
            salt: saltBase64,
            check: checkBase64
        };
    }

    clearStorageKey() {
        this.storageKey = null;
        this.storageSalt = null;
        this._extractableDek = null;
        this.clearEcdhPrivateKey();
    }

    getStorageKey() {
        return this.storageKey;
    }

    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    async deriveKeyFromPassword(password, salt = null) {
        if (!salt) {
            salt = crypto.getRandomValues(new Uint8Array(16));
        }

        const encoder = new TextEncoder();
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 600000,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        return { key, salt };
    }

    async initializeKey(password, saltBase64 = null) {
        let salt = null;
        if (saltBase64) {
            salt = new Uint8Array(this.base64ToArrayBuffer(saltBase64));
        }

        const { key, salt: derivedSalt } = await this.deriveKeyFromPassword(password, salt);
        this.encryptionKey = key;
        this.salt = derivedSalt;

        this.resetInactivityTimer();

        return this.arrayBufferToBase64(this.salt);
    }

    async encrypt(plaintext) {
        if (!this.encryptionKey) {
            throw new Error('암호화 키가 초기화되지 않았습니다.');
        }

        if (!this.salt) {
            throw new Error('Salt가 초기화되지 않았습니다.');
        }

        const iv = crypto.getRandomValues(new Uint8Array(12));

        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);

        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128 
            },
            this.encryptionKey,
            data
        );

        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        const saltBase64 = this.arrayBufferToBase64(this.salt.buffer);
        const encryptedBase64 = this.arrayBufferToBase64(combined.buffer);

        return `SALT:${saltBase64}:ENC2:${encryptedBase64}`;
    }

    async decrypt(encryptedData, password = null) {
        if (encryptedData.startsWith('SALT:')) {
            const parts = encryptedData.split(':');
            if (parts.length !== 4 || parts[2] !== 'ENC2') {
                throw new Error('암호화 데이터 형식이 올바르지 않습니다.');
            }

            const saltBase64 = parts[1];
            const encryptedBase64 = parts[3];

            let key = this.encryptionKey;
            if (!key) {
                if (!password) throw new Error('복호화에 필요한 비밀번호가 없습니다.');
                key = (await this.deriveKeyFromPassword(password, new Uint8Array(this.base64ToArrayBuffer(saltBase64)))).key;
            }

            const combined = new Uint8Array(this.base64ToArrayBuffer(encryptedBase64));

            const iv = combined.slice(0, 12);
            const ciphertext = combined.slice(12);

            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                key,
                ciphertext
            );

            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        }

        if (!this.encryptionKey) {
            throw new Error('암호화 키가 초기화되지 않았습니다.');
        }

        let dataToDecrypt = encryptedData;
        if (encryptedData.startsWith('ENC1:')) {
            dataToDecrypt = encryptedData.substring(5);
        }

        const combined = new Uint8Array(this.base64ToArrayBuffer(dataToDecrypt));

        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            this.encryptionKey,
            ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    isEncrypted(data) {
        if (!data || typeof data !== 'string') {
            return false;
        }

        if (data.startsWith('SALT:')) {
            return true;
        }

        if (data.startsWith('ENC1:')) {
            return true;
        }

        const isBase64Like = /^[A-Za-z0-9+/]+=*$/.test(data) && data.length > 20;
        return isBase64Like;
    }

    clearKey() {
        this.encryptionKey = null;
        this.salt = null;
        this.stopInactivityTimer();
    }

    isKeyInitialized() {
        return this.encryptionKey !== null;
    }



    resetInactivityTimer() {
        this.stopInactivityTimer();

        this.inactivityTimer = setTimeout(() => {
            console.warn('비활성 시간 초과로 자동 로그아웃됩니다.');
            this.handleInactivityTimeout();
        }, this.INACTIVITY_TIMEOUT);
    }

    stopInactivityTimer() {
        if (this.inactivityTimer) {
            clearTimeout(this.inactivityTimer);
            this.inactivityTimer = null;
        }
    }

    handleInactivityTimeout() {
        this.clearKey();

        const options = window.csrfUtils ? window.csrfUtils.addCsrfHeader({ method: 'POST' }) : { method: 'POST' };
        if (!options.credentials) options.credentials = 'same-origin';
        
        fetch('/api/auth/logout', options)
            .then(() => {
                alert('보안을 위해 15분 동안 활동이 없어 자동 로그아웃되었습니다.');
                window.location.href = '/login.html';
            })
            .catch(error => {
                console.error('자동 로그아웃 중 오류:', error);
                window.location.href = '/login.html';
            });
    }



    async encryptWithKey(plaintext, key) {
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);

        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            key,
            data
        );

        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        return this.arrayBufferToBase64(combined.buffer);
    }

    async decryptWithKey(encryptedBase64, key) {
        const combined = new Uint8Array(this.base64ToArrayBuffer(encryptedBase64));

        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            key,
            ciphertext
        );

        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }


    // ===== DEK (Data Encryption Key) Methods =====

    async generateDek() {
        return await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true, // extractable
            ['encrypt', 'decrypt']
        );
    }

    async deriveKek(password, saltBase64 = null) {
        let salt = saltBase64 ? new Uint8Array(this.base64ToArrayBuffer(saltBase64)) : null;
        const { key: kekKey, salt: derivedSalt } = await this.deriveKeyFromPassword(password, salt);

        return {
            key: kekKey,
            salt: derivedSalt,
            saltBase64: this.arrayBufferToBase64(derivedSalt.buffer)
        };
    }

    async wrapDekWithKek(dek, kek) {
        const wrappedDek = await crypto.subtle.wrapKey(
            'raw',
            dek,
            kek,
            { name: 'AES-KW' }
        );
        return this.arrayBufferToBase64(wrappedDek);
    }

    async unwrapDekWithKek(wrappedDekB64, kek) {
        const wrappedDek = new Uint8Array(this.base64ToArrayBuffer(wrappedDekB64));
        return await crypto.subtle.unwrapKey(
            'raw',
            wrappedDek,
            kek,
            { name: 'AES-KW' },
            { name: 'AES-GCM', length: 256 },
            false, // not extractable for direct use
            ['encrypt', 'decrypt']
        );
    }

    async unlockStorageWithDek(wrappedDekB64, password, kekSaltB64) {
        const { key: kek } = await this.deriveKek(password, kekSaltB64);
        const dek = await this.unwrapDekWithKek(wrappedDekB64, kek);

        this.storageKey = dek;

        const extractableDek = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );
        const rawDek = await crypto.subtle.exportKey('raw', dek);
        this._extractableDek = await crypto.subtle.importKey(
            'raw',
            rawDek,
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt']
        );

        return true;
    }

    // ===== ECDH Key Pair Methods =====

    async generateEcdhKeyPair() {
        return await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true, // extractable
            ['deriveBits']
        );
    }

    async exportPublicKeyToBase64(pubKey) {
        const spki = await crypto.subtle.exportKey('spki', pubKey);
        return this.arrayBufferToBase64(spki);
    }

    async importPublicKeyFromBase64(b64) {
        const spki = new Uint8Array(this.base64ToArrayBuffer(b64));
        return await crypto.subtle.importKey(
            'spki',
            spki,
            { name: 'ECDH', namedCurve: 'P-256' },
            false,
            []
        );
    }

    async encryptPrivateKey(privKey, password) {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const { key: kek } = await this.deriveKek(password, this.arrayBufferToBase64(salt.buffer));

        // Export private key as PKCS8
        const pkcs8 = await crypto.subtle.exportKey('pkcs8', privKey);
        const privateKeyPem = this.arrayBufferToBase64(pkcs8);

        // Encrypt with AES-GCM
        const encryptedPrivateKey = await this.encryptWithKey(privateKeyPem, kek);

        return {
            encryptedPrivateKey,
            keyWrapSalt: this.arrayBufferToBase64(salt.buffer)
        };
    }

    async decryptPrivateKey(encryptedPrivateKeyB64, keyWrapSaltB64, password) {
        const { key: kek } = await this.deriveKek(password, keyWrapSaltB64);
        const privateKeyPem = await this.decryptWithKey(encryptedPrivateKeyB64, kek);

        // Import from PKCS8
        const pkcs8 = new Uint8Array(this.base64ToArrayBuffer(privateKeyPem));
        return await crypto.subtle.importKey(
            'pkcs8',
            pkcs8,
            { name: 'ECDH', namedCurve: 'P-256' },
            true, // extractable
            ['deriveBits']
        );
    }

    // ===== ECDH-based DEK Wrapping =====

    async wrapDekForCollaborator(dek, recipientPubKeyB64) {
        const recipientPubKey = await this.importPublicKeyFromBase64(recipientPubKeyB64);

        // Generate ephemeral key pair
        const ephemeralKeyPair = await this.generateEcdhKeyPair();

        // Perform ECDH
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: recipientPubKey },
            ephemeralKeyPair.privateKey,
            256
        );

        // HKDF to derive wrapping key
        const info = new TextEncoder().encode('nteok-dek-wrap-v1');
        const wrappingKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                salt: new Uint8Array(0),
                info: info,
                hash: 'SHA-256'
            },
            await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']),
            { name: 'AES-KW', length: 256 },
            false,
            ['wrapKey']
        );

        // Wrap DEK
        const wrappedDek = await crypto.subtle.wrapKey('raw', dek, wrappingKey, { name: 'AES-KW' });

        // Export ephemeral public key
        const ephemeralPublicKey = await this.exportPublicKeyToBase64(ephemeralKeyPair.publicKey);

        return {
            wrappedDek: this.arrayBufferToBase64(wrappedDek),
            ephemeralPublicKey
        };
    }

    async unwrapDekAsCollaborator(wrappedDekB64, ephemeralPubKeyB64, myPrivKey) {
        const ephemeralPubKey = await this.importPublicKeyFromBase64(ephemeralPubKeyB64);

        // Perform ECDH
        const sharedBits = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: ephemeralPubKey },
            myPrivKey,
            256
        );

        // HKDF to derive wrapping key
        const info = new TextEncoder().encode('nteok-dek-wrap-v1');
        const wrappingKey = await crypto.subtle.deriveKey(
            {
                name: 'HKDF',
                salt: new Uint8Array(0),
                info: info,
                hash: 'SHA-256'
            },
            await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']),
            { name: 'AES-KW', length: 256 },
            false,
            ['unwrapKey']
        );

        // Unwrap DEK
        const wrappedDek = new Uint8Array(this.base64ToArrayBuffer(wrappedDekB64));
        return await crypto.subtle.unwrapKey(
            'raw',
            wrappedDek,
            wrappingKey,
            { name: 'AES-KW' },
            { name: 'AES-GCM', length: 256 },
            false, // not extractable
            ['encrypt', 'decrypt']
        );
    }

    async unlockStorageWithEcdh(wrappedDekB64, ephemeralPubKeyB64, myPrivKey) {
        const dek = await this.unwrapDekAsCollaborator(wrappedDekB64, ephemeralPubKeyB64, myPrivKey);
        this.storageKey = dek;
        return true;
    }

    // ===== ECDH Private Key Management =====

    setMyEcdhPrivateKey(key) {
        this._myEcdhPrivateKey = key;
    }

    getMyEcdhPrivateKey() {
        return this._myEcdhPrivateKey;
    }

    clearEcdhPrivateKey() {
        this._myEcdhPrivateKey = null;
    }

    // ===== Master Key Methods (existing) =====

    clearMasterKey() {
        this.masterKey = null;
        this.masterKeySalt = null;
        this.loginPassword = null;

        sessionStorage.removeItem('_mk_salt');
    }

    async tryRestoreMasterKey(password) {
        const saltBase64 = sessionStorage.getItem('_mk_salt');
        if (!saltBase64) {
            return false;
        }

        try {
            await this.initializeMasterKey(password, saltBase64);
            return true;
        } catch (error) {
            console.error('마스터 키 복구 실패:', error);
            return false;
        }
    }
}

const cryptoManager = new CryptoManager();
window.cryptoManager = cryptoManager;
