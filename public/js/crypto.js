/**
 * 종단간 암호화(E2EE) 유틸리티
 * AES-256-GCM을 사용한 양자 컴퓨터 저항성 암호화
 */

class CryptoManager {
    constructor() {
        this.encryptionKey = null;
        this.salt = null;
        this.password = null; // 메모리 전용 비밀번호 저장 (새로고침 시 삭제됨)

        // 마스터 키 기반 자동 암호화 (신규)
        this.masterKey = null; // 사용자 마스터 키 (로그인 비밀번호에서 유도)
        this.masterKeySalt = null; // 마스터 키용 salt (사용자별 고정)
        this.loginPassword = null; // 로그인 비밀번호 (세션 동안 유지)

        this.inactivityTimer = null; // 자동 로그아웃 타이머
        this.INACTIVITY_TIMEOUT = 15 * 60 * 1000; // 15분 (밀리초)
    }

    /**
     * Base64 문자열을 ArrayBuffer로 변환
     */
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * ArrayBuffer를 Base64 문자열로 변환
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }

    /**
     * 비밀번호에서 암호화 키 유도 (PBKDF2)
     * @param {string} password - 사용자 비밀번호
     * @param {Uint8Array} salt - Salt (없으면 새로 생성)
     * @returns {Promise<{key: CryptoKey, salt: Uint8Array}>}
     */
    async deriveKeyFromPassword(password, salt = null) {
        // Salt가 없으면 새로 생성 (16 bytes)
        if (!salt) {
            salt = crypto.getRandomValues(new Uint8Array(16));
        }

        // 비밀번호를 키 재료로 변환
        const encoder = new TextEncoder();
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // PBKDF2로 AES-256 키 유도
        // 반복 횟수 600,000 (2023 OWASP 권장사항)
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

    /**
     * 암호화 키 초기화
     * @param {string} password - 사용자 비밀번호
     * @param {string} saltBase64 - Base64 인코딩된 salt (선택사항)
     */
    async initializeKey(password, saltBase64 = null) {
        let salt = null;
        if (saltBase64) {
            salt = new Uint8Array(this.base64ToArrayBuffer(saltBase64));
        }

        const { key, salt: derivedSalt } = await this.deriveKeyFromPassword(password, salt);
        this.encryptionKey = key;
        this.salt = derivedSalt;
        this.password = password; // 메모리에만 저장 (새로고침 시 삭제)

        // 자동 로그아웃 타이머 시작
        this.resetInactivityTimer();

        return this.arrayBufferToBase64(this.salt);
    }

    /**
     * 데이터 암호화 (AES-256-GCM)
     * @param {string} plaintext - 평문
     * @returns {Promise<string>} Salt + IV + 암호문 포함 (SALT:<salt>:ENC2:<encrypted>)
     */
    async encrypt(plaintext) {
        if (!this.encryptionKey) {
            throw new Error('암호화 키가 초기화되지 않았습니다.');
        }

        if (!this.salt) {
            throw new Error('Salt가 초기화되지 않았습니다.');
        }

        // IV 생성 (12 bytes, GCM 모드 권장)
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // 평문을 바이트로 변환
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);

        // AES-256-GCM으로 암호화
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128 // 인증 태그 길이 (비트)
            },
            this.encryptionKey,
            data
        );

        // IV + ciphertext를 하나로 결합
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        // Salt를 Base64로 인코딩
        const saltBase64 = this.arrayBufferToBase64(this.salt.buffer);
        const encryptedBase64 = this.arrayBufferToBase64(combined.buffer);

        // 형식: SALT:<salt_base64>:ENC2:<encrypted_base64>
        return `SALT:${saltBase64}:ENC2:${encryptedBase64}`;
    }

    /**
     * 데이터 복호화 (AES-256-GCM)
     * @param {string} encryptedData - 암호화된 데이터
     * @param {string} password - 비밀번호 (새 형식 ENC2 사용 시 필요)
     * @returns {Promise<string>} 평문
     */
    async decrypt(encryptedData, password = null) {
        // 새 형식: SALT:<salt>:ENC2:<encrypted>
        if (encryptedData.startsWith('SALT:')) {
            const parts = encryptedData.split(':');
            if (parts.length !== 4 || parts[2] !== 'ENC2') {
                throw new Error('암호화 데이터 형식이 올바르지 않습니다.');
            }

            const saltBase64 = parts[1];
            const encryptedBase64 = parts[3];

            // 비밀번호가 제공되지 않았으면 메모리에 저장된 비밀번호 사용
            const pwd = password || this.password;
            if (!pwd) {
                throw new Error('복호화에 필요한 비밀번호가 없습니다.');
            }

            // Salt로 키 재생성
            const salt = new Uint8Array(this.base64ToArrayBuffer(saltBase64));
            const { key } = await this.deriveKeyFromPassword(pwd, salt);

            // Base64 디코딩
            const combined = new Uint8Array(this.base64ToArrayBuffer(encryptedBase64));

            // IV와 ciphertext 분리
            const iv = combined.slice(0, 12);
            const ciphertext = combined.slice(12);

            // 복호화
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv,
                    tagLength: 128
                },
                key,
                ciphertext
            );

            // 바이트를 문자열로 변환
            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        }

        // 구 형식 (하위 호환성): ENC1:<encrypted>
        if (!this.encryptionKey) {
            throw new Error('암호화 키가 초기화되지 않았습니다.');
        }

        let dataToDecrypt = encryptedData;
        if (encryptedData.startsWith('ENC1:')) {
            dataToDecrypt = encryptedData.substring(5);
        }

        // Base64 디코딩
        const combined = new Uint8Array(this.base64ToArrayBuffer(dataToDecrypt));

        // IV와 ciphertext 분리
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        // 복호화
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            this.encryptionKey,
            ciphertext
        );

        // 바이트를 문자열로 변환
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    /**
     * 보안 개선: 암호화 여부 확인 (매직 바이트 또는 Base64 패턴 검사)
     * @param {string} data - 확인할 데이터
     * @returns {boolean} 암호화 여부
     */
    isEncrypted(data) {
        if (!data || typeof data !== 'string') {
            return false;
        }

        // 최신 방식: SALT 포함
        if (data.startsWith('SALT:')) {
            return true;
        }

        // 이전 방식: ENC1 매직 바이트
        if (data.startsWith('ENC1:')) {
            return true;
        }

        // 구 방식: Base64 패턴 확인 (하위 호환성)
        // 20자 이상 + Base64 문자만 포함
        const isBase64Like = /^[A-Za-z0-9+/]+=*$/.test(data) && data.length > 20;
        return isBase64Like;
    }

    /**
     * 암호화 키 제거 (로그아웃 시)
     */
    clearKey() {
        this.encryptionKey = null;
        this.salt = null;
        this.password = null; // 메모리에서 비밀번호 제거
        this.stopInactivityTimer();
    }

    /**
     * 키가 초기화되었는지 확인
     */
    isKeyInitialized() {
        return this.encryptionKey !== null;
    }

    /**
     * 메모리에 저장된 비밀번호 가져오기
     */
    getPassword() {
        return this.password;
    }

    /**
     * 비활성 타이머 초기화 (사용자 활동 시 호출)
     */
    resetInactivityTimer() {
        this.stopInactivityTimer();

        this.inactivityTimer = setTimeout(() => {
            console.warn('비활성 시간 초과로 자동 로그아웃됩니다.');
            this.handleInactivityTimeout();
        }, this.INACTIVITY_TIMEOUT);
    }

    /**
     * 비활성 타이머 중지
     */
    stopInactivityTimer() {
        if (this.inactivityTimer) {
            clearTimeout(this.inactivityTimer);
            this.inactivityTimer = null;
        }
    }

    /**
     * 비활성 시간 초과 처리
     */
    handleInactivityTimeout() {
        this.clearKey();

        // 로그아웃 API 호출
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

    // ============================================================
    // 마스터 키 기반 자동 암호화 메소드 (신규)
    // ============================================================

    // ==================== 마스터 키 시스템 제거됨 ====================
    // initializeMasterKey, encryptWithMasterKey, decryptWithMasterKey 제거됨
    // generateCollectionKey, encryptCollectionKey, decryptCollectionKey 제거됨
    // 선택적 암호화 시스템으로 변경

    /**
     * 특정 키로 데이터 암호화 (컬렉션 키 사용)
     * @param {string} plaintext - 평문
     * @param {CryptoKey} key - 암호화 키
     * @returns {Promise<string>} Base64 암호문
     */
    async encryptWithKey(plaintext, key) {
        // IV 생성
        const iv = crypto.getRandomValues(new Uint8Array(12));

        // 평문을 바이트로 변환
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);

        // AES-256-GCM으로 암호화
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            key,
            data
        );

        // IV + ciphertext 결합
        const combined = new Uint8Array(iv.length + ciphertext.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(ciphertext), iv.length);

        return this.arrayBufferToBase64(combined.buffer);
    }

    /**
     * 특정 키로 데이터 복호화 (컬렉션 키 사용)
     * @param {string} encryptedBase64 - Base64 암호문
     * @param {CryptoKey} key - 복호화 키
     * @returns {Promise<string>} 평문
     */
    async decryptWithKey(encryptedBase64, key) {
        // Base64 디코딩
        const combined = new Uint8Array(this.base64ToArrayBuffer(encryptedBase64));

        // IV와 ciphertext 분리
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);

        // 복호화
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: 128
            },
            key,
            ciphertext
        );

        // 바이트를 문자열로 변환
        const decoder = new TextDecoder();
        return decoder.decode(decrypted);
    }

    // isMasterKeyInitialized 제거됨 (마스터 키 시스템 제거)

    /**
     * 마스터 키 제거 (로그아웃 시)
     */
    clearMasterKey() {
        this.masterKey = null;
        this.masterKeySalt = null;
        this.loginPassword = null;

        // sessionStorage에서 salt 제거
        sessionStorage.removeItem('_mk_salt');
    }

    /**
     * 새로고침 시 마스터 키 복구 시도
     * @param {string} password - 로그인 비밀번호
     * @returns {Promise<boolean>} 복구 성공 여부
     */
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

// 전역 CryptoManager 인스턴스
const cryptoManager = new CryptoManager();
window.cryptoManager = cryptoManager;
