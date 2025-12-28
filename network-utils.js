/**
 * ==================== 네트워크 유틸리티 모듈 ====================
 * IP 처리, GeoIP 조회, 로그인 로그 등 네트워크 관련 기능
 */

const geoip = require("geoip-lite");

/**
 * IP 주소로부터 위치 정보 조회 (GeoIP)
 * @param {string} ip - IP 주소
 * @returns {object} { country, region, city, timezone }
 */
function getLocationFromIP(ip) {
    try {
        if (!ip) {
            return {
                country: null,
                region: null,
                city: null,
                timezone: null
            };
        }

        // IPv6 매핑된 IPv4 주소 처리 (예: ::ffff:192.168.1.1)
        let cleanIP = ip;
        if (ip.startsWith('::ffff:')) {
            cleanIP = ip.substring(7);
        }

        // 사설 IP 또는 localhost는 null 반환 (국가 화이트리스트 체크에서 별도 처리)
        if (cleanIP === '::1' || cleanIP === '127.0.0.1' || cleanIP === 'localhost' ||
            cleanIP.startsWith('192.168.') || cleanIP.startsWith('10.')) {
            return {
                country: null,
                region: null,
                city: null,
                timezone: null
            };
        }

        // 172.16.0.0 ~ 172.31.255.255 범위 체크
        const match = cleanIP.match(/^172\.(\d+)\./);
        if (match) {
            const secondOctet = parseInt(match[1]);
            if (secondOctet >= 16 && secondOctet <= 31) {
                return {
                    country: null,
                    region: null,
                    city: null,
                    timezone: null
                };
            }
        }

        const geo = geoip.lookup(cleanIP);

        if (!geo) {
            return {
                country: null,
                region: null,
                city: null,
                timezone: null
            };
        }

        return {
            country: geo.country || null,
            region: geo.region || null,
            city: geo.city || null,
            timezone: geo.timezone || null
        };
    } catch (error) {
        console.error('GeoIP 조회 오류:', error);
        return {
            country: null,
            region: null,
            city: null,
            timezone: null
        };
    }
}

/**
 * 사설 IP 또는 localhost 확인
 * @param {string} ip - IP 주소
 * @returns {boolean} 사설 IP 또는 localhost 여부
 */
function isPrivateOrLocalIP(ip) {
    if (!ip) return true;

    // IPv6 매핑된 IPv4 주소 처리 (예: ::ffff:192.168.1.1)
    let cleanIP = ip;
    if (ip.startsWith('::ffff:')) {
        cleanIP = ip.substring(7);
    }

    // localhost 체크
    if (cleanIP === '::1' || cleanIP === '127.0.0.1' || cleanIP === 'localhost') return true;

    // 사설 IP 대역 체크
    if (cleanIP.startsWith('192.168.') || cleanIP.startsWith('10.')) return true;

    // 172.16.0.0 ~ 172.31.255.255 범위 체크
    const match = cleanIP.match(/^172\.(\d+)\./);
    if (match) {
        const secondOctet = parseInt(match[1]);
        if (secondOctet >= 16 && secondOctet <= 31) return true;
    }

    return false;
}

/**
 * 국가 화이트리스트 체크
 * @param {object} userSettings - { country_whitelist_enabled, allowed_login_countries }
 * @param {string} ipAddress - IP 주소
 * @returns {object} { allowed: boolean, reason?: string }
 */
function checkCountryWhitelist(userSettings, ipAddress) {
    // 1. 사설 IP/localhost는 항상 허용
    if (isPrivateOrLocalIP(ipAddress)) {
        return { allowed: true };
    }

    // 2. 화이트리스트가 비활성화되어 있으면 허용
    if (!userSettings.country_whitelist_enabled) {
        return { allowed: true };
    }

    // 3. IP로부터 국가 정보 조회
    const location = getLocationFromIP(ipAddress);

    // 4. GeoIP 조회 실패 시 차단 (사용자 설정: 엄격한 보안)
    if (!location.country) {
        return {
            allowed: false,
            reason: 'GeoIP 조회 실패 - 국가를 확인할 수 없음'
        };
    }

    // 5. 화이트리스트 파싱
    let allowedCountries = [];
    if (userSettings.allowed_login_countries) {
        try {
            allowedCountries = JSON.parse(userSettings.allowed_login_countries);
        } catch (e) {
            console.error('화이트리스트 파싱 오류:', e);
            // 파싱 오류 시 차단 (안전한 기본값)
            return {
                allowed: false,
                reason: '화이트리스트 설정 오류'
            };
        }
    }

    // 6. 화이트리스트가 비어있으면 모든 국가 차단 (사용자 설정)
    if (!Array.isArray(allowedCountries) || allowedCountries.length === 0) {
        return {
            allowed: false,
            reason: `허용되지 않은 국가에서의 로그인 시도 (감지된 국가: ${location.country})`
        };
    }

    // 7. 국가 체크
    if (!allowedCountries.includes(location.country)) {
        return {
            allowed: false,
            reason: `허용되지 않은 국가에서의 로그인 시도 (감지된 국가: ${location.country})`
        };
    }

    return { allowed: true };
}

/**
 * IP 주소 마스킹 (개인정보 보호)
 * @param {string} ip - IP 주소
 * @returns {string} 마스킹된 IP 주소
 */
function maskIPAddress(ip) {
    if (!ip) return '알 수 없음';

    // IPv6 매핑된 IPv4 주소 처리 (예: ::ffff:192.168.1.1)
    if (ip.startsWith('::ffff:')) {
        const ipv4Part = ip.substring(7);
        const parts = ipv4Part.split('.');
        if (parts.length === 4) {
            parts[3] = '***';
            return '::ffff:' + parts.join('.');
        }
    }

    // IPv4: 마지막 옥텟 마스킹 (예: 192.168.1.100 -> 192.168.1.***)
    if (ip.includes('.') && !ip.includes(':')) {
        const parts = ip.split('.');
        if (parts.length === 4) {
            parts[3] = '***';
            return parts.join('.');
        }
    }

    // IPv6: 마지막 4개 세그먼트 마스킹
    if (ip.includes(':')) {
        const parts = ip.split(':');
        if (parts.length >= 4) {
            for (let i = parts.length - 4; i < parts.length; i++) {
                parts[i] = '****';
            }
            return parts.join(':');
        }
    }

    return ip;
}

/**
 * Date -> MySQL DATETIME 문자열 (YYYY-MM-DD HH:MM:SS)
 */
function formatDateForDb(date) {
    const pad = (n) => (n < 10 ? "0" + n : "" + n);

    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    const hour = pad(date.getHours());
    const minute = pad(date.getMinutes());
    const second = pad(date.getSeconds());

    return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
}

/**
 * 로그인 시도 기록
 * @param {object} pool - MySQL 연결 풀
 * @param {object} params - 로그 파라미터
 * @param {number|null} params.userId - 사용자 ID (실패 시 null)
 * @param {string|null} params.username - 시도한 사용자명
 * @param {string} params.ipAddress - IP 주소
 * @param {number} params.port - 포트 번호
 * @param {boolean} params.success - 성공 여부
 * @param {string|null} params.failureReason - 실패 사유
 * @param {string|null} params.userAgent - User-Agent 헤더
 */
async function recordLoginAttempt(pool, params) {
    try {
        const {
            userId,
            username,
            ipAddress,
            port,
            success,
            failureReason,
            userAgent
        } = params;

        // GeoIP 정보 조회
        const location = getLocationFromIP(ipAddress);

        // 현재 시각
        const now = formatDateForDb(new Date());

        await pool.execute(
            `INSERT INTO login_logs (
                user_id, username, ip_address, port,
                country, region, city, timezone,
                user_agent, success, failure_reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                userId,
                username,
                ipAddress,
                port,
                location.country,
                location.region,
                location.city,
                location.timezone,
                userAgent,
                success ? 1 : 0,
                failureReason,
                now
            ]
        );

        console.log(`[로그인 로그] 사용자: ${username || '알 수 없음'}, 성공: ${success}, IP: ${ipAddress}`);
    } catch (error) {
        console.error('로그인 로그 기록 실패:', error);
        // 로그 기록 실패가 로그인 프로세스를 방해하지 않도록 에러를 던지지 않음
    }
}

module.exports = {
    getLocationFromIP,
    isPrivateOrLocalIP,
    checkCountryWhitelist,
    maskIPAddress,
    formatDateForDb,
    recordLoginAttempt
};
