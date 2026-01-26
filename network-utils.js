/**
 * ==================== 네트워크 유틸리티 모듈 ====================
 * IP 처리, GeoIP 조회, 로그인 로그 등 네트워크 관련 기능
 */

const geoip = require("geoip-lite");
const ipaddr = require("ipaddr.js");
const net = require("net");

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

        const cleanIP = normalizeIp(ip);
        // 사설/로컬/예약(IPv4/IPv6) 대역은 GeoIP 조회 의미가 없고,
        // SSRF/화이트리스트 로직과의 일관성을 위해 동일한 판정을 사용
        if (!cleanIP || isPrivateOrLocalIP(cleanIP)) {
            return {
                country: null,
                region: null,
                city: null,
                timezone: null
            };
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

    const cleanIP = normalizeIp(ip);
    if (!cleanIP) return true;

    // 과거 호환: 문자열 localhost는 로컬로 취급
    if (String(cleanIP).toLowerCase() === 'localhost') return true;
    // IP가 아니면(예: unknown) 여기서는 로컬로 판정하지 않음
    if (net.isIP(cleanIP) === 0) return false;

    try {
        let addr = ipaddr.parse(cleanIP);
        // IPv4-mapped IPv6 (::ffff:127.0.0.1 등) -> IPv4로 변환 후 판정
        if (addr.kind() === 'ipv6' && typeof addr.isIPv4MappedAddress === 'function' && addr.isIPv4MappedAddress())
            addr = addr.toIPv4Address();

        // SSRF 방어 관점: "unicast(공인 글로벌 유니캐스트)"만 통과, 나머지는 전부 차단
        return addr.range() !== 'unicast';
    } catch (e) {
        // 파싱 실패는 보수적으로 로컬로 판정
        return true;
    }
}

/**
 * 요청 객체로부터 실제 클라이언트 IP를 안전하게 추출.
 *
 * = 목표 =
 * - 직접 접속(프록시 없음): remoteAddress를 그대로 사용 (X-Forwarded-For 무시)
 * - 같은 호스트의 리버스 프록시(nginx/caddy 등, remoteAddress가 loopback): X-Forwarded-For / X-Real-IP 반영
 * - 그 외 프록시(별도 호스트/클라우드 LB 등): TRUST_PROXY_CIDRS(환경변수)로 명시적으로 허용한 프록시만 신뢰
 *
 * = 주의 =
 * - X-Forwarded-For / X-Real-IP 헤더는 쉽게 스푸핑될 수 있으므로, 신뢰할 수 있는 프록시에서 들어온 요청에 대해서만 반영해야 함.
 *   (Express 공식 문서에도 trust proxy를 신중히 설정하라고 권고함)
 */
function normalizeIp(ip) {
    if (!ip) return null;
    let s = String(ip).trim();
    // IPv6-mapped IPv4 (::ffff:1.2.3.4)
    if (s.startsWith('::ffff:')) s = s.substring(7);
    // remove IPv6 zone index (fe80::1%lo0)
    s = s.replace(/%[0-9A-Za-z_.-]+$/, '');
    return s;
}

function isValidIp(ip) {
    const s = normalizeIp(ip);
    if (!s) return false;
    return net.isIP(s) !== 0;
}

function isLoopbackIp(ip) {
    const s = normalizeIp(ip);
    return s === '127.0.0.1' || s === '::1' || s === 'localhost' || (typeof s === 'string' && s.startsWith('127.'));
}

function parseTrustedProxyCidrsFromEnv() {
    const raw = (process.env.TRUST_PROXY_CIDRS || '').trim();
    if (!raw) return [];
    const parts = raw.split(',').map(s => s.trim()).filter(Boolean);

    const cidrs = [];
    for (const part of parts) {
        try {
            // ipaddr.js는 IPv4/IPv6 CIDR 모두 지원
            const parsed = ipaddr.parseCIDR(part);
            cidrs.push(parsed); // [addr, prefixLen]
        } catch (e) {
            console.warn(`[보안 설정] TRUST_PROXY_CIDRS 항목 파싱 실패: "${part}" (${e.message})`);
        }
    }
    return cidrs;
}

function isIpInCidrs(ip, cidrs) {
    const s = normalizeIp(ip);
    if (!s || !Array.isArray(cidrs) || cidrs.length === 0) return false;
    if (!isValidIp(s)) return false;

    let addr;
    try {
        addr = ipaddr.parse(s);
        // IPv4-mapped IPv6를 IPv4로 변환
        if (addr.kind() === 'ipv6' && addr.isIPv4MappedAddress?.())
            addr = addr.toIPv4Address();
    } catch {
        return false;
    }

    return cidrs.some(([range, prefix]) => {
        try {
            // kind mismatch 보호
            if (addr.kind() !== range.kind()) return false;
            return addr.match(range, prefix);
        } catch {
            return false;
        }
    });
}

function extractForwardedClientIp(req) {
    // X-Forwarded-For: "client, proxy1, proxy2"
    const xff = req?.headers?.['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
        const first = xff.split(',')[0].trim();
        if (isValidIp(first)) return normalizeIp(first);
    }

    // X-Real-IP: "client"
    const xRealIp = req?.headers?.['x-real-ip'];
    if (typeof xRealIp === 'string' && xRealIp.trim())
        if (isValidIp(xRealIp)) return normalizeIp(xRealIp.trim());

    // RFC 7239 Forwarded 헤더까지 처리하고 싶다면 여기서 확장 가능
    return null;
}

/**
 * 실제 클라이언트 IP 반환
 * @param {import('express').Request} req
 * @returns {string} ip 문자열 (unknown이면 'unknown')
 */
function getClientIpFromRequest(req) {
    const remote = normalizeIp(req?.socket?.remoteAddress || req?.connection?.remoteAddress || req?.ip);
    const mode = (process.env.TRUST_PROXY || 'auto').toLowerCase();
    const trustedProxyCidrs = parseTrustedProxyCidrsFromEnv();

    // 완전 비활성화 모드: 어떤 경우에도 forwarded 헤더를 신뢰하지 않음
    if (mode === 'off' || mode === 'false' || mode === '0')
        return remote || 'unknown';

    // 완전 활성화 모드(비추천): forwarded 헤더를 무조건 신뢰
    // - 운영에서는 가능하면 쓰지 말고, TRUST_PROXY_CIDRS로 프록시를 명시적으로 제한하세요.
    if (mode === 'on' || mode === 'true' || mode === '1')
        return extractForwardedClientIp(req) || remote || 'unknown';

    // auto 모드:
    // 1) remote가 loopback이면(같은 머신 프록시) forwarded 헤더 사용
    // 2) remote가 TRUST_PROXY_CIDRS에 포함되면 forwarded 헤더 사용
    const isTrustedProxy =
        (remote && isLoopbackIp(remote)) ||
        (remote && isIpInCidrs(remote, trustedProxyCidrs));

    if (isTrustedProxy)
        return extractForwardedClientIp(req) || remote || 'unknown';

    // direct 접속 또는 신뢰되지 않은 프록시: remoteAddress 사용
    return remote || 'unknown';
}

/**
 * 국가 화이트리스트 체크
 * @param {object} userSettings - { country_whitelist_enabled, allowed_login_countries }
 * @param {string} ipAddress - IP 주소
 * @returns {object} { allowed: boolean, reason?: string }
 */
function checkCountryWhitelist(userSettings, ipAddress) {
	// 사설 IP/localhost 처리 -> 리버스 프록시 설정(trust proxy/forwarded 헤더)이 잘못되면
    // 실제 클라이언트 IP 대신 프록시의 사설 IP가 들어와 화이트리스트가 무력화될 수 있음
    // - 운영(PROD) 기본값: 사설 IP를 자동 허용하지 않음 (안전한 기본값)
    const allowPrivateBypass =
        !process.env.NODE_ENV || process.env.NODE_ENV !== 'production' ||
        String(process.env.COUNTRY_WHITELIST_ALLOW_PRIVATE_IP || '').toLowerCase() === 'true';

    if (isPrivateOrLocalIP(ipAddress)) {
        if (allowPrivateBypass) {
            return { allowed: true };
        }
        return {
            allowed: false,
            reason: '사설/로컬 IP는 국가 화이트리스트 검증을 우회할 수 있어 프로덕션 기본값에서 차단됩니다. ' +
                '리버스 프록시 사용 시 TRUST_PROXY_CIDRS 또는 TRUST_PROXY 설정을 확인하세요.'
        };
    }

    // 화이트리스트가 비활성화되어 있으면 허용
    if (!userSettings.country_whitelist_enabled) {
        return { allowed: true };
    }

    // IP로부터 국가 정보 조회
    const location = getLocationFromIP(ipAddress);

    // GeoIP 조회 실패 시 차단 (사용자 설정: 엄격한 보안)
    if (!location.country) {
        return {
            allowed: false,
            reason: 'GeoIP 조회 실패 - 국가를 확인할 수 없음'
        };
    }

    // 화이트리스트 파싱
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

    // 화이트리스트가 비어있으면 모든 국가 차단 (사용자 설정)
    if (!Array.isArray(allowedCountries) || allowedCountries.length === 0) {
        return {
            allowed: false,
            reason: `허용되지 않은 국가에서의 로그인 시도 (감지된 국가: ${location.country})`
        };
    }

    // 국가 체크
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
    recordLoginAttempt,
    getClientIpFromRequest,
    normalizeIp
};
