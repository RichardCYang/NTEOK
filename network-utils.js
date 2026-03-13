const geoip = require("geoip-lite");
const ipaddr = require("ipaddr.js");
const net = require("net");

const SPECIAL_USE_IPV4_CIDRS = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.0.0.0/24',
    '192.0.2.0/24',
    '192.88.99.0/24',
    '192.168.0.0/16',
    '198.18.0.0/15',
    '198.51.100.0/24',
    '203.0.113.0/24',
    '224.0.0.0/4',
    '240.0.0.0/4',
    '255.255.255.255/32'
].map(cidr => ipaddr.parseCIDR(cidr));

const SPECIAL_USE_IPV6_CIDRS = [
    '::/128',
    '::1/128',
    '64:ff9b::/96',
    '100::/64',
    '2001::/32',
    '2001:2::/48',
    '2001:db8::/32',
    'fc00::/7',
    'fe80::/10',
    'ff00::/8'
].map(cidr => ipaddr.parseCIDR(cidr));

function parseNormalizedAddr(ip) {
    try {
        let addr = ipaddr.parse(String(ip));
        if (addr.kind() === 'ipv6' && typeof addr.isIPv4MappedAddress === 'function' && addr.isIPv4MappedAddress()) addr = addr.toIPv4Address();
        return addr;
    } catch {
        return null;
    }
}

function isSpecialUseAddress(addr) {
    const cidrs = addr.kind() === 'ipv4' ? SPECIAL_USE_IPV4_CIDRS : SPECIAL_USE_IPV6_CIDRS;
    return cidrs.some(([range, prefix]) => addr.match(range, prefix));
}

function getLocationFromIP(ip) {
    try {
        if (!ip) return { country: null, region: null, city: null, timezone: null };
        const cleanIP = normalizeIp(ip);
        if (!cleanIP || isPrivateOrLocalIP(cleanIP)) return { country: null, region: null, city: null, timezone: null };
        const geo = geoip.lookup(cleanIP);
        if (!geo) return { country: null, region: null, city: null, timezone: null };
        return {
            country: geo.country || null,
            region: geo.region || null,
            city: geo.city || null,
            timezone: geo.timezone || null
        };
    } catch (error) {
        console.error('GeoIP 조회 오류:', error);
        return { country: null, region: null, city: null, timezone: null };
    }
}

function isPrivateOrLocalIP(ip) {
    const cleanIP = normalizeIp(ip);
    if (!cleanIP) return true;
    if (String(cleanIP).toLowerCase() === 'localhost') return true;
    if (net.isIP(cleanIP) === 0) return false;
    const addr = parseNormalizedAddr(cleanIP);
    if (!addr) return true;
    if (isSpecialUseAddress(addr)) return true;
    if (addr.kind() === 'ipv4') return addr.range() !== 'unicast';
    if (addr.kind() === 'ipv6') return addr.range() !== 'global';
    return true;
}

function normalizeIp(ip) {
    if (!ip) return null;
    let s = String(ip).trim();
    if (s.startsWith('::ffff:')) s = s.substring(7);
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

function isSubnetTooBroad(range, prefix) {
    if (range.kind() === 'ipv4') return prefix <= 8;
    if (range.kind() === 'ipv6') return prefix <= 32;
    return false;
}

function parseTrustedProxyCidrsFromEnv() {
    const raw = (process.env.TRUST_PROXY_CIDRS || '').trim();
    if (!raw) return [];
    const parts = raw.split(',').map(s => s.trim()).filter(Boolean);
    const cidrs = [];
    for (const part of parts) {
        try {
            const [range, prefix] = ipaddr.parseCIDR(part);
            if (isSubnetTooBroad(range, prefix)) console.warn(`[보안] TRUST_PROXY_CIDRS에 너무 광범위한 서브넷이 포함되어 있습니다: "${part}" (권장되지 않음)`);
            cidrs.push([range, prefix]);
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
        if (addr.kind() === 'ipv6' && typeof addr.isIPv4MappedAddress === 'function' && addr.isIPv4MappedAddress()) addr = addr.toIPv4Address();
    } catch {
        return false;
    }
    return cidrs.some(([range, prefix]) => {
        try {
            if (addr.kind() !== range.kind()) return false;
            return addr.match(range, prefix);
        } catch {
            return false;
        }
    });
}

function shouldTrustForwardedHeaders(remote, trustedProxyCidrs) {
    if (!remote) return false;
    if (!Array.isArray(trustedProxyCidrs) || trustedProxyCidrs.length === 0) return false;
    return isIpInCidrs(remote, trustedProxyCidrs);
}

function parseForwardedChain(req) {
    const xff = req?.headers?.['x-forwarded-for'];
    if (typeof xff === 'string' && xff.trim()) {
        const hops = xff
            .split(',')
            .map(part => normalizeIp(part))
            .filter(ip => isValidIp(ip));
        if (hops.length > 0) return hops;
    }
    const xRealIp = normalizeIp(req?.headers?.['x-real-ip']);
    if (isValidIp(xRealIp)) return [xRealIp];
    return [];
}

function extractClientIpFromTrustedChain(remote, forwardedChain, trustedProxyCidrs) {
    const chain = [...forwardedChain, remote].filter(Boolean);
    if (chain.length === 0) return null;
    for (let i = chain.length - 1; i >= 0; i--) {
        const hop = chain[i];
        if (!isIpInCidrs(hop, trustedProxyCidrs)) return hop;
    }
    return chain[0] || null;
}

function getClientIpFromRequest(req) {
    const remote = normalizeIp(req?.socket?.remoteAddress || req?.connection?.remoteAddress || req?.ip);
    const mode = (process.env.TRUST_PROXY || 'auto').toLowerCase();
    const trustedProxyCidrs = parseTrustedProxyCidrsFromEnv();
    const isProduction = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
    if (mode === 'off' || mode === 'false' || mode === '0') return remote || 'unknown';
    if ((mode === 'on' || mode === 'true' || mode === '1') && isProduction) console.warn('[보안] TRUST_PROXY=on(true/1)은 지원하지 않습니다. 반드시 TRUST_PROXY=auto 와 TRUST_PROXY_CIDRS 를 함께 지정하세요.');
    if (mode === 'auto' || mode === 'on' || mode === 'true' || mode === '1') {
        if (shouldTrustForwardedHeaders(remote, trustedProxyCidrs)) {
            const forwardedChain = parseForwardedChain(req);
            const derived = extractClientIpFromTrustedChain(remote, forwardedChain, trustedProxyCidrs);
            if (derived) return derived;
        }
    }
    return remote || 'unknown';
}

function checkCountryWhitelist(userSettings, ipAddress) {
    const allowPrivateBypass = !process.env.NODE_ENV || process.env.NODE_ENV !== 'production' || String(process.env.COUNTRY_WHITELIST_ALLOW_PRIVATE_IP || '').toLowerCase() === 'true';
    if (isPrivateOrLocalIP(ipAddress)) {
        if (allowPrivateBypass) return { allowed: true };
        return {
            allowed: false,
            reason: '사설/로컬 IP는 국가 화이트리스트 검증을 우회할 수 있어 프로덕션 기본값에서 차단됩니다. 리버스 프록시 사용 시 TRUST_PROXY_CIDRS 또는 TRUST_PROXY 설정을 확인하세요.'
        };
    }
    if (!userSettings.country_whitelist_enabled) return { allowed: true };
    const location = getLocationFromIP(ipAddress);
    if (!location.country) return { allowed: false, reason: 'GeoIP 조회 실패 - 국가를 확인할 수 없음' };
    let allowedCountries = [];
    if (userSettings.allowed_login_countries) {
        try {
            allowedCountries = JSON.parse(userSettings.allowed_login_countries);
        } catch (e) {
            console.error('화이트리스트 파싱 오류:', e);
            return { allowed: false, reason: '화이트리스트 설정 오류' };
        }
    }
    if (!Array.isArray(allowedCountries) || allowedCountries.length === 0) return {
        allowed: false,
        reason: `허용되지 않은 국가에서의 로그인 시도 (감지된 국가: ${location.country})`
    };
    if (!allowedCountries.includes(location.country)) return {
        allowed: false,
        reason: `허용되지 않은 국가에서의 로그인 시도 (감지된 국가: ${location.country})`
    };
    return { allowed: true };
}

function maskIPAddress(ip) {
    if (!ip) return '알 수 없음';
    if (ip.startsWith('::ffff:')) {
        const ipv4Part = ip.substring(7);
        const parts = ipv4Part.split('.');
        if (parts.length === 4) {
            parts[3] = '***';
            return '::ffff:' + parts.join('.');
        }
    }
    if (ip.includes('.') && !ip.includes(':')) {
        const parts = ip.split('.');
        if (parts.length === 4) {
            parts[3] = '***';
            return parts.join('.');
        }
    }
    if (ip.includes(':')) {
        const parts = ip.split(':');
        if (parts.length >= 4) {
            for (let i = parts.length - 4; i < parts.length; i++) parts[i] = '****';
            return parts.join(':');
        }
    }
    return ip;
}

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
        const location = getLocationFromIP(ipAddress);
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
    }
}

function isPublicRoutableIP(ip) {
    if (!ip) return false;
    const cleanIP = normalizeIp(ip);
    if (!cleanIP) return false;
    const addr = parseNormalizedAddr(cleanIP);
    if (!addr) return false;
    if (isSpecialUseAddress(addr)) return false;
    const range = addr.range();
    if (addr.kind() === 'ipv4') return range === 'unicast';
    if (addr.kind() === 'ipv6') {
        if (range !== 'global') return false;
        if (typeof addr.isLinkLocal === 'function' && addr.isLinkLocal()) return false;
        return true;
    }
    return false;
}

module.exports = {
    getLocationFromIP,
    isPrivateOrLocalIP,
    isPublicRoutableIP,
    checkCountryWhitelist,
    maskIPAddress,
    formatDateForDb,
    recordLoginAttempt,
    getClientIpFromRequest,
    normalizeIp,
    isSubnetTooBroad,
    parseTrustedProxyCidrsFromEnv
};
