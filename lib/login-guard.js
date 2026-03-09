const LOGIN_MAX_FAILS_IP = Number(process.env.LOGIN_MAX_FAILS_IP || 10);
const LOGIN_MAX_FAILS_USER_PER_IP = Number(process.env.LOGIN_MAX_FAILS_USER_PER_IP || 5);
const LOGIN_LOCK_MS = Number(process.env.LOGIN_LOCK_MS || (15 * 60 * 1000));

function normalizeUsername(username) {
    return String(username || '').trim().toLowerCase();
}

function normalizeIp(ip) {
    return String(ip || 'unknown').trim().toLowerCase();
}

async function getLockStatus(redis, key) {
    const raw = await redis.get(key);
    if (!raw) return { ok: true };
    const st = JSON.parse(raw);
    if (st.lockedUntil && Date.now() < st.lockedUntil) return { ok: false, retryAfterMs: st.lockedUntil - Date.now() };
    return { ok: true };
}

async function assertLoginNotLocked(redis, username, ip) {
    const iStatus = await getLockStatus(redis, `login-lock:ip:${normalizeIp(ip)}`);
    if (!iStatus.ok) return iStatus;
    const uiStatus = await getLockStatus(redis, `login-lock:user-ip:${normalizeUsername(username)}:${normalizeIp(ip)}`);
    if (!uiStatus.ok) return uiStatus;
    return { ok: true };
}

async function incrLock(redis, key, max) {
    const raw = await redis.get(key);
    const cur = raw ? JSON.parse(raw) : { failCount: 0, lockedUntil: 0 };
    cur.failCount += 1;
    if (cur.failCount >= max) {
        cur.failCount = 0;
        cur.lockedUntil = Date.now() + LOGIN_LOCK_MS;
    }
    await redis.set(key, JSON.stringify(cur), { PX: LOGIN_LOCK_MS * 2 });
}

async function recordLoginFailure(redis, username, ip) {
    await incrLock(redis, `login-lock:ip:${normalizeIp(ip)}`, LOGIN_MAX_FAILS_IP);
    await incrLock(redis, `login-lock:user-ip:${normalizeUsername(username)}:${normalizeIp(ip)}`, LOGIN_MAX_FAILS_USER_PER_IP);
}

async function clearLoginFailures(redis, username, ip) {
    await redis.del(`login-lock:ip:${normalizeIp(ip)}`);
    await redis.del(`login-lock:user-ip:${normalizeUsername(username)}:${normalizeIp(ip)}`);
}

module.exports = {
    assertLoginNotLocked,
    recordLoginFailure,
    clearLoginFailures
};
