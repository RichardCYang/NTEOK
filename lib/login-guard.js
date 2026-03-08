const LOGIN_MAX_FAILS = Number(process.env.LOGIN_MAX_FAILS || 8);
const LOGIN_LOCK_MS = Number(process.env.LOGIN_LOCK_MS || (15 * 60 * 1000));

function normalizeUsername(username) {
    return String(username || '').trim().toLowerCase();
}

function normalizeIp(ip) {
    return String(ip || 'unknown').trim().toLowerCase();
}

function keyFor(username, ip) {
    return `login-lock:${normalizeUsername(username)}:${normalizeIp(ip)}`;
}

async function assertLoginNotLocked(redis, username, ip) {
    const raw = await redis.get(keyFor(username, ip));
    if (!raw) return { ok: true };
    const st = JSON.parse(raw);
    if (st.lockedUntil && Date.now() < st.lockedUntil) return { ok: false, retryAfterMs: st.lockedUntil - Date.now() };
    return { ok: true };
}

async function recordLoginFailure(redis, username, ip) {
    const key = keyFor(username, ip);
    const raw = await redis.get(key);
    const cur = raw ? JSON.parse(raw) : { failCount: 0, lockedUntil: 0 };
    cur.failCount += 1;
    if (cur.failCount >= LOGIN_MAX_FAILS) {
        cur.failCount = 0;
        cur.lockedUntil = Date.now() + LOGIN_LOCK_MS;
    }
    await redis.set(key, JSON.stringify(cur), { PX: LOGIN_LOCK_MS * 2 });
}

async function clearLoginFailures(redis, username, ip) {
    await redis.del(keyFor(username, ip));
}

module.exports = {
    assertLoginNotLocked,
    recordLoginFailure,
    clearLoginFailures
};
