const LOGIN_MAX_FAILS_IP = Number(process.env.LOGIN_MAX_FAILS_IP || 10);
const LOGIN_MAX_FAILS_USER_PER_IP = Number(process.env.LOGIN_MAX_FAILS_USER_PER_IP || 5);
const LOGIN_LOCK_MS = Number(process.env.LOGIN_LOCK_MS || (15 * 60 * 1000));

function normalizeUsername(username) {
    return String(username || '').trim().toLowerCase();
}

function normalizeIp(ip) {
    return String(ip || 'unknown').trim().toLowerCase();
}

async function getLockStatus(redis, lockKey) {
    const raw = await redis.get(lockKey);
    if (!raw) return { ok: true };
    const lockedUntil = Number(raw);
    if (Number.isFinite(lockedUntil) && lockedUntil > Date.now()) {
        return { ok: false, retryAfterMs: lockedUntil - Date.now() };
    }
    return { ok: true };
}

async function assertLoginNotLocked(redis, username, ip) {
    const iStatus = await getLockStatus(redis, `login-lock-until:ip:${normalizeIp(ip)}`);
    if (!iStatus.ok) return iStatus;
    const uiStatus = await getLockStatus(
        redis,
        `login-lock-until:user-ip:${normalizeUsername(username)}:${normalizeIp(ip)}`
    );
    if (!uiStatus.ok) return uiStatus;
    return { ok: true };
}

async function incrLock(redis, failKey, lockKey, max) {
    const count = await redis.incr(failKey);
    if (count === 1) await redis.pExpire(failKey, LOGIN_LOCK_MS * 2);
    if (count >= max) {
        const lockedUntil = Date.now() + LOGIN_LOCK_MS;
        const tx = redis.multi();
        tx.set(lockKey, String(lockedUntil), { PX: LOGIN_LOCK_MS });
        tx.del(failKey);
        await tx.exec();
    }
}

async function recordLoginFailure(redis, username, ip) {
    await incrLock(
        redis,
        `login-fails:ip:${normalizeIp(ip)}`,
        `login-lock-until:ip:${normalizeIp(ip)}`,
        LOGIN_MAX_FAILS_IP
    );
    await incrLock(
        redis,
        `login-fails:user-ip:${normalizeUsername(username)}:${normalizeIp(ip)}`,
        `login-lock-until:user-ip:${normalizeUsername(username)}:${normalizeIp(ip)}`,
        LOGIN_MAX_FAILS_USER_PER_IP
    );
}

async function clearLoginFailures(redis, username, ip) {
    await redis.del(`login-fails:ip:${normalizeIp(ip)}`);
    await redis.del(`login-lock-until:ip:${normalizeIp(ip)}`);
    await redis.del(`login-fails:user-ip:${normalizeUsername(username)}:${normalizeIp(ip)}`);
    await redis.del(`login-lock-until:user-ip:${normalizeUsername(username)}:${normalizeIp(ip)}`);
}

module.exports = {
    assertLoginNotLocked,
    recordLoginFailure,
    clearLoginFailures
};
