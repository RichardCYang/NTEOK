const { redis, ensureRedis } = require("./redis");
function sessionKey(sessionId) {
	return `sess:${sessionId}`;
}
function userSessionsKey(userId) {
	return `user-sessions:${userId}`;
}
async function getSession(sessionId) {
	await ensureRedis();
	const raw = await redis.get(sessionKey(sessionId));
	return raw ? JSON.parse(raw) : null;
}
async function saveSession(sessionId, session, ttlMs) {
	await ensureRedis();
	const tx = redis.multi();
	tx.set(sessionKey(sessionId), JSON.stringify(session), { PX: ttlMs });
	if (session?.userId != null) {
		tx.sAdd(userSessionsKey(session.userId), sessionId);
		tx.pExpire(userSessionsKey(session.userId), ttlMs);
	}
	await tx.exec();
}
async function listUserSessions(userId) {
	await ensureRedis();
	return await redis.sMembers(userSessionsKey(userId));
}
async function revokeSession(sessionId, reason = "logout") {
	await ensureRedis();
	const current = await getSession(sessionId);
	const tx = redis.multi();
	tx.del(sessionKey(sessionId));
	if (current?.userId) tx.sRem(userSessionsKey(current.userId), sessionId);
	tx.publish("session-revoke", JSON.stringify({ sessionId, reason }));
	await tx.exec();
}
module.exports = {
	getSession,
	saveSession,
	listUserSessions,
	revokeSession
};
