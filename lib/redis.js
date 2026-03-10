const { createClient } = require("redis");

// 개별 설정값 또는 통합 URL 지원
const REDIS_HOST = process.env.REDIS_HOST || "127.0.0.1";
const REDIS_PORT = process.env.REDIS_PORT || "6379";
const REDIS_PASSWORD = process.env.REDIS_PASSWORD || "";

const REDIS_URL = process.env.REDIS_URL || (REDIS_PASSWORD 
    ? `redis://:${REDIS_PASSWORD}@${REDIS_HOST}:${REDIS_PORT}`
    : `redis://${REDIS_HOST}:${REDIS_PORT}`);

const redis = createClient({ url: REDIS_URL });
redis.on("error", (err) => {
	console.error("[redis] error:", err);
});
let _ready;
function ensureRedis() {
	if (!_ready) _ready = redis.connect();
	return _ready;
}
module.exports = { redis, ensureRedis };
