const { createClient } = require("redis");
const REDIS_URL = process.env.REDIS_URL || "redis://127.0.0.1:6379";
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
