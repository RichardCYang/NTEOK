import fs from "node:fs";
import path from "node:path";

const candidates = [
	path.join("node_modules", "@simplewebauthn", "browser", "dist", "bundle", "index.umd.min.js"),
	path.join("node_modules", "@simplewebauthn", "browser", "dist", "bundle", "index.es5.umd.min.js"),
	path.join("node_modules", "@simplewebauthn", "browser", "dist", "bundle", "index.js"),
	path.join("node_modules", "@simplewebauthn", "browser", "dist", "bundle", "index.mjs"),
	path.join("node_modules", "@simplewebauthn", "browser", "dist", "index.js"),
	path.join("node_modules", "@simplewebauthn", "browser", "dist", "index.mjs")
];

const src = candidates.find(p => fs.existsSync(p));
if (!src) throw new Error("[SECURITY] @simplewebauthn/browser bundle path를 찾을 수 없습니다.");

const dst = path.join("public", "lib", "simplewebauthn", "browser.js");
fs.mkdirSync(path.dirname(dst), { recursive: true });
fs.copyFileSync(src, dst);

console.log(`[SECURITY] synced ${src} -> ${dst}`);