import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const PUBLIC_DIR = path.join(process.cwd(), "public");
const manifestPath = path.join(PUBLIC_DIR, "importmap-integrity.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));

const MUST_VERIFY = [
	"/lib/dompurify/dompurify.js",
	"/lib/simplewebauthn/browser.js",
	"/lib/tiptap/tiptap-for-browser.min.js",
	"/lib/katex/katex.min.js",
	"/lib/html2canvas/html2canvas.min.js",
	"/lib/jspdf/jspdf.umd.min.js",
	"/lib/sortablejs/Sortable.min.js"
];

function sha384(buf) {
	return `sha384-${crypto.createHash("sha384").update(buf).digest("base64")}`;
}

for (const rel of MUST_VERIFY) {
	const expected = manifest[rel];
	if (!expected) throw new Error(`[SECURITY] integrity manifest 누락: ${rel}`);
	const abs = path.join(PUBLIC_DIR, rel.replace(/^\//, ""));
	const actual = sha384(fs.readFileSync(abs));
	if (actual !== expected) throw new Error(`[SECURITY] 로컬 벤더 번들 무결성 불일치: ${rel}`);
}

console.log("[SECURITY] 로컬 벤더 번들 무결성 검증 통과.");