import fs from "node:fs";
import path from "node:path";

// public 폴더에 남아 배포되면 위험한 파일 확장자/이름 패턴
const FORBIDDEN_EXT_RE = /\.(?:bak|backup|old|tmp|swp|swo|orig|save)$/i;
const FORBIDDEN_NAMES_RE = /^(?:\.env(?:\..*)?|id_rsa|id_dsa|\.npmrc|\.yarnrc(?:\.yml)?|docker-compose\.ya?ml)$/i;

const PUBLIC_DIR = path.resolve(process.cwd(), "public");

function walk(dir, out = []) {
	if (!fs.existsSync(dir)) return out;
	const entries = fs.readdirSync(dir, { withFileTypes: true });
	for (const e of entries) {
		const full = path.join(dir, e.name);
		if (e.isDirectory()) walk(full, out);
		else if (e.isFile()) out.push(full);
	}
	return out;
}

const files = walk(PUBLIC_DIR);
const bad = [];

for (const f of files) {
	const rel = path.relative(process.cwd(), f);
	const base = path.basename(f);
	if (FORBIDDEN_EXT_RE.test(f) || FORBIDDEN_NAMES_RE.test(base))
		bad.push(rel);
}

if (bad.length) {
	console.error("\n[보안] public/ 디렉토리에 배포 금지 파일이 포함되어 있습니다:");
	for (const b of bad) console.error("  -", b);
	console.error("\n조치:");
	console.error("  1 - 위 파일을 삭제 또는 이동하고");
	console.error("  2 - .gitignore에 패턴을 추가한 뒤");
	console.error("  3 - 다시 실행하세요.\n");
	process.exit(1);
}

process.exit(0);