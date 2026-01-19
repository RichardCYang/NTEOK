/**
 * 외부 리소스 무결성(SRI) + Importmap integrity 자동 생성 스크립트
 *
 * 1) public/*.html에서 data-sri="true"가 붙은 외부 <script>/<link>를 찾아 sha384 SRI 생성 후 integrity=... 삽입
 * 2) index.html의 importmap(imports) + public/js 내 https://esm.sh/ URL을 seed로 잡아
 *    모듈을 내려받고(허용 도메인만) 간단한 import 파싱으로 의존 모듈까지 따라가며
 *    public/importmap-integrity.json에 { url: "sha384-..." } 형태로 저장
 * 참고:
 * - SRI는 브라우저가 CDN 리소스가 변조되었는지 검증해 불일치 시 실행을 차단합니다.
 * - Chrome 127+는 import maps의 integrity 섹션으로 imported ES modules 무결성 검증을 지원합니다.
 */

import { readFile, writeFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, "..");
const PUBLIC_DIR = path.join(ROOT, "public");

const HASH_ALG = "sha384";
const MAX_MODULES = 800;
const ALLOWED_ORIGINS = new Set([
	"https://esm.sh",
	"https://cdn.jsdelivr.net",
	"https://cdnjs.cloudflare.com",
]);

function sriFromBytes(buf) {
	const b64 = createHash(HASH_ALG).update(buf).digest("base64");
	return `${HASH_ALG}-${b64}`;
}

async function fetchBytes(url) {
	const u = new URL(url);
	if (!ALLOWED_ORIGINS.has(u.origin))
		throw new Error(`Blocked origin: ${u.origin} (${url})`);

	const res = await fetch(url, { redirect: "follow" });
	if (!res.ok)
		throw new Error(`Fetch failed ${res.status} for ${url}`);

	const ab = await res.arrayBuffer();
	return Buffer.from(ab);
}

async function loadHtmlFiles() {
	const entries = await readdir(PUBLIC_DIR, { withFileTypes: true });
	return entries
		.filter((e) => e.isFile() && e.name.endsWith(".html"))
		.map((e) => path.join(PUBLIC_DIR, e.name));
}

function extractImportmapJson(html) {
	const m = html.match(/<script[^>]*type=["']importmap["'][^>]*>([\s\S]*?)<\/script>/i);
	if (!m) return null;
	let raw = m[1].trim();

	// index.html 템플릿에 들어있는 __IMPORTMAP_INTEGRITY__ 토큰은 런타임에 치환되지만,
	// 여기서는 JSON.parse가 실패하므로 스캔 단계에서는 빈 객체로 대체한다.
	raw = raw.replace(/__IMPORTMAP_INTEGRITY__/g, "{}");

	return JSON.parse(raw);
}

function collectEsmShUrlsFromJs(jsText) {
  const out = new Set();
  const re = /https:\/\/esm\.sh\/[^\s"'`)<]+/g;
  let m;
  while ((m = re.exec(jsText))) out.add(m[0]);
  return out;
}

async function collectSeedModuleUrls() {
	const indexPath = path.join(PUBLIC_DIR, "index.html");
	const indexHtml = await readFile(indexPath, "utf8");
	const map = extractImportmapJson(indexHtml);
	const seeds = new Set();
	if (map?.imports) {
		for (const v of Object.values(map.imports)) {
		    if (typeof v === "string" && v.startsWith("https://")) seeds.add(v);
		}
	}
	// public/js 내 direct esm.sh imports seed
	const jsDir = path.join(PUBLIC_DIR, "js");
	const jsFiles = await readdir(jsDir, { withFileTypes: true });
	for (const f of jsFiles) {
		if (!f.isFile() || !f.name.endsWith(".js")) continue;
		const p = path.join(jsDir, f.name);
		const t = await readFile(p, "utf8");
		for (const u of collectEsmShUrlsFromJs(t)) seeds.add(u);
	}
	return seeds;
}

function extractModuleDeps(moduleText, baseUrl) {
	const deps = new Set();

	// https 상대 경로 탐색
	const absRe = /(?:from\s+|import\s*\()\s*["'](https:\/\/[^"']+)["']/g;

	let m;
	while ((m = absRe.exec(moduleText))) deps.add(m[1]);

	// relative 절대 경로 탐색
	const relRe = /(?:from\s+|import\s*\()\s*["'](\.?\.\/[^"']+)["']/g;
	while ((m = relRe.exec(moduleText))) {
		try {
		    deps.add(new URL(m[1], baseUrl).toString());
		} catch {}
	}

	return deps;
}

async function buildImportmapIntegrity(seeds) {
	const integrity = {};
	const seen = new Set();
	const q = [...seeds];

	while (q.length) {
		const url = q.shift();
		if (seen.has(url)) continue;
		seen.add(url);
		if (seen.size > MAX_MODULES)
		    throw new Error(`Too many modules (${seen.size}). Increase MAX_MODULES or narrow seeds.`);

		const bytes = await fetchBytes(url);
		integrity[url] = sriFromBytes(bytes);

		// JS처럼 보이는 문자열만 텍스트로 추출(파싱)
		const text = bytes.toString("utf8");
		for (const dep of extractModuleDeps(text, url)) {
		    try {
			    const u = new URL(dep);
			    if (ALLOWED_ORIGINS.has(u.origin)) q.push(dep);
		    } catch {}
		}
	}

	return integrity;
}

function applySriToHtml(html, sriMap) {
	// data-sri="true"가 붙은 외부 src/href에 integrity 삽입
	// (아주 단순한 정규식 기반 치환이므로, 복잡한 케이스는 수동 점검 권장)

	// <script ... src="https://..." ... data-sri="true" ...>
	html = html.replace(/<script([^>]*?)\s+src=["'](https:\/\/[^"']+)["']([^>]*?\sdata-sri=["']true["'][^>]*)>/gi,
		(full, pre, url, post) => {
		    const integrity = sriMap[url];
		    if (!integrity) return full; // 못 찾으면 그대로
		    if (/integrity=/.test(full)) return full; // 이미 있으면 그대로
		    return `<script${pre} src="${url}" integrity="${integrity}"${post.replace(/\sdata-sri=["']true["']/i, "")}>`;
		}
	);

	// <link ... href="https://..." ... data-sri="true" ...>
	html = html.replace(/<link([^>]*?)\s+href=["'](https:\/\/[^"']+)["']([^>]*?\sdata-sri=["']true["'][^>]*)>/gi,
		(full, pre, url, post) => {
		    const integrity = sriMap[url];
		    if (!integrity) return full;
		    if (/integrity=/.test(full)) return full;
		    return `<link${pre} href="${url}" integrity="${integrity}"${post.replace(/\sdata-sri=["']true["']/i, "")}>`;
		}
	);

	return html;
}

async function main() {
	// HTML에 걸린 외부 리소스(SRI)
	const htmlFiles = await loadHtmlFiles();
	const externalUrls = new Set();
	for (const p of htmlFiles) {
		const html = await readFile(p, "utf8");
		const re = /\s(?:src|href)=["'](https:\/\/[^"']+)["']/gi;
		let m;
		while ((m = re.exec(html))) {
		    const u = new URL(m[1]);
		    if (ALLOWED_ORIGINS.has(u.origin)) externalUrls.add(m[1]);
		}
	}

	const sriMap = {};
	for (const url of externalUrls) {
		try {
		    const bytes = await fetchBytes(url);
		    sriMap[url] = sriFromBytes(bytes);
		    process.stdout.write(".");
		} catch (e) {
		    console.warn(`\n[SRI] skip ${url}: ${e.message}`);
		}
	}
	console.log("\n[SRI] done");

	// Importmap integrity 생성(모듈 그래프)
	const seeds = await collectSeedModuleUrls();
	const integrityMap = await buildImportmapIntegrity(seeds);
	await writeFile(path.join(PUBLIC_DIR, "importmap-integrity.json"), JSON.stringify(integrityMap, null, 2));
	console.log(`[Importmap] wrote ${Object.keys(integrityMap).length} entries`);

	// HTML에 integrity 자동 삽입(선택)
	for (const p of htmlFiles) {
		const html = await readFile(p, "utf8");
		const out = applySriToHtml(html, sriMap);
		if (out !== html) await writeFile(p, out, "utf8");
	}
	console.log("[HTML] integrity attributes updated where possible");
}

main().catch((e) => {
	console.error(e);
	process.exit(1);
});