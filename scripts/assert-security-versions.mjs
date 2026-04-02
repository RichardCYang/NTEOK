import fs from 'node:fs';
import semver from 'semver';

const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const lock = fs.existsSync('package-lock.json') ? JSON.parse(fs.readFileSync('package-lock.json', 'utf8')) : null;

const CRITICAL = {
	'dompurify': '3.3.2',
	'isomorphic-dompurify': '3.0.0',
	'@simplewebauthn/browser': '13.2.2',
	'@simplewebauthn/server': '13.2.2',
	'ws': '8.18.3',
	'axios': '1.13.5',
	'node-forge': '1.4.0',
	'lodash': '4.18.1',
	'path-to-regexp': '8.4.2',
	'brace-expansion': '5.0.5'
};

function normalizeSemver(raw) {
	const s = String(raw || '').trim().replace(/^[^0-9]*/, '').split(/[+-]/)[0];
	const m = s.match(/^(\d+)\.(\d+)\.(\d+)$/);
	if (!m) return null;
	return [Number(m[1]), Number(m[2]), Number(m[3])];
}

function compareSemver(a, b) {
	for (let i = 0; i < 3; i++) {
		if (a[i] > b[i]) return 1;
		if (a[i] < b[i]) return -1;
	}
	return 0;
}

function getInstalledVersion(name) {
	if (!lock?.packages) return null;
	const key = `node_modules/${name}`;
	return lock.packages[key]?.version || null;
}

for (const [name, min] of Object.entries(CRITICAL)) {
	const declared =
		pkg.dependencies?.[name] ||
		pkg.devDependencies?.[name] ||
		pkg.overrides?.[name] ||
		null;

	const installed = getInstalledVersion(name) || declared;
	if (!installed) continue;

	const cur = normalizeSemver(installed);
	const req = normalizeSemver(min);
	if (!cur || !req) {
		console.error(`[SECURITY] semver parse failed for ${name}: current=${installed}, minimum=${min}`);
		process.exit(1);
	}

	if (compareSemver(cur, req) < 0) {
		console.error(`[SECURITY] ${name} version ${installed} is below minimum ${min}`);
		process.exit(1);
	}
}
console.log('[SECURITY] Dependency version check passed.');

const v = process.versions.node;
const ok = semver.satisfies(
  v,
  '>=20.20.0 <21 || >=22.22.0 <23 || >=24.13.0 <25 || >=25.3.0'
);

if (!ok) {
  console.error(`[SECURITY] Unsupported Node.js runtime for 2026-01 security floor: ${v}`);
  process.exit(1);
}
