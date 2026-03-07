import fs from 'node:fs';
import path from 'node:path';
const pkg = JSON.parse(fs.readFileSync('package.json', 'utf8'));
const lock = fs.existsSync('package-lock.json') ? JSON.parse(fs.readFileSync('package-lock.json', 'utf8')) : null;
const CRITICAL = { 'dompurify': '3.3.2', 'isomorphic-dompurify': '3.0.0' };
for (const [name, min] of Object.entries(CRITICAL)) {
	const current = pkg.dependencies[name] || pkg.devDependencies?.[name] || pkg.overrides?.[name];
	if (current && current.replace(/[\^~]/, '') < min) {
		console.error(`[SECURITY] ${name} version ${current} is vulnerable. Minimum ${min} required.`);
		process.exit(1);
	}
}
console.log('[SECURITY] Dependency version check passed.');
