const fs = require('fs');
const path = require('path');
const net = require('net');
const yauzl = require('yauzl');
const { promisify } = require('util');
const { isPrivateOrLocalIP } = require('./network-utils');

const SAFE_BASE_ATTACHMENT_EXTS = new Set([
	'.jpg', '.jpeg', '.png', '.gif', '.webp', '.pdf'
]);

const RICH_DOC_ATTACHMENT_EXTS = new Set([
	'.txt', '.md', '.csv', '.docx', '.xlsx', '.pptx'
]);

const ALLOWED_ATTACHMENT_EXTS = new Set(SAFE_BASE_ATTACHMENT_EXTS);
if (String(process.env.ENABLE_RICH_DOCUMENT_ATTACHMENTS).toLowerCase() === 'true') {
	for (const ext of RICH_DOC_ATTACHMENT_EXTS) ALLOWED_ATTACHMENT_EXTS.add(ext);
}
const { domainToASCII } = require('node:url');

function isHostnameAllowedForPreview(hostname) {
    if (typeof hostname !== 'string') return false;
    const ascii = domainToASCII(String(hostname).trim());
    const h = String(ascii || '').toLowerCase().replace(/\.$/, '');
    if (!h) return false;
    if (h.length > 253) return false;
    if (h.includes('..') || h.startsWith('.') || h.endsWith('.')) return false;
    if (net.isIP(h)) return false;
    if (!h.includes('.')) return false;
    if (!/^[a-z0-9.-]+$/.test(h)) return false;

    const labels = h.split('.');
    for (const label of labels) {
        if (!label || label.length > 63) return false;
        if (!/^[a-z0-9-]+$/.test(label)) return false;
        if (label.startsWith('-') || label.endsWith('-')) return false;
    }

    const PREVIEW_BLOCKED_HOSTS = new Set([
        'localhost',
        'localhost.localdomain',
        'metadata.google.internal',
        'metadata.goog',
        'metadata.azure.com'
    ]);
    const PREVIEW_BLOCKED_SUFFIXES = [
        '.localhost',
        '.local',
        '.internal'
    ];

    if (PREVIEW_BLOCKED_HOSTS.has(h)) return false;
    if (PREVIEW_BLOCKED_SUFFIXES.some(suffix => h.endsWith(suffix))) return false;

    return true;
}

function detectImageTypeFromMagic(buf) {
	if (!Buffer.isBuffer(buf)) return null;
	if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' };
	if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47 && buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a) return { ext: 'png', mime: 'image/png' };
	if (buf.length >= 6 && buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38 && (buf[4] === 0x37 || buf[4] === 0x39) && buf[5] === 0x61) return { ext: 'gif', mime: 'image/gif' };
	if (buf.length >= 12 && buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x57 && buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50) return { ext: 'webp', mime: 'image/webp' };
	return null;
}

function assertImageFileSignature(filePath, allowedExts) {
	const fd = fs.openSync(filePath, 'r');
	try {
		const header = Buffer.alloc(32);
		fs.readSync(fd, header, 0, header.length, 0);
		const detected = detectImageTypeFromMagic(header);
		if (!detected) throw new Error('BAD_IMAGE_SIGNATURE');
		const set = allowedExts instanceof Set ? allowedExts : new Set(allowedExts || []);
		if (set.size > 0 && !set.has(detected.ext) && !set.has(detected.ext === 'jpg' ? 'jpeg' : detected.ext)) throw new Error('DISALLOWED_IMAGE_TYPE');
		return detected;
	} finally {
		fs.closeSync(fd);
	}
}

function bufferLooksLikeActiveContent(buf) {
	const head = Buffer.isBuffer(buf) ? buf.slice(0, 4096).toString('utf8').toLowerCase() : '';
	return head.includes('<html') || head.includes('<script') || head.includes('<svg') || head.includes('<?xml') || head.includes('javascript:') || head.includes('<iframe') || head.includes('<object') || head.includes('<embed');
}

function assertSafeCsvContent(text) {
	if (Buffer.isBuffer(text)) text = text.toString('utf8');
	const dangerous = /^[\s]*[=+\-@]/m;
	if (dangerous.test(text)) throw new Error('DANGEROUS_CSV_FORMULA');
}

function neutralizeCsvCell(value) {
	const s = String(value ?? '');
	return /^[\s]*[=+\-@]/.test(s) ? `'${s}` : s;
}

function readFileHead(filePath, size = 4096) {
	const fd = fs.openSync(filePath, 'r');
	try {
		const head = Buffer.alloc(size);
		const n = fs.readSync(fd, head, 0, head.length, 0);
		return head.slice(0, n);
	} finally {
		fs.closeSync(fd);
	}
}

function readTextFileFully(filePath, maxBytes = 8 * 1024 * 1024) {
	const st = fs.statSync(filePath);
	if (st.size > maxBytes) throw new Error('TEXT_ATTACHMENT_TOO_LARGE');
	return fs.readFileSync(filePath, 'utf8');
}

async function assertSafeOoxmlArchive(filePath) {
	const openZip = promisify(yauzl.open);
	const zip = await openZip(filePath, { lazyEntries: true });
	return await new Promise((resolve, reject) => {
		let hasContentTypes = false;
		let rejected = false;
		const fail = (err) => {
			if (rejected) return;
			rejected = true;
			try { zip.close(); } catch (_) {}
			reject(err);
		};
		zip.on('entry', (entry) => {
			const name = String(entry.fileName || '').toLowerCase();
			if (name === '[content_types].xml') hasContentTypes = true;
			if (
				name.includes('vbaproject.bin') ||
				name.endsWith('.bin') ||
				name.includes('/embeddings/') ||
				name.includes('/activex/') ||
				name.includes('embeddings/') ||
				name.includes('oleobject') ||
				name.endsWith('.rels')
			) return fail(new Error('UNSAFE_OOXML_ACTIVE_CONTENT'));
			zip.readEntry();
		});
		zip.on('end', () => {
			if (!hasContentTypes) return fail(new Error('BAD_OOXML_STRUCTURE'));
			resolve();
		});
		zip.on('error', fail);
		zip.readEntry();
	});
}

const PDF_ACTIVE_TOKEN_RE = /\/(?:JS|JavaScript|OpenAction|RichMedia|Launch|AcroForm|URI|SubmitForm|Named|EmbeddedFile)\b/i;
const PDF_SCAN_MAX_BYTES = 16 * 1024 * 1024;

async function assertSafePdfFile(filePath, maxBytes = PDF_SCAN_MAX_BYTES) {
	const fh = await fs.promises.open(filePath, 'r');
	try {
		const st = await fh.stat();
		if (st.size < 5) throw new Error('BAD_PDF_SIGNATURE');
		if (st.size > maxBytes) throw new Error('PDF_SCAN_TOO_LARGE');
		const signature = Buffer.alloc(5);
		await fh.read(signature, 0, signature.length, 0);
		if (!signature.equals(Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D]))) throw new Error('BAD_PDF_SIGNATURE');
		const chunk = Buffer.alloc(64 * 1024);
		const overlapBytes = 128;
		let offset = 0;
		let carry = '';
		while (offset < st.size) {
			const toRead = Math.min(chunk.length, st.size - offset);
			const { bytesRead } = await fh.read(chunk, 0, toRead, offset);
			if (!bytesRead) break;
			const windowText = carry + chunk.subarray(0, bytesRead).toString('latin1');
			if (PDF_ACTIVE_TOKEN_RE.test(windowText)) throw new Error('UNSAFE_PDF_ACTIVE_CONTENT');
			carry = windowText.slice(-overlapBytes);
			offset += bytesRead;
		}
	} finally {
		await fh.close();
	}
}

async function scanPdfWithAvOrCdr(filePath) {
    const cmd = String(process.env.PDF_ATTACHMENT_SCAN_CMD || "").trim();
    if (!cmd) throw new Error("PDF 스캔 설정이 필요합니다.");
    const { execFile } = require("child_process");
    await new Promise((resolve, reject) => {
        execFile(cmd, [filePath], { timeout: 60000 }, (err) => {
            if (err) return reject(new Error("보안 스캐너가 위험한 PDF로 판단했습니다."));
            resolve();
        });
    });
}

async function assertSafeAttachmentFile(filePath, originalName = '') {
    const ext = path.extname(String(originalName || filePath)).toLowerCase();
    if (!ALLOWED_ATTACHMENT_EXTS.has(ext)) throw new Error('허용되지 않는 첨부파일 형식입니다.');

    if (RICH_DOC_ATTACHMENT_EXTS.has(ext) &&
        String(process.env.ENABLE_RICH_DOCUMENT_ATTACHMENTS).toLowerCase() !== 'true') {
        throw new Error('문서 첨부 기능이 비활성화되어 있습니다.');
    }

    const head = readFileHead(filePath, 4096);
    
    if (['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext)) {
        const detected = assertImageFileSignature(filePath, new Set(['jpg', 'jpeg', 'png', 'gif', 'webp']));
        const normalized = `.${detected.ext === 'jpg' ? 'jpg' : detected.ext}`;
        const equivalent = (ext === '.jpeg' && normalized === '.jpg') || ext === normalized;
        if (!equivalent) throw new Error('이미지 확장자가 실제 파일 형식과 일치하지 않습니다.');
        return;
    }

    if (ext === '.pdf') {
        await assertSafePdfFile(filePath);
        await scanPdfWithAvOrCdr(filePath);
        return;
    }
	if (['.docx', '.xlsx', '.pptx'].includes(ext)) {
		if (String(process.env.REQUIRE_OFFICE_ATTACHMENT_SCAN).toLowerCase() !== 'true') {
			throw new Error('OFFICE_SCAN_REQUIRED');
		}
		if (!head.slice(0, 4).equals(Buffer.from([0x50, 0x4B, 0x03, 0x04]))) throw new Error('BAD_OOXML_SIGNATURE');
		await assertSafeOoxmlArchive(filePath);
		return;
	}
	if (ext === '.csv') {
		const text = readTextFileFully(filePath);
		if (bufferLooksLikeActiveContent(Buffer.from(text, 'utf8'))) throw new Error('ACTIVE_CONTENT_ATTACHMENT');
		assertSafeCsvContent(text);
		return;
	}
	if (ext === '.txt' || ext === '.md') {
		const text = readTextFileFully(filePath);
		if (bufferLooksLikeActiveContent(Buffer.from(text, 'utf8'))) throw new Error('ACTIVE_CONTENT_ATTACHMENT');
		return;
	}

	// Any remaining binary type must be explicitly recognized above.
	// Reject unknown/polyglot binaries even if the extension is allowlisted.
	if (bufferLooksLikeActiveContent(head)) throw new Error('ACTIVE_CONTENT_ATTACHMENT');
	throw new Error('UNRECOGNIZED_ATTACHMENT_SIGNATURE');
}

function installDomPurifySecurityHooks(DOMPurify) {
	if (!DOMPurify?.addHook) return;
	DOMPurify.addHook('afterSanitizeAttributes', (node) => {
		if (String(node.tagName).toLowerCase() === 'a') {
			const target = String(node.getAttribute('target') || '').trim().toLowerCase();
			if (target === '_blank') {
				const rel = (node.getAttribute('rel') || '').toLowerCase();
				const set = new Set(rel.split(/\s+/).filter(Boolean));
				set.add('noopener'); set.add('noreferrer');
				node.setAttribute('rel', Array.from(set).join(' '));
			}
		}
	});
}

module.exports = {
	detectImageTypeFromMagic,
	assertImageFileSignature,
	assertSafeAttachmentFile,
	assertSafeCsvContent,
	neutralizeCsvCell,
	installDomPurifySecurityHooks,
	isHostnameAllowedForPreview
};
