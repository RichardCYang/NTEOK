'use strict';

const express = require('express');
const router = express.Router();
const archiver = require('archiver');
const yauzl = require('yauzl');
const { JSDOM } = require('jsdom');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const crypto = require('crypto');
const erl = require('express-rate-limit');

const BACKUP_SIGNING_KEY = process.env.BACKUP_SIGNING_KEY || null;

function signBackupManifest(raw, userId) {
    if (!BACKUP_SIGNING_KEY) throw new Error('BACKUP_SIGNING_KEY 미설정');
    const hmac = crypto.createHmac('sha256', BACKUP_SIGNING_KEY);
    hmac.update(String(raw));
    if (userId) hmac.update(`:user:${userId}`);
    return hmac.digest('hex');
}

function verifyBackupManifest(raw, sig, userId) {
    if (!BACKUP_SIGNING_KEY) return false;
    const expected = signBackupManifest(raw, userId);
    try {
        return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(String(sig || '').trim(), 'hex'));
    } catch (_) {
        return false;
    }
}

function sha256HexFromBuffer(buf) {
    return crypto.createHash('sha256').update(buf).digest('hex');
}

async function sha256HexFromEntry(entry) {
    if (entry.data) return crypto.createHash('sha256').update(entry.data).digest('hex');
    return await new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const rs = fs.createReadStream(entry.tempFilePath, { highWaterMark: 64 * 1024 });
        rs.on('data', (chunk) => hash.update(chunk));
        rs.on('error', reject);
        rs.on('end', () => resolve(hash.digest('hex')));
    });
}
const rateLimit = erl.rateLimit || erl;
const { ipKeyGenerator } = erl;
const { Transform, pipeline } = require('stream');
const { promisify } = require('util');
const pipelineAsync = promisify(pipeline);
const { validateAndNormalizeIcon } = require('../utils/icon-utils.js');
const { assertSafeAttachmentFile } = require("../security-utils.js");


const MULTIPART_COMMON_LIMITS = Object.freeze({
    files: 1,
    fields: 16,
    parts: 20,
    fieldNameSize: 100,
    fieldSize: 64 * 1024,
    headerPairs: 2000
});

const DANGEROUS_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);

function stripDangerousKeys(value, seen = new WeakSet()) {
    if (!value || typeof value !== "object") return;
    if (seen.has(value)) return;
    seen.add(value);

    if (Array.isArray(value)) {
        for (const item of value) stripDangerousKeys(item, seen);
        return;
    }

    for (const key of Object.keys(value)) {
        if (DANGEROUS_OBJECT_KEYS.has(key)) {
            delete value[key];
            continue;
        }
        stripDangerousKeys(value[key], seen);
    }
}

function safeJsonParse(text, context = "json") {
    try {
        const obj = JSON.parse(text, (k, v) => {
            if (DANGEROUS_OBJECT_KEYS.has(k)) return undefined;
            return v;
        });
        if (obj && typeof obj === 'object') {
            stripDangerousKeys(obj);
        }
        return obj;
    } catch (e) {
        console.warn(`[safeJsonParse] 파싱 실패 (${context}):`, e.message);
        return null;
    }
}


const tempDir = 'temp';
if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
}

const MAX_BACKUP_ZIP_BYTES = 50 * 1024 * 1024;
const MAX_ZIP_ENTRIES = 1000;
const MAX_ENTRY_UNCOMPRESSED_BYTES = 5 * 1024 * 1024;
const MAX_TOTAL_UNCOMPRESSED_BYTES = 100 * 1024 * 1024;
const MAX_SUSPICIOUS_RATIO = 2000;
const MIN_RATIO_ENTRY_BYTES = 1 * 1024 * 1024;
const MAX_HTML_PAGES = 500;
const MAX_PAGE_HTML_BYTES = 1024 * 1024;

const MAX_ENTRY_BUFFER_BYTES = 256 * 1024;

const FILE_TYPE = Object.freeze({
    PAPERCLIP: 'paperclip',
    IMGS: 'imgs'
});

function normalizeFileType(raw) {
    const t = String(raw || '').trim().toLowerCase();
    if (!t) return null;
    if (t === 'image' || t === 'img' || t === 'images') return FILE_TYPE.IMGS;
    if (t === FILE_TYPE.IMGS) return FILE_TYPE.IMGS;
    if (t === FILE_TYPE.PAPERCLIP) return FILE_TYPE.PAPERCLIP;
    return null;
}

function openZipFile(zipPath) {
    return new Promise((resolve, reject) => {
        yauzl.open(zipPath, { lazyEntries: true, autoClose: true }, (err, zipfile) => {
            if (err) return reject(err);
            resolve(zipfile);
        });
    });
}

function openZipReadStream(zipfile, entry) {
    return new Promise((resolve, reject) => {
        zipfile.openReadStream(entry, (err, stream) => {
            if (err) return reject(err);
            resolve(stream);
        });
    });
}

function readStreamToBufferWithLimits(stream, { perEntryLimitBytes, getTotalBytes, addTotalBytes, context }) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let size = 0;
        let done = false;

        function fail(err) {
            if (done) return;
            done = true;
            try { stream.destroy(); } catch (_) { }
            reject(err);
        }

        stream.on('data', (chunk) => {
            if (done) return;

            size += chunk.length;
            addTotalBytes(chunk.length);

            if (size > perEntryLimitBytes)
                return fail(new Error(`[보안] ZIP 항목이 제한을 초과했습니다: ${context}`));

            if (getTotalBytes() > MAX_TOTAL_UNCOMPRESSED_BYTES)
                return fail(new Error('[보안] ZIP 전체 해제 용량이 제한을 초과했습니다.'));

            chunks.push(chunk);
        });
        stream.on('end', () => {
            if (done) return;
            done = true;
            resolve(Buffer.concat(chunks, size));
        });
        stream.on('error', fail);
    });
}

const backupUpload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, tempDir);
        },
        filename: (req, file, cb) => {
            const uniqueSuffix = Date.now() + '-' + crypto.randomBytes(6).toString('hex');
            cb(null, 'backup-' + uniqueSuffix + '.zip');
        }
    }),
    limits: {
        ...MULTIPART_COMMON_LIMITS,
        fileSize: MAX_BACKUP_ZIP_BYTES,
        fields: 4,
        parts: 4
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) {
            cb(null, true);
        } else {
            cb(new Error('ZIP 파일만 업로드 가능합니다.'));
        }
    }
});

function createImportTempDir() {
    const dir = path.join(tempDir, `import-extract-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    return dir;
}

function entryTempPath(extractDir, entryName) {
    const h = crypto.createHash('sha256').update(entryName).digest('hex').slice(0, 32);
    return path.join(extractDir, h);
}

function createLimitTransform({ perEntryLimitBytes, getTotalBytes, addTotalBytes, context }) {
    let size = 0;
    return new Transform({
        transform(chunk, enc, cb) {
            size += chunk.length;
            addTotalBytes(chunk.length);
            if (size > perEntryLimitBytes)
                return cb(new Error(`[보안] ZIP 항목이 제한을 초과했습니다: ${context}`));

            if (getTotalBytes() > MAX_TOTAL_UNCOMPRESSED_BYTES)
                return cb(new Error('[보안] ZIP 전체 해제 용량이 제한을 초과했습니다.'));

			cb(null, chunk);
        }
    });
}

async function readStreamToTempFileWithLimits(stream, { outPath, perEntryLimitBytes, getTotalBytes, addTotalBytes, context }) {
    const limiter = createLimitTransform({ perEntryLimitBytes, getTotalBytes, addTotalBytes, context });
    const ws = fs.createWriteStream(outPath, { flags: 'wx', mode: 0o600 });
    try {
        await pipelineAsync(stream, limiter, ws);
        return outPath;
    } catch (e) {
        try { ws.destroy(); } catch (_) {}
        try { if (fs.existsSync(outPath)) fs.unlinkSync(outPath); } catch (_) {}
        throw e;
    }
}

module.exports = (dependencies) => {
    const {
		pool,
        redis,
        backupRepo,
		flushAllPendingE2eeSaves,
        authMiddleware,
        csrfMiddleware,
        toIsoString,
        sanitizeInput,
		sanitizeHtmlContent,
        generatePageId,
        formatDateForDb,
        logError,
        getClientIpFromRequest,
        requireRecentReauth,
        requireStrongStepUp,
        issueActionTicket,
        consumeActionTicket,
        getSessionFromRequest
	} = dependencies;

    if (typeof requireStrongStepUp !== 'function')
        throw new Error('routes/backup.js: requireStrongStepUp dependency missing');
    if (typeof getClientIpFromRequest !== 'function')
        throw new Error('routes/backup.js: getClientIpFromRequest dependency missing');

    function canonicalClientIp(req) {
        return String(
            getClientIpFromRequest(req) ||
            req.ip ||
            req.socket?.remoteAddress ||
            '0.0.0.0'
        ).trim();
    }

    function userAndIpRateKey(req) {
        const userPart = req.user?.id ? String(req.user.id) : 'anon';
        const ipPart = ipKeyGenerator(canonicalClientIp(req));
        return `${userPart}:${ipPart}`;
    }

    const backupImportLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 2,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: userAndIpRateKey,
    });

    const backupExportLimiter = rateLimit({
        windowMs: 10 * 60 * 1000,
        max: 3,
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: userAndIpRateKey,
    });

    router.post('/export-ticket',
        authMiddleware,
        csrfMiddleware,
        requireStrongStepUp({ maxAgeMs: 10 * 60 * 1000, requireMfaIfEnabled: true }),
        backupExportLimiter,
        async (req, res) => {
            try {
                const session = await getSessionFromRequest(req);
                if (!session) return res.status(401).json({ error: '세션이 만료되었습니다.' });
				const bindCtx = {
				    userAgent: req.headers['user-agent'] || '',
				    clientIp: canonicalClientIp(req),
				    origin: req.headers.origin || req.headers.referer || ''
				};
				const ticket = await issueActionTicket(
				    session.id,
				    'backup-export',
				    String(req.user.id),
				    bindCtx
				);
                res.json({ ok: true, ticket });
            } catch (e) {
                logError('POST /api/backup/export-ticket', e);
                res.status(500).json({ error: '백업 export 티켓 발급 실패' });
            }
        }
    );

    const wsConnections = dependencies.wsConnections;
    const yjsDocuments = dependencies.yjsDocuments;
    const saveYjsDocToDatabase = dependencies.saveYjsDocToDatabase;
    const enqueueYjsDbSave = dependencies.enqueueYjsDbSave;
    const flushAllPendingYjsDbSaves = dependencies.flushAllPendingYjsDbSaves;
    const issuePageSnapshotToken = dependencies.issuePageSnapshotToken;

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function normalizeStorageName(rawName) {
        if (typeof rawName !== 'string') rawName = '';
        let name = rawName.trim();

        name = name.replace(/[\u0000-\u001F\u007F]/g, '');

        if (name.length > 100) name = name.slice(0, 100);

        if (/[<>&"'`]/.test(name)) {
            name = name.replace(/[<>&"'`]/g, '');
        }

        if (!name) name = '가져온 저장소';
        return name;
    }

    const DEFAULT_COVERS = [
        'default/img1.png',
        'default/img2.png',
        'default/img3.png',
        'default/img4.png',
        'default/img5.png',
        'default/img6.png'
	];

    function normalizeImportedCoverRef(raw, currentUserId) {
        if (raw == null) return null;
        const s = String(raw).trim();
        if (!s) return null;

        if (DEFAULT_COVERS.includes(s)) return s;

        const normalized = normalizeAssetRefOnImport(s, currentUserId) || s;
        const re = new RegExp(`^${currentUserId}\\/([A-Za-z0-9][A-Za-z0-9._-]{0,199}\\.(?:png|jpe?g|gif|webp))$`, 'i');
        const m = normalized.match(re);
        if (!m) return null;

        const filename = m[1];
        if (filename.includes('..') || /["'()\\]/.test(filename)) return null;
        return `${currentUserId}/${filename}`;
    }

    function normalizeImportInt(value, { min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER, fallback = 0 } = {}) {
        const n = Number(value);
        if (!Number.isFinite(n)) return fallback;
        return Math.max(min, Math.min(max, Math.trunc(n)));
    }

    function normalizeImportedId(value, { maxLen = 64 } = {}) {
        if (typeof value !== 'string') return null;
        const s = value.trim();
        if (!s || s.length > maxLen) return null;
        if (/[\x00-\x1F\x7F]/.test(s)) return null;
        return s;
    }

    const EXPORT_ALLOWED_IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

    function normalizeUserImageRefForExport(raw, userId) {
        if (typeof raw !== "string") return null;

        const s = raw.replace(/\\/g, "/").trim();
        if (!s) return null;

        if (s.includes(String.fromCharCode(0)) || s.includes("..")) return null;
        if (s.startsWith("/") || s.startsWith("~")) return null;

        const m = s.match(/^(\d+)\/([A-Za-z0-9._-]{1,200}\.(?:png|jpe?g|gif|webp))$/i);
        if (!m) return null;

        const ownerId = Number(m[1]);
        if (!Number.isFinite(ownerId) || ownerId !== userId) return null;

        const filename = m[2];
        if (path.basename(filename) !== filename) return null;

        const ext = path.extname(filename).toLowerCase();
        if (!EXPORT_ALLOWED_IMAGE_EXTENSIONS.has(ext)) return null;

        return `${ownerId}/${filename}`;
    }

    function resolveSafeUserFilePath(rootDir, userId, filename) {
        const baseDir = path.join(rootDir, String(userId));
        const candidate = path.join(baseDir, filename);

        const resolvedBase = path.resolve(baseDir) + path.sep;
        const resolved = path.resolve(candidate);

        if (!resolved.startsWith(resolvedBase)) return null;

        try {
            const st = fs.lstatSync(resolved);
            if (!st.isFile() || st.isSymbolicLink()) return null;
        } catch (e) {
            return null;
        }

        return resolved;
    }

	const BACKUP_IMPORT_MAX_ENTRIES = Number(process.env.BACKUP_IMPORT_MAX_ENTRIES || 5000);
	const BACKUP_IMPORT_MAX_TOTAL_UNCOMPRESSED = Number(process.env.BACKUP_IMPORT_MAX_TOTAL_UNCOMPRESSED || (300 * 1024 * 1024));
	const BACKUP_IMPORT_MAX_ENTRY_UNCOMPRESSED = Number(process.env.BACKUP_IMPORT_MAX_ENTRY_UNCOMPRESSED || (20 * 1024 * 1024));

	const ALLOWED_IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

	async function readBackupZipEntriesForImport(zipPath) {
		const zipfile = await openZipFile(zipPath);
		const zipEntries = [];
		const extractDir = createImportTempDir();
		const allowedTopLevel = ['backup-info.json', 'file-refs.json', 'workspaces/', 'collections/', 'pages/', 'images/', 'paperclip/', 'e2ee/'];
		let entryCount = 0;
		let htmlEntryCount = 0;
		let totalHeaderUncompressed = 0;
		let totalBytesRead = 0;
		const getTotalBytes = () => totalBytesRead;
		const addTotalBytes = (n) => { totalBytesRead += n; };

		return await new Promise((resolve, reject) => {
			function fail(err) {
				try { zipfile.close(); } catch (_) { }
				try { fs.rmSync(extractDir, { recursive: true, force: true }); } catch (_) {}
				reject(err);
			}
			zipfile.on('error', fail);
			zipfile.on('end', () => resolve({ zipEntries, extractDir }));
			zipfile.on('entry', (entry) => {
				(async () => {
					try {
						entryCount++;
						if (entryCount > MAX_ZIP_ENTRIES) throw new Error(`[보안] 백업 ZIP 엔트리 수가 너무 많습니다. (최대 ${MAX_ZIP_ENTRIES}개)`);
						const entryName = String(entry.fileName || '');
						if (!entryName) throw new Error('[보안] ZIP 엔트리 이름이 비어 있습니다.');
						if (entryName.includes('\\') || entryName.includes('\0')) throw new Error('[보안] ZIP 엔트리 경로 형식이 유효하지 않습니다.');
						if (path.isAbsolute(entryName) || entryName.split('/').some(seg => seg === '..' || seg === '.')) throw new Error('[보안] ZIP 엔트리 경로 조작이 감지되었습니다.');
						if (entryName.endsWith('/')) { zipfile.readEntry(); return; }
						const allowed = allowedTopLevel.some(prefix => entryName === prefix || entryName.startsWith(prefix));
						if (!allowed) { zipfile.readEntry(); return; }
						const uncompressed = Number(entry.uncompressedSize || 0);
						const compressed = Number(entry.compressedSize || 0);
						if (!Number.isFinite(uncompressed) || uncompressed < 0) throw new Error('[보안] ZIP 엔트리 크기 정보를 확인할 수 없습니다.');
						if (uncompressed > MAX_ENTRY_UNCOMPRESSED_BYTES) throw new Error('[보안] 백업 파일 내 일부 항목이 너무 큽니다.');
						if (entryName.startsWith('pages/') && entryName.endsWith('.html')) {
							htmlEntryCount++;
							if (htmlEntryCount > MAX_HTML_PAGES) throw new Error(`[보안] 백업 내 HTML 페이지 수가 너무 많습니다. (최대 ${MAX_HTML_PAGES}개)`);
							if (uncompressed > MAX_PAGE_HTML_BYTES) throw new Error(`[보안] 백업 내 개별 HTML 페이지 크기가 제한을 초과했습니다. (최대 ${MAX_PAGE_HTML_BYTES / 1024}KB)`);
						}
						totalHeaderUncompressed += uncompressed;
						if (totalHeaderUncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES) throw new Error('[보안] 백업 파일의 전체 해제 용량이 너무 큽니다.');
						if (compressed > 0 && uncompressed >= MIN_RATIO_ENTRY_BYTES) {
							const ratio = uncompressed / compressed;
							if (ratio > MAX_SUSPICIOUS_RATIO) throw new Error('[보안] 압축 비율이 비정상적으로 높아 Zip Bomb 의심으로 차단했습니다.');
						}
						const perEntryLimitBytes = MAX_ENTRY_UNCOMPRESSED_BYTES;
						const forceToDisk = entryName.startsWith('pages/') || entryName.startsWith('images/') || entryName.startsWith('e2ee/');
						const canBuffer = !forceToDisk && uncompressed <= MAX_ENTRY_BUFFER_BYTES;
						const stream = await openZipReadStream(zipfile, entry);
						if (canBuffer) {
							const buf = await readStreamToBufferWithLimits(stream, { perEntryLimitBytes, getTotalBytes, addTotalBytes, context: entryName });
							zipEntries.push({ entryName, isDirectory: false, data: buf });
						} else {
							const outPath = entryTempPath(extractDir, entryName);
							await readStreamToTempFileWithLimits(stream, { outPath, perEntryLimitBytes, getTotalBytes, addTotalBytes, context: entryName });
							zipEntries.push({ entryName, isDirectory: false, tempFilePath: outPath });
						}
						zipfile.readEntry();
					} catch (e) { fail(e); }
				})();
			});
			zipfile.readEntry();
		});
	}

    const IMAGE_FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.(?:png|jpe?g|gif|webp)$/i;
    const WINDOWS_RESERVED = new Set([
        "CON","PRN","AUX","NUL",
        "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
        "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9",
    ]);

    function getSafeImageFilenameFromZipPath(maybePath) {
        if (typeof maybePath !== "string") return null;
        const normalized = maybePath.replace(/\\/g, "/").trim();
        if (!normalized) return null;

        const base = normalized.split("/").pop();
        if (!base) return null;
        if (/[\x00-\x1F\x7F]/.test(base)) return null;
        if (base.includes("/") || base.includes("\\")) return null;
        if (base.includes("..")) return null;

        if (!IMAGE_FILENAME_RE.test(base)) return null;

        const stem = base.replace(/\.[^.]+$/, "");
        const first = stem.split(".")[0].toUpperCase();
        if (WINDOWS_RESERVED.has(first)) return null;

        return base;
    }

    function getSafePaperclipFilenameFromZipPath(maybePath) {
        if (typeof maybePath !== "string") return null;
        const normalized = maybePath.replace(/\\/g, "/").trim();
        if (!normalized) return null;

        const base = normalized.split("/").pop();
        if (!base) return null;
        if (/[\x00-\x1F\x7F]/.test(base)) return null;
        if (base.includes("/") || base.includes("\\") || base.includes("..")) return null;

        if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,250}$/.test(base)) return null;

        const stem = base.replace(/\.[^.]+$/, "");
        if (WINDOWS_RESERVED.has(stem.toUpperCase())) return null;

        return base;
    }

    function safeResolveIntoDir(baseDir, filename) {
	    const base = path.resolve(baseDir);
	    const target = path.resolve(base, filename);
	    const rel = path.relative(base, target);
	    if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
	    if (!target.startsWith(base + path.sep)) return null;
	    return target;
    }

function escapeRegExp(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function makeUniqueFilename(original, suffix) {
    const ext = path.extname(original);
    const base = path.basename(original, ext);
    return `${base}__imp__${suffix}${ext}`;
}

function ensureUniqueDestPath(targetDir, filename) {
    const baseDir = path.resolve(targetDir);
    const initial = safeResolveIntoDir(baseDir, filename);
    if (!initial) return { filename: null, fullPath: null };
    if (!fs.existsSync(initial)) return { filename, fullPath: initial };

    for (let i = 0; i < 20; i++) {
        const suffix = `${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}${i ? "-" + i : ""}`;
        const candName = makeUniqueFilename(filename, suffix);
        const candPath = safeResolveIntoDir(baseDir, candName);
        if (!candPath) continue;
        if (!fs.existsSync(candPath)) return { filename: candName, fullPath: candPath };
    }

    return { filename: null, fullPath: null };
}

	function isSupportedImageBuffer(buf, filename) {
	    if (!Buffer.isBuffer(buf) || buf.length < 12) return false;

	    const ext = path.extname(filename).toLowerCase();

	    if (ext === ".png") {
	        return buf.length >= 8 &&
	            buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47 &&
	            buf[4] === 0x0D && buf[5] === 0x0A && buf[6] === 0x1A && buf[7] === 0x0A;
	    }

	    if (ext === ".jpg" || ext === ".jpeg")
	        return buf.length >= 3 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF;

	    if (ext === ".gif")
	        return buf.length >= 4 && buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38;

	    if (ext === ".webp") {
	        return buf.length >= 12 &&
	            buf.toString("ascii", 0, 4) === "RIFF" &&
	            buf.toString("ascii", 8, 12) === "WEBP";
	    }

	    return false;
	}

    function stringifyJsonForHtmlScriptTag(value) {
        return JSON.stringify(value, null, 2)
            .replace(/</g, '\\u003C')
            .replace(/>/g, '\\u003E')
            .replace(/&/g, '\\u0026')
            .replace(/\u2028/g, '\\u2028')
            .replace(/\u2029/g, '\\u2029');
    }

    function normalizeBackupBoolean(v, defaultValue = false) {
        if (v === true || v === false) return v;
        if (v === 1 || v === 0) return v === 1;
        if (typeof v === 'string') {
            const s = v.trim().toLowerCase();
            if (s === 'true' || s === '1') return true;
            if (s === 'false' || s === '0') return false;
        }
        return defaultValue;
    }

    function normalizePageRowForBackupExport(pageRow) {
        const isEncrypted = normalizeBackupBoolean(pageRow.is_encrypted, false);
        return {
            id: pageRow.id,
            parentId: pageRow.parent_id || null,
            sortOrder: pageRow.sort_order || 0,

            title: pageRow.title || '제목 없음',
            content: pageRow.content || '',
            icon: pageRow.icon || null,
            coverImage: pageRow.cover_image || null,
            coverPosition: pageRow.cover_position || 50,

            isEncrypted,
            encryptionSalt: pageRow.encryption_salt || null,
            encryptedContent: pageRow.encrypted_content || null,
            shareAllowed: normalizeBackupBoolean(pageRow.share_allowed, false),

            createdAt: toIsoString(pageRow.created_at) || pageRow.created_at,
            updatedAt: toIsoString(pageRow.updated_at) || pageRow.updated_at
        };
    }

    function convertPageToHTML(pageData) {
        const pageMetadata = {
            id: pageData.id,
            parentId: pageData.parentId,
            sortOrder: pageData.sortOrder,
            isEncrypted: pageData.isEncrypted,
            encryptionSalt: pageData.encryptionSalt || null,
            encryptedContent: pageData.encryptedContent || null,
            shareAllowed: pageData.shareAllowed || false,
            coverImage: pageData.coverImage || null,
            coverPosition: pageData.coverPosition || 50,
            isCoverImage: pageData.coverImage && !DEFAULT_COVERS.includes(pageData.coverImage) ? true : false
        };

        const html = `<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(pageData.title)}</title>
    <!-- NTEOK Page Metadata (DO NOT MODIFY) -->
    <script type="application/json" id="nteok-metadata">
${stringifyJsonForHtmlScriptTag(pageMetadata)}
    </script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }
        h1 { font-size: 2em; margin-bottom: 0.5em; }
        img { max-width: 100%; height: auto; }
        .metadata {
            color: #666;
            font-size: 0.9em;
            margin-bottom: 2em;
            padding-bottom: 1em;
            border-bottom: 1px solid #eee;
        }
        .cover-image {
            width: 100%;
            max-height: 400px;
            object-fit: cover;
            margin-bottom: 2em;
        }
    </style>
</head>
<body>
    ${pageData.coverImage ? `<img class="cover-image" src="../images/${pageData.coverImage}" alt="Cover">` : ''}
    <h1>${pageData.icon ? pageData.icon + ' ' : ''}${escapeHtml(pageData.title)}</h1>
    <div class="metadata">
        <div>생성: ${new Date(pageData.createdAt).toLocaleString('ko-KR')}</div>
        <div>수정: ${new Date(pageData.updatedAt).toLocaleString('ko-KR')}</div>
        ${pageData.isEncrypted ? '<div style="color: #dc2626;">🔒 암호화된 페이지</div>' : ''}
    </div>
    <div class="content">
        ${pageData.content || '<p>암호화된 내용입니다.</p>'}
    </div>
</body>
</html>`;
        return html;
    }

    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    function extractPageFromHTML(html, currentUserId) {
        try {
            const dom = new JSDOM(html);
            const doc = dom.window.document;

            const metadataScript = doc.querySelector('#nteok-metadata');
            let metadata = null;
            if (metadataScript) {
                try {
                    const metadataText = metadataScript.textContent?.trim();
                    if (metadataText && metadataText.length < 1024 * 1024) {
                        metadata = safeJsonParse(metadataText, 'nteok-metadata');
                    }
                } catch (e) { }
            }

            const titleEl = doc.querySelector('h1');
            const contentEl = doc.querySelector('.content');

            let title = titleEl ? titleEl.textContent.trim() : '제목 없음';

            const iconMatch = title.match(/^([\p{Emoji}\u200d]+)\s+(.+)$/u);
            let icon = null;
            if (iconMatch) {
                icon = iconMatch[1];
                title = iconMatch[2];
            }

            const elements = doc.querySelectorAll('[src], [data-src], [data-url], [data-thumbnail], [data-favicon]');
            for (const el of elements) {
                for (const attr of ['src', 'data-src', 'data-url', 'data-thumbnail', 'data-favicon']) {
                    if (el.hasAttribute(attr)) {
                        const val = el.getAttribute(attr);
                        const normalized = normalizeAssetRefOnImport(val, currentUserId);
                        if (normalized) el.setAttribute(attr, normalized);
                    }
                }
            }

            const coverImageEl = doc.querySelector('.cover-image');
            let coverImage = null;
            if (coverImageEl) {
                const src = coverImageEl.getAttribute('src');
                if (src) {
                    const match = src.match(/\.\.\/images\/(.+)/);
                    if (match) coverImage = match[1];
                }
            }
            if (coverImage) coverImage = normalizeImportedCoverRef(coverImage, currentUserId);

            const finalContent = sanitizeHtmlContent(contentEl ? contentEl.innerHTML : '<p></p>');

            const metaParentRaw = metadata?.parentId ?? metadata?.parent_id ?? null;
            const metaParentId = normalizeImportedId(
                (typeof metaParentRaw === 'string' && metaParentRaw.trim()) ? metaParentRaw.trim() : null
            );

            const metaIsEncrypted = normalizeBackupBoolean(metadata?.isEncrypted ?? metadata?.is_encrypted, false);
            const metaShareAllowed = normalizeBackupBoolean(metadata?.shareAllowed ?? metadata?.share_allowed, false);

            return {
                backupId: normalizeImportedId(metadata?.id),
                parentId: metaParentId,
                title,
                content: finalContent,
                icon: icon || (metadata?.icon) || null,
                isEncrypted: metaIsEncrypted,
                encryptionSalt: metaIsEncrypted ? ((metadata?.encryptionSalt ?? metadata?.encryption_salt) || null) : null,
                encryptedContent: metaIsEncrypted ? ((metadata?.encryptedContent ?? metadata?.encrypted_content) || null) : null,
                shareAllowed: metaShareAllowed,
                coverImage: normalizeImportedCoverRef(coverImage || metadata?.coverImage || null, currentUserId),
                coverPosition: normalizeImportInt(metadata?.coverPosition, { min: 0, max: 100, fallback: 50 }),
                sortOrder: normalizeImportInt(metadata?.sortOrder, { min: -1000000000, max: 1000000000, fallback: 0 }),
                isCoverImage: metadata?.isCoverImage || false
            };
        } catch (error) {
            return {
                title: '제목 없음',
                content: '<p></p>',
                icon: null,
                isEncrypted: false,
                encryptionSalt: null,
                encryptedContent: null,
                shareAllowed: false,
                coverImage: null,
                coverPosition: 50,
                parentId: null,
                sortOrder: 0,
                isCoverImage: false
            };
        }
    }

    router.post('/export', authMiddleware, csrfMiddleware, requireStrongStepUp({ maxAgeMs: 10 * 60 * 1000, requireMfaIfEnabled: true }), backupExportLimiter, async (req, res) => {
        const userId = req.user.id;

        try {
            const session = await getSessionFromRequest(req);
            if (!session) return res.status(401).json({ error: '세션이 만료되었습니다.' });

            const { ticket } = req.body || {};
            const bindCtx = {
    userAgent: req.headers['user-agent'] || '',
    clientIp: canonicalClientIp(req),
    origin: req.headers.origin || req.headers.referer || ''
};
const valid = await consumeActionTicket(
    session.id,
    'backup-export',
    String(userId),
    String(ticket || ''),
    bindCtx
);
            if (!valid) return res.status(403).json({ error: '유효하지 않거나 만료된 export 티켓입니다.' });

            res.set('Cache-Control', 'no-store, max-age=0');
            res.set('Pragma', 'no-cache');
            res.set('Cross-Origin-Resource-Policy', 'same-origin');
            res.set('X-Content-Type-Options', 'nosniff');

            await flushAllPendingE2eeSaves(pool);

            try {
                const [ownedRows] = await pool.execute(
                    `SELECT id FROM storages WHERE user_id = ?`,
                    [userId]
                );
                const ownedStorageIds = new Set((ownedRows || []).map(r => String(r.id)));

                let requested = 0;
                if (wsConnections && wsConnections.pages && ownedStorageIds.size > 0) {
                    for (const [pid, conns] of wsConnections.pages.entries()) {
                        if (!conns || conns.size === 0) continue;
                        for (const c of Array.from(conns)) {
                            const stgId = c && c.storageId ? String(c.storageId) : '';
                            if (!stgId || !ownedStorageIds.has(stgId)) continue;
                            if (c.isE2ee) continue;
                            const perm = String(c.permission || '');
                            if (perm !== 'EDIT' && perm !== 'ADMIN') continue;
                            try {
                                const snapshotToken = (typeof issuePageSnapshotToken === 'function') ? issuePageSnapshotToken(c, pid) : null;
                                c.ws.send(JSON.stringify({
                                    event: 'request-page-snapshot',
                                    data: { pageId: String(pid), snapshotToken }
                                }));
                                requested++;
                            } catch (_) {}
                        }
                    }
                }

                if (requested > 0) {
                    const waitMsRaw = Number.parseInt(process.env.BACKUP_EXPORT_SNAPSHOT_WAIT_MS || '1200', 10);
                    const waitMs = Number.isFinite(waitMsRaw) ? Math.max(200, Math.min(5000, waitMsRaw)) : 1200;
                    await sleep(waitMs);
                }

                if (yjsDocuments && ownedStorageIds.size > 0 && typeof enqueueYjsDbSave === 'function' && typeof saveYjsDocToDatabase === 'function') {
                    for (const [pageId, docInfo] of yjsDocuments.entries()) {
                        if (!docInfo || !docInfo.ydoc) continue;
                        const stgId = docInfo.storageId ? String(docInfo.storageId) : '';
                        if (!stgId || !ownedStorageIds.has(stgId)) continue;
                        if (docInfo.isEncrypted === true) continue;

                        if (docInfo.saveTimeout) {
                            try { clearTimeout(docInfo.saveTimeout); } catch (_) {}
                            docInfo.saveTimeout = null;
                        }

                        enqueueYjsDbSave(pageId, () =>
                            saveYjsDocToDatabase(pool, sanitizeHtmlContent, pageId, docInfo.ydoc, { preserveDbMetadata: true })
                        ).catch(() => {});
                    }

                    if (typeof flushAllPendingYjsDbSaves === 'function') {
                        await flushAllPendingYjsDbSaves();
                    }
                }
            } catch (e) {
                try { console.warn('[backup export] plaintext flush failed (continue):', e?.message || e); } catch (_) {}
            }

            const { storages, pages } = await backupRepo.getExportRows(userId);

            if (!storages || storages.length === 0)
                return res.status(404).json({ error: '내보낼 데이터가 없습니다.' });

            const archive = archiver('zip', {
                zlib: { level: 9 }
            });

            res.attachment('nteok-backup.zip');
            res.type('application/zip');

            archive.on('error', (err) => {
                logError('ZIP 생성 오류', err);
                if (!res.headersSent) res.status(500).json({ error: 'ZIP 생성 실패' });
            });

            archive.pipe(res);

            const integrityEntries = [];
            const appendTrackedBuffer = (name, data) => {
                const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
                integrityEntries.push({ name, sha256: sha256HexFromBuffer(buf) });
                archive.append(buf, { name });
            };
            const appendTrackedFile = (name, filePath) => {
                const buf = fs.readFileSync(filePath);
                integrityEntries.push({ name, sha256: sha256HexFromBuffer(buf) });
                archive.append(buf, { name });
            };

            const imagesToInclude = new Set();
            const paperclipsToInclude = new Set();
            const pageIdsForRefs = pages.map(p => p.id);
            const fileRefs = pageIdsForRefs.length > 0 ? await backupRepo.listFileRefsForPageIds(pageIdsForRefs) : [];

            for (const ref of fileRefs) {
                const ftype = normalizeFileType(ref.file_type);
                if (ftype === FILE_TYPE.IMGS) {
                    const normalized = normalizeUserImageRefForExport(`${ref.owner_user_id}/${ref.stored_filename}`, userId);
                    if (normalized) imagesToInclude.add(normalized);
                } else if (ftype === FILE_TYPE.PAPERCLIP) {
                    const s = `${ref.owner_user_id}/${ref.stored_filename}`;
                    if (!s.includes('..') && !s.startsWith('/') && ref.owner_user_id === userId) {
                        paperclipsToInclude.add(s);
                    }
                }
            }

            const imgRegex = /\/imgs\/(\d+)\/([A-Za-z0-9._-]{1,200}\.(?:png|jpe?g|gif|webp))(?:\?[^"'\s]*)?/gi;
            for (const page of pages) {
                if (page.is_encrypted) continue;
                const content = page.content || '';
                let match;
                while ((match = imgRegex.exec(content)) !== null) {
                    const normalized = normalizeUserImageRefForExport(`${match[1]}/${match[2]}`, userId);
                    if (normalized) imagesToInclude.add(normalized);
                }
            }

            for (const page of pages) {
				if (!page.cover_image) continue;
				if (DEFAULT_COVERS.includes(page.cover_image)) continue;
				const normalized = normalizeUserImageRefForExport(page.cover_image, userId);
				if (normalized) imagesToInclude.add(normalized);
            }

            const storageMap = new Map();
            storages.forEach(stg => storageMap.set(stg.id, stg));

            for (const storage of storages) {
                const storageFolderName = makeSafeZipFolderName({
                    label: storage.name,
                    stableId: storage.id,
                    fallback: 'storage'
                });
                const storageMetadata = {
                    id: storage.id,
                    name: storage.name,
                    sortOrder: storage.sort_order,
                    createdAt: toIsoString(storage.created_at),
                    updatedAt: toIsoString(storage.updated_at),
                    isEncrypted: storage.is_encrypted ? true : false,
                    encryptionSalt: storage.encryption_salt || null,
                    encryptionCheck: storage.encryption_check || null
                };

                appendTrackedBuffer(
                    `workspaces/${storageFolderName}.json`,
                    JSON.stringify(storageMetadata, null, 2)
                );
            }

            let e2eeStatesCount = 0;
            for (const page of pages) {
                const storage = storageMap.get(page.storage_id);
                if (!storage) continue;

                const storageFolderName = makeSafeZipFolderName({
                    label: storage.name,
                    stableId: storage.id,
                    fallback: 'storage'
                });
                const pageFileName = makeSafeZipFileBaseName({
                    label: page.title || 'untitled',
                    stableId: page.id,
                    fallback: 'page'
                });

                const pageData = normalizePageRowForBackupExport(page);

                const html = convertPageToHTML(pageData);
                appendTrackedBuffer(`pages/${storageFolderName}/${pageFileName}.html`, html);

                if (page.e2ee_yjs_state) {
                    try {
                        const buf = Buffer.isBuffer(page.e2ee_yjs_state)
                            ? page.e2ee_yjs_state
                            : Buffer.from(String(page.e2ee_yjs_state), 'utf8');
                        appendTrackedBuffer(`e2ee/${page.id}.bin`, buf);
                        e2eeStatesCount++;
                    } catch (_) {}
                }
            }

            for (const imageRef of imagesToInclude) {
                const parts = imageRef.split('/');
                const ownerId = Number(parts[0]);
                const filename = parts[1];

                const coversRoot = path.join(__dirname, '..', 'covers');
                const imgsRoot = path.join(__dirname, '..', 'imgs');

                const coverPath = resolveSafeUserFilePath(coversRoot, ownerId, filename);
                const imgPath = resolveSafeUserFilePath(imgsRoot, ownerId, filename);

                const finalPath = coverPath || imgPath;
                if (finalPath) {
                    appendTrackedFile(`images/${imageRef}`, finalPath);
                }
            }

            for (const pcRef of paperclipsToInclude) {
                const parts = pcRef.split('/');
                const ownerId = Number(parts[0]);
                const filename = parts[1];

                const pcRoot = path.join(__dirname, '..', 'paperclip');
                const finalPath = resolveSafeUserFilePath(pcRoot, ownerId, filename);
                if (finalPath) {
                    appendTrackedFile(`paperclip/${pcRef}`, finalPath);
                }
            }

            const safeFileRefs = fileRefs
                .map(ref => {
                    const ft = normalizeFileType(ref.file_type);
                    if (!ft) return null;
                    return {
                        page_id: ref.page_id,
                        owner_user_id: ref.owner_user_id,
                        stored_filename: ref.stored_filename,
                        file_type: ft
                    };
                })
                .filter(Boolean);
            appendTrackedBuffer('file-refs.json', JSON.stringify({ fileRefs: safeFileRefs }, null, 2));

            const backupInfo = {
                version: '2.2 (E2EE yjs_state binary support)',
                exportDate: new Date().toISOString(),
                storagesCount: storages.length,
                pagesCount: pages.length,
                e2eeStatesCount,
                imagesCount: imagesToInclude.size,
                paperclipsCount: paperclipsToInclude.size
            };
            appendTrackedBuffer('backup-info.json', JSON.stringify(backupInfo, null, 2));

            const backupManifest = {
                version: 1,
                createdAt: new Date().toISOString(),
                entries: integrityEntries.sort((a, b) => a.name.localeCompare(b.name)),
                encrypted: {
                    storages: storages.map(s => ({
                        id: s.id,
                        isEncrypted: Number(s.is_encrypted) === 1,
                        hasSalt: !!s.encryption_salt,
                        hasCheck: !!s.encryption_check
                    })),
                    e2eePages: pages.filter(p => !!p.e2ee_yjs_state).map(p => p.id)
                }
            };
            const backupManifestRaw = JSON.stringify(backupManifest);
            archive.append(backupManifestRaw, { name: 'backup-manifest.json' });
            archive.append(signBackupManifest(backupManifestRaw, userId), { name: 'backup-manifest.sig' });

            await archive.finalize();
            console.log(`[백업 내보내기] 사용자 ${userId} 완료 (E2EE 상태: ${e2eeStatesCount})`);
        } catch (error) {
            logError('POST /api/backup/export', error);
            if (!res.headersSent) res.status(500).json({ error: '백업 내보내기 실패' });
        }
    });

    function normalizeAssetRefOnImport(src, currentUserId) {
        if (!src || typeof src !== 'string') return null;
        const m = src.match(/^\/(imgs|paperclip|covers)\/(\d+)\/([A-Za-z0-9._-]+)$/);
        if (!m) return src;
        const type = m[1];
        const filename = m[3];
        return `/${type}/${currentUserId}/${filename}`;
    }

    router.post('/import', authMiddleware, csrfMiddleware, requireStrongStepUp({ maxAgeMs: 10 * 60 * 1000, requireMfaIfEnabled: true }), backupImportLimiter, backupUpload.single('backup'), async (req, res) => {
        const userId = req.user.id;
        const uploadedFile = req.file;

        if (req.body.confirm !== 'IMPORT_BACKUP') {
            if (uploadedFile && fs.existsSync(uploadedFile.path)) fs.unlinkSync(uploadedFile.path);
            return res.status(400).json({ error: '가져오기 확인이 필요합니다.' });
        }

        if (!uploadedFile) return res.status(400).json({ error: '파일이 없습니다.' });

        const importLockKey = `backup-import:${userId}`;
        const importLockValue = crypto.randomBytes(16).toString('hex');

        let connection = null;
        let extractDir;
        const stagingFiles = [];
        try {
            if (redis) {
                const locked = await redis.set(importLockKey, importLockValue, { NX: true, PX: 15 * 60 * 1000 });
                if (!locked) return res.status(429).json({ error: '이미 백업 가져오기가 진행 중입니다. 잠시 후 다시 시도하세요.' });
            }

            const importResult = await readBackupZipEntriesForImport(uploadedFile.path);
            const zipEntries = importResult.zipEntries;
            extractDir = importResult.extractDir;

            const manifestEntry = zipEntries.find(e => e.entryName === 'backup-manifest.json');
            const manifestSigEntry = zipEntries.find(e => e.entryName === 'backup-manifest.sig');
            if (!manifestEntry || !manifestSigEntry) throw new Error('서명되지 않은 백업은 가져올 수 없습니다.');

            const manifestRaw = manifestEntry.data ? manifestEntry.data.toString('utf8') : fs.readFileSync(manifestEntry.tempFilePath, 'utf8');
            const manifestSig = manifestSigEntry.data ? manifestSigEntry.data.toString('utf8') : fs.readFileSync(manifestSigEntry.tempFilePath, 'utf8');
            if (!verifyBackupManifest(manifestRaw, manifestSig, userId)) throw new Error('백업 서명 검증 실패: 타인의 백업이거나 신뢰할 수 없는 백업입니다.');

            const manifest = safeJsonParse(manifestRaw, 'backup-manifest.json');
            if (!manifest || !Array.isArray(manifest.entries)) throw new Error('백업 매니페스트 형식이 올바르지 않습니다.');
            if (manifest.entries.length > 1000) throw new Error('백업 매니페스트 항목 수가 너무 많습니다.');

            const zipEntryByName = new Map((zipEntries || []).map(e => [e.entryName, e]));
            for (const item of manifest.entries) {
                const entry = zipEntryByName.get(item.name);
                if (!entry) throw new Error(`백업 무결성 오류: 항목 누락 (${item.name})`);
                const actualHash = await sha256HexFromEntry(entry);
                if (actualHash !== item.sha256) throw new Error(`백업 무결성 오류: 해시 불일치 (${item.name})`);
            }

            const manifestEntriesSet = new Set(manifest.entries.map(e => e.name));
            for (const entry of zipEntries) {
                if (entry.entryName === 'backup-manifest.json' || entry.entryName === 'backup-manifest.sig') continue;
                if (!manifestEntriesSet.has(entry.entryName)) throw new Error(`[보안] 매니페스트에 기재되지 않은 파일이 포함되어 있습니다: ${entry.entryName}`);
            }

            connection = await pool.getConnection();
            await connection.beginTransaction();

            function normalizeBoolean(v) {
                if (v === true || v === false) return v;
                if (v === 1 || v === 0) return Boolean(v);
                if (typeof v === 'string') {
                    const s = v.trim().toLowerCase();
                    if (s === 'true' || s === '1') return true;
                    if (s === 'false' || s === '0') return false;
                }
                return null;
            }

            function normalizeMaybeBase64(v, maxLen = 4096) {
                if (v === null || v === undefined) return null;
                if (typeof v !== 'string') return null;
                const s = v.trim();
                if (!s) return null;
                if (s.length > maxLen) return null;
                if (!/^[A-Za-z0-9+/=_-]+$/.test(s)) return null;
                return s;
            }

            const workspaceMap = new Map();
            const storageEncryptionMetaById = new Map();
            const oldToNewPageMap = new Map();
            const importedPages = [];
            const imgFilenameMap = new Map();
            const coverFilenameMap = new Map();
            const paperclipFilenameMap = new Map();
            const coverImageFilenames = new Set();
            let totalPages = 0;
            let totalImages = 0;

			const MAX_E2EE_STATE_BYTES = (() => {
				const v = Number.parseInt(
					process.env.WS_MAX_YJS_STATE_BYTES || process.env.BACKUP_IMPORT_MAX_E2EE_STATE_BYTES || String(1024 * 1024),
					10
				);
				if (!Number.isFinite(v)) return 1024 * 1024;
				return Math.max(128 * 1024, Math.min(32 * 1024 * 1024, v));
			})();

            const workspaceEntries = zipEntries.filter(e => e.entryName.startsWith('workspaces/') || e.entryName.startsWith('collections/'));

            for (const entry of workspaceEntries) {
                if (entry.isDirectory || !entry.entryName.endsWith('.json')) continue;
                const metadata = safeJsonParse(entry.data.toString('utf8'), entry.entryName);
                if (!metadata) continue;

                const isEncrypted = normalizeBoolean(metadata.isEncrypted ?? metadata.is_encrypted) === true;
                const encryptionSalt = normalizeMaybeBase64(metadata.encryptionSalt ?? metadata.encryption_salt);
                const encryptionCheck = normalizeMaybeBase64(metadata.encryptionCheck ?? metadata.encryption_check, 8192);

                if (isEncrypted && (!encryptionSalt || !encryptionCheck)) {
                    throw new Error('백업에 암호화 저장소 정보가 불완전합니다. (encryptionSalt/encryptionCheck 누락)\n새 버전에서 다시 내보내기 후 가져오기를 진행해주세요.');
                }

                const nowStr = formatDateForDb(new Date());
                const storageId = 'stg-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
                const safeStorageName = normalizeStorageName(metadata?.name);

                await connection.execute(
                    `INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at, is_encrypted, encryption_salt, encryption_check)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        storageId,
                        userId,
                        safeStorageName,
                        metadata.sortOrder || 0,
                        nowStr,
                        nowStr,
                        isEncrypted ? 1 : 0,
                        isEncrypted ? encryptionSalt : null,
                        isEncrypted ? encryptionCheck : null
                    ]
                );

                const folderName = entry.entryName.split('/').pop().replace('.json', '');
                workspaceMap.set(folderName, storageId);
                storageEncryptionMetaById.set(storageId, {
                    isEncrypted,
                    encryptionSalt: isEncrypted ? encryptionSalt : null,
                    encryptionCheck: isEncrypted ? encryptionCheck : null
                });
            }

            if (workspaceMap.size === 0) {
                const folders = new Set();
                zipEntries.forEach(e => {
                    if (e.entryName.startsWith('pages/')) {
                        const parts = e.entryName.split('/');
                        if (parts.length >= 3) folders.add(parts[1]);
                    }
                });
                for (const f of folders) {
                    const storageId = 'stg-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');
                    const safeStorageName = normalizeStorageName(f);
                    await connection.execute(
                        `INSERT INTO storages (id, user_id, name, created_at, updated_at, is_encrypted, encryption_salt, encryption_check)
                         VALUES (?, ?, ?, NOW(), NOW(), 0, NULL, NULL)`,
                        [storageId, userId, safeStorageName]
                    );
                    workspaceMap.set(f, storageId);
                    storageEncryptionMetaById.set(storageId, { isEncrypted: false, encryptionSalt: null, encryptionCheck: null });
                }
            }

            let detectedE2eePagesMissingStorageMeta = false;
            for (const entry of zipEntries) {
                if (entry.isDirectory || !entry.entryName.startsWith('pages/') || !entry.entryName.endsWith('.html')) continue;

                const parts = entry.entryName.split('/');
                const folderName = parts[1];
                const storageId = workspaceMap.get(folderName);
                if (!storageId) continue;

                const html = entry.data
                    ? entry.data.toString('utf8')
                    : fs.readFileSync(entry.tempFilePath, 'utf8');
                const pageData = extractPageFromHTML(html, userId);
                const pageId = generatePageId(new Date());
                const nowStr = formatDateForDb(new Date());

                const oldId = pageData.backupId || `backup-${crypto.createHash('sha256').update(entry.entryName).digest('hex').slice(0, 24)}`;
                oldToNewPageMap.set(String(oldId), { newId: pageId, storageId });
                importedPages.push({ newId: pageId, storageId, parentOldId: pageData.parentId, coverImage: null });

                let coverImage = pageData.coverImage;
                if (coverImage && !DEFAULT_COVERS.includes(coverImage)) {
                    const cParts = coverImage.split('/');
                    if (cParts.length === 2) {
                        coverImageFilenames.add(cParts[1]);
                        coverImage = `${userId}/${cParts[1]}`;
                    }
                }
                importedPages[importedPages.length - 1].coverImage = coverImage;

                const safeTitle = sanitizeInput(pageData.title || '제목 없음').slice(0, 200);
                const safeIcon = validateAndNormalizeIcon(pageData.icon);
                const safeContent = pageData.isEncrypted ? '' : sanitizeHtmlContent(pageData.content || '<p></p>');
                const safeEncryptionSalt = pageData.isEncrypted ? (pageData.encryptionSalt || null) : null;
                const safeEncryptedContent = pageData.isEncrypted ? (pageData.encryptedContent || null) : null;

				const stMeta = storageEncryptionMetaById.get(storageId);
				const isStorageE2ee = Boolean(stMeta?.isEncrypted);
				let e2eeStateBuf = null;
				if (isStorageE2ee && pageData.isEncrypted) {
					const e2eeEntryName = `e2ee/${oldId}.bin`;
					const e2eeEntry = zipEntryByName.get(e2eeEntryName);
					if (e2eeEntry) {
						try {
							const buf = e2eeEntry.data
								? e2eeEntry.data
								: fs.readFileSync(e2eeEntry.tempFilePath);
							if (Buffer.isBuffer(buf) && buf.length > 0 && buf.length <= MAX_E2EE_STATE_BYTES) {
								e2eeStateBuf = buf;
							} else if (Buffer.isBuffer(buf) && buf.length > MAX_E2EE_STATE_BYTES) {
								throw new Error(`E2EE 상태 파일이 너무 큽니다: ${e2eeEntryName}`);
							}
						} catch (e) {
							throw new Error(`E2EE 상태 파일을 읽을 수 없습니다: ${e2eeEntryName} (${e?.message || e})`);
						}
					}
				}

				if (isStorageE2ee && pageData.isEncrypted && !e2eeStateBuf && !safeEncryptedContent) {
					throw new Error('E2EE 페이지 복원 데이터가 불완전합니다. (e2ee state + encryptedContent 모두 누락)\n새 버전에서 다시 내보내기 후 가져오기를 진행해주세요.');
				}

                if (pageData.isEncrypted && !safeEncryptionSalt) {
                    if (!stMeta?.isEncrypted || !stMeta.encryptionSalt || !stMeta.encryptionCheck) {
                        detectedE2eePagesMissingStorageMeta = true;
                    }
                }

                await connection.execute(
                    `INSERT INTO pages (id, user_id, storage_id, title, content, encryption_salt, encrypted_content,
                                       e2ee_yjs_state, e2ee_yjs_state_updated_at,
                                       sort_order, created_at, updated_at, is_encrypted, share_allowed, icon, cover_image, cover_position, parent_id)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
                    [pageId, userId, storageId, safeTitle, safeContent, safeEncryptionSalt, safeEncryptedContent,
                     e2eeStateBuf, e2eeStateBuf ? nowStr : null,
                     pageData.sortOrder || 0, nowStr, nowStr, pageData.isEncrypted ? 1 : 0, pageData.shareAllowed ? 1 : 0, safeIcon, coverImage, pageData.coverPosition || 50]
                );

                totalPages++;
            }

            if (detectedE2eePagesMissingStorageMeta) {
                throw new Error('이 백업은 암호화 저장소(E2EE) 복원에 필요한 정보가 포함되어 있지 않습니다.\n(스토리지 encryptionSalt/encryptionCheck 누락)\n새 버전에서 다시 내보내기 후 가져오기를 진행해주세요.');
            }

            for (const p of importedPages) {
                if (!p.parentOldId) continue;
                const parent = oldToNewPageMap.get(String(p.parentOldId));
                if (!parent) continue;
                if (String(parent.storageId) !== String(p.storageId)) continue;

                await connection.execute(
                    `UPDATE pages SET parent_id = ? WHERE id = ?`,
                    [parent.newId, p.newId]
                );
            }

            const fileRefsEntry = zipEntries.find(e => e.entryName === 'file-refs.json');
            const backupFileRefs = fileRefsEntry ? (safeJsonParse(fileRefsEntry.data.toString('utf8'), 'file-refs.json')?.fileRefs || []) : [];

            let totalPaperclips = 0;
            const stagingDir = path.join(extractDir, 'staging');
            fs.mkdirSync(stagingDir, { recursive: true });

            for (const entry of zipEntries) {
                const isImage = entry.entryName.startsWith('images/');
                const isPaperclip = entry.entryName.startsWith('paperclip/');
                if (entry.isDirectory || (!isImage && !isPaperclip)) continue;

                const assetPath = entry.entryName.substring(isImage ? 7 : 10);
                if (isImage && DEFAULT_COVERS.includes(assetPath)) continue;

                const filename = isImage ? getSafeImageFilenameFromZipPath(assetPath) : getSafePaperclipFilenameFromZipPath(assetPath);
                if (!filename) continue;

                const isCover = isImage && coverImageFilenames.has(filename);
                const subDir = isImage ? (isCover ? 'covers' : 'imgs') : 'paperclip';
                const targetDir = path.join(__dirname, '..', subDir, String(userId));
                if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

                const unique = ensureUniqueDestPath(targetDir, filename);
                if (!unique.fullPath || !unique.filename) continue;

                if (unique.filename !== filename) {
                    if (isImage) {
                        if (isCover) coverFilenameMap.set(filename, unique.filename);
                        else imgFilenameMap.set(filename, unique.filename);
                    } else {
                        paperclipFilenameMap.set(filename, unique.filename);
                    }
                }

                const stagingPath = path.join(stagingDir, `${crypto.randomBytes(12).toString('hex')}-${unique.filename}`);

                const processFile = async (srcPath, destPath, buf) => {
                    if (buf) {
                        if (isImage && !isSupportedImageBuffer(buf, unique.filename)) return false;
                        if (!isImage) {
                            const tp = path.join(tempDir, `v-${crypto.randomBytes(8).toString('hex')}`);
                            try {
                                fs.writeFileSync(tp, buf);
                                await assertSafeAttachmentFile(tp, unique.filename);
                            } catch (e) {
                                return false;
                            } finally {
                                try {
                                    if (fs.existsSync(tp)) fs.unlinkSync(tp);
                                } catch (_) {}
                            }
                        }
                        fs.writeFileSync(destPath, buf);
                    } else {
                        if (isImage) {
                            const fd = fs.openSync(srcPath, 'r');
                            const h = Buffer.alloc(16);
                            const n = fs.readSync(fd, h, 0, 16, 0);
                            fs.closeSync(fd);
                            if (!isSupportedImageBuffer(h.slice(0, n), unique.filename)) return false;
                        } else {
                            try { await assertSafeAttachmentFile(srcPath, unique.filename); } catch (e) { return false; }
                        }
                        fs.copyFileSync(srcPath, destPath);
                    }
                    return true;
                };

                if (await processFile(entry.tempFilePath, stagingPath, entry.data)) {
                    stagingFiles.push({ stagingPath, targetPath: unique.fullPath });
                    if (isImage) totalImages++;
                    else totalPaperclips++;
                }
            }

            let totalStagingSize = 0;
            for (const f of stagingFiles) {
                try { totalStagingSize += fs.statSync(f.stagingPath).size; } catch (_) {}
            }

            const dirs = [
                path.join(__dirname, "..", "paperclip", String(userId)),
                path.join(__dirname, "..", "imgs", String(userId)),
                path.join(__dirname, "..", "covers", String(userId))
            ];
            let currentUsage = 0;
            for (const d of dirs) {
                if (fs.existsSync(d)) {
                    const files = fs.readdirSync(d);
                    for (const f of files) {
                        try { currentUsage += fs.statSync(path.join(d, f)).size; } catch (_) {}
                    }
                }
            }
            const MAX_PAPERCLIP_BYTES_PER_USER = (() => {
                const raw = String(process.env.MAX_PAPERCLIP_BYTES_PER_USER || '').trim().toLowerCase();
                if (!raw) return 1024 * 1024 * 1024;
                const m = raw.match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/);
                if (!m) return 1024 * 1024 * 1024;
                const n = Number(m[1]);
                const unit = m[2] || 'b';
                const mul = unit === 'gb' ? 1024**3 : unit === 'mb' ? 1024**2 : unit === 'kb' ? 1024 : 1;
                return Math.max(50 * 1024 * 1024, Math.min(20 * 1024**3, Math.floor(n * mul)));
            })();
            if (currentUsage + totalStagingSize > MAX_PAPERCLIP_BYTES_PER_USER) {
                throw new Error('UPLOAD_QUOTA_EXCEEDED');
            }

            for (const ref of backupFileRefs) {
                const mapping = oldToNewPageMap.get(String(ref.page_id));
                if (!mapping) continue;

                const ft = normalizeFileType(ref.file_type);
                if (!ft) continue;

                let stored = String(ref.stored_filename || '');
                if (!stored) continue;
                if (ft === FILE_TYPE.PAPERCLIP) stored = paperclipFilenameMap.get(stored) || stored;
                else if (ft === FILE_TYPE.IMGS) stored = imgFilenameMap.get(stored) || coverFilenameMap.get(stored) || stored;

                await connection.execute(
                    `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
                     VALUES (?, ?, ?, ?, NOW())`,
                    [mapping.newId, userId, stored, ft]
                );
            }

            for (const p of importedPages) {
                const [row] = await connection.execute('SELECT content, is_encrypted FROM pages WHERE id = ?', [p.newId]);
                if (!row.length || row[0].is_encrypted || !row[0].content) continue;

                let content = row[0].content;
                const dom = new JSDOM(content);
                const doc = dom.window.document;
                const elements = doc.querySelectorAll('[src], [data-src], [data-url], [data-thumbnail], [data-favicon]');
                let modified = false;
                for (const el of elements) {
                    for (const attr of ['src', 'data-src', 'data-url', 'data-thumbnail', 'data-favicon']) {
                        if (el.hasAttribute(attr)) {
                            const val = el.getAttribute(attr);
                            const normalized = normalizeAssetRefOnImport(val, userId);
                            if (normalized && normalized !== val) {
                                el.setAttribute(attr, normalized);
                                modified = true;
                            }
                        }
                    }
                }

                for (const [oldName, newName] of imgFilenameMap.entries()) {
                    const oldP = `/imgs/${userId}/${escapeRegExp(oldName)}`;
                    const newP = `/imgs/${userId}/${newName}`;
                    const targetEls = doc.querySelectorAll(`[src^="${oldP}"], [data-src^="${oldP}"], [data-url^="${oldP}"]`);
                    for (const el of targetEls) {
                        for (const attr of ['src', 'data-src', 'data-url']) {
                            if (el.getAttribute(attr) === oldP) {
                                el.setAttribute(attr, newP);
                                modified = true;
                            }
                        }
                    }
                }

                if (modified) await connection.execute('UPDATE pages SET content = ? WHERE id = ?', [doc.body.innerHTML, p.newId]);

                try {
                    if (p.coverImage && typeof p.coverImage === 'string') {
                        const parts = p.coverImage.split('/');
                        if (parts.length === 2 && String(parts[0]) === String(userId)) {
                            const oldFn = parts[1];
                            const newFn = coverFilenameMap.get(oldFn);
                            if (newFn) {
                                const newCover = `${userId}/${newFn}`;
                                await connection.execute('UPDATE pages SET cover_image = ? WHERE id = ?', [newCover, p.newId]);
                                p.coverImage = newCover;
                            }
                        }
                    }
                } catch (_) {}
            }

const finalizedTargets = [];
try {
    for (const f of stagingFiles) {
        try {
            fs.renameSync(f.stagingPath, f.targetPath);
        } catch (e) {
            fs.copyFileSync(f.stagingPath, f.targetPath);
            fs.unlinkSync(f.stagingPath);
        }
        finalizedTargets.push(f.targetPath);
    }

    await connection.commit();
} catch (finalizeError) {
    try { await connection.rollback(); } catch (_) {}
    for (const targetPath of finalizedTargets.reverse()) {
        try {
            if (fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
        } catch (_) {}
    }
    throw finalizeError;
}

            if (uploadedFile && fs.existsSync(uploadedFile.path)) fs.unlinkSync(uploadedFile.path);
            res.json({
                ok: true,
                storagesCount: workspaceMap.size,
                pagesCount: totalPages,
                imagesCount: totalImages,
                paperclipsCount: totalPaperclips
            });
        } catch (error) {
            const incidentId = crypto.randomBytes(4).toString("hex").toUpperCase();
            logError(`[IMPORT_ERROR] [${incidentId}]`, error);
            if (connection) await connection.rollback();
            for (const f of stagingFiles) {
                try { if (fs.existsSync(f.stagingPath)) fs.unlinkSync(f.stagingPath); } catch (_) {}
            }
            if (uploadedFile && fs.existsSync(uploadedFile.path)) fs.unlinkSync(uploadedFile.path);
            if (String(error?.message) === "UPLOAD_QUOTA_EXCEEDED") return res.status(413).json({ error: "업로드 용량 제한을 초과했습니다.", incidentId });
            res.status(500).json({ error: "백업을 가져오는 중 오류가 발생했습니다.", incidentId });
        } finally {
            if (redis) {
                try {
                    await redis.eval(
                        `if redis.call("GET", KEYS[1]) == ARGV[1]
                          then return redis.call("DEL", KEYS[1])
                          else return 0
                         end`,
                        { keys: [importLockKey], arguments: [importLockValue] }
                    );
                } catch (_) {}
            }
            if (connection) connection.release();
            try { if (typeof extractDir === 'string') fs.rmSync(extractDir, { recursive: true, force: true }); } catch (_) {}
        }
    });

    function sanitizeZipPathSegment(raw, { fallback = 'item', maxLen = 80 } = {}) {
        const s0 = String(raw ?? '').normalize('NFKC');

        let s = s0.replace(/[\u0000-\u001F\u007F]/g, '');

        s = s.replace(/[\\/\u2215\u2044\u29F8\uFF0F\uFF3C]/g, '_');

        s = s.replace(/[<>:"|?*]/g, '_');

        s = s.trim().replace(/\s+/g, ' ');

        s = s.replace(/[ .]+$/g, '');

        if (!s || /^\.+$/.test(s) || s === '.' || s === '..')
            s = fallback;

        if (s.length > maxLen)
            s = s.slice(0, maxLen);

        s = s.replace(/(^|\s)\.\.(\s|$)/g, '_');

        return s || fallback;
    }

    function makeSafeZipFolderName({ label, stableId, fallback }) {
        const base = sanitizeZipPathSegment(label, { fallback, maxLen: 48 });
        const id = sanitizeZipPathSegment(String(stableId || ''), { fallback: 'id', maxLen: 32 });
        return `${base}-${id}`;
    }

    function makeSafeZipFileBaseName({ label, stableId, fallback }) {
        const base = sanitizeZipPathSegment(label, { fallback, maxLen: 64 });
        const id = sanitizeZipPathSegment(String(stableId || ''), { fallback: 'id', maxLen: 24 });
        return `${base}-${id}`;
    }

    return router;
};
