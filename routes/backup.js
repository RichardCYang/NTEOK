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

const MAX_BACKUP_ZIP_BYTES = 20 * 1024 * 1024;        	
const MAX_ZIP_ENTRIES = 2000;                         	
const MAX_ENTRY_UNCOMPRESSED_BYTES = 10 * 1024 * 1024;	
const MAX_TOTAL_UNCOMPRESSED_BYTES = 200 * 1024 * 1024; 
const MAX_SUSPICIOUS_RATIO = 2000;                    	
const MIN_RATIO_ENTRY_BYTES = 1 * 1024 * 1024;        	

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

const backupImportLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 2, 
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => String(req.user?.id || ipKeyGenerator(req)),
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
        backupRepo,
		flushAllPendingE2eeSaves,
        authMiddleware,
        toIsoString,
        sanitizeInput,
		sanitizeHtmlContent,
        generatePublishToken,
        generatePageId,
        formatDateForDb,
        logError
	} = dependencies;

    const wsConnections = dependencies.wsConnections;
    const yjsDocuments = dependencies.yjsDocuments;
    const saveYjsDocToDatabase = dependencies.saveYjsDocToDatabase;
    const enqueueYjsDbSave = dependencies.enqueueYjsDbSave;
    const flushAllPendingYjsDbSaves = dependencies.flushAllPendingYjsDbSaves;

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    const KEEP_IMPORT_PUBLISH_TOKENS = String(process.env.KEEP_IMPORT_PUBLISH_TOKENS || '').toLowerCase() === 'true';
    if (KEEP_IMPORT_PUBLISH_TOKENS) console.warn('[security] KEEP_IMPORT_PUBLISH_TOKENS is deprecated and ignored. Imported pages now start unpublished.');

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

    function isValidPublishToken(token) {
        return typeof token === 'string' && /^[a-f0-9]{64}$/i.test(token);
    }

    async function insertPublishLinkWithRetry(connection, { token, pageId, ownerUserId, createdAt, updatedAt, allowComments = 0, isActive = 0 }) {
        let t = token;
        for (let i = 0; i < 5; i++) {
            try {
                await connection.execute(
                    `INSERT INTO page_publish_links (token, page_id, owner_user_id, is_active, created_at, updated_at, allow_comments)
                     VALUES (?, ?, ?, ?, ?, ?, ?)` ,
                    [t, pageId, ownerUserId, isActive ? 1 : 0, createdAt, updatedAt, allowComments]
                );
                return t;
            } catch (e) {
                if (e && (e.code === 'ER_DUP_ENTRY' || e.errno === 1062)) {
                    t = generatePublishToken();
                    continue;
                }
                throw e;
            }
        }
        throw new Error('PUBLISH_TOKEN_INSERT_RETRY_EXCEEDED');
    }

    const DEFAULT_COVERS = [
        'default/img1.png',
        'default/img2.png',
        'default/img3.png',
        'default/img4.png',
        'default/img5.png',
        'default/img6.png'
	];

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
						if (entryCount > Math.min(BACKUP_IMPORT_MAX_ENTRIES, MAX_ZIP_ENTRIES)) {
							throw new Error(`[보안] 백업 ZIP 엔트리 수가 너무 많습니다. (최대 ${Math.min(BACKUP_IMPORT_MAX_ENTRIES, MAX_ZIP_ENTRIES)}개)`);
						}

						const entryName = String(entry.fileName || '');
						if (!entryName) throw new Error('[보안] ZIP 엔트리 이름이 비어 있습니다.');

						if (entryName.includes('\\') || entryName.includes('\0')) {
							throw new Error('[보안] ZIP 엔트리 경로 형식이 유효하지 않습니다.');
						}

						if (path.isAbsolute(entryName) || entryName.split('/').some(seg => seg === '..' || seg === '.')) {
							throw new Error('[보안] ZIP 엔트리 경로 조작이 감지되었습니다.');
						}

						if (entryName.endsWith('/')) {
							zipfile.readEntry();
							return;
						}

						const allowed = allowedTopLevel.some(prefix => entryName === prefix || entryName.startsWith(prefix));
						if (!allowed) {
							zipfile.readEntry();
							return;
						}

						const uncompressed = Number(entry.uncompressedSize || 0);
						const compressed = Number(entry.compressedSize || 0);
						if (!Number.isFinite(uncompressed) || uncompressed < 0) {
							throw new Error('[보안] ZIP 엔트리 크기 정보를 확인할 수 없습니다.');
						}

						if (uncompressed > BACKUP_IMPORT_MAX_ENTRY_UNCOMPRESSED) {
							throw new Error('[보안] 백업 파일 내 일부 항목이 너무 큽니다.');
						}

						totalHeaderUncompressed += uncompressed;
						if (totalHeaderUncompressed > BACKUP_IMPORT_MAX_TOTAL_UNCOMPRESSED) {
							throw new Error('[보안] 백업 파일의 전체 해제 용량이 너무 큽니다.');
						}

						if (compressed > 0 && uncompressed >= MIN_RATIO_ENTRY_BYTES) {
							const ratio = uncompressed / compressed;
							if (ratio > MAX_SUSPICIOUS_RATIO) {
								throw new Error('[보안] 압축 비율이 비정상적으로 높아 Zip Bomb 의심으로 차단했습니다.');
							}
						}

						const perEntryLimitBytes = Math.min(BACKUP_IMPORT_MAX_ENTRY_UNCOMPRESSED, MAX_ENTRY_UNCOMPRESSED_BYTES);
						const forceToDisk = entryName.startsWith('pages/') || entryName.startsWith('images/') || entryName.startsWith('e2ee/');
						const canBuffer = !forceToDisk && Number(entry.uncompressedSize || 0) <= MAX_ENTRY_BUFFER_BYTES;

						const stream = await openZipReadStream(zipfile, entry);

						if (canBuffer) {
							const buf = await readStreamToBufferWithLimits(stream, {
								perEntryLimitBytes,
								getTotalBytes,
								addTotalBytes,
								context: entryName
							});
							zipEntries.push({ entryName, isDirectory: false, data: buf });
						} else {
							const outPath = entryTempPath(extractDir, entryName);
							await readStreamToTempFileWithLimits(stream, {
								outPath,
								perEntryLimitBytes,
								getTotalBytes,
								addTotalBytes,
								context: entryName
							});
							zipEntries.push({ entryName, isDirectory: false, tempFilePath: outPath });
						}
						zipfile.readEntry();
					} catch (e) {
						fail(e);
					}
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

    function normalizePageRowForBackupExport(pageRow, publishInfo) {
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
            updatedAt: toIsoString(pageRow.updated_at) || pageRow.updated_at,

            wasPublished: Boolean(publishInfo?.token),
            publishedAt: publishInfo?.createdAt || null,
            allowComments: publishInfo?.allowComments || 0
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
            wasPublished: pageData.wasPublished === true,
            publishedAt: pageData.publishedAt || null,
            allowComments: pageData.allowComments || 0,
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

    function extractPageFromHTML(html) {
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
                        console.log('[메타데이터 파싱 성공]', {
                            coverImage: metadata?.coverImage,
                            isCoverImage: metadata?.isCoverImage
                        });
                    } else if (metadataText) {
                        console.warn('[메타데이터 파싱 거부]: 데이터가 너무 큽니다.');
                    }
                } catch (e) {
                    console.warn('[메타데이터 파싱 실패]:', e.message, 'Content:', metadataScript.textContent?.substring(0, 200));
                }
            } else {
                console.warn('[메타데이터 스크립트 없음]');
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

            const content = contentEl ? contentEl.innerHTML : '<p></p>';

            const coverImageEl = doc.querySelector('.cover-image');
            let coverImage = null;
            if (coverImageEl) {
                const src = coverImageEl.getAttribute('src');
                if (src) {
                    const match = src.match(/\.\.\/images\/(.+)/);
                    if (match) {
                        coverImage = match[1];
                    }
                }
            }

            const metaParentRaw = metadata?.parentId ?? metadata?.parent_id ?? null;
            const metaParentId = (typeof metaParentRaw === 'string' && metaParentRaw.trim()) ? metaParentRaw.trim() : null;

            const metaIsEncrypted = normalizeBackupBoolean(metadata?.isEncrypted ?? metadata?.is_encrypted, false);
            const metaShareAllowed = normalizeBackupBoolean(metadata?.shareAllowed ?? metadata?.share_allowed, false);

            return {
                backupId: (typeof metadata?.id === 'string' && metadata.id.trim()) ? metadata.id.trim() : null,
                parentId: metaParentId,
                title,
                content,
                icon: icon || (metadata?.icon) || null,
                isEncrypted: metaIsEncrypted,
                encryptionSalt: (metadata?.encryptionSalt ?? metadata?.encryption_salt) || null,
                encryptedContent: (metadata?.encryptedContent ?? metadata?.encrypted_content) || null,
                shareAllowed: metaShareAllowed,
                coverImage: coverImage || metadata?.coverImage || null,
                coverPosition: metadata?.coverPosition || 50,
                sortOrder: metadata?.sortOrder || 0,
                publishToken: metadata?.publishToken || null,
                wasPublished: normalizeBackupBoolean(
                    metadata?.wasPublished,
                    Boolean(metadata?.publishToken)
                ),
                publishedAt: metadata?.publishedAt || null,
                allowComments: metadata?.allowComments || 0,
                isCoverImage: metadata?.isCoverImage || false
            };
        } catch (error) {
            console.error('HTML 파싱 오류:', error);
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
                publishToken: null,
                publishedAt: null,
                allowComments: 0,
                isCoverImage: false
            };
        }
    }

    router.get('/export', authMiddleware, async (req, res) => {
        const userId = req.user.id;

        try {
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
                                c.ws.send(JSON.stringify({
                                    event: 'request-page-snapshot',
                                    data: { pageId: String(pid) }
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

			const { storages, pages, publishes } = await backupRepo.getExportRows(userId);

            if (!storages || storages.length === 0)
                return res.status(404).json({ error: '내보낼 데이터가 없습니다.' });

            const publishMap = new Map();

			(publishes || []).forEach(pub => {
				publishMap.set(pub.page_id, {
					token: pub.token,
					createdAt: toIsoString(pub.created_at),
					allowComments: pub.allow_comments || 0
				});
			});

            const archive = archiver('zip', {
                zlib: { level: 9 } 
            });

            res.attachment('nteok-backup.zip');
            res.type('application/zip');

            archive.on('error', (err) => {
                console.error('ZIP 생성 오류:', err);
                res.status(500).json({ error: 'ZIP 생성 실패' });
            });

            archive.pipe(res);

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

                archive.append(
                    JSON.stringify(storageMetadata, null, 2),
                    { name: `workspaces/${storageFolderName}.json` }
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

                const publishInfo = publishMap.get(page.id);
                const pageData = normalizePageRowForBackupExport(page, publishInfo);

                const html = convertPageToHTML(pageData);
                archive.append(html, { name: `pages/${storageFolderName}/${pageFileName}.html` });

                if (page.e2ee_yjs_state) {
                    try {
                        const buf = Buffer.isBuffer(page.e2ee_yjs_state)
                            ? page.e2ee_yjs_state
                            : Buffer.from(String(page.e2ee_yjs_state), 'utf8');
                        archive.append(buf, { name: `e2ee/${page.id}.bin` });
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
                    archive.file(finalPath, { name: `images/${imageRef}` });
                }
            }

            for (const pcRef of paperclipsToInclude) {
                const parts = pcRef.split('/');
                const ownerId = Number(parts[0]);
                const filename = parts[1];

                const pcRoot = path.join(__dirname, '..', 'paperclip');
                const finalPath = resolveSafeUserFilePath(pcRoot, ownerId, filename);
                if (finalPath) {
                    archive.file(finalPath, { name: `paperclip/${pcRef}` });
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
            archive.append(JSON.stringify({ fileRefs: safeFileRefs }, null, 2), { name: 'file-refs.json' });

            const backupInfo = {
                version: '2.2 (E2EE yjs_state binary support)',
                exportDate: new Date().toISOString(),
                storagesCount: storages.length,
                pagesCount: pages.length,
                e2eeStatesCount,
                imagesCount: imagesToInclude.size,
                paperclipsCount: paperclipsToInclude.size
            };
            archive.append(JSON.stringify(backupInfo, null, 2), { name: 'backup-info.json' });

            await archive.finalize();
            console.log(`[백업 내보내기] 사용자 ${userId} 완료 (E2EE 상태: ${e2eeStatesCount})`);
        } catch (error) {
            logError('GET /api/backup/export', error);
            if (!res.headersSent) res.status(500).json({ error: '백업 내보내기 실패' });
        }
    });

    router.post('/import', authMiddleware, backupImportLimiter, backupUpload.single('backup'), async (req, res) => {
        const userId = req.user.id;
        const uploadedFile = req.file;

        if (!uploadedFile) return res.status(400).json({ error: '파일이 없습니다.' });

        let connection;
        let extractDir;
        try {
            const importResult = await readBackupZipEntriesForImport(uploadedFile.path);
            const zipEntries = importResult.zipEntries;
            extractDir = importResult.extractDir;

			const zipEntryByName = new Map((zipEntries || []).map(e => [e.entryName, e]));

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
            let skippedPublishedLinks = 0;
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
                const pageData = extractPageFromHTML(html);
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

                if (pageData.publishToken || pageData.wasPublished) skippedPublishedLinks++;

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

                const targetPath = unique.fullPath;

                const processFile = (srcPath, destPath, buf) => {
                    if (buf) {
                        if (isImage && !isSupportedImageBuffer(buf, unique.filename)) return false;
                        if (!isImage) {
                            try {
                                const tp = path.join(tempDir, `v-${crypto.randomBytes(8).toString('hex')}`);
                                fs.writeFileSync(tp, buf);
                                assertSafeAttachmentFile(tp, unique.filename);
                                fs.unlinkSync(tp);
                            } catch (e) { return false; }
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
                            try { assertSafeAttachmentFile(srcPath, unique.filename); } catch (e) { return false; }
                        }
                        try { fs.renameSync(srcPath, destPath); } catch (e) {
                            fs.copyFileSync(srcPath, destPath);
                            fs.unlinkSync(srcPath);
                        }
                    }
                    return true;
                };

                if (processFile(entry.tempFilePath, targetPath, entry.data)) {
                    if (isImage) totalImages++;
                    else totalPaperclips++;
                }
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
                const oldUserIdPattern = /\/(imgs|paperclip|covers)\/(\d+)\//g;
                let newContent = content.replace(oldUserIdPattern, `/$1/${userId}/`);

                for (const [oldName, newName] of imgFilenameMap.entries()) {
                    newContent = newContent.replace(new RegExp(`/imgs/${userId}/${escapeRegExp(oldName)}`, 'g'), `/imgs/${userId}/${newName}`);
                }

                for (const [oldName, newName] of paperclipFilenameMap.entries()) {
                    newContent = newContent.replace(new RegExp(`/paperclip/${userId}/${escapeRegExp(oldName)}`, 'g'), `/paperclip/${userId}/${newName}`);
                }

                for (const [oldName, newName] of coverFilenameMap.entries()) {
                    newContent = newContent.replace(new RegExp(`/covers/${userId}/${escapeRegExp(oldName)}`, 'g'), `/covers/${userId}/${newName}`);
                }

                if (newContent !== content) {
                    await connection.execute('UPDATE pages SET content = ? WHERE id = ?', [newContent, p.newId]);
                }

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

            await connection.commit();
            fs.unlinkSync(uploadedFile.path);
            res.json({
                ok: true,
                storagesCount: workspaceMap.size,
                pagesCount: totalPages,
                imagesCount: totalImages,
                paperclipsCount: totalPaperclips,
                skippedPublishedLinks
            });
        } catch (error) {
            const incidentId = crypto.randomBytes(4).toString("hex").toUpperCase();
            logError(`[IMPORT_ERROR] [${incidentId}]`, error);
            if (connection) await connection.rollback();
            if (uploadedFile && fs.existsSync(uploadedFile.path)) fs.unlinkSync(uploadedFile.path);
            res.status(500).json({ error: "백업을 가져오는 중 오류가 발생했습니다.", incidentId });
        } finally {
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
