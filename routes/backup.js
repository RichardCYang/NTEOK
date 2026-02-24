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

/**
 * 보안: 안전한 JSON 파서 -> 백업 ZIP/HTML 내부의 JSON은 신뢰할 수 없는 입력
 * - __proto__/constructor/prototype 키는 프로토타입 오염(Prototype Pollution)의 대표적인 트리거
 * - JSON.parse 결과를 다른 객체와 병합(Object.assign/spread/merge)하거나, 일부 라이브러리가
 *   내부적으로 merge를 수행할 때 예기치 않은 동작/DoS/권한 우회로 이어질 수 있음
 *
 * 참고:
 * - OWASP Prototype Pollution Prevention Cheat Sheet
 * - CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes)
 */
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
    // reviver 단계에서 위험 키를 제거(가능한 한 빨리 제거)
    // 혹시 남아있을 수 있는 구조를 방어적으로 재귀 삭제
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

/**
 * Backup Routes
 *
 * 이 파일은 백업 관련 라우트를 처리합니다.
 * - 백업 내보내기 (ZIP)
 * - 백업 불러오기 (ZIP)
 */

// 백업 파일 업로드 설정
// temp 폴더를 미리 생성
const tempDir = 'temp';
if (!fs.existsSync(tempDir)) {
    fs.mkdirSync(tempDir, { recursive: true });
}

// 보안: ZIP Bomb / Decompression Bomb 방어용 제한값
// OWASP 권고: 압축 해제 후 크기 및 내부 파일 수 제한 필요
// - File Upload Cheat Sheet: 압축파일 처리 시 압축 해제 후 크기 고려 필요
// - ASVS 논의: 최대 uncompressed size + 최대 files inside container 권고
const MAX_BACKUP_ZIP_BYTES = 20 * 1024 * 1024;        	// 업로드 ZIP 자체 크기: 20MB
const MAX_ZIP_ENTRIES = 2000;                         	// ZIP 내부 파일 개수 제한
const MAX_ENTRY_UNCOMPRESSED_BYTES = 10 * 1024 * 1024;	// 엔트리 1개 압축해제 최대: 10MB
const MAX_TOTAL_UNCOMPRESSED_BYTES = 200 * 1024 * 1024; // 전체 압축해제 최대: 200MB
const MAX_SUSPICIOUS_RATIO = 2000;                    	// (선택) 초고압축 비율 의심 기준
const MIN_RATIO_ENTRY_BYTES = 1 * 1024 * 1024;        	// ratio 검사 적용 최소 크기(1MB 이상)

// 메모리 DoS 방지: 이 크기 이하 + pages/images/ 아닌 경우만 Buffer로 보관, 그 외는 디스크 스풀
const MAX_ENTRY_BUFFER_BYTES = 256 * 1024; // 256KB

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
            // 파일명에 타임스탐프 추가로 중복 방지
            const uniqueSuffix = Date.now() + '-' + crypto.randomBytes(6).toString('hex');
            cb(null, 'backup-' + uniqueSuffix + '.zip');
        }
    }),
    limits: {
        fileSize: MAX_BACKUP_ZIP_BYTES
    },
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/zip' || file.originalname.endsWith('.zip')) {
            cb(null, true);
        } else {
            cb(new Error('ZIP 파일만 업로드 가능합니다.'));
        }
    }
});

// 백업 import 전용 레이트리밋 — DoS 반복 공격 비용 상승
// authMiddleware 뒤에 배치하므로 req.user?.id 기준으로 사용자 구분
const backupImportLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 2, // 1분에 2회: 정상 UX 유지 + 반복 공격 억제
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => String(req.user?.id || ipKeyGenerator(req)),
});

// import 세션별 임시 디렉터리 생성 (mode 0o700: 소유자만 접근)
function createImportTempDir() {
    const dir = path.join(tempDir, `import-extract-${Date.now()}-${crypto.randomBytes(6).toString('hex')}`);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    return dir;
}

// ZIP 엔트리 이름을 해시하여 안전한 임시 파일 경로 반환 (경로 조작 원천 차단)
function entryTempPath(extractDir, entryName) {
    const h = crypto.createHash('sha256').update(entryName).digest('hex').slice(0, 32);
    return path.join(extractDir, h);
}

// 스트림 압축 해제 중 크기 제한을 적용하는 Transform 생성
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

// 스트림을 임시 파일로 저장 (메모리 적재 없이 디스크 스풀)
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
        authMiddleware,
        toIsoString,
        sanitizeInput,
		sanitizeHtmlContent,
        generatePublishToken,
        generatePageId,
        formatDateForDb,
        logError
	} = dependencies;

    /**
     * 보안: 백업 가져오기(import)에서 발행(공개 공유) 토큰을 그대로 복원하면 신뢰할 수 없는
     * 백업 파일(또는 변조된 백업)을 가져오는 순간 공격자가 알고 있는 토큰으로 페이지가 즉시 공개되어 내용이 유출될 수 있음
     *
     * 기본 동작: import 시 기존 토큰을 무시하고 새 토큰을 재발급하여 복원
     * (기능 호환이 필요한 경우에만 환경변수로 opt-in)
     *   - KEEP_IMPORT_PUBLISH_TOKENS=true : 백업에 포함된 토큰을 그대로 유지(신뢰된 백업 전제)
     */
    const KEEP_IMPORT_PUBLISH_TOKENS = String(process.env.KEEP_IMPORT_PUBLISH_TOKENS || '').toLowerCase() === 'true';

    /**
     * 보안: 저장소 이름(워크스페이스/컬렉션 이름) 정규화
     * - backup import는 외부에서 가져오는 신뢰 불가 입력이므로 반드시 서버에서 검증해야 함
     * - 목표: Stored XSS 및 UI 템플릿/DOM 주입 취약점의 우회 경로 차단
     */
    function normalizeStorageName(rawName) {
        // 기본 타입/trim
        if (typeof rawName !== 'string') rawName = '';
        let name = rawName.trim();

        // 제어문자 제거 (로그/헤더/렌더링 혼란 방지)
        name = name.replace(/[\u0000-\u001F\u007F]/g, '');

        // 너무 길면 자르기 (DB/렌더링 보호)
        if (name.length > 100) name = name.slice(0, 100);

        // XSS 위험 문자를 원천 차단 (정책은 프로젝트 전체와 동일하게 유지 권장)
        //    - sanitizeInput은 태그 제거 중심이므로 여기서는 추가로 위험 기호를 막아 정책을 확실히 함
        //    - (원한다면 아래 정규식 정책을 storages 생성/수정 API와 동일하게 맞추는 것이 최선)
        if (/[<>&"'`]/.test(name)) {
            // 태그/엔티티/속성 기반 공격을 원천 차단
            name = name.replace(/[<>&"'`]/g, '');
        }

        // 최종적으로 비어 있으면 안전한 기본값
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
                // 토큰 충돌(중복 키) 발생 시 재생성
                if (e && (e.code === 'ER_DUP_ENTRY' || e.errno === 1062)) {
                    t = generatePublishToken();
                    continue;
                }
                throw e;
            }
        }
        throw new Error('PUBLISH_TOKEN_INSERT_RETRY_EXCEEDED');
    }

    /**
     * 기본 커버 이미지 목록
     */
    const DEFAULT_COVERS = [
        'default/img1.png',
        'default/img2.png',
        'default/img3.png',
        'default/img4.png',
        'default/img5.png',
        'default/img6.png'
	];

   	/**
     * 보안: 백업 내보내기 하드닝 (경로 순회 / 임의 파일 포함 방지)
     * 백업 내보내기(export)는 pages.content에서 /imgs/... 패턴을 수집해 서버 파일을 ZIP에 포함시키는 구조
     * 이때 ../ 등 경로 조작이 허용되면 임의 서버 파일을 백업 ZIP으로 유출할 수 있음
     * 따라서 내보내기 시 포함 가능한 파일을 아래로 강하게 제한:
     * - 현재 사용자(userId) 디렉토리 아래에 있는 파일만
     * - 허용된 이미지 확장자만
     * - 심볼릭 링크 차단
     */
    const EXPORT_ALLOWED_IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

    function normalizeUserImageRefForExport(raw, userId) {
        if (typeof raw !== "string") return null;

        // Windows 구분자 등 정규화
        const s = raw.replace(/\\/g, "/").trim();
        if (!s) return null;

        // 경로 조작/이상치 차단
        if (s.includes(String.fromCharCode(0)) || s.includes("..")) return null;
        if (s.startsWith("/") || s.startsWith("~")) return null;

        // "<userId>/<filename.ext>" 1-세그먼트만 허용
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

        // 경로 순회 방지 (루트 디렉토리 이탈 금지)
        if (!resolved.startsWith(resolvedBase)) return null;

        try {
            const st = fs.lstatSync(resolved);
            // 심볼릭 링크/디렉토리 등은 포함 금지
            if (!st.isFile() || st.isSymbolicLink()) return null;
        } catch (e) {
            return null;
        }

        return resolved;
    }

	/**
	* 백업 Import 보안 하드닝
	* - ZIP Bomb / 리소스 고갈 방지 (엔트리 수/총 해제 용량/개별 해제 용량 제한)
	* - 허용된 파일/이미지 타입만 처리
	*/
	const BACKUP_IMPORT_MAX_ENTRIES = Number(process.env.BACKUP_IMPORT_MAX_ENTRIES || 5000);
	const BACKUP_IMPORT_MAX_TOTAL_UNCOMPRESSED = Number(process.env.BACKUP_IMPORT_MAX_TOTAL_UNCOMPRESSED || (300 * 1024 * 1024)); // 300MB
	const BACKUP_IMPORT_MAX_ENTRY_UNCOMPRESSED = Number(process.env.BACKUP_IMPORT_MAX_ENTRY_UNCOMPRESSED || (20 * 1024 * 1024)); // 20MB

	const ALLOWED_IMAGE_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp"]);

	async function readBackupZipEntriesForImport(zipPath) {
		const zipfile = await openZipFile(zipPath);
		const zipEntries = [];
		// 큰 엔트리(pages/, images/)를 메모리 대신 디스크에 스풀하기 위한 임시 디렉터리
		const extractDir = createImportTempDir();

		const allowedTopLevel = ['backup-info.json', 'workspaces/', 'collections/', 'pages/', 'images/'];

		let entryCount = 0;
		let totalHeaderUncompressed = 0;
		let totalBytesRead = 0;
		const getTotalBytes = () => totalBytesRead;
		const addTotalBytes = (n) => { totalBytesRead += n; };

		return await new Promise((resolve, reject) => {
			function fail(err) {
				try { zipfile.close(); } catch (_) { }
				// 실패 시 임시 디렉터리 즉시 정리
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

						// 경로 조작/이상 경로 차단
						if (entryName.includes('\\') || entryName.includes('\0')) {
							throw new Error('[보안] ZIP 엔트리 경로 형식이 유효하지 않습니다.');
						}

						// '..'는 경로 세그먼트로만 차단(파일명에 포함된 '..'는 허용)
						if (path.isAbsolute(entryName) || entryName.split('/').some(seg => seg === '..' || seg === '.')) {
							throw new Error('[보안] ZIP 엔트리 경로 조작이 감지되었습니다.');
						}

						// 디렉토리는 skip
						if (entryName.endsWith('/')) {
							zipfile.readEntry();
							return;
						}

						// 허용된 최상위 경로만 처리 (그 외는 해제하지 않고 무시)
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

						// (선택) 초고압축 비율 감지
						if (compressed > 0 && uncompressed >= MIN_RATIO_ENTRY_BYTES) {
							const ratio = uncompressed / compressed;
							if (ratio > MAX_SUSPICIOUS_RATIO) {
								throw new Error('[보안] 압축 비율이 비정상적으로 높아 Zip Bomb 의심으로 차단했습니다.');
							}
						}

						const perEntryLimitBytes = Math.min(BACKUP_IMPORT_MAX_ENTRY_UNCOMPRESSED, MAX_ENTRY_UNCOMPRESSED_BYTES);
						// pages/, images/ 엔트리 또는 큰 파일은 디스크로 스풀 (메모리 DoS 방지)
						const forceToDisk = entryName.startsWith('pages/') || entryName.startsWith('images/');
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

    /**
     * 보안(Zip Slip 방지): ZIP 엔트리에서 나온 파일명은 절대 신뢰하면 안 됨
     * - 확장자만 체크하면 Windows 백슬래시(\) 경로 구분자를 이용한 탈출 가능성이 생길 수 있음
     */
    const IMAGE_FILENAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.(?:png|jpe?g|gif|webp)$/i;
    const WINDOWS_RESERVED = new Set([
        "CON","PRN","AUX","NUL",
        "COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
        "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9",
    ]);

    function getSafeImageFilenameFromZipPath(maybePath) {
        if (typeof maybePath !== "string") return null;
        // 백슬래시를 슬래시로 정규화(Windows 경로 구분자 우회 차단)
        const normalized = maybePath.replace(/\\/g, "/").trim();
        if (!normalized) return null;

        const base = normalized.split("/").pop();
        if (!base) return null;
        // 제어문자/경로문자/상위이동 차단
        if (/[\x00-\x1F\x7F]/.test(base)) return null;
        if (base.includes("/") || base.includes("\\")) return null;
        if (base.includes("..")) return null;

        if (!IMAGE_FILENAME_RE.test(base)) return null;

        // Windows 예약 장치명(CON, PRN 등) 방어(상대경로 탈출은 아니지만 예외 케이스 방지)
        const stem = base.replace(/\.[^.]+$/, "");
        const first = stem.split(".")[0].toUpperCase();
        if (WINDOWS_RESERVED.has(first)) return null;

        return base;
    }

    function safeResolveIntoDir(baseDir, filename) {
        const base = path.resolve(baseDir);
        const target = path.resolve(base, filename);
        const rel = path.relative(base, target);
        // base 밖으로 나가거나(../), 절대경로가 되어버리면 차단
        if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
        // startsWith 경계(유사 prefix) 혼동 방지
        if (!target.startsWith(base + path.sep)) return null;
        return target;
    }

	function isSupportedImageBuffer(buf, filename) {
	    if (!Buffer.isBuffer(buf) || buf.length < 12) return false;

	    const ext = path.extname(filename).toLowerCase();

	    // PNG: 89 50 4E 47 0D 0A 1A 0A
	    if (ext === ".png") {
	        return buf.length >= 8 &&
	            buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47 &&
	            buf[4] === 0x0D && buf[5] === 0x0A && buf[6] === 0x1A && buf[7] === 0x0A;
	    }

	    // JPEG: FF D8 FF
	    if (ext === ".jpg" || ext === ".jpeg")
	        return buf.length >= 3 && buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF;

	    // GIF: 47 49 46 38
	    if (ext === ".gif")
	        return buf.length >= 4 && buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38;

	    // WEBP: "RIFF"...."WEBP"
	    if (ext === ".webp") {
	        return buf.length >= 12 &&
	            buf.toString("ascii", 0, 4) === "RIFF" &&
	            buf.toString("ascii", 8, 12) === "WEBP";
	    }

	    return false;
	}

    /**
     * 페이지 내용을 HTML로 변환
     */
    function convertPageToHTML(pageData) {
        // 페이지 메타데이터를 JSON으로 인코딩
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
            publishToken: pageData.publishToken || null,
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
${JSON.stringify(pageMetadata, null, 2)}
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

    /**
     * HTML 이스케이프
     */
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

    /**
     * HTML에서 페이지 내용 추출
     */
    function extractPageFromHTML(html) {
        try {
            const dom = new JSDOM(html);
            const doc = dom.window.document;

            // 메타데이터 스크립트 추출
            const metadataScript = doc.querySelector('#nteok-metadata');
            let metadata = null;
            if (metadataScript) {
                try {
                    const metadataText = metadataScript.textContent?.trim();
                    // 보안: 메타데이터 길이 제한 (DoS 완화)
                    if (metadataText && metadataText.length < 1024 * 1024) {
                        // 보안: 백업 HTML 내부 JSON은 신뢰 불가 -> prototype pollution 트리거 키 제거
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

            // 아이콘 제거
            const iconMatch = title.match(/^([\p{Emoji}\u200d]+)\s+(.+)$/u);
            let icon = null;
            if (iconMatch) {
                icon = iconMatch[1];
                title = iconMatch[2];
            }

            const content = contentEl ? contentEl.innerHTML : '<p></p>';

            // 커버 이미지 추출
            const coverImageEl = doc.querySelector('.cover-image');
            let coverImage = null;
            if (coverImageEl) {
                const src = coverImageEl.getAttribute('src');
                if (src) {
                    // "../images/userId/filename.png" 형식에서 경로 추출
                    const match = src.match(/\.\.\/images\/(.+)/);
                    if (match) {
                        coverImage = match[1];
                    }
                }
            }

            // 메타데이터가 있으면 사용, 없으면 기본값
            return {
                title,
                content,
                icon: icon || (metadata?.icon) || null,
                isEncrypted: metadata?.isEncrypted || false,
                encryptionSalt: metadata?.encryptionSalt || null,
                encryptedContent: metadata?.encryptedContent || null,
                shareAllowed: metadata?.shareAllowed || false,
                coverImage: coverImage || metadata?.coverImage || null,
                coverPosition: metadata?.coverPosition || 50,
                parentId: metadata?.parentId || null,
                sortOrder: metadata?.sortOrder || 0,
                publishToken: metadata?.publishToken || null,
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

    /**
     * 백업 내보내기
     * GET /api/backup/export
     */
    router.get('/export', authMiddleware, async (req, res) => {
        const userId = req.user.id;

        try {
			// DB 접근은 repo에서만 수행 (접근제어 SQL 정책 중앙화 포함)
			const { storages, pages, publishes } = await backupRepo.getExportRows(userId);

            if (!storages || storages.length === 0)
                return res.status(404).json({ error: '내보낼 데이터가 없습니다.' });

            // 페이지별 발행 상태 조회
            const publishMap = new Map();

			(publishes || []).forEach(pub => {
				publishMap.set(pub.page_id, {
					token: pub.token,
					createdAt: toIsoString(pub.created_at),
					allowComments: pub.allow_comments || 0
				});
			});

            // ZIP 아카이브 생성
            const archive = archiver('zip', {
                zlib: { level: 9 } // 최대 압축
            });

            // 응답 헤더 설정
            res.attachment('nteok-backup.zip');
            res.type('application/zip');

            // 에러 핸들링
            archive.on('error', (err) => {
                console.error('ZIP 생성 오류:', err);
                res.status(500).json({ error: 'ZIP 생성 실패' });
            });

            // 아카이브를 응답으로 파이프
            archive.pipe(res);

            // 이미지 수집
            const imagesToInclude = new Set();

            // 커버 이미지 수집
            for (const page of pages) {
				if (!page.cover_image) continue;
				if (DEFAULT_COVERS.includes(page.cover_image)) continue;

				const normalized = normalizeUserImageRefForExport(page.cover_image, userId);
				if (normalized) imagesToInclude.add(normalized);
            }

            // 페이지 내용에서 이미지 수집
            const imgRegex = /\/imgs\/(\d+)\/([A-Za-z0-9._-]{1,200}\.(?:png|jpe?g|gif|webp))(?:\?[^"'\s]*)?/gi;
            for (const page of pages) {
                const content = page.content || '';
                let match;
                while ((match = imgRegex.exec(content)) !== null) {
                    const normalized = normalizeUserImageRefForExport(`${match[1]}/${match[2]}`, userId);
                    if (normalized) imagesToInclude.add(normalized);
                }
            }

            // 저장소 메타데이터 생성
            const storageMap = new Map();
            storages.forEach(stg => storageMap.set(stg.id, stg));

            // 각 저장소의 메타데이터 파일 추가
            // 보안: ZIP 엔트리 이름에 .. 같은 dot-segment가 들어가면
            // 사용자가 백업 ZIP을 OS/unzip 도구로 풀 때 Zip Slip(경로 순회)로 이어질 수 있음
            // -> 사람이 읽기 쉬운 이름 + 고유 ID를 섞어 충돌/우회 모두 방지
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
                    updatedAt: toIsoString(storage.updated_at)
                };

                archive.append(
                    JSON.stringify(storageMetadata, null, 2),
                    { name: `workspaces/${storageFolderName}.json` }
                );
            }

            // 페이지 추가
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
                const pageData = {
                    ...page,
                    publishToken: publishInfo?.token || null,
                    publishedAt: publishInfo?.createdAt || null,
                    allowComments: publishInfo?.allowComments || 0
                };

                const html = convertPageToHTML(pageData);
                archive.append(html, { name: `pages/${storageFolderName}/${pageFileName}.html` });
            }

            // 이미지 추가
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

            // 백업 정보 파일 추가
            const backupInfo = {
                version: '2.0 (storages based)',
                exportDate: new Date().toISOString(),
                storagesCount: storages.length,
                pagesCount: pages.length,
                imagesCount: imagesToInclude.size
            };
            archive.append(JSON.stringify(backupInfo, null, 2), { name: 'backup-info.json' });

            await archive.finalize();
            console.log(`[백업 내보내기] 사용자 ${userId} 완료`);
        } catch (error) {
            logError('GET /api/backup/export', error);
            if (!res.headersSent) res.status(500).json({ error: '백업 내보내기 실패' });
        }
    });

    /**
     * 백업 불러오기
     * POST /api/backup/import
     */
    router.post('/import', authMiddleware, backupImportLimiter, backupUpload.single('backup'), async (req, res) => {
        const userId = req.user.id;
        const uploadedFile = req.file;

        if (!uploadedFile) return res.status(400).json({ error: '파일이 없습니다.' });

        let connection;
        let extractDir;
        try {
            // 보안: Zip Bomb(Decompression Bomb) 대응을 위해 스트리밍으로 읽고,
            // 실제 해제(읽기) 바이트 기준으로 상한을 강제
            // 큰 엔트리는 디스크 스풀 - extractDir에 임시 파일 저장
            const importResult = await readBackupZipEntriesForImport(uploadedFile.path);
            const zipEntries = importResult.zipEntries;
            extractDir = importResult.extractDir;

            connection = await pool.getConnection();
            await connection.beginTransaction();

            const workspaceMap = new Map(); // 폴더명 -> 저장소 ID
            const pageDataMap = new Map();
            let totalPages = 0;
            let totalImages = 0;

            // 1. 저장소(구 컬렉션) 생성
            const workspaceEntries = zipEntries.filter(e => e.entryName.startsWith('workspaces/') || e.entryName.startsWith('collections/'));

            for (const entry of workspaceEntries) {
                if (entry.isDirectory || !entry.entryName.endsWith('.json')) continue;
                // 보안: 백업 ZIP 내부 JSON은 신뢰 불가 -> prototype pollution 트리거 키 제거
                const metadata = safeJsonParse(entry.data.toString('utf8'), entry.entryName);
                if (!metadata) continue;

                const nowStr = formatDateForDb(new Date());
                const storageId = 'stg-' + Date.now() + '-' + crypto.randomBytes(4).toString('hex');

                // 보안: 외부 ZIP에서 온 저장소 이름은 신뢰 불가 → 반드시 정규화
                const safeStorageName = normalizeStorageName(metadata?.name);

                await connection.execute(
                    `INSERT INTO storages (id, user_id, name, sort_order, created_at, updated_at)
                     VALUES (?, ?, ?, ?, ?, ?)`,
                    [storageId, userId, safeStorageName, metadata.sortOrder || 0, nowStr, nowStr]
                );

                const folderName = entry.entryName.split('/').pop().replace('.json', '');
                workspaceMap.set(folderName, storageId);
            }

            // 하위 호환성 (폴더 기반)
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

                    // 보안: 폴더명 기반 저장소 생성도 외부 입력(백업 ZIP) → 정규화
                    const safeStorageName = normalizeStorageName(f);

                    await connection.execute(`INSERT INTO storages (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, NOW(), NOW())`, [storageId, userId, safeStorageName]);
                    workspaceMap.set(f, storageId);
                }
            }

            // 2. 페이지 복원
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

                pageDataMap.set(pageId, pageData);

                let coverImage = pageData.coverImage;
                if (coverImage && !DEFAULT_COVERS.includes(coverImage)) {
                    const cParts = coverImage.split('/');
                    if (cParts.length === 2) coverImage = `${userId}/${cParts[1]}`;
                }

                // 보안: 백업(import) 파일의 HTML은 신뢰할 수 없으므로 서버 기준으로 정화/정규화한다.
                // - pages.content는 WebSocket(Yjs) 초기 상태 시딩에도 사용되므로,
                //   여기서 정화를 빼먹으면 악성 HTML이 협업자/새 세션으로 전파될 수 있다(Stored XSS).
                const safeTitle = sanitizeInput(pageData.title || '제목 없음').slice(0, 200);
                // 중요: icon은 프론트에서 class="..."로 렌더링되므로, 백업(import)에서도
                // allowlist 검증을 적용하여 속성 탈출/DOM XSS 위험을 제거
                const safeIcon = validateAndNormalizeIcon(pageData.icon);
                const safeContent = pageData.isEncrypted ? '' : sanitizeHtmlContent(pageData.content || '<p></p>');
                const safeEncryptionSalt = pageData.isEncrypted ? (pageData.encryptionSalt || null) : null;
                const safeEncryptedContent = pageData.isEncrypted ? (pageData.encryptedContent || null) : null;

                await connection.execute(
                    `INSERT INTO pages (id, user_id, storage_id, title, content, encryption_salt, encrypted_content,
                                       sort_order, created_at, updated_at, is_encrypted, share_allowed, icon, cover_image, cover_position)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [pageId, userId, storageId, safeTitle, safeContent, safeEncryptionSalt, safeEncryptedContent,
                     pageData.sortOrder || 0, nowStr, nowStr, pageData.isEncrypted ? 1 : 0, pageData.shareAllowed ? 1 : 0, safeIcon, coverImage, pageData.coverPosition || 50]
                );

                // 보안: import 시 publish token은 기본적으로 신뢰하지 않음
                // - KEEP_IMPORT_PUBLISH_TOKENS=false(기본): 토큰 재발급 + 비활성(is_active=0)로 복원
                // - KEEP_IMPORT_PUBLISH_TOKENS=true : 신뢰된 백업 전제 하에 토큰 유지 + 활성 복원
                if (pageData.publishToken) {
                    const backupToken = String(pageData.publishToken || '');
                    const useBackupToken = KEEP_IMPORT_PUBLISH_TOKENS && isValidPublishToken(backupToken);

                    const finalToken = useBackupToken ? backupToken : generatePublishToken();
                    const isActive = useBackupToken ? 1 : 0;

                    await insertPublishLinkWithRetry(connection, {
                        token: finalToken,
                        pageId,
                        ownerUserId: userId,
                        createdAt: nowStr,
                        updatedAt: nowStr,
                        allowComments: pageData.allowComments ? 1 : 0,
                        isActive
                    });
                }

                totalPages++;
            }

            // 3. 이미지 복원
            for (const entry of zipEntries) {
                if (!entry.entryName.startsWith('images/') || entry.isDirectory) continue;
                const imagePath = entry.entryName.substring(7);
                if (DEFAULT_COVERS.includes(imagePath)) continue;

                // ZIP 엔트리에서 파일명 추출 + 엄격 검증 (Zip Slip/Path Traversal 방지)
                const filename = getSafeImageFilenameFromZipPath(imagePath);
                if (!filename) continue;

                let isCover = false;
                for (const pd of pageDataMap.values()) {
                    if (pd.coverImage && pd.coverImage.includes(filename)) { isCover = true; break; }
                }

                const targetDir = path.join(__dirname, '..', isCover ? 'covers' : 'imgs', String(userId));
                if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

                // 최종 저장 경로를 baseDir 내부로 강제
                const targetPath = safeResolveIntoDir(targetDir, filename);
                if (!targetPath) continue;

                if (entry.data) {
                    // 메모리 Buffer 엔트리
                    if (!isSupportedImageBuffer(entry.data, filename)) continue;
                    fs.writeFileSync(targetPath, entry.data);
                } else {
                    // 디스크 스풀 엔트리: 헤더만 읽어 타입 검증 후 이동
                    const fd = fs.openSync(entry.tempFilePath, 'r');
                    const header = Buffer.alloc(16);
                    const n = fs.readSync(fd, header, 0, 16, 0);
                    fs.closeSync(fd);
                    if (!isSupportedImageBuffer(header.slice(0, n), filename)) continue;
                    // 파일 이동 (메모리 사용 최소화)
                    try {
                        fs.renameSync(entry.tempFilePath, targetPath);
                    } catch (e) {
                        fs.copyFileSync(entry.tempFilePath, targetPath);
                        fs.unlinkSync(entry.tempFilePath);
                    }
                }
                totalImages++;
            }

            await connection.commit();
            fs.unlinkSync(uploadedFile.path);
            res.json({ ok: true, storagesCount: workspaceMap.size, pagesCount: totalPages, imagesCount: totalImages });
        } catch (error) {
            if (connection) await connection.rollback();
            if (uploadedFile && fs.existsSync(uploadedFile.path)) fs.unlinkSync(uploadedFile.path);
            logError('POST /api/backup/import', error);
            res.status(500).json({ error: error.message });
        } finally {
            if (connection) connection.release();
            // import용 임시 디렉터리 정리 (성공/실패 모두)
            try { if (typeof extractDir === 'string') fs.rmSync(extractDir, { recursive: true, force: true }); } catch (_) {}
        }
    });

    /**
     * ZIP 엔트리 경로 세그먼트 안전 정규화
     * 보안: 공격자가 storage/page 이름에 .. 같은 dot-segment를 넣으면
     * ZIP 엔트리: pages/../<file>.html 형태가 만들어져 추출 시 의도치 않은 경로로 쓰일 수 있음 (Zip Slip / Path Traversal)
     * 따라서: (1) path separator 제거, (2) dot-only segment 차단,
     *         (3) 끝 공백/점 제거(Windows 호환), (4) 충돌 방지를 위해 안정적 ID를 suffix로 부여
     */
    function sanitizeZipPathSegment(raw, { fallback = 'item', maxLen = 80 } = {}) {
        const s0 = String(raw ?? '').normalize('NFKC');

        // 제어문자 제거
        let s = s0.replace(/[\u0000-\u001F\u007F]/g, '');

        // (POSIX/Windows/유니코드 유사 구분자) 경로 구분자 제거
        s = s.replace(/[\\/\u2215\u2044\u29F8\uFF0F\uFF3C]/g, '_');

        // ZIP/Windows에서 문제되는 예약 문자 제거
        s = s.replace(/[<>:"|?*]/g, '_');

        // 공백 정리
        s = s.trim().replace(/\s+/g, ' ');

        // Windows: 끝의 공백/점은 경로 해석이 바뀌거나 충돌을 만들 수 있음
        s = s.replace(/[ .]+$/g, '');

        // dot-segment 차단 ("." / ".." / "..." 같은 값)
        if (!s || /^\.+$/.test(s) || s === '.' || s === '..')
            s = fallback;

        // 길이 제한
        if (s.length > maxLen)
            s = s.slice(0, maxLen);

        // 남아있는 .. 패턴(단독 세그먼트로 해석될 소지) 제거
        // 일부 unzip 도구의 구현 차이를 고려해 완화
        s = s.replace(/(^|\s)\.\.(\s|$)/g, '_');

        // 비어있으면 fallback
        return s || fallback;
    }

    function makeSafeZipFolderName({ label, stableId, fallback }) {
        const base = sanitizeZipPathSegment(label, { fallback, maxLen: 48 });
        const id = sanitizeZipPathSegment(String(stableId || ''), { fallback: 'id', maxLen: 32 });
        // 폴더명은 충돌 가능성이 높으므로 ID suffix를 강제
        return `${base}-${id}`;
    }

    function makeSafeZipFileBaseName({ label, stableId, fallback }) {
        const base = sanitizeZipPathSegment(label, { fallback, maxLen: 64 });
        const id = sanitizeZipPathSegment(String(stableId || ''), { fallback: 'id', maxLen: 24 });
        // 파일명도 중복(동일 제목) 가능 → ID suffix로 덮어쓰기 방지
        return `${base}-${id}`;
    }

    return router;
};
