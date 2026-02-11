const express = require('express');
const router = express.Router();
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const { JSDOM } = require('jsdom');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const crypto = require('crypto');

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

function getEntrySizes(entry) {
	// adm-zip는 entry.header.size(압축해제 크기), entry.header.compressedSize(압축 크기)를 제공
	const uncompressed = Number(entry?.header?.size || 0);
	const compressed = Number(entry?.header?.compressedSize || 0);
	return { uncompressed, compressed };
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
        generateCollectionId,
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

    async function insertPublishLinkWithRetry(connection, { token, pageId, ownerUserId, createdAt, updatedAt, allowComments = 0 }) {
        let t = token;
        for (let i = 0; i < 5; i++) {
            try {
                await connection.execute(
                    `INSERT INTO page_publish_links (token, page_id, owner_user_id, is_active, created_at, updated_at, allow_comments)
                     VALUES (?, ?, ?, 1, ?, ?, ?)` ,
                    [t, pageId, ownerUserId, createdAt, updatedAt, allowComments]
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

	function getUncompressedSize(entry) {
	    // adm-zip: entry.header.size 는 uncompressed size (number)
	    const size = entry?.header?.size;
	    if (typeof size !== "number" || !Number.isFinite(size) || size < 0)
	        return null;
	    return size;
	}

	function validateZipEntriesForImport(zipEntries) {
	    if (!Array.isArray(zipEntries))
	        throw new Error("유효하지 않은 백업 파일입니다.");

	    if (zipEntries.length > BACKUP_IMPORT_MAX_ENTRIES)
	        throw new Error(`백업 파일 내 항목이 너무 많습니다. (최대 ${BACKUP_IMPORT_MAX_ENTRIES}개)`);

	    let total = 0;

	    for (const entry of zipEntries) {
	        if (!entry || entry.isDirectory) continue;

	        // Windows 구분자(\) 등 비정상 경로 방지
	        if (typeof entry.entryName === "string" && entry.entryName.includes("\\"))
	            throw new Error("백업 파일 경로 형식이 유효하지 않습니다.");

	        const size = getUncompressedSize(entry);
	        if (size === null) {
	            // 크기를 알 수 없는 엔트리는 처리하지 않음 (안전 우선)
	            throw new Error("백업 파일의 일부 항목 크기를 확인할 수 없습니다.");
	        }

	        if (size > BACKUP_IMPORT_MAX_ENTRY_UNCOMPRESSED)
	            throw new Error("백업 파일 내 일부 항목이 너무 큽니다.");

	        total += size;
	        if (total > BACKUP_IMPORT_MAX_TOTAL_UNCOMPRESSED)
	            throw new Error("백업 파일의 전체 해제 용량이 너무 큽니다.");
	    }
	}

	function isAllowedImageFilename(filename) {
	    const ext = path.extname(filename).toLowerCase();
	    return ALLOWED_IMAGE_EXTENSIONS.has(ext);
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
                    if (metadataText) {
                        metadata = JSON.parse(metadataText);
                        console.log('[메타데이터 파싱 성공]', {
                            coverImage: metadata?.coverImage,
                            isCoverImage: metadata?.isCoverImage
                        });
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
					createdAt: toIsoString(pub.created_at)
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
            for (const storage of storages) {
                const storageFolderName = sanitizeFilename(storage.name);
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

                const storageFolderName = sanitizeFilename(storage.name);
                const pageFileName = sanitizeFilename(page.title || 'untitled');

                const publishInfo = publishMap.get(page.id);
                const pageData = {
                    ...page,
                    publishToken: publishInfo?.token || null,
                    publishedAt: publishInfo?.createdAt || null
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
    router.post('/import', authMiddleware, backupUpload.single('backup'), async (req, res) => {
        const userId = req.user.id;
        const uploadedFile = req.file;

        if (!uploadedFile) return res.status(400).json({ error: '파일이 없습니다.' });

        let connection;
        try {
            const zip = new AdmZip(uploadedFile.path);
            const zipEntries = zip.getEntries();
			validateZipEntriesForImport(zipEntries);

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
                const metadata = JSON.parse(entry.getData().toString('utf8'));
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

                const pageData = extractPageFromHTML(entry.getData().toString('utf8'));
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
                const safeIcon = pageData.icon ? sanitizeInput(String(pageData.icon)).slice(0, 64) : null;
                const safeContent = pageData.isEncrypted ? '' : sanitizeHtmlContent(pageData.content || '<p></p>');
                const safeEncryptionSalt = pageData.encryptionSalt || null;
                const safeEncryptedContent = pageData.encryptedContent || null;

                await connection.execute(
                    `INSERT INTO pages (id, user_id, storage_id, title, content, encryption_salt, encrypted_content,
                                       sort_order, created_at, updated_at, is_encrypted, share_allowed, icon, cover_image, cover_position)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [pageId, userId, storageId, safeTitle, safeContent, safeEncryptionSalt, safeEncryptedContent,
                     pageData.sortOrder || 0, nowStr, nowStr, pageData.isEncrypted ? 1 : 0, pageData.shareAllowed ? 1 : 0, safeIcon, coverImage, pageData.coverPosition || 50]
                );
                totalPages++;
            }

            // 3. 이미지 복원
            for (const entry of zipEntries) {
                if (!entry.entryName.startsWith('images/') || entry.isDirectory) continue;
                const imagePath = entry.entryName.substring(7);
                if (DEFAULT_COVERS.includes(imagePath)) continue;

                const parts = imagePath.split('/');
                const filename = parts[parts.length - 1];
                if (!isAllowedImageFilename(filename)) continue;

                let isCover = false;
                for (const pd of pageDataMap.values()) {
                    if (pd.coverImage && pd.coverImage.includes(filename)) { isCover = true; break; }
                }

                const targetDir = path.join(__dirname, '..', isCover ? 'covers' : 'imgs', String(userId));
                if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

                const imageData = entry.getData();
                if (isSupportedImageBuffer(imageData, filename)) {
                    fs.writeFileSync(path.join(targetDir, filename), imageData);
                    totalImages++;
                }
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
        }
    });

    /**
     * 파일명 정리 (특수문자 제거)
     */
    function sanitizeFilename(name) {
        return name.replace(/[<>:"/\\|?*]/g, '_').substring(0, 100);
    }

    /**
     * 안전한 경로 검증 (ZIP Slip 방지)
     * @param {string} entryPath - ZIP 엔트리 경로
     * @param {string} baseDir - 기준 디렉토리
     * @returns {boolean} - 안전한 경로면 true
     */
	function isSafePath(entryPath, baseDir) {
		// Windows 경로 구분자(\\) 차단
		if (entryPath.includes('\\')) {
		    console.warn(`[보안] Windows 경로 구분자 감지: ${entryPath}`);
		    return false;
		}

        // 경로 조작 문자열 검사
        if (entryPath.includes('..') || entryPath.includes('./') || entryPath.includes('.\\')) {
            console.warn(`[보안] 경로 조작 시도 감지: ${entryPath}`);
            return false;
        }

        // 절대 경로 검사
        if (path.isAbsolute(entryPath)) {
            console.warn(`[보안] 절대 경로 사용 시도: ${entryPath}`);
            return false;
        }

        // null byte 검사
        if (entryPath.includes('\0')) {
            console.warn(`[보안] null byte 감지: ${entryPath}`);
            return false;
        }

        // 최종 경로가 기준 디렉토리 내부인지 검증
        try {
            const resolvedPath = path.resolve(baseDir, entryPath);
            const resolvedBase = path.resolve(baseDir);

            if (!resolvedPath.startsWith(resolvedBase + path.sep) && resolvedPath !== resolvedBase) {
                console.warn(`[보안] 디렉토리 탈출 시도: ${entryPath} -> ${resolvedPath}`);
                return false;
            }
        } catch (error) {
            console.error(`[보안] 경로 검증 오류: ${entryPath}`, error);
            return false;
        }

        return true;
    }

    return router;
};
