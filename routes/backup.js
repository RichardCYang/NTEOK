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
			const { collections, shares, pages, publishes } = await backupRepo.getExportRows(userId);

            if (!collections || collections.length === 0)
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
            res.attachment('backup.zip');
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

				// 기본 커버는 포함하지 않음
				if (DEFAULT_COVERS.includes(page.cover_image)) continue;

				const normalized = normalizeUserImageRefForExport(page.cover_image, userId);
				if (!normalized) {
				    // 커버 이미지 경로가 유효하지 않으면 제외
				    continue;
				}

				imagesToInclude.add(normalized);
				console.log(`[커버 이미지 수집] ${page.title} -> ${normalized}`);
            }

            // 페이지 내용에서 이미지 수집
            // - 정상 포맷: /imgs/<userId>/<filename.ext>
            // - 쿼리스트링은 무시 (?:\?...) 허용
            const imgRegex = /\/imgs\/(\d+)\/([A-Za-z0-9._-]{1,200}\.(?:png|jpe?g|gif|webp))(?:\?[^"'\s]*)?/gi;

            for (const page of pages) {
                const content = page.content || '';
                let match;
                while ((match = imgRegex.exec(content)) !== null) {
                    const normalized = normalizeUserImageRefForExport(`${match[1]}/${match[2]}`, userId);
                    // 유효한 이미지 참조만 포함
                    if (normalized)
                        imagesToInclude.add(normalized);
                }
            }

            // 컬렉션 메타데이터 생성
            const collectionMap = new Map();
            const sharesByCollection = new Map();

            collections.forEach(col => {
                collectionMap.set(col.id, col);
                sharesByCollection.set(col.id, []);
            });

            // 공유 정보 그룹화
            shares.forEach(share => {
                const list = sharesByCollection.get(share.collection_id);
                if (list) {
                    list.push({
                        username: share.shared_with_username,
                        permission: share.permission
                    });
                }
            });

            // 각 컬렉션의 메타데이터 파일 추가
            for (const collection of collections) {
                const collectionFolderName = sanitizeFilename(collection.name);
                const collectionMetadata = {
                    id: collection.id,
                    name: collection.name,
                    sortOrder: collection.sort_order,
                    createdAt: toIsoString(collection.created_at),
                    updatedAt: toIsoString(collection.updated_at),
                    isEncrypted: Boolean(collection.is_encrypted),
                    defaultEncryption: Boolean(collection.default_encryption),
                    enforceEncryption: Boolean(collection.enforce_encryption),
                    shares: sharesByCollection.get(collection.id) || []
                };

                archive.append(
                    JSON.stringify(collectionMetadata, null, 2),
                    { name: `collections/${collectionFolderName}.json` }
                );
            }

            // 페이지 추가
            for (const page of pages) {
                const collection = collectionMap.get(page.collection_id);
                if (!collection) continue;

                const collectionFolderName = sanitizeFilename(collection.name);
                const pageFolderName = sanitizeFilename(page.title || 'untitled');

                const publishInfo = publishMap.get(page.id);
                const pageData = {
                    id: page.id,
                    title: page.title || '제목 없음',
                    content: page.content || '<p></p>',
                    createdAt: toIsoString(page.created_at),
                    updatedAt: toIsoString(page.updated_at),
                    parentId: page.parent_id,
                    sortOrder: page.sort_order,
                    isEncrypted: page.is_encrypted ? true : false,
                    encryptionSalt: page.encryption_salt || null,
                    encryptedContent: page.encrypted_content || null,
                    shareAllowed: page.share_allowed ? true : false,
                    icon: page.icon || null,
                    coverImage: page.cover_image || null,
                    coverPosition: page.cover_position || 50,
                    publishToken: publishInfo?.token || null,
                    publishedAt: publishInfo?.createdAt || null
                };

                const html = convertPageToHTML(pageData);
                archive.append(html, { name: `pages/${collectionFolderName}/${pageFolderName}.html` });
            }

            // 이미지 추가
            for (const imageRef of imagesToInclude) {
                const normalized = normalizeUserImageRefForExport(imageRef, userId);

                // 유효하지 않은 경로 제외
                if (!normalized)
                    continue;

                const parts = normalized.split('/');
                const ownerId = Number(parts[0]);
                const filename = parts[1];

                // covers 또는 imgs 아래의 해당 사용자 폴더만 허용
                const coversRoot = path.join(__dirname, '..', 'covers');
                const imgsRoot = path.join(__dirname, '..', 'imgs');

                const coverPath = resolveSafeUserFilePath(coversRoot, ownerId, filename);
                const imgPath = resolveSafeUserFilePath(imgsRoot, ownerId, filename);

                const finalPath = coverPath || imgPath;

                // 파일이 없으면 조용히 스킵
                if (!finalPath)
                    continue;

                // ZIP 내부 경로도 안전한 값(정규화된 normalized)만 사용 (Zip Slip 방지)
                archive.file(finalPath, { name: `images/${normalized}` });
            }

            // 백업 정보 파일 추가
            const backupInfo = {
                version: '1.0',
                exportDate: new Date().toISOString(),
                collectionsCount: collections.length,
                pagesCount: pages.length,
                imagesCount: imagesToInclude.size
            };
            archive.append(JSON.stringify(backupInfo, null, 2), { name: 'backup-info.json' });

            // ZIP 완료
            await archive.finalize();

            console.log(`[백업 내보내기] 사용자 ${userId} - 컬렉션: ${collections.length}, 페이지: ${pages.length}, 이미지: ${imagesToInclude.size}`);
        } catch (error) {
            logError('GET /api/backup/export', error);
            if (!res.headersSent) {
                res.status(500).json({ error: '백업 내보내기 실패' });
            }
        }
    });

    /**
     * 백업 불러오기
     * POST /api/backup/import
     */
    router.post('/import', authMiddleware, backupUpload.single('backup'), async (req, res) => {
        const userId = req.user.id;
        const uploadedFile = req.file;

        if (!uploadedFile) {
            return res.status(400).json({ error: '백업 파일이 업로드되지 않았습니다.' });
        }

        let connection;

        try {
            // ZIP 파일 열기
            const zip = new AdmZip(uploadedFile.path);
            const zipEntries = zip.getEntries();

            // 보안: ZIP Bomb 사전 검증
            if (zipEntries.length > MAX_ZIP_ENTRIES)
                throw new Error(`유효하지 않은 백업 파일: ZIP 엔트리 개수 초과(${zipEntries.length})`);

            let totalUncompressed = 0;
            for (const entry of zipEntries) {
                if (entry.isDirectory) continue;

                // ZipSlip 계열 우회 방지: entryName 기본 sanity check
                // (기존 코드의 isSafePath와 별개로 사전 차단)
                const name = String(entry.entryName || '');
                if (!name || name.length > 512)
                    throw new Error(`유효하지 않은 백업 파일: 엔트리 이름이 비정상`);

                if (name.includes('..') || name.startsWith('/') || /^[A-Za-z]:/.test(name) || name.includes('\\'))
                    throw new Error(`유효하지 않은 백업 파일: 위험한 경로 엔트리 감지`);

                const { uncompressed, compressed } = getEntrySizes(entry);
                if (uncompressed <= 0) continue;

                // 엔트리 단일 크기 제한
                if (uncompressed > MAX_ENTRY_UNCOMPRESSED_BYTES)
                    throw new Error(`유효하지 않은 백업 파일: 엔트리 압축해제 크기 초과(${name})`);

                totalUncompressed += uncompressed;
                if (totalUncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES)
                    throw new Error(`유효하지 않은 백업 파일: 전체 압축해제 크기 초과`);

                // (선택) 고압축 ratio 탐지: ratio 단독 사용은 false positive 가능 → 크기 조건과 조합
                if (compressed > 0 && uncompressed >= MIN_RATIO_ENTRY_BYTES) {
                    const ratio = uncompressed / compressed;
                    if (ratio > MAX_SUSPICIOUS_RATIO)
                        throw new Error(`유효하지 않은 백업 파일: 비정상적 압축 비율 감지(${name})`);
                }
            }

			console.log(`[백업 불러오기] 사용자 ${userId} - 파일 개수: ${zipEntries.length}`);

			// ZIP Bomb / 리소스 고갈 방지: 엔트리 수/해제 용량 검증
			validateZipEntriesForImport(zipEntries);

			// 백업 정보 확인
            const backupInfoEntry = zipEntries.find(entry => entry.entryName === 'backup-info.json');
            if (backupInfoEntry) {
                const backupInfo = JSON.parse(backupInfoEntry.getData().toString('utf8'));
                console.log('[백업 정보]', backupInfo);
            }

            // 컬렉션 메타데이터 파일 읽기
            const collectionMetadataEntries = zipEntries.filter(entry =>
                entry.entryName.startsWith('collections/') && entry.entryName.endsWith('.json')
            );

            // 트랜잭션 시작
            connection = await pool.getConnection();
            await connection.beginTransaction();

            const collectionMap = new Map(); // 폴더명 -> 컬렉션 ID
            const pageDataMap = new Map(); // 페이지 ID -> pageData (이미지 처리를 위해)
            let totalPages = 0;
            let totalImages = 0;

            // 컬렉션 생성 (메타데이터 포함)
            for (const entry of collectionMetadataEntries) {
                const metadataJson = entry.getData().toString('utf8');
                const metadata = JSON.parse(metadataJson);

                const now = new Date();
                const collectionId = generateCollectionId(now);
                const nowStr = formatDateForDb(now);

                // 컬렉션 이름 추출 (파일명에서)
                const filename = entry.entryName.split('/').pop().replace('.json', '');

                await connection.execute(
                    `INSERT INTO collections (id, user_id, name, sort_order, created_at, updated_at,
                                             is_encrypted, default_encryption, enforce_encryption)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        collectionId,
                        userId,
                        metadata.name,
                        metadata.sortOrder || 0,
                        nowStr,
                        nowStr,
                        metadata.isEncrypted ? 1 : 0,
                        metadata.defaultEncryption ? 1 : 0,
                        metadata.enforceEncryption ? 1 : 0
                    ]
                );

                collectionMap.set(filename, collectionId);
                console.log(`[컬렉션 생성] ${metadata.name} (${filename}) -> ID ${collectionId}`);

                // 공유 정보는 복원하지 않음 (사용자명이 시스템에 없을 수 있음)
                // 필요하다면 별도 로직 추가 가능
            }

            // 기존 방식 호환성: collections 폴더가 없는 경우 pages 폴더에서 컬렉션 추출
            if (collectionMetadataEntries.length === 0) {
                const collectionFolders = new Set();
                for (const entry of zipEntries) {
                    if (!entry.isDirectory && entry.entryName.endsWith('.html') && entry.entryName.startsWith('pages/')) {
                        const parts = entry.entryName.split('/');
                        if (parts.length >= 3) {
                            collectionFolders.add(parts[1]);
                        }
                    }
                }

                for (const folderName of collectionFolders) {
                    const now = new Date();
                    const collectionId = generateCollectionId(now);
                    const nowStr = formatDateForDb(now);

                    await connection.execute(
                        `INSERT INTO collections (id, user_id, name, sort_order, created_at, updated_at)
                         VALUES (?, ?, ?, 0, ?, ?)`,
                        [collectionId, userId, folderName, nowStr, nowStr]
                    );
                    collectionMap.set(folderName, collectionId);
                    console.log(`[컬렉션 생성 (호환)] ${folderName} -> ID ${collectionId}`);
                }
            }

            // 페이지 및 이미지 복원
            for (const entry of zipEntries) {
                if (entry.isDirectory) continue;

                const entryName = entry.entryName;

                // ZIP Slip 방지: 경로 검증
                const baseExtractDir = path.join(__dirname, '..');
                if (!isSafePath(entryName, baseExtractDir)) {
                    console.warn(`[보안] 위험한 ZIP 엔트리 건너뜀: ${entryName}`);
                    continue;
                }

                // HTML 페이지 처리 (pages/ 폴더)
                if (entryName.endsWith('.html') && entryName.startsWith('pages/')) {
                    const parts = entryName.split('/');
                    if (parts.length < 3) continue; // pages/collectionName/pageName.html

                    const collectionFolder = parts[1];
                    const collectionId = collectionMap.get(collectionFolder);
                    if (!collectionId) continue;

                    const html = entry.getData().toString('utf8');
                    const pageData = extractPageFromHTML(html);

                    // 페이지 생성
                    const now = new Date();
                    const pageId = generatePageId(now);
                    const nowStr = formatDateForDb(now);

                    // 디버그: coverImage 정보 출력
                    if (pageData.coverImage) {
                        console.log(`[페이지 복원 메타] ${pageData.title} - 커버: ${pageData.coverImage}, isCover: ${pageData.isCoverImage}`);
                    }

                    // pageData를 맵에 저장 (이미지 처리 시 참조용)
                    pageDataMap.set(pageId, pageData);

                    // 커버 이미지 처리
                    let coverImage = pageData.coverImage;
                    if (coverImage) {
                        if (DEFAULT_COVERS.includes(coverImage)) {
                            // 기본 커버인 경우: 그대로 유지
                            console.log(`[기본 커버 복원] ${coverImage}`);
                        } else {
                            // 커스텀 커버 이미지인 경우 경로의 userId 부분을 새 userId로 업데이트
                            const parts = coverImage.split('/');
                            if (parts.length === 2) {
                                // 원본 형식: oldUserId/filename -> 새 형식: newUserId/filename
                                coverImage = `${userId}/${parts[1]}`;
                                console.log(`[커버 경로 업데이트] ${pageData.coverImage} -> ${coverImage}`);
                            } else {
                                // 경로 형식이 맞지 않으면 무시
                                console.log(`[커버 경로 형식 오류] ${coverImage} (parts.length: ${parts.length})`);
                                coverImage = null;
                            }
                        }
                    }

                    await connection.execute(
                        `INSERT INTO pages (id, user_id, parent_id, title, content, encryption_salt, encrypted_content,
                                           sort_order, created_at, updated_at, collection_id,
                                           is_encrypted, share_allowed, icon, cover_image, cover_position)
                         VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                        [
                            pageId,
                            userId,
                            sanitizeInput(pageData.title),
                            sanitizeHtmlContent(pageData.content),
                            pageData.encryptionSalt,
                            pageData.encryptedContent,
                            pageData.sortOrder || 0,
                            nowStr,
                            nowStr,
                            collectionId,
                            pageData.isEncrypted ? 1 : 0,
                            pageData.shareAllowed ? 1 : 0,
                            pageData.icon,
                            coverImage,
                            pageData.coverPosition || 50
                        ]
                    );

                    // 발행 정보 복원
                    // 보안: import는 신뢰할 수 없는 입력일 수 있으므로,
                    // - 기본값: 백업에 포함된 publishToken을 그대로 사용하지 않고 새 토큰을 재발급
                    // - opt-in(KEEP_IMPORT_PUBLISH_TOKENS=true) 시에만 검증된 토큰을 유지
                    if (pageData.publishToken) {
                    	const keepToken = KEEP_IMPORT_PUBLISH_TOKENS && isValidPublishToken(pageData.publishToken);
                        const requestedToken = keepToken ? pageData.publishToken : generatePublishToken();

                        const createdAt = pageData.publishedAt ? formatDateForDb(new Date(pageData.publishedAt)) : nowStr;

                        const finalToken = await insertPublishLinkWithRetry(connection, {
                            token: requestedToken,
                            pageId,
                            ownerUserId: userId,
                            createdAt,
                            updatedAt: nowStr,
                            // 안전 기본값: import로는 공개 댓글을 자동 활성화하지 않음
                            allowComments: 0
                        });

						// 보안: 토큰 일부만 표시
						const maskedToken = String(finalToken).substring(0, 8) + '...';
                        const note = keepToken ? '' : ' (import 보안: 토큰 재발급)';
                        console.log(`[발행 정보 복원] ${pageData.title} - 토큰: ${maskedToken}${note}`);
                    }

                    totalPages++;
                    console.log(`[페이지 복원] ${pageData.title} (암호화: ${pageData.isEncrypted})`);
                }

                // 이미지 처리
                if (entryName.startsWith('images/')) {
                    const imagePath = entryName.substring('images/'.length);

                    console.log(`[이미지 처리 시작] ${imagePath}`);

                    // 기본 커버 이미지는 건너뛰기
                    if (DEFAULT_COVERS.includes(imagePath)) {
                        console.log(`[이미지 건너뛰기] 기본 커버: ${imagePath}`);
                        continue;
                    }

                    const parts = imagePath.split('/');
                    if (parts.length < 2) {
                        console.log(`[이미지 경로 오류] ${imagePath} (parts.length: ${parts.length})`);
                        continue;
                    }

                    // 이미지 타입 판별: userId/filename 형식이므로 첫 번째 부분을 제거하고 나머지는 filename
					const filename = parts[parts.length - 1];

					// 허용된 이미지 확장자만 복원
					if (!isAllowedImageFilename(filename)) {
					    console.warn(`[보안] 허용되지 않은 이미지 확장자: ${filename}`);
					    continue;
					}

					// 파일명 추가 검증 (경로 조작 방지)
                    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
                        console.warn(`[보안] 위험한 파일명 감지: ${filename}`);
                        continue;
                    }

                    // 백업에서 원래 어느 폴더에 있었는지 판별
                    // pageDataMap에서 이 이미지가 커버인지 확인
                    let isCoverImage = false;

                    for (const pageData of pageDataMap.values()) {
                        if (pageData && pageData.coverImage && pageData.coverImage.includes(filename) && pageData.isCoverImage) {
                            isCoverImage = true;
                            console.log(`[커버 이미지 감지] ${filename} (${pageData.title})`);
                            break;
                        }
                    }

                    // 디렉토리 설정
                    let targetDir;
                    if (isCoverImage) {
                        targetDir = path.join(__dirname, '..', 'covers', String(userId));
                    } else {
                        targetDir = path.join(__dirname, '..', 'imgs', String(userId));
                    }

                    console.log(`[이미지 저장 위치] ${imagePath} -> ${targetDir}`);

                    // 디렉토리 생성
                    if (!fs.existsSync(targetDir)) {
                        fs.mkdirSync(targetDir, { recursive: true });
                        console.log(`[디렉토리 생성] ${targetDir}`);
                    }

                    const targetPath = path.join(targetDir, filename);

                    // 최종 경로 검증 (디렉토리 탈출 방지)
                    const resolvedTargetPath = path.resolve(targetPath);
                    const resolvedTargetDir = path.resolve(targetDir);
                    if (!resolvedTargetPath.startsWith(resolvedTargetDir + path.sep)) {
                        console.warn(`[보안] 디렉토리 탈출 시도 차단: ${targetPath}`);
                        continue;
                    }

                    // 이미지 저장 (매직바이트 확인)
					const imageData = entry.getData();
					if (!isSupportedImageBuffer(imageData, filename)) {
						console.warn(`[보안] 이미지 시그니처 불일치(스푸핑 가능): ${filename}`);
						continue;
					}

					// 최종 필터 통과된 데이터 쓰기
					fs.writeFileSync(targetPath, imageData);

                    totalImages++;
                    console.log(`[이미지 복원 완료] ${imagePath} -> ${filename}`);
                }
            }

            // 트랜잭션 커밋
            await connection.commit();

            // 임시 파일 삭제
            fs.unlinkSync(uploadedFile.path);

            console.log(`[백업 불러오기 완료] 컬렉션: ${collectionMap.size}, 페이지: ${totalPages}, 이미지: ${totalImages}`);

            res.json({
                ok: true,
                collectionsCount: collectionMap.size,
                pagesCount: totalPages,
                imagesCount: totalImages
            });
        } catch (error) {
            // 트랜잭션 롤백
            if (connection) {
                await connection.rollback();
            }

            // 임시 파일 삭제
            if (uploadedFile && fs.existsSync(uploadedFile.path)) {
                fs.unlinkSync(uploadedFile.path);
            }

			logError('POST /api/backup/import', error);

			// 입력(백업 파일) 문제는 400으로 반환
			const msg = String(error?.message || '백업 불러오기 실패');
			const isBadRequest = /백업 파일|유효하지 않은|허용되지 않은|경로 형식|시그니처/.test(msg);
			res.status(isBadRequest ? 400 : 500).json({ error: '백업 불러오기 실패: ' + msg });
        } finally {
            if (connection) {
                connection.release();
            }
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
