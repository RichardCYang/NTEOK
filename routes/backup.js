const express = require('express');
const router = express.Router();
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const { JSDOM } = require('jsdom');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

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

const backupUpload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            cb(null, tempDir);
        },
        filename: (req, file, cb) => {
            // 파일명에 타임스탐프 추가로 중복 방지
            const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
            cb(null, 'backup-' + uniqueSuffix + '.zip');
        }
    }),
    limits: {
        fileSize: 100 * 1024 * 1024 // 100MB
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
        authMiddleware,
        toIsoString,
        sanitizeInput,
        sanitizeHtmlContent,
        generatePageId,
        generateCollectionId,
        formatDateForDb,
        logError
    } = dependencies;

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
     * 페이지 내용을 HTML로 변환
     */
    function convertPageToHTML(page) {
        // 페이지 메타데이터를 JSON으로 인코딩
        const pageMetadata = {
            id: page.id,
            parentId: page.parentId,
            sortOrder: page.sortOrder,
            isEncrypted: page.isEncrypted,
            encryptionSalt: page.encryptionSalt || null,
            encryptedContent: page.encryptedContent || null,
            shareAllowed: page.shareAllowed || false,
            coverPosition: page.coverPosition || 50
        };

        const html = `<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(page.title)}</title>
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
    ${page.coverImage ? `<img class="cover-image" src="../images/${page.coverImage}" alt="Cover">` : ''}
    <h1>${page.icon ? page.icon + ' ' : ''}${escapeHtml(page.title)}</h1>
    <div class="metadata">
        <div>생성: ${new Date(page.createdAt).toLocaleString('ko-KR')}</div>
        <div>수정: ${new Date(page.updatedAt).toLocaleString('ko-KR')}</div>
        ${page.isEncrypted ? '<div style="color: #dc2626;">🔒 암호화된 페이지</div>' : ''}
    </div>
    <div class="content">
        ${page.content || '<p>암호화된 내용입니다.</p>'}
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
                    metadata = JSON.parse(metadataScript.textContent);
                } catch (e) {
                    console.warn('메타데이터 파싱 실패:', e);
                }
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
                coverImage: coverImage || null,
                coverPosition: metadata?.coverPosition || 50,
                parentId: metadata?.parentId || null,
                sortOrder: metadata?.sortOrder || 0
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
                sortOrder: 0
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
            // 1. 사용자의 모든 컬렉션 조회 (암호화 정보 포함)
            const [collections] = await pool.execute(
                `SELECT id, name, sort_order, created_at, updated_at,
                        is_encrypted, default_encryption, enforce_encryption
                 FROM collections
                 WHERE user_id = ?
                 ORDER BY sort_order ASC`,
                [userId]
            );

            if (collections.length === 0) {
                return res.status(404).json({ error: '내보낼 데이터가 없습니다.' });
            }

            // 2. 컬렉션 공유 정보 조회
            const collectionIds = collections.map(c => c.id);
            const [shares] = await pool.execute(
                `SELECT cs.collection_id, cs.shared_with_user_id, cs.permission,
                        u.username as shared_with_username
                 FROM collection_shares cs
                 JOIN users u ON cs.shared_with_user_id = u.id
                 WHERE cs.collection_id IN (${collectionIds.map(() => '?').join(',')})`,
                collectionIds
            );

            // 3. 모든 페이지 조회 (암호화 데이터 포함)
            const [pages] = await pool.execute(
                `SELECT id, title, content, encryption_salt, encrypted_content,
                        created_at, updated_at, parent_id, sort_order, collection_id,
                        is_encrypted, share_allowed, icon, cover_image, cover_position
                 FROM pages
                 WHERE collection_id IN (SELECT id FROM collections WHERE user_id = ?)
                 ORDER BY collection_id ASC, parent_id IS NULL DESC, sort_order ASC`,
                [userId]
            );

            // 3. ZIP 아카이브 생성
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

            // 4. 이미지 수집
            const imagesToInclude = new Set();

            // 커버 이미지 수집
            for (const page of pages) {
                if (page.cover_image) {
                    // 기본 커버가 아닌 경우에만 추가
                    if (!DEFAULT_COVERS.includes(page.cover_image)) {
                        imagesToInclude.add(page.cover_image);
                    }
                }
            }

            // 페이지 내용에서 이미지 수집
            for (const page of pages) {
                const content = page.content || '';
                const imgRegex = /\/imgs\/([^"'\s]+)/g;
                let match;
                while ((match = imgRegex.exec(content)) !== null) {
                    imagesToInclude.add(match[1]);
                }
            }

            // 5. 컬렉션 메타데이터 생성
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

            // 6. 페이지 추가
            for (const page of pages) {
                const collection = collectionMap.get(page.collection_id);
                if (!collection) continue;

                const collectionFolderName = sanitizeFilename(collection.name);
                const pageFolderName = sanitizeFilename(page.title || 'untitled');

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
                    coverPosition: page.cover_position || 50
                };

                const html = convertPageToHTML(pageData);
                archive.append(html, { name: `pages/${collectionFolderName}/${pageFolderName}.html` });
            }

            // 6. 이미지 추가
            for (const imagePath of imagesToInclude) {
                const fullPath = path.join(__dirname, '..', 'covers', imagePath);
                if (fs.existsSync(fullPath)) {
                    archive.file(fullPath, { name: `images/${imagePath}` });
                } else {
                    // imgs 폴더에서도 확인
                    const imgsPath = path.join(__dirname, '..', 'imgs', imagePath);
                    if (fs.existsSync(imgsPath)) {
                        archive.file(imgsPath, { name: `images/${imagePath}` });
                    }
                }
            }

            // 7. 백업 정보 파일 추가
            const backupInfo = {
                version: '1.0',
                exportDate: new Date().toISOString(),
                collectionsCount: collections.length,
                pagesCount: pages.length,
                imagesCount: imagesToInclude.size
            };
            archive.append(JSON.stringify(backupInfo, null, 2), { name: 'backup-info.json' });

            // 8. ZIP 완료
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
            // 1. ZIP 파일 열기
            const zip = new AdmZip(uploadedFile.path);
            const zipEntries = zip.getEntries();

            console.log(`[백업 불러오기] 사용자 ${userId} - 파일 개수: ${zipEntries.length}`);

            // 2. 백업 정보 확인
            const backupInfoEntry = zipEntries.find(entry => entry.entryName === 'backup-info.json');
            if (backupInfoEntry) {
                const backupInfo = JSON.parse(backupInfoEntry.getData().toString('utf8'));
                console.log('[백업 정보]', backupInfo);
            }

            // 3. 컬렉션 메타데이터 파일 읽기
            const collectionMetadataEntries = zipEntries.filter(entry =>
                entry.entryName.startsWith('collections/') && entry.entryName.endsWith('.json')
            );

            // 트랜잭션 시작
            connection = await pool.getConnection();
            await connection.beginTransaction();

            const collectionMap = new Map(); // 폴더명 -> 컬렉션 ID
            let totalPages = 0;
            let totalImages = 0;

            // 4. 컬렉션 생성 (메타데이터 포함)
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

            // 5. 페이지 및 이미지 복원
            for (const entry of zipEntries) {
                if (entry.isDirectory) continue;

                const entryName = entry.entryName;

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

                    // 커버 이미지 처리 (기본 커버는 제외)
                    let coverImage = pageData.coverImage;
                    if (coverImage && DEFAULT_COVERS.includes(coverImage)) {
                        coverImage = null;
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

                    totalPages++;
                    console.log(`[페이지 복원] ${pageData.title} (암호화: ${pageData.isEncrypted})`);
                }

                // 이미지 처리
                if (entryName.startsWith('images/')) {
                    const imagePath = entryName.substring('images/'.length);

                    // 기본 커버 이미지는 건너뛰기
                    if (DEFAULT_COVERS.includes(imagePath)) {
                        console.log(`[이미지 건너뛰기] 기본 커버: ${imagePath}`);
                        continue;
                    }

                    const parts = imagePath.split('/');
                    if (parts.length < 2) continue;

                    // 이미지를 사용자의 covers 또는 imgs 폴더에 저장
                    let targetDir;
                    if (imagePath.includes('cover') || entry.entryName.includes('cover')) {
                        targetDir = path.join(__dirname, '..', 'covers', String(userId));
                    } else {
                        targetDir = path.join(__dirname, '..', 'imgs', String(userId));
                    }

                    // 디렉토리 생성
                    if (!fs.existsSync(targetDir)) {
                        fs.mkdirSync(targetDir, { recursive: true });
                    }

                    const filename = parts[parts.length - 1];
                    const targetPath = path.join(targetDir, filename);

                    // 이미지 저장
                    fs.writeFileSync(targetPath, entry.getData());
                    totalImages++;
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
            res.status(500).json({ error: '백업 불러오기 실패: ' + error.message });
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

    return router;
};
