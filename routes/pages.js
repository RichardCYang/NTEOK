const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const dns = require("node:dns").promises;
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const ipaddr = require("ipaddr.js");
const { assertImageFileSignature } = require("../security-utils.js");

/**
 * Pages Routes
 *
 * 이 파일은 페이지 관련 라우트를 처리합니다.
 * - 페이지 목록 조회
 * - 단일 페이지 조회
 * - 페이지 생성
 * - 페이지 수정
 * - 페이지 삭제
 * - 페이지 공유 허용 설정
 */

module.exports = (dependencies) => {
    const {
        pool,
        authMiddleware,
        toIsoString,
		sanitizeInput,
		sanitizeFilenameComponent,
        sanitizeExtension,
        sanitizeHtmlContent,
        generatePageId,
        formatDateForDb,
        getCollectionPermission,
        wsBroadcastToCollection,
        logError,
        generatePublishToken,
        coverUpload,
        editorImageUpload,
        themeUpload,
        fileUpload,
        outboundFetchLimiter,
        path,
        fs,
        yjsDocuments
	} = dependencies;

    /**
     * 보안: 업로드된 이미지 파일명을 정규화하여 속성 주입(XSS) 및 MIME 혼동을 차단
     * - multer 저장 단계에서는 .upload 같은 임시 확장자로 저장
     * - 여기서 파일 시그니처 검증 결과(detected.ext)에 맞춰 안전한 확장자로 변경
     * - 파일명에는 [a-zA-Z0-9._-] 외 문자를 제거하여 HTML/헤더/경로 컨텍스트 위험 문자 차단
     */
	function normalizeUploadedImageFile(fileObj, detectedExt) {
	    if (!fileObj?.path || !fileObj?.filename) throw new Error('INVALID_UPLOAD');
	    const ext = `.${String(detectedExt || '').toLowerCase()}`;
		const safeExt = sanitizeExtension(ext);

	    if (!safeExt || !['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(safeExt))
	        throw new Error('UNSUPPORTED_IMAGE_TYPE');

	    const dir = path.dirname(fileObj.path);
	    const rawBase = path.basename(fileObj.filename, path.extname(fileObj.filename));
	    const base = sanitizeFilenameComponent(rawBase, 80).replace(/[^a-zA-Z0-9._-]/g, '') || crypto.randomBytes(8).toString('hex');
	    let newFilename = `${base}${safeExt}`;
		let newPath = path.join(dir, newFilename);

	    if (fs.existsSync(newPath)) {
	        const suffix = crypto.randomBytes(4).toString('hex');
	        newFilename = `${base}-${suffix}${safeExt}`;
	        newPath = path.join(dir, newFilename);
		}

	    const resolvedDir = path.resolve(dir) + path.sep;
		const resolvedNewPath = path.resolve(newPath);

	    if (!resolvedNewPath.startsWith(resolvedDir)) throw new Error('PATH_TRAVERSAL_BLOCKED');
	    if (newPath !== fileObj.path) {
	        fs.renameSync(fileObj.path, newPath);
	        fileObj.path = newPath;
	        fileObj.filename = newFilename;
	    }
	}

    const ALLOWED_PROTOCOLS = new Set(["http:", "https:"]);
	const ALLOWED_PORTS = new Set([80, 443]);

	// 아이콘 입력 검증/정규화 (HTML 주입 및 이상한 class 문자열 차단)
    // - 이모지(짧은 텍스트) 또는 FontAwesome class list만 허용
    function validateAndNormalizeIcon(raw) {
        if (raw === undefined || raw === null) return null;
        if (typeof raw !== "string") return null;

        const icon = raw.trim();
        if (icon === "") return null;

        // 마크업/속성 주입 시도 차단 (서버 저장 단계에서 방어)
        if (/[<>]/.test(icon)) {
            const err = new Error("INVALID_ICON");
            err.code = "INVALID_ICON";
            throw err;
        }

        // FontAwesome: 예) "fa-solid fa-star" / "fa-regular fa-file" / "fa-brands fa-github"
        const FA_CLASS_RE = /^(fa-(solid|regular|brands|light|thin|duotone|sharp|sharp-solid|sharp-regular|sharp-light|sharp-thin|sharp-duotone))\s+fa-[a-z0-9-]+(?:\s+fa-[a-z0-9-]+)*$/i;

        // (기존 로직 호환) 단일 클래스만 오는 경우: "fa-star"
        const FA_SINGLE_RE = /^fa-[a-z0-9-]+$/i;

        if (FA_CLASS_RE.test(icon) || FA_SINGLE_RE.test(icon))
            return icon;

        // 이모지/짧은 텍스트(공백/제어문자/따옴표/앰퍼샌드 제외)만 허용
        // (길이는 넉넉히 8로 제한: variation selector 등을 어느 정도 허용)
        if (icon.length <= 8 && !/\s/.test(icon) && !/["'`&]/.test(icon))
            return icon;

        const err = new Error("INVALID_ICON");
        err.code = "INVALID_ICON";
        throw err;
    }

	function isPublicRoutableIp(address) {
	    try {
		    // net.isIP: 0(아님), 4, 6
		    if (!net.isIP(address)) return false;
		    const parsed = ipaddr.parse(address);

		    // ipaddr.js range()가 unicast가 아니면 내부/특수 대역으로 취급 (보수적으로 차단)
		    return parsed.range() === "unicast";
	    } catch {
		    return false;
	    }
    }

    async function resolveAndValidateHost(hostname) {
	    // hostname이 이미 IP면 그대로 검증
	    if (net.isIP(hostname)) {
		    if (!isPublicRoutableIp(hostname)) throw new Error("Disallowed IP");
		    return { address: hostname, family: net.isIP(hostname) };
	    }

	    const results = await dns.lookup(hostname, { all: true, verbatim: true });
	    if (!results || results.length === 0) throw new Error("DNS lookup failed");

	    // 하나라도 비공개/특수 대역이 섞여 있으면 차단 (우회 여지 제거)
	    for (const r of results) {
		    if (!isPublicRoutableIp(r.address)) throw new Error("Disallowed resolved IP");
	    }

	    // 핀ning용으로 첫 번째 주소 선택(원하면 랜덤 선택 가능)
	    return results[0];
    }

    async function assertSafeExternalUrl(rawUrl) {
	    const u = new URL(rawUrl);

	    if (!ALLOWED_PROTOCOLS.has(u.protocol)) throw new Error("Only http/https allowed");
	    if (u.username || u.password) throw new Error("Userinfo not allowed");

	    const port = u.port ? Number(u.port) : (u.protocol === "https:" ? 443 : 80);
	    if (!ALLOWED_PORTS.has(port)) throw new Error("Port not allowed");

	    const resolved = await resolveAndValidateHost(u.hostname);

	    // DNS 고정: lookup을 강제로 고정해서 DNS 재할당 위험을 낮춤
		const lookup = (hostname, options, cb) => {
			const opts = typeof options === "number" ? { family: options } : (options || {});
			const addr = resolved.address;
			const fam = resolved.family;

			if (!addr) return cb(new Error("Resolved address missing"));

			if (opts.all) {
				return cb(null, [{ address: addr, family: fam }]);
			}
			return cb(null, addr, fam);
		};

	    const httpAgent = new http.Agent({ lookup });
	    const httpsAgent = new https.Agent({ lookup });

	    return { urlObj: u, httpAgent, httpsAgent };
    }

    async function safeAxiosGet(rawUrl, axios, axiosOpts = {}, { maxRedirects = 2 } = {}) {
	    let current = rawUrl;

	    for (let i = 0; i <= maxRedirects; i++) {
		    const { urlObj, httpAgent, httpsAgent } = await assertSafeExternalUrl(current);

		    const resp = await axios.get(urlObj.toString(), {
		        ...axiosOpts,
		        httpAgent,
		        httpsAgent,
		        maxRedirects: 0, // OWASP 권고: 자동 리다이렉트는 비활성화 후 직접 검증하며 따라가기 :contentReference[oaicite:1]{index=1}
		        validateStatus: (s) => s >= 200 && s < 400
		    });

		    // 수동 리다이렉트 처리(필요할 때만)
		    if (resp.status >= 300 && resp.status < 400 && resp.headers.location) {
		        const next = new URL(resp.headers.location, urlObj).toString();
		        current = next;
		        continue;
		    }

		    return resp;
	    }

	    throw new Error("Too many redirects");
    }

    /**
     * 보안: 허용 목록 + 프록시 이미지의 시그니처 확인
     * NOTE: 다양한 환경에서 SVG(image/svg+xml)는 실행이 가능할 수 있는 위험이 있음 (예: 문서를 열람할 때 등)
     * 동일 origin 프록시 엔드포인트에서는 이러한 점이 XSS 공격 벡터가 될 수 있음 -> 이러한 상황을 방지하기 위해
     * 오직 레스터 이미지와 파일 시그니처가 확인된 이미지만 허용하도록 함 (매직 바이트)
     */
    function detectSafeRasterImageMime(buf) {
        if (!buf) return null;
        const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);

        // JPEG: FF D8 FF
        if (b.length >= 3 && b[0] === 0xFF && b[1] === 0xD8 && b[2] === 0xFF) return 'image/jpeg';

        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4E && b[3] === 0x47 && b[4] === 0x0D && b[5] === 0x0A && b[6] === 0x1A && b[7] === 0x0A) return 'image/png';

        // GIF: GIF87a or GIF89a
        if (b.length >= 6 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38 && (b[4] === 0x37 || b[4] === 0x39) && b[5] === 0x61) return 'image/gif';

        // WebP: RIFF....WEBP
        if (b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return 'image/webp';

        return null;
    }

    /**
     * 사용자 업로드 커버 이미지 목록 조회
     * GET /api/pages/covers/user
     */
    router.get("/covers/user", authMiddleware, async (req, res) => {
        const userId = req.user.id;

        try {
            const userCoversDir = path.join(__dirname, '..', 'covers', String(userId));

            // 사용자 폴더가 없으면 빈 배열 반환
            if (!fs.existsSync(userCoversDir)) {
                return res.json([]);
            }

            // 디렉토리 내 파일 목록 읽기
            const files = fs.readdirSync(userCoversDir);

            // 이미지 파일만 필터링
            const imageFiles = files.filter(file => {
                const ext = path.extname(file).toLowerCase();
                return ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext);
            });

            // 파일 정보 조회 (생성일자 기준 정렬)
            const covers = imageFiles.map(file => {
                const filePath = path.join(userCoversDir, file);
                const stats = fs.statSync(filePath);
                return {
                    path: `${userId}/${file}`,
                    filename: file,
                    uploadedAt: stats.birthtime.toISOString()
                };
            }).sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));

            res.json(covers);
        } catch (error) {
            logError("GET /api/pages/covers/user", error);
            res.status(500).json({ error: "커버 목록 조회 실패" });
        }
    });

    /**
     * 사용자 업로드 커버 이미지 삭제
     * DELETE /api/pages/covers/:filename
     */
    router.delete("/covers/:filename", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        const filename = req.params.filename;

        try {
        	const safeName = path.basename(filename);

        	// path.basename() 함수를 통하면 입력값 파일 정보에서 순수하게 파일명.확장자 정보만 가져오고 나머지 상위 경로 정보는 모두 지움
         	// 그런데 그렇게 basename() 함수를 통하여 순수 확장자만 남은 파일이름과 실제 클라이언트 요청 정보가 다르다면, 요청 정보에 서버 전체 경로를 요구할 가능성이 있으므로 차단
			if (safeName !== filename) {
				return res.status(400).json({ error: "잘못된 파일명입니다." });
			}

			// 확장자/문자 허용 목록 확인
			if (!/^[a-zA-Z0-9._-]+\.(png|jpe?g|webp|gif)$/i.test(safeName)) {
				return res.status(400).json({ error: "허용되지 않은 파일 형식입니다." });
			}

			const coverPath = path.join(userId.toString(), safeName);
            const filePath = path.join(__dirname, '..', 'covers', coverPath);

            // 파일 존재 확인
            if (!fs.existsSync(filePath)) {
                return res.status(404).json({ error: "파일을 찾을 수 없습니다." });
            }

            // 해당 커버를 사용 중인 페이지가 있는지 확인
            const [pages] = await pool.execute(
                `SELECT id FROM pages WHERE cover_image = ? AND user_id = ?`,
                [coverPath, userId]
            );

            if (pages.length > 0) {
                return res.status(400).json({
                    error: "해당 커버를 사용 중인 페이지가 있습니다. 먼저 페이지의 커버를 변경해주세요."
                });
            }

            // 파일 삭제
            fs.unlinkSync(filePath);

            console.log("DELETE /api/pages/covers/:filename 삭제 완료:", coverPath);
            res.json({ success: true });
        } catch (error) {
            logError("DELETE /api/pages/covers/:filename", error);
            res.status(500).json({ error: "커버 삭제 실패" });
        }
    });

    /**
     * 페이지 목록 조회 (소유한 페이지 + 공유받은 컬렉션의 페이지)
     * GET /api/pages
     *
     * 성능 최적화:
     * - DISTINCT 제거, UNION ALL로 분리하여 인덱스 활용 극대화
     * - 각 쿼리가 독립적인 인덱스 사용
     * - 중복 제거 필요 없음 (두 쿼리가 겹치지 않음)
     */
    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const collectionId =
                typeof req.query.collectionId === "string" && req.query.collectionId.trim() !== ""
                    ? req.query.collectionId.trim()
                    : null;

            // 성능 최적화: 쿼리를 UNION ALL로 분리 (DISTINCT 제거)
            // 1. 본인 소유 페이지 (인덱스: idx_pages_collection_user)
            // 2. 공유받은 컬렉션의 페이지 (인덱스: idx_shared_with_user)
            let query = `
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.collection_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    INNER JOIN collections c ON p.collection_id = c.id
                    WHERE c.user_id = ?
                    ${collectionId ? 'AND p.collection_id = ?' : ''}
                )
                UNION ALL
                (
                    SELECT p.id, p.title, p.updated_at, p.parent_id, p.sort_order,
                           p.collection_id, p.is_encrypted, p.share_allowed, p.user_id,
                           p.icon, p.cover_image, p.cover_position, p.horizontal_padding
                    FROM pages p
                    INNER JOIN collection_shares cs ON p.collection_id = cs.collection_id
                    WHERE cs.shared_with_user_id = ?
                      AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)
                    ${collectionId ? 'AND p.collection_id = ?' : ''}
                )
                ORDER BY collection_id ASC, parent_id IS NULL DESC, sort_order ASC, updated_at DESC
            `;

            const params = collectionId
                ? [userId, collectionId, userId, userId, collectionId]
                : [userId, userId, userId];

            const [rows] = await pool.execute(query, params);

            const list = rows.map((row) => ({
                id: row.id,
                title: row.title || "제목 없음",
                updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id,
                sortOrder: row.sort_order,
                collectionId: row.collection_id,
                isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id,
                icon: row.icon || null,
                coverImage: row.cover_image || null,
                coverPosition: row.cover_position || 50,
                horizontalPadding: row.horizontal_padding || null
            }));

            console.log("GET /api/pages 응답 개수:", list.length, "(최적화된 UNION 쿼리)");

            res.json(list);
        } catch (error) {
            logError("GET /api/pages", error);
            res.status(500).json({ error: "페이지 목록 불러오기 실패." });
        }
    });

    /**
     * 단일 페이지 조회 (소유한 페이지 또는 공유받은 컬렉션의 페이지)
     * GET /api/pages/:id
     */
    router.get("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const [rows] = await pool.execute(
                `SELECT p.id, p.title, p.content, p.encryption_salt, p.encrypted_content,
                        p.created_at, p.updated_at, p.parent_id, p.sort_order, p.collection_id,
                        p.is_encrypted, p.share_allowed, p.user_id, p.icon, p.cover_image, p.cover_position,
                        p.horizontal_padding
                 FROM pages p
                 LEFT JOIN collections c ON p.collection_id = c.id
                 LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                 WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)
                 AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)`,
                [userId, id, userId, userId, userId]
            );

            if (!rows.length) {
                console.warn("GET /api/pages/:id - 페이지 없음 또는 권한 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const row = rows[0];

            // 보안: 저장형 XSS 방지(Defense-in-Depth): 응답 직전에도 한 번 더 정화
            // - 과거(패치 전) 저장된 악성 콘텐츠가 남아있을 수 있음
            // - 특히 YouTube 블록은 data-src를 iframe.src로 승격하므로, data-src가 안전하지 않으면 XSS로 이어짐
            const safeContent = sanitizeHtmlContent(row.content || "<p></p>");

            const page = {
                id: row.id,
                title: row.title || "제목 없음",
                content: safeContent,
                encryptionSalt: row.encryption_salt || null,
                encryptedContent: row.encrypted_content || null,
                createdAt: toIsoString(row.created_at),
                updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id,
                sortOrder: row.sort_order,
                collectionId: row.collection_id,
                isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id,
                icon: row.icon || null,
                coverImage: row.cover_image || null,
                coverPosition: row.cover_position || 50,
                horizontalPadding: row.horizontal_padding || null
            };

            console.log("GET /api/pages/:id 응답:", id);

            res.json(page);
        } catch (error) {
            logError("GET /api/pages/:id", error);
            res.status(500).json({ error: "페이지 불러오기 실패." });
        }
    });

    /**
     * 새 페이지 생성
     * POST /api/pages
     * body: { title?: string, content?: string, parentId?: string, sortOrder?: number, collectionId: string, icon?: string, isEncrypted?: boolean, encryptionSalt?: string, encryptedContent?: string }
     */
    router.post("/", authMiddleware, async (req, res) => {
        const rawTitle = typeof req.body.title === "string" ? req.body.title : "";
        const title = sanitizeInput(rawTitle.trim() !== "" ? rawTitle.trim() : "제목 없음");

        const now = new Date();
        const id = generatePageId(now);
        const nowStr = formatDateForDb(now);
        // 평문 콘텐츠(암호화 페이지에서는 저장하지 않음)
        const rawContent = typeof req.body.content === "string" ? req.body.content : "<p></p>";
        const content = sanitizeHtmlContent(rawContent);

        // 암호화 관련 필드 (클라이언트에서 생성된 값)
        const isEncryptedFromBody = typeof req.body.isEncrypted === "boolean" ? req.body.isEncrypted : null;
        const encryptionSaltFromBody = typeof req.body.encryptionSalt === "string" ? req.body.encryptionSalt : null;
        const encryptedContentFromBody = typeof req.body.encryptedContent === "string" ? req.body.encryptedContent : null;

        const userId = req.user.id;

        const parentId =
            typeof req.body.parentId === "string" && req.body.parentId.trim() !== ""
                ? req.body.parentId.trim()
                : null;
        const sortOrder =
            typeof req.body.sortOrder === "number" && Number.isFinite(req.body.sortOrder)
                ? req.body.sortOrder
                : 0;
        const collectionId =
            typeof req.body.collectionId === "string" && req.body.collectionId.trim() !== ""
                ? req.body.collectionId.trim()
                : null;

        let icon = null;
        try {
            icon = validateAndNormalizeIcon(req.body.icon);
        } catch (e) {
            if (e && e.code === "INVALID_ICON")
                return res.status(400).json({ error: "유효하지 않은 아이콘 값입니다." });
            throw e;
        }

		if (!collectionId) {
            return res.status(400).json({ error: "collectionId가 필요합니다." });
		}

        try {
            const { permission } = await getCollectionPermission(collectionId, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 생성할 권한이 없습니다." });
            }

            // 보안: 서버 측 암호화 정책 강제
            // - 기존 구현은 컬렉션 enforceEncryption/defaultEncryption 설정이 있어도
            //   /api/pages 생성에서 평문(content)을 그대로 DB에 저장할 수 있었음(클라이언트 정책 신뢰).
            // - 악성/구형 클라이언트 또는 공유받은 EDIT 사용자가 임의 요청으로 평문 저장을 유도하면
            //   암호화 강제 컬렉션의 기밀성이 깨짐.
            const [colRows] = await pool.execute(
                `SELECT default_encryption, enforce_encryption FROM collections WHERE id = ? LIMIT 1`,
                [collectionId]
            );

            if (!colRows.length)
                return res.status(404).json({ error: "컬렉션을 찾을 수 없습니다." });

            const enforceEncryption = colRows[0].enforce_encryption === 1;
            const defaultEncryption = colRows[0].default_encryption === 1;

            // 컬렉션 정책에 따라 신규 페이지의 암호화 여부 결정
            // - enforceEncryption: 무조건 암호화(평문 저장 금지)
            // - defaultEncryption: 요청에 명시가 없으면 암호화로 간주(하위 호환 위해 명시적으로 false면 평문 허용)
            const shouldEncrypt = enforceEncryption ? true : (isEncryptedFromBody !== null ? isEncryptedFromBody : defaultEncryption);

            if (enforceEncryption && isEncryptedFromBody === false)
                return res.status(400).json({ error: "이 컬렉션은 암호화를 강제합니다. 평문 페이지를 생성할 수 없습니다." });

            // 암호화 페이지인 경우: 서버는 평문 content를 저장하지 않으며, 암호문 필드를 필수로 요구
            let contentToStore = content;
            let isEncryptedToStore = 0;
            let encryptionSaltToStore = null;
            let encryptedContentToStore = null;

            if (shouldEncrypt) {
                if (!encryptionSaltFromBody || !encryptedContentFromBody) {
                    return res.status(400).json({
                        error: "암호화된 페이지를 생성하려면 encryptionSalt와 encryptedContent가 필요합니다."
                    });
                }

                // 보안: 평문 저장 금지
                contentToStore = '';
                isEncryptedToStore = 1;
                encryptionSaltToStore = encryptionSaltFromBody;
                encryptedContentToStore = encryptedContentFromBody;
            }

            if (parentId) {
                // 자기 참조 차단
                if (parentId === id) {
                    return res.status(400).json({ error: "자기 자신을 부모로 설정할 수 없습니다." });
                }

                const [parentRows] = await pool.execute(
                    `SELECT p.id, p.collection_id
                     FROM pages p
                     LEFT JOIN collections c ON p.collection_id = c.id
                     LEFT JOIN collection_shares cs ON p.collection_id = cs.collection_id AND cs.shared_with_user_id = ?
                     WHERE p.id = ? AND (p.user_id = ? OR c.user_id = ? OR cs.collection_id IS NOT NULL)`,
                    [userId, parentId, userId, userId]
                );

                if (!parentRows.length) {
                    return res.status(400).json({ error: "부모 페이지를 찾을 수 없습니다." });
                }

                if (parentRows[0].collection_id !== collectionId) {
                    return res.status(400).json({ error: "부모 페이지와 동일한 컬렉션이어야 합니다." });
                }

                // 순환 참조 검증 (최대 깊이 10)
                let currentId = parentId;
                let depth = 0;
                while (currentId && depth < 10) {
                    const [ancestorRows] = await pool.execute(
                        `SELECT parent_id FROM pages WHERE id = ?`,
                        [currentId]
                    );
                    if (!ancestorRows.length) break;

                    if (ancestorRows[0].parent_id === id) {
                        return res.status(400).json({ error: "순환 참조가 발생합니다." });
                    }

                    currentId = ancestorRows[0].parent_id;
                    depth++;
                }

                if (depth >= 10) {
                    return res.status(400).json({ error: "페이지 계층 구조가 너무 깊습니다. (최대 10단계)" });
                }
            }

            await pool.execute(
                `
                INSERT INTO pages (
                    id, user_id, parent_id, title, content,
                    sort_order, created_at, updated_at, collection_id, icon,
                    is_encrypted, encryption_salt, encrypted_content
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
	                id, userId, parentId, title, contentToStore,
	                sortOrder, nowStr, nowStr, collectionId, icon,
	                isEncryptedToStore, encryptionSaltToStore, encryptedContentToStore
	            ]
            );

            const page = {
                id,
                title,
                content: contentToStore,
                encryptionSalt: encryptionSaltToStore,
                encryptedContent: encryptedContentToStore,
                parentId,
                sortOrder,
                collectionId,
                createdAt: now.toISOString(),
                updatedAt: now.toISOString(),
                icon,
                isEncrypted: Boolean(isEncryptedToStore)
            };

            console.log("POST /api/pages 생성:", id);

            res.status(201).json(page);
        } catch (error) {
            logError("POST /api/pages", error);
            res.status(500).json({ error: "페이지 생성 실패." });
        }
    });

    /**
     * 페이지 수정
     * PUT /api/pages/:id
     * body: { title?: string, content?: string, isEncrypted?: boolean, icon?: string }
     */
    router.put("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        // 평문 필드
        const titleFromBody = typeof req.body.title === "string" ? sanitizeInput(req.body.title.trim()) : null;
        const contentFromBody = typeof req.body.content === "string" ? sanitizeHtmlContent(req.body.content) : null;
        const isEncryptedFromBody = typeof req.body.isEncrypted === "boolean" ? req.body.isEncrypted : null;

        let iconFromBody = undefined;
        if (typeof req.body.icon === "string") {
            try {
                iconFromBody = validateAndNormalizeIcon(req.body.icon);
            } catch (e) {
                if (e && e.code === "INVALID_ICON")
                    return res.status(400).json({ error: "유효하지 않은 아이콘 값입니다." });
                throw e;
            }
        }

        const horizontalPaddingFromBody = typeof req.body.horizontalPadding === 'number' ?
            Math.max(0, Math.min(300, req.body.horizontalPadding)) : (req.body.horizontalPadding === null ? null : undefined);

        // 암호화 필드 (선택적 암호화)
        const encryptionSaltFromBody = typeof req.body.encryptionSalt === "string" ? req.body.encryptionSalt : null;
        const encryptedContentFromBody = typeof req.body.encryptedContent === "string" ? req.body.encryptedContent : null;

        if (!titleFromBody && !contentFromBody && isEncryptedFromBody === null && iconFromBody === undefined &&
            !encryptionSaltFromBody && !encryptedContentFromBody && horizontalPaddingFromBody === undefined) {
            return res.status(400).json({ error: "수정할 데이터 없음." });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, title, content, encryption_salt, encrypted_content,
                        created_at, updated_at, parent_id, sort_order, collection_id, is_encrypted, user_id, icon,
                        horizontal_padding
                 FROM pages
                 WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                console.warn("PUT /api/pages/:id - 페이지 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const existing = rows[0];

            const { permission } = await getCollectionPermission(existing.collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 수정할 권한이 없습니다." });
            }

            // 보안: 서버 측 암호화 정책 강제 (enforceEncryption=1이면 평문 전환 금지)
            const [colRows] = await pool.execute(
                `SELECT enforce_encryption FROM collections WHERE id = ? LIMIT 1`,
                [existing.collection_id]
            );
            const enforceEncryption = colRows.length && colRows[0].enforce_encryption === 1;

            // 암호화 여부 결정
            const newIsEncrypted = isEncryptedFromBody !== null ? (isEncryptedFromBody ? 1 : 0) : existing.is_encrypted;
            const isChangingEncryptionState = existing.is_encrypted !== newIsEncrypted;

            if (enforceEncryption && newIsEncrypted !== 1) {
                return res.status(400).json({
                    error: "이 컬렉션은 암호화를 강제합니다. 페이지를 평문으로 변경할 수 없습니다."
                });
            }

            // 평문 -> 암호화로 전환하는 경우, 암호화 필드는 반드시 제공되어야 함
            if (isChangingEncryptionState && newIsEncrypted === 1) {
                if (!encryptionSaltFromBody || !encryptedContentFromBody) {
                    return res.status(400).json({
                        error: "암호화로 전환하려면 encryptionSalt와 encryptedContent가 필요합니다."
                    });
                }
            }

            if (isChangingEncryptionState && permission !== "ADMIN") {
            	return res.status(403).json({ error: "암호화 설정 변경 권한이 없습니다." });
            }

            // 제목은 항상 평문으로 저장
            const newTitle = titleFromBody && titleFromBody !== "" ? titleFromBody : existing.title;

            // 내용 처리
            let newContent;
            if (newIsEncrypted === 1) {
                // 암호화된 페이지: content는 빈 문자열 (암호화됨)
                newContent = '';
            } else {
                // 평문 페이지: content도 평문 저장
                newContent = contentFromBody !== null ? contentFromBody : existing.content;
            }

            const newIcon = iconFromBody !== undefined ? (iconFromBody !== "" ? iconFromBody : null) : existing.icon;
            const newHorizontalPadding = horizontalPaddingFromBody !== undefined ? horizontalPaddingFromBody : existing.horizontal_padding;

            // 암호화 필드 업데이트
            const newEncryptionSalt = encryptionSaltFromBody !== null ? encryptionSaltFromBody : existing.encryption_salt;
            const newEncryptedContent = encryptedContentFromBody !== null ? encryptedContentFromBody : existing.encrypted_content;

            const now = new Date();
            const nowStr = formatDateForDb(now);

            // [보안] 콘텐츠 변경 전, 기존에 포함되어 있던 파일 목록 추출 (자동 정리를 위해)
            const oldFiles = existing.is_encrypted ? [] : extractFilesFromPage(existing);

            let updateSql = `UPDATE pages
                 SET title = ?, content = ?, encryption_salt = ?, encrypted_content = ?,
                     is_encrypted = ?, icon = ?, horizontal_padding = ?, updated_at = ?`;
            const updateParams = [newTitle, newContent, newEncryptionSalt, newEncryptedContent,
                 newIsEncrypted, newIcon, newHorizontalPadding, nowStr];

            // 콘텐츠가 변경된 경우 yjs_state 초기화 (재동기화 유도)
            if (contentFromBody !== null) {
                updateSql += `, yjs_state = NULL`;
                // 서버 메모리 캐시도 제거하여 다음 연결 시 DB에서 다시 로드하도록 유도
                if (yjsDocuments && yjsDocuments.has(id)) {
                    yjsDocuments.delete(id);
                }
            }

            updateSql += ` WHERE id = ?`;
            updateParams.push(id);

            await pool.execute(updateSql, updateParams);

            // [보안] 콘텐츠 저장 후 자동 파일 정리 수행
            if (!newIsEncrypted && contentFromBody !== null) {
                const newFiles = extractFilesFromPage({ content: contentFromBody });
                // 이전에는 있었지만 새 콘텐츠에는 없는 파일들 찾기
                const deletedFiles = oldFiles.filter(f => !newFiles.includes(f));
                if (deletedFiles.length > 0) {
                    // 현재 페이지를 제외한 다른 페이지의 참조만 확인하여 삭제
                    cleanupOrphanedFiles(deletedFiles, userId, id).catch(e => console.error(e));
                }
            }

            const page = {
                id,
                title: newTitle,
                content: newContent,
                encryptionSalt: newEncryptionSalt,
                encryptedContent: newEncryptedContent,
                parentId: existing.parent_id,
                sortOrder: existing.sort_order,
                collectionId: existing.collection_id,
                createdAt: toIsoString(existing.created_at),
                updatedAt: now.toISOString(),
                icon: newIcon,
                isEncrypted: Boolean(newIsEncrypted),
                horizontalPadding: newHorizontalPadding
            };

            console.log("PUT /api/pages/:id 수정 완료:", id);

            if (titleFromBody && titleFromBody !== existing.title) {
                wsBroadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'title',
                    value: newTitle
                });
            }

            if (iconFromBody !== undefined && newIcon !== existing.icon) {
                wsBroadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'icon',
                    value: newIcon
                });
            }

            if (horizontalPaddingFromBody !== undefined && newHorizontalPadding !== existing.horizontal_padding) {
                wsBroadcastToCollection(existing.collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'horizontalPadding',
                    value: newHorizontalPadding
                });
            }

            res.json(page);
        } catch (error) {
            logError("PUT /api/pages/:id", error);
            res.status(500).json({ error: "페이지 수정 실패." });
        }
    });

    /**
     * 페이지 순서 변경 (같은 컬렉션 내)
     * PATCH /api/pages/reorder
     * body: { collectionId: string, pageIds: string[], parentId: string | null }
     */
    router.patch("/reorder", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        const { collectionId, pageIds, parentId } = req.body;

        if (!collectionId || !Array.isArray(pageIds) || pageIds.length === 0) {
            return res.status(400).json({ error: "collectionId와 pageIds 배열이 필요합니다." });
        }

        const conn = await pool.getConnection();
        try {
            // 권한 확인
            const { permission } = await getCollectionPermission(collectionId, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지 순서를 변경할 권한이 없습니다." });
            }

            await conn.beginTransaction();

            // 모든 페이지가 같은 컬렉션, 같은 부모에 속하는지 확인
            const parentIdCondition = parentId ? `parent_id = ?` : `parent_id IS NULL`;
            const placeholders = pageIds.map(() => '?').join(',');
            const params = parentId
                ? [collectionId, parentId, ...pageIds]
                : [collectionId, ...pageIds];

            const [rows] = await conn.execute(
                `SELECT id FROM pages WHERE collection_id = ? AND ${parentIdCondition} AND id IN (${placeholders})`,
                params
            );

            if (rows.length !== pageIds.length) {
                await conn.rollback();
                return res.status(400).json({ error: "일부 페이지가 조건에 맞지 않습니다." });
            }

            // 순서 업데이트
            for (let i = 0; i < pageIds.length; i++) {
                await conn.execute(
                    `UPDATE pages SET sort_order = ?, updated_at = NOW() WHERE id = ?`,
                    [i * 10, pageIds[i]]
                );
            }

            await conn.commit();
            console.log(`[Reorder] 페이지 순서 변경 완료: ${pageIds.length}개`);

            // WebSocket 브로드캐스트
            wsBroadcastToCollection(collectionId, 'pages-reordered', {
                parentId,
                pageIds
            }, userId);

            res.json({ ok: true, updated: pageIds.length });

        } catch (error) {
            await conn.rollback();
            logError("PATCH /api/pages/reorder", error);
            res.status(500).json({ error: "순서 변경 실패" });
        } finally {
            conn.release();
        }
    });

    /**
     * 페이지 이동 (다른 컬렉션으로)
     * PATCH /api/pages/:id/move
     * body: { targetCollectionId: string, targetParentId: string | null, sortOrder: number }
     */
    router.patch("/:id/move", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;
        const { targetCollectionId, targetParentId, sortOrder } = req.body;

        if (!targetCollectionId) {
            return res.status(400).json({ error: "targetCollectionId가 필요합니다." });
        }

        try {
            // 현재 페이지 정보 조회
            const [pageRows] = await pool.execute(
                `SELECT id, collection_id, parent_id, is_encrypted FROM pages WHERE id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const currentCollectionId = pageRows[0].collection_id;
            const isEncrypted = pageRows[0].is_encrypted;

            // 같은 컬렉션으로 이동 시 거부
            if (currentCollectionId === targetCollectionId) {
                return res.status(400).json({ error: "같은 컬렉션으로 이동할 수 없습니다. 순서 변경은 /reorder API를 사용하세요." });
            }

            // 암호화된 페이지는 이동 불가
            if (isEncrypted) {
                return res.status(400).json({ error: "암호화된 페이지는 다른 컬렉션으로 이동할 수 없습니다." });
            }

            // 출발 컬렉션 권한 확인
            const { permission: sourcePerm } = await getCollectionPermission(currentCollectionId, userId);
            if (!sourcePerm || sourcePerm === 'READ') {
                return res.status(403).json({ error: "페이지를 이동할 권한이 없습니다." });
            }

            // 도착 컬렉션 권한 확인
            const { permission: targetPerm } = await getCollectionPermission(targetCollectionId, userId);
            if (!targetPerm || targetPerm === 'READ') {
                return res.status(403).json({ error: "대상 컬렉션에 페이지를 추가할 권한이 없습니다." });
            }

            // 페이지 이동 (최상위로, 계층 구조 제거)
            const newSortOrder = typeof sortOrder === 'number' ? sortOrder : 0;
            await pool.execute(
                `UPDATE pages SET collection_id = ?, parent_id = ?, sort_order = ?, updated_at = NOW() WHERE id = ?`,
                [targetCollectionId, targetParentId || null, newSortOrder, pageId]
            );

            console.log(`[Move] 페이지 이동: ${pageId} (${currentCollectionId} → ${targetCollectionId})`);

            // 실시간 동기화: 출발/도착 컬렉션 모두 알림
            wsBroadcastToCollection(currentCollectionId, 'page-moved-out', {
                pageId,
                targetCollectionId
            }, userId);
            wsBroadcastToCollection(targetCollectionId, 'page-moved-in', {
                pageId,
                sourceCollectionId: currentCollectionId
            }, userId);

            res.json({ ok: true, pageId, newCollectionId: targetCollectionId });

        } catch (error) {
            logError("PATCH /api/pages/:id/move", error);
            res.status(500).json({ error: "페이지 이동 실패" });
        }
    });

    /**
     * 페이지 제목만 수정
     * PATCH /api/pages/:id
     * body: { title: string }
     */
    router.patch("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { title } = req.body;

        if (!title || typeof title !== "string") {
            return res.status(400).json({ error: "제목이 필요합니다." });
        }

        const sanitizedTitle = sanitizeInput(title.trim());

        try {
            const [rows] = await pool.execute(
                `SELECT collection_id FROM pages WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const collectionId = rows[0].collection_id;
            const { permission } = await getCollectionPermission(collectionId, userId);

            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 수정할 권한이 없습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `UPDATE pages SET title = ?, updated_at = ? WHERE id = ?`,
                [sanitizedTitle, nowStr, id]
            );

            // 실시간 동기화
            wsBroadcastToCollection(collectionId, 'metadata-change', {
                pageId: id,
                field: 'title',
                value: sanitizedTitle
            });

            res.json({ success: true, title: sanitizedTitle });
        } catch (error) {
            logError("PATCH /api/pages/:id", error);
            res.status(500).json({ error: "제목 수정 실패." });
        }
    });

    /**
     * 페이지에서 이미지 URL 추출
     * @param {Object} page - 페이지 객체 (content, cover_image 포함)
     * @returns {Array<string>} - 이미지 경로 배열 (예: ["1/abc.jpg", "1/xyz.png"])
     */
    function extractImagesFromPage(page) {
        const images = [];

        // 1. content에서 <img> 태그의 src 추출
        if (page.content) {
            const imgRegex = /<img[^>]+src=["']\/imgs\/([^"']+)["']/g;
            let match;
            while ((match = imgRegex.exec(page.content)) !== null) {
                images.push(match[1]); // "userId/filename.jpg"
            }
        }

        // 2. cover_image 추가
        if (page.cover_image) {
            images.push(page.cover_image); // "userId/filename.jpg"
        }

        return images;
    }

    /**
     * 고립된 이미지 삭제 (다른 페이지에서 참조하지 않는 이미지만)
     * @param {Array<string>} imageUrls - 이미지 경로 배열
     * @param {number} userId - 사용자 ID
     */
    async function cleanupOrphanedImages(imageUrls, userId) {
        if (!imageUrls || imageUrls.length === 0) return;

        for (const imageUrl of imageUrls) {
            try {
                // 이미지 경로에서 userId와 filename 추출
                const parts = imageUrl.split('/');
                if (parts.length !== 2) continue;

				const [imgUserId, filename] = parts;

                // 보안: 파일명에 경로 탐색(..)이나 백슬래시(\)가 포함된 경우 차단 (Windows 경로 순회 방지)
                if (filename.includes('..') || filename.includes('\\')) {
                    console.warn(`[보안] 유효하지 않은 이미지 파일명 감지: ${filename}`);
                    continue;
                }

				// 소유자(업로드 사용자) 외에는 파일 삭제 금지
                const imgUserIdNum = parseInt(imgUserId, 10);
                if (!Number.isFinite(imgUserIdNum) || imgUserIdNum !== userId)
                    continue;

				// 해당 이미지를 참조하는 다른 페이지가 있는지 확인
                const [contentRows] = await pool.execute(
                	`SELECT COUNT(*) as count FROM pages WHERE content LIKE ?`,
                    [`%/imgs/${imageUrl}%`]
                );

                const [coverRows] = await pool.execute(
                	`SELECT COUNT(*) as count FROM pages WHERE cover_image = ?`,
                    [imageUrl]
                );

                const totalReferences = contentRows[0].count + coverRows[0].count;

                // 참조가 없으면 물리적 파일 삭제
                if (totalReferences === 0) {
                    // imgs 폴더에서 삭제 시도
                    const imgPath = path.join(__dirname, '..', 'imgs', imgUserId, filename);
                    if (fs.existsSync(imgPath)) {
                        fs.unlinkSync(imgPath);
                        console.log(`이미지 삭제됨: ${imgPath}`);
                    }

                    // covers 폴더에서도 삭제 시도 (커버 이미지인 경우)
                    const coverPath = path.join(__dirname, '..', 'covers', imgUserId, filename);
                    if (fs.existsSync(coverPath)) {
                        fs.unlinkSync(coverPath);
                        console.log(`커버 이미지 삭제됨: ${coverPath}`);
                    }
                }
            } catch (err) {
                console.error(`이미지 정리 중 오류 (${imageUrl}):`, err);
                // 개별 이미지 정리 실패는 무시하고 계속 진행
            }
        }
    }

    /**
     * 페이지에서 파일 URL 추출
     */
    function extractFilesFromPage(page) {
        const files = [];
        if (page.content) {
            const fileRegex = /<div[^>]+data-type="file-block"[^>]+data-src=["']\/paperclip\/([^"']+)["']/g;
            let match;
            while ((match = fileRegex.exec(page.content)) !== null) {
                files.push(match[1]); // "userId/filename.ext"
            }
        }
        return files;
    }

    /**
     * 고립된 파일 삭제 (다른 페이지에서 참조하지 않는 파일만)
     */
    async function cleanupOrphanedFiles(filePaths, userId, excludePageId = null) {
        if (!filePaths || filePaths.length === 0) return;

        for (const filePath of filePaths) {
            try {
                const parts = filePath.split('/');
                if (parts.length !== 2) continue;

                const [fileUserId, filename] = parts;

                // 보안: 파일명에 경로 탐색(..)이나 백슬래시(\)가 포함된 경우 차단 (Windows 경로 순회 방지)
                if (filename.includes('..') || filename.includes('\\')) {
                    console.warn(`[보안] 유효하지 않은 파일명 감지: ${filename}`);
                    continue;
                }

                const fileUserIdNum = parseInt(fileUserId, 10);
                if (!Number.isFinite(fileUserIdNum) || fileUserIdNum !== userId) continue;

                // 본인 페이지를 제외하고 다른 페이지에서 사용 중인지 확인
                let query = `SELECT COUNT(*) as count FROM pages WHERE content LIKE ?`;
                let params = [`%/paperclip/${filePath}%` || ''];

                if (excludePageId) {
                    query += ` AND id != ?`;
                    params.push(excludePageId);
                }

                const [rows] = await pool.execute(query, params);

                if (rows[0].count === 0) {
                    const fullPath = path.join(__dirname, '..', 'paperclip', fileUserId, filename);
                    if (fs.existsSync(fullPath)) {
                        fs.unlinkSync(fullPath);
                        console.log(`[보안] 참조 없는 파일 삭제 성공: ${fullPath}`);
                    }
                } else {
                    console.log(`[보안] 파일 삭제 건너뜀 (다른 페이지에서 사용 중): ${filePath}`);
                }
            } catch (err) {
                console.error(`파일 정리 중 오류 (${filePath}):`, err);
            }
        }
    }

    /**
     * 파일 블록 파일 삭제 요청
     * DELETE /api/pages/:id/file-cleanup
     */
    router.delete("/:id/file-cleanup", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;
        const { fileUrl } = req.body;

        if (!fileUrl) return res.status(400).json({ error: "파일 URL이 필요합니다." });

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT collection_id FROM pages WHERE id = ?`,
                [pageId]
            );
            if (!rows.length) return res.status(404).json({ error: "페이지 없음" });

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') return res.status(403).json({ error: "권한 없음" });

            // URL에서 경로 추출 (/paperclip/1/abc.txt -> 1/abc.txt)
            const filePathMatch = fileUrl.match(/\/paperclip\/(.+)$/);
            if (filePathMatch) {
                // 현재 페이지(pageId)를 제외하고 검색하여 삭제 수행
                await cleanupOrphanedFiles([filePathMatch[1]], userId, pageId);
            }

            res.json({ success: true });
        } catch (error) {
            logError("DELETE /api/pages/:id/file-cleanup", error);
            res.status(500).json({ error: "파일 삭제 처리 실패" });
        }
    });

    /**
     * 페이지 삭제 (EDIT 이상 권한 필요)
     * DELETE /api/pages/:id
     */
    router.delete("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            // 페이지 정보 조회 (이미지 및 파일 정리를 위해)
            const [rows] = await pool.execute(
                `SELECT id, collection_id, content, cover_image FROM pages WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                console.warn("DELETE /api/pages/:id - 페이지 없음:", id);
                return res.status(404).json({ error: "Page not found" });
            }

            const page = rows[0];

            const { permission } = await getCollectionPermission(page.collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "페이지를 삭제할 권한이 없습니다." });
            }

            // 페이지에서 사용된 이미지 및 파일 추출
            const imageUrls = extractImagesFromPage(page);
            const filePaths = extractFilesFromPage(page);

            // 페이지 삭제
            await pool.execute(
                `DELETE FROM pages WHERE id = ?`,
                [id]
            );

            console.log("DELETE /api/pages/:id 삭제:", id);

            // 고립된 리소스 정리 (비동기)
            if (imageUrls.length > 0) {
                cleanupOrphanedImages(imageUrls, userId).catch(e => console.error(e));
            }
            if (filePaths.length > 0) {
                cleanupOrphanedFiles(filePaths, userId).catch(e => console.error(e));
            }

            res.json({ ok: true, removedId: id });
        } catch (error) {
            logError("DELETE /api/pages/:id", error);
            res.status(500).json({ error: "페이지 삭제 실패." });
        }
    });

    /**
     * 페이지 공유 허용 설정 업데이트
     * PUT /api/pages/:id/share-permission
     * body: { shareAllowed: boolean }
     */
    router.put("/:id/share-permission", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { shareAllowed } = req.body;

        if (typeof shareAllowed !== "boolean") {
            return res.status(400).json({ error: "shareAllowed는 boolean 값이어야 합니다." });
        }

        try {
            const [rows] = await pool.execute(
                `SELECT id, collection_id, is_encrypted, user_id FROM pages WHERE id = ?`,
                [id]
            );

            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = rows[0];

            if (!page.is_encrypted) {
                return res.status(400).json({ error: "암호화된 페이지만 공유 허용 설정이 가능합니다." });
            }

            if (page.user_id !== userId) {
                return res.status(403).json({ error: "페이지 생성자만 공유 허용 설정을 변경할 수 있습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `UPDATE pages SET share_allowed = ?, updated_at = ? WHERE id = ?`,
                [shareAllowed ? 1 : 0, nowStr, id]
            );

            res.json({ ok: true, shareAllowed });
        } catch (error) {
            logError("PUT /api/pages/:id/share-permission", error);
            res.status(500).json({ error: "공유 허용 설정 업데이트 실패." });
        }
    });

    /**
     * 커버 이미지 업로드
     * POST /api/pages/:id/cover
     */
    router.post("/:id/cover", authMiddleware, coverUpload.single('cover'), async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
			// 업로드 파일 시그니처 검증 (Content-Type 스푸핑 방지)
			const allowed = new Set(['jpg','jpeg','png','gif','webp']);
            const detected = assertImageFileSignature(req.file.path, allowed);
            normalizeUploadedImageFile(req.file, detected.ext);

            const cleanupUpload = () => {
                try {
                    if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                } catch (_) {}
            };

            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id, p.cover_image FROM pages p WHERE p.id = ?`,
                [id]
            );
			if (!rows.length) {
				cleanupUpload();
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // DB 업데이트
            const coverPath = `${userId}/${req.file.filename}`;
            await pool.execute(
                `UPDATE pages SET cover_image = ?, updated_at = NOW() WHERE id = ?`,
                [coverPath, id]
            );

            // WebSocket 브로드캐스트
            wsBroadcastToCollection(rows[0].collection_id, 'metadata-change', {
                pageId: id,
                field: 'coverImage',
                value: coverPath
            }, userId);

            console.log("POST /api/pages/:id/cover 업로드 완료:", coverPath);
            res.json({ coverImage: coverPath });
		} catch (error) {
			try {
                if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            } catch (_) {}

            logError("POST /api/pages/:id/cover", error);
            res.status(500).json({ error: "커버 업로드 실패" });
        }
    });

    /**
     * 커버 이미지 선택/위치 조정
     * PUT /api/pages/:id/cover
     * body: { coverImage?: string, coverPosition?: number }
     */
    router.put("/:id/cover", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { coverImage, coverPosition } = req.body;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id, p.cover_image FROM pages p WHERE p.id = ?`,
                [id]
            );
            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // 업데이트할 필드 결정
            const updates = [];
            const values = [];

           	// coverImage 입력 검증 (IDOR/권한 우회 방지)
            // - default/... 은 공개 기본 커버로 허용
            // - 사용자 업로드 커버는 반드시 본인(userId) 디렉토리의 파일만 허용
            let normalizedCoverImage = coverImage;
            if (coverImage !== undefined) {
                if (coverImage === null || coverImage === '') {
                    normalizedCoverImage = null;
                } else if (typeof coverImage !== 'string') {
                    return res.status(400).json({ error: "coverImage는 문자열이어야 합니다." });
                } else {
                    const trimmed = coverImage.trim();
                    const isDefaultCover = /^default[\\/][^/\\]+\.(?:png|jpe?g|gif|webp)$/i.test(trimmed);
                    if (isDefaultCover) {
                        normalizedCoverImage = trimmed;
                    } else {
                        const m = trimmed.match(/^(\d+)[\\/]([A-Za-z0-9._-]+\.(?:png|jpe?g|gif|webp))$/i);
                        if (!m) return res.status(400).json({ error: "유효하지 않은 coverImage 형식입니다." });
                        const ownerId = parseInt(m[1], 10);
                        const fname = path.basename(m[2]);
                        if (!Number.isFinite(ownerId) || ownerId !== userId)
                            return res.status(403).json({ error: "다른 사용자의 커버 이미지는 선택할 수 없습니다." });
                        const coverFsPath = path.join(__dirname, '..', 'covers', String(userId), fname);
                        if (!fs.existsSync(coverFsPath))
                            return res.status(400).json({ error: "존재하지 않는 커버 이미지입니다." });
                        normalizedCoverImage = `${userId}/${fname}`;
                    }
                }
                updates.push('cover_image = ?');
                values.push(normalizedCoverImage);
            }

            if (typeof coverPosition === 'number') {
                updates.push('cover_position = ?');
                values.push(Math.max(0, Math.min(100, coverPosition)));
            }

            if (updates.length === 0) {
                return res.status(400).json({ error: "업데이트할 데이터 없음" });
            }

            updates.push('updated_at = NOW()');
            values.push(id);

            await pool.execute(
                `UPDATE pages SET ${updates.join(', ')} WHERE id = ?`,
                values
            );

            // WebSocket 브로드캐스트
            if (coverImage !== undefined) {
                wsBroadcastToCollection(rows[0].collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'coverImage',
                    value: normalizedCoverImage
                }, userId);
            }
            if (typeof coverPosition === 'number') {
                wsBroadcastToCollection(rows[0].collection_id, 'metadata-change', {
                    pageId: id,
                    field: 'coverPosition',
                    value: Math.max(0, Math.min(100, coverPosition))
                }, userId);
            }

            console.log("PUT /api/pages/:id/cover 업데이트 완료");
            res.json({ success: true });
        } catch (error) {
            logError("PUT /api/pages/:id/cover", error);
            res.status(500).json({ error: "커버 업데이트 실패" });
        }
    });

    /**
     * 커버 이미지 제거
     * DELETE /api/pages/:id/cover
     */
    router.delete("/:id/cover", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id, p.cover_image FROM pages p WHERE p.id = ?`,
                [id]
            );
            if (!rows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // DB 업데이트 (파일은 삭제하지 않고 사용자 이미지 탭에 유지)
            await pool.execute(
                `UPDATE pages SET cover_image = NULL, cover_position = 50, updated_at = NOW() WHERE id = ?`,
                [id]
            );

            // WebSocket 브로드캐스트
            wsBroadcastToCollection(rows[0].collection_id, 'metadata-change', {
                pageId: id,
                field: 'coverImage',
                value: null
            }, userId);

            console.log("DELETE /api/pages/:id/cover 제거 완료");
            res.json({ success: true });
        } catch (error) {
            logError("DELETE /api/pages/:id/cover", error);
            res.status(500).json({ error: "커버 제거 실패" });
        }
    });

    /**
     * 파일 해시 계산
     */
    function calculateFileHash(filePath) {
        return new Promise((resolve, reject) => {
            const hash = crypto.createHash('md5');
            const stream = fs.createReadStream(filePath);

            stream.on('data', (data) => hash.update(data));
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', (err) => reject(err));
        });
    }

    /**
     * 사용자 폴더에서 같은 해시의 파일 찾기
     */
    async function findDuplicateImage(userImgDir, newFileHash, newFilePath) {
        try {
            const files = fs.readdirSync(userImgDir);

            for (const file of files) {
                const filePath = path.join(userImgDir, file);

                // 새로 업로드된 파일은 제외
                if (filePath === newFilePath) continue;

                // 파일인지 확인
                const stat = fs.statSync(filePath);
                if (!stat.isFile()) continue;

                // 해시 비교
                const existingFileHash = await calculateFileHash(filePath);
                if (existingFileHash === newFileHash) {
                    return file; // 중복 파일명 반환
                }
            }

            return null; // 중복 없음
        } catch (error) {
            console.error('중복 파일 검사 오류:', error);
            return null;
        }
    }

    /**
     * 에디터 이미지 업로드
     * POST /api/pages/:id/editor-image
     */
    router.post("/:id/editor-image", authMiddleware, editorImageUpload.single('image'), async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
			// 업로드 파일 시그니처 검증 (Content-Type 스푸핑 방지)
			const allowed = new Set(['jpg','jpeg','png','gif','webp']);
            const detected = assertImageFileSignature(req.file.path, allowed);
            normalizeUploadedImageFile(req.file, detected.ext);

            const cleanupUpload = () => {
                try {
                    if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                } catch (_) {}
            };

            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id FROM pages p WHERE p.id = ?`,
                [id]
            );
			if (!rows.length) {
				cleanupUpload();
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
			if (!permission || permission === 'READ') {
				cleanupUpload();
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // 업로드된 파일 정보
            const uploadedFilePath = req.file.path;
            const uploadedFileName = req.file.filename;
            const userImgDir = path.dirname(uploadedFilePath);

            // 파일 해시 계산
            const fileHash = await calculateFileHash(uploadedFilePath);

            // 중복 파일 확인
            const duplicateFileName = await findDuplicateImage(userImgDir, fileHash, uploadedFilePath);

            let finalFileName;

            if (duplicateFileName) {
                // 중복 파일이 있으면 새 파일 삭제
                fs.unlinkSync(uploadedFilePath);
                finalFileName = duplicateFileName;
                console.log("POST /api/pages/:id/editor-image 중복 이미지 발견, 기존 파일 사용:", finalFileName);
            } else {
                // 중복이 없으면 새 파일 사용
                finalFileName = uploadedFileName;
                console.log("POST /api/pages/:id/editor-image 새 이미지 업로드 완료:", finalFileName);
            }

            // 이미지 경로 반환
            const imagePath = `${userId}/${finalFileName}`;
            const imageUrl = `/imgs/${imagePath}`;

            res.json({ url: imageUrl });
		} catch (error) {
			try {
                if (req.file?.path && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            } catch (_) {}

            logError("POST /api/pages/:id/editor-image", error);
            res.status(500).json({ error: "이미지 업로드 실패" });
        }
    });

    /**
     * 파일 블록 파일 업로드
     * POST /api/pages/:id/file
     */
    router.post("/:id/file", authMiddleware, fileUpload.single('file'), async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id FROM pages p WHERE p.id = ?`,
                [id]
            );
            if (!rows.length) {
                // 파일이 이미 업로드되었으므로 삭제 (고아 파일 방지)
                if (req.file) fs.unlinkSync(req.file.path);
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const { permission } = await getCollectionPermission(rows[0].collection_id, userId);
            if (!permission || permission === 'READ') {
                // 파일이 이미 업로드되었으므로 삭제
                if (req.file) fs.unlinkSync(req.file.path);
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            if (!req.file) {
                 return res.status(400).json({ error: "파일이 업로드되지 않았습니다." });
            }

            // 업로드된 파일 정보
            const uploadedFilePath = req.file.path;
            const uploadedFileName = req.file.filename;
            const userFileDir = path.dirname(uploadedFilePath);

            // 파일 해시 계산
            const fileHash = await calculateFileHash(uploadedFilePath);

            // 중복 파일 확인 (findDuplicateImage 함수 재사용 가능하지만 이름이...)
            // findDuplicateImage는 해당 디렉토리의 모든 파일을 뒤지므로 파일도 체크 가능
            const duplicateFileName = await findDuplicateImage(userFileDir, fileHash, uploadedFilePath);

            let finalFileName;

            if (duplicateFileName) {
                // 중복 파일이 있으면 새 파일 삭제
                fs.unlinkSync(uploadedFilePath);
                finalFileName = duplicateFileName;
                console.log("POST /api/pages/:id/file 중복 파일 발견, 기존 파일 사용:", finalFileName);
            } else {
                // 중복이 없으면 새 파일 사용
                finalFileName = uploadedFileName;
                console.log("POST /api/pages/:id/file 새 파일 업로드 완료:", finalFileName);
            }

            // 파일 URL 반환
            // /paperclip/:userId/:filename
            const fileUrl = `/paperclip/${userId}/${finalFileName}`;

            // 원본 파일명 (사용자에게 보여줄 이름) - 중복 시에는 기존 파일명(랜덤생성됨)을 쓰게 되는데...
            // 블록에는 "사용자가 올린 원본 이름"을 보여주고 싶지만, 중복 처리 로직 때문에
            // 물리적 파일명은 랜덤해시가 붙어있음.
            // 하지만 클라이언트에서는 req.file.originalname을 알고 있으므로 그걸 쓰면 됨.
            // 단, 중복 파일인 경우 req.file.originalname이 맞는지? 맞음. 방금 올린거니까.

            res.json({
                url: fileUrl,
                filename: req.file.originalname,
                size: req.file.size
            });

        } catch (error) {
            logError("POST /api/pages/:id/file", error);
            // 에러 발생 시 파일 삭제 시도
            if (req.file && fs.existsSync(req.file.path)) {
                try { fs.unlinkSync(req.file.path); } catch (e) {}
            }
            res.status(500).json({ error: "파일 업로드 실패" });
        }
    });

    /**
     * 북마크 메타데이터 추출
     * POST /api/pages/:id/bookmark-metadata
     */
    router.post("/:id/bookmark-metadata", authMiddleware, outboundFetchLimiter, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;
        const { url } = req.body;

        try {
            // 권한 확인
            const [rows] = await pool.execute(
                `SELECT p.collection_id FROM pages p WHERE p.id = ? AND p.user_id = ?`,
                [pageId, userId]
            );
            if (!rows.length) {
                return res.status(404).json({ success: false, error: "페이지를 찾을 수 없습니다." });
            }

            // URL 유효성 검사
            if (!url || typeof url !== 'string') {
                return res.status(400).json({ success: false, error: "유효한 URL을 입력해주세요." });
            }

            let parsedUrl;
            try {
                parsedUrl = new URL(url);
                if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
                    throw new Error('HTTP/HTTPS URL만 지원합니다.');
                }
            } catch (error) {
                return res.status(400).json({ success: false, error: "유효하지 않은 URL입니다." });
            }

            // SSRF 방지: 내부 IP 주소 차단
            const hostname = parsedUrl.hostname.toLowerCase();

            // URL에서 HTML 가져오기
            const axios = require('axios');
            const cheerio = require('cheerio');
			const response = await safeAxiosGet(url, axios, {
            	timeout: 8000,
             	maxBodyLength: 5 * 1024 * 1024,		// 5MB 제한
             	maxContentLength: 5 * 1024 * 1024,	// 5MB 제한
              	headers: {
             		// 페이스북 봇인 척 위장 (해당 방법이 가장 호환성이 좋음) -> Reddit과 같은 클라이언트 측 렌더링(CSR) 페이지 우회용
					// Reddit과 같은 클라이언트 측 렌더링(CSR) 페이지들은 User-Agent를 봇으로 속이면, CSR용 빈 HTML을 제공하는 것이 아니라, 실제 데이터(og:title 등)를 바로 넘겨줌
					'User-Agent': 'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)'
					// 또는 트위터 봇: 'Twitterbot/1.0' -> (페이스북 봇이 안 통할 시)
					// 또는 구글 봇: 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' -> (페이스북, 트위터 봇 둘 다 안 통할 시)
				}
			}, { maxRedirects: 2 });

            // HTML 파싱
            const $ = cheerio.load(response.data);

            // 메타데이터 추출 (우선순위: Open Graph > Twitter Card > 기본 메타태그)
            const ogTitle = $('meta[property="og:title"]').attr('content');
            const twitterTitle = $('meta[name="twitter:title"]').attr('content');
            const pageTitle = $('title').text();

            const ogDesc = $('meta[property="og:description"]').attr('content');
            const twitterDesc = $('meta[name="twitter:description"]').attr('content');
            const metaDesc = $('meta[name="description"]').attr('content');

            const ogImage = $('meta[property="og:image"]').attr('content');
            const twitterImage = $('meta[name="twitter:image"]').attr('content');

            const metadata = {
                url: url,
                title: pageTitle || ogTitle || twitterTitle || '제목 없음',
                description: ogDesc || twitterDesc || metaDesc || '',
                thumbnail: ogImage || twitterImage || ''
            };

            // 상대 URL을 절대 URL로 변환
            if (metadata.thumbnail && !metadata.thumbnail.startsWith('http')) {
                try {
                    metadata.thumbnail = new URL(metadata.thumbnail, parsedUrl.origin).href;
                } catch (error) {
                    metadata.thumbnail = '';
                }
            }

            // 제목/설명 길이 제한
            if (metadata.title && metadata.title.length > 200) {
                metadata.title = metadata.title.substring(0, 197) + '...';
            }
            if (metadata.description && metadata.description.length > 300) {
                metadata.description = metadata.description.substring(0, 297) + '...';
            }

            res.json({ success: true, metadata });

        } catch (error) {
            logError("POST /api/pages/:id/bookmark-metadata", error);
            res.status(500).json({ success: false, error: "메타데이터 추출 실패" });
        }
    });

    /**
     * 북마크 이미지 프록시 (CSP 정책 우회)
     * GET /api/pages/proxy/image?url=...
     */
    router.get("/proxy/image", authMiddleware, outboundFetchLimiter, async (req, res) => {
        const { url } = req.query;

        try {
            // URL 유효성 검사
            if (!url || typeof url !== 'string') {
                return res.status(400).json({ error: "유효한 URL을 입력해주세요." });
            }

            let parsedUrl;
            try {
                parsedUrl = new URL(url);
                if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
                    throw new Error('HTTP/HTTPS URL만 지원합니다.');
                }
            } catch (error) {
                return res.status(400).json({ error: "유효하지 않은 URL입니다." });
            }

            // SSRF 방지: 내부 IP 주소 차단
            const hostname = parsedUrl.hostname.toLowerCase();

            // 이미지 가져오기
            const axios = require('axios');
			const response = await safeAxiosGet(url, axios, {
				timeout: 8000,
				maxBodyLength: 5 * 1024 * 1024,		// 5MB 제한
				maxContentLength: 5 * 1024 * 1024,	// 5MB 제한
				responseType: 'arraybuffer',		// 바이너리로 받기
				headers: {
					'User-Agent': 'Mozilla/5.0 (compatible; NTEOK-Bot/1.0)'
				},
			}, { maxRedirects: 0 });

			// 보안: 프록시 이미지의 엄격한 허용 목록 (SVG 금지)
            const dataBuf = Buffer.isBuffer(response.data) ? response.data : Buffer.from(response.data);
            const detectedMime = detectSafeRasterImageMime(dataBuf);

            if (!detectedMime) {
                // 레스터 이미지가 아닌 다른 모든 종류의 파일 금지
                // (예: image/svg+xml 형식은 문서 열람 시, 스크립트를 실행시킬 수 있는 위험이 있음)
                return res.status(400).json({ error: "지원하지 않는 이미지 형식입니다. (jpeg/png/gif/webp만 허용)" });
            }

            // 캐시 헤더 설정 (1시간)
            res.set('Cache-Control', 'public, max-age=3600');
            res.set('Content-Type', detectedMime);
            res.set('X-Content-Type-Options', 'nosniff');
            res.set('Content-Security-Policy', "default-src 'none'; sandbox");
            res.set('Cross-Origin-Resource-Policy', 'same-origin');

            res.send(dataBuf);
        } catch (error) {
            logError("GET /api/pages/proxy/image", error);
            res.status(500).json({ error: "이미지 프록시 실패" });
        }
    });

    /**
     * 페이지 발행 상태 확인
     * GET /api/pages/:id/publish
     */
    router.get("/:id/publish", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;

        try {
            const [pageRows] = await pool.execute(
                `SELECT p.id, p.user_id, p.collection_id, p.is_encrypted
                 FROM pages p WHERE p.id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];
            const { permission } = await getCollectionPermission(page.collection_id, userId);
            if (!permission) {
                return res.status(403).json({ error: "권한이 없습니다." });
			}

			// 보안: 발행 토큰(token)은 페이지 소유자(또는 ADMIN)에게만 공개
			// - 공유받은 READ/EDIT 사용자는 published 여부만 알 수 있도록 제한
			const isOwner = page.user_id === userId;
			const isAdmin = permission === "ADMIN";

            const [publishRows] = await pool.execute(
                `SELECT token, created_at, allow_comments FROM page_publish_links
                 WHERE page_id = ? AND is_active = 1`,
                [pageId]
            );

            if (publishRows.length === 0)
                return res.json({ published: false });

            const publish = publishRows[0];

            // 소유자/ADMIN이 아니면 token/url 노출 금지
            if (!isOwner && !isAdmin)
                return res.json({ published: true });

            return res.json({
                published: true,
                token: publish.token,
                url: `${process.env.BASE_URL || "https://localhost:3000"}/shared/page/${publish.token}`,
                createdAt: toIsoString(publish.created_at),
                allowComments: publish.allow_comments === 1
            });

        } catch (error) {
            logError("GET /api/pages/:id/publish", error);
            res.status(500).json({ error: "발행 상태 확인 실패" });
        }
    });

    /**
     * 페이지 발행
     * POST /api/pages/:id/publish
     */
    router.post("/:id/publish", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;
        // 발행 시 댓글 허용 여부 설정 (기본값 false)
        const allowComments = req.body.allowComments === true;

        try {
            const [pageRows] = await pool.execute(
                `SELECT id, user_id, is_encrypted FROM pages WHERE id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            const page = pageRows[0];

            if (page.user_id !== userId) {
                return res.status(403).json({ error: "페이지 소유자만 발행할 수 있습니다." });
            }

            if (page.is_encrypted === 1) {
                return res.status(400).json({
                    error: "암호화된 페이지는 발행할 수 없습니다."
                });
            }

            // 이미 발행된 경우 확인
            const [existingRows] = await pool.execute(
                `SELECT token FROM page_publish_links
                 WHERE page_id = ? AND is_active = 1`,
                [pageId]
            );

            if (existingRows.length > 0) {
                // 이미 발행됨 -> 설정 업데이트
                const token = existingRows[0].token;
                await pool.execute(
                    `UPDATE page_publish_links
                     SET allow_comments = ?, updated_at = NOW()
                     WHERE page_id = ? AND is_active = 1`,
                    [allowComments ? 1 : 0, pageId]
                );

                const url = `${process.env.BASE_URL || "https://localhost:3000"}/shared/page/${token}`;
                return res.json({ ok: true, token, url, allowComments });
            }

            // 새 토큰 생성
            const token = generatePublishToken();
            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `INSERT INTO page_publish_links
                 (token, page_id, owner_user_id, is_active, created_at, updated_at, allow_comments)
                 VALUES (?, ?, ?, 1, ?, ?, ?)`,
                [token, pageId, userId, nowStr, nowStr, allowComments ? 1 : 0]
            );

            const url = `${process.env.BASE_URL || "https://localhost:3000"}/shared/page/${token}`;
            // 보안: 토큰 일부만 표시
            console.log(`POST /api/pages/:id/publish 발행 완료: ${pageId}, 토큰: ${token.substring(0, 8)}...`);

            res.json({ ok: true, token, url, allowComments });

        } catch (error) {
            logError("POST /api/pages/:id/publish", error);
            res.status(500).json({ error: "페이지 발행 실패" });
        }
    });

    /**
     * 페이지 발행 취소
     * DELETE /api/pages/:id/publish
     */
    router.delete("/:id/publish", authMiddleware, async (req, res) => {
        const pageId = req.params.id;
        const userId = req.user.id;

        try {
            const [pageRows] = await pool.execute(
                `SELECT id, user_id FROM pages WHERE id = ?`,
                [pageId]
            );

            if (!pageRows.length) {
                return res.status(404).json({ error: "페이지를 찾을 수 없습니다." });
            }

            if (pageRows[0].user_id !== userId) {
                return res.status(403).json({ error: "페이지 소유자만 발행을 취소할 수 있습니다." });
            }

            const now = new Date();
            const nowStr = formatDateForDb(now);

            await pool.execute(
                `UPDATE page_publish_links
                 SET is_active = 0, updated_at = ?
                 WHERE page_id = ? AND is_active = 1`,
                [nowStr, pageId]
            );

            console.log("DELETE /api/pages/:id/publish 발행 취소 완료:", pageId);
            res.json({ ok: true });

        } catch (error) {
            logError("DELETE /api/pages/:id/publish", error);
            res.status(500).json({ error: "발행 취소 실패" });
        }
    });

    return router;
};
