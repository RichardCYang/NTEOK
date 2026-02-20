const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const dns = require("node:dns").promises;
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const ipaddr = require("ipaddr.js");
const { assertImageFileSignature } = require("../security-utils.js");
const { validateAndNormalizeIcon } = require("../utils/icon-utils.js");

const erl = require("express-rate-limit");
const rateLimit = erl.rateLimit || erl;
const { ipKeyGenerator } = erl;

// cover_image는 UI에서 `/covers/${coverImage}` 형태로 쓰이므로
// "default/<file>" 또는 "<userId>/<file>"만 허용 (저장형 CSS Injection 차단)
function validateCoverImageRef(ref, currentUserId) {
    if (ref === null || ref === '') return { ok: true, value: null };
    if (typeof ref !== 'string') return { ok: false, error: 'coverImage 형식이 올바르지 않습니다.' };

    const s = ref.trim();
    if (s.length < 3 || s.length > 260) return { ok: false, error: 'coverImage 길이가 비정상입니다.' };
    if (/[\x00-\x1F\x7F]/.test(s)) return { ok: false, error: 'coverImage에 제어문자를 사용할 수 없습니다.' };

    const parts = s.split('/');
    if (parts.length !== 2) return { ok: false, error: 'coverImage 형식이 올바르지 않습니다.' };
    const [scope, filename] = parts;

    const isDefault = scope === 'default';
    const isUser = /^\d{1,12}$/.test(scope) && String(scope) === String(currentUserId);
    if (!isDefault && !isUser) return { ok: false, error: 'coverImage 범위가 허용되지 않습니다.' };

    // filename: 슬래시 불가(이미 split), path traversal/문자열 주입 방지
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(filename)) return { ok: false, error: 'coverImage 파일명이 올바르지 않습니다.' };
    if (filename.includes('..') || /["'()\\]/.test(filename)) return { ok: false, error: 'coverImage 파일명에 허용되지 않는 문자가 포함되어 있습니다.' };
    // 확장자 allowlist(커버 업로드 정책과 일치)
    if (!/\.(?:jpe?g|png|gif|webp)$/i.test(filename)) return { ok: false, error: '허용되지 않는 커버 이미지 확장자입니다.' };

    return { ok: true, value: `${scope}/${filename}` };
}

module.exports = (dependencies) => {
    const {
		pool,
		pagesRepo,
        storagesRepo,
        pageSqlPolicy,
        authMiddleware,
        toIsoString,
		sanitizeInput,
		sanitizeFilenameComponent,
        sanitizeExtension,
        sanitizeHtmlContent,
        generatePageId,
        formatDateForDb,
        wsBroadcastToStorage,
        logError,
        generatePublishToken,
        coverUpload,
        editorImageUpload,
        themeUpload,
        fileUpload,
        path,
        fs,
        yjsDocuments,
        isPrivateOrLocalIP,
        getClientIpFromRequest
	} = dependencies;

    function getClientIp(req) {
        return (
            req.clientIp ||
            (typeof getClientIpFromRequest === 'function' ? getClientIpFromRequest(req) : null) ||
            req.ip ||
            req.connection?.remoteAddress ||
            req.socket?.remoteAddress ||
            'unknown'
        );
    }

    /**
     * 보안: 암호화(is_encrypted=1) + 공유불가(share_allowed=0) 페이지는 작성자만 접근 가능해야 함
     * - 기존에는 일부 Write 엔드포인트가 pool.execute("SELECT * FROM pages WHERE id=?")로 직접 로드하여
     * - pageSqlPolicy(가시성 정책)를 우회 → 권한우회(Broken Access Control) 발생
     * - 모든 mutation 전에 pagesRepo.getPageByIdForUser()로 객체 단위 권한 검증을 통일
     */
    async function loadPageForMutationOr404(userId, pageId, res) {
        const page = await pagesRepo.getPageByIdForUser({ userId, pageId });
        if (!page) {
            // 존재 여부 최소화: 숨김 페이지도 동일하게 404
            res.status(404).json({ error: "Not found" });
            return null;
        }
        return page;
    }

	function normalizeUploadedImageFile(fileObj, detectedExt) {
	    if (!fileObj?.path || !fileObj?.filename) throw new Error('INVALID_UPLOAD');
	    const ext = `.${String(detectedExt || '').toLowerCase()}`;
		const safeExt = sanitizeExtension(ext);
	    if (!safeExt || !['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(safeExt)) throw new Error('UNSUPPORTED_IMAGE_TYPE');
	    const dir = path.dirname(fileObj.path);
	    const rawBase = path.basename(fileObj.filename, path.extname(fileObj.filename));
	    const base = sanitizeFilenameComponent(rawBase, 80).replace(/[^a-zA-Z0-9._-]/g, '') || crypto.randomBytes(8).toString('hex');
	    let newFilename = `${base}${safeExt}`;
		let newPath = path.join(dir, newFilename);
	    if (fs.existsSync(newPath)) { const suffix = crypto.randomBytes(4).toString('hex'); newFilename = `${base}-${suffix}${safeExt}`; newPath = path.join(dir, newFilename); }
	    const resolvedDir = path.resolve(dir) + path.sep;
		const resolvedNewPath = path.resolve(newPath);
	    if (!resolvedNewPath.startsWith(resolvedDir)) throw new Error('PATH_TRAVERSAL_BLOCKED');
	    if (newPath !== fileObj.path) { fs.renameSync(fileObj.path, newPath); fileObj.path = newPath; fileObj.filename = newFilename; }
	}

	function wsPageVisibilityFromRow(row) {
		const ownerUserId = Number(row && row.user_id);
		return { ownerUserId, isEncrypted: Boolean(row && row.is_encrypted === 1), shareAllowed: Boolean(row && row.share_allowed === 1) };
	}

    const outboundProxyLimiter = rateLimit({
        windowMs: 60 * 1000,
        max: 30,
        keyGenerator: (req) => { const uid = req.user?.id ? String(req.user.id) : "anon"; const rawIp = getClientIp(req); const ipKey = rawIp && rawIp !== 'unknown' ? ipKeyGenerator(rawIp, 56) : "noip"; return `outbound:${uid}:${ipKey}`; },
        handler: (req, res) => res.status(429).json({ error: "Too many requests" }),
    });

    /**
     * SSRF 방어: URL 파싱/포트/프로토콜 검증 + userinfo 차단
     * - dns.lookup(all:true)는 OS resolver(/etc/hosts 포함) + A/AAAA 모두 반영
     * - resolve/검증 후 실제 요청 시 lookup을 핀닝하여 DNS rebinding(TOCTOU)을 완화
     */
    const OUTBOUND_ALLOWED_PORTS = (() => {
        const raw = String(process.env.OUTBOUND_HTTP_ALLOWED_PORTS || "80,443")
            .split(",")
            .map(s => s.trim())
            .filter(Boolean);

        const set = new Set();
        for (const p of raw) {
            const n = Number.parseInt(p, 10);
            if (Number.isFinite(n) && n > 0 && n < 65536) set.add(n);
        }
        if (set.size === 0) { set.add(80); set.add(443); }
        return set;
    })();

    const OUTBOUND_DNS_LOOKUP_TIMEOUT_MS = (() => {
        const n = Number.parseInt(process.env.OUTBOUND_DNS_LOOKUP_TIMEOUT_MS || "1500", 10);
        if (!Number.isFinite(n)) return 1500;
        return Math.max(200, Math.min(5000, n));
    })();

    function isRedirectStatus(code) {
        return code === 301 || code === 302 || code === 303 || code === 307 || code === 308;
    }

    async function dnsLookupAll(hostname) {
        const p = dns.lookup(hostname, { all: true, verbatim: true });
        const t = new Promise((_, reject) =>
            setTimeout(() => reject(new Error("DNS lookup timeout")), OUTBOUND_DNS_LOOKUP_TIMEOUT_MS)
        );
        return Promise.race([p, t]);
    }

    function normalizedDefaultPort(u) {
        if (u.port) {
            const n = Number.parseInt(u.port, 10);
            return Number.isFinite(n) ? n : null;
        }
        return u.protocol === "https:" ? 443 : 80;
    }

    function makePinnedLookup(address, family) {
        return (hostname, options, callback) => {
            const cb = typeof options === "function" ? options : callback;
            const opts = typeof options === "object" ? options : {};

            if (opts.all) {
                process.nextTick(() => cb(null, [{ address, family }]));
            } else {
                process.nextTick(() => cb(null, address, family));
            }
        };
    }

    async function validateOutboundUrl(urlStr) {
        if (typeof urlStr !== "string") throw new Error("Invalid URL");
        const trimmed = urlStr.trim();
        if (!trimmed) throw new Error("Invalid URL");
        if (trimmed.length > 2048) throw new Error("URL is too long");

        let u;
        try { u = new URL(trimmed); } catch { throw new Error("Invalid URL"); }

        if (u.protocol !== "http:" && u.protocol !== "https:")
            throw new Error("Only http/https allowed");

        // userinfo (username:password@host) 차단
        if (u.username || u.password)
            throw new Error("Userinfo in URL is not allowed");

        const port = normalizedDefaultPort(u);
        if (!port || !OUTBOUND_ALLOWED_PORTS.has(port))
            throw new Error("Port is not allowed");

        const hostname = u.hostname;
        if (!hostname) throw new Error("Invalid hostname");

        const ipFamily = net.isIP(hostname);
        if (ipFamily) {
            if (isPrivateOrLocalIP(hostname)) throw new Error("Private/local IP is not allowed");
            return { url: u, lookup: makePinnedLookup(hostname, ipFamily) };
        }

        let addrs;
        try {
            addrs = await dnsLookupAll(hostname);
        } catch {
            throw new Error("Failed to resolve hostname");
        }

        if (!Array.isArray(addrs) || addrs.length === 0)
            throw new Error("Failed to resolve hostname");

        for (const a of addrs) {
            const ip = a?.address;
            if (!ip || isPrivateOrLocalIP(ip))
                throw new Error("Private/local IP is not allowed");
        }

        const pinned = addrs[0];
        const fam = pinned.family || net.isIP(pinned.address) || 0;
        return { url: u, lookup: makePinnedLookup(pinned.address, fam) };
    }

    const METADATA_FETCH_TIMEOUT_MS = (() => {
        const n = Number.parseInt(process.env.METADATA_FETCH_TIMEOUT_MS || "5000", 10);
        if (!Number.isFinite(n)) return 5000;
        return Math.max(1000, Math.min(15000, n));
    })();

    const METADATA_MAX_BYTES = (() => {
        const n = Number.parseInt(process.env.METADATA_MAX_BYTES || String(512 * 1024), 10); // 512KB
        if (!Number.isFinite(n)) return 512 * 1024;
        return Math.max(32 * 1024, Math.min(2 * 1024 * 1024, n));
    })();

    const METADATA_MAX_REDIRECTS = (() => {
        const n = Number.parseInt(process.env.METADATA_MAX_REDIRECTS || "3", 10);
        if (!Number.isFinite(n)) return 3;
        return Math.max(0, Math.min(10, n));
    })();

    async function getMetadata(urlStr) {
        let current = urlStr;

        for (let i = 0; i <= METADATA_MAX_REDIRECTS; i++) {
            const { url, lookup } = await validateOutboundUrl(current);

            const result = await new Promise((resolve, reject) => {
                const protocol = url.protocol === "https:" ? https : http;

                const req = protocol.get(url, {
                    timeout: METADATA_FETCH_TIMEOUT_MS,
                    lookup,
                    headers: {
                        'User-Agent': 'NTEOK-MetadataFetcher/1.0',
                        'Accept': 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1'
                    }
                }, (res) => {
                    const status = res.statusCode || 0;

                    if (isRedirectStatus(status) && res.headers.location) {
                        res.resume();
                        try {
                            const nextUrl = new URL(res.headers.location, url);
                            return resolve({ redirectTo: nextUrl.toString() });
                        } catch {
                            return reject(new Error("Invalid redirect URL"));
                        }
                    }

                    if (status < 200 || status >= 300) {
                        res.resume();
                        return reject(new Error(`Failed to fetch metadata (status: ${status})`));
                    }

                    const ct = String(res.headers['content-type'] || '').toLowerCase();
                    if (!(ct.includes('text/html') || ct.includes('application/xhtml+xml'))) {
                        res.resume();
                        return reject(new Error("Unsupported content-type for metadata"));
                    }

                    let size = 0;
                    const chunks = [];

                    res.on('data', (chunk) => {
                        size += chunk.length;
                        if (size > METADATA_MAX_BYTES) {
                            res.destroy(new Error("Metadata response too large"));
                            return;
                        }
                        chunks.push(chunk);
                    });
                    res.on('end', () => resolve({ body: Buffer.concat(chunks).toString('utf8') }));
                    res.on('error', reject);
                });

                req.on('error', reject);
                req.on('timeout', () => {
                    req.destroy(new Error("Metadata request timeout"));
                });
            });

            if (result?.redirectTo) {
                if (i === METADATA_MAX_REDIRECTS) throw new Error("Too many redirects");
                current = result.redirectTo;
                continue;
            }

            const html = result.body || "";
            const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
            const descMatch = html.match(/<meta\s+name=["']description["']\s+content=["']([^"']+)["']/i);
            const ogImageMatch = html.match(/<meta\s+property=["']og:image["']\s+content=["']([^"']+)["']/i);

            return {
                title: titleMatch ? titleMatch[1].trim() : '',
                description: descMatch ? descMatch[1].trim() : '',
                thumbnail: ogImageMatch ? ogImageMatch[1].trim() : ''
            };
        }

        throw new Error("Too many redirects");
    }

    function blockCrossSiteFetch(req, res, next) {
        const sfs = String(req.headers["sec-fetch-site"] || "").toLowerCase();
        if (sfs && !["same-origin", "same-site", "none"].includes(sfs)) return res.status(403).json({ error: "Forbidden" });
        return next();
    }

    router.get("/covers/user", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        try {
            const userCoversDir = path.join(__dirname, '..', 'covers', String(userId));
            if (!fs.existsSync(userCoversDir)) return res.json([]);
            const files = fs.readdirSync(userCoversDir);
            const covers = files.filter(f => ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(path.extname(f).toLowerCase()))
                .map(f => { const stats = fs.statSync(path.join(userCoversDir, f)); return { path: `${userId}/${f}`, filename: f, uploadedAt: stats.birthtime.toISOString() }; })
                .sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
            res.json(covers);
        } catch (error) { logError("GET /api/pages/covers/user", error); res.status(500).json({ error: "Failed" }); }
    });

    router.get("/", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = typeof req.query.storageId === "string" ? req.query.storageId.trim() : null;
            const rows = await pagesRepo.listPagesForUser({ userId, storageId });
            const list = rows.map((row) => ({
                id: row.id, title: row.title || "제목 없음", updatedAt: toIsoString(row.updated_at), parentId: row.parent_id,
                sortOrder: row.sort_order, storageId: row.storage_id, isEncrypted: row.is_encrypted ? true : false,
                shareAllowed: row.share_allowed ? true : false, userId: row.user_id, icon: row.icon || null,
                coverImage: row.cover_image || null, coverPosition: row.cover_position || 50, horizontalPadding: row.horizontal_padding || null
            }));
            res.json(list);
        } catch (error) { logError("GET /api/pages", error); res.status(500).json({ error: "Failed" }); }
    });

    router.get("/history", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        const storageId = typeof req.query.storageId === "string" ? req.query.storageId.trim() : null;
        if (!storageId) return res.status(400).json({ error: "storageId required" });
        try {
            const history = await pagesRepo.getUpdateHistory({ userId, storageId });
            res.json(history.map(h => ({
                id: h.id,
                userId: h.user_id,
                username: h.username,
                pageId: h.page_id,
                pageTitle: h.page_title,
                action: h.action,
                details: h.details ? JSON.parse(h.details) : null,
                createdAt: toIsoString(h.created_at)
            })));
        } catch (error) {
            logError("GET /api/pages/history", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    // 휴지통 목록 조회
    router.get("/trash", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const storageId = typeof req.query.storageId === "string" ? req.query.storageId.trim() : null;
            if (!storageId) return res.status(400).json({ error: "storageId required" });

            const pages = await pagesRepo.listTrashedPagesForUser({ userId, storageId });
            res.json(pages.map(p => ({
                id: p.id,
                title: p.title || "제목 없음",
                updatedAt: toIsoString(p.updated_at),
                deletedAt: toIsoString(p.deleted_at),
                storageId: p.storage_id,
                userId: p.user_id
            })));
        } catch (e) {
            logError("GET /api/pages/trash", e);
            res.status(500).json({ error: "Failed" });
        }
    });

    router.get("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
           	const row = await pagesRepo.getPageByIdForUser({ userId, pageId: id });
            if (!row) return res.status(404).json({ error: "Not found" });
            res.json({
                id: row.id, title: row.title || "제목 없음", content: sanitizeHtmlContent(row.content || "<p></p>"),
                encryptionSalt: row.encryption_salt, encryptedContent: row.encrypted_content,
                createdAt: toIsoString(row.created_at), updatedAt: toIsoString(row.updated_at),
                parentId: row.parent_id, sortOrder: row.sort_order, storageId: row.storage_id,
                isEncrypted: row.is_encrypted ? true : false, shareAllowed: row.share_allowed ? true : false,
                userId: row.user_id, icon: row.icon || null, coverImage: row.cover_image || null,
                coverPosition: row.cover_position || 50, horizontalPadding: row.horizontal_padding || null
            });
        } catch (error) { logError("GET /api/pages/:id", error); res.status(500).json({ error: "Failed" }); }
    });

    router.post("/", authMiddleware, async (req, res) => {
        const title = sanitizeInput(String(req.body.title || "제목 없음").trim());
        const storageId = req.body.storageId;
        if (!storageId) return res.status(400).json({ error: "storageId required" });
        const userId = req.user.id;
        const now = new Date();
        const id = generatePageId(now);
        const nowStr = formatDateForDb(now);
        try {
            const permission = await storagesRepo.getPermission(userId, storageId);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                return res.status(403).json({ error: "이 저장소에 페이지를 생성할 권한이 없습니다." });
            }
            const parentId = req.body.parentId || null;
            const sortOrder = req.body.sortOrder || 0;
            const isEncrypted = req.body.isEncrypted === true ? 1 : 0;
            const salt = req.body.encryptionSalt || null;
            const encContent = req.body.encryptedContent || null;
            const content = isEncrypted ? '' : sanitizeHtmlContent(req.body.content || "<p></p>");
            if (isEncrypted && (!salt || !encContent)) return res.status(400).json({ error: "Encryption fields missing" });
            await pool.execute(`INSERT INTO pages (id, user_id, parent_id, title, content, sort_order, created_at, updated_at, storage_id, is_encrypted, encryption_salt, encrypted_content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, userId, parentId, title, content, sortOrder, nowStr, nowStr, storageId, isEncrypted, salt, encContent]);

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId,
                pageId: id,
                action: 'CREATE_PAGE',
                details: { title }
            });

            res.status(201).json({ id, title, storageId, parentId, isEncrypted: !!isEncrypted, updatedAt: now.toISOString() });
        } catch (e) { logError("POST /api/pages", e); res.status(500).json({ error: "Failed" }); }
    });

    router.put("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                return res.status(403).json({ error: "이 페이지를 수정할 권한이 없습니다." });
            }

            const title = req.body.title !== undefined ? sanitizeInput(req.body.title) : existing.title;
            const isEncrypted = req.body.isEncrypted !== undefined ? (req.body.isEncrypted ? 1 : 0) : existing.is_encrypted;
            const salt = req.body.encryptionSalt || existing.encryption_salt;
            const encContent = req.body.encryptedContent || existing.encrypted_content;
            const content = isEncrypted ? '' : (req.body.content !== undefined ? sanitizeHtmlContent(req.body.content) : existing.content);
            const icon = req.body.icon !== undefined ? validateAndNormalizeIcon(req.body.icon) : existing.icon;
            const hPadding = req.body.horizontalPadding !== undefined ? req.body.horizontalPadding : existing.horizontal_padding;
            const nowStr = formatDateForDb(new Date());
            let sql = `UPDATE pages SET title=?, content=?, is_encrypted=?, encryption_salt=?, encrypted_content=?, icon=?, horizontal_padding=?, updated_at=?`;
            const params = [title, content, isEncrypted, salt, encContent, icon, hPadding, nowStr];
            // 보안: 암호화 페이지는 서버/DB 어디에도 평문이 남지 않아야 함
            // - yjs_state는 협업 편집 상태(전체 문서 스냅샷)를 그대로 담을 수 있어(평문 잔존) 암호화 보안을 훼손
            // - 따라서 (1) 콘텐츠가 직접 업데이트되거나, (2) 암호화 상태가 바뀌거나, (3) 암호화 상태인 경우에는
            //   yjs_state를 항상 초기화하고, 서버 메모리의 Yjs 문서도 drop
            const encryptionStateChanged = Number(existing.is_encrypted) !== Number(isEncrypted);
            const shouldResetYjsState = (req.body.content !== undefined) || encryptionStateChanged || (Number(isEncrypted) === 1);
            if (shouldResetYjsState) {
                sql += `, yjs_state=NULL`;
                if (yjsDocuments && yjsDocuments.has(id)) yjsDocuments.delete(id);
            }
            sql += ` WHERE id=?`; params.push(id);
            await pool.execute(sql, params);

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: existing.storage_id,
                pageId: id,
                action: 'UPDATE_PAGE',
                details: { title }
            });

            wsBroadcastToStorage(existing.storage_id, 'metadata-change', { pageId: id, field: 'title', value: title }, null, { pageVisibility: wsPageVisibilityFromRow(existing) });
            res.json({ id, title, updatedAt: new Date().toISOString() });
        } catch (e) { logError("PUT /api/pages/:id", e); res.status(500).json({ error: "Failed" }); }
    });

    router.patch("/reorder", authMiddleware, async (req, res) => {
        const { storageId, pageIds, parentId } = req.body;
        const userId = req.user.id;
        try {
            const permission = await storagesRepo.getPermission(userId, storageId);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                return res.status(403).json({ error: "이 저장소의 페이지 순서를 변경할 권한이 없습니다." });
            }
            for (let i = 0; i < pageIds.length; i++) { await pool.execute(`UPDATE pages SET sort_order=?, updated_at=NOW() WHERE id=? AND storage_id=?`, [i * 10, pageIds[i], storageId]); }

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId,
                action: 'REORDER_PAGES',
                details: { parentId, count: pageIds.length }
            });

            wsBroadcastToStorage(storageId, 'pages-reordered', { parentId, pageIds }, userId);
            res.json({ ok: true });
        } catch (e) { logError("PATCH /api/pages/reorder", e); res.status(500).json({ error: "Failed" }); }
    });

    // 페이지 복구
    router.post("/:id/restore", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const { id } = req.params;

            const page = await pagesRepo.getPageByIdForUser({ userId, pageId: id, includeDeleted: true });
            if (!page) return res.status(404).json({ error: "Not found" });

            const permission = await storagesRepo.getPermission(userId, page.storage_id);
            if (!permission) {
                return res.status(403).json({ error: "이 페이지를 복구할 권한이 없습니다." });
            }

            const isOwnerOfPage = Number(page.user_id) === Number(userId);
            const canRestore =
                permission === 'ADMIN' ||
                (permission === 'EDIT' && isOwnerOfPage);

            if (!canRestore) {
                return res.status(403).json({
                    error: "이 페이지를 복구할 권한이 없습니다. (ADMIN 또는 본인 작성 페이지만 복구 가능)"
                });
            }

            await pagesRepo.restorePageAndDescendants({
                rootPageId: id,
                storageId: page.storage_id,
                actorUserId: userId,
                isAdmin: permission === 'ADMIN'
            });

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: page.storage_id,
                pageId: id,
                action: 'RESTORE_PAGE',
                details: { title: page.title }
            });

            res.json({ ok: true });
        } catch (e) {
            logError("POST /api/pages/:id/restore", e);
            res.status(500).json({ error: "Failed" });
        }
    });

    // 페이지 영구 삭제
    router.delete("/:id/permanent", authMiddleware, async (req, res) => {
        try {
            const userId = req.user.id;
            const { id } = req.params;

            const page = await pagesRepo.getPageByIdForUser({ userId, pageId: id, includeDeleted: true });
            if (!page) return res.status(404).json({ error: "Not found" });

            const permission = await storagesRepo.getPermission(userId, page.storage_id);
            if (!permission) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            const isOwnerOfPage = Number(page.user_id) === Number(userId);
            const canDelete =
                permission === 'ADMIN' ||
                (permission === 'EDIT' && isOwnerOfPage);

            if (!canDelete) {
                return res.status(403).json({ error: "이 페이지를 영구 삭제할 권한이 없습니다." });
            }

            await pagesRepo.permanentlyDeletePage(id, userId);

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: page.storage_id,
                pageId: id,
                action: 'PERMANENT_DELETE_PAGE',
                details: { title: page.title }
            });

            res.json({ ok: true });
        } catch (e) {
            logError("DELETE /api/pages/:id/permanent", e);
            res.status(500).json({ error: "Failed" });
        }
    });

    router.delete("/:id", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission) {
                return res.status(403).json({ error: "이 페이지를 삭제할 권한이 없습니다." });
            }

            /**
             * 권한 정책 강화 (Broken Access Control 방지)
             * - ADMIN: 어떤 페이지든 삭제 가능
             * - EDIT : 본인이 작성한 페이미 삭제 가능
             * - READ : 삭제 불가
             */
            const isOwnerOfPage = Number(existing.user_id) === Number(userId);
            const canDelete =
                permission === 'ADMIN' ||
                (permission === 'EDIT' && isOwnerOfPage);

            if (!canDelete) {
                return res.status(403).json({
                    error: "이 페이지를 삭제할 권한이 없습니다. (ADMIN 또는 본인 작성 페이지만 삭제 가능)"
                });
            }

            // Soft delete: 자신과 모든 하위 페이지의 deleted_at 설정
            await pagesRepo.softDeletePageAndDescendants({
                rootPageId: id,
                storageId: existing.storage_id,
                rootParentId: existing.parent_id || null,
                actorUserId: userId,
                isAdmin: permission === 'ADMIN'
            });

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: existing.storage_id,
                pageId: id,
                action: 'DELETE_PAGE',
                details: { title: existing.title }
            });

            res.json({ ok: true });
        } catch (e) { logError("DELETE /api/pages/:id", e); res.status(500).json({ error: "Failed" }); }
    });

    router.delete("/covers/:filename", authMiddleware, async (req, res) => {
        const userId = req.user.id;
        const filename = path.basename(req.params.filename);
        try {
            const baseDir = path.resolve(__dirname, '..', 'covers', String(userId));
            const targetPath = path.resolve(baseDir, filename);
            const rel = path.relative(baseDir, targetPath);

            if (rel.startsWith("..") || path.isAbsolute(rel)) {
                return res.status(400).json({ error: "Invalid filename" });
            }

            if (fs.existsSync(targetPath)) {
                const st = fs.statSync(targetPath);
                if (st.isFile()) fs.unlinkSync(targetPath);
            }
            res.json({ ok: true });
        } catch (error) {
            logError("DELETE /api/pages/covers/:filename", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    router.put("/:id/cover", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                return res.status(403).json({ error: "Forbidden" });
            }

            let coverImage = existing.cover_image;
            if (req.body.coverImage !== undefined) {
                const v = validateCoverImageRef(req.body.coverImage, userId);
                if (!v.ok) return res.status(400).json({ error: v.error });
                coverImage = v.value;
            }

            let coverPosition = existing.cover_position;
            if (req.body.coverPosition !== undefined) {
                const n = Number(req.body.coverPosition);
                if (!Number.isFinite(n)) return res.status(400).json({ error: "coverPosition 형식이 올바르지 않습니다." });
                const clamped = Math.max(0, Math.min(100, Math.round(n)));
                coverPosition = clamped;
            }

            await pool.execute(`UPDATE pages SET cover_image=?, cover_position=?, updated_at=NOW() WHERE id=?`, [coverImage, coverPosition, id]);

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: existing.storage_id,
                pageId: id,
                action: 'UPDATE_COVER',
                details: { coverImage, coverPosition }
            });

            if (req.body.coverImage !== undefined) {
                wsBroadcastToStorage(existing.storage_id, 'metadata-change', { pageId: id, field: 'coverImage', value: coverImage }, null, { pageVisibility: wsPageVisibilityFromRow(existing) });
            }
            if (req.body.coverPosition !== undefined) {
                wsBroadcastToStorage(existing.storage_id, 'metadata-change', { pageId: id, field: 'coverPosition', value: coverPosition }, null, { pageVisibility: wsPageVisibilityFromRow(existing) });
            }

            res.json({ ok: true });
        } catch (error) {
            logError("PUT /api/pages/:id/cover", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    router.post("/:id/cover", authMiddleware, coverUpload.single('cover'), async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        if (!req.file) return res.status(400).json({ error: "No file uploaded" });

        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) {
                if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                return;
            }

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                return res.status(403).json({ error: "Forbidden" });
            }

            const sig = await assertImageFileSignature(req.file.path);
            normalizeUploadedImageFile(req.file, sig.ext);

            const coverPath = `${userId}/${req.file.filename}`;
            await pool.execute(`UPDATE pages SET cover_image=?, cover_position=50, updated_at=NOW() WHERE id=?`, [coverPath, id]);

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: existing.storage_id,
                pageId: id,
                action: 'UPDATE_COVER',
                details: { coverImage: coverPath }
            });

            wsBroadcastToStorage(existing.storage_id, 'metadata-change', { pageId: id, field: 'coverImage', value: coverPath }, null, { pageVisibility: wsPageVisibilityFromRow(existing) });

            res.json({ coverImage: coverPath });
        } catch (error) {
            if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            logError("POST /api/pages/:id/cover", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    router.delete("/:id/cover", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                return res.status(403).json({ error: "Forbidden" });
            }

            await pool.execute(`UPDATE pages SET cover_image=NULL, updated_at=NOW() WHERE id=?`, [id]);

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: existing.storage_id,
                pageId: id,
                action: 'DELETE_COVER',
                details: null
            });

            wsBroadcastToStorage(existing.storage_id, 'metadata-change', { pageId: id, field: 'coverImage', value: null }, null, { pageVisibility: wsPageVisibilityFromRow(existing) });

            res.json({ ok: true });
        } catch (error) {
            logError("DELETE /api/pages/:id/cover", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    router.post("/:id/file", authMiddleware, fileUpload.single('file'), async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        if (!req.file) return res.status(400).json({ error: "No file uploaded" });

        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) {
                if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                return;
            }

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                return res.status(403).json({ error: "Forbidden" });
            }

            // 보안: 파일 시그니처 검증 (이미지인 경우) 및 파일명 정규화
            const ext = path.extname(req.file.originalname).toLowerCase();
            const isImageExt = ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext);

            if (isImageExt) {
                const sig = await assertImageFileSignature(req.file.path).catch(() => null);
                if (sig) normalizeUploadedImageFile(req.file, sig.ext);
            }

            const fileUrl = `/paperclip/${userId}/${req.file.filename}`;

            res.json({
                url: fileUrl,
                filename: req.file.originalname,
                size: req.file.size
            });
        } catch (error) {
            if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            logError("POST /api/pages/:id/file", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    // paperclip URL/filename 검증(경로 조작 방지)
    // - /paperclip/<userId>/<storedFilename> 형태만 허용
    // - storedFilename은 업로드 저장 규칙(서버에서 생성)과 일치하는 안전한 문자만 허용
    const PAPERCLIP_PATH_RE = /^\/paperclip\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/;
    function parsePaperclipPathFromUserInput(raw) {
        if (typeof raw !== "string") return null;
        const s = raw.trim();
        if (!s) return null;

        // 절대 URL이 들어와도 pathname만 추출 (호스트/스킴 무시)
        let pathname = s;
        try {
            // base는 어떤 값이든 무방(상대경로 파싱용)
            pathname = new URL(s, "http://local").pathname;
        } catch (_) {
            pathname = s; // 상대경로 등 파싱 실패 시 원문 그대로(아래 정규식에서 걸러짐)
        }

        const m = pathname.match(PAPERCLIP_PATH_RE);
        if (!m) return null;
        const urlUserId = m[1];
        const filename = m[2];
        if (filename.includes("..")) return null; // 점-점 시퀀스는 명시 차단
        return { urlUserId, filename };
    }

    router.delete("/:id/file-cleanup", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { fileUrl } = req.body;

        if (!fileUrl) return res.status(400).json({ error: "fileUrl required" });

        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                return res.status(403).json({ error: "Forbidden" });
            }

            const parsed = parsePaperclipPathFromUserInput(fileUrl);
            if (!parsed) {
                // 입력 검증 실패는 400 (경로 조작/이상치 차단)
                return res.status(400).json({ error: "Invalid fileUrl" });
            }

            const { urlUserId, filename } = parsed;

            if (String(urlUserId) !== String(userId)) {
                return res.status(403).json({ error: "자신의 파일만 삭제할 수 있습니다." });
            }

            // 경로 정규화 + 디렉터리 경계 체크 (Windows/절대경로/드라이브 경로 등 방어)
            const baseDir = path.resolve(__dirname, "..", "paperclip", String(userId));
            const targetPath = path.resolve(baseDir, filename);
            const rel = path.relative(baseDir, targetPath);
            if (rel.startsWith("..") || path.isAbsolute(rel)) {
                return res.status(400).json({ error: "Invalid fileUrl" });
            }

            // 파일만 삭제(디렉터리 삭제 시도 차단)
            if (fs.existsSync(targetPath)) {
                const st = fs.statSync(targetPath);
                if (st.isFile()) fs.unlinkSync(targetPath);
            }

            res.json({ ok: true });
        } catch (error) {
            logError("DELETE /api/pages/:id/file-cleanup", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    router.post("/:id/editor-image", authMiddleware, editorImageUpload.single('image'), async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        if (!req.file) return res.status(400).json({ error: "No file uploaded" });

        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) {
                if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                return;
            }

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                return res.status(403).json({ error: "Forbidden" });
            }

            const sig = await assertImageFileSignature(req.file.path);
            normalizeUploadedImageFile(req.file, sig.ext);

            const imageUrl = `/imgs/${userId}/${req.file.filename}`;
            res.json({ url: imageUrl });
        } catch (error) {
            if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            logError("POST /api/pages/:id/editor-image", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    // 페이지 발행 링크(공유 URL)는 사실상 URL 안의 비밀 토큰(capability URL)
    // 따라서 읽기 권한만 있는 협업자(READ)에게 토큰을 노출하지 않도록 최소권한을 적용
    function canManagePublish(permission, ownerUserId, currentUserId) {
        // 소유자이거나, 저장소 권한이 ADMIN 인 경우만 발행 링크를 관리/열람 가능
        return String(ownerUserId) === String(currentUserId) || permission === 'ADMIN';
    }

    router.get("/:id/publish", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            // 암호화 페이지는 공개 발행 대상이 아니므로, 토큰/URL은 반환하지 않음
            if (existing.is_encrypted === 1) {
                return res.json({ published: false });
            }

            const [pub] = await pool.execute(
                `SELECT token, created_at, allow_comments FROM page_publish_links WHERE page_id=? AND is_active=1`,
                [id]
            );
            if (!pub.length) return res.json({ published: false });

            const base = (process.env.BASE_URL || '').replace(/\/$/, '');
            const allowComments = pub[0].allow_comments === 1;

            // READ 협업자에게는 발행됨 상태만 알려주고, 토큰은 숨김(정보 노출/오남용 방지)
            if (!canManagePublish(permission, existing.user_id, userId)) {
                return res.json({
                    published: true,
                    createdAt: toIsoString(pub[0].created_at),
                    allowComments
                });
            }

            res.json({
                published: true,
                token: pub[0].token,
                url: base ? `${base}/shared/page/${pub[0].token}` : `/shared/page/${pub[0].token}`,
                createdAt: toIsoString(pub[0].created_at),
                allowComments
            });
        } catch (e) {
            logError("GET /api/pages/:id/publish", e);
            res.status(500).json({ error: "Failed" });
        }
    });

    // 발행(또는 allow_comments 설정 갱신)
    router.post("/:id/publish", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            if (!canManagePublish(permission, existing.user_id, userId)) {
                return res.status(403).json({ error: "발행 링크를 관리할 권한이 없습니다." });
            }

            if (existing.is_encrypted === 1) {
                return res.status(400).json({ error: "암호화된 페이지는 발행할 수 없습니다." });
            }

            const allowComments = req.body && req.body.allowComments === true;
            const now = new Date();
            const nowStr = now.toISOString().slice(0, 19).replace('T', ' ');

            // 이미 발행된 경우: 토큰은 유지하고 설정만 업데이트
            const [active] = await pool.execute(
                `SELECT id, token FROM page_publish_links WHERE page_id=? AND is_active=1 LIMIT 1`,
                [id]
            );

            let token;
            if (active.length) {
                token = active[0].token;
                await pool.execute(
                    `UPDATE page_publish_links SET allow_comments=?, updated_at=? WHERE id=?`,
                    [allowComments ? 1 : 0, nowStr, active[0].id]
                );
            } else {
                // 최초 발행: 새 토큰 발급
                let inserted = false;
                for (let i = 0; i < 3; i++) {
                    try {
                        token = generatePublishToken();
                        await pool.execute(
                            `INSERT INTO page_publish_links (token, page_id, owner_user_id, is_active, allow_comments, created_at, updated_at)
                             VALUES (?, ?, ?, 1, ?, ?, ?)`,
                            [token, id, existing.user_id, allowComments ? 1 : 0, nowStr, nowStr]
                        );
                        inserted = true;
                        break;
                    } catch (err) {
                        // 토큰 충돌(UNIQUE) 시 재시도
                        if (err && err.code === 'ER_DUP_ENTRY') continue;
                        throw err;
                    }
                }
                if (!inserted) {
                    return res.status(500).json({ error: "토큰 생성에 실패했습니다." });
                }
            }

            const base = (process.env.BASE_URL || '').replace(/\/$/, '');
            const url = base ? `${base}/shared/page/${token}` : `/shared/page/${token}`;
            res.json({ published: true, token, url, allowComments });
        } catch (e) {
            logError("POST /api/pages/:id/publish", e);
            res.status(500).json({ error: "Failed" });
        }
    });

    // 발행 취소
    router.delete("/:id/publish", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;

        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission) {
                return res.status(403).json({ error: "권한이 없습니다." });
            }

            if (!canManagePublish(permission, existing.user_id, userId)) {
                return res.status(403).json({ error: "발행 링크를 관리할 권한이 없습니다." });
            }

            const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');
            await pool.execute(
                `UPDATE page_publish_links SET is_active=0, updated_at=? WHERE page_id=? AND is_active=1`,
                [nowStr, id]
            );
            res.json({ ok: true });
        } catch (e) {
            logError("DELETE /api/pages/:id/publish", e);
            res.status(500).json({ error: "Failed" });
        }
    });

    /**
     * 북마크 메타데이터 추출 (SSRF 방어 적용)
     * POST /api/pages/:id/bookmark-metadata
     */
    router.post("/:id/bookmark-metadata", authMiddleware, outboundProxyLimiter, async (req, res) => {
        const { url } = req.body;
        const pageId = req.params.id;
        const userId = req.user.id;

        if (!url) return res.status(400).json({ error: "URL is required" });

        try {
            // 권한 확인 (페이지에 접근 가능한지)
            const existing = await pagesRepo.getPageByIdForUser({ userId, pageId });
            if (!existing) return res.status(404).json({ error: "Not found" });

            const metadata = await getMetadata(url);
            res.json({ success: true, metadata });
        } catch (error) {
            logError("POST /api/pages/:id/bookmark-metadata", error);
            res.status(400).json({ error: error.message || "Failed to fetch metadata" });
        }
    });

    /**
     * 이미지 프록시 (SSRF 방어 및 CSP 우회용)
     * GET /api/pages/proxy/image?url=...
     */
    router.get("/proxy/image", authMiddleware, outboundProxyLimiter, async (req, res) => {
        const urlStr = (typeof req.query.url === "string") ? req.query.url : "";
        if (!urlStr) return res.status(400).end();

        const IMAGE_PROXY_TIMEOUT_MS = (() => {
            const n = Number.parseInt(process.env.IMAGE_PROXY_TIMEOUT_MS || "10000", 10);
            if (!Number.isFinite(n)) return 10000;
            return Math.max(1000, Math.min(30000, n));
        })();

        const IMAGE_PROXY_MAX_BYTES = (() => {
            const n = Number.parseInt(process.env.IMAGE_PROXY_MAX_BYTES || String(5 * 1024 * 1024), 10);
            if (!Number.isFinite(n)) return 5 * 1024 * 1024;
            return Math.max(256 * 1024, Math.min(20 * 1024 * 1024, n));
        })();

        const IMAGE_PROXY_MAX_REDIRECTS = (() => {
            const n = Number.parseInt(process.env.IMAGE_PROXY_MAX_REDIRECTS || "3", 10);
            if (!Number.isFinite(n)) return 3;
            return Math.max(0, Math.min(10, n));
        })();

        async function openImageStream(urlCandidate) {
            let current = urlCandidate;

            for (let i = 0; i <= IMAGE_PROXY_MAX_REDIRECTS; i++) {
                const { url, lookup } = await validateOutboundUrl(current);
                const protocol = url.protocol === "https:" ? https : http;

                const proxyRes = await new Promise((resolve, reject) => {
                    const proxyReq = protocol.get(url, {
                        timeout: IMAGE_PROXY_TIMEOUT_MS,
                        lookup,
                        headers: {
                            'User-Agent': 'NTEOK-ImageProxy/1.0',
                            'Accept': 'image/*,*/*;q=0.1'
                        }
                    }, (r) => resolve(r));

                    proxyReq.on('error', reject);
                    proxyReq.on('timeout', () => {
                        proxyReq.destroy(new Error("Image proxy timeout"));
                    });
                });

                const status = proxyRes.statusCode || 0;
                if (isRedirectStatus(status) && proxyRes.headers.location) {
                    if (i === IMAGE_PROXY_MAX_REDIRECTS) {
                        proxyRes.resume();
                        throw new Error("Too many redirects");
                    }
                    try {
                        const nextUrl = new URL(proxyRes.headers.location, url);
                        proxyRes.resume();
                        current = nextUrl.toString();
                        continue;
                    } catch {
                        proxyRes.resume();
                        throw new Error("Invalid redirect URL");
                    }
                }

                return { proxyRes, finalUrl: url };
            }

            throw new Error("Too many redirects");
        }

        try {
            const { proxyRes, finalUrl } = await openImageStream(urlStr);

            const status = proxyRes.statusCode || 0;
            if (status < 200 || status >= 300) {
                proxyRes.resume();
                return res.status(502).end();
            }

            const contentType = String(proxyRes.headers['content-type'] || '').toLowerCase();
            const isImage = contentType.startsWith('image/');
            const isOctetStream = contentType.includes('application/octet-stream');
            const isSvgMime = contentType.includes('image/svg') || contentType.includes('svg+xml');

            const pathname = finalUrl?.pathname || '';
            const ext = path.extname(pathname).toLowerCase();
            // 보안: SVG는 스크립트가 실행될 수 있는 활성 콘텐츠 이므로 프록시로 same-origin 서빙 금지
            // - 사용자가 프록시 URL을 직접 열면(SVG 문서로 렌더링) same-origin XSS로 이어질 수 있음
            const allowedExt = new Set(['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.ico', '.tif', '.tiff']);

            if (isSvgMime || ext === '.svg') {
                proxyRes.resume();
                return res.status(403).end();
            }

            if (!isImage && !(isOctetStream && allowedExt.has(ext))) {
                proxyRes.resume();
                return res.status(403).end();
            }

            const lenHeader = proxyRes.headers['content-length'];
            if (lenHeader) {
                const len = Number.parseInt(String(lenHeader), 10);
                if (Number.isFinite(len) && len > IMAGE_PROXY_MAX_BYTES) {
                    proxyRes.resume();
                    return res.status(413).end();
                }
            }

            res.writeHead(200, {
                'Content-Type': contentType || 'application/octet-stream',
                'X-Content-Type-Options': 'nosniff',
                // 보안: 이미지 프록시 URL을 사용자가 직접 열어도 문서 컨텍스트에서 스크립트가 못 돌게 강제
                // (SVG를 차단하더라도, 혹시 모를 타입 혼동/브라우저 동작 차이를 방어적으로 커버)
                'Content-Security-Policy': "default-src 'none'; sandbox",
                'Cross-Origin-Resource-Policy': 'same-origin',
                // 인증이 필요한 프록시이므로 shared cache 저장 방지(선호: private/no-store)
                'Cache-Control': 'private, max-age=86400'
            });

            let seen = 0;
            proxyRes.on('data', (chunk) => {
                seen += chunk.length;
                if (seen > IMAGE_PROXY_MAX_BYTES) {
                    proxyRes.destroy(new Error("Image too large"));
                    try { res.destroy(); } catch (_) {}
                }
            });
            proxyRes.on('error', () => {
                try { res.destroy(); } catch (_) {}
            });

            proxyRes.pipe(res);
        } catch (e) {
            const msg = String(e?.message || '');
            if (
                msg.includes('Invalid URL') ||
                msg.includes('Only http/https') ||
                msg.includes('Userinfo') ||
                msg.includes('Port is not allowed') ||
                msg.includes('Private/local IP') ||
                msg.includes('Failed to resolve')
            ) {
                return res.status(403).end();
            }
            if (msg.toLowerCase().includes('timeout')) return res.status(504).end();
            return res.status(500).end();
        }
    });

    return router;
};