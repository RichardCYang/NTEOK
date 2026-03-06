const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const dns = require("node:dns").promises;
const http = require("node:http");
const https = require("node:https");
const net = require("node:net");
const ipaddr = require("ipaddr.js");
const cheerio = require("cheerio");
const { assertImageFileSignature } = require("../security-utils.js");
const { validateAndNormalizeIcon } = require("../utils/icon-utils.js");

const METADATA_FETCH_TIMEOUT_MS = 5000;
const METADATA_FETCH_MAX_BYTES = 2 * 1024 * 1024;
const LINK_PREVIEW_ALLOWED_PORTS = (() => {
    const raw = String(process.env.LINK_PREVIEW_ALLOWED_PORTS || '80,443').trim();
    const out = new Set();
    for (const part of raw.split(',')) {
        const n = Number.parseInt(part.trim(), 10);
        if (Number.isFinite(n) && n >= 1 && n <= 65535) out.add(n);
    }
    return out.size > 0 ? out : new Set([80, 443]);
})();

function makeFetchError(code, message) {
    const err = new Error(message || code);
    err.code = code;
    return err;
}

function normalizeResolvedAddress(entry) {
    if (!entry) return null;
    if (typeof entry === 'string') return entry;
    if (typeof entry.address === 'string') return entry.address;
    return null;
}

async function resolvePublicOutboundAddresses(hostname, isPrivateOrLocalIP) {
    const host = String(hostname || '').trim().replace(/^\[/, '').replace(/\]$/, '');
    if (!host) throw makeFetchError('HOST_REQUIRED');

    if (net.isIP(host)) {
        if (isPrivateOrLocalIP(host)) throw makeFetchError('BLOCKED_PRIVATE_IP');
        return [host];
    }

    const v4 = await dns.resolve4(host).catch(() => []);
    const v6 = await dns.resolve6(host).catch(() => []);
    const addresses = [...v4, ...v6]
        .map(normalizeResolvedAddress)
        .filter(Boolean);

    if (addresses.length === 0) throw makeFetchError('HOST_NOT_FOUND');

    const uniqueAddresses = [...new Set(addresses)];
    for (const ip of uniqueAddresses) {
        if (isPrivateOrLocalIP(ip)) throw makeFetchError('BLOCKED_PRIVATE_IP');
    }

    return uniqueAddresses;
}

function fetchHtmlFromPinnedAddress(targetUrl, pinnedIp, isPrivateOrLocalIP) {
    return new Promise((resolve, reject) => {
        const protocolModule = targetUrl.protocol === 'https:' ? https : http;
        const port = Number(targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80));

        if (!LINK_PREVIEW_ALLOWED_PORTS.has(port)) {
            return reject(makeFetchError('DISALLOWED_PORT'));
        }

        const req = protocolModule.request({
            protocol: targetUrl.protocol,
            hostname: targetUrl.hostname,
            port,
            method: 'GET',
            path: `${targetUrl.pathname || '/'}${targetUrl.search || ''}`,
            lookup: (_hostname, _opts, cb) => cb(null, pinnedIp, net.isIP(pinnedIp)),
            servername: net.isIP(targetUrl.hostname) ? undefined : targetUrl.hostname,
            agent: false,
            timeout: METADATA_FETCH_TIMEOUT_MS,
            headers: {
                'User-Agent': 'NTEOK-Link-Preview/1.0',
                'Accept': 'text/html,application/xhtml+xml;q=0.9',
                'Accept-Encoding': 'identity',
                'Host': targetUrl.host
            }
        }, (upstreamRes) => {
            const remoteIp = upstreamRes.socket?.remoteAddress;
            if (remoteIp && isPrivateOrLocalIP(remoteIp)) {
                upstreamRes.resume();
                return reject(makeFetchError('BLOCKED_PRIVATE_IP'));
            }

            const status = Number(upstreamRes.statusCode || 0);
            if (status >= 300 && status < 400) {
                upstreamRes.resume();
                return reject(makeFetchError('REDIRECT_BLOCKED'));
            }
            if (status < 200 || status >= 400) {
                upstreamRes.resume();
                return reject(makeFetchError('UPSTREAM_BAD_STATUS'));
            }

            const contentType = String(upstreamRes.headers['content-type'] || '').toLowerCase();
            if (contentType && !contentType.includes('text/html') && !contentType.includes('application/xhtml+xml')) {
                upstreamRes.resume();
                return reject(makeFetchError('NOT_HTML'));
            }

            const chunks = [];
            let total = 0;

            upstreamRes.on('data', (chunk) => {
                total += chunk.length;
                if (total > METADATA_FETCH_MAX_BYTES) {
                    req.destroy(makeFetchError('TOO_LARGE'));
                    return;
                }
                chunks.push(chunk);
            });

            upstreamRes.on('end', () => {
                resolve(Buffer.concat(chunks).toString('utf8'));
            });
        });

        req.on('timeout', () => req.destroy(makeFetchError('ETIMEDOUT')));
        req.on('error', reject);
        req.end();
    });
}

async function fetchHtmlWithoutRedirects(targetUrl, resolvedIps, isPrivateOrLocalIP) {
    let lastError = null;

    for (const ip of resolvedIps) {
        try {
            return await fetchHtmlFromPinnedAddress(targetUrl, ip, isPrivateOrLocalIP);
        } catch (err) {
            lastError = err;
            if ([
                'BLOCKED_PRIVATE_IP',
                'DISALLOWED_PORT',
                'REDIRECT_BLOCKED',
                'NOT_HTML',
                'TOO_LARGE'
            ].includes(String(err?.code || ''))) {
                throw err;
            }
        }
    }

    throw lastError || makeFetchError('FETCH_FAILED');
}

const erl = require("express-rate-limit");
const rateLimit = erl.rateLimit || erl;
const { ipKeyGenerator } = erl;

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

    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(filename)) return { ok: false, error: 'coverImage 파일명이 올바르지 않습니다.' };
    if (filename.includes('..') || /["'()\\]/.test(filename)) return { ok: false, error: 'coverImage 파일명에 허용되지 않는 문자가 포함되어 있습니다.' };
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
        wsBroadcastToPage,
        wsBroadcastToStorage,
        wsCloseConnectionsForPage,
        wsHasActiveConnectionsForPage,
        saveYjsDocToDatabase,
        enqueueYjsDbSave,
        logError,
        generatePublishToken,
        coverUpload,
        editorImageUpload,
        fileUpload,
        path,
        fs,
        yjsDocuments,
        extractFilesFromContent,
        invalidateYjsPersistenceForPage,
        isPrivateOrLocalIP,
        getClientIpFromRequest,
        outboundFetchLimiter
	} = dependencies;

    async function syncPageFileRefs(pageId, pageOwnerUserId, content) {
        if (!content) return;
        try {
            const ownerId = Number(pageOwnerUserId);
            if (!Number.isFinite(ownerId)) throw new Error('Invalid pageOwnerUserId');

            const newFiles = extractFilesFromContent(content, ownerId);

            for (const file of newFiles) {
                const parts = file.ref.split('/');
                const fileOwnerId = parseInt(parts[0], 10);
                const filename = parts[1];
                if (fileOwnerId === ownerId) {
                    await pool.execute(
                        `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
                         VALUES (?, ?, ?, ?, NOW())`,
                        [pageId, fileOwnerId, filename, file.type]
                    );
                }
            }

            const currentPaperclipFiles = newFiles.filter(f => f.type === 'paperclip').map(f => f.ref.split('/')[1]);
            if (currentPaperclipFiles.length > 0) {
                await pool.execute(
                    `DELETE FROM page_file_refs
                      WHERE page_id = ?
                        AND owner_user_id = ?
                        AND file_type = 'paperclip'
                        AND stored_filename NOT IN (${currentPaperclipFiles.map(() => '?').join(',')})`,
                    [pageId, ownerId, ...currentPaperclipFiles]
                );
            } else {
                await pool.execute(
                    `DELETE FROM page_file_refs
                      WHERE page_id = ? AND owner_user_id = ? AND file_type = 'paperclip'`,
                    [pageId, ownerId]
                );
            }

            const currentImgsFiles = newFiles.filter(f => f.type === 'imgs').map(f => f.ref.split('/')[1]);
            if (currentImgsFiles.length > 0) {
                await pool.execute(
                    `DELETE FROM page_file_refs
                      WHERE page_id = ?
                        AND owner_user_id = ?
                        AND file_type = 'imgs'
                        AND stored_filename NOT IN (${currentImgsFiles.map(() => '?').join(',')})`,
                    [pageId, ownerId, ...currentImgsFiles]
                );
            } else {
                await pool.execute(
                    `DELETE FROM page_file_refs
                      WHERE page_id = ? AND owner_user_id = ? AND file_type = 'imgs'`,
                    [pageId, ownerId]
                );
            }
        } catch (regErr) {
            logError('syncPageFileRefs 실패', regErr);
        }
    }

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

    const fileUploadLimiter = rateLimit({
        windowMs: 60 * 60 * 1000,
        max: Number.parseInt(process.env.FILE_UPLOAD_MAX_PER_HOUR || "60", 10),
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req) => req.user?.id ? `user:${req.user.id}` : `ip:${getClientIp(req)}`,
        handler: (_req, res) => res.status(429).json({ error: "업로드 요청이 너무 많습니다. 잠시 후 다시 시도해주세요." })
    });

    const usageCache = new Map(); 
    const USAGE_CACHE_TTL_MS = 30 * 1000;

    const quotaLocks = new Map(); 
    function withQuotaLock(userId, fn) {
        const key = String(userId);
        const prev = quotaLocks.get(key) || Promise.resolve();
        const next = prev.then(fn, fn);
        quotaLocks.set(key, next.finally(() => {
            if (quotaLocks.get(key) === next) quotaLocks.delete(key);
        }));
        return next;
    }

    async function computeDirUsageBytes(dirPath) {
        let total = 0;
        try {
            const items = await fs.promises.readdir(dirPath, { withFileTypes: true });
            for (const it of items) {
                if (!it.isFile()) continue;
                const fp = path.join(dirPath, it.name);
                try {
                    const st = await fs.promises.stat(fp);
                    total += st.size;
                } catch (_) {}
            }
        } catch (_) {}
        return total;
    }

    async function enforceUploadQuotaOrThrow(userId, newFilePath) {
        return withQuotaLock(userId, async () => {
            const dirs = [
                path.join(__dirname, "..", "paperclip", String(userId)),
                path.join(__dirname, "..", "imgs", String(userId)),
                path.join(__dirname, "..", "covers", String(userId))
            ];

            const bases = dirs.map(d => path.resolve(d) + path.sep);
            const resolvedNew = newFilePath ? path.resolve(newFilePath) : "";
            const isNewPathSafe =
                resolvedNew &&
                bases.some(b => resolvedNew.startsWith(b));

            const safeUnlinkNewFile = () => {
                if (!isNewPathSafe) return;
                try { if (newFilePath && fs.existsSync(newFilePath)) fs.unlinkSync(newFilePath); } catch (_) {}
            };

            const now = Date.now();
            const cached = usageCache.get(userId);

            if (cached && (now - cached.ts) < USAGE_CACHE_TTL_MS) {
                let addedBytes = 0;
                if (isNewPathSafe) {
                    try {
                        const st = await fs.promises.stat(newFilePath);
                        if (st && typeof st.size === "number" && st.size > 0) addedBytes = st.size;
                    } catch (_) {}
                }

                const projected = (cached.bytes || 0) + addedBytes;
                if (projected > MAX_PAPERCLIP_BYTES_PER_USER) {
                    safeUnlinkNewFile();
                    usageCache.delete(userId);
                    throw new Error("UPLOAD_QUOTA_EXCEEDED");
                }

                usageCache.set(userId, { bytes: projected, ts: now });
                return;
            }

            let totalBytes = 0;
            for (const d of dirs) {
                totalBytes += await computeDirUsageBytes(d);
            }
            usageCache.set(userId, { bytes: totalBytes, ts: now });

            if (totalBytes > MAX_PAPERCLIP_BYTES_PER_USER) {
                safeUnlinkNewFile();
                usageCache.delete(userId);
                throw new Error("UPLOAD_QUOTA_EXCEEDED");
            }
        });
    }

    async function loadPageForMutationOr404(userId, pageId, res) {
        const page = await pagesRepo.getPageByIdForUser({ userId, pageId });
        if (!page) {
            res.status(404).json({ error: "Not found" });
            return null;
        }
        return page;
    }

    function syncYjsMetadataFromRest(pageId, patch = {}) {
        try {
            const pid = String(pageId || '');
            if (!pid || !yjsDocuments) return;
            const docInfo = yjsDocuments.get(pid);
            if (!docInfo?.ydoc) return;

            let update = null;
            const handler = (u) => { update = u; };
            docInfo.ydoc.once('update', handler);

            const yMeta = docInfo.ydoc.getMap('metadata');
            docInfo.ydoc.transact(() => {
                if (Object.prototype.hasOwnProperty.call(patch, 'title')) {
                    const t = (typeof patch.title === 'string' && patch.title.trim())
                        ? patch.title.trim().slice(0, 255)
                        : '제목 없음';
                    yMeta.set('title', t);
                }

                if (Object.prototype.hasOwnProperty.call(patch, 'icon')) {
                    yMeta.set('icon', validateAndNormalizeIcon(patch.icon));
                }

                if (Object.prototype.hasOwnProperty.call(patch, 'sortOrder')) {
                    const n = Number(patch.sortOrder);
                    if (Number.isFinite(n)) yMeta.set('sortOrder', Math.max(-1e9, Math.min(1e9, Math.trunc(n))));
                }

                if (Object.prototype.hasOwnProperty.call(patch, 'parentId')) {
                    const p = patch.parentId;
                    if (p == null) yMeta.set('parentId', null);
                    else if (typeof p === 'string') yMeta.set('parentId', p.trim().slice(0, 128));
                }

                if (Object.prototype.hasOwnProperty.call(patch, 'content')) {
                    const c = (typeof patch.content === 'string') ? patch.content : '';
                    yMeta.set('content', c);
                }
            }, 'rest-sync');

            docInfo.ydoc.off('update', handler);

            if (update && typeof wsBroadcastToPage === 'function') {
                wsBroadcastToPage(pid, 'yjs-update', {
                    update: Buffer.from(update).toString('base64')
                });
            }

            if (typeof invalidateYjsPersistenceForPage === 'function') {
                invalidateYjsPersistenceForPage(pid);
            }

            docInfo.lastAccess = Date.now();
        } catch (_) {
        }
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

    router.get("/fetch-metadata", authMiddleware, outboundFetchLimiter, async (req, res) => {
        const { url } = req.query;
        if (!url) return res.status(400).json({ error: "URL이 필요합니다." });

        try {
            let targetUrl;
            try {
                targetUrl = new URL(url);
            } catch (e) {
                return res.status(400).json({ error: "유효하지 않은 URL 형식입니다." });
            }

            if (!['http:', 'https:'].includes(targetUrl.protocol)) {
                return res.status(400).json({ error: "HTTP/HTTPS 프로토콜만 허용됩니다." });
            }

            if (targetUrl.username || targetUrl.password) {
                return res.status(400).json({ error: "인증 정보가 포함된 URL은 허용되지 않습니다." });
            }

            const resolvedIps = await resolvePublicOutboundAddresses(targetUrl.hostname, isPrivateOrLocalIP);
            const html = await fetchHtmlWithoutRedirects(targetUrl, resolvedIps, isPrivateOrLocalIP);

            const $ = cheerio.load(html);
            const title = $('title').first().text() || $('meta[property="og:title"]').attr('content') || $('meta[name="twitter:title"]').attr('content') || targetUrl.hostname;

            let favicon = null;
            const faviconSelectors = [
                'link[rel="apple-touch-icon"]',
                'link[rel="apple-touch-icon-precomposed"]',
                'link[rel="icon"]',
                'link[rel="shortcut icon"]',
                'link[rel="alternate icon"]'
            ];

            for (const selector of faviconSelectors) {
                const href = $(selector).attr('href');
                if (href) {
                    favicon = href;
                    break;
                }
            }

            if (!favicon) {
                favicon = '/favicon.ico';
            }

            if (favicon && !favicon.startsWith('http') && !favicon.startsWith('data:')) {
                if (favicon.startsWith('//')) {
                    favicon = targetUrl.protocol + favicon;
                } else if (favicon.startsWith('/')) {
                    favicon = targetUrl.origin + favicon;
                } else {
                    const basePath = targetUrl.origin + targetUrl.pathname.substring(0, targetUrl.pathname.lastIndexOf('/') + 1);
                    favicon = basePath + favicon;
                }
            }

            res.json({
                title: title.trim().substring(0, 500),
                favicon: favicon,
                url: url
            });

        } catch (error) {
            switch (String(error?.code || '')) {
                case 'HOST_NOT_FOUND':
                    return res.status(400).json({ error: "호스트를 찾을 수 없습니다." });
                case 'BLOCKED_PRIVATE_IP':
                    return res.status(403).json({ error: "허용되지 않은 호스트입니다." });
                case 'DISALLOWED_PORT':
                    return res.status(400).json({ error: "허용되지 않은 포트입니다." });
                case 'REDIRECT_BLOCKED':
                    return res.status(400).json({ error: "리다이렉트 URL은 허용되지 않습니다." });
                case 'NOT_HTML':
                    return res.status(400).json({ error: "HTML 콘텐츠가 아닙니다." });
                case 'TOO_LARGE':
                    return res.status(413).json({ error: "메타데이터 응답이 너무 큽니다." });
                case 'ETIMEDOUT':
                case 'ECONNABORTED':
                    return res.status(504).json({ error: "요청 시간이 초과되었습니다." });
                case 'UPSTREAM_BAD_STATUS':
                    return res.status(502).json({ error: "상대 서버 응답이 유효하지 않습니다." });
                default:
                    logError("GET /api/pages/fetch-metadata", error);
                    return res.status(500).json({ error: "메타데이터를 가져오는데 실패했습니다." });
            }
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

    async function validateParentForCreate({ userId, storageId, parentId }) {
        if (parentId == null) return { ok: true, parentId: null };
        if (typeof parentId !== "string") return { ok: false, status: 400, error: "Invalid parentId" };

        const normalizedParentId = parentId.trim();
        if (!normalizedParentId || normalizedParentId.length > 64)
            return { ok: false, status: 400, error: "Invalid parentId" };

        const parent = await pagesRepo.getPageByIdForUser({ userId, pageId: normalizedParentId });
        if (!parent) {
            return { ok: false, status: 404, error: "Parent page not found" };
        }

        if (String(parent.storage_id) !== String(storageId)) {
            return { ok: false, status: 404, error: "Parent page not found" };
        }

        if (parent.deleted_at)
            return { ok: false, status: 404, error: "Parent page not found" };

        return { ok: true, parentId: normalizedParentId };
    }

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
            if (!permission || !['EDIT', 'ADMIN'].includes(permission))
                return res.status(403).json({ error: "이 저장소에 페이지를 생성할 권한이 없습니다." });

            const parentCheck = await validateParentForCreate({
                userId,
                storageId,
                parentId: req.body.parentId ?? null
            });

            if (!parentCheck.ok)
                return res.status(parentCheck.status).json({ error: parentCheck.error });

            const parentId = parentCheck.parentId;
            const sortOrder = req.body.sortOrder || 0;
            const isEncrypted = req.body.isEncrypted === true ? 1 : 0;
            const salt = req.body.encryptionSalt || null;
            const encContent = req.body.encryptedContent || null;

            if (isEncrypted) {
                if (!encContent) return res.status(400).json({ error: "Encryption fields missing" });

                if (salt) {
                    if (typeof salt !== "string" || salt.length > 512 || !/^[A-Za-z0-9+/=]*$/.test(salt))
                        return res.status(400).json({ error: "유효하지 않은 encryptionSalt 형식" });
                }

                if (typeof encContent !== "string")
                    return res.status(400).json({ error: "유효하지 않은 encryptedContent 형식" });

                if (encContent.length > 5 * 1024 * 1024)
                    return res.status(400).json({ error: "encryptedContent가 너무 큽니다." });

                const isWellFormed =
                    /^SALT:[A-Za-z0-9+/=]+:ENC2:[A-Za-z0-9+/=]+$/.test(encContent) ||
                    /^ENC1:[A-Za-z0-9+/=]+$/.test(encContent) ||
                    /^[A-Za-z0-9+/=]+$/.test(encContent);

                if (!isWellFormed || /[\x00-\x1F\x7F]/.test(encContent))
                    return res.status(400).json({ error: "encryptedContent 형식이 올바르지 않거나 허용되지 않는 문자가 포함되어 있습니다." });
            }

            const hasContentField = Object.prototype.hasOwnProperty.call(req.body, 'content');
            if (!isEncrypted && hasContentField && typeof req.body.content !== 'string') {
                return res.status(400).json({ error: 'content must be a string' });
            }

            const content = isEncrypted
                ? ''
                : sanitizeHtmlContent(hasContentField ? (req.body.content || '<p></p>') : '<p></p>');

            const shareAllowed = (isEncrypted && !salt) ? 1 : 0;

            await pool.execute(`INSERT INTO pages (id, user_id, parent_id, title, content, sort_order, created_at, updated_at, storage_id, is_encrypted, encryption_salt, encrypted_content, share_allowed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, userId, parentId, title, content, sortOrder, nowStr, nowStr, storageId, isEncrypted, salt, encContent, shareAllowed]);

            if (!isEncrypted && content)
                await syncPageFileRefs(id, userId, content);

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
            const [pageRows] = await pool.execute(
                `SELECT p.user_id,
                        p.storage_id,
                        p.title,
                        p.content,
                        p.icon,
                        p.horizontal_padding,
                        p.is_encrypted,
                        p.encryption_salt,
                        p.encrypted_content,
                        p.share_allowed,
                        s.is_encrypted AS storage_is_encrypted,
                        s.encryption_salt AS storage_encryption_salt
                   FROM pages p
                   JOIN storages s ON p.storage_id = s.id
                  WHERE p.id = ?`,
                [id]
            );

            if (pageRows.length === 0) {
                return res.status(404).json({ error: "Page not found" });
            }

            const existing = pageRows[0];
            const hasEncryptedContentField = Object.prototype.hasOwnProperty.call(req.body, "encryptedContent");

            const isE2eePage =
                Number(existing.storage_is_encrypted) === 1 &&
                Number(existing.is_encrypted) === 1 &&
                (existing.encryption_salt === null || existing.encryption_salt === undefined);
            if (isE2eePage && hasEncryptedContentField) {
                return res.status(403).json({ error: "E2EE content must be saved via WebSocket to prevent data loss" });
            }

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission))
                return res.status(403).json({ error: "이 페이지를 수정할 권한이 없습니다." });

            const reqIsEncrypted = (req.body.isEncrypted === true || req.body.isEncrypted === false) ? req.body.isEncrypted : undefined;
            const isEncrypted = (reqIsEncrypted !== undefined) ? (reqIsEncrypted ? 1 : 0) : existing.is_encrypted;
            const encryptionStateChanged = Number(existing.is_encrypted) !== Number(isEncrypted);

            const isRealtimeCollabPage = (Number(existing.storage_is_encrypted) === 0 && Number(existing.is_encrypted) === 0);
            const contentWillBeReset = (req.body.content !== undefined) || encryptionStateChanged || (Number(isEncrypted) === 1);

            if (isRealtimeCollabPage && contentWillBeReset && typeof wsHasActiveConnectionsForPage === 'function') {
                if (wsHasActiveConnectionsForPage(id)) {
                    return res.status(409).json({
                        error: '이 페이지는 현재 실시간 협업으로 열려 있어 REST 저장이 충돌합니다. (데이터 유실 방지)\n페이지를 새로고침하거나, 다른 탭/사용자의 편집을 종료한 뒤 다시 시도하세요.'
                    });
                }
            }


            const turningOffEncryption =
                encryptionStateChanged &&
                Number(existing.is_encrypted) === 1 &&
                Number(isEncrypted) === 0;
            if (turningOffEncryption && req.body.content === undefined) {
                return res.status(400).json({ error: "암호화 해제 전환 시에는 복호화된 평문 content가 필요합니다." });
            }

            const hasEncryptionSalt = Object.prototype.hasOwnProperty.call(req.body, "encryptionSalt");
            const hasEncryptedContent = hasEncryptedContentField;

            let salt;
            let encContent;

            if (Number(isEncrypted) === 1) {
                salt = hasEncryptionSalt ? req.body.encryptionSalt : existing.encryption_salt;
                encContent = hasEncryptedContent ? req.body.encryptedContent : existing.encrypted_content;

                if (encryptionStateChanged && !hasEncryptedContent)
                    return res.status(400).json({ error: "암호화 전환 시 encryptedContent가 필요합니다." });

                if (salt != null) {
                    if (typeof salt !== "string" || salt.length > 512 || !/^[A-Za-z0-9+/=]*$/.test(salt))
                        return res.status(400).json({ error: "유효하지 않은 encryptionSalt 형식" });
                }

                if (encContent != null) {
                    if (typeof encContent !== "string")
                        return res.status(400).json({ error: "유효하지 않은 encryptedContent 형식" });

                    if (encContent.length > 5 * 1024 * 1024)
                        return res.status(400).json({ error: "encryptedContent가 너무 큽니다." });

                    const isWellFormed =
                        /^SALT:[A-Za-z0-9+/=]+:ENC2:[A-Za-z0-9+/=]+$/.test(encContent) ||
                        /^ENC1:[A-Za-z0-9+/=]+$/.test(encContent) ||
                        /^[A-Za-z0-9+/=]+$/.test(encContent);

                    if (!isWellFormed || /[\x00-\x1F\x7F]/.test(encContent))
                        return res.status(400).json({ error: "encryptedContent 형식이 올바르지 않거나 허용되지 않는 문자가 포함되어 있습니다." });
                }
            } else {
                salt = null;
                encContent = null;
            }

            const hasContentField = Object.prototype.hasOwnProperty.call(req.body, 'content');
            if (!isEncrypted && hasContentField && typeof req.body.content !== 'string') {
                return res.status(400).json({ error: 'content must be a string' });
            }

            const content = isEncrypted
                ? ''
                : (hasContentField
                    ? sanitizeHtmlContent(req.body.content || '<p></p>')
                    : (existing.content ?? '<p></p>'));
            const icon = req.body.icon !== undefined ? validateAndNormalizeIcon(req.body.icon) : (existing.icon ?? null);
            const hPadding = req.body.horizontalPadding !== undefined ? req.body.horizontalPadding : (existing.horizontal_padding ?? null);
            const nowStr = formatDateForDb(new Date());

            if (Number(isEncrypted) === 0 && req.body.content === undefined) {
                const patch = {};
                if (req.body.title !== undefined) patch.title = title;
                if (req.body.icon !== undefined) patch.icon = icon;
                if (Object.keys(patch).length > 0) syncYjsMetadataFromRest(id, patch);
            }
            const shareAllowed = (Number(isEncrypted) === 1 && !salt) ? 1 : 0;
            let sql = `UPDATE pages SET title=?, content=?, is_encrypted=?, encryption_salt=?, encrypted_content=?, icon=?, horizontal_padding=?, updated_at=?, share_allowed=?`;
            const params = [title, content, isEncrypted, salt, encContent, icon, hPadding, nowStr, shareAllowed];
            const shouldResetYjsState = (req.body.content !== undefined) || encryptionStateChanged || (Number(isEncrypted) === 1);
            if (shouldResetYjsState) {
                invalidateYjsPersistenceForPage(id); 
                sql += `, yjs_state=NULL`;
                try {
                    const docInfo = yjsDocuments && yjsDocuments.get(id);
                    if (docInfo?.saveTimeout) {
                        clearTimeout(docInfo.saveTimeout);
                        docInfo.saveTimeout = null;
                    }
                } catch (_) {}
                if (yjsDocuments && yjsDocuments.has(id)) yjsDocuments.delete(id);

                if (req.body.content !== undefined && typeof wsCloseConnectionsForPage === 'function')
                    wsCloseConnectionsForPage(id, 1012, 'Page updated via REST');
            }

            sql += ` WHERE id=?`; params.push(id);
            await pool.execute(sql, params);

            if (!isEncrypted && content)
                await syncPageFileRefs(id, userId, content);

            if (encryptionStateChanged && typeof wsCloseConnectionsForPage === 'function')
                wsCloseConnectionsForPage(id, 1008, 'Page access policy changed');

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: existing.storage_id,
                pageId: id,
                action: 'UPDATE_PAGE',
                details: { title }
            });

            const updatedVis = wsPageVisibilityFromRow({ ...existing, is_encrypted: Number(isEncrypted) });
            wsBroadcastToStorage(existing.storage_id, 'metadata-change', { pageId: id, field: 'title', value: title }, null, { pageVisibility: updatedVis });
            res.json({ id, title, updatedAt: new Date().toISOString() });
        } catch (e) { logError("PUT /api/pages/:id", e); res.status(500).json({ error: "Failed" }); }
    });

    router.patch("/reorder", authMiddleware, async (req, res) => {
        const { storageId, pageIds, parentId } = req.body;
        const userId = req.user.id;

        try {
            if (typeof storageId !== "string" || !storageId.trim())
                return res.status(400).json({ error: "storageId required" });

            if (!Array.isArray(pageIds) || pageIds.length === 0)
                return res.status(400).json({ error: "pageIds required" });

            const MAX_REORDER_PAGES = Number(process.env.MAX_REORDER_PAGES || 2000);
            if (pageIds.length > MAX_REORDER_PAGES)
                return res.status(413).json({ error: `Too many pageIds (max ${MAX_REORDER_PAGES})` });

            const normalizedIds = [];
            const seen = new Set();
            for (const raw of pageIds) {
                if (typeof raw !== "string") return res.status(400).json({ error: "Invalid pageId" });
                const pid = raw.trim();
                if (!pid || pid.length > 64) return res.status(400).json({ error: "Invalid pageId" });
                if (seen.has(pid)) return res.status(400).json({ error: "Duplicate pageId" });
                seen.add(pid);
                normalizedIds.push(pid);
            }

            const permission = await storagesRepo.getPermission(userId, storageId);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission)) {
                return res.status(403).json({ error: "이 저장소의 페이지 순서를 변경할 권한이 없습니다." });
            }

            if (parentId) {
                const parent = await pagesRepo.getPageByIdForUser({ userId, pageId: parentId });
                if (!parent || String(parent.storage_id) !== String(storageId))
                    return res.status(404).json({ error: "Not found" });
            }

            const vis = (pageSqlPolicy && typeof pageSqlPolicy.andVisible === "function")
                ? pageSqlPolicy.andVisible({ alias: "p", viewerUserId: userId })
                : { sql: "AND NOT (p.is_encrypted = 1 AND p.share_allowed = 0 AND p.user_id != ?)", params: [userId] };

            const placeholders = normalizedIds.map(() => "?").join(",");
            const [visibleRows] = await pool.execute(
                `SELECT p.id
                   FROM pages p
              LEFT JOIN storage_shares ss
                     ON p.storage_id = ss.storage_id
                    AND ss.shared_with_user_id = ?
                  WHERE p.storage_id = ?
                    AND p.deleted_at IS NULL
                    AND (p.user_id = ? OR ss.storage_id IS NOT NULL)
                    ${vis.sql}
                    AND p.id IN (${placeholders})`,
                [userId, storageId, userId, ...vis.params, ...normalizedIds]
            );

            const allowed = new Set((visibleRows || []).map(r => String(r.id)));
            if (allowed.size !== normalizedIds.length) {
                return res.status(404).json({ error: "Not found" });
            }

            for (let i = 0; i < normalizedIds.length; i++) {
                syncYjsMetadataFromRest(normalizedIds[i], { sortOrder: i * 10 });
            }

            const conn = await pool.getConnection();
            try {
                await conn.beginTransaction();
                for (let i = 0; i < normalizedIds.length; i++) {
                    const pid = normalizedIds[i];
                    await conn.execute(
                        `UPDATE pages SET sort_order=?, updated_at=NOW() WHERE id=? AND storage_id=?`,
                        [i * 10, pid, storageId]
                    );
                }
                await conn.commit();
            } catch (e) {
                try { await conn.rollback(); } catch (_) {}
                throw e;
            } finally {
                try { conn.release(); } catch (_) {}
            }

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId,
                action: 'REORDER_PAGES',
                details: { parentId, count: normalizedIds.length }
            });

            wsBroadcastToStorage(storageId, 'pages-reordered', { parentId, pageIds: normalizedIds }, userId);
            res.json({ ok: true });
        } catch (e) {
            logError("PATCH /api/pages/reorder", e);
            res.status(500).json({ error: "Failed" });
        }
    });

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

            await pagesRepo.permanentlyDeletePageAndDescendants({
                pageId: id,
                userId,
                isAdmin: permission === 'ADMIN'
            });

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

            const isOwnerOfPage = Number(existing.user_id) === Number(userId);
            const canDelete =
                permission === 'ADMIN' ||
                (permission === 'EDIT' && isOwnerOfPage);

            if (!canDelete) {
                return res.status(403).json({
                    error: "이 페이지를 삭제할 권한이 없습니다. (ADMIN 또는 본인 작성 페이지만 삭제 가능)"
                });
            }

            const delResult = await pagesRepo.softDeletePageAndDescendants({
                rootPageId: id,
                storageId: existing.storage_id,
                rootParentId: existing.parent_id || null,
                actorUserId: userId,
                isAdmin: permission === 'ADMIN'
            });

            const deletedPageIds = Array.isArray(delResult?.deletedPageIds) && delResult.deletedPageIds.length
                ? delResult.deletedPageIds
                : [id];

            for (const pid of deletedPageIds) {
                invalidateYjsPersistenceForPage(pid);

                try {
                    const docInfo = yjsDocuments.get(pid);
                    if (docInfo?.ydoc) {
                        await enqueueYjsDbSave(pid, () => saveYjsDocToDatabase(pool, sanitizeHtmlContent, pid, docInfo.ydoc, { allowDeleted: true }));
                    }
                } catch (_) {}

                try {
                    const docInfo = yjsDocuments.get(pid);
                    if (docInfo?.saveTimeout) {
                        clearTimeout(docInfo.saveTimeout);
                        docInfo.saveTimeout = null;
                    }
                    yjsDocuments.delete(pid);
                } catch (_) {}

                try {
                    const conns = wsConnections?.pages?.get(pid);
                    if (conns && conns.size) {
                        try { wsBroadcastToPage(pid, 'page-deleted', { pageId: pid }); } catch (_) {}

                        for (const c of Array.from(conns)) {
                            try {
                                if (c.ws) {
                                    c.ws.close(1008, 'Page deleted');
                                }
                            } catch (_) {}
                        }
                        wsConnections.pages.delete(pid);
                    }
                } catch (_) {}
            }

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

            const coverRef = `${userId}/${filename}`;
            const [useRows] = await pool.execute(
                `SELECT COUNT(*) AS cnt
                   FROM pages
                  WHERE user_id = ?
                    AND cover_image = ?
                    AND deleted_at IS NULL`,
                [userId, coverRef]
            );
            const inUse = Number(useRows?.[0]?.cnt || 0);
            if (inUse > 0) {
                return res.status(409).json({
                    error: `이 커버 이미지는 현재 ${inUse}개 페이지에서 사용 중입니다. 먼저 해당 페이지의 커버를 제거/변경한 뒤 다시 시도하세요.`
                });
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

    router.post("/:id/cover", authMiddleware, fileUploadLimiter, coverUpload.single('cover'), async (req, res) => {
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

            try {
                await enforceUploadQuotaOrThrow(userId, req.file.path);
            } catch (e) {
                if (String(e?.message) === "UPLOAD_QUOTA_EXCEEDED")
                    return res.status(413).json({ error: "업로드 용량 제한을 초과했습니다. (파일 정리 후 다시 시도해주세요)" });
                throw e;
            }

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

    router.post("/:id/file", authMiddleware, fileUploadLimiter, fileUpload.single('file'), async (req, res) => {
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

            const ext = path.extname(req.file.originalname).toLowerCase();
            const isImageExt = ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext);

            if (isImageExt) {
                const sig = await assertImageFileSignature(req.file.path).catch(() => null);
                if (sig) normalizeUploadedImageFile(req.file, sig.ext);
            }

            try {
                await enforceUploadQuotaOrThrow(userId, req.file.path);
            } catch (e) {
                if (String(e?.message) === "UPLOAD_QUOTA_EXCEEDED")
                    return res.status(413).json({ error: "업로드 용량 제한을 초과했습니다. (첨부파일 정리 후 다시 시도해주세요)" });
                throw e;
            }

            const fileUrl = `/paperclip/${userId}/${req.file.filename}`;

            await pool.execute(
                `INSERT IGNORE INTO page_file_refs
                    (page_id, owner_user_id, stored_filename, file_type, created_at)
                 VALUES (?, ?, ?, 'paperclip', NOW())`,
                [id, userId, req.file.filename]
            );

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

    const PAPERCLIP_PATH_RE = /^\/paperclip\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/;
    function parsePaperclipPathFromUserInput(raw) {
        if (typeof raw !== "string") return null;
        const s = raw.trim();
        if (!s) return null;

        let pathname = s;
        try {
            pathname = new URL(s, "http://local").pathname;
        } catch (_) {
            pathname = s; 
        }

        const m = pathname.match(PAPERCLIP_PATH_RE);
        if (!m) return null;
        const urlUserId = m[1];
        const filename = m[2];
        if (filename.includes("..")) return null; 
        return { urlUserId, filename };
    }

    function escapeLikeForSql(s) {
        return String(s).replace(/[\\%_]/g, (m) => `\\${m}`);
    }

    async function countPlaintextPaperclipRefsForUser(ownerUserId, filename, excludePageId) {
        const fileUrlPart = `/paperclip/${ownerUserId}/${filename}`;
        const likePattern = `%${escapeLikeForSql(fileUrlPart)}%`;

        const params = [ownerUserId, likePattern];
        let sql = `
            SELECT COUNT(*) AS cnt
              FROM pages
             WHERE user_id = ?
               AND is_encrypted = 0
               AND deleted_at IS NULL
               AND content LIKE ? ESCAPE '\\\\'
        `;
        if (excludePageId) {
            sql += ` AND id != ?`;
            params.push(excludePageId);
        }

        const [rows] = await pool.execute(sql, params);
        return Number(rows?.[0]?.cnt || 0);
    }

    async function backfillPaperclipRefsFromPlaintextContentForUser(ownerUserId, filename) {
        const fileUrlPart = `/paperclip/${ownerUserId}/${filename}`;
        const likePattern = `%${escapeLikeForSql(fileUrlPart)}%`;
        try {
            await pool.execute(
                `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
                 SELECT id, ?, ?, 'paperclip', NOW()
                   FROM pages
                  WHERE user_id = ?
                    AND is_encrypted = 0
                    AND deleted_at IS NULL
                    AND content LIKE ? ESCAPE '\\\\'`,
                [ownerUserId, filename, ownerUserId, likePattern]
            );
        } catch (_) {}
    }

    function findActiveYjsPagesReferencingPaperclip(ownerIdStr, filename, excludePageId) {
        try {
            if (!yjsDocuments) return [];
            const needle = `/paperclip/${ownerIdStr}/${filename}`;
            const out = [];
            for (const [pid, info] of yjsDocuments.entries()) {
                if (!info?.ydoc) continue;
                if (excludePageId && String(pid) === String(excludePageId)) continue;
                if (String(info.ownerUserId) !== String(ownerIdStr)) continue;
                if (info.isEncrypted === true) continue;

                const meta = info.ydoc.getMap('metadata');
                const html = meta?.get('content') || '';
                if (typeof html === 'string' && html.includes(needle)) {
                    out.push(String(pid));
                    continue;
                }
                try {
                    const xml = info.ydoc.getXmlFragment('prosemirror')?.toString?.() || '';
                    if (typeof xml === 'string' && xml.includes(needle)) out.push(String(pid));
                } catch (_) {}
            }
            return out;
        } catch (_) {
            return [];
        }
    }

    async function backfillPaperclipRefsForPageIds(pageIds, ownerUserId, filename) {
        if (!Array.isArray(pageIds) || pageIds.length === 0) return;
        const values = pageIds.map(() => `(?, ?, ?, 'paperclip', NOW())`).join(',');
        const params = [];
        for (const pid of pageIds) params.push(String(pid), ownerUserId, filename);
        try {
            await pool.execute(
                `INSERT IGNORE INTO page_file_refs (page_id, owner_user_id, stored_filename, file_type, created_at)
                 VALUES ${values}`,
                params
            );
        } catch (_) {}
    }

    function movePaperclipToTrash(fullPath, ownerUserId, filename) {
        try {
            const trashDir = path.resolve(__dirname, '..', 'paperclip-trash', String(ownerUserId));
            const trashBase = path.resolve(trashDir) + path.sep;
            if (!fs.existsSync(trashDir)) fs.mkdirSync(trashDir, { recursive: true, mode: 0o700 });

            const stamp = `${Date.now().toString(36)}-${Math.random().toString(16).slice(2, 10)}`;
            const dest = path.resolve(trashDir, `${stamp}-${filename}`);
            if (!dest.startsWith(trashBase)) return false;

            try { fs.renameSync(fullPath, dest); return true; }
            catch { fs.copyFileSync(fullPath, dest); fs.unlinkSync(fullPath); return true; }
        } catch (_) {
            return false;
        }
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
                return res.status(400).json({ error: "Invalid fileUrl" });
            }

            const { urlUserId, filename } = parsed;

            if (String(urlUserId) !== String(userId)) {
                return res.status(403).json({ error: "자신의 파일만 삭제할 수 있습니다." });
            }

            const baseDir = path.resolve(__dirname, "..", "paperclip", String(userId));
            const targetPath = path.resolve(baseDir, filename);
            const rel = path.relative(baseDir, targetPath);
            if (rel.startsWith("..") || path.isAbsolute(rel)) {
                return res.status(400).json({ error: "Invalid fileUrl" });
            }

            let remaining = null;
            let deletedPhysical = false;
            let connection;
            try {
                connection = await pool.getConnection();
                await connection.beginTransaction();

                await connection.execute(
                    `DELETE FROM page_file_refs
                      WHERE page_id = ?
                        AND owner_user_id = ?
                        AND stored_filename = ?
                        AND file_type = 'paperclip'`,
                    [id, userId, filename]
                );

                const [cntRows] = await connection.execute(
                    `SELECT COUNT(*) AS cnt
                       FROM page_file_refs
                      WHERE owner_user_id = ?
                        AND stored_filename = ?
                        AND file_type = 'paperclip'`,
                    [userId, filename]
                );
                remaining = Number(cntRows?.[0]?.cnt || 0);

                await connection.commit();
            } catch (txErr) {
                try { if (connection) await connection.rollback(); } catch (_) {}
                throw txErr;
            } finally {
                try { if (connection) connection.release(); } catch (_) {}
            }

            let blockedByPlaintextRefs = false;
            let blockedByActiveYjsRefs = false;
            let selfHealedRegistry = false;

            if (remaining === 0) {
                const plaintextRefs = await countPlaintextPaperclipRefsForUser(userId, filename, id);
                if (plaintextRefs > 0) {
                    blockedByPlaintextRefs = true;
                    selfHealedRegistry = true;
                    await backfillPaperclipRefsFromPlaintextContentForUser(userId, filename);
                }

                try {
                    const fileUrlPart = `/paperclip/${userId}/${filename}`;
                    const likePattern = `%${escapeLikeForSql(fileUrlPart)}%`;
                    const [selfRows] = await pool.execute(
                        `SELECT COUNT(*) AS cnt
                           FROM pages
                          WHERE id = ?
                            AND user_id = ?
                            AND is_encrypted = 0
                            AND content LIKE ? ESCAPE '\\\\'`,
                        [id, userId, likePattern]
                    );
                    if (Number(selfRows?.[0]?.cnt || 0) > 0) {
                        blockedByPlaintextRefs = true;
                        selfHealedRegistry = true;
                        await backfillPaperclipRefsForPageIds([String(id)], userId, filename);
                    }
                } catch (_) {}

                const activePages = findActiveYjsPagesReferencingPaperclip(userId, filename, id);
                if (activePages.length > 0) {
                    blockedByActiveYjsRefs = true;
                    selfHealedRegistry = true;
                    await backfillPaperclipRefsForPageIds(activePages, userId, filename);
                }

                if (selfHealedRegistry) {
                    const [cntRows2] = await pool.execute(
                        `SELECT COUNT(*) AS cnt
                           FROM page_file_refs
                          WHERE owner_user_id = ?
                            AND stored_filename = ?
                            AND file_type = 'paperclip'`,
                        [userId, filename]
                    );
                    remaining = Number(cntRows2?.[0]?.cnt || 0);
                }

                if (!blockedByPlaintextRefs && !blockedByActiveYjsRefs) {
                    if (fs.existsSync(targetPath) && fs.statSync(targetPath).isFile()) {
                        const moved = movePaperclipToTrash(targetPath, userId, filename);
                        if (!moved) fs.unlinkSync(targetPath);
                        deletedPhysical = true;
                    }
                }
            }

            res.json({
                ok: true,
                remainingRefs: remaining,
                deletedPhysical,
                blockedByPlaintextRefs,
                blockedByActiveYjsRefs,
                selfHealedRegistry
            });
        } catch (error) {
            logError("DELETE /api/pages/:id/file-cleanup", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    const IMG_PATH_RE = /^\/imgs\/(\d{1,12})\/([A-Za-z0-9][A-Za-z0-9._-]{0,199})$/;
    function parseImgsPathFromUserInput(raw) {
        if (typeof raw !== "string") return null;
        const s = raw.trim();
        if (!s) return null;

        let pathname = s;
        try { pathname = new URL(s, "http://local").pathname; } catch (_) { pathname = s; }

        const m = pathname.match(IMG_PATH_RE);
        if (!m) return null;
        const urlUserId = m[1];
        const filename = m[2];
        if (filename.includes("..")) return null;
        return { urlUserId, filename };
    }

    router.post("/:id/register-asset-ref", authMiddleware, async (req, res) => {
        const id = req.params.id;
        const userId = req.user.id;
        const { assetUrl } = req.body || {};

        if (!assetUrl) return res.status(400).json({ error: "assetUrl required" });

        try {
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission))
                return res.status(403).json({ error: "Forbidden" });

            const parsedPaper = parsePaperclipPathFromUserInput(assetUrl);
            const parsedImg = parsedPaper ? null : parseImgsPathFromUserInput(assetUrl);
            if (!parsedPaper && !parsedImg) return res.status(400).json({ error: "Invalid assetUrl" });

            const urlUserId = parsedPaper ? parsedPaper.urlUserId : parsedImg.urlUserId;
            const filename = parsedPaper ? parsedPaper.filename : parsedImg.filename;
            const fileType = parsedPaper ? 'paperclip' : 'imgs';

            if (String(urlUserId) !== String(userId))
                return res.status(403).json({ error: "자신의 자산만 등록할 수 있습니다." });

            await pool.execute(
                `INSERT IGNORE INTO page_file_refs
                    (page_id, owner_user_id, stored_filename, file_type, created_at)
                 VALUES (?, ?, ?, ?, NOW())`,
                [id, userId, filename, fileType]
            );

            res.json({ ok: true });
        } catch (e) {
            logError("POST /api/pages/:id/register-asset-ref", e);
            res.status(500).json({ error: "Failed" });
        }
    });

    router.post("/:id/editor-image", authMiddleware, fileUploadLimiter, editorImageUpload.single('image'), async (req, res) => {
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

            try {
                await enforceUploadQuotaOrThrow(userId, req.file.path);
            } catch (e) {
                if (String(e?.message) === "UPLOAD_QUOTA_EXCEEDED")
                    return res.status(413).json({ error: "업로드 용량 제한을 초과했습니다. (이미지 정리 후 다시 시도해주세요)" });
                throw e;
            }

            const imageUrl = `/imgs/${userId}/${req.file.filename}`;

            await pool.execute(
                `INSERT IGNORE INTO page_file_refs
                    (page_id, owner_user_id, stored_filename, file_type, created_at)
                 VALUES (?, ?, ?, 'imgs', NOW())`,
                [id, userId, req.file.filename]
            );

            res.json({ url: imageUrl });
        } catch (error) {
            if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            logError("POST /api/pages/:id/editor-image", error);
            res.status(500).json({ error: "Failed" });
        }
    });

    function canManagePublish(permission, ownerUserId, currentUserId) {
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

    return router;
};