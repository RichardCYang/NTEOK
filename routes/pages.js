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
        wsCloseConnectionsForPage,
        logError,
        generatePublishToken,
        coverUpload,
        editorImageUpload,
        fileUpload,
        path,
        fs,
        yjsDocuments,
        extractFilesFromContent,
        isPrivateOrLocalIP,
        getClientIpFromRequest
	} = dependencies;

    // 주의: 이 동기화는 특정 사용자(pageOwnerUserId)의 첨부 레지스트리 slice만 갱신함
    // 따라서 삭제 쿼리도 반드시 owner_user_id 범위로 제한해야 타 사용자 레코드를 건드리지 않음
    async function syncPageFileRefs(pageId, pageOwnerUserId, content) {
        if (!content) return;
        try {
            const ownerId = Number(pageOwnerUserId);
            if (!Number.isFinite(ownerId)) throw new Error('Invalid pageOwnerUserId');

            const newFiles = extractFilesFromContent(content, ownerId);

            // 신규 파일 등록 (INSERT IGNORE)
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

            // 이 페이지에서 더 이상 참조되지 않는 레지스트리 제거
            // 중요: 현재 동기화 대상(ownerId)의 레코드만 제거해야 타 사용자 첨부 레지스트리를 보호함
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

    /**
     * ============================================================
     * 보안: 업로드 총량 + 횟수 제한 (CWE-400 / OWASP API4)
     * ------------------------------------------------------------
     * 문제: 단건 파일 크기만 제한되어 있고, 총량/횟수 제한이 없어
     *      디스크 고갈(DoS)이 가능함
     * 해결:
     *  - userId 기준 업로드 레이트리밋
     *  - userId 기준 디렉터리 총량 quota 강제
     * ============================================================
     */

    // 환경변수로 조정 가능 (기본값: 1GB)
    const MAX_PAPERCLIP_BYTES_PER_USER = (() => {
        const raw = String(process.env.MAX_PAPERCLIP_BYTES_PER_USER || '').trim().toLowerCase();
        if (!raw) return 1024 * 1024 * 1024; // 1GB
        const m = raw.match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/);
        if (!m) return 1024 * 1024 * 1024;
        const n = Number(m[1]);
        const unit = m[2] || 'b';
        const mul = unit === 'gb' ? 1024**3 : unit === 'mb' ? 1024**2 : unit === 'kb' ? 1024 : 1;
        // 50MB~20GB 범위로 클램핑 (최소 50MB, 최대 20GB)
        return Math.max(50 * 1024 * 1024, Math.min(20 * 1024**3, Math.floor(n * mul)));
    })();

    // 업로드 요청 횟수 제한 (기본: 60회/시간)
    const fileUploadLimiter = rateLimit({
        windowMs: 60 * 60 * 1000,
        max: Number.parseInt(process.env.FILE_UPLOAD_MAX_PER_HOUR || "60", 10),
        standardHeaders: true,
        legacyHeaders: false,
        keyGenerator: (req) => req.user?.id ? `user:${req.user.id}` : `ip:${getClientIp(req)}`,
        handler: (_req, res) => res.status(429).json({ error: "업로드 요청이 너무 많습니다. 잠시 후 다시 시도해주세요." })
    });

    // 디렉터리 사용량 캐시(성능)
    const usageCache = new Map(); // key=userId -> { bytes, ts }
    const USAGE_CACHE_TTL_MS = 30 * 1000;

    /**
     * 보안(중요): 업로드 quota 체크는 비동기 I/O(await) 사이에 레이스가 발생할 수 있음
     * - 동시에 여러 업로드가 들어오면, 둘 다 캐시 기준으로 통과 → 총량 초과가 누락될 수 있음
     * - userId 단위로 직렬화하여 TOCTOU/레이스를 방지
     */
    const quotaLocks = new Map(); // userId(string) -> Promise chain
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
            // 보안: paperclip, imgs, covers 세 곳의 용량을 모두 합산하여 사용자 총 할당량(Quota) 체크
            const dirs = [
                path.join(__dirname, "..", "paperclip", String(userId)),
                path.join(__dirname, "..", "imgs", String(userId)),
                path.join(__dirname, "..", "covers", String(userId))
            ];

            // 방어 심층화: newFilePath는 반드시 해당 userId의 업로드 디렉터리 내부여야만 stat/unlink 수행
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

            /**
             * 취약점 수정(핵심):
             * - 캐시 fast-path에서도 이번 업로드 파일 크기를 반영하여 projected total로 판정해야 함
             * - 그렇지 않으면 TTL 동안 여러 업로드로 quota 우회 → 디스크 고갈(DoS)
             */
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

                // 캐시를 누적 갱신하여 TTL 동안 연속 업로드도 정확히 제한
                usageCache.set(userId, { bytes: projected, ts: now });
                return;
            }

            let totalBytes = 0;
            for (const d of dirs) {
                totalBytes += await computeDirUsageBytes(d);
            }
            usageCache.set(userId, { bytes: totalBytes, ts: now });

            if (totalBytes > MAX_PAPERCLIP_BYTES_PER_USER) {
                // quota 초과 시 방금 업로드한 파일은 즉시 삭제
                safeUnlinkNewFile();
                // 캐시 무효화 (다음 요청 때 다시 계산하도록)
                usageCache.delete(userId);
                throw new Error("UPLOAD_QUOTA_EXCEEDED");
            }
        });
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

    // ===== SSRF 방어 강화: 기능별 Host Allowlist (Fail-Closed) =====
    // 북마크 예시: BOOKMARK_METADATA_HOST_ALLOWLIST=example.com,*.trusted-site.com
    // 이미지 예시: IMAGE_PROXY_HOST_ALLOWLIST=images.example.com,*.cdn.example.net
    // 패턴 규칙:
    // - exact: example.com
    // - suffix wildcard: *.example.com  (하위 도메인만 허용, apex 미포함)
    function parseHostAllowlist(envName) {
        return String(process.env[envName] || "")
            .split(",")
            .map(v => v.trim().toLowerCase())
            .filter(Boolean);
    }

    const BOOKMARK_METADATA_HOST_ALLOWLIST = parseHostAllowlist("BOOKMARK_METADATA_HOST_ALLOWLIST");
    const IMAGE_PROXY_HOST_ALLOWLIST = parseHostAllowlist("IMAGE_PROXY_HOST_ALLOWLIST");

    function hostMatchesAllowlist(hostname, patterns) {
        const h = String(hostname || "").toLowerCase();
        if (!h) return false;
        for (const p of patterns) {
            if (p.startsWith("*.")) {
                const base = p.slice(2);
                // *.example.com 은 foo.example.com 허용, example.com 은 불허
                if (base && h.length > base.length && h.endsWith("." + base)) return true;
            } else {
                if (h === p) return true;
            }
        }
        return false;
    }

    function getFeatureHostAllowlist(feature) {
        if (feature === "bookmark-metadata") return BOOKMARK_METADATA_HOST_ALLOWLIST;
        if (feature === "image-proxy") return IMAGE_PROXY_HOST_ALLOWLIST;
        return [];
    }

    function enforceOutboundHostPolicy(u, feature) {
        const hostname = String(u?.hostname || "").toLowerCase();
        if (!hostname) throw new Error("Invalid hostname");

        // 기능별 allowlist 미설정 시 차단 (Fail-Closed)
        const patterns = getFeatureHostAllowlist(feature);
        if (!Array.isArray(patterns) || patterns.length === 0)
            throw new Error(`Outbound host allowlist is not configured for ${feature}`);

        // IP literal 직접 입력은 차단 (공격 표면 축소)
        if (net.isIP(hostname))
            throw new Error("IP literal hosts are not allowed");

        if (!hostMatchesAllowlist(hostname, patterns))
            throw new Error("Host is not allowed");
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

    async function validateOutboundUrl(urlStr, feature = "generic") {
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

        // 보안: 기능별 host allowlist 우선 적용
        // - public 인터넷 전체를 허용하지 않고, 필요한 도메인만 허용
        // - SSRF/open proxy 성격 제거
        if (feature === "bookmark-metadata" || feature === "image-proxy")
            enforceOutboundHostPolicy(u, feature);

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
            const { url, lookup } = await validateOutboundUrl(current, "bookmark-metadata");

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

    // 인증이 필요한 outbound 프록시/메타데이터 엔드포인트 보호용:
    // - same-site(서브도메인)는 SameSite 쿠키가 전송될 수 있으므로 허용하지 않음
    // - same-origin만 허용
    // - Fetch Metadata 미지원/누락 환경에서는 Origin/Referer로 보수적 fallback
    function requireSameOriginForOutboundProxy(req, res, next) {
        const sfs = String(req.headers["sec-fetch-site"] || "").toLowerCase();

        // modern browsers: Sec-Fetch-Site는 브라우저가 세팅하는 forbidden header
        if (sfs) {
            if (sfs !== "same-origin")
                return res.status(403).json({ error: "Forbidden" });
            return next();
        }

        const expectedOrigin = `${req.protocol}://${req.get("host")}`;
        const origin = String(req.headers.origin || "").trim();
        const referer = String(req.headers.referer || "").trim();

        const hasSameOrigin = (raw) => {
            if (!raw) return false;
            try {
                const u = new URL(raw);
                return u.origin === expectedOrigin;
            } catch {
                return false;
            }
        };

        // 둘 다 없으면(구형/비정상 클라이언트) 보수적으로 차단
        // 이 엔드포인트는 브라우저 앱 내부에서만 호출되므로 호환성 영향이 작음
        if (!origin && !referer)
            return res.status(403).json({ error: "Forbidden" });

        if (origin && !hasSameOrigin(origin))
            return res.status(403).json({ error: "Forbidden" });

        if (referer && !hasSameOrigin(referer))
            return res.status(403).json({ error: "Forbidden" });
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

    // 보안: parentId는 객체 ID이므로 저장소 권한만으로 충분하지 않음
    // - 현재 사용자에게 보이는 페이지인지(객체 단위 권한)
    // - 같은 저장소인지(교차 저장소 참조 금지)
    async function validateParentForCreate({ userId, storageId, parentId }) {
        if (parentId == null) return { ok: true, parentId: null };
        if (typeof parentId !== "string") return { ok: false, status: 400, error: "Invalid parentId" };

        const normalizedParentId = parentId.trim();
        if (!normalizedParentId || normalizedParentId.length > 64)
            return { ok: false, status: 400, error: "Invalid parentId" };

        // pagesRepo.getPageByIdForUser 는 pageSqlPolicy 를 통해 가시성(암호화/비공개 포함)까지 반영
        const parent = await pagesRepo.getPageByIdForUser({ userId, pageId: normalizedParentId });
        if (!parent) {
            // 존재 여부/권한 여부를 구분하지 않아 정보 누출 방지
            return { ok: false, status: 404, error: "Parent page not found" };
        }

        if (String(parent.storage_id) !== String(storageId)) {
            // 교차 저장소 부모 연결 금지 (무결성 + 테넌트 격리)
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
                
                // 보안: 암호화 필드 형식 및 크기 검증 (Stored XSS 및 DoS 방어)
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

            const content = isEncrypted ? '' : sanitizeHtmlContent(req.body.content || "<p></p>");
            await pool.execute(`INSERT INTO pages (id, user_id, parent_id, title, content, sort_order, created_at, updated_at, storage_id, is_encrypted, encryption_salt, encrypted_content) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [id, userId, parentId, title, content, sortOrder, nowStr, nowStr, storageId, isEncrypted, salt, encContent]);

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
            const existing = await loadPageForMutationOr404(userId, id, res);
            if (!existing) return;

            const permission = await storagesRepo.getPermission(userId, existing.storage_id);
            if (!permission || !['EDIT', 'ADMIN'].includes(permission))
                return res.status(403).json({ error: "이 페이지를 수정할 권한이 없습니다." });

            const title = req.body.title !== undefined ? sanitizeInput(req.body.title) : existing.title;
            const isEncrypted = req.body.isEncrypted !== undefined ? (req.body.isEncrypted ? 1 : 0) : existing.is_encrypted;
            const encryptionStateChanged = Number(existing.is_encrypted) !== Number(isEncrypted);

            const hasEncryptionSalt = Object.prototype.hasOwnProperty.call(req.body, "encryptionSalt");
            const hasEncryptedContent = Object.prototype.hasOwnProperty.call(req.body, "encryptedContent");

            let salt;
            let encContent;

            if (Number(isEncrypted) === 1) {
                // 암호화 페이지: 명시적으로 전달된 값만 반영, 없으면 기존값 유지
                // (|| 사용 금지: '' 같은 falsy 값 때문에 기존값으로 되돌아가는 버그 방지)
                salt = hasEncryptionSalt ? req.body.encryptionSalt : existing.encryption_salt;
                encContent = hasEncryptedContent ? req.body.encryptedContent : existing.encrypted_content;

                // 상태 전환(평문 -> 암호화) 시에는 최소한 암호문은 있어야 함 (솔트는 저장소 레벨일 경우 없을 수 있음)
                if (encryptionStateChanged && !hasEncryptedContent)
                    return res.status(400).json({ error: "암호화 전환 시 encryptedContent가 필요합니다." });

                // 보안: 암호화 필드 형식 및 크기 검증 (Stored XSS 및 DoS 방어)
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
                // 보안: 평문 페이지로 저장될 때는 암호화 잔존 데이터 완전 제거
                salt = null;
                encContent = null;
            }

            const content = isEncrypted
                ? ''
                : (req.body.content !== undefined ? sanitizeHtmlContent(req.body.content) : existing.content);
            const icon = req.body.icon !== undefined ? validateAndNormalizeIcon(req.body.icon) : existing.icon;
            const hPadding = req.body.horizontalPadding !== undefined ? req.body.horizontalPadding : existing.horizontal_padding;
            const nowStr = formatDateForDb(new Date());
            let sql = `UPDATE pages SET title=?, content=?, is_encrypted=?, encryption_salt=?, encrypted_content=?, icon=?, horizontal_padding=?, updated_at=?`;
            const params = [title, content, isEncrypted, salt, encContent, icon, hPadding, nowStr];
            // 보안: 암호화 페이지는 서버/DB 어디에도 평문이 남지 않아야 함
            // - yjs_state는 협업 편집 상태(전체 문서 스냅샷)를 그대로 담을 수 있어(평문 잔존) 암호화 보안을 훼손
            // - 따라서 (1) 콘텐츠가 직접 업데이트되거나, (2) 암호화 상태가 바뀌거나, (3) 암호화 상태인 경우에는
            //   yjs_state를 항상 초기화하고, 서버 메모리의 Yjs 문서도 drop
            const shouldResetYjsState = (req.body.content !== undefined) || encryptionStateChanged || (Number(isEncrypted) === 1);
            if (shouldResetYjsState) {
                sql += `, yjs_state=NULL`;
                if (yjsDocuments && yjsDocuments.has(id)) yjsDocuments.delete(id);
            }

            sql += ` WHERE id=?`; params.push(id);
            await pool.execute(sql, params);

            if (!isEncrypted && content)
                await syncPageFileRefs(id, userId, content);

            // 보안: 페이지 암호화 정책 변경 시 기존 page WebSocket 구독 즉시 강제 종료
            // - yjsDocuments.delete()만으론 이미 열려 있는 WS 연결이 살아남아 TOCTOU 권한 우회 가능
            if (encryptionStateChanged && typeof wsCloseConnectionsForPage === 'function')
                wsCloseConnectionsForPage(id, 1008, 'Page access policy changed');

            await pagesRepo.recordUpdateHistory({
                userId,
                storageId: existing.storage_id,
                pageId: id,
                action: 'UPDATE_PAGE',
                details: { title }
            });

            // 보안: 브로드캐스트 필터링은 업데이트 후 가시성 상태 기준으로 수행
            // - 업데이트 전(existing) 상태를 쓰면 정책 전환 타이밍에 잘못된 대상에게 알림이 전파될 수 있음
            const updatedVis = wsPageVisibilityFromRow({ ...existing, is_encrypted: Number(isEncrypted) });
            wsBroadcastToStorage(existing.storage_id, 'metadata-change', { pageId: id, field: 'title', value: title }, null, { pageVisibility: updatedVis });
            res.json({ id, title, updatedAt: new Date().toISOString() });
        } catch (e) { logError("PUT /api/pages/:id", e); res.status(500).json({ error: "Failed" }); }
    });

    router.patch("/reorder", authMiddleware, async (req, res) => {
        const { storageId, pageIds, parentId } = req.body;
        const userId = req.user.id;

        // 보안: 대량 변경 API는 반드시 객체 단위 권한(Object-level auth)을 다시 강제해야 함
        // - storage 권한(EDIT/ADMIN)이 있어도, 특정 페이지는 is_encrypted=1 + share_allowed=0 정책으로 비가시일 수 있음
        // - (특히) 과거에 접근 가능했던 페이지의 ID를 알고 있는 협업자가, 접근이 회수된 뒤에도
        //   이 엔드포인트를 통해 sort_order를 변경하는 무단 변경(Broken Access Control)을 막기 위함
        try {
            if (typeof storageId !== "string" || !storageId.trim())
                return res.status(400).json({ error: "storageId required" });

            if (!Array.isArray(pageIds) || pageIds.length === 0)
                return res.status(400).json({ error: "pageIds required" });

            // DoS 방지: 한 번에 너무 많은 업데이트 금지
            const MAX_REORDER_PAGES = Number(process.env.MAX_REORDER_PAGES || 2000);
            if (pageIds.length > MAX_REORDER_PAGES)
                return res.status(413).json({ error: `Too many pageIds (max ${MAX_REORDER_PAGES})` });

            // 입력 정규화 + 중복/이상치 차단
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

            // (선택) parentId가 있으면, 해당 parent 페이지도 보이는지 확인
            if (parentId) {
                const parent = await pagesRepo.getPageByIdForUser({ userId, pageId: parentId });
                if (!parent || String(parent.storage_id) !== String(storageId))
                    return res.status(404).json({ error: "Not found" });
            }

            // 핵심: 요청에 포함된 모든 pageId가 현재 사용자에게 보이는 페이지인지 DB에서 재검증
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
                // 존재/권한 여부를 섞어 404로 통일 (enumeration 완화)
                return res.status(404).json({ error: "Not found" });
            }

            // 일관성: 트랜잭션으로 sort_order 일괄 적용
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
                // 메모리에 로드된 Yjs 문서 정리
                try {
                    const docInfo = yjsDocuments.get(pid);
                    if (docInfo?.ydoc) {
                        // DB에 최종 상태 저장 (선택: 삭제 직전 상태 보존)
                        await saveYjsDocToDatabase(pool, sanitizeHtmlContent, pid, docInfo.ydoc);
                    }
                } catch (_) {}

                try {
                    yjsDocuments.delete(pid);
                } catch (_) {}

                // 실시간 구독(WebSocket) 정리
                try {
                    const conns = wsConnections?.pages?.get(pid);
                    if (conns && conns.size) {
                        // 구독자들에게 페이지 삭제 알림 전송 (클라이언트 UI 반영용)
                        try { wsBroadcastToPage(pid, 'page-deleted', { pageId: pid }); } catch (_) {}

                        // 연결 강제 종료 (Broken Access Control 차단)
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

            // 보안: 업로드 총량 강제 (디스크 고갈 DoS 방지)
            try {
                // cover 이미지는 covers 디렉토리에 저장되지만, paperclip 기준으로 quota를 통합 적용할 수도 있음
                // 여기서는 paperclip/ userId 디렉토리와 cover/ userId 디렉토리를 각각 관리하거나
                // enforceUploadQuotaOrThrow가 paperclip을 체크하므로, cover도 동일한 userId별 자원 정책 적용
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

            // 보안: 파일 시그니처 검증 (이미지인 경우) 및 파일명 정규화
            const ext = path.extname(req.file.originalname).toLowerCase();
            const isImageExt = ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext);

            if (isImageExt) {
                const sig = await assertImageFileSignature(req.file.path).catch(() => null);
                if (sig) normalizeUploadedImageFile(req.file, sig.ext);
            }

            // 보안: 업로드 총량 강제 (디스크 고갈 DoS 방지)
            try {
                await enforceUploadQuotaOrThrow(userId, req.file.path);
            } catch (e) {
                if (String(e?.message) === "UPLOAD_QUOTA_EXCEEDED")
                    return res.status(413).json({ error: "업로드 용량 제한을 초과했습니다. (첨부파일 정리 후 다시 시도해주세요)" });
                throw e;
            }

            const fileUrl = `/paperclip/${userId}/${req.file.filename}`;

            // 보안: 첨부파일-페이지 정당 참조 레지스트리 등록
            // - 다운로드 권한 검증 시 본문 문자열 LIKE 만으로 판단하면 위조 가능(IDOR/BOLA)
            // - 서버가 업로드 성공 시점에만 레지스트리를 기록하여 정당한 첨부를 증명
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

            // 보안: 레지스트리에서도 제거
            await pool.execute(
                `DELETE FROM page_file_refs
                  WHERE page_id = ? AND owner_user_id = ? AND stored_filename = ? AND file_type = 'paperclip'`,
                [id, userId, filename]
            );

            res.json({ ok: true });
        } catch (error) {
            logError("DELETE /api/pages/:id/file-cleanup", error);
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

            // 보안: 업로드 총량 강제 (디스크 고갈 DoS 방지)
            try {
                // editor-image는 imgs 디렉토리에 저장되지만, paperclip 기준으로 quota를 통합 적용하거나
                // enforceUploadQuotaOrThrow를 그대로 호출 (내부적으로 paperclip을 보더라도
                // 동일한 userId별 자원 정책의 일환으로 작동)
                await enforceUploadQuotaOrThrow(userId, req.file.path);
            } catch (e) {
                if (String(e?.message) === "UPLOAD_QUOTA_EXCEEDED")
                    return res.status(413).json({ error: "업로드 용량 제한을 초과했습니다. (이미지 정리 후 다시 시도해주세요)" });
                throw e;
            }

            const imageUrl = `/imgs/${userId}/${req.file.filename}`;

            // 보안: 이미지-페이지 정당 참조 레지스트리 등록
            // - 다운로드 권한 검증 시 본문 문자열 LIKE 만으로 판단하면 위조 가능(IDOR/BOLA)
            // - 서버가 업로드 성공 시점에만 레지스트리를 기록하여 정당한 첨부를 증명
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
    router.post("/:id/bookmark-metadata", authMiddleware, requireSameOriginForOutboundProxy, outboundProxyLimiter, async (req, res) => {
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
    router.get("/proxy/image", authMiddleware, requireSameOriginForOutboundProxy, outboundProxyLimiter, async (req, res) => {
        const urlStr = (typeof req.query.url === "string") ? req.query.url : "";
        if (!urlStr) return res.status(400).end();

        // URL 문자열 기반 1차 SVG 사전 차단
        // fetch 전에 차단하여 불필요한 외부 요청 및 MIME 스니핑 우회 시도 방지
        const urlStrLower = urlStr.toLowerCase();
        if (urlStrLower.includes(".svg") || urlStrLower.includes("image/svg") || urlStrLower.includes("svg+xml")) {
            return res.status(415).end();
        }

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
                const { url, lookup } = await validateOutboundUrl(current, "image-proxy");
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
                // sandbox + 명시적 지시어로 SVG 우회/브라우저 동작 차이를 방어 (Defense-in-Depth)
                'Content-Security-Policy': "default-src 'none'; sandbox; script-src 'none'; style-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
                'Cross-Origin-Resource-Policy': 'same-origin',
                // 인증 API 프록시 응답은 shared cache/브라우저 캐시 저장 자체를 금지
                'Cache-Control': 'private, no-store',
                // 외부로 Referer 헤더가 노출되지 않도록 차단
                'Referrer-Policy': 'no-referrer'
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
                msg.includes('Host is not allowed') ||
                msg.includes('allowlist is not configured') ||
                msg.includes('IP literal hosts are not allowed') ||
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