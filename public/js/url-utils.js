/**
 * URL 유틸: href에 넣기 전에 http/https allowlist로 정규화/검증
 * - data: / javascript: / file: 등 위험/불필요 스킴 차단
 * - 제어문자 차단
 * - 스킴이 없으면 https:// 자동 보정(원치 않으면 addHttpsIfMissing=false)
 */
const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
const HAS_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

export function sanitizeHttpHref(raw, { allowRelative = false, addHttpsIfMissing = true, maxLen = 2048 } = {}) {
    if (typeof raw !== "string") return null;
    const v = raw.trim();
    if (!v) return null;
    if (v.length > maxLen) return null;
    if (CONTROL_CHARS_RE.test(v)) return null;

    // 상대 경로 허용 옵션
    if (allowRelative && (v.startsWith("/") || v.startsWith("#")))
        return v;

    const candidate = (!HAS_SCHEME_RE.test(v) && addHttpsIfMissing) ? `https://${v}` : v;
    let u;
    try {
        u = new URL(candidate);
    } catch {
        return null;
    }

    // http/https만 허용
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;

    // 사용자/패스워드 포함 URL은 피싱/오용 소지가 있어 제거(필요하면 정책 조정)
    u.username = "";
    u.password = "";

    return u.toString();
}