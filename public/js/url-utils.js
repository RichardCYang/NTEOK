const CONTROL_CHARS_RE = /[\u0000-\u001F\u007F]/;
const HAS_SCHEME_RE = /^[a-zA-Z][a-zA-Z0-9+.-]*:/;

export function sanitizeHttpHref(raw, { allowRelative = false, addHttpsIfMissing = true, maxLen = 2048 } = {}) {
    if (typeof raw !== "string") return null;
    const v = raw.trim();
    if (!v) return null;
    if (v.length > maxLen) return null;
    if (CONTROL_CHARS_RE.test(v)) return null;
    if (v.startsWith("//")) return null;

    if (allowRelative && v.startsWith("#"))
        return v;

    if (allowRelative && v.startsWith("/")) {
        if (v.startsWith("//")) return null;
        return v;
    }

    const candidate = (!HAS_SCHEME_RE.test(v) && addHttpsIfMissing) ? `https://${v}` : v;
    let u;
    try {
        u = new URL(candidate);
    } catch {
        return null;
    }

    if (u.protocol !== "http:" && u.protocol !== "https:") return null;

    u.username = "";
    u.password = "";

    return u.toString();
}