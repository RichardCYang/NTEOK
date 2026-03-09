const SAFE_ALIGN = new Set(['left', 'center', 'right']);

export function sanitizeBlockAlign(raw, fallback = 'center') {
    const v = String(raw ?? '').trim().toLowerCase();
    return SAFE_ALIGN.has(v) ? v : fallback;
}

export function sanitizeCssLength(raw, fallback = '100%') {
    const v = String(raw ?? '').trim().toLowerCase();
    if (!v) return fallback;
    if (v === 'auto') return 'auto';

    const px = v.match(/^(\d{1,4})px$/);
    if (px) {
        const n = Number(px[1]);
        return (n >= 32 && n <= 2400) ? `${n}px` : fallback;
    }

    const pct = v.match(/^(\d{1,3})%$/);
    if (pct) {
        const n = Number(pct[1]);
        return (n >= 10 && n <= 100) ? `${n}%` : fallback;
    }

    return fallback;
}
