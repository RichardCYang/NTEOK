
function validateAndNormalizeIcon(icon) {
    if (icon === null || icon === undefined) return null;

    const raw = String(icon).trim();
    if (!raw) return null;

    if (/[<>"'`]/.test(raw)) return null;

    const FA_RE = /^(fa-[\w-]+)(\s+fa-[\w-]+)*$/i;
    if (FA_RE.test(raw)) return raw;

    if (raw.length <= 8 && !/\s/.test(raw) && !/["'`&<>]/.test(raw)) {
        return raw;
    }

    return null;
}

module.exports = { validateAndNormalizeIcon };
