const DANGEROUS_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

function scrubDangerousKeys(value, seen = new WeakSet()) {
    if (!value || typeof value !== 'object') return value;
    if (seen.has(value)) return value;
    seen.add(value);

    if (Array.isArray(value)) {
        for (let i = 0; i < value.length; i += 1) {
            value[i] = scrubDangerousKeys(value[i], seen);
        }
        return value;
    }

    for (const key of Object.keys(value)) {
        if (DANGEROUS_KEYS.has(key)) {
            delete value[key];
            continue;
        }
        value[key] = scrubDangerousKeys(value[key], seen);
    }

    return value;
}

export function safeJsonParse(text, fallback = null) {
    if (typeof text !== 'string' || !text.trim()) return fallback;
    try {
        return scrubDangerousKeys(JSON.parse(text));
    } catch {
        return fallback;
    }
}

export function safeJsonClone(value, fallback = null) {
    try {
        return scrubDangerousKeys(JSON.parse(JSON.stringify(value)));
    } catch {
        return fallback;
    }
}
