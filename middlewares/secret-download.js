'use strict';

function applySecretHeaders(res) {
    res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Content-Type-Options', 'nosniff');
}

function requireTopLevelNavigation(req, res, next) {
    const site = String(req.headers['sec-fetch-site'] || '').toLowerCase();
    const mode = String(req.headers['sec-fetch-mode'] || '').toLowerCase();
    const dest = String(req.headers['sec-fetch-dest'] || '').toLowerCase();
    const user = String(req.headers['sec-fetch-user'] || '');

    if (site && site !== 'same-origin') return res.status(403).json({ error: 'same-origin navigation only' });
    if (mode !== 'navigate' || user !== '?1') return res.status(403).json({ error: 'interactive navigation required' });
    if (dest && dest !== 'document' && dest !== 'iframe') return res.status(403).json({ error: 'invalid navigation destination' });
    return next();
}

module.exports = {
    applySecretHeaders,
    requireTopLevelNavigation
};
