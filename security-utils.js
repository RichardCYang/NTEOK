const fs = require('fs');
const path = require('path');

const ALLOWED_ATTACHMENT_EXTS = new Set([
    '.pdf', '.txt', '.md', '.csv',
    '.docx', '.xlsx', '.pptx',
    '.jpg', '.jpeg', '.png', '.gif', '.webp',
    '.mp3', '.wav', '.mp4', '.mov'
]);

const BLOCKED_ATTACHMENT_EXTS = new Set([
    '.html', '.htm', '.xhtml', '.svg', '.xml',
    '.js', '.mjs', '.cjs', '.hta', '.swf', '.jar', '.wasm',
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.msi', '.apk', '.appimage',
    '.php', '.jsp', '.asp', '.aspx', '.cgi', '.pl', '.sh',
    '.doc', '.xls', '.ppt'
]);

function detectImageTypeFromMagic(buf) {
    if (!Buffer.isBuffer(buf)) return null;
    if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { ext: 'jpg', mime: 'image/jpeg' };
    if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47 && buf[4] === 0x0d && buf[5] === 0x0a && buf[6] === 0x1a && buf[7] === 0x0a) return { ext: 'png', mime: 'image/png' };
    if (buf.length >= 6 && buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38 && (buf[4] === 0x37 || buf[4] === 0x39) && buf[5] === 0x61) return { ext: 'gif', mime: 'image/gif' };
    if (buf.length >= 12 && buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x57 && buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50) return { ext: 'webp', mime: 'image/webp' };
    return null;
}

function assertImageFileSignature(filePath, allowedExts) {
    const fd = fs.openSync(filePath, 'r');
    try {
        const header = Buffer.alloc(32);
        fs.readSync(fd, header, 0, header.length, 0);
        const detected = detectImageTypeFromMagic(header);
        if (!detected) throw new Error('BAD_IMAGE_SIGNATURE');
        const set = allowedExts instanceof Set ? allowedExts : new Set(allowedExts || []);
        if (set.size > 0 && !set.has(detected.ext) && !set.has(detected.ext === 'jpg' ? 'jpeg' : detected.ext)) throw new Error('DISALLOWED_IMAGE_TYPE');
        return detected;
    } finally {
        fs.closeSync(fd);
    }
}

function bufferLooksLikeActiveContent(buf) {
    const head = Buffer.isBuffer(buf) ? buf.slice(0, 4096).toString('utf8').toLowerCase() : '';
    return head.includes('<html') || head.includes('<script') || head.includes('<svg') || head.includes('<?xml') || head.includes('javascript:') || head.includes('<iframe') || head.includes('<object') || head.includes('<embed');
}

function assertSafeAttachmentFile(filePath, originalName = '') {
    const ext = path.extname(String(originalName || filePath)).toLowerCase();
    if (!ALLOWED_ATTACHMENT_EXTS.has(ext) || BLOCKED_ATTACHMENT_EXTS.has(ext)) throw new Error('DISALLOWED_ATTACHMENT_TYPE');
    const fd = fs.openSync(filePath, 'r');
    try {
        const head = Buffer.alloc(4096);
        const n = fs.readSync(fd, head, 0, head.length, 0);
        if (bufferLooksLikeActiveContent(head.slice(0, n))) throw new Error('ACTIVE_CONTENT_ATTACHMENT');
        if (ext === '.pdf' && !head.slice(0, 5).equals(Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2D]))) throw new Error('BAD_PDF_SIGNATURE');
        if (['.docx', '.xlsx', '.pptx'].includes(ext) && !head.slice(0, 4).equals(Buffer.from([0x50, 0x4B, 0x03, 0x04]))) throw new Error('BAD_OOXML_SIGNATURE');
    } finally {
        fs.closeSync(fd);
    }
}

function installDomPurifySecurityHooks(DOMPurify) {
    if (!DOMPurify?.addHook) return;
    DOMPurify.addHook('afterSanitizeAttributes', (node) => {
        if (String(node.tagName).toLowerCase() === 'a') {
            const target = String(node.getAttribute('target') || '').trim().toLowerCase();
            if (target === '_blank') {
                const rel = (node.getAttribute('rel') || '').toLowerCase();
                const set = new Set(rel.split(/\s+/).filter(Boolean));
                set.add('noopener'); set.add('noreferrer');
                node.setAttribute('rel', Array.from(set).join(' '));
            }
        }
    });
}

module.exports = {
    detectImageTypeFromMagic,
    assertImageFileSignature,
    assertSafeAttachmentFile,
    installDomPurifySecurityHooks
};
