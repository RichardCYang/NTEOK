const fs = require('fs');

function detectImageTypeFromMagic(buf) {
	if (!Buffer.isBuffer(buf)) return null;
	if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff)
		return { ext: 'jpg', mime: 'image/jpeg' };

	if (buf.length >= 8 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47)
		return { ext: 'png', mime: 'image/png' };

	if (buf.length >= 6 && buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46)
		return { ext: 'gif', mime: 'image/gif' };

	if (buf.length >= 12 && buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 && buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50)
		return { ext: 'webp', mime: 'image/webp' };

	return null;
}

function assertImageFileSignature(filePath, allowedExts) {
	const fd = fs.openSync(filePath, 'r');
	try {
		const header = Buffer.alloc(16);
		fs.readSync(fd, header, 0, header.length, 0);
		const detected = detectImageTypeFromMagic(header);

		if (!detected)
			throw new Error('BAD_IMAGE_SIGNATURE');

		const set = allowedExts instanceof Set ? allowedExts : new Set(allowedExts || []);
		const det2 = detected.ext === 'jpg' ? 'jpeg' : detected.ext;

		if (set.size > 0 && !set.has(detected.ext) && !set.has(det2))
		    throw new Error('DISALLOWED_IMAGE_TYPE');

		return detected;
	} finally {
		fs.closeSync(fd);
	}
}

function installDomPurifySecurityHooks(DOMPurify) {
	if (!DOMPurify?.addHook) return;
	DOMPurify.addHook('afterSanitizeAttributes', (node) => {
		if (String(node.tagName).toLowerCase() === 'a') {
		    if (node.getAttribute('target') === '_blank') {
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
	installDomPurifySecurityHooks
};