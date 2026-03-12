module.exports = ({ resolvePageAccess }) => {
    async function canWritePage({ viewerUserId, pageId, includeDeleted = false }) {
        const resolved = await resolvePageAccess({ viewerUserId, pageId, includeDeleted });
        if (!resolved || !resolved.canWrite) return { ok: false, error: '권한이 없습니다.', code: 403 };
        
        const { page, isPageOwner } = resolved;
        if (Number(page.is_encrypted) === 1 && Number(page.share_allowed) === 0 && !isPageOwner) return { ok: false, error: '비공개 암호화 페이지는 페이지 소유자만 변경할 수 있습니다.', code: 403 };
        
        return { ok: true, page, permission: resolved.permission, isPageOwner };
    }

    async function canDeletePage({ viewerUserId, pageId, includeDeleted = true }) {
        const resolved = await resolvePageAccess({ viewerUserId, pageId, includeDeleted });
        if (!resolved) return { ok: false, error: '페이지를 찾을 수 없거나 권한이 없습니다.', code: 404 };
        
        const { page, isPageOwner } = resolved;
        if (!isPageOwner) return { ok: false, error: '페이지 소유자만 삭제할 수 있습니다.', code: 403 };
        
        return { ok: true, page, isPageOwner };
    }

    return { canWritePage, canDeletePage };
};
