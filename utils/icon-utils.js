/**
 * 아이콘 입력값 검증/정규화 유틸
 *
 * 보안: 아이콘 값은 클라이언트에서 class="..." 속성으로 사용되는 경우가 많아
 * - 따옴표/각괄호/제어문자 등이 섞이면 DOM 기반 XSS(속성 탈출) 위험이 증가
 * - 따라서 허용 목록 기반(positive validation) 으로 제한
 */

function validateAndNormalizeIcon(icon) {
    if (icon === null || icon === undefined) return null;

    const raw = String(icon).trim();
    if (!raw) return null;

    // 기본 방어: 속성 탈출에 악용되는 문자는 차단
    if (/[<>"'`]/.test(raw)) return null;

    // FontAwesome class allowlist (예: "fa-solid fa-lock")
    const FA_RE = /^(fa-[\w-]+)(\s+fa-[\w-]+)*$/i;
    if (FA_RE.test(raw)) return raw;

    // 이모지(간단/짧은 형태) allowlist: 공백/따옴표/앰퍼샌드 등 차단
    if (raw.length <= 8 && !/\s/.test(raw) && !/["'`&<>]/.test(raw)) {
        return raw;
    }

    return null;
}

module.exports = { validateAndNormalizeIcon };
