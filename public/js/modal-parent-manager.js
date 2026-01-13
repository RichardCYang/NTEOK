/**
 * 부모 모달을 숨기고, 자식 모달에 "어떤 부모를 복구해야 하는지"를 기록합니다.
 * @param {string} parentSelector 예: '#security-settings-modal'
 * @param {HTMLElement} childModalEl 자식 모달 엘리먼트
 */
export function hideParentModalForChild(parentSelector, childModalEl) {
    if (!parentSelector || !childModalEl) return;

    const parent = document.querySelector(parentSelector);
    if (!parent) return;

    // 이미 안 보이는 상태면 아무 것도 하지 않음
    if (parent.classList.contains('hidden')) return;

    parent.classList.add('hidden');
    childModalEl.dataset.restoreParentModal = parentSelector;
}

/**
 * 자식 모달에 기록된 부모 모달을 다시 표시합니다.
 * @param {HTMLElement} childModalEl 자식 모달 엘리먼트
 */
export function restoreParentModalFromChild(childModalEl) {
	if (!childModalEl) return;

	const parentSelector = childModalEl.dataset.restoreParentModal;
	if (!parentSelector) return;

	const parent = document.querySelector(parentSelector);
	if (parent)
	    parent.classList.remove('hidden');

	delete childModalEl.dataset.restoreParentModal;
}