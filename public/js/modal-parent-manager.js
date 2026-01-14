/**
 * 부모 모달을 숨기고, 자식 모달에 어떤 부모를 복구해야 하는지를 기록합니다.
 * @param {string} parentSelector
 * @param {HTMLElement} childModalEl
 */
const childModalObservers = new WeakMap();

export function hideParentModalForChild(parentSelector, childModalEl) {
    if (!parentSelector || !childModalEl) return;

    const parent = document.querySelector(parentSelector);
    if (!parent) return;

    // 이미 안 보이는 상태면 아무 것도 하지 않음
    if (parent.classList.contains('hidden')) return;

    childModalEl.dataset.restoreParentModal = parentSelector;

    const applyStandby = () => {
        if (!childModalEl.classList.contains('hidden')) {
            parent.classList.add('modal-standby');
            return true;
        }
        return false;
    };

    if (applyStandby()) return;

    const existingObserver = childModalObservers.get(childModalEl);
    if (existingObserver) existingObserver.disconnect();

    const observer = new MutationObserver(() => {
        if (applyStandby()) {
            observer.disconnect();
            childModalObservers.delete(childModalEl);
        }
    });

    observer.observe(childModalEl, { attributes: true, attributeFilter: ['class'] });
    childModalObservers.set(childModalEl, observer);
}

/**
 * 자식 모달에 기록된 부모 모달을 다시 표시합니다.
 * @param {HTMLElement} childModalEl 자식 모달 엘리먼트
 */
export function restoreParentModalFromChild(childModalEl) {
    if (!childModalEl) return;

    const observer = childModalObservers.get(childModalEl);
    if (observer) {
        observer.disconnect();
        childModalObservers.delete(childModalEl);
    }

    const parentSelector = childModalEl.dataset.restoreParentModal;
    if (!parentSelector) return;

    const parent = document.querySelector(parentSelector);
    if (parent) parent.classList.remove('modal-standby');

    delete childModalEl.dataset.restoreParentModal;
}
