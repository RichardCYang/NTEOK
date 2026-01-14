/**
 * Track parent modal visibility while opening child modals.
 * @param {string} parentSelector
 * @param {HTMLElement} childModalEl
 */
const childModalObservers = new WeakMap();

export function hideParentModalForChild(parentSelector, childModalEl) {
    if (!parentSelector || !childModalEl) return;

    const parent = document.querySelector(parentSelector);
    if (!parent) return;

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
 * Restore parent modal visibility when closing a child modal.
 * @param {HTMLElement} childModalEl
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
