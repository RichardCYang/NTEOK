export function flushEditorTransientNodeViews(editor) {
    if (!editor?.view?.dom) return;

    const root = editor.view.dom;
    const active = document.activeElement;

    if (active && typeof active.blur === 'function' && root.contains(active)) active.blur();

    document.dispatchEvent(new CustomEvent('nteok:flush-nodeviews'));
}
