
export function secureFetch(url, options = {}) {
    let targetUrl;
    try {
        targetUrl = new URL(url, window.location.href);
    } catch (e) {
        throw new Error('[보안]: Invalid URL');
    }

    const isSameOrigin = (targetUrl.origin === window.location.origin);

    const finalOptions = { ...options };
    if (!finalOptions.credentials)
        finalOptions.credentials = isSameOrigin ? 'same-origin' : 'omit';

    const method = (finalOptions.method || 'GET').toUpperCase();
    const isStateChanging = !['GET', 'HEAD', 'OPTIONS'].includes(method);

    if (isSameOrigin && isStateChanging) {
        finalOptions.headers = finalOptions.headers || {};
        finalOptions.headers = window.csrfUtils.addCsrfHeader({
            headers: finalOptions.headers
        }).headers;
    }

    return fetch(targetUrl.toString(), finalOptions);
}

export function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

export function escapeHtmlAttr(text) {
    if (text === undefined || text === null) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#x27;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

export function addIcon(button, icon) {
	button.textContent = "";
	const iEl = document.createElement("i");
	const safeIcon = String(icon || "").replace(/[^a-zA-Z0-9 _-]/g, "").trim();
	iEl.className = safeIcon;
	button.appendChild(iEl);
}

export function showErrorInEditor(message, editor) {
    const safeMessage = message || '오류가 발생했습니다.';

    if (editor) {
        const escapedMessage = escapeHtml(safeMessage);
        editor.commands.setContent(`<p style="color: red;">${escapedMessage}</p>`, { emitUpdate: false });
    } else {
        const el = document.querySelector("#editor");
        if (el) {
            el.textContent = '';
            const p = document.createElement('p');
            p.style.color = 'red';
            p.textContent = safeMessage;
            el.appendChild(p);
        }
    }
}

export function closeAllDropdowns() {
    document.querySelectorAll(".dropdown-menu").forEach(menu => {
        menu.classList.add("hidden");
        const dropdown = menu.closest("[data-dropdown]");
        if (dropdown) {
            dropdown.classList.remove("open");
        }
    });
}

export function openDropdown(menu, trigger) {
    menu.classList.remove("hidden");
    const dropdown = trigger ? trigger.closest("[data-dropdown]") : null;
    if (dropdown) {
        dropdown.classList.add("open");
    }
}

export function showContextMenu(triggerBtn, menuItems) {
    const contextMenu = document.querySelector("#context-menu");
    const contextMenuContent = document.querySelector("#context-menu-content");

    if (!contextMenu || !contextMenuContent) return;

    contextMenuContent.textContent = "";

    if (typeof menuItems === "string") {
        const warn = document.createElement("div");
        warn.style.padding = "10px";
        warn.style.fontSize = "12px";
        warn.style.color = "#b91c1c";
        warn.textContent = "[SECURITY] Deprecated menuItems string detected. Please migrate to array format.";
        contextMenuContent.appendChild(warn);

        const pre = document.createElement("pre");
        pre.style.whiteSpace = "pre-wrap";
        pre.style.wordBreak = "break-word";
        pre.style.padding = "10px";
        pre.style.margin = "0";
        pre.textContent = menuItems;
        contextMenuContent.appendChild(pre);
    } else if (Array.isArray(menuItems)) {
        menuItems.forEach((item) => {
            const btn = document.createElement("button");
            btn.type = "button";

            if (item.action) btn.dataset.action = String(item.action);
            if (item.className) btn.className = String(item.className);

            if (item.dataset && typeof item.dataset === "object") {
                Object.entries(item.dataset).forEach(([k, v]) => {
                    const safeKey = String(k).replace(/[^a-zA-Z0-9_-]/g, "");
                    btn.dataset[safeKey] = String(v);
                });
            }

            if (item.icon) {
                const iEl = document.createElement("i");
                iEl.className = String(item.icon).replace(/[^a-zA-Z0-9 _-]/g, "").trim();
                iEl.style.marginRight = "8px";
                btn.appendChild(iEl);
            }

            const label = document.createElement("span");
            label.textContent = item.label ? String(item.label) : "";
            btn.appendChild(label);

            contextMenuContent.appendChild(btn);
        });
    } else {
        const fallback = document.createElement("div");
        fallback.style.padding = "10px";
        fallback.textContent = "Invalid context menu items.";
        contextMenuContent.appendChild(fallback);
    }

    const rect = triggerBtn.getBoundingClientRect();

    contextMenu.style.left = '0px';
    contextMenu.style.top = '0px';
    contextMenu.classList.remove("hidden");

    const menuRect = contextMenu.getBoundingClientRect();

    let left = rect.right + 6;
    let top = rect.top;

    if (left + menuRect.width > window.innerWidth) {
        left = rect.left - menuRect.width - 6;
    }

    if (top + menuRect.height > window.innerHeight) {
        top = window.innerHeight - menuRect.height - 10;
    }

    if (top < 10) {
        top = 10;
    }

    contextMenu.style.left = `${left}px`;
    contextMenu.style.top = `${top}px`;
}

export function closeContextMenu() {
    const contextMenu = document.querySelector("#context-menu");
    if (contextMenu) {
        contextMenu.classList.add("hidden");
        delete contextMenu.dataset.triggerId;
    }
}

export function syncPageUpdatedAtPadding() {
    const editorEl = document.querySelector(".editor");
    if (!editorEl) return;

    const editorStyle = window.getComputedStyle(editorEl);
    const proseEl = editorEl.querySelector(".ProseMirror");
    const proseStyle = proseEl ? window.getComputedStyle(proseEl) : null;

    const editorLeft = parseFloat(editorStyle.paddingLeft) || 0;
    const editorRight = parseFloat(editorStyle.paddingRight) || 0;
    const proseLeft = proseStyle ? parseFloat(proseStyle.paddingLeft) || 0 : 0;
    const proseRight = proseStyle ? parseFloat(proseStyle.paddingRight) || 0 : 0;

    const totalLeft = editorLeft + proseLeft;
    const totalRight = editorRight + proseRight;

    const updatedAtContainer = document.querySelector("#page-updated-at-container");
    if (updatedAtContainer) {
        updatedAtContainer.style.paddingLeft = `${totalLeft}px`;
        updatedAtContainer.style.paddingRight = `${totalRight}px`;
    }

    const commentsContainer = document.querySelector("#page-comments-section");
    if (commentsContainer) {
        commentsContainer.style.paddingLeft = `${totalLeft}px`;
        commentsContainer.style.paddingRight = `${totalRight}px`;
    }
}

export function showLoadingOverlay() {
    const overlay = document.querySelector('.loading-overlay');
    if (overlay) {
        overlay.classList.remove('hidden');
    }
}

export function hideLoadingOverlay() {
    const overlay = document.querySelector('.loading-overlay');
    if (overlay) {
        overlay.classList.add('hidden');
    }
}

export function openSidebar() {
    const sidebar = document.querySelector(".sidebar");
    const overlay = document.querySelector("#sidebar-overlay");

    if (sidebar) {
        sidebar.classList.add("open");
    }
    if (overlay) {
        overlay.classList.add("visible");
    }
}

export function closeSidebar() {
    const sidebar = document.querySelector(".sidebar");
    const overlay = document.querySelector("#sidebar-overlay");

    if (sidebar) {
        sidebar.classList.remove("open");
    }
    if (overlay) {
        overlay.classList.remove("visible");
    }
}

export function toggleModal(modal, show) {
    const modalEl = typeof modal === 'string' ? document.querySelector(modal) : modal;
    if (!modalEl) return;

    if (show) {
        modalEl.classList.remove('hidden');
    } else {
        modalEl.classList.add('hidden');
    }
}

export function bindModalOverlayClick(modalEl, closeFn) {
    if (!modalEl || !closeFn) return;
    const overlay = modalEl.querySelector('.modal-overlay');
    if (overlay) {
        overlay.addEventListener('click', closeFn);
    }
}
