import { writeFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const LIB_DIR = path.join(__dirname, "..", "public", "lib");

const LIBRARIES = [
	{
		name: "font-awesome",
		files: [
			{
				url: "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css",
				path: "css/all.min.css",
			},
            { url: "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/webfonts/fa-brands-400.woff2", path: "webfonts/fa-brands-400.woff2" },
            { url: "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/webfonts/fa-regular-400.woff2", path: "webfonts/fa-regular-400.woff2" },
            { url: "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/webfonts/fa-solid-900.woff2", path: "webfonts/fa-solid-900.woff2" },
            { url: "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/webfonts/fa-v4compatibility.woff2", path: "webfonts/fa-v4compatibility.woff2" },
		],
		license: "https://raw.githubusercontent.com/FortAwesome/Font-Awesome/6.5.0/LICENSE.txt",
	},
	{
		name: "katex",
		files: [
			{
				url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css",
				path: "katex.min.css",
			},
			{
				url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js",
				path: "katex.min.js",
			},
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_AMS-Regular.woff2", path: "fonts/KaTeX_AMS-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Caligraphic-Bold.woff2", path: "fonts/KaTeX_Caligraphic-Bold.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Caligraphic-Regular.woff2", path: "fonts/KaTeX_Caligraphic-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Fraktur-Bold.woff2", path: "fonts/KaTeX_Fraktur-Bold.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Fraktur-Regular.woff2", path: "fonts/KaTeX_Fraktur-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Main-Bold.woff2", path: "fonts/KaTeX_Main-Bold.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Main-BoldItalic.woff2", path: "fonts/KaTeX_Main-BoldItalic.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Main-Italic.woff2", path: "fonts/KaTeX_Main-Italic.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Main-Regular.woff2", path: "fonts/KaTeX_Main-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Math-BoldItalic.woff2", path: "fonts/KaTeX_Math-BoldItalic.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Math-Italic.woff2", path: "fonts/KaTeX_Math-Italic.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_SansSerif-Bold.woff2", path: "fonts/KaTeX_SansSerif-Bold.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_SansSerif-Italic.woff2", path: "fonts/KaTeX_SansSerif-Italic.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_SansSerif-Regular.woff2", path: "fonts/KaTeX_SansSerif-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Script-Regular.woff2", path: "fonts/KaTeX_Script-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Size1-Regular.woff2", path: "fonts/KaTeX_Size1-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Size2-Regular.woff2", path: "fonts/KaTeX_Size2-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Size3-Regular.woff2", path: "fonts/KaTeX_Size3-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Size4-Regular.woff2", path: "fonts/KaTeX_Size4-Regular.woff2" },
            { url: "https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/fonts/KaTeX_Typewriter-Regular.woff2", path: "fonts/KaTeX_Typewriter-Regular.woff2" },
		],
		license: "https://raw.githubusercontent.com/KaTeX/KaTeX/v0.16.9/LICENSE",
	},
	{
		name: "tiptap",
		files: [
			{
				url: "https://cdn.jsdelivr.net/gh/panphora/tiptap-for-browser@2.0.0-beta.166/tiptap-for-browser.min.js",
				path: "tiptap-for-browser.min.js",
			},
		],
		license: "https://raw.githubusercontent.com/ueberdosis/tiptap/main/LICENSE",
	},
	{
		name: "html2canvas",
		files: [
			{
				url: "https://cdn.jsdelivr.net/npm/html2canvas@1.4.1/dist/html2canvas.min.js",
				path: "html2canvas.min.js",
			},
		],
		license: "https://raw.githubusercontent.com/niklasvh/html2canvas/master/LICENSE",
	},
	{
		name: "jspdf",
		files: [
			{
				url: "https://cdn.jsdelivr.net/npm/jspdf@2.5.1/dist/jspdf.umd.min.js",
				path: "jspdf.umd.min.js",
			},
		],
		license: "https://raw.githubusercontent.com/parallax/jsPDF/master/LICENSE",
	},
	{
		name: "html2pdf",
		files: [
			{
				url: "https://cdn.jsdelivr.net/npm/html2pdf.js@0.10.2/dist/html2pdf.bundle.min.js",
				path: "html2pdf.bundle.min.js",
			},
		],
		license: "https://raw.githubusercontent.com/eKoopmans/html2pdf.js/master/LICENSE",
	},
	{
		name: "sortablejs",
		files: [
			{
				url: "https://cdn.jsdelivr.net/npm/sortablejs@1.15.0/Sortable.min.js",
				path: "Sortable.min.js",
			},
		],
		license: "https://raw.githubusercontent.com/SortableJS/Sortable/master/LICENSE",
	},
    {
        name: "dompurify",
        files: [
            {
                url: "https://esm.sh/dompurify@3.3.1?bundle&target=es2022",
                path: "dompurify.js"
            }
        ],
        license: "https://raw.githubusercontent.com/cure53/dompurify/main/LICENSE"
    },
    {
        name: "yjs",
        files: [{ url: "https://esm.sh/yjs@13.6.18?bundle&target=es2022", path: "yjs.js" }],
        license: "https://raw.githubusercontent.com/yjs/yjs/master/LICENSE"
    },
    {
        name: "y-protocols",
        files: [
            { url: 'https://esm.sh/y-protocols/awareness?bundle&target=es2022', path: 'awareness.js' },
        ],
        license: "https://raw.githubusercontent.com/yjs/y-protocols/master/LICENSE"
    },
    {
        name: "lib0",
        files: [{ url: "https://esm.sh/lib0@0.2.109?bundle&target=es2022", path: "lib0.js" }],
        license: "https://raw.githubusercontent.com/dmonad/lib0/master/LICENSE"
    },
    {
        name: "y-prosemirror",
        files: [{ url: "https://esm.sh/y-prosemirror@1.2.1?bundle&target=es2022", path: "y-prosemirror.js" }],
        license: "https://raw.githubusercontent.com/yjs/y-prosemirror/master/LICENSE"
    },
    {
        name: "tiptap-extensions",
        files: [
            { url: "https://esm.sh/@tiptap/extension-text-align@2.0.0-beta.209?bundle&target=es2022", path: "text-align.js" },
            { url: "https://esm.sh/@tiptap/extension-color@2.0.0-beta.209?bundle&target=es2022", path: "color.js" },
            { url: "https://esm.sh/@tiptap/extension-text-style@2.0.0-beta.209?bundle&target=es2022", path: "text-style.js" },
            { url: "https://esm.sh/@tiptap/extension-font-family@2.0.0-beta.209?bundle&target=es2022", path: "font-family.js" },
            { url: "https://esm.sh/@tiptap/extension-task-list@2.0.0-beta.209?bundle&target=es2022", path: "task-list.js" },
            { url: "https://esm.sh/@tiptap/extension-task-item@2.0.0-beta.209?bundle&target=es2022", path: "task-item.js" },
            { url: "https://esm.sh/@tiptap/extension-table@2.0.0-beta.209?bundle&target=es2022", path: "table.js" },
            { url: "https://esm.sh/@tiptap/extension-table-row@2.0.0-beta.209?bundle&target=es2022", path: "table-row.js" },
            { url: "https://esm.sh/@tiptap/extension-table-header@2.0.0-beta.209?bundle&target=es2022", path: "table-header.js" },
            { url: "https://esm.sh/@tiptap/extension-table-cell@2.0.0-beta.209?bundle&target=es2022", path: "table-cell.js" },
            { url: "https://esm.sh/@tiptap/core@2.0.0-beta.209?bundle&target=es2022", path: "core.js" },
            { url: "https://cdn.jsdelivr.net/npm/prosemirror-tables@1.6.4/+esm", path: "prosemirror-tables.js" },
        ],
        license: "https://raw.githubusercontent.com/ueberdosis/tiptap/main/LICENSE"
    },
    {
        name: "simplewebauthn",
        files: [{ url: "https://cdn.jsdelivr.net/npm/@simplewebauthn/browser@10.0.0/+esm", path: "browser.js" }],
        license: "https://raw.githubusercontent.com/MasterQ32/simplewebauthn/master/LICENSE"
    },
    {
        name: "prosemirror-model",
        files: [{ url: "https://esm.sh/prosemirror-model@1.22.3?bundle&target=es2022", path: "prosemirror-model.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-model/master/LICENSE"
    },
    {
        name: "prosemirror-state",
        files: [{ url: "https://esm.sh/prosemirror-state@1.4.3?bundle&target=es2022", path: "prosemirror-state.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-state/master/LICENSE"
    },
    {
        name: "prosemirror-view",
        files: [{ url: "https://esm.sh/prosemirror-view@1.39.0?bundle&target=es2022", path: "prosemirror-view.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-view/master/LICENSE"
    },
    {
        name: "prosemirror-keymap",
        files: [{ url: "https://esm.sh/prosemirror-keymap@1.2.2?bundle&target=es2022", path: "prosemirror-keymap.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-keymap/master/LICENSE"
    },
    {
        name: "prosemirror-commands",
        files: [{ url: "https://esm.sh/prosemirror-commands@1.5.2?bundle&target=es2022", path: "prosemirror-commands.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-commands/master/LICENSE"
    },
    {
        name: "prosemirror-history",
        files: [{ url: "https://esm.sh/prosemirror-history@1.4.1?bundle&target=es2022", path: "prosemirror-history.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-history/master/LICENSE"
    },
    {
        name: "prosemirror-inputrules",
        files: [{ url: "https://esm.sh/prosemirror-inputrules@1.4.0?bundle&target=es2022", path: "prosemirror-inputrules.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-inputrules/master/LICENSE"
    },
    {
        name: "prosemirror-schema-list",
        files: [{ url: "https://esm.sh/prosemirror-schema-list@^1.2.2?bundle&target=es2022", path: "prosemirror-schema-list.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-schema-list/master/LICENSE"
    },
    {
        name: "prosemirror-transform",
        files: [{ url: "https://esm.sh/prosemirror-transform@1.9.0?bundle&target=es2022", path: "prosemirror-transform.js" }],
        license: "https://raw.githubusercontent.com/ProseMirror/prosemirror-transform/master/LICENSE"
    }
];

async function download(url) {
	const res = await fetch(url);
	if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.statusText}`);
    
    // Check if it's an esm.sh shim re-exporting a bundle
    const contentType = res.headers.get("content-type") || "";
    if (contentType.includes("javascript")) {
        let text = await res.text();
        const bundleMatch = text.match(/export \* from "(\/[^"]+\.bundle\.mjs)"/);
        if (bundleMatch) {
            const bundleUrl = new URL(bundleMatch[1], url).toString();
            console.log(`  - Following shim redirect: ${bundleUrl}`);
            const bundleRes = await fetch(bundleUrl);
            if (!bundleRes.ok) throw new Error(`Failed to fetch bundle ${bundleUrl}`);
            return Buffer.from(await bundleRes.arrayBuffer());
        }
        return Buffer.from(text, "utf8");
    }
    
	return Buffer.from(await res.arrayBuffer());
}

function patchCode(text) {
    // 1. Fix absolute path imports (e.g. from "/npm/..." or from "/@tiptap/...")
    text = text.replace(/(from|import)\s*["']\/([^"']+)["']/g, (match, p1, p2) => {
        let name = p2;
        if (name.startsWith('npm/')) {
            name = name.slice(4); // remove npm/
        }
        if (name.startsWith('@')) {
            const parts = name.split('/');
            if (parts[1] && parts[1].includes('@')) {
                name = parts[0] + '/' + parts[1].split('@')[0];
            } else {
                name = parts[0] + '/' + (parts[1] || '');
            }
        } else {
            name = name.split('@')[0].split('?')[0].split('/')[0];
        }
        if (name.endsWith('/')) name = name.slice(0, -1);
        return `${p1} "${name}"`;
    });

    // 2. Fix bare specifiers with versions (e.g. from "@tiptap/core@2.0.0")
    text = text.replace(/(from|import)\s*["']([^"\/][^"']+)["']/g, (match, p1, p2) => {
        let name = p2;
        if (name.includes('@', 1)) {
            if (name.startsWith('@')) {
                const parts = name.split('/');
                if (parts[1] && parts[1].includes('@')) {
                    name = parts[0] + '/' + parts[1].split('@')[0];
                }
            } else {
                name = name.split('@')[0];
            }
        }
        return `${p1} "${name}"`;
    });

    // 3. Remove node imports (common in esm.sh bundles)
    // Handles:
    // import "node";
    // import __Process$ from "node";
    // import { Buffer as __Buffer$ } from "node";
    text = text.replace(/import\s+[^"']+["']node["'];?/g, '');
    text = text.replace(/import\s+["']node["'];?/g, '');
    
    // Also common: "node:process", "node:buffer" etc.
    text = text.replace(/import\s+[^"']+["']node:[^"']+["'];?/g, '');
    text = text.replace(/import\s+["']node:[^"']+["'];?/g, '');
    
    return text;
}

async function main() {
	for (const lib of LIBRARIES) {
		console.log(`Downloading ${lib.name}...`);
		const libPath = path.join(LIB_DIR, lib.name);

		for (const file of lib.files) {
			let data = await download(file.url);
            const filePath = path.join(libPath, file.path);
            await mkdir(path.dirname(filePath), { recursive: true });

            if (filePath.endsWith(".js") || filePath.endsWith(".mjs")) {
                data = Buffer.from(patchCode(data.toString("utf8")), "utf8");
            }

			await writeFile(filePath, data);
			console.log(`  - ${file.path}`);
		}

		if (lib.license) {
			try {
				const data = await download(lib.license);
				await writeFile(path.join(libPath, "LICENSE"), data);
				console.log(`  - LICENSE`);
			} catch (e) {
				console.warn(`  - Failed to download LICENSE: ${e.message}`);
			}
		}
	}
}

main().catch(console.error);