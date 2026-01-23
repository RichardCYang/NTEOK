import { readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, "..", "public");

async function generateIntegrity(filePath) {
    const content = await readFile(path.join(PUBLIC_DIR, filePath));
    const hash = createHash("sha384").update(content).digest("base64");
    return `sha384-${hash}`;
}

async function main() {
    const mapping = {
        "/lib/yjs/yjs.js": "yjs",
        "/lib/y-protocols/awareness.js": "y-protocols/awareness",
        "/lib/lib0/lib0.js": "lib0",
        "/lib/y-prosemirror/y-prosemirror.js": "y-prosemirror",
        "/lib/prosemirror-model/prosemirror-model.js": "prosemirror-model",
        "/lib/prosemirror-state/prosemirror-state.js": "prosemirror-state",
        "/lib/prosemirror-view/prosemirror-view.js": "prosemirror-view",
        "/lib/prosemirror-keymap/prosemirror-keymap.js": "prosemirror-keymap",
        "/lib/prosemirror-schema-list/prosemirror-schema-list.js": "prosemirror-schema-list",
        "/lib/prosemirror-commands/prosemirror-commands.js": "prosemirror-commands",
        "/lib/prosemirror-history/prosemirror-history.js": "prosemirror-history",
        "/lib/prosemirror-inputrules/prosemirror-inputrules.js": "prosemirror-inputrules",
        "/lib/prosemirror-transform/prosemirror-transform.js": "prosemirror-transform",
        "/lib/tiptap-extensions/core.js": "@tiptap/core",
        "/lib/tiptap-extensions/text-align.js": "@tiptap/extension-text-align",
        "/lib/tiptap-extensions/color.js": "@tiptap/extension-color",
        "/lib/tiptap-extensions/text-style.js": "@tiptap/extension-text-style",
        "/lib/tiptap-extensions/font-family.js": "@tiptap/extension-font-family",
        "/lib/tiptap-extensions/task-list.js": "@tiptap/extension-task-list",
        "/lib/tiptap-extensions/task-item.js": "@tiptap/extension-task-item",
        "/lib/tiptap-extensions/table.js": "@tiptap/extension-table",
        "/lib/tiptap-extensions/table-row.js": "@tiptap/extension-table-row",
        "/lib/tiptap-extensions/table-header.js": "@tiptap/extension-table-header",
        "/lib/tiptap-extensions/table-cell.js": "@tiptap/extension-table-cell",
        "/lib/tiptap-extensions/prosemirror-tables.js": "@tiptap/prosemirror-tables",
        "/lib/dompurify/dompurify.js": "dompurify"
    };

    const integrity = {};
    for (const [localPath, _] of Object.entries(mapping)) {
        try {
            const fullPath = path.join(PUBLIC_DIR, localPath);
            const content = await readFile(fullPath);
            const hash = createHash("sha384").update(content).digest("base64");
            integrity[localPath] = `sha384-${hash}`;
        } catch (e) {
            console.warn(`Failed to generate integrity for ${localPath}: ${e.message}`);
        }
    }

    await writeFile(path.join(PUBLIC_DIR, "importmap-integrity.json"), JSON.stringify(integrity, null, 2));
    console.log("Updated importmap-integrity.json with local file hashes.");
}

main().catch(console.error);