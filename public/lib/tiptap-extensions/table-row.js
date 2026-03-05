
import{Node as e,mergeAttributes as r}from "@tiptap/core";var o=e.create({name:"tableRow",addOptions(){return{HTMLAttributes:{}}},content:"(tableCell | tableHeader)*",tableRole:"row",parseHTML(){return[{tag:"tr"}]},renderHTML({HTMLAttributes:t}){return["tr",r(this.options.HTMLAttributes,t),0]}});export{o as TableRow,o as default};
//# sourceMappingURL=extension-table-row.bundle.mjs.map