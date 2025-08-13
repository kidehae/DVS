import { promises as fs } from "fs";
import path from "path";
export async function loadProjectFiles(dir) {
    const files = [];
    async function walk(currentPath) {
        const entries = await fs.readdir(currentPath, { withFileTypes: true });
        for (const entry of entries) {
            const fullPath = path.join(currentPath, entry.name);
            if (entry.isDirectory()) {
                // Skip node_modules folder entirely
                if (entry.name === "node_modules")
                    continue;
                await walk(fullPath);
            }
            else if (/\.(js|ts|jsx|tsx|html)$/i.test(entry.name)) {
                const content = await fs.readFile(fullPath, "utf-8");
                files.push({
                    path: fullPath,
                    content,
                    isServerCode: /\.(js|ts)$/i.test(entry.name) && /express|koa|fastify/.test(content),
                    isClientCode: /\.(js|ts|jsx|tsx|html)$/i.test(entry.name) &&
                        /document|window/.test(content),
                    language: entry.name.split(".").pop()?.toLowerCase(),
                    size: content.length
                });
            }
        }
    }
    await walk(dir);
    return files;
}
//# sourceMappingURL=load_files.js.map