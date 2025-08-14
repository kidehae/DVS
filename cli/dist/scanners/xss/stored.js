// -------------------------
// 2) Detection Function
// -------------------------
const detectStoredXSS = (sourceFiles) => {
    const vulns = [];
    // -------------------------
    // Sources (server & client)
    // -------------------------
    const serverSources = [
        "req\\.query",
        "req\\.body",
        "req\\.params",
        "req\\.headers",
        "req\\.cookies",
        "req\\.files",
        "req\\.input",
        "req\\.rawBody",
        "process\\.env", // attacker-controlled in some setups
    ];
    const clientSources = [
        "window\\.location",
        "document\\.location",
        "location\\.hash",
        "location\\.search",
        "document\\.cookie",
        "localStorage\\.getItem",
        "sessionStorage\\.getItem",
        "indexedDB\\.get",
        "document\\.referrer",
        "window\\.name",
        "WebSocket\\.data",
        "postMessage\\.data",
        "messageEvent\\.data",
        "navigator\\.clipboard\\.readText",
    ];
    const allSources = [...serverSources, ...clientSources];
    // -------------------------
    // Storage Operations
    // -------------------------
    const storageOperations = [
        // Database operations
        { re: /\b(?:db|database|client)\.(?:insert|update|save|create|upsert|replace)\s*\(/g, type: "database" },
        { re: /\bModel\.(?:create|update|findOneAndUpdate|updateOne|updateMany|insertMany|save)\s*\(/g, type: "orm" },
        // Filesystem operations
        { re: /\bfs\.(?:writeFile|appendFile|createWriteStream|promises\.writeFile)\s*\(/g, type: "filesystem" },
        // Browser storage
        { re: /\b(?:localStorage|sessionStorage)\.setItem\s*\(/g, type: "webstorage" },
        { re: /\bindexedDB\.(?:put|add)\s*\(/g, type: "indexeddb" },
        { re: /\bdocument\.cookie\s*=/g, type: "cookie" },
        // Cloud storage
        { re: /\b(?:s3|blobService)\.(?:putObject|upload|createBlockBlobFromText|createAppendBlobFromText)\s*\(/g, type: "cloudstorage" },
        // Caching systems
        { re: /\b(?:cache|redis)\.(?:set|setex|hset|put)\s*\(/g, type: "cache" },
        // Array operations (merged into one regex)
        { re: /\b\w+\.(?:push|unshift|splice)\s*\(/g, type: "array" },
        // Variable assignment (catch-all)
        { re: /\b\w+\s*=\s*[^;]+;/g, type: "var_assign" }
    ];
    // -------------------------
    // Output Sinks (extended)
    // -------------------------
    const serverSinks = [
        {
            re: /\b\w+\.(send|write|end|jsonp|json)\s*\([\s\S]*?\)/g,
            desc: ".send/.write/.end/.json/.jsonp",
            context: "html",
        },
        {
            re: /\b\w+\.render\s*\(\s*[^,]+,\s*[\s\S]*?\)/g,
            desc: ".render(view, data)",
            context: "html",
        },
        {
            re: /\b\w+\.redirect\s*\([\s\S]*?\)/g,
            desc: ".redirect(url)",
            context: "url",
        },
    ];
    const clientDomSinks = [
        {
            re: /\b\w+\.innerHTML\s*=\s*[\s\S]*?;/g,
            desc: "innerHTML assignment",
            context: "html",
        },
        {
            re: /\bouterHTML\s*=\s*[\s\S]*?;/g,
            desc: "outerHTML assignment",
            context: "html",
        },
        {
            re: /insertAdjacentHTML\s*\([\s\S]*?\)/g,
            desc: "insertAdjacentHTML(...)",
            context: "html",
        },
        {
            re: /document\.write(?:ln)?\s*\([\s\S]*?\)/g,
            desc: "document.write / writeln",
            context: "html",
        },
        {
            re: /\$\([\s\S]*?\)\.html\s*\([\s\S]*?\)/g,
            desc: "jQuery.html()",
            context: "html",
        },
        {
            re: /\$\([\s\S]*?\)\.append\s*\([\s\S]*?\)/g,
            desc: "jQuery.append()",
            context: "html",
        },
        {
            re: /\bsetAttribute\s*\(\s*["']on\w+["'],\s*[\s\S]*?\)/g,
            desc: "setAttribute with event handler",
            context: "attr",
        },
    ];
    // -------------------------
    // Sanitizers
    // -------------------------
    const htmlSanitizers = [
        /escapeHtml\s*\(/g,
        /DOMPurify\.sanitize\s*\(/g,
        /\.textContent\s*=/g,
        /createTextNode\s*\(/g,
    ];
    const urlSanitizers = [/encodeURIComponent\s*\(/g, /encodeURI\s*\(/g];
    const lineFromIndex = (text, idx) => text.slice(0, idx).split("\n").length;
    const sliceHasSource = (slice, sources) => sources.some((s) => new RegExp(s).test(slice));
    const isSanitizedForContext = (slice, context) => {
        if (context === "url")
            return urlSanitizers.some((re) => re.test(slice));
        if (context === "html")
            return htmlSanitizers.some((re) => re.test(slice));
        return false;
    };
    // -------------------------
    // Main Detection
    // -------------------------
    for (const file of sourceFiles) {
        const { content } = file;
        const storagePoints = [];
        // Pass 1: find storage ops
        for (const { re, type } of storageOperations) {
            for (const match of content.matchAll(re)) {
                const idx = match.index ?? 0;
                const slice = content.slice(Math.max(0, idx - 300), Math.min(content.length, idx + match[0].length + 300));
                if (sliceHasSource(slice, allSources)) {
                    storagePoints.push({
                        match,
                        type,
                        line: lineFromIndex(content, idx),
                        context: slice,
                    });
                }
            }
        }
        // Pass 2: sinks
        const sinks = file.isServerCode ? serverSinks : clientDomSinks;
        for (const { re, context } of sinks) {
            for (const sinkMatch of content.matchAll(re)) {
                const sinkIdx = sinkMatch.index ?? 0;
                const sinkLine = lineFromIndex(content, sinkIdx);
                for (const storage of storagePoints) {
                    if (sinkLine > storage.line) {
                        const sinkSlice = content.slice(Math.max(0, sinkIdx - 300), Math.min(content.length, sinkIdx + sinkMatch[0].length + 300));
                        const sanitized = isSanitizedForContext(sinkSlice, context);
                        if (!sanitized) {
                            vulns.push({
                                type: "Stored XSS",
                                file: file.path,
                                line: sinkLine,
                                pattern: sinkMatch[0].trim(), // Now shows the exact vulnerable code
                                recommendation: context === "html"
                                    ? "Sanitize stored data before output using DOMPurify or similar."
                                    : "Properly encode/escape stored data for the context.",
                                severity: "high",
                                confidence: 0.9,
                                snippet: sinkMatch[0].slice(0, 200),
                                sanitized: sanitized,
                            });
                        }
                    }
                }
            }
        }
        // Pass 3: direct storage → output
        if (file.isServerCode) {
            const storageToOutputPatterns = [
                {
                    re: /(?:const|let|var)\s+\w+\s*=\s*await\s+\w+\.(?:findOne|findById)\s*\([\s\S]*?\)[\s\S]*?res\.(?:send|render|json)\s*\([\s\S]*?\w+\.\w+/g,
                    desc: "DB query directly to output",
                },
                {
                    re: /fs\.readFile\w*\s*\([\s\S]*?\)[\s\S]*?res\.(?:send|write)\s*\(/g,
                    desc: "File read directly to output",
                },
                {
                    re: /res\.(?:send|render|json)\([^)]*?\b\w+\.map\([^)]*?=>[^)]*?\$\{[^}]+?\}/g,
                    desc: "Direct array map to template output",
                },
            ];
            for (const { re } of storageToOutputPatterns) {
                for (const match of content.matchAll(re)) {
                    const idx = match.index ?? 0;
                    const slice = content.slice(Math.max(0, idx - 300), idx + match[0].length + 300);
                    if (sliceHasSource(slice, allSources) &&
                        !isSanitizedForContext(slice, "html")) {
                        vulns.push({
                            type: "Stored XSS (Direct Storage to Output)",
                            file: file.path,
                            line: lineFromIndex(content, idx),
                            pattern: match[0].trim(), // Now shows the actual vulnerable line
                            recommendation: "Add sanitization between retrieval and output.",
                            severity: "critical",
                            confidence: 0.95,
                            snippet: match[0].slice(0, 200),
                            sanitized: false,
                        });
                    }
                }
            }
        }
    }
    // Remove duplicates based on file + line + pattern
    const uniqueVulns = Array.from(new Map(vulns.map(v => [
        `${v.file}:${v.line}:${v.pattern}`,
        v
    ])).values());
    return uniqueVulns;
};
export default detectStoredXSS;
//# sourceMappingURL=stored.js.map