// // detectors/reflective.ts
// interface SourceFile {
//   path: string;
//   content: string;
//   isTemplate?: boolean;
//   isServerCode?: boolean;
//   isClientCode?: boolean;
// }
const detectReflectiveXSS = (sourceFiles) => {
    const vulns = [];
    // -------------------------
    // 1) Sources (server only)
    // -------------------------
    const serverSources = [
        "req\\.query",
        "req\\.body",
        "req\\.params",
        "req\\.headers",
        "req\\.cookies",
    ];
    // -------------------------
    // 2) Sinks (server)
    // NOTE: all use [\s\S]*? (multiline-friendly)
    // Added CSS-related sinks & contexts.
    // -------------------------
    const serverSinks = [
        // HTML-like responses
        {
            re: /\b\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.(send|write|end|jsonp)\s*\([\s\S]*?\)/g,
            desc: "Response HTML send/write/end/jsonp",
            context: "html",
        },
        // JSON (mostly safe if served as application/json, but keep awareness)
        {
            re: /\b\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.json\s*\([\s\S]*?\)/g,
            desc: "Response JSON",
            context: "json",
        },
        // Template rendering with locals/data
        {
            re: /\b\w+\.render\s*\(\s*[^,]+,\s*[\s\S]*?\)/g,
            desc: "render(view, data)",
            context: "html",
        },
        // Redirects (URL context)
        {
            re: /\b\w+\.redirect\s*\([\s\S]*?\)/g,
            desc: "redirect(url)",
            context: "url",
        },
        // Explicit HTML content-type
        {
            re: /\b\w+\.(set|setHeader)\s*\(\s*['"]content-type['"]\s*,\s*['"]text\/html\b[^'"]*['"]\s*\)/gi,
            desc: "set Content-Type: text/html",
            context: "html",
        },
        // .type('html').send(...)
        {
            re: /\b\w+\.type\s*\(\s*['"]html?['"]\s*\)[\s\S]*?\.(send|end)\s*\([\s\S]*?\)/g,
            desc: ".type('html').send/end(...)",
            context: "html",
        },
        // -------------------------
        // CSS-related reflective sinks
        // -------------------------
        // Explicit CSS content-type
        {
            re: /\b\w+\.(set|setHeader)\s*\(\s*['"]content-type['"]\s*,\s*['"]text\/css\b[^'"]*['"]\s*\)/gi,
            desc: "set Content-Type: text/css",
            context: "css",
        },
        // .type('css').send(...)
        {
            re: /\b\w+\.type\s*\(\s*['"]css['"]\s*\)[\s\S]*?\.(send|end|write)\s*\([\s\S]*?\)/g,
            desc: ".type('css').send/end/write(...)",
            context: "css",
        },
        // Inline <style> blocks being constructed (inside strings/templates)
        // e.g., res.send(`<style>${req.query.css}</style>`)
        {
            re: /<style[^>]*>[\s\S]*?(?:\+|\$\{)[\s\S]*?<\/style>/gi,
            desc: "Inline <style> with dynamic interpolation",
            context: "css",
        },
        // style=" ... " attributes with concatenation/interpolation
        // e.g., res.send(`<div style="color:${req.query.c}">`)
        {
            re: /style\s*=\s*["'`][\s\S]*?(?:\+|\$\{)[\s\S]*?["'`]/gi,
            desc: "style= attribute with dynamic interpolation",
            context: "css",
        },
        // Sending strings that look like CSS with dynamic pieces
        // e.g., res.send('body{background:'+req.query.bg+'}')
        {
            re: /\b\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.(send|write|end)\s*\([\s\S]*?(?:^|[,{;]\s*)[a-zA-Z-]{2,}\s*:\s*[\s\S]*?(?:\+|\$\{)[\s\S]*?[;}][\s\S]*?\)/gm,
            desc: "Sending CSS-like properties with dynamic interpolation",
            context: "css",
        },
    ];
    // -------------------------
    // 3) Context-aware sanitizers
    // -------------------------
    const htmlSanitizers = [
        /escapeHtml\s*\(/g,
        /(?:^|[\W_])(?:escape|_\.escape|validator\.escape)\s*\(/g,
        /DOMPurify\.sanitize\s*\(/g,
        /\.textContent\s*=/g,
        /createTextNode\s*\(/g,
    ];
    const urlSanitizers = [/encodeURIComponent\s*\(/g, /encodeURI\s*\(/g];
    // CSS sanitizers / defensive APIs
    const cssSanitizers = [
        /cssesc\s*\(/g,
        /sanitizeCss\s*\(/g,
        /safeStyle\s*\(/g,
        /styleSafe\s*\(/g,
        /isSafeCss\s*\(/g,
        /\/\^#[0-9a-fA-F]{3,6}\$\/g?/g,
        /\/\^[a-zA-Z0-9# ,.%()\-]+\$\//g,
    ];
    // CSS "dangerous" constructs
    const cssDangerous = [
        /expression\s*\(/gi,
        /behavior\s*:\s*url\s*\(/gi,
        /url\s*\(\s*['"]?\s*javascript\s*:/gi,
    ];
    // -------------------------
    // Utils
    // -------------------------
    const lineFromIndex = (text, idx) => text.slice(0, idx).split("\n").length;
    const sliceHasSource = (slice, sources) => sources.some((s) => new RegExp(s).test(slice));
    const sliceHasAny = (slice, patterns) => patterns.some((re) => re.test(slice));
    const isSanitizedForContext = (slice, context) => {
        if (context === "url")
            return sliceHasAny(slice, urlSanitizers);
        if (context === "html")
            return sliceHasAny(slice, htmlSanitizers);
        if (context === "css")
            return sliceHasAny(slice, cssSanitizers);
        return false;
    };
    // -------------------------
    // 4) Template checks (server-rendered)
    // -------------------------
    const templateUnescaped = [
        {
            re: /<\?=\s*([^?]+)\s*\?>/g,
            rec: "Use <?= htmlspecialchars(...) ?> or escape output.",
        },
        {
            re: /\{\{\{\s*([^}]+)\s*\}\}\}/g,
            rec: "Use {{ var }} (escaped) instead of triple braces in Handlebars.",
        },
        {
            re: /<%-\s*([^%]+)\s*%>/g,
            rec: "Use <%= %> (escaped) instead of <%- %> in EJS.",
        },
        { re: /!=\s*\w+/g, rec: "Use #{var} (escaped) instead of != var in Pug." },
        {
            re: /style\s*=\s*["'`][\s\S]*?(?:\+|\$\{)[\s\S]*?["'`]/gi,
            rec: "Avoid dynamic style attributes or sanitize CSS tokens.",
        },
    ];
    for (const file of sourceFiles) {
        const { content } = file;
        // A) Template scanning
        if (file.isTemplate) {
            for (const { re, rec } of templateUnescaped) {
                for (const m of content.matchAll(re)) {
                    const idx = m.index ?? 0;
                    vulns.push({
                        type: "Reflective XSS (Template/Unescaped)",
                        file: file.path,
                        line: lineFromIndex(content, idx),
                        pattern: m[0],
                        recommendation: rec,
                        severity: "high",
                        confidence: 0.9,
                        snippet: content.slice(Math.max(0, idx - 50), idx + 50),
                        sanitized: false,
                    });
                }
            }
        }
        // B) Server-side sink scanning (HTML/URL/CSS/JSON)
        if (file.isServerCode) {
            for (const { re, desc, context } of serverSinks) {
                for (const m of content.matchAll(re)) {
                    const idx = m.index ?? 0;
                    const sliceStart = Math.max(0, idx - 300);
                    const sliceEnd = Math.min(content.length, idx + m[0].length + 300);
                    const slice = content.slice(sliceStart, sliceEnd);
                    const hasSource = sliceHasSource(slice, serverSources);
                    const sanitized = isSanitizedForContext(slice, context);
                    const cssDanger = context === "css" ? sliceHasAny(slice, cssDangerous) : false;
                    if (hasSource && (!sanitized || cssDanger)) {
                        let recommendation = "";
                        let vulnerabilityType = "";
                        let severity = "high";
                        switch (context) {
                            case "url":
                                recommendation =
                                    "Validate redirect/URL targets (allow-list) and encode parameters with encodeURIComponent().";
                                vulnerabilityType = "Open Redirect / URL Injection";
                                severity = "medium";
                                break;
                            case "css":
                                recommendation =
                                    "Never inject raw user input into CSS. Restrict to a safe allow-list (e.g., /^#[0-9a-f]{3,6}$/i for colors), or sanitize tokens (cssesc). Disallow url(javascript:), expression(), and external URLs.";
                                vulnerabilityType = "Reflective CSS Injection";
                                severity = cssDanger ? "critical" : "high";
                                break;
                            case "json":
                                recommendation =
                                    "Ensure response is application/json and not embedded in HTML. Avoid reflecting untrusted JSON inside <script> without escaping.";
                                vulnerabilityType = "Reflected JSON (check embedding)";
                                severity = "medium";
                                break;
                            default:
                                recommendation =
                                    "Escape/encode untrusted data before sending HTML (e.g., escapeHtml/validator.escape) or ensure the template auto-escapes.";
                                vulnerabilityType = "Reflective XSS (Server)";
                                severity = "high";
                        }
                        vulns.push({
                            type: vulnerabilityType,
                            file: file.path,
                            line: lineFromIndex(content, idx),
                            pattern: `${desc}: ${m[0].slice(0, 200)}${m[0].length > 200 ? "..." : ""}`,
                            recommendation,
                            severity,
                            confidence: sanitized ? 0.6 : 0.9,
                            snippet: content.slice(Math.max(0, idx - 100), idx + 100),
                            sanitized,
                        });
                    }
                }
            }
        }
    }
    return vulns;
};
export default detectReflectiveXSS;
//# sourceMappingURL=reflective.js.map