// // detectors/reflective.ts
// interface SourceFile {
//   path: string;
//   content: string;
//   isTemplate?: boolean;
//   isServerCode?: boolean;
//   isClientCode?: boolean;
// }

// interface Vulnerability {
//   type: string;
//   file: string;
//   line?: number;
//   pattern: string;
//   recommendation: string;
// }

// const detectReflectiveXSS = (sourceFiles: SourceFile[]): Vulnerability[] => {
//   const vulnerabilities: Vulnerability[] = [];

//   // ========================
//   // 1. Identify Injection Points
//   // ========================
//   const inputSources: string[] = [
//     // Server-side (Node/Express)
//     "req\\.query", // URL parameters
//     "req\\.body", // POST data
//     "req\\.params", // Route parameters
//     "req\\.headers", // HTTP headers
//     "req\\.cookies", // Cookies

//     // Client-side (if scanning frontend files)
//     "window\\.location", // window.location
//     "document\\.location", // document.location
//     "document\\.cookie", // document.cookie
//     "localStorage\\.getItem", // localStorage.getItem
//     "sessionStorage\\.getItem", // sessionStorage.getItem
//   ];

//   // ========================
//   // 2. Trace to Output Sinks
//   // ========================
//   const outputSinks: RegExp[] = [
//     // Server-side response methods
//     /\b\w+\.(send|write|end|json|jsonp|redirect|setHeader)\([^)]*\)/, // Match common response methods
//     /\b\w+\.render\([^,]+,\s*{[^}]*}[^)]*\)/, // res.render(view, {data})

//     // DOM-based sinks
//     /document\.write\([^)]*\)/, //ocument.write()
//     /document\.writeln\([^)]*\)/, //document.writeln()
//     /\w+\.innerHTML\s*=/, // elemet.innerHTML =
//     /outerHTML\s*=/, // element.outerHTML =
//     /insertAdjacentHTML\([^)]*\)/, // element.insertAdjacentHTML(position, html)
//   ];

//   // ========================
//   // 3. Sanitization Patterns
//   // ========================
//   const sanitizationPatterns: string[] = [
//     // Node.js sanitizers
//     "escape\\(",
//     "escapeHtml\\(",
//     "DOMPurify\\.sanitize\\(",
//     "xss\\.filterXSS\\(",
//     "validator\\.escape\\(",

//     // Browser sanitizers
//     "encodeURI\\(",
//     "encodeURIComponent\\(",
//     "textContent\\s*=",
//     "createTextNode\\(",
//   ];

//   sourceFiles.forEach((file: SourceFile) => {
//     const lines: string[] = file.content.split("\n");

//     // ====================================
//     // A. TEMPLATE CHECKS (EJS, Pug, etc.)
//     // ====================================
//     if (file.isTemplate) {
//       lines.forEach((line: string, lineNumber: number) => {
//         // Check for unescaped output syntax
//         const unescapedPatterns: RegExp[] = [
//           // PHP
//           /<\?=\s*([^?]+)\s*\?>/g,
//           // Handlebars/Mustache (unescaped)
//           /\{\{\{\s*([^}]+)\s*\}\}\}/g,
//           // EJS unescaped
//           /<%-\s*([^%]+)\s*%>/g,
//           // Pug unescaped
//           /!=\s*\w+/g,
//         ];

//         unescapedPatterns.forEach((pattern: RegExp) => {
//           const matches: RegExpMatchArray | null = line.match(pattern);
//           if (matches) {
//             vulnerabilities.push({
//               type: "Reflective XSS (Template)",
//               file: file.path,
//               line: lineNumber + 1,
//               pattern: matches[0],
//               recommendation:
//                 "Use escaped output syntax: <%= %> in EJS, {{ }} in Handlebars",
//             });
//           }
//         });
//       });
//     }

//     // ====================================
//     // B. SERVER-SIDE CODE CHECKS
//     // ====================================
//     if (file.isServerCode) {
//       lines.forEach((line: string, lineNumber: number) => {
//         // Check for dangerous sinks
//         outputSinks.forEach((sinkPattern: RegExp) => {
//           const sinkMatches: RegExpMatchArray | null = line.match(sinkPattern);
//           if (sinkMatches) {
//             // Verify if any input sources are used in the sink
//             const hasInput: boolean = inputSources.some((source: string) =>
//               new RegExp(source).test(sinkMatches[0])
//             );

//             // Check if sanitization is present
//             const isSanitized: boolean = sanitizationPatterns.some(
//               (sanitizer: string) => line.includes(sanitizer)
//             );

//             if (hasInput && !isSanitized) {
//               vulnerabilities.push({
//                 type: "Reflective XSS (Server)",
//                 file: file.path,
//                 line: lineNumber + 1,
//                 pattern: sinkMatches[0],
//                 recommendation:
//                   "Sanitize input using escapeHtml() or DOMPurify before output",
//               });
//             }
//           }
//         });
//       });
//     }
//   });

//   return vulnerabilities;
// };

// export default detectReflectiveXSS;

// version 2
// detectors/reflective.ts
// interface SourceFile {
//   path: string;
//   content: string;
//   isTemplate?: boolean;
//   isServerCode?: boolean;
// }

// interface Vulnerability {
//   type: string;
//   file: string;
//   line?: number;
//   pattern: string;
//   recommendation: string;
// }

// const detectReflectiveXSS = (sourceFiles: SourceFile[]): Vulnerability[] => {
//   const vulns: Vulnerability[] = [];

//   // -------------------------
//   // 1) Sources (server only)
//   // -------------------------
//   const serverSources = [
//     "req\\.query",
//     "req\\.body",
//     "req\\.params",
//     "req\\.headers",
//     "req\\.cookies",
//   ];

//   // -------------------------
//   // 2) Sinks (server)
//   // -------------------------
//   const serverSinks: {
//     re: RegExp;
//     desc: string;
//     context: "html" | "url" | "header" | "json";
//   }[] = [
//     {
//       re: /\b\w+\.(send|write|end|jsonp|json)\s*\([\s\S]*?\)/g,
//       desc: ".send/.write/.end/.json/.jsonp",
//       context: "html",
//     },
//     {
//       re: /\b\w+\.render\s*\(\s*[^,]+,\s*[\s\S]*?\)/g,
//       desc: ".render(view, data)",
//       context: "html",
//     },
//     {
//       re: /\b\w+\.redirect\s*\([\s\S]*?\)/g,
//       desc: ".redirect(url)",
//       context: "url",
//     },
//     {
//       re: /\b\w+\.(set|setHeader)\s*\(\s*['"]Content-Type['"]\s*,\s*['"]text\/html['"]\s*\)/g,
//       desc: "set Content-Type: text/html",
//       context: "html",
//     },
//     {
//       re: /\b\w+\.type\s*\(\s*['"]html?['"]\s*\)[\s\S]*?\.(send|end)\s*\([\s\S]*?\)/g,
//       desc: ".type('html').send(...)",
//       context: "html",
//     },
//   ];

//   // -------------------------
//   // 3) Context-aware sanitizers
//   // -------------------------
//   const htmlSanitizers = [
//     /escapeHtml\s*\(/g, //escape html
//     /(?:^|[\W_])(?:escape|_\.escape|validator\.escape)\s*\(/g, //escape and validator.escape
//     /DOMPurify\.sanitize\s*\(/g,
//     /\.textContent\s*=/g,
//     /createTextNode\s*\(/g,
//   ];
//   const urlSanitizers = [/encodeURIComponent\s*\(/g, /encodeURI\s*\(/g]; //url sanitizers

//   const lineFromIndex = (text: string, idx: number) =>
//     text.slice(0, idx).split("\n").length;

//   const sliceHasSource = (slice: string, sources: string[]) =>
//     sources.some((s) => new RegExp(s).test(slice));

//   const isSanitizedForContext = (
//     slice: string,
//     context: "html" | "url" | "header" | "json"
//   ) => {
//     if (context === "url") return urlSanitizers.some((re) => re.test(slice));
//     if (context === "html") return htmlSanitizers.some((re) => re.test(slice));
//     return false;
//   };

//   // -------------------------
//   // 4) Template checks
//   // -------------------------
//   const templateUnescaped: { re: RegExp; rec: string }[] = [
//     {
//       re: /<\?=\s*([^?]+)\s*\?>/g,
//       rec: "Use <?= htmlspecialchars(...) ?> in PHP or escape output.",
//     },
//     {
//       re: /\{\{\{\s*([^}]+)\s*\}\}\}/g,
//       rec: "Use {{ var }} (escaped) instead of triple braces in Handlebars.",
//     },
//     {
//       re: /<%-\s*([^%]+)\s*%>/g,
//       rec: "Use <%= %> (escaped) instead of <%- %> in EJS.",
//     },
//     { re: /!=\s*\w+/g, rec: "Use #{var} (escaped) instead of != var in Pug." },
//   ];

//   for (const file of sourceFiles) {
//     const { content } = file;

//     // A) Template scanning
//     if (file.isTemplate) {
//       for (const { re, rec } of templateUnescaped) {
//         for (const m of content.matchAll(re)) {
//           const idx = (m as any).index ?? 0;
//           vulns.push({
//             type: "Reflective XSS (Template/Unescaped)",
//             file: file.path,
//             line: lineFromIndex(content, idx),
//             pattern: m[0],
//             recommendation: rec,
//           });
//         }
//       }
//     }

//     // B) Server-side sink scanning
//     if (file.isServerCode) {
//       for (const { re, desc, context } of serverSinks) {
//         for (const m of content.matchAll(re)) {
//           const idx = (m as any).index ?? 0;
//           const sliceStart = Math.max(0, idx - 300);
//           const sliceEnd = Math.min(content.length, idx + m[0].length + 300);
//           const slice = content.slice(sliceStart, sliceEnd);

//           const hasSource = sliceHasSource(slice, serverSources);
//           const sanitized = isSanitizedForContext(slice, context);

//           if (hasSource && !sanitized) {
//             vulns.push({
//               type: "Reflective XSS (Server)",
//               file: file.path,
//               line: lineFromIndex(content, idx),
//               pattern: `${desc}: ${m[0].slice(0, 200)}${
//                 m[0].length > 200 ? "..." : ""
//               }`,
//               recommendation:
//                 context === "url"
//                   ? "Sanitize/validate URLs and use encodeURIComponent for parameters."
//                   : "Escape untrusted HTML output using escapeHtml/validator.escape.",
//             });
//           }
//         }
//       }
//     }
//   }

//   return vulns;
// };

// export default detectReflectiveXSS;

//version 3

// detectors/reflective.ts
// interface SourceFile {
//   path: string;
//   content: string;
//   isTemplate?: boolean;
//   isServerCode?: boolean;
// }

// interface Vulnerability {
//   type: string;
//   file: string;
//   line?: number;
//   pattern: string;
//   recommendation: string;
// }

// const detectReflectiveXSS = (sourceFiles: SourceFile[]): Vulnerability[] => {
//   const vulns: Vulnerability[] = [];

//   // -------------------------
//   // 1) Sources (server only)
//   // -------------------------
//   const serverSources = [
//     "req\\.query",
//     "req\\.body",
//     "req\\.params",
//     "req\\.headers",
//     "req\\.cookies",
//   ];

//   // -------------------------
//   // 2) Sinks (server)
//   // NOTE: all use [\s\S]*? (multiline-friendly)
//   // Added CSS-related sinks & contexts.
//   // -------------------------
//   const serverSinks: {
//     re: RegExp;
//     desc: string;
//     context: "html" | "url" | "header" | "json" | "css";
//   }[] = [
//     // HTML-like responses
//     {
//       re: /\b\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.(send|write|end|jsonp)\s*\([\s\S]*?\)/g,
//       desc: "Response HTML send/write/end/jsonp",
//       context: "html",
//     },
//     // JSON (mostly safe if served as application/json, but keep awareness)
//     {
//       re: /\b\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.json\s*\([\s\S]*?\)/g,
//       desc: "Response JSON",
//       context: "json",
//     },
//     // Template rendering with locals/data
//     {
//       re: /\b\w+\.render\s*\(\s*[^,]+,\s*[\s\S]*?\)/g,
//       desc: "render(view, data)",
//       context: "html",
//     },
//     // Redirects (URL context)
//     {
//       re: /\b\w+\.redirect\s*\([\s\S]*?\)/g,
//       desc: "redirect(url)",
//       context: "url",
//     },
//     // Explicit HTML content-type
//     {
//       re: /\b\w+\.(set|setHeader)\s*\(\s*['"]content-type['"]\s*,\s*['"]text\/html\b[^'"]*['"]\s*\)/gi,
//       desc: "set Content-Type: text/html",
//       context: "html",
//     },
//     // .type('html').send(...)
//     {
//       re: /\b\w+\.type\s*\(\s*['"]html?['"]\s*\)[\s\S]*?\.(send|end)\s*\([\s\S]*?\)/g,
//       desc: ".type('html').send/end(...)",
//       context: "html",
//     },

//     // -------------------------
//     // CSS-related reflective sinks
//     // -------------------------

//     // Explicit CSS content-type
//     {
//       re: /\b\w+\.(set|setHeader)\s*\(\s*['"]content-type['"]\s*,\s*['"]text\/css\b[^'"]*['"]\s*\)/gi,
//       desc: "set Content-Type: text/css",
//       context: "css",
//     },
//     // .type('css').send(...)
//     {
//       re: /\b\w+\.type\s*\(\s*['"]css['"]\s*\)[\s\S]*?\.(send|end|write)\s*\([\s\S]*?\)/g,
//       desc: ".type('css').send/end/write(...)",
//       context: "css",
//     },
//     // Inline <style> blocks being constructed (inside strings/templates)
//     // e.g., res.send(`<style>${req.query.css}</style>`)
//     {
//       re: /<style[^>]*>[\s\S]*?(?:\+|\$\{)[\s\S]*?<\/style>/gi,
//       desc: "Inline <style> with dynamic interpolation",
//       context: "css",
//     },
//     // style=" ... " attributes with concatenation/interpolation
//     // e.g., res.send(`<div style="color:${req.query.c}">`)
//     {
//       re: /style\s*=\s*["'`][\s\S]*?(?:\+|\$\{)[\s\S]*?["'`]/gi,
//       desc: "style= attribute with dynamic interpolation",
//       context: "css",
//     },
//     // Sending strings that look like CSS with dynamic pieces
//     // e.g., res.send('body{background:'+req.query.bg+'}')
//     {
//       re: /\b\w+(?:\.[a-zA-Z_]\w*\s*\([\s\S]*?\))*\.(send|write|end)\s*\([\s\S]*?(?:^|[,{;]\s*)[a-zA-Z-]{2,}\s*:\s*[\s\S]*?(?:\+|\$\{)[\s\S]*?[;}][\s\S]*?\)/gm,
//       desc: "Sending CSS-like properties with dynamic interpolation",
//       context: "css",
//     },
//   ];

//   // -------------------------
//   // 3) Context-aware sanitizers
//   // -------------------------
//   const htmlSanitizers = [
//     /escapeHtml\s*\(/g,
//     /(?:^|[\W_])(?:escape|_\.escape|validator\.escape)\s*\(/g,
//     /DOMPurify\.sanitize\s*\(/g,
//     /\.textContent\s*=/g,
//     /createTextNode\s*\(/g,
//   ];
//   const urlSanitizers = [/encodeURIComponent\s*\(/g, /encodeURI\s*\(/g];

//   // CSS sanitizers / defensive APIs
//   const cssSanitizers = [
//     /cssesc\s*\(/g, // https://github.com/mathiasbynens/cssesc
//     /sanitizeCss\s*\(/g, // project-specific sanitizer
//     /safeStyle\s*\(/g, // project-specific sanitizer
//     /styleSafe\s*\(/g, // project-specific sanitizer
//     /isSafeCss\s*\(/g, // project-specific validator
//     // common strict whitelist patterns for colors and simple tokens
//     /\/\^#[0-9a-fA-F]{3,6}\$\/g?/g, // /^#[0-9a-fA-F]{3,6}$/[g]
//     /\/\^[a-zA-Z0-9# ,.%()\-]+\$\//g, // /^[a-zA-Z0-9# ,.%()-]+$/
//   ];

//   // CSS "dangerous" constructs (if present together with user input, treat as high risk)
//   const cssDangerous = [
//     /expression\s*\(/gi, // old IE
//     /behavior\s*:\s*url\s*\(/gi, // old IE .htc behaviors
//     /url\s*\(\s*['"]?\s*javascript\s*:/gi, // url(javascript:...)
//   ];

//   // -------------------------
//   // Utils
//   // -------------------------
//   const lineFromIndex = (text: string, idx: number) =>
//     text.slice(0, idx).split("\n").length;

//   const sliceHasSource = (slice: string, sources: string[]) =>
//     sources.some((s) => new RegExp(s).test(slice));

//   const sliceHasAny = (slice: string, patterns: RegExp[]) =>
//     patterns.some((re) => re.test(slice));

//   const isSanitizedForContext = (
//     slice: string,
//     context: "html" | "url" | "header" | "json" | "css"
//   ) => {
//     if (context === "url") return sliceHasAny(slice, urlSanitizers);
//     if (context === "html") return sliceHasAny(slice, htmlSanitizers);
//     if (context === "css") return sliceHasAny(slice, cssSanitizers);
//     // headers/json: assume unsafe unless proven otherwise; JSON is safe if not embedded into HTML
//     return false;
//   };

//   // -------------------------
//   // 4) Template checks (server-rendered)
//   // -------------------------
//   const templateUnescaped: { re: RegExp; rec: string }[] = [
//     // PHP short echo (unescaped)
//     {
//       re: /<\?=\s*([^?]+)\s*\?>/g,
//       rec: "Use <?= htmlspecialchars(...) ?> or escape output.",
//     },
//     // Handlebars/Mustache triple braces (unescaped)
//     {
//       re: /\{\{\{\s*([^}]+)\s*\}\}\}/g,
//       rec: "Use {{ var }} (escaped) instead of triple braces in Handlebars.",
//     },
//     // EJS raw output
//     {
//       re: /<%-\s*([^%]+)\s*%>/g,
//       rec: "Use <%= %> (escaped) instead of <%- %> in EJS.",
//     },
//     // Pug unescaped
//     { re: /!=\s*\w+/g, rec: "Use #{var} (escaped) instead of != var in Pug." },
//     // (Optional) template inline style injections
//     {
//       re: /style\s*=\s*["'`][\s\S]*?(?:\+|\$\{)[\s\S]*?["'`]/gi,
//       rec: "Avoid dynamic style attributes or sanitize CSS tokens.",
//     },
//   ];

//   for (const file of sourceFiles) {
//     const { content } = file;

//     // A) Template scanning
//     if (file.isTemplate) {
//       for (const { re, rec } of templateUnescaped) {
//         for (const m of content.matchAll(re)) {
//           const idx = (m as any).index ?? 0;
//           vulns.push({
//             type: "Reflective XSS (Template/Unescaped)",
//             file: file.path,
//             line: lineFromIndex(content, idx),
//             pattern: m[0],
//             recommendation: rec,
//           });
//         }
//       }
//     }

//     // B) Server-side sink scanning (HTML/URL/CSS/JSON)
//     if (file.isServerCode) {
//       for (const { re, desc, context } of serverSinks) {
//         for (const m of content.matchAll(re)) {
//           const idx = (m as any).index ?? 0;

//           // Look around the match to catch nearby variable assembly
//           const sliceStart = Math.max(0, idx - 300);
//           const sliceEnd = Math.min(content.length, idx + m[0].length + 300);
//           const slice = content.slice(sliceStart, sliceEnd);

//           const hasSource = sliceHasSource(slice, serverSources);
//           const sanitized = isSanitizedForContext(slice, context);

//           // For CSS, also consider "dangerous" functions as a risk amplifier
//           const cssDanger =
//             context === "css" ? sliceHasAny(slice, cssDangerous) : false;

//           if (hasSource && (!sanitized || cssDanger)) {
//             let recommendation = "";
//             if (context === "url") {
//               recommendation =
//                 "Validate redirect/URL targets (allow-list) and encode parameters with encodeURIComponent().";
//             } else if (context === "css") {
//               recommendation =
//                 "Never inject raw user input into CSS. Restrict to a safe allow-list (e.g., /^#[0-9a-f]{3,6}$/i for colors), or sanitize tokens (cssesc). Disallow url(javascript:), expression(), and external URLs.";
//             } else if (context === "json") {
//               recommendation =
//                 "Ensure response is application/json and not embedded in HTML. Avoid reflecting untrusted JSON inside <script> without escaping.";
//             } else {
//               recommendation =
//                 "Escape/encode untrusted data before sending HTML (e.g., escapeHtml/validator.escape) or ensure the template auto-escapes.";
//             }

//             vulns.push({
//               type:
//                 context === "css"
//                   ? "Reflective CSS Injection"
//                   : context === "url"
//                   ? "Open Redirect / URL Injection"
//                   : context === "json"
//                   ? "Reflected JSON (check embedding)"
//                   : "Reflective XSS (Server)",
//               file: file.path,
//               line: lineFromIndex(content, idx),
//               pattern: `${desc}: ${m[0].slice(0, 200)}${
//                 m[0].length > 200 ? "..." : ""
//               }`,
//               recommendation,
//             });
//           }
//         }
//       }
//     }
//   }

//   return vulns;
// };

// export default detectReflectiveXSS;

//version 4

import {
  SourceFile,
  Vulnerability,
  SinkDefinition,
} from "../../utils/types.js";

const detectReflectiveXSS = (sourceFiles: SourceFile[]): Vulnerability[] => {
  const vulns: Vulnerability[] = [];

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
  const serverSinks: SinkDefinition[] = [
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
  const lineFromIndex = (text: string, idx: number) =>
    text.slice(0, idx).split("\n").length;

  const sliceHasSource = (slice: string, sources: string[]) =>
    sources.some((s) => new RegExp(s).test(slice));

  const sliceHasAny = (slice: string, patterns: RegExp[]) =>
    patterns.some((re) => re.test(slice));

  const isSanitizedForContext = (
    slice: string,
    context: "html" | "url" | "header" | "json" | "css" | "attr" | "js"
  ) => {
    if (context === "url") return sliceHasAny(slice, urlSanitizers);
    if (context === "html") return sliceHasAny(slice, htmlSanitizers);
    if (context === "css") return sliceHasAny(slice, cssSanitizers);
    return false;
  };

  // -------------------------
  // 4) Template checks (server-rendered)
  // -------------------------
  const templateUnescaped: { re: RegExp; rec: string }[] = [
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
          const idx = (m as any).index ?? 0;
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
          const idx = (m as any).index ?? 0;

          const sliceStart = Math.max(0, idx - 300);
          const sliceEnd = Math.min(content.length, idx + m[0].length + 300);
          const slice = content.slice(sliceStart, sliceEnd);

          const hasSource = sliceHasSource(slice, serverSources);
          const sanitized = isSanitizedForContext(slice, context);
          const cssDanger =
            context === "css" ? sliceHasAny(slice, cssDangerous) : false;

          if (hasSource && (!sanitized || cssDanger)) {
            let recommendation = "";
            let vulnerabilityType = "";
            let severity: "low" | "medium" | "high" | "critical" = "high";

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
              pattern: `${desc}: ${m[0].slice(0, 200)}${
                m[0].length > 200 ? "..." : ""
              }`,
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
