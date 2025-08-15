// import {
//   SourceFile,
//   Vulnerability,
//   SinkDefinition,
// } from "../../utils/types.js";

// type ContextType = "html" | "js" | "url" | "attr" | "css";

// const detectDOMXSS = (sourceFiles: SourceFile[]): Vulnerability[] => {
//   const vulns: Vulnerability[] = [];

//   // Enhanced source patterns
//   const domSources: string[] = [
//     "location\\.hash",
//     "location\\.hash\\.substring\\(",
//     "location\\.hash\\.slice\\(",
//     "decodeURIComponent\\(location\\.hash\\)",
//     "location\\.search",
//     "location\\.pathname",
//     "location\\.href",
//     "document\\.URL",
//     "document\\.documentURI",
//     "document\\.baseURI",
//     "document\\.referrer",
//     "URLSearchParams",
//     "document\\.cookie",
//     "window\\.name",
//     "localStorage(?:\\.getItem)?",
//     "sessionStorage(?:\\.getItem)?",
//     "indexedDB",
//     "document\\.forms",
//     "\\.value\\b",
//     "\\.files\\b",
//     "\\.getAttribute\\(",
//     "\\.attributes\\b",
//     "navigator\\.userAgent",
//     "navigator\\.language",
//     "navigator\\.plugins",
//     "screen\\.(width|height)",
//     "fetch\\(",
//     "XMLHttpRequest",
//     "xhr\\.",
//     "WebSocket\\(",
//     "postMessage\\(",
//   ];

//   // More comprehensive sink patterns
//   const domSinks: SinkDefinition[] = [
//     // HTML injection
//     {
//       re: /\bdocument\.(write|writeln)\s*\([^)]*\)/g,
//       desc: "document.write/writeln",
//       context: "html",
//     },
//     {
//       re: /\b(?:document\.getElementById\([^)]+\)|[\w.]+)\.(innerHTML|outerHTML)\s*=/g,
//       desc: "element.innerHTML/outerHTML =",
//       context: "html",
//     },
//     {
//       re: /\b\w+\.insertAdjacentHTML\s*\([^)]*\)/g,
//       desc: "insertAdjacentHTML()",
//       context: "html",
//     },

//     // Script execution
//     {
//       re: /\beval\s*\([^)]*\)/g,
//       desc: "eval()",
//       context: "js",
//     },
//     {
//       re: /\bnew\s+Function\s*\([^)]*\)/g,
//       desc: "new Function()",
//       context: "js",
//     },
//     {
//       re: /\b(?:setTimeout|setInterval)\s*\(\s*['"`]/g,
//       desc: "setTimeout/setInterval(string)",
//       context: "js",
//     },

//     // URL/navigation
//     {
//       re: /\blocation\s*=\s*[^;]+/g,
//       desc: "location = ...",
//       context: "url",
//     },
//     {
//       re: /\blocation\.(href|assign|replace)\s*\([^)]*\)|\blocation\.href\s*=/g,
//       desc: "location.href/assign/replace",
//       context: "url",
//     },
//     {
//       re: /\bwindow\.open\s*\([^)]*\)/g,
//       desc: "window.open()",
//       context: "url",
//     },

//     // Attribute/event-handler assignments
//     {
//       re: /\b\w+\.setAttribute\s*\(\s*['"][^'"]+['"]\s*,\s*(?:[^)]*?(?:\+|\$\{)[^)]*?|['"][^'"]*userInput[^'"]*['"])\)/gi,
//       desc: "setAttribute() with dynamic value",
//       context: "attr",
//     },
//     {
//       re: /\b\w+\.on[a-z]+\s*=\s*(?:[^;]*?(?:\+|\$\{)|['"][^'"]*userInput[^'"]*['"])/gi,
//       desc: "inline event handler with dynamic",
//       context: "attr",
//     },

//     // CSS injection
//     {
//       re: /\b(?:document\.getElementById\([^)]+\)|[\w.]+)\.style\.(innerHTML|cssText)\s*=\s*(?:[^;]*?(?:\+|\$\{)|['"][^'"]*userInput[^'"]*['"])/g,
//       desc: "style.innerHTML/cssText =",
//       context: "css",
//     },
//     {
//       re: /\b\w+\.style\.setProperty\s*\(\s*['"][^'"]+['"]\s*,\s*(?:[^)]*?(?:\+|\$\{)|['"][^'"]*userInput[^'"]*['"])\)/g,
//       desc: "style.setProperty()",
//       context: "css",
//     },

//     // URL-bearing attributes
//     {
//       re: /\b\w+\.(src|href|srcdoc|data|code|formAction|action)\s*=\s*(?:[^;]*?(?:\+|\$\{)|['"][^'"]*userInput[^'"]*['"])/g,
//       desc: "URL-bearing attribute assignment",
//       context: "url",
//     },
//     {
//       re: /<(?:iframe|frame|embed|object)\s+[^>]*(?:src|srcdoc)\s*=\s*(?:['"][^'"]*userInput[^'"]*['"]|`[^`]*\$\{[^}]*\}[^`]*`)/gi,
//       desc: "Embedded element src/srcdoc",
//       context: "url",
//     },
//   ];

//   const lineFromIndex = (text: string, idx: number): number =>
//     text.slice(0, idx).split("\n").length;

//   const sliceHasAny = (slice: string, patterns: (RegExp | string)[]): boolean =>
//     patterns.some((p: RegExp | string) =>
//       p instanceof RegExp ? p.test(slice) : new RegExp(p).test(slice)
//     );

//   for (const file of sourceFiles) {
//     const { content, isClientCode, language, isTemplate } = file;

//     const looksClient =
//       isClientCode ||
//       isTemplate ||
//       (language && /^(js|ts|tsx|jsx|html)$/i.test(language)) ||
//       /\.(html?|jsx?|tsx?)$/i.test(file.path);

//     if (!looksClient || !content) continue;

//     // First scan for all sinks
//     for (const sink of domSinks) {
//       for (const m of content.matchAll(sink.re)) {
//         const idx = (m as any).index ?? 0;
//         const ctx = sink.context as ContextType;

//         // Use larger window for better source detection
//         const slice = content.slice(
//           Math.max(0, idx - 750),
//           Math.min(content.length, idx + m[0].length + 750)
//         );

//         // More lenient source detection
//         const hasSource =
//           sliceHasAny(slice, domSources) ||
//           /userInput|location\.hash/.test(slice);

//         if (!hasSource) continue;

//         let severity: "low" | "medium" | "high" | "critical" = "high";
//         let type = `DOM-based ${ctx.toUpperCase()} Injection`;
//         let recommendation = "";

//         switch (ctx) {
//           case "html":
//             type = "DOM-based HTML Injection";
//             recommendation =
//               "Use textContent instead of innerHTML/outerHTML or sanitize with DOMPurify";
//             severity = "high";
//             break;
//           case "js":
//             type = "DOM-based JS Execution";
//             recommendation = "Never execute dynamic code from user input";
//             severity = "critical";
//             break;
//           case "url":
//             type = "DOM-based URL Injection";
//             recommendation =
//               "Validate all URLs and block javascript:/data: schemes";
//             severity = /javascript:/.test(m[0]) ? "critical" : "high";
//             break;
//           case "attr":
//             type = "DOM-based Attribute Injection";
//             recommendation = "Avoid setting attributes with dynamic user input";
//             severity = "high";
//             break;
//           case "css":
//             type = "DOM-based CSS Injection";
//             recommendation = "Never inject user input into CSS properties";
//             severity = /expression\(|javascript:/.test(m[0])
//               ? "critical"
//               : "high";
//             break;
//         }

//         vulns.push({
//           type,
//           file: file.path,
//           line: lineFromIndex(content, idx),
//           pattern: `${sink.desc}: ${m[0].slice(0, 200)}${
//             m[0].length > 200 ? "..." : ""
//           }`,
//           recommendation,
//           severity,
//           confidence: 0.95,
//           snippet: slice,
//           sanitized: false,
//         });
//       }
//     }

//     // Special case for inline javascript: URLs
//     const inlineJsUrls =
//       /(?:href|src|action)\s*=\s*["']\s*javascript:[^"']*["']/gi;
//     for (const m of content.matchAll(inlineJsUrls)) {
//       const idx = (m as any).index ?? 0;
//       vulns.push({
//         type: "DOM-based URL Injection",
//         file: file.path,
//         line: lineFromIndex(content, idx),
//         pattern: m[0],
//         recommendation:
//           "Remove all javascript: URLs - use event handlers instead",
//         severity: "critical",
//         confidence: 1.0,
//         snippet: content.slice(
//           Math.max(0, idx - 100),
//           Math.min(content.length, idx + m[0].length + 100)
//         ),
//         sanitized: false,
//       });
//     }
//   }

//   return vulns;
// };

// export default detectDOMXSS;

import {
  SourceFile,
  Vulnerability,
  SinkDefinition,
} from "../../utils/types.js";

type ContextType = "html" | "js" | "url" | "attr" | "css";

const detectDOMXSS = (sourceFiles: SourceFile[]): Vulnerability[] => {
  const vulns: Vulnerability[] = [];

  // Enhanced source patterns
  const domSources: string[] = [
    "location\\.hash",
    "location\\.hash\\.substring\\(",
    "location\\.hash\\.slice\\(",
    "decodeURIComponent\\(location\\.hash\\)",
    "location\\.search",
    "location\\.pathname",
    "location\\.href",
    "document\\.URL",
    "document\\.documentURI",
    "document\\.baseURI",
    "document\\.referrer",
    "URLSearchParams",
    "document\\.cookie",
    "window\\.name",
    "localStorage(?:\\.getItem)?",
    "sessionStorage(?:\\.getItem)?",
    "indexedDB",
    "document\\.forms",
    "\\.value\\b",
    "\\.files\\b",
    "\\.getAttribute\\(",
    "\\.attributes\\b",
    "navigator\\.userAgent",
    "navigator\\.language",
    "navigator\\.plugins",
    "screen\\.(width|height)",
    "fetch\\(",
    "XMLHttpRequest",
    "xhr\\.",
    "WebSocket\\(",
    "postMessage\\(",
  ];

  // More comprehensive sink patterns
  const domSinks: SinkDefinition[] = [
    // HTML injection
    {
      re: /\bdocument\.(write|writeln)\s*\([^)]*\)/g,
      desc: "document.write/writeln",
      context: "html",
    },
    {
      re: /\b(?:document\.getElementById\([^)]+\)|[\w.]+)\.(innerHTML|outerHTML)\s*=/g,
      desc: "element.innerHTML/outerHTML =",
      context: "html",
    },
    {
      re: /\b\w+\.insertAdjacentHTML\s*\([^)]*\)/g,
      desc: "insertAdjacentHTML()",
      context: "html",
    },

    // Script execution
    {
      re: /\beval\s*\([^)]*\)/g,
      desc: "eval()",
      context: "js",
    },
    {
      re: /\bnew\s+Function\s*\([^)]*\)/g,
      desc: "new Function()",
      context: "js",
    },
    {
      re: /\b(?:setTimeout|setInterval)\s*\(\s*['"`]/g,
      desc: "setTimeout/setInterval(string)",
      context: "js",
    },

    // URL/navigation
    {
      re: /\blocation\s*=\s*[^;]+/g,
      desc: "location = ...",
      context: "url",
    },
    {
      re: /\blocation\.(href|assign|replace)\s*\([^)]*\)|\blocation\.href\s*=/g,
      desc: "location.href/assign/replace",
      context: "url",
    },
    {
      re: /\bwindow\.open\s*\([^)]*\)/g,
      desc: "window.open()",
      context: "url",
    },

    // Attribute/event-handler assignments
    {
      re: /\b\w+\.setAttribute\s*\(\s*['"][^'"]+['"]\s*,\s*(?:[^)]*?(?:\+|\$\{)[^)]*?|['"][^'"]*userInput[^'"]*['"])\)/gi,
      desc: "setAttribute() with dynamic value",
      context: "attr",
    },
    {
      re: /\b\w+\.on[a-z]+\s*=\s*(?:[^;]*?(?:\+|\$\{)|['"][^'"]*userInput[^'"]*['"])/gi,
      desc: "inline event handler with dynamic",
      context: "attr",
    },

    // CSS injection
    {
      re: /\b(?:document\.getElementById\([^)]+\)|[\w.]+)\.style\.(innerHTML|cssText)\s*=\s*(?:[^;]*?(?:\+|\$\{)|['"][^'"]*userInput[^'"]*['"])/g,
      desc: "style.innerHTML/cssText =",
      context: "css",
    },
    {
      re: /\b\w+\.style\.setProperty\s*\(\s*['"][^'"]+['"]\s*,\s*(?:[^)]*?(?:\+|\$\{)|['"][^'"]*userInput[^'"]*['"])\)/g,
      desc: "style.setProperty()",
      context: "css",
    },

    // URL-bearing attributes
    {
      re: /\b\w+\.(src|href|srcdoc|data|code|formAction|action)\s*=\s*(?:[^;]*?(?:\+|\$\{)|['"][^'"]*userInput[^'"]*['"])/g,
      desc: "URL-bearing attribute assignment",
      context: "url",
    },
    {
      re: /<(?:iframe|frame|embed|object)\s+[^>]*(?:src|srcdoc)\s*=\s*(?:['"][^'"]*userInput[^'"]*['"]|`[^`]*\$\{[^}]*\}[^`]*`)/gi,
      desc: "Embedded element src/srcdoc",
      context: "url",
    },
  ];

  const lineFromIndex = (text: string, idx: number): number =>
    text.slice(0, idx).split("\n").length;

  const sliceHasAny = (slice: string, patterns: (RegExp | string)[]): boolean =>
    patterns.some((p: RegExp | string) =>
      p instanceof RegExp ? p.test(slice) : new RegExp(p).test(slice)
    );

  for (const file of sourceFiles) {
    const { content, isClientCode, language, isTemplate } = file;

    const looksClient =
      isClientCode ||
      isTemplate ||
      (language && /^(js|ts|tsx|jsx|html)$/i.test(language)) ||
      /\.(html?|jsx?|tsx?)$/i.test(file.path);

    if (!looksClient || !content) continue;

    // First scan for all sinks
    for (const sink of domSinks) {
      for (const m of content.matchAll(sink.re)) {
        const idx = (m as any).index ?? 0;
        const ctx = sink.context as ContextType;

        // Use larger window for better source detection
        const slice = content.slice(
          Math.max(0, idx - 750),
          Math.min(content.length, idx + m[0].length + 750)
        );

        // More lenient source detection
        const hasSource =
          sliceHasAny(slice, domSources) ||
          /userInput|location\.hash/.test(slice);

        if (!hasSource) continue;

        let severity: "low" | "medium" | "high" | "critical" = "high";
        let type = `DOM-based ${ctx.toUpperCase()} Injection`;
        let recommendation = "";

        switch (ctx) {
          case "html":
            type = "DOM-based HTML Injection";
            recommendation =
              "Use textContent instead of innerHTML/outerHTML or sanitize with DOMPurify";
            severity = "high";
            break;
          case "js":
            type = "DOM-based JS Execution";
            recommendation = "Never execute dynamic code from user input";
            severity = "critical";
            break;
          case "url":
            type = "DOM-based URL Injection";
            recommendation =
              "Validate all URLs and block javascript:/data: schemes";
            severity = /javascript:/.test(m[0]) ? "critical" : "high";
            break;
          case "attr":
            type = "DOM-based Attribute Injection";
            recommendation = "Avoid setting attributes with dynamic user input";
            severity = "high";
            break;
          case "css":
            type = "DOM-based CSS Injection";
            recommendation = "Never inject user input into CSS properties";
            severity = /expression\(|javascript:/.test(m[0])
              ? "critical"
              : "high";
            break;
        }

        vulns.push({
          type,
          file: file.path,
          line: lineFromIndex(content, idx),
          pattern: `${sink.desc}: ${m[0].trim()}`,
          recommendation,
          severity,
          confidence: 0.95,
          snippet: `${sink.desc}: ${m[0].trim()}`,
          sanitized: false,
        });
      }
    }

    // Special case for inline javascript: URLs
    const inlineJsUrls =
      /(?:href|src|action)\s*=\s*["']\s*javascript:[^"']*["']/gi;
    for (const m of content.matchAll(inlineJsUrls)) {
      const idx = (m as any).index ?? 0;
      vulns.push({
        type: "DOM-based URL Injection",
        file: file.path,
        line: lineFromIndex(content, idx),
        pattern: m[0].trim(),
        recommendation:
          "Remove all javascript: URLs - use event handlers instead",
        severity: "critical",
        confidence: 1.0,
        // snippet: content.slice(
        //   Math.max(0, idx - 100),
        //   Math.min(content.length, idx + m[0].length + 100)
        // ),
        snippet: m[0].trim(),

        sanitized: false,
      });
    }
  }

  return vulns;
};

export default detectDOMXSS;
