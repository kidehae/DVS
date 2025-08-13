import detectReflectiveXSS from "../scanners/xss/reflective.js";
import detectStoredXSS from "../scanners/xss/stored.js";
export interface SourceFile {
    path: string;
    content: string;
    isTemplate?: boolean;
    isServerCode?: boolean;
    isClientCode?: boolean;
    language?: string;
    framework?: string;
    dependencies?: string[];
    lastModified?: Date;
    size?: number;
}
export interface SinkDefinition {
    re: RegExp;
    desc: string;
    context: "html" | "url" | "header" | "json" | "attr" | "css";
}
export interface Vulnerability {
    type: string;
    file: string;
    line?: number;
    pattern: string;
    recommendation: string;
    severity: "low" | "medium" | "high" | "critical";
    confidence: number;
    snippet?: string;
    sanitized?: boolean;
}
export interface ScanResult {
    reflectiveXSS: ReturnType<typeof detectReflectiveXSS>;
    storedXSS: ReturnType<typeof detectStoredXSS>;
}
