import detectReflectiveXSS from "../scanners/xss/reflective.js";
import detectStoredXSS from "../scanners/xss/stored.js";
import detectDOMXSS from "../scanners/xss/dom.js";

export interface SourceFile {
  path: string;
  content: string;
  isTemplate?: boolean;
  isServerCode?: boolean;
  isClientCode?: boolean;
  language?: string; // e.g., "js", "ts", "html"
  framework?: string; // e.g., "react", "express"
  dependencies?: string[]; // npm packages used
  lastModified?: Date;
  size?: number; // bytes or line count
}

export interface SinkDefinition {
  re: RegExp;
  desc: string;
  context: "html" | "url" | "header" | "json" | "attr" | "css" | "js";
}

export interface Vulnerability {
  type: string;
  file: string;
  line?: number;
  pattern: string;
  recommendation: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number; // 0–1
  snippet?: string;
  sanitized?: boolean;
}

export interface ScanResult {
  reflectiveXSS: ReturnType<typeof detectReflectiveXSS>;
  storedXSS: ReturnType<typeof detectStoredXSS>;
  domXSS: ReturnType<typeof detectDOMXSS>;
}
