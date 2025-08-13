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
  context: "html" | "url" | "header" | "json" | "attr";
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
  storedXSS: ReturnType<typeof detectStoredXSS>,
}