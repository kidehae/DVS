import detectStoredXSS from "./xss/stored.js";
import { ScanResult, SourceFile } from "../utils/types.js";

export const runCodeScan = (sourceFiles: SourceFile[]): ScanResult => {
  console.log("🔍 Running code scanner...");
  const storedXSSResults = detectStoredXSS(sourceFiles);

  return {
    storedXSS: storedXSSResults,
  }
}
