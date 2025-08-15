import detectReflectiveXSS from "./xss/reflective.js";
import detectStoredXSS from "./xss/stored.js";
import detectDOMXSS from "./xss/dom.js";
import { ScanResult, SourceFile } from "../utils/types.js";

export const runCodeScan = (sourceFiles: SourceFile[]): ScanResult => {
  console.log("🔍 Running code scanner...");
  const reflectiveXSSResults = detectReflectiveXSS(sourceFiles);
  const storedXSSResults = detectStoredXSS(sourceFiles);
  const domXSSResults = detectDOMXSS(sourceFiles);
  return {
    reflectiveXSS: reflectiveXSSResults,
    storedXSS: storedXSSResults,
    domXSS: domXSSResults,
  };
};
