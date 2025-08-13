import detectReflectiveXSS from "./xss/reflective.js";
import detectStoredXSS from "./xss/stored.js";
export const runCodeScan = (sourceFiles) => {
    console.log("🔍 Running code scanner...");
    const reflectiveXSSResults = detectReflectiveXSS(sourceFiles);
    const storedXSSResults = detectStoredXSS(sourceFiles);
    return {
        reflectiveXSS: reflectiveXSSResults,
        storedXSS: storedXSSResults,
    };
};
//# sourceMappingURL=code_scanner.js.map