import detectStoredXSS from "./xss/stored.js";
export const runCodeScan = (sourceFiles) => {
    console.log("🔍 Running code scanner...");
    const storedXSSResults = detectStoredXSS(sourceFiles);
    return {
        storedXSS: storedXSSResults,
    };
};
//# sourceMappingURL=code_scanner.js.map