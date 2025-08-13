import { SourceFile, Vulnerability } from "../../utils/types.js";
declare const detectStoredXSS: (sourceFiles: SourceFile[]) => Vulnerability[];
export default detectStoredXSS;
