import { SourceFile, Vulnerability } from "../../utils/types.js";
declare const detectReflectiveXSS: (sourceFiles: SourceFile[]) => Vulnerability[];
export default detectReflectiveXSS;
