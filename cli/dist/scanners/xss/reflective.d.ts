interface SourceFile {
    path: string;
    content: string;
    isTemplate?: boolean;
    isServerCode?: boolean;
}
interface Vulnerability {
    type: string;
    file: string;
    line?: number;
    pattern: string;
    recommendation: string;
}
declare const detectReflectiveXSS: (sourceFiles: SourceFile[]) => Vulnerability[];
export default detectReflectiveXSS;
