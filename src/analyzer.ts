// TODO: implement secret scanning logic
import type { ScanResult, LogLeakResult } from "./types.js";

export function scanForSecrets(_projectPath: string): ScanResult {
  throw new Error("not implemented");
}

export function checkGitignoreCoverage(_projectPath: string): ScanResult["gitignoreIssues"] {
  throw new Error("not implemented");
}

export function scanForLogLeaks(_projectPath: string): LogLeakResult {
  throw new Error("not implemented");
}
