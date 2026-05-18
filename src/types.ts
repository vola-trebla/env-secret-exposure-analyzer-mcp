export type Severity = 'critical' | 'high' | 'medium' | 'low';

export interface SecretFinding {
  file: string;
  line: number;
  column: number;
  pattern: string;
  severity: Severity;
  preview: string; // masked, e.g. "sk-ant-****..."
}

export interface GitignoreIssue {
  file: string;
  coveredByGitignore: boolean;
  suggestedRule?: string;
}

export interface LogLeakFinding {
  file: string;
  line: number;
  expression: string; // e.g. console.log(process.env.SECRET_KEY)
  severity: Severity;
}

export interface ScanResult {
  scannedFiles: number;
  findings: SecretFinding[];
  gitignoreIssues: GitignoreIssue[];
}

export interface LogLeakResult {
  scannedFiles: number;
  findings: LogLeakFinding[];
}
