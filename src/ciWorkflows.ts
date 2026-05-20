import * as fs from 'fs';
import * as path from 'path';

export interface CiWorkflowFinding {
  file: string;
  job: string;
  step: string;
  line: number;
  pattern_found: string;
  risk: 'injection' | 'log_leak';
  recommendation: string;
}

export interface CiWorkflowResult {
  files_scanned: number;
  findings: CiWorkflowFinding[];
}

const DANGEROUS_PATTERNS: Array<{
  pattern: RegExp;
  risk: 'injection' | 'log_leak';
  recommendation: string;
}> = [
  {
    // ${{ secrets.ANYTHING }} in a run step — GitHub Actions expands this before the shell sees it,
    // so the plaintext value appears in the runner log.
    pattern: /\$\{\{\s*secrets\.\w+\s*\}\}/,
    risk: 'log_leak',
    recommendation:
      'Bind the secret to an env var (env: MY_SECRET: ${{ secrets.MY_SECRET }}) and reference it as $MY_SECRET in the run step. Never interpolate ${{ secrets.* }} directly in shell commands.',
  },
  {
    // ${{ github.token }} same issue
    pattern: /\$\{\{\s*github\.token\s*\}\}/,
    risk: 'log_leak',
    recommendation:
      'Use the automatically provided $GITHUB_TOKEN env var instead of ${{ github.token }} in run steps.',
  },
  {
    // Untrusted user-controlled input — PR title/body, commit message, issue title
    // can contain shell metacharacters and enable command injection.
    pattern: /\$\{\{\s*github\.event\.(pull_request|issue|head_commit|commits)\.[.\w]+\s*\}\}/,
    risk: 'injection',
    recommendation:
      'Never interpolate untrusted PR/issue/commit content directly in run steps — attackers control this value. Write the value to a file or use an action with explicit input sanitization.',
  },
];

function findWorkflowFiles(repoPath: string): string[] {
  const files: string[] = [];

  const ghDir = path.join(repoPath, '.github', 'workflows');
  if (fs.existsSync(ghDir)) {
    try {
      for (const entry of fs.readdirSync(ghDir, { withFileTypes: true })) {
        if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) {
          files.push(path.join(ghDir, entry.name));
        }
      }
    } catch {
      // unreadable dir
    }
  }

  const circleConfig = path.join(repoPath, '.circleci', 'config.yml');
  if (fs.existsSync(circleConfig)) files.push(circleConfig);

  const gitlabConfig = path.join(repoPath, '.gitlab-ci.yml');
  if (fs.existsSync(gitlabConfig)) files.push(gitlabConfig);

  return files;
}

function checkText(
  text: string,
  lineNum: number,
  file: string,
  job: string,
  step: string,
  findings: CiWorkflowFinding[],
): void {
  for (const { pattern, risk, recommendation } of DANGEROUS_PATTERNS) {
    const match = text.match(pattern);
    if (match) {
      findings.push({
        file,
        job,
        step,
        line: lineNum,
        pattern_found: match[0],
        risk,
        recommendation,
      });
      break;
    }
  }
}

function scanWorkflowFile(filePath: string, repoRoot: string): CiWorkflowFinding[] {
  const findings: CiWorkflowFinding[] = [];
  let content: string;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return findings;
  }

  const relPath = path.relative(repoRoot, filePath);
  const lines = content.split('\n');

  let currentJob = '(unknown)';
  let currentStep = '(unknown)';
  let inRunBlock = false;
  let runIndent = 0;
  let inJobsSection = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    const rawIndent = line.length - line.trimStart().length;

    if (/^jobs:\s*$/.test(line)) {
      inJobsSection = true;
    }

    // Job name: exactly 2 spaces + identifier + colon (GitHub Actions)
    if (inJobsSection && /^ {2}[a-zA-Z0-9_][a-zA-Z0-9_-]*:\s*$/.test(line)) {
      currentJob = trimmed.replace(/:$/, '');
      currentStep = '(unknown)';
      inRunBlock = false;
    }

    // Step name
    const stepNameMatch = line.match(/^\s+-\s+name:\s+(.+)$/);
    if (stepNameMatch) {
      currentStep = stepNameMatch[1].trim();
      inRunBlock = false;
    }

    // run: block detection
    const runMatch = line.match(/^(\s+)run:\s*(.*)?$/);
    if (runMatch) {
      inRunBlock = true;
      runIndent = runMatch[1].length;
      const inlineCmd = (runMatch[2] ?? '').trim();
      if (inlineCmd && inlineCmd !== '|' && inlineCmd !== '>' && !inlineCmd.startsWith('#')) {
        checkText(inlineCmd, i + 1, relPath, currentJob, currentStep, findings);
        inRunBlock = false;
      }
    } else if (inRunBlock) {
      if (rawIndent > runIndent && trimmed.length > 0 && !trimmed.startsWith('#')) {
        checkText(trimmed, i + 1, relPath, currentJob, currentStep, findings);
      } else if (trimmed.length > 0 && !trimmed.startsWith('#')) {
        inRunBlock = false;
      }
    }

    // CircleCI command: and GitLab script: single-line entries
    const cmdMatch = line.match(/^\s+(?:command|script):\s+(.+)$/);
    if (cmdMatch) {
      checkText(cmdMatch[1].trim(), i + 1, relPath, currentJob, currentStep, findings);
    }
  }

  return findings;
}

export function scanCiWorkflows(repoPath: string): CiWorkflowResult {
  if (!fs.existsSync(repoPath)) throw new Error(`Path not found: ${repoPath}`);

  const workflowFiles = findWorkflowFiles(repoPath);
  const findings: CiWorkflowFinding[] = [];

  for (const file of workflowFiles) {
    findings.push(...scanWorkflowFile(file, repoPath));
  }

  return { files_scanned: workflowFiles.length, findings };
}
