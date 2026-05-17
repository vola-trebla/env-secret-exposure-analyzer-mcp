import fs from "fs";
import path from "path";
import type {
  ScanResult,
  LogLeakResult,
  SecretFinding,
  LogLeakFinding,
  Severity,
} from "./types.js";

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: Severity }> = [
  { name: "AWS Access Key", pattern: /\bAKIA[0-9A-Z]{16}\b/, severity: "critical" },
  {
    name: "AWS Secret Key",
    pattern: /aws[_.]?secret[_.]?access[_.]?key\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?/i,
    severity: "critical",
  },
  {
    name: "GitHub Token",
    pattern: /\bghp_[A-Za-z0-9]{36,}\b|\bgho_[A-Za-z0-9]{36,}\b|\bghs_[A-Za-z0-9]{36,}\b/,
    severity: "critical",
  },
  {
    name: "Stripe Secret Key",
    pattern: /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/,
    severity: "critical",
  },
  {
    name: "Stripe Publishable Key",
    pattern: /\bpk_(live|test)_[A-Za-z0-9]{24,}\b/,
    severity: "high",
  },
  {
    name: "Private Key",
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: "critical",
  },
  { name: "Anthropic API Key", pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/, severity: "critical" },
  { name: "OpenAI API Key", pattern: /\bsk-[A-Za-z0-9]{32,}\b/, severity: "critical" },
  { name: "Slack Token", pattern: /\bxox[baprs]-[A-Za-z0-9-]+\b/, severity: "critical" },
  { name: "Google API Key", pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: "high" },
  { name: "Hardcoded password", pattern: /password\s*[:=]\s*['"][^'"]{6,}['"]/i, severity: "high" },
  { name: "Hardcoded secret", pattern: /secret\s*[:=]\s*['"][^'"]{6,}['"]/i, severity: "medium" },
  { name: "Hardcoded token", pattern: /token\s*[:=]\s*['"][^'"]{16,}['"]/i, severity: "medium" },
];

const SENSITIVE_FILE_PATTERNS = [
  /^\.env(?!\.example$|\.sample$|\.template$)(\.|$)/,
  /^secrets?\.(json|yaml|yml|toml)$/i,
  /^credentials?\.(json|yaml|yml)$/i,
  /private[_\-.]?key/i,
  /\.pem$/,
  /\.p12$/,
  /\.pfx$/,
  /id_(rsa|dsa|ecdsa|ed25519)$/,
];

const LOG_LEAK_PATTERNS = [
  /console\.(log|error|warn|info|debug)\s*\([^)]*process\.env\.[A-Z_]+/,
  /console\.(log|error|warn|info|debug)\s*\([^)]*\b(password|secret|token|apiKey|api_key|privateKey|private_key)\b/i,
  /logger\.(log|error|warn|info|debug)\s*\([^)]*process\.env\.[A-Z_]+/,
  /logger\.(log|error|warn|info|debug)\s*\([^)]*\b(password|secret|token|apiKey)\b/i,
  /JSON\.stringify\s*\([^)]*process\.env\b/,
];

const DEFAULT_SCAN_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".env",
  ".env.local",
  ".env.development",
  ".env.production",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".ini",
  ".sh",
  ".bash",
]);

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage"]);

function maskSecret(value: string): string {
  if (value.length <= 8) return "****";
  return value.slice(0, 4) + "****" + value.slice(-4);
}

function* walkFiles(dir: string, extensions?: Set<string>): Generator<string> {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) yield* walkFiles(path.join(dir, entry.name), extensions);
    } else {
      const ext = path.extname(entry.name).toLowerCase();
      const base = entry.name;
      if (!extensions || extensions.has(ext) || extensions.has(base)) {
        yield path.join(dir, entry.name);
      }
    }
  }
}

export function scanForSecrets(projectPath: string, extensions?: string[]): ScanResult {
  if (!fs.existsSync(projectPath)) throw new Error(`Path not found: ${projectPath}`);

  const extSet = extensions ? new Set(extensions) : DEFAULT_SCAN_EXTENSIONS;
  const findings: SecretFinding[] = [];
  let scannedFiles = 0;

  for (const filePath of walkFiles(projectPath, extSet)) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }
    scannedFiles++;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const { name, pattern, severity } of SECRET_PATTERNS) {
        const match = line.match(pattern);
        if (match) {
          const matched = match[0];
          findings.push({
            file: path.relative(projectPath, filePath),
            line: i + 1,
            column: match.index ?? 0,
            pattern: name,
            severity,
            preview: maskSecret(matched),
          });
        }
      }
    }
  }

  const gitignoreIssues = checkGitignoreCoverage(projectPath);
  return { scannedFiles, findings, gitignoreIssues };
}

export function checkGitignoreCoverage(projectPath: string): ScanResult["gitignoreIssues"] {
  if (!fs.existsSync(projectPath)) throw new Error(`Path not found: ${projectPath}`);

  const gitignorePath = path.join(projectPath, ".gitignore");
  const gitignoreContent = fs.existsSync(gitignorePath)
    ? fs.readFileSync(gitignorePath, "utf8")
    : "";
  const gitignoreLines = gitignoreContent
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const issues: ScanResult["gitignoreIssues"] = [];

  function isIgnored(filename: string): boolean {
    return gitignoreLines.some((rule) => {
      const ruleBase = rule.replace(/^\//, "").replace(/\/$/, "");
      if (ruleBase === filename) return true;
      if (ruleBase.startsWith("*.") && filename.endsWith(ruleBase.slice(1))) return true;
      if (
        ruleBase.includes("*") &&
        new RegExp("^" + ruleBase.replace(/\*/g, ".*") + "$").test(filename)
      )
        return true;
      return false;
    });
  }

  // Walk only top-level and one level deep for sensitive files
  for (const entry of fs.readdirSync(projectPath, { withFileTypes: true })) {
    if (entry.isDirectory() && SKIP_DIRS.has(entry.name)) continue;
    if (!entry.isFile()) continue;
    if (SENSITIVE_FILE_PATTERNS.some((p) => p.test(entry.name))) {
      const covered = isIgnored(entry.name);
      issues.push({
        file: entry.name,
        coveredByGitignore: covered,
        suggestedRule: covered ? undefined : entry.name,
      });
    }
  }

  return issues;
}

export function scanForLogLeaks(projectPath: string): LogLeakResult {
  if (!fs.existsSync(projectPath)) throw new Error(`Path not found: ${projectPath}`);

  const sourceExtensions = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs"]);
  const findings: LogLeakFinding[] = [];
  let scannedFiles = 0;

  for (const filePath of walkFiles(projectPath, sourceExtensions)) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      continue;
    }
    scannedFiles++;

    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const pattern of LOG_LEAK_PATTERNS) {
        const match = line.match(pattern);
        if (match) {
          const isEnvLeak = line.includes("process.env");
          findings.push({
            file: path.relative(projectPath, filePath),
            line: i + 1,
            expression: line.trim().slice(0, 120),
            severity: isEnvLeak ? "high" : "medium",
          });
          break;
        }
      }
    }
  }

  return { scannedFiles, findings };
}
