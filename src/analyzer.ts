import fs from 'fs';
import path from 'path';
import type {
  ScanResult,
  LogLeakResult,
  SecretFinding,
  LogLeakFinding,
  Severity,
} from './types.js';

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: Severity }> = [
  // Cloud providers
  { name: 'AWS Access Key', pattern: /\bAKIA[0-9A-Z]{16}\b/, severity: 'critical' },
  {
    name: 'AWS Secret Key',
    pattern: /aws[_.]?secret[_.]?access[_.]?key\s*[:=]\s*['"]?[A-Za-z0-9/+]{40}['"]?/i,
    severity: 'critical',
  },
  // Source control / CI tokens
  {
    name: 'GitHub Token',
    pattern: /\bghp_[A-Za-z0-9]{36,}\b|\bgho_[A-Za-z0-9]{36,}\b|\bghs_[A-Za-z0-9]{36,}\b/,
    severity: 'critical',
  },
  // Payment
  {
    name: 'Stripe Secret Key',
    pattern: /\bsk_(live|test)_[A-Za-z0-9]{24,}\b/,
    severity: 'critical',
  },
  {
    name: 'Stripe Publishable Key',
    pattern: /\bpk_(live|test)_[A-Za-z0-9]{24,}\b/,
    severity: 'high',
  },
  { name: 'Stripe Webhook Secret', pattern: /\bwhsec_[A-Za-z0-9]{32,}\b/, severity: 'critical' },
  // Cryptographic keys
  {
    name: 'Private Key',
    pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical',
  },
  // AI / LLM providers
  { name: 'Anthropic API Key', pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/, severity: 'critical' },
  { name: 'OpenAI API Key', pattern: /\bsk-[A-Za-z0-9]{32,}\b/, severity: 'critical' },
  // Communication
  { name: 'Slack Token', pattern: /\bxox[baprs]-[A-Za-z0-9-]+\b/, severity: 'critical' },
  {
    name: 'Twilio Auth Token',
    pattern: /\btwilio[_.]?auth[_.]?token\s*[:=]\s*['"]?[a-f0-9]{32}['"]?/i,
    severity: 'critical',
  },
  { name: 'Twilio Account SID', pattern: /\bAC[a-f0-9]{32}\b/, severity: 'high' },
  {
    name: 'SendGrid API Key',
    pattern: /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}\b/,
    severity: 'critical',
  },
  // Google
  { name: 'Google API Key', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: 'high' },
  // no \b before GOCSPX — hyphen after the prefix breaks word boundary detection
  {
    name: 'Google OAuth Client Secret',
    pattern: /GOCSPX-[A-Za-z0-9_-]{24,}/,
    severity: 'critical',
  },
  // Monitoring / observability
  // flexible key length — real Sentry DSNs vary
  {
    name: 'Sentry DSN',
    pattern: /https:\/\/[a-f0-9]{8,}@[a-z0-9]+\.ingest\.sentry\.io\/\d+/,
    severity: 'medium',
  },
  {
    name: 'Datadog API Key',
    pattern: /\bdatadog[_.]?api[_.]?key\s*[:=]\s*['"]?[a-f0-9]{32}['"]?/i,
    severity: 'high',
  },
  // Database URLs with embedded credentials — handles passwords containing '@'
  {
    name: 'Database URL with password',
    pattern: /(postgres|postgresql|mysql|mongodb|redis|amqp|mssql):\/\/[^\s"'@]*:[^\s"']*@/i,
    severity: 'critical',
  },
  // MSSQL / ADO.NET semicolon-delimited connection strings: Password=secret;
  {
    name: 'MSSQL connection string password',
    pattern: /Password\s*=\s*(?!your[_\- ]|<|{|\$)[^;'">\s]{4,}/i,
    severity: 'critical',
  },
  // PEM private key inlined with escaped newlines (single-line env var format)
  {
    name: 'Inlined PEM private key',
    pattern: /-----BEGIN[^-]*PRIVATE KEY-----(?:\\n|\\r|[^-])+-----END[^-]*PRIVATE KEY-----/,
    severity: 'critical',
  },
  // Generic secrets in .env / source code
  // (?!process\.env) — skip references like `password: process.env.X` which is correct code
  {
    name: 'Hardcoded password',
    pattern: /password\s*[:=]\s*(?!process\.env)['"]?[^\s'"]{6,}['"]?/i,
    severity: 'high',
  },
  {
    name: 'Hardcoded JWT secret',
    pattern: /jwt[_.]?secret\s*[:=]\s*(?!process\.env)['"]?[^\s'"]{16,}['"]?/i,
    severity: 'critical',
  },
  {
    name: 'Hardcoded session secret',
    pattern: /session[_.]?secret\s*[:=]\s*(?!process\.env)['"]?[^\s'"]{8,}['"]?/i,
    severity: 'high',
  },
  {
    name: 'Hardcoded encryption key',
    pattern: /encryption[_.]?key\s*[:=]\s*(?!process\.env)['"]?[a-f0-9]{32,}['"]?/i,
    severity: 'critical',
  },
  {
    name: 'Hardcoded secret',
    pattern: /\bsecret\s*[:=]\s*(?!process\.env)['"][^'"]{8,}['"]/i,
    severity: 'medium',
  },
  {
    name: 'Hardcoded token',
    pattern: /\btoken\s*[:=]\s*(?!process\.env)['"][^'"]{16,}['"]/i,
    severity: 'medium',
  },
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

const LOG_LEAK_PATTERNS: Array<{ pattern: RegExp; severity: Severity }> = [
  // Logging entire process.env object — dumps all secrets at once
  {
    pattern: /console\.(log|error|warn|info|debug)\s*\([^)]*\bprocess\.env\b[^.)]/,
    severity: 'critical',
  },
  {
    pattern: /logger\.(log|error|warn|info|debug)\s*\([^)]*\bprocess\.env\b[^.]/,
    severity: 'critical',
  },
  // Logging specific env vars
  {
    pattern: /console\.(log|error|warn|info|debug)\s*\([^)]*process\.env\.[A-Z_]+/,
    severity: 'high',
  },
  {
    pattern: /logger\.(log|error|warn|info|debug)\s*\([^)]*process\.env\.[A-Z_]+/,
    severity: 'high',
  },
  // Logging objects that likely contain secrets by name
  {
    pattern:
      /console\.(log|error|warn|info|debug)\s*\([^)]*\b(password|secret|token|apiKey|api_key|privateKey|private_key|authToken|auth_token)\b/i,
    severity: 'high',
  },
  {
    pattern:
      /logger\.(log|error|warn|info|debug)\s*\([^)]*\b(password|secret|token|apiKey|authToken)\b/i,
    severity: 'high',
  },
  // JSON.stringify with process.env or config objects
  { pattern: /JSON\.stringify\s*\([^)]*process\.env\b/, severity: 'critical' },
  { pattern: /JSON\.stringify\s*\([^)]*\b(config|cfg|settings|env)\b/, severity: 'high' },
];

const DEFAULT_SCAN_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.ini',
  '.sh',
  '.bash',
]);

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  '.next',
  'coverage',
  'playwright-report',
  'test-results',
  '.nyc_output',
  'storybook-static',
]);

function maskSecret(value: string): string {
  if (value.length <= 8) return '****';
  return value.slice(0, 4) + '****' + value.slice(-4);
}

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

const PLACEHOLDER_NAME_PATTERNS =
  /test|example|dummy|mock|placeholder|sample|fake|demo|your[_\- ]|changeme/i;
const PLACEHOLDER_VALUE_PATTERNS =
  /^(your|my|the|example|test|dummy|placeholder|changeme|xxx+|aaa+|000+|1234|abcd)/i;

function isLikelyPlaceholder(line: string, matchedValue: string): boolean {
  // Check if variable name on this line contains placeholder keywords
  if (PLACEHOLDER_NAME_PATTERNS.test(line.split('=')[0] ?? '')) return true;
  // Check if the value itself looks like a template
  if (PLACEHOLDER_VALUE_PATTERNS.test(matchedValue)) return true;
  // Repeating character sequences (e.g. AAAA...AAAA, 0000...0000)
  if (/^(.)\1{7,}$/.test(matchedValue)) return true;
  // Low entropy (< 2.0 bits/char) also signals placeholder
  if (shannonEntropy(matchedValue) < 2.0) return true;
  return false;
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
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    scannedFiles++;

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const { name, pattern, severity } of SECRET_PATTERNS) {
        const match = line.match(pattern);
        if (match) {
          const matched = match[0];
          const entropy = shannonEntropy(matched);
          findings.push({
            file: path.relative(projectPath, filePath),
            line: i + 1,
            column: match.index ?? 0,
            pattern: name,
            severity,
            preview: maskSecret(matched),
            entropy_score: entropy,
            likely_placeholder: isLikelyPlaceholder(line, matched),
          });
        }
      }
    }
  }

  const gitignoreIssues = checkGitignoreCoverage(projectPath);
  return { scannedFiles, findings, gitignoreIssues };
}

export function checkGitignoreCoverage(projectPath: string): ScanResult['gitignoreIssues'] {
  if (!fs.existsSync(projectPath)) throw new Error(`Path not found: ${projectPath}`);

  const gitignorePath = path.join(projectPath, '.gitignore');
  const gitignoreContent = fs.existsSync(gitignorePath)
    ? fs.readFileSync(gitignorePath, 'utf8')
    : '';
  const gitignoreLines = gitignoreContent
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);

  const issues: ScanResult['gitignoreIssues'] = [];

  function isIgnored(filename: string): boolean {
    return gitignoreLines.some((rule) => {
      const ruleBase = rule.replace(/^\//, '').replace(/\/$/, '');
      if (ruleBase === filename) return true;
      if (ruleBase.startsWith('*.') && filename.endsWith(ruleBase.slice(1))) return true;
      if (
        ruleBase.includes('*') &&
        new RegExp('^' + ruleBase.replace(/\*/g, '.*') + '$').test(filename)
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

  const sourceExtensions = new Set(['.ts', '.tsx', '.js', '.jsx', '.mjs']);
  const findings: LogLeakFinding[] = [];
  let scannedFiles = 0;

  for (const filePath of walkFiles(projectPath, sourceExtensions)) {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch {
      continue;
    }
    scannedFiles++;

    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const { pattern, severity } of LOG_LEAK_PATTERNS) {
        const match = line.match(pattern);
        if (match) {
          findings.push({
            file: path.relative(projectPath, filePath),
            line: i + 1,
            expression: line.trim().slice(0, 120),
            severity,
          });
          break;
        }
      }
    }
  }

  return { scannedFiles, findings };
}
