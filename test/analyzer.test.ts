import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import path from 'path';
import fs from 'fs';
import os from 'os';
import { scanForSecrets, checkGitignoreCoverage, scanForLogLeaks } from '../src/analyzer.js';

const fixtures = path.resolve(import.meta.dirname, 'fixtures');
const fix = (p: string) => path.join(fixtures, p);

// Leaky fixtures are created at test time — not committed to git
// because GitHub push protection blocks files containing secret-shaped strings,
// even obviously fake ones. This is an ironic constraint for a secret scanner.
let leakyDir: string;

beforeAll(() => {
  leakyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-mcp-leaky-'));

  fs.mkdirSync(path.join(leakyDir, 'src'), { recursive: true });

  // Secrets in source file
  fs.writeFileSync(
    path.join(leakyDir, 'src', 'config.ts'),
    [
      `const apiKey = "sk-ant-api03-${'A'.repeat(60)}";`,
      `const stripeKey = "sk_live_${'A'.repeat(24)}";`,
      `console.log("api key:", apiKey);`,
      `console.log(process.env.DATABASE_PASSWORD);`,
    ].join('\n'),
  );

  // Secrets in .env file
  fs.writeFileSync(
    path.join(leakyDir, '.env'),
    [`GITHUB_TOKEN=ghp_${'A'.repeat(40)}`, `AWS_ACCESS_KEY_ID=AKIA${'A'.repeat(16)}`].join('\n'),
  );

  // Incomplete gitignore (missing .env)
  fs.writeFileSync(path.join(leakyDir, '.gitignore'), 'node_modules/\n');
});

afterAll(() => {
  fs.rmSync(leakyDir, { recursive: true, force: true });
});

describe('scanForSecrets', () => {
  it('clean project: no findings', () => {
    const result = scanForSecrets(fix('clean'));
    expect(result.findings).toHaveLength(0);
    expect(result.scannedFiles).toBeGreaterThan(0);
  });

  it('leaky project: detects Anthropic key in .ts file', () => {
    const result = scanForSecrets(leakyDir);
    expect(result.findings.map((f) => f.pattern)).toContain('Anthropic API Key');
  });

  it('detects MSSQL connection string password', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-mcp-mssql-'));
    fs.writeFileSync(
      path.join(dir, '.env'),
      'DB_CONN=Server=myserver;Password=hunter2secret;Database=mydb',
    );
    const result = scanForSecrets(dir);
    fs.rmSync(dir, { recursive: true, force: true });
    expect(result.findings.map((f) => f.pattern)).toContain('MSSQL connection string password');
  });

  it('does not flag MSSQL placeholder values', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-mcp-mssql-ph-'));
    fs.writeFileSync(
      path.join(dir, '.env'),
      'DB_CONN=Server=myserver;Password=your_password_here;Database=mydb',
    );
    const result = scanForSecrets(dir);
    fs.rmSync(dir, { recursive: true, force: true });
    const mssqlFindings = result.findings.filter(
      (f) => f.pattern === 'MSSQL connection string password',
    );
    expect(mssqlFindings).toHaveLength(0);
  });

  it('detects inlined PEM private key with escaped newlines', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-mcp-pem-'));
    fs.writeFileSync(
      path.join(dir, '.env'),
      `PRIVATE_KEY=-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA\\n-----END RSA PRIVATE KEY-----`,
    );
    const result = scanForSecrets(dir);
    fs.rmSync(dir, { recursive: true, force: true });
    expect(result.findings.map((f) => f.pattern)).toContain('Inlined PEM private key');
  });

  it('leaky project: detects Stripe key', () => {
    const result = scanForSecrets(leakyDir);
    expect(result.findings.map((f) => f.pattern)).toContain('Stripe Secret Key');
  });

  it('leaky project: detects GitHub token in .env', () => {
    const result = scanForSecrets(leakyDir);
    expect(result.findings.map((f) => f.pattern)).toContain('GitHub Token');
  });

  it('leaky project: detects AWS access key', () => {
    const result = scanForSecrets(leakyDir);
    expect(result.findings.map((f) => f.pattern)).toContain('AWS Access Key');
  });

  it('masked preview does not expose full secret', () => {
    const result = scanForSecrets(leakyDir);
    for (const f of result.findings) {
      expect(f.preview).toContain('****');
    }
  });

  it('returns relative file paths', () => {
    const result = scanForSecrets(leakyDir);
    for (const f of result.findings) {
      expect(path.isAbsolute(f.file)).toBe(false);
    }
  });

  it('throws on nonexistent path', () => {
    expect(() => scanForSecrets('/nonexistent/path')).toThrow('Path not found');
  });
});

describe('checkGitignoreCoverage', () => {
  it('clean project: no uncovered sensitive files', () => {
    const issues = checkGitignoreCoverage(fix('clean'));
    const uncovered = issues.filter((i) => !i.coveredByGitignore);
    expect(uncovered).toHaveLength(0);
  });

  it('leaky project: .env is NOT covered by gitignore', () => {
    const issues = checkGitignoreCoverage(leakyDir);
    const uncovered = issues.filter((i) => !i.coveredByGitignore);
    expect(uncovered.length).toBeGreaterThan(0);
    expect(uncovered.some((i) => i.file === '.env')).toBe(true);
  });

  it('suggests gitignore rule for uncovered files', () => {
    const issues = checkGitignoreCoverage(leakyDir);
    const uncovered = issues.filter((i) => !i.coveredByGitignore);
    for (const i of uncovered) {
      expect(i.suggestedRule).toBeTruthy();
    }
  });
});

describe('scanForLogLeaks', () => {
  it('clean project: no log leaks', () => {
    const result = scanForLogLeaks(fix('clean'));
    expect(result.findings).toHaveLength(0);
  });

  it('leaky project: detects console.log(process.env.*)', () => {
    const result = scanForLogLeaks(leakyDir);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some((f) => f.severity === 'high')).toBe(true);
  });

  it('returns line numbers', () => {
    const result = scanForLogLeaks(leakyDir);
    for (const f of result.findings) {
      expect(f.line).toBeGreaterThan(0);
    }
  });
});
