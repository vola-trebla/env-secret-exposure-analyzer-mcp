import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execSync } from 'child_process';
import { scanGitHistory } from '../src/gitHistory.js';

let testDir: string;

function git(cwd: string, ...args: string[]): void {
  execSync(`git ${args.join(' ')}`, {
    cwd,
    stdio: 'pipe',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Test',
      GIT_AUTHOR_EMAIL: 'test@test.com',
      GIT_COMMITTER_NAME: 'Test',
      GIT_COMMITTER_EMAIL: 'test@test.com',
    },
  });
}

function initRepo(subdir: string): string {
  const repoPath = path.join(testDir, subdir);
  fs.mkdirSync(repoPath, { recursive: true });
  git(repoPath, 'init');
  git(repoPath, 'config', 'user.email', 'test@test.com');
  git(repoPath, 'config', 'user.name', 'Test');
  return repoPath;
}

function commitFile(repoPath: string, filename: string, content: string): void {
  fs.writeFileSync(path.join(repoPath, filename), content, 'utf8');
  git(repoPath, 'add', filename);
  git(repoPath, 'commit', '-m', `"add ${filename}"`);
}

beforeAll(() => {
  testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-history-test-'));
});

afterAll(() => {
  fs.rmSync(testDir, { recursive: true, force: true });
});

describe('scanGitHistory', () => {
  it('throws when path does not exist', () => {
    expect(() => scanGitHistory('/nonexistent/path/abc')).toThrow('Path not found');
  });

  it('throws when path is not a git repository', () => {
    const notRepo = path.join(testDir, 'not-a-repo');
    fs.mkdirSync(notRepo, { recursive: true });
    expect(() => scanGitHistory(notRepo)).toThrow('Not a git repository');
  });

  it('returns zero findings for a clean repo', () => {
    const repo = initRepo('clean-repo');
    commitFile(repo, 'README.md', '# Hello\nThis is a clean file.\n');
    const result = scanGitHistory(repo);
    expect(result.commits_scanned).toBe(1);
    expect(result.findings).toHaveLength(0);
    expect(result.summary).toContain('No secrets found');
  });

  it('detects an AWS access key added in a commit', () => {
    const repo = initRepo('aws-key-repo');
    // Construct key programmatically — never commit a realistic-looking key literal
    const awsKey = 'AKIA' + 'B'.repeat(16);
    commitFile(repo, '.env', `AWS_ACCESS_KEY_ID=${awsKey}\n`);
    const result = scanGitHistory(repo);
    expect(result.findings.length).toBeGreaterThanOrEqual(1);
    const finding = result.findings.find((f) => f.pattern === 'AWS Access Key');
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe('critical');
    expect(finding?.file).toBe('.env');
    expect(finding?.rotation_required).toBe(true);
  });

  it('marks a secret as still_present when still in working tree', () => {
    const repo = initRepo('still-present-repo');
    const awsKey = 'AKIA' + 'C'.repeat(16);
    commitFile(repo, 'config.ts', `const key = '${awsKey}';\n`);
    const result = scanGitHistory(repo);
    const finding = result.findings.find((f) => f.pattern === 'AWS Access Key');
    expect(finding?.status).toBe('still_present');
  });

  it('marks a secret as deleted when removed from working tree', () => {
    const repo = initRepo('deleted-secret-repo');
    const awsKey = 'AKIA' + 'D'.repeat(16);
    // First commit — add the secret
    commitFile(repo, 'config.ts', `const key = '${awsKey}';\n`);
    // Second commit — remove it
    commitFile(repo, 'config.ts', `const key = process.env.AWS_KEY;\n`);
    const result = scanGitHistory(repo);
    const finding = result.findings.find((f) => f.pattern === 'AWS Access Key');
    expect(finding?.status).toBe('deleted_in_later_commit');
    expect(finding?.rotation_required).toBe(true);
  });

  it('deduplicates the same secret value across multiple commits', () => {
    const repo = initRepo('dedup-repo');
    const awsKey = 'AKIA' + 'E'.repeat(16);
    commitFile(repo, 'a.ts', `const k = '${awsKey}';\n`);
    // Same value in a second file — different commit, same matched string
    commitFile(repo, 'b.ts', `export const k = '${awsKey}';\n`);
    const result = scanGitHistory(repo);
    const awsFindings = result.findings.filter((f) => f.pattern === 'AWS Access Key');
    // Dedup key is pattern::matched — same key value → only one finding
    expect(awsFindings).toHaveLength(1);
  });

  it('respects .gitleaksignore and skips listed files', () => {
    const repo = initRepo('gitleaksignore-repo');
    const awsKey = 'AKIA' + 'F'.repeat(16);
    fs.writeFileSync(path.join(repo, '.gitleaksignore'), 'secrets.env\n', 'utf8');
    git(repo, 'add', '.gitleaksignore');
    git(repo, 'commit', '-m', '"add gitleaksignore"');
    commitFile(repo, 'secrets.env', `AWS_ACCESS_KEY_ID=${awsKey}\n`);
    const result = scanGitHistory(repo);
    const finding = result.findings.find(
      (f) => f.pattern === 'AWS Access Key' && f.file === 'secrets.env',
    );
    expect(finding).toBeUndefined();
  });

  it('includes commit hash and date in findings', () => {
    const repo = initRepo('commit-meta-repo');
    const awsKey = 'AKIA' + 'G'.repeat(16);
    commitFile(repo, 'app.env', `KEY=${awsKey}\n`);
    const result = scanGitHistory(repo);
    const finding = result.findings.find((f) => f.pattern === 'AWS Access Key');
    expect(finding?.commit_hash).toHaveLength(40);
    expect(finding?.commit_date).toBeTruthy();
  });

  it('returns a summary with finding counts', () => {
    const repo = initRepo('summary-repo');
    const awsKey = 'AKIA' + 'H'.repeat(16);
    commitFile(repo, 'cfg.env', `KEY=${awsKey}\n`);
    const result = scanGitHistory(repo);
    expect(result.summary).toMatch(/\d+ secret\(s\) found/);
  });

  it('includes entropy_score and masked preview in findings', () => {
    const repo = initRepo('entropy-repo');
    const awsKey = 'AKIA' + 'I'.repeat(16);
    commitFile(repo, 'app.env', `AWS_ACCESS_KEY_ID=${awsKey}\n`);
    const result = scanGitHistory(repo);
    const finding = result.findings.find((f) => f.pattern === 'AWS Access Key');
    expect(finding?.entropy_score).toBeTypeOf('number');
    expect(finding?.preview).toMatch(/\*{4}/);
    expect(finding?.preview).not.toBe(awsKey);
  });
});
