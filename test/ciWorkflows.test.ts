import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanCiWorkflows } from '../src/ciWorkflows.js';

let testDir: string;

beforeAll(() => {
  testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ci-workflows-test-'));
});

afterAll(() => {
  fs.rmSync(testDir, { recursive: true, force: true });
});

function makeWorkflowDir(subdir: string): string {
  const dir = path.join(testDir, subdir, '.github', 'workflows');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeWorkflow(dir: string, name: string, content: string): void {
  fs.writeFileSync(path.join(dir, name), content, 'utf8');
}

describe('scanCiWorkflows', () => {
  it('throws when repo path does not exist', () => {
    expect(() => scanCiWorkflows('/nonexistent/abc')).toThrow('Path not found');
  });

  it('returns zero findings and zero files when no workflow files exist', () => {
    const emptyDir = path.join(testDir, 'empty-repo');
    fs.mkdirSync(emptyDir, { recursive: true });
    const result = scanCiWorkflows(emptyDir);
    expect(result.files_scanned).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it('detects ${{ secrets.* }} in a multi-line run block as log_leak', () => {
    const wfDir = makeWorkflowDir('secrets-inline');
    writeWorkflow(
      wfDir,
      'deploy.yml',
      [
        'jobs:',
        '  deploy:',
        '    steps:',
        '      - name: Deploy',
        '        run: |',
        '          curl -H "Authorization: ${{ secrets.API_KEY }}" https://api.example.com',
      ].join('\n'),
    );
    const result = scanCiWorkflows(path.join(testDir, 'secrets-inline'));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].risk).toBe('log_leak');
    expect(result.findings[0].pattern_found).toContain('secrets.API_KEY');
    expect(result.findings[0].job).toBe('deploy');
    expect(result.findings[0].step).toBe('Deploy');
  });

  it('detects ${{ secrets.* }} in a single-line run command', () => {
    const wfDir = makeWorkflowDir('secrets-single');
    writeWorkflow(
      wfDir,
      'ci.yml',
      [
        'jobs:',
        '  build:',
        '    steps:',
        '      - name: Publish',
        '        run: npm publish --token=${{ secrets.NPM_TOKEN }}',
      ].join('\n'),
    );
    const result = scanCiWorkflows(path.join(testDir, 'secrets-single'));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].risk).toBe('log_leak');
    expect(result.findings[0].pattern_found).toContain('secrets.NPM_TOKEN');
  });

  it('detects ${{ github.token }} in run step as log_leak', () => {
    const wfDir = makeWorkflowDir('github-token');
    writeWorkflow(
      wfDir,
      'ci.yml',
      [
        'jobs:',
        '  release:',
        '    steps:',
        '      - name: Push tag',
        '        run: git push https://${{ github.token }}@github.com/org/repo.git',
      ].join('\n'),
    );
    const result = scanCiWorkflows(path.join(testDir, 'github-token'));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].risk).toBe('log_leak');
    expect(result.findings[0].pattern_found).toBe('${{ github.token }}');
  });

  it('detects ${{ github.event.pull_request.title }} in run step as injection', () => {
    const wfDir = makeWorkflowDir('pr-injection');
    writeWorkflow(
      wfDir,
      'ci.yml',
      [
        'jobs:',
        '  label:',
        '    steps:',
        '      - name: Label PR',
        '        run: |',
        '          echo "PR title: ${{ github.event.pull_request.title }}"',
      ].join('\n'),
    );
    const result = scanCiWorkflows(path.join(testDir, 'pr-injection'));
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].risk).toBe('injection');
    expect(result.findings[0].pattern_found).toContain('pull_request.title');
  });

  it('does not flag ${{ secrets.* }} used in env: block (safe pattern)', () => {
    const wfDir = makeWorkflowDir('safe-env');
    writeWorkflow(
      wfDir,
      'ci.yml',
      [
        'jobs:',
        '  build:',
        '    steps:',
        '      - name: Deploy',
        '        env:',
        '          API_KEY: ${{ secrets.API_KEY }}',
        '        run: curl -H "Authorization: $API_KEY" https://api.example.com',
      ].join('\n'),
    );
    const result = scanCiWorkflows(path.join(testDir, 'safe-env'));
    expect(result.findings).toHaveLength(0);
  });

  it('returns relative file paths in findings', () => {
    const repoRoot = path.join(testDir, 'rel-paths');
    const wfDir = path.join(repoRoot, '.github', 'workflows');
    fs.mkdirSync(wfDir, { recursive: true });
    writeWorkflow(
      wfDir,
      'ci.yml',
      [
        'jobs:',
        '  build:',
        '    steps:',
        '      - name: Step',
        '        run: echo ${{ secrets.TOKEN }}',
      ].join('\n'),
    );
    const result = scanCiWorkflows(repoRoot);
    expect(result.findings[0].file).not.toContain(repoRoot);
    expect(result.findings[0].file).toContain('.github');
  });

  it('counts scanned workflow files', () => {
    const repoRoot = path.join(testDir, 'multi-files');
    const wfDir = path.join(repoRoot, '.github', 'workflows');
    fs.mkdirSync(wfDir, { recursive: true });
    writeWorkflow(wfDir, 'ci.yml', 'jobs:\n  build:\n    steps:\n      - run: echo hello\n');
    writeWorkflow(wfDir, 'deploy.yml', 'jobs:\n  deploy:\n    steps:\n      - run: echo done\n');
    const result = scanCiWorkflows(repoRoot);
    expect(result.files_scanned).toBe(2);
  });
});
