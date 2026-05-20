#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod/v4';
import { scanForSecrets, checkGitignoreCoverage, scanForLogLeaks } from './analyzer.js';
import { scanCiWorkflows } from './ciWorkflows.js';

const server = new McpServer({
  name: 'env-secret-exposure-analyzer-mcp',
  version: '0.1.0',
});

server.tool(
  'scan_for_secrets',
  'Scan a project directory for hardcoded secrets, API keys, tokens, and passwords. Detects patterns like AWS keys, GitHub tokens, Stripe keys, private keys, and generic high-entropy strings. Returns file path, line number, severity, and a masked preview.',
  {
    projectPath: z.string().describe('Absolute path to the project root to scan, e.g. /project'),
    extensions: z
      .array(z.string())
      .optional()
      .describe(
        'File extensions to scan, e.g. [".ts",".js",".env"]. Defaults to common source files.',
      ),
  },
  async (args) => {
    const result = scanForSecrets(args.projectPath);
    const lines = [
      `Secret Scan Results`,
      `  Project:       ${args.projectPath}`,
      `  Files scanned: ${result.scannedFiles}`,
      `  Findings:      ${result.findings.length}`,
      ``,
    ];
    for (const f of result.findings) {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.file}:${f.line}`);
      lines.push(`    Pattern: ${f.pattern}`);
      lines.push(`    Preview: ${f.preview}`);
      lines.push(
        `    Entropy: ${f.entropy_score} bits/char${f.likely_placeholder ? ' (likely placeholder — low confidence)' : ''}`,
      );
    }
    if (result.findings.length === 0) lines.push(`  ✓ No secrets found.`);
    return { content: [{ type: 'text', text: lines.join('\n') }] };
  },
);

server.tool(
  'check_gitignore_coverage',
  'Check whether sensitive files (.env, .env.local, secrets.json, etc.) are properly covered by .gitignore rules. Flags files that contain secrets but could be accidentally committed.',
  {
    projectPath: z.string().describe('Absolute path to the project root to check'),
  },
  async (args) => {
    const issues = checkGitignoreCoverage(args.projectPath);
    const lines = [`Gitignore Coverage Check`, `  Project: ${args.projectPath}`, ``];
    const exposed = issues.filter((i) => !i.coveredByGitignore);
    if (exposed.length === 0) {
      lines.push(`  ✓ All sensitive files are covered by .gitignore.`);
    } else {
      lines.push(`  ✗ ${exposed.length} sensitive file(s) NOT covered by .gitignore:`);
      for (const i of exposed) {
        lines.push(`    ${i.file}`);
        if (i.suggestedRule) lines.push(`    → Add to .gitignore: ${i.suggestedRule}`);
      }
    }
    return { content: [{ type: 'text', text: lines.join('\n') }] };
  },
);

server.tool(
  'scan_for_log_leaks',
  'Scan source files for console.log / logger calls that may print environment variables or secrets at runtime. Catches patterns like console.log(process.env.SECRET) or logger.info({ apiKey }) before they reach production logs.',
  {
    projectPath: z.string().describe('Absolute path to the project root to scan'),
  },
  async (args) => {
    const result = scanForLogLeaks(args.projectPath);
    const lines = [
      `Log Leak Scan`,
      `  Project:       ${args.projectPath}`,
      `  Files scanned: ${result.scannedFiles}`,
      `  Findings:      ${result.findings.length}`,
      ``,
    ];
    for (const f of result.findings) {
      lines.push(`  [${f.severity.toUpperCase()}] ${f.file}:${f.line}`);
      lines.push(`    ${f.expression}`);
    }
    if (result.findings.length === 0) lines.push(`  ✓ No log leaks found.`);
    return { content: [{ type: 'text', text: lines.join('\n') }] };
  },
);

server.tool(
  'scan_ci_workflows',
  'Scans GitHub Actions (.github/workflows/*.yml), CircleCI (.circleci/config.yml), and GitLab CI (.gitlab-ci.yml) workflow files for dangerous secret interpolation patterns. Detects ${{ secrets.* }} and ${{ github.token }} used directly in run: steps (log_leak risk — GitHub Actions logs the expanded plaintext) and ${{ github.event.pull_request.* }} / issue / commit content interpolated in shell commands (injection risk — attacker-controlled input). Returns file, job, step, pattern_found, risk, and recommendation.',
  {
    repo_path: z.string().describe('Absolute path to the repository root to scan'),
  },
  async (args) => {
    try {
      const result = scanCiWorkflows(args.repo_path);
      const lines = [
        `CI Workflow Scan Results`,
        `  Repository:    ${args.repo_path}`,
        `  Files scanned: ${result.files_scanned}`,
        `  Findings:      ${result.findings.length}`,
        ``,
      ];
      for (const f of result.findings) {
        const riskLabel = f.risk === 'injection' ? 'INJECTION' : 'LOG_LEAK';
        lines.push(`  [${riskLabel}] ${f.file}:${f.line}`);
        lines.push(`    Job:     ${f.job}`);
        lines.push(`    Step:    ${f.step}`);
        lines.push(`    Pattern: ${f.pattern_found}`);
        lines.push(`    Fix:     ${f.recommendation}`);
        lines.push('');
      }
      if (result.findings.length === 0)
        lines.push(`  ✓ No dangerous CI secret interpolations found.`);
      return { content: [{ type: 'text', text: lines.join('\n') }] };
    } catch (err) {
      return {
        content: [
          { type: 'text', text: `Error: ${err instanceof Error ? err.message : String(err)}` },
        ],
        isError: true,
      };
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
