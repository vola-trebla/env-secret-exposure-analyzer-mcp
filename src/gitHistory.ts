import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { matchSecretsInLine, maskSecret, shannonEntropy, isLikelyPlaceholder } from './analyzer.js';
import type { Severity } from './types.js';

export interface GitHistoryFinding {
  commit_hash: string;
  commit_date: string;
  file: string;
  line: number;
  pattern: string;
  severity: Severity;
  preview: string;
  entropy_score: number;
  likely_placeholder: boolean;
  status: 'still_present' | 'deleted_in_later_commit';
  rotation_required: boolean;
}

export interface GitHistoryResult {
  commits_scanned: number;
  findings: GitHistoryFinding[];
  summary: string;
}

function loadGitleaksIgnore(repoPath: string): Set<string> {
  const ignored = new Set<string>();
  const ignorePath = path.join(repoPath, '.gitleaksignore');
  if (!fs.existsSync(ignorePath)) return ignored;
  try {
    for (const line of fs.readFileSync(ignorePath, 'utf8').split('\n')) {
      const t = line.trim();
      if (t && !t.startsWith('#')) ignored.add(t);
    }
  } catch {
    // ignore read errors
  }
  return ignored;
}

export function scanGitHistory(
  repoPath: string,
  lastNCommits = 50,
  sinceDays = 30,
): GitHistoryResult {
  if (!fs.existsSync(repoPath)) throw new Error(`Path not found: ${repoPath}`);

  const gitleaksIgnore = loadGitleaksIgnore(repoPath);

  // Run git log -p to get diff output across recent commits
  const result = spawnSync(
    'git',
    [
      'log',
      '-p',
      `--pretty=format:COMMIT_START %H %ci`,
      `-n`,
      String(lastNCommits),
      `--since=${sinceDays} days ago`,
      '--diff-filter=AM', // only added and modified files
    ],
    { cwd: repoPath, encoding: 'utf8', maxBuffer: 50 * 1024 * 1024 },
  );

  if (result.error) throw new Error(`git error: ${result.error.message}`);
  if (result.status !== 0) {
    const stderr = result.stderr?.trim() ?? '';
    throw new Error(
      stderr.includes('not a git repository')
        ? 'Not a git repository'
        : `git log failed: ${stderr || 'unknown error'}`,
    );
  }

  const output = result.stdout;
  const lines = output.split('\n');

  // Parse git log -p output
  let currentCommit = '';
  let currentDate = '';
  let currentFile = '';
  let currentNewLine = 0; // tracks line number in new file from @@ headers
  const commitsSet = new Set<string>();

  // Raw findings before deduplication — keyed by (pattern+matched) to dedup across commits
  const rawByKey = new Map<
    string,
    {
      commit_hash: string;
      commit_date: string;
      file: string;
      line: number;
      pattern: string;
      severity: Severity;
      matched: string;
    }
  >();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Commit header: COMMIT_START <hash> <date>
    if (line.startsWith('COMMIT_START ')) {
      const parts = line.slice('COMMIT_START '.length).split(' ');
      currentCommit = parts[0];
      currentDate = parts.slice(1).join(' ').trim();
      currentFile = '';
      commitsSet.add(currentCommit);
      continue;
    }

    // File path from diff header: diff --git a/path b/path
    const diffMatch = line.match(/^diff --git a\/.+ b\/(.+)$/);
    if (diffMatch) {
      currentFile = diffMatch[1];
      currentNewLine = 0;
      continue;
    }

    // Also capture from +++ b/path
    const plusPlusMatch = line.match(/^\+\+\+ b\/(.+)$/);
    if (plusPlusMatch) {
      currentFile = plusPlusMatch[1];
      continue;
    }

    // Hunk header: @@ -old,count +new,count @@ — extract new file starting line
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      currentNewLine = parseInt(hunkMatch[1], 10) - 1; // will be incremented on first + line
      continue;
    }

    // Added line (but not the +++ header)
    if (line.startsWith('+') && !line.startsWith('+++')) {
      currentNewLine++;
      const addedContent = line.slice(1);

      // Skip if file is in .gitleaksignore
      if (gitleaksIgnore.has(currentFile)) continue;

      const matches = matchSecretsInLine(addedContent);
      for (const { name, severity, matched } of matches) {
        // Dedup key: same pattern + same matched value = same credential
        const key = `${name}::${matched}`;
        if (!rawByKey.has(key)) {
          rawByKey.set(key, {
            commit_hash: currentCommit,
            commit_date: currentDate,
            file: currentFile,
            line: currentNewLine,
            pattern: name,
            severity,
            matched,
          });
        }
      }
    } else if (line.startsWith(' ') || line.startsWith('-') || line === '') {
      // context or removed line — advance line counter only for context lines
      if (line.startsWith(' ')) currentNewLine++;
    }
  }

  // Import pattern map for still_present check — rebuild from analyzer exports
  // We use matchSecretsInLine on current file content to determine status
  const findings: GitHistoryFinding[] = [];

  for (const raw of rawByKey.values()) {
    const entropy = shannonEntropy(raw.matched);
    const likelyPh = isLikelyPlaceholder('', raw.matched);

    const stillPresent = checkStillPresent(repoPath, raw.file, raw.matched);

    findings.push({
      commit_hash: raw.commit_hash,
      commit_date: raw.commit_date,
      file: raw.file,
      line: raw.line,
      pattern: raw.pattern,
      severity: raw.severity,
      preview: maskSecret(raw.matched),
      entropy_score: entropy,
      likely_placeholder: likelyPh,
      status: stillPresent ? 'still_present' : 'deleted_in_later_commit',
      rotation_required: true, // always: git history is permanent even if deleted
    });
  }

  // Sort by severity then status (still_present first)
  const severityOrder: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => {
    const sv = severityOrder[a.severity] - severityOrder[b.severity];
    if (sv !== 0) return sv;
    return a.status === 'still_present' && b.status !== 'still_present' ? -1 : 1;
  });

  const stillPresentCount = findings.filter((f) => f.status === 'still_present').length;
  const deletedCount = findings.filter((f) => f.status === 'deleted_in_later_commit').length;

  let summary: string;
  if (findings.length === 0) {
    summary = `No secrets found in the last ${commitsSet.size} commit(s). History appears clean.`;
  } else {
    summary =
      `${findings.length} secret(s) found across ${commitsSet.size} scanned commit(s). ` +
      `${stillPresentCount} still present in working tree (rotate immediately). ` +
      `${deletedCount} deleted from working tree but recoverable from git history — rotate and run BFG Repo-Cleaner to purge.`;
  }

  return { commits_scanned: commitsSet.size, findings, summary };
}

function checkStillPresent(repoPath: string, relFile: string, matchedValue: string): boolean {
  const fullPath = path.join(repoPath, relFile);
  if (!fs.existsSync(fullPath)) return false;
  try {
    return fs.readFileSync(fullPath, 'utf8').includes(matchedValue);
  } catch {
    return false;
  }
}
