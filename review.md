# env-secret-exposure-analyzer-mcp — v0.2.0 Review

Reviewed after merging all four v2 roadmap issues (PRs #7–#10).

## Overall Assessment

**Flagship-ready.** Five tools covering the full secret-exposure surface: static scan, gitignore coverage, log leaks, CI workflow injection/log-leak, and git history. All tools tested via stdio JSON-RPC against real data with zero false positives on the sample project.

## What Shipped in v2

| Issue | Tool / Feature                                                        | PR  |
| ----- | --------------------------------------------------------------------- | --- |
| #3    | Expanded secret patterns (MSSQL conn string, Inlined PEM)             | #7  |
| #6    | Shannon entropy scoring + `likely_placeholder` on all findings        | #8  |
| #4    | `scan_ci_workflows` — GH Actions/CircleCI/GitLab injection & log-leak | #9  |
| #5    | `scan_git_history` — git log -p parsing, dedup, still_present status  | #10 |

## Issues Found and Fixed During This Pass

### Patterns missed on first live run (fixed in PR #7)

- Database URLs where the password contains `@` — original regex `:[^@]+@` failed; fixed to `:[^\s"']*@`
- Google OAuth client secret `GOCSPX-` — `\b` before the prefix fails because `-` is not a word boundary char; removed `\b`
- Sentry DSN — original required exactly 32 hex chars; real DSNs vary; changed to `{8,}`

### False positive in `isStillPresent` (fixed before PR #10)

`gitHistory.ts` had both `isStillPresent` (regex-based, unused) and `checkStillPresent` (string-includes, used). Removed `isStillPresent`.

## Verification Run

```
npm run build   ✓
npm test        ✓  44 tests, 3 files
npm run lint    ✓
format:check    ✓
```

Live stdio smoke test — `scan_git_history` on this repo:

- 16 commits scanned
- 10 findings (test fixtures, README examples, pattern definitions in src/analyzer.ts)
- All findings correctly show `still_present` status and masked previews
- Correct JSON-RPC response shape

## Known Acceptable False Positives

- `src/analyzer.ts` itself is scanned and the `Password\s*=` MSSQL regex string matches the `Hardcoded password` pattern
- Test fixtures in `test/` contain intentional fake secrets — expected
- README examples flagged by `Database URL with password` — expected, acceptable for a tool that leans toward recall over precision

These can be suppressed via `.gitleaksignore` in user repos.

## Suggested Future Work

- `--exclude-paths` parameter to skip test dirs and `node_modules` strays
- `likely_placeholder` filter flag (skip findings with `likely_placeholder: true`)
- GitLab CI injection patterns (`$CI_COMMIT_MESSAGE` in `script:`)
