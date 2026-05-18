# 🔐 env-secret-exposure-analyzer-mcp

[![npm](https://img.shields.io/npm/v/env-secret-exposure-analyzer-mcp)](https://www.npmjs.com/package/env-secret-exposure-analyzer-mcp)
[![CI](https://github.com/vola-trebla/env-secret-exposure-analyzer-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/vola-trebla/env-secret-exposure-analyzer-mcp/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Your AI agent is one debug session away from leaking your secrets.**

MCP server that scans your project for secret exposure risks — hardcoded API keys, unprotected `.env` files, and `console.log` calls that print credentials at runtime. Before your agent accidentally reads them out loud.

---

## 🤔 The problem

You ask your AI agent to debug a config issue. It reads `src/config.ts`. Inside:

```typescript
console.log('Config loaded:', JSON.stringify(config));
console.log(process.env.DATABASE_PASSWORD);
```

The agent now has your database password in its context. It might log it, include it in a summary, or pass it to another tool. And your `.env` isn't in `.gitignore`, so the next `git push` will do the rest.

None of this requires the agent to be malicious. It just needs to be helpful.

`env-secret-exposure-analyzer-mcp` catches this before it happens. 🔐

---

## 🛠️ Tools

### `scan_for_secrets`

Scans source files, config files, and `.env` files for 20+ secret patterns. Returns file path, line number, severity, and a masked preview — never the full value.

**Detects:**

- AWS access keys + secret keys
- GitHub tokens (`ghp_`, `gho_`, `ghs_`)
- Stripe secret/publishable keys + webhook secrets (`whsec_`)
- Anthropic, OpenAI API keys
- SendGrid (`SG.xxx`), Twilio auth token + account SID
- Google API keys + OAuth client secrets (`GOCSPX-`)
- Slack tokens (`xox*`)
- Private keys (`-----BEGIN ... PRIVATE KEY-----`)
- Database URLs with embedded credentials (`postgres://user:pass@host`)
- JWT secrets, session secrets, encryption keys
- Sentry DSN, Datadog API key
- Generic hardcoded passwords, secrets, tokens

```
Secret Scan Results
  Project:       /project
  Files scanned: 24
  Findings:      5

  [CRITICAL] .env:3 — AWS Access Key
    Preview: AKIA****MPLE
  [CRITICAL] .env:7 — Database URL with password
    Preview: post****sswd
  [CRITICAL] src/auth.ts:12 — Hardcoded JWT secret
    Preview: my-s****ecret
  [HIGH] .env:14 — Hardcoded session secret
    Preview: sess****key!
  [MEDIUM] .env:28 — Sentry DSN
    Preview: http****7890
```

### `check_gitignore_coverage`

Checks whether sensitive files (`.env`, `.env.local`, `secrets.json`, private keys, certificates) are covered by `.gitignore`. Flags files that could be accidentally committed.

```
Gitignore Coverage Check
  Project: /project

  ✗ .env → Add to .gitignore: .env
  ✗ .env.local → Add to .gitignore: .env.local
  ✓ secrets.json
```

### `scan_for_log_leaks`

Scans source files for `console.log` / `logger` calls that print `process.env` variables or objects with secret-sounding names at runtime. Catches the most common "it's just a debug line" mistakes.

```
Log Leak Scan
  Project:       /project
  Files scanned: 18
  Findings:      3

  [CRITICAL] src/config.ts:8
    console.log("Config loaded:", JSON.stringify(config));
  [HIGH] src/server.ts:42
    console.log(process.env.AWS_SECRET_ACCESS_KEY);
  [HIGH] src/db.ts:15
    logger.info({ password: dbConfig.password });
```

---

## 🧪 What it looks like in practice

A realistic `.env` with 20 secrets — database URLs, AWS, Stripe, Twilio, SendGrid, Google OAuth, Sentry, JWT secrets, encryption keys. Before this MCP: an AI agent reads the file, has no idea what's sensitive, and proceeds to use those values in generated code or responses.

After one `scan_for_secrets` call: **16 findings**, all categorized by severity, all previews masked. The agent knows exactly what's dangerous before it touches anything.

---

## ⚡ Setup

```json
{
  "mcpServers": {
    "secret-scanner": {
      "command": "npx",
      "args": ["-y", "env-secret-exposure-analyzer-mcp"]
    }
  }
}
```

---

## 🚀 Usage

> "Scan this project for any secrets or API keys that might be exposed. Check if .env files are in .gitignore, and look for any console.log calls that might be leaking credentials."

The agent runs all three tools in sequence and reports a full picture: what's hardcoded, what's not protected, what's being logged.

Works great alongside:

- [tsconfig-inheritance-flattener-mcp](https://www.npmjs.com/package/tsconfig-inheritance-flattener-mcp) — for TypeScript config analysis
- [release-readiness-triage-mcp](https://www.npmjs.com/package/release-readiness-triage-mcp) — for CI triage before release
- [ast-impact-mapper-mcp](https://www.npmjs.com/package/ast-impact-mapper-mcp) — for code→test correlation

---

## 📦 Links

- **npm:** [npmjs.com/package/env-secret-exposure-analyzer-mcp](https://www.npmjs.com/package/env-secret-exposure-analyzer-mcp)
- **GitHub:** [github.com/vola-trebla/env-secret-exposure-analyzer-mcp](https://github.com/vola-trebla/env-secret-exposure-analyzer-mcp)

## License

MIT
