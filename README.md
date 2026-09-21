# 🛡️ SecretScrub

> **Ultra-fast, zero-leak pre-commit secret scanner with Shannon entropy analysis and multi-provider credential detection.**

[![CI](https://github.com/mahdyarmonfared/secret-scrub/actions/workflows/ci.yml/badge.svg)](https://github.com/mahdyarmonfared/secret-scrub/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

Leaking API keys or private keys into public GitHub repositories is an instant security disaster. **SecretScrub** guards your codebase, configurations, and git commits by intercepting credentials **before** they leave your workstation.

---

## ⚡ Key Capabilities

- 🔍 **18+ High-Fidelity Signatures**: Pinpoint AWS IAM keys, OpenAI & Anthropic tokens, GitHub PATs, Stripe live credentials, Slack/Discord webhooks, Database connection strings, and Private Key blocks (`RSA`, `OPENSSH`, `EC`).
- 🎲 **Shannon Entropy Analysis**: Heuristic evaluation ($H(X) \ge 4.2$) flags unstructured high-entropy strings and secret assignments even when specific regex patterns don't match.
- 🪝 **One-Click Pre-Commit Hook**: Install a native `.git/hooks/pre-commit` guard with a single command (`secret-scrub hook install`) to reject leaks at `git commit` time.
- ⚡ **Lightning Fast Git Staged Mode**: `--staged` inspects only staged diff files in milliseconds without crawling irrelevant directories.
- 🎭 **Zero-Leak Redaction**: Discovered secrets are masked in reports (`AKIA12••••••••CDEF`), preventing terminal logs from becoming leakage vectors.
- 🤖 **CI/CD Native**: Standardized exit codes (`0` clean, `1` secrets detected) and machine-readable `--json` output for automated GitHub Actions and GitLab CI gates.

---

## 🏗️ Architecture Overview

```text
 ┌──────────────────────────────────────────────────────────────┐
 │                      Git Pre-Commit / CLI                    │
 └──────────────────────────────┬───────────────────────────────┘
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
        [--staged Mode]                 [Directory Scan]
       git diff --cached             Recursive FS Walker
                 │                             │
                 └──────────────┬──────────────┘
                                ▼
                       Binary File Filter
                    (Zero-byte / Null check)
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
       [Rule Signatures]             [Shannon Entropy]
     18+ Cloud & API Patterns       H(X) >= 4.2 bits/char
                 │                             │
                 └──────────────┬──────────────┘
                                ▼
                      False-Positive Filter
                  (Docs, Samples, Placeholders)
                                │
                 ┌──────────────┴──────────────┐
                 ▼                             ▼
        [Terminal Table]                 [JSON Output]
       Colored CLI Report                 CI/CD Pipeline
```

---

## 🚀 Quick Start

### 1. Run Instantly via `npx` (No installation needed)

```bash
# Scan current repository
npx secret-scrub scan

# Scan only Git staged files (instant pre-commit check)
npx secret-scrub scan --staged
```

### 2. Install Globally

```bash
npm install -g secret-scrub

# Scan any path or directory
secret-scrub scan ./src

# Install git pre-commit hook in your project
secret-scrub hook install
```

### 3. Add to Your Project (`devDependencies`)

```bash
npm install --save-dev secret-scrub
```

Add a scan script to your `package.json`:

```json
{
  "scripts": {
    "security:check": "secret-scrub scan --min-severity high"
  }
}
```

---

## 📖 CLI Usage & Command Reference

```bash
Usage: secret-scrub [command] [options]

Commands:
  scan [targetPath]    Scan files, directories, or staged git files (default: ".")
  hook install         Install SecretScrub pre-commit hook into current Git repo
  hook uninstall       Remove SecretScrub pre-commit hook
  hook run             Manually execute the pre-commit staged verification
  rules                List all supported credential signatures and providers

Options:
  -s, --staged                 Scan only Git staged files
  -e, --entropy                Enable Shannon entropy analysis for unknown tokens
  -i, --ignore <patterns...>   Additional file/dir glob patterns to ignore
  -m, --min-severity <level>   Minimum severity to trigger exit failure (low|medium|high|critical) [default: "high"]
  -j, --json                   Output findings as standardized JSON
  -v, --version                Output the version number
  -h, --help                   Display help for command
```

### Examples

```bash
# Scan whole project with entropy heuristics enabled
secret-scrub scan . --entropy

# Output raw JSON for pipeline consumption
secret-scrub scan . --json > security-audit.json

# Fail only if critical credentials (e.g. AWS, Stripe live keys) are found
secret-scrub scan . --min-severity critical
```

---

## 🛡️ Supported Detection Signatures

| Provider | Credential Signature | Severity |
| :--- | :--- | :---: |
| **AWS** | Access Key ID (`AKIA...`, `ASIA...`) | `CRITICAL` |
| **AWS** | Secret Access Key (`aws_secret_access_key`) | `CRITICAL` |
| **GitHub** | Personal Access Token Classic (`ghp_...`, `gho_...`) | `CRITICAL` |
| **GitHub** | Fine-Grained Personal Access Token (`github_pat_...`) | `CRITICAL` |
| **OpenAI** | Project & Legacy API Keys (`sk-proj-...`, `sk-...`) | `CRITICAL` |
| **Anthropic** | Claude API Keys (`sk-ant-...`) | `CRITICAL` |
| **Stripe** | Live Secret Key (`sk_live_...`, `rk_live_...`) | `CRITICAL` |
| **Stripe** | Publishable Key (`pk_live_...`) | `LOW` |
| **Google** | Cloud & Maps API Key (`AIza...`) | `HIGH` |
| **Slack** | Bot & User OAuth Tokens (`xoxb-...`, `xoxp-...`) | `CRITICAL` |
| **Slack** | Incoming Webhook URL | `HIGH` |
| **Discord** | Bot Token & Webhook URL | `CRITICAL` |
| **Telegram** | BotFather API Token | `HIGH` |
| **PKI / SSH** | Private Key Headers (`RSA`, `OPENSSH`, `EC`, `PGP`) | `CRITICAL` |
| **Database** | Plaintext URI Passwords (`postgres://`, `mongodb://`, etc.) | `CRITICAL` |
| **JWT** | JSON Web Tokens with embedded claims | `MEDIUM` |
| **Generic** | High-entropy assignments to `password`, `secret_key` | `HIGH` |

---

## ⚙️ Configuration (`.secretscrubignore`)

Create a `.secretscrubignore` file in your project root to exclude legitimate test fixtures, mock data, or documentation:

```gitignore
# Exclude test fixtures with dummy credentials
tests/fixtures/mock-credentials.json

# Exclude generated docs
docs/sample-payloads/

# Ignore custom vendor builds
vendor/legacy-bundle.js
```

`secret-scrub` automatically honors your `.gitignore` rules in addition to `.secretscrubignore`.

---

## 🧪 Testing

The test suite uses Node's native test runner with zero third-party testing dependencies:

```bash
npm test
```

---

## 🤝 Contributing

Contributions, new rule signatures, and false-positive filter improvements are welcome! Please check out [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📄 License

[MIT](LICENSE) © 2026 [Mahdyar Monfared](https://github.com/mahdyarmonfared)
