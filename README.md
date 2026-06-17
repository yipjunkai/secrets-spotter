# Secrets Spotter

[![CI](https://github.com/yipjunkai/secrets-spotter/actions/workflows/verify.yml/badge.svg)](https://github.com/yipjunkai/secrets-spotter/actions/workflows/verify.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/yipjunkai/secrets-spotter/badge)](https://securityscorecards.dev/viewer/?uri=github.com/yipjunkai/secrets-spotter)
[![Release](https://img.shields.io/github/v/release/yipjunkai/secrets-spotter)](https://github.com/yipjunkai/secrets-spotter/releases/latest)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#-license)

**A CLI tool and Chrome extension that detects exposed API keys, tokens, and other secrets in files, stdin, web pages, and network traffic.** Rust core with 64 detection patterns. Fully local — no data leaves your machine or browser.

```text
$ secrets-spotter src/ .env
[Critical] AWS Access Key ID
  File: src/aws.js:42
  Match: AKIA****EXAMPLE
[Medium] Google API Key
  File: .env:8
  Match: AIza****Z9aA
```

## ⚡ Approach

Three-tier detection pipeline tuned for speed and precision:

1. **Known-prefix patterns (50)** — fixed prefixes baked into the credential format itself (`AKIA`, `ghp_`, `sk-ant-`, `eyJ...eyJ`). Highest confidence, lowest false-positive rate.
2. **Keyword patterns (12)** — service or generic variable names paired with high-entropy values (`aws_secret_access_key=...`, `authorization: Bearer ...`).
3. **Entropy fallback (2)** — broad keyword match (`key`, `token`, `secret`) with Shannon-entropy validation (≥3.5 bits/char) to catch novel formats.

A `RegexSet` + `memchr` pre-filter on prefix substrings means non-matching input is rejected without running any regex. False-positive filtering rejects placeholders, code identifiers (camelCase / snake_case / kebab-case), URLs, file paths, and low-diversity character sets before reporting.

## 📦 Install

### From GitHub Releases

Pre-built CLI binaries for Linux x86_64, macOS (Intel + Apple Silicon), and Windows x86_64 are published with each tag:

```bash
# Replace TARGET with your platform (x86_64-unknown-linux-gnu, aarch64-apple-darwin, ...)
curl -L https://github.com/yipjunkai/secrets-spotter/releases/latest/download/secrets-spotter-v1.2.0-${TARGET}.tar.gz | tar xz # x-release-please-version
```

### From source

```bash
git clone https://github.com/yipjunkai/secrets-spotter
cd secrets-spotter
just build
# CLI binary at target/release/secrets-spotter
```

Requires [Rust](https://rustup.rs/), [`just`](https://github.com/casey/just), and [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/) (extension only).

### Chrome extension

1. `just build` (builds the WASM into `extension/wasm/`)
2. Open `chrome://extensions/` → enable **Developer mode** → **Load unpacked** → select the `extension/` folder

## 🚀 Quick start

```bash
# Scan files and directories
secrets-spotter src/ .env config/

# Scan from stdin
cat credentials.json | secrets-spotter

# JSON output for scripting / CI
secrets-spotter --format json .

# SARIF output for GitHub Code Scanning
secrets-spotter --format sarif . > results.sarif

# Filter by severity
secrets-spotter --severity high .

# Glob filter
secrets-spotter --glob "*.js,*.env,*.yaml" .

# Reveal full unredacted values (use with care)
secrets-spotter --reveal .

# Quiet mode — exit code only
secrets-spotter --quiet .
```

Once the Chrome extension is loaded, browse any website. The icon badge shows the count of Critical/High findings. Click the icon for a grouped breakdown with redacted previews, copy-to-clipboard, and an expandable JWT decoder.

## ✨ Features

- **CLI tool** for scanning files, directories, and stdin — CI/CD ready with JSON and SARIF output
- **Chrome extension** for real-time scanning of DOM content, fetch, XHR, WebSocket, Server-Sent Events, and cookies
- **64 detection patterns** — AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, database connection strings, and 58 more (including keyword-gated legacy formats)
- **False-positive filtering** — Shannon entropy, placeholder detection, code-identifier rejection, URL/path exclusion
- **JWT decoder in popup** — expandable header / payload JSON view for detected JWTs
- **SPA-aware** — extension re-scans on `pushState`, `replaceState`, `popstate`, and `hashchange` navigations
- **Fully local** — no data leaves your machine or browser; no telemetry, no cloud calls

## 🗺️ Coming soon

- [ ] Chrome Web Store listing
- [ ] Firefox support (Manifest V3 port)
- [ ] User-defined rules via options page
- [ ] Per-site disable toggle and severity filtering in popup
- [ ] Allowlisting for known-safe values (public keys, test fixtures)
- [ ] Dark mode in popup

## 🤔 Why Secrets Spotter exists

Existing secret scanners optimize for the **server-side audit** workflow: scan a git history, scan a CI build, scan an S3 bucket. They're heavy, slow, and operate on already-committed code.

Secrets Spotter optimizes for two complementary workflows the existing tools miss:

- **Local pre-flight** — a CLI fast enough to run on every save (`secrets-spotter src/` in tens of milliseconds), not just on commit. Same Rust regex engine as the extension, no Python / Node startup tax.
- **Live browser scanning** — the Chrome extension surfaces secrets as you visit sites. Find your own keys leaking from someone else's frontend, find production tokens accidentally shipped in client JS, audit a vendor's web app in real time.

Both surfaces are fully local — nothing about your code, network traffic, or browsing leaves the machine.

## 📁 Project structure

```text
secrets-spotter/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── core/                   # Shared detection library (no WASM deps)
│   │   └── src/
│   │       ├── lib.rs          # Public API (scan_text, merge_findings)
│   │       ├── detector.rs     # Detection engine + false-positive filtering
│   │       ├── patterns.rs     # 64 secret regex patterns
│   │       ├── types.rs        # SecretKind, Severity, SecretFinding
│   │       ├── filter.rs       # URL/content filtering (skip CDNs, media)
│   │       ├── cookies.rs      # Cookie parsing utility
│   │       └── attributes.rs   # HTML attribute formatting
│   ├── cli/                    # CLI binary
│   │   └── src/
│   │       ├── main.rs         # Entry point + arg parsing
│   │       ├── scan.rs         # File/dir/stdin scanning
│   │       └── output.rs       # Text, JSON, SARIF formatters
│   └── wasm/                   # WASM bindings for extension
│       └── src/
│           └── lib.rs          # Thin #[wasm_bindgen] wrappers
├── extension/                  # Chrome extension (Manifest V3)
│   ├── manifest.json
│   ├── background/service-worker.js
│   ├── content/
│   │   ├── interceptor.js      # Network traffic capture (MAIN world)
│   │   └── content.js          # DOM scanning (ISOLATED world)
│   ├── popup/
│   └── wasm/                   # Compiled WASM output (build artifacts)
├── .github/workflows/          # ci (verify), release, security, stale
└── justfile                    # Build, test, lint, clean recipes
```

## 💻 CLI reference

```text
secrets-spotter [OPTIONS] [PATH...]
```

| Option                | Description                                                                    |
| --------------------- | ------------------------------------------------------------------------------ |
| `[PATH...]`           | Files or directories to scan. Reads stdin if omitted.                          |
| `-f, --format <FMT>`  | `text` (default), `json`, `sarif`                                              |
| `-s, --severity <L>`  | Minimum severity: `critical`, `high`, `medium`, `low` (default)                |
| `-g, --glob <P>`      | Only scan files matching glob (comma-separated, e.g. `"*.js,*.env"`)           |
| `--max-size <N>`      | Max file size in bytes (default 2,097,152 = 2 MiB)                             |
| `--reveal`            | Print full unredacted match values (off by default — secrets are masked)       |
| `--no-color`          | Disable colored output                                                         |
| `-q, --quiet`         | Suppress output, exit code only                                                |
| `-h, --help`          | Print help                                                                     |
| `-V, --version`       | Print version                                                                  |

Exit codes:

| Code | Meaning                            |
| ---- | ---------------------------------- |
| `0`  | No secrets found                   |
| `1`  | Secrets found                      |
| `2`  | Error (bad arguments, I/O failure) |

## 🌐 Chrome extension internals

```text
Page loaded → interceptor.js patches fetch, XHR, WebSocket, SSE, and cookies
            → content.js extracts DOM text + structured attributes
            → Text truncated to 2 MB and deduplicated by SHA-256 hash
            → Background service worker runs the WASM scanner
            → Rust matches against RegexSet (+ memchr prefix prefilter)
            → False positives filtered (entropy, placeholders, code identifiers, English words)
            → Findings deduplicated in single O(n) pass, merged across scan batches
            → Findings shown in popup (JWTs include a decoder view)
            → SPA navigations trigger re-scan automatically
```

### `SCAN_EXTERNAL_RESOURCES` (`extension/content/interceptor.js`)

Controls whether the extension re-fetches external `<script src>` and `<link stylesheet>` files to scan their contents. **Default: `false`.**

Disabled by default because the interceptor runs in the page's MAIN world, where fetches are subject to the page's Content Security Policy. Sites with strict `connect-src` directives will block these fetches and log console errors. Most secrets in external scripts are caught indirectly when the script *uses* them in fetch/XHR calls — which the interceptor captures regardless.

To enable: set `SCAN_EXTERNAL_RESOURCES = true` in `extension/content/interceptor.js`.

## 🔍 Detection patterns

64 patterns across three tiers, plus keyword-gated legacy formats.

### Known-prefix patterns (50)

Match by a fixed prefix or structure baked into the credential itself — highest confidence.

| Service            | Prefix/Structure                                               |
| ------------------ | -------------------------------------------------------------- |
| AWS Access Key ID  | `AKIA...`                                                      |
| AWS Temp Key (STS) | `ASIA...`                                                      |
| GitHub PAT         | `ghp_` / `github_pat_`                                         |
| GitHub OAuth       | `gho_`                                                         |
| GitHub App         | `ghu_` / `ghr_` (36 chars)                                     |
| GitHub App Install | `ghs_` (legacy 36 chars + new stateless ~520 chars)            |
| Private Key (PEM)  | `-----BEGIN...PRIVATE KEY-----`                                |
| Private Key (SSH2) | `---- BEGIN SSH2...` / `PuTTY-User-Key-File-`                  |
| Password in URL    | `protocol://user:pass@host` (incl. redis, mongodb, amqp, smtp) |
| JWT                | `eyJ...eyJ...`                                                 |
| Slack              | `xox[bpors]-`                                                  |
| Slack App-Level    | `xapp-`                                                        |
| Google API Key     | `AIza`                                                         |
| Stripe Secret      | `sk_(live\|test)_`                                             |
| Stripe Publishable | `pk_(live\|test)_`                                             |
| Stripe Restricted  | `rk_(live\|test)_`                                             |
| Stripe Webhook     | `whsec_`                                                       |
| Twilio API Key SID | `SK` + 32 hex chars                                            |
| Twilio Account SID | `AC` + 32 hex chars                                            |
| SendGrid           | `SG.`                                                          |
| Discord Bot        | `[MNO]...(dot-separated base64)`                               |
| npm                | `npm_`                                                         |
| PyPI               | `pypi-`                                                        |
| Shopify            | `shp(at\|ss\|ca\|pa)_`                                         |
| Square             | `sq0atp-` / `sq0csp-` / `EAAA`                                 |
| Anthropic          | `sk-ant-(api03\|admin01\|oat01)-`                              |
| OpenAI (legacy)    | `sk-...T3BlbkFJ...`                                            |
| OpenAI (new)       | `sk-(proj\|svcacct\|admin)-...T3BlbkFJ...`                     |
| DigitalOcean       | `dop_v1_`                                                      |
| Linear             | `lin_api_`                                                     |
| PostHog            | `ph[cxsar]_`                                                   |
| GitLab PAT         | `glpat-`                                                       |
| Cloudflare API     | `cfat_` / `cfut_` / `cfk_`                                     |
| Cloudflare Origin  | `v1.0-<24hex>-<146hex>`                                        |
| Supabase Access    | `sbp_`                                                         |
| Supabase Secret    | `sb_secret_`                                                   |
| GCP OAuth          | `ya29.`                                                        |
| Hashicorp Vault    | `hvs.`                                                         |
| Doppler            | `dp.(st\|sa\|ct).`                                             |
| Vercel             | `vc[pirak]_` (vcp_/vci_/vca_/vcr_/vck_)                        |
| Databricks         | `dapi`                                                         |
| Grafana            | `glsa_`                                                        |
| Pulumi             | `pul-`                                                         |
| Hugging Face       | `hf_`                                                          |

### Keyword: service-specific (6)

Match by a service name in the variable name (e.g. `heroku_api_key=...`).

AWS Secret Key, Heroku, Azure Subscription Key, Datadog, Cloudflare API Token, Mailgun.

### Keyword: generic dev words (3)

Match by common developer variable names (`api_key=...`, `authorization: Bearer ...`).

Generic API Key, Bearer Token, Generic API Token.

### Entropy-based fallback (2)

Broad keyword match (`key`, `token`, `secret`, `password`) with Shannon entropy validation (≥3.5 bits/char) to catch credentials that don't match any known prefix or service keyword.

### Legacy formats (3)

Older token formats that are no longer issued but whose existing tokens may still be valid. Keyword-gated to avoid false positives on the (often generic) old shapes.

- **GitHub** — pre-2021 40-char hex PAT / OAuth token (gated on a `github`/`gh` token keyword; a bare 40-hex is a SHA-1)
- **HashiCorp Vault** — pre-1.10 `s.` service token (gated on a `vault` keyword)
- **Vercel** — pre-2026 24-char token (gated on a `vercel` keyword)

OpenAI's legacy `sk-…T3BlbkFJ…` and Square's `sq0atp-` are also labeled `(legacy)` in findings.

### False-positive filtering

- **Placeholder detection** — skips `YOUR_KEY`, `example`, `test`, `TODO`, and similar
- **Example-key allowlist** — skips published non-functional sample credentials (AWS's `AKIA...EXAMPLE`, Stripe's documentation test keys) across all pattern tiers, including known-prefix
- **Template / interpolation rejection** — skips `{{...}}`, `${...}`, `<...>`, `%...%`, and `name()` call wrappers
- **Shannon entropy** — rejects low-entropy values for entropy-gated patterns (UTF-8-aware, counts chars not bytes)
- **Character class diversity** — requires a mix of upper, lower, digits, or symbols / non-ASCII
- **English word filtering** — ignores lowercase hyphenated phrases like `my-setting`
- **URL / path exclusion** — ignores values that look like URLs or file paths
- **Code identifier rejection** — skips camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case, and dot-notation values

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The recipe for adding a new detection pattern is documented there with a worked example.

Security issues: please use the [private advisory channel](https://github.com/yipjunkai/secrets-spotter/security/advisories/new) — see [SECURITY.md](SECURITY.md).

## 📄 License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in **Secrets Spotter** by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
