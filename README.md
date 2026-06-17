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
- **Chrome extension** for real-time scanning of DOM content, network traffic (fetch, XHR, WebSocket, Server-Sent Events), cookies, `localStorage`/`sessionStorage`, the page URL, and external `<script>` bundles
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
- [ ] User-defined allowlisting for known-safe values (beyond the built-in example-key filter)
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
│   │   ├── benches/            # Criterion scan bench + CI regression corpus
│   │   └── src/
│   │       ├── lib.rs          # Public API (scan_text, merge_findings)
│   │       ├── detector.rs     # Detection engine + false-positive filtering
│   │       ├── patterns.rs     # 64 secret regex patterns
│   │       ├── types.rs        # SecretKind, Severity, SecretFinding
│   │       ├── filter.rs       # URL/content filtering (skip CDNs, media)
│   │       ├── cookies.rs      # Cookie parsing utility
│   │       ├── attributes.rs   # HTML attribute formatting
│   │       ├── test_fixtures.rs # Secret-free fixture builders (tests + fuzz seeds)
│   │       └── pattern_tests.rs # Per-pattern positive/negative cases
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
│   ├── icons/                  # Extension icons (16/32/48/128 px)
│   ├── test/                   # vitest suite (happy-dom)
│   └── wasm/                   # Compiled WASM output (build artifacts)
├── fuzz/                       # cargo-fuzz workspace (5 targets) — see fuzz/README.md
├── .github/workflows/          # verify (CI), release, release-please, security, audit, scorecard, fuzz, stale
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
| `--no-ignore`         | Also scan files a directory walk would skip via `.gitignore` / `.ignore` (skipped by default) |
| `--max-size <N>`      | Max file size in bytes (default 2,097,152 = 2 MiB)                             |
| `--reveal`            | Print full unredacted match values (off by default — secrets are masked)       |
| `--no-color`          | Disable colored output                                                         |
| `-q, --quiet`         | Suppress output, exit code only                                                |
| `-h, --help`          | Print help                                                                     |
| `-V, --version`       | Print version                                                                  |

> **Directory scans honor `.gitignore`.** Walking a directory skips files matched by `.gitignore` / `.ignore` / git exclude rules — which often includes `.env`. Pass `--no-ignore` to include them, or name the file directly as a path argument (explicitly-listed files are always scanned).

Exit codes:

| Code | Meaning                            |
| ---- | ---------------------------------- |
| `0`  | No secrets found                   |
| `1`  | Secrets found                      |
| `2`  | Error (bad arguments, I/O failure) |

## 🌐 Chrome extension internals

```text
Page loaded → interceptor.js patches fetch, XHR, WebSocket, SSE, and cookies
            → content.js extracts DOM + structured attrs, localStorage/
              sessionStorage, and the URL; collects external <script src> URLs
            → Text truncated to 2 MB and deduplicated by SHA-256 hash
            → Background service worker runs the WASM scanner — and fetches the
              external <script> bundles itself (free of the page's CSP)
            → Rust matches against RegexSet (+ memchr prefix prefilter)
            → False positives filtered (entropy, placeholders, code identifiers, English words)
            → Findings deduplicated in single O(n) pass, merged across scan batches
            → Findings shown in popup (JWTs include a decoder view)
            → SPA navigations trigger re-scan automatically
```

### External script scanning (`extension/content/content.js`)

External `<script src>` bundles are a primary secret-leak surface — hardcoded keys in config objects, keys used only inside a Worker, etc. — that the network interceptor misses unless the page later *uses* the key in an intercepted call. `content.js` collects their URLs and the **service worker** fetches and scans each one.

Doing the fetch in the worker rather than the page's MAIN world means the page's Content Security Policy (`connect-src`) doesn't apply and there are no console errors. Each unique URL is fetched once (cached), the read is size-capped, and CDN/library hosts are skipped via the shared `should_scan` filter — so only first-party bundles are fetched.

**Default: on.** Set `SCAN_EXTERNAL_RESOURCES = false` in `extension/content/content.js` to disable.

## 🔍 Detection patterns

64 patterns across three tiers, plus keyword-gated legacy formats.

### Known-prefix patterns (50)

Match by a fixed prefix or structure baked into the credential itself — highest confidence.

| Service            | Prefix/Structure                                               | Severity       |
| ------------------ | -------------------------------------------------------------- | -------------- |
| Anthropic          | `sk-ant-(api03\|admin01\|oat01)-`                              | Critical       |
| AWS Access Key ID  | `AKIA...`                                                      | Critical       |
| AWS Temp Key (STS) | `ASIA...`                                                      | Critical       |
| Cloudflare API     | `cfat_` / `cfut_` / `cfk_`                                     | Critical       |
| Cloudflare Origin  | `v1.0-<24hex>-<146hex>`                                        | Critical       |
| Databricks         | `dapi`                                                         | Critical       |
| DigitalOcean       | `dop_v1_`                                                      | Critical       |
| Discord Bot        | `[MNO]...(dot-separated base64)`                               | Critical       |
| Doppler            | `dp.(st\|sa\|ct\|pt\|scim\|audit).`                            | Critical       |
| GCP OAuth          | `ya29.`                                                        | Critical       |
| GitHub App         | `ghu_` / `ghr_` (36 chars)                                     | Critical       |
| GitHub App Install | `ghs_` (legacy 36 chars + new stateless ~520 chars)            | Critical       |
| GitHub OAuth       | `gho_`                                                         | Critical       |
| GitHub PAT         | `ghp_` / `github_pat_`                                         | Critical       |
| GitLab PAT         | `glpat-`                                                       | Critical       |
| Google API Key     | `AIza`                                                         | Medium         |
| Grafana            | `glsa_`                                                        | Critical       |
| Hashicorp Vault    | `hvs.`                                                         | Critical       |
| Hugging Face       | `hf_`                                                          | Critical       |
| JWT                | `eyJ...eyJ...`                                                 | Medium         |
| Linear             | `lin_api_`                                                     | Critical       |
| npm                | `npm_`                                                         | Critical       |
| OpenAI (legacy)    | `sk-...T3BlbkFJ...`                                            | Critical       |
| OpenAI (new)       | `sk-(proj\|svcacct\|admin)-...T3BlbkFJ...`                     | Critical       |
| Password in URL    | `protocol://user:pass@host` (incl. redis, mongodb, amqp, smtp) | Critical       |
| PostHog            | `ph[cxsar]_`                                                   | Low / Critical |
| Private Key (PEM)  | `-----BEGIN...PRIVATE KEY-----`                                | Critical       |
| Private Key (SSH2) | `---- BEGIN SSH2...` / `PuTTY-User-Key-File-`                  | Critical       |
| Pulumi             | `pul-`                                                         | Critical       |
| PyPI               | `pypi-`                                                        | Critical       |
| SendGrid           | `SG.`                                                          | Critical       |
| Shopify            | `shp(at\|ss\|ca\|pa)_`                                         | Critical       |
| Slack              | `xox[bpors]-`                                                  | Critical       |
| Slack App-Level    | `xapp-`                                                        | Critical       |
| Square             | `sq0atp-` / `sq0csp-` / `EAAA`                                 | Critical       |
| Stripe Publishable | `pk_(live\|test)_`                                             | Low            |
| Stripe Restricted  | `rk_(live\|test)_`                                             | High           |
| Stripe Secret      | `sk_(live\|test)_`                                             | Critical       |
| Stripe Webhook     | `whsec_`                                                       | Critical       |
| Supabase Access    | `sbp_`                                                         | Critical       |
| Supabase Secret    | `sb_secret_`                                                   | Critical       |
| Twilio Account SID | `AC` + 32 hex chars                                            | Low            |
| Twilio API Key SID | `SK` + 32 hex chars                                            | High           |
| Vercel             | `vc[pirak]_` (vcp_/vci_/vca_/vcr_/vck_)                        | Critical       |

### Keyword patterns (9)

No fixed prefix on the credential itself — matched by a service or generic variable name sitting next to a high-entropy value (lower confidence than known-prefix, so entropy/format-gated).

| Service / Type         | Trigger keyword(s)                             | Value shape       | Severity       |
| ---------------------- | ---------------------------------------------- | ----------------- | -------------- |
| AWS Secret Access Key  | `aws_secret_access_key` / `secret_key`         | 40 base64 chars   | Critical       |
| Azure Subscription Key | `subscription_key` / `ocp-apim-…`              | 32 hex            | High           |
| Bearer Token           | `authorization:` / `auth:` + `Bearer`          | 20–512 chars      | High           |
| Cloudflare API Token   | `cloudflare…`                                  | 37–40 chars       | Critical       |
| Datadog API Key        | `dd_api_key` / `datadog_api_key`               | 32 hex            | Critical       |
| Generic API Key        | `api_key` / `apikey` / `api_secret`            | 20–64 chars       | Medium         |
| Generic API Token      | `api_token` / `access_token` / `client_secret` | 20–512 (quoted)   | High           |
| Heroku API Key         | `heroku_api_key`                               | UUID              | Critical       |
| Mailgun API Key        | `mailgun…`                                     | `key-` + 32       | High           |

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
- **Character class diversity** — high-entropy values must mix at least 2 of: uppercase, lowercase, digits (symbols / non-ASCII don't count toward the threshold)
- **English word filtering** — ignores lowercase hyphenated phrases like `my-setting`
- **URL / path exclusion** — ignores values that look like URLs or file paths
- **Code identifier rejection** — skips camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case, and dot-notation values

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The recipe for adding a new detection pattern is documented there with a worked example.

Security issues: please use the [private advisory channel](https://github.com/yipjunkai/secrets-spotter/security/advisories/new) — see [SECURITY.md](SECURITY.md).

## 📄 License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE), at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in **Secrets Spotter** by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
