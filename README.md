# Secrets Spotter

A CLI tool and Chrome extension that detects exposed secrets in files, directories, stdin, web pages, and network traffic. Uses a shared Rust core with 50 detection patterns and high-performance regex matching.

## Features

- **CLI tool** for scanning files, directories, and stdin — CI/CD ready with JSON and SARIF output
- **Chrome extension** for real-time scanning of DOM content, fetch, XHR, WebSocket, Server-Sent Events, and cookies
- **50 detection patterns** — AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, database connection strings, and more
- **False-positive filtering** using Shannon entropy, placeholder detection, code identifier rejection, and context analysis
- **JWT decoder in popup** — expandable header/payload JSON view for detected JWTs
- **SPA-aware** — re-scans on pushState, replaceState, popstate, and hashchange navigations
- **Fully local** — no data leaves your machine or browser

## CLI Usage

```bash
# Scan files
secrets-spotter src/ .env config/

# Scan from stdin
cat credentials.json | secrets-spotter

# JSON output (for scripting / CI)
secrets-spotter --format json .

# SARIF output (for GitHub Code Scanning)
secrets-spotter --format sarif . > results.sarif

# Filter by severity
secrets-spotter --severity high .

# Only scan specific file types
secrets-spotter --glob "*.js,*.env,*.yaml" .

# Quiet mode — exit code only
secrets-spotter --quiet .
```

### CLI Options

```
secrets-spotter [OPTIONS] [PATH...]

ARGUMENTS:
  [PATH...]              Files or directories to scan (reads from stdin if omitted)

OPTIONS:
  -f, --format <FMT>     Output format: text (default), json, sarif
  -s, --severity <LVL>   Minimum severity: critical, high, medium, low (default: low)
  -g, --glob <PATTERN>   Only scan files matching glob (e.g. "*.js,*.env")
      --max-size <N>     Max file size in bytes (default: 2097152)
      --no-color         Disable colored output
  -q, --quiet            Suppress output, exit code only
  -h, --help             Print help
  -V, --version          Print version
```

### Exit Codes

| Code | Meaning                            |
| ---- | ---------------------------------- |
| `0`  | No secrets found                   |
| `1`  | Secrets found                      |
| `2`  | Error (bad arguments, I/O failure) |

## Chrome Extension

### How It Works

```text
Page loaded → interceptor.js patches fetch, XHR, WebSocket, SSE, and cookies
            → content.js extracts DOM text + structured attributes
            → Text truncated to 2 MB and deduplicated by SHA-256 hash
            → Background service worker runs WASM scanner
            → Rust matches against known-prefix and keyword patterns (RegexSet + memchr pre-filter)
            → False positives filtered (entropy, placeholders, code identifiers, English words)
            → Findings deduplicated in single O(n) pass, merged across scan batches
            → Findings shown in popup (JWTs include a decoder view)
            → SPA navigations trigger re-scan automatically
```

### Extension Install

1. Run `./scripts/build.sh`
2. Open `chrome://extensions/`
3. Enable **Developer mode**
4. Click **Load unpacked** → select the `extension/` folder

Browse any website. The extension icon badge shows the count of secrets found. Click the icon to view findings grouped by severity, with redacted previews and copy-to-clipboard for full values. JWT findings include an expandable decoder with header and payload JSON.

### Configuration

#### `SCAN_EXTERNAL_RESOURCES` (interceptor.js)

Controls whether the extension re-fetches external `<script src>` and `<link stylesheet>` files to scan their contents. **Default: `false`.**

This is disabled by default because the interceptor runs in the page's MAIN world, where fetches are subject to the page's Content Security Policy (CSP). Sites with strict `connect-src` directives will block these fetches and log console errors. Most secrets in external scripts are already caught indirectly when the script uses them in fetch/XHR calls, which the interceptor captures.

To enable, set `SCAN_EXTERNAL_RESOURCES = true` in `extension/content/interceptor.js`.

## Project Structure

```text
secrets-spotter/
├── Cargo.toml                  # Workspace root
├── crates/
│   ├── core/                   # Shared detection library (no WASM deps)
│   │   └── src/
│   │       ├── lib.rs          # Public API (scan_text, merge_findings)
│   │       ├── detector.rs     # Detection engine + false-positive filtering
│   │       ├── patterns.rs     # 50 secret regex patterns
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
│   ├── background/
│   │   └── service-worker.js
│   ├── content/
│   │   ├── interceptor.js      # Network traffic capture (MAIN world)
│   │   └── content.js          # DOM scanning (ISOLATED world)
│   ├── popup/
│   └── wasm/                   # Compiled WASM output (build artifacts)
├── scripts/
│   ├── build.sh                # Build CLI + WASM
│   └── clean.sh                # Clean all build artifacts
```

## Detection Strategy

Secrets Spotter uses a three-tier detection strategy (50 patterns total):

### Known-prefix patterns (41)

Match by a fixed prefix or structure baked into the key itself — highest confidence.

| Service            | Prefix/Structure                                               |
| ------------------ | -------------------------------------------------------------- |
| AWS Access Key ID  | `AKIA...`                                                      |
| AWS Temp Key (STS) | `ASIA...`                                                      |
| GitHub PAT         | `ghp_` / `github_pat_`                                         |
| GitHub OAuth       | `gho_`                                                         |
| GitHub App         | `ghu_` / `ghs_` / `ghr_`                                       |
| Private Key (PEM)  | `-----BEGIN...PRIVATE KEY-----`                                |
| Password in URL    | `protocol://user:pass@host` (incl. redis, mongodb, amqp, smtp) |
| JWT                | `eyJ...eyJ...`                                                 |
| Slack              | `xox[bpors]-`                                                  |
| Slack App-Level    | `xapp-`                                                        |
| Google API Key     | `AIza`                                                         |
| Stripe Secret      | `sk_(live\|test)_`                                             |
| Stripe Publishable | `pk_(live\|test)_`                                             |
| Stripe Restricted  | `rk_(live\|test)_`                                             |
| Stripe Webhook     | `whsec_`                                                       |
| Twilio             | `SK` + 32 hex chars                                            |
| SendGrid           | `SG.`                                                          |
| Discord Bot        | `[MN]...(dot-separated base64)`                                |
| Mailgun            | `key-`                                                         |
| npm                | `npm_`                                                         |
| PyPI               | `pypi-`                                                        |
| Shopify            | `shp(at\|ss\|ca\|pa)_`                                         |
| Square             | `sq0atp-`                                                      |
| Anthropic          | `sk-ant-api03-`                                                |
| OpenAI (legacy)    | `sk-...T3BlbkFJ...`                                            |
| OpenAI (new)       | `sk-proj-` / `sk-svcacct-`                                     |
| DigitalOcean       | `dop_v1_`                                                      |
| Linear             | `lin_api_`                                                     |
| PostHog            | `ph[cx]_`                                                      |
| GitLab PAT         | `glpat-`                                                       |
| Cloudflare API     | `cf_`                                                          |
| Supabase Service   | `sbp_`                                                         |
| GCP OAuth          | `ya29.`                                                        |
| Hashicorp Vault    | `hvs.`                                                         |
| Doppler            | `dp.(st\|sa\|ct).`                                             |
| Vercel             | `vercel_`                                                      |
| Databricks         | `dapi`                                                         |
| Grafana            | `glsa_`                                                        |
| Pulumi             | `pul-`                                                         |
| Hugging Face       | `hf_`                                                          |

### Keyword patterns: service-specific (4)

Match by a service name in the variable name (e.g. `heroku_api_key=...`).

AWS Secret Key, Heroku, Azure Subscription Key, Datadog.

### Keyword patterns: generic dev words (3)

Match by common developer variable names (e.g. `api_key=...`, `authorization: Bearer ...`).

Generic API Key, Bearer Token, Generic API Token.

### Entropy-based fallback (2)

Broad keyword match (`key`, `token`, `secret`, `password`, etc.) with Shannon entropy validation (min 3.5 bits/char) to catch secrets that don't match any known prefix or service keyword.

### False-positive filtering

- **Placeholder detection** — skips `YOUR_KEY`, `example`, `test`, `TODO`, etc.
- **Shannon entropy** — rejects low-entropy values for entropy-gated patterns (UTF-8-aware, counts chars not bytes)
- **Character class diversity** — requires mix of uppercase, lowercase, digits, or symbols/non-ASCII
- **English word filtering** — ignores lowercase hyphenated words like `my-setting`
- **URL / path exclusion** — ignores values that look like URLs or file paths
- **Code identifier rejection** — skips camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case, and dot-notation values

## Development

### Prerequisites

- [Rust](https://rustup.rs/)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/) (for extension builds)

### Build

```bash
# Build everything (CLI + WASM extension)
./scripts/build.sh

# Build CLI only
cargo build --release -p secrets-spotter

# Build WASM only
wasm-pack build crates/wasm --target web --out-dir ../../extension/wasm --release
```

## License

Secrets Spotter is licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in **Secrets Spotter** by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
