# Secrets Spotter

A Chrome extension that scans web pages and network traffic for exposed secrets in real time. Uses a Rust core compiled to WebAssembly for high-performance pattern matching against 30+ secret types.

## Features

- **Real-time scanning** of DOM content, fetch, XHR, WebSocket, and Server-Sent Events
- **30+ detection patterns** — AWS keys, GitHub tokens, Stripe keys, JWTs, private keys, and more
- **False-positive filtering** using Shannon entropy, placeholder detection, and context analysis
- **Visual highlighting** of detected secrets directly on the page
- **Severity levels** — Critical, High, Medium, Low — with color-coded results
- **Fully local** — no data leaves your browser

## How It Works

```text
Page loaded → interceptor.js patches network APIs
           → content.js extracts DOM text
           → Background service worker runs WASM scanner
           → Rust matches against 30+ regex patterns
           → False positives filtered (entropy, placeholders, English words)
           → Findings highlighted on page + shown in popup
```

## Project Structure

```text
secrets-spotter/
├── rust-core/               # Rust WASM core
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs           # WASM entry point (scan_text, pattern_count)
│       ├── detector.rs      # Detection engine + false-positive filtering
│       ├── patterns.rs      # 30+ secret regex patterns
│       ├── types.rs         # SecretKind enum, Severity, SecretFinding
│       ├── filter.rs        # URL/content filtering (skip CDNs, media, etc.)
│       ├── cookies.rs       # Cookie parsing utility
│       └── attributes.rs    # HTML attribute formatting utility
├── extension/               # Chrome extension (Manifest V3)
│   ├── manifest.json
│   ├── background/
│   │   └── service-worker.js
│   ├── content/
│   │   ├── interceptor.js   # Network traffic capture (MAIN world)
│   │   ├── content.js       # DOM scanning + highlighting (ISOLATED world)
│   │   └── content.css
│   ├── popup/
│   │   ├── popup.html
│   │   ├── popup.js
│   │   └── popup.css
│   ├── icons/
│   └── wasm/                # Compiled WASM output (built artifacts)
├── .github/workflows/
│   ├── verify.yml           # CI: secret scanning, lint, WASM build
│   └── release.yml          # Builds + packages extension ZIP on version tags
└── scripts/
    └── build.sh             # Builds Rust → WASM via wasm-pack
```

## Detection Strategy

Secrets Spotter uses a three-tier detection strategy (31 patterns total):

### Known-prefix patterns (22)

Match by a fixed prefix or structure baked into the key itself — highest confidence.

| Service           | Prefix/Structure                |
| ----------------- | ------------------------------- |
| AWS Access Key ID | `AKIA...`                       |
| GitHub PAT        | `ghp_` / `github_pat_`          |
| GitHub OAuth      | `gho_`                          |
| Private Key (PEM) | `-----BEGIN...PRIVATE KEY-----` |
| Password in URL   | `protocol://user:pass@host`     |
| JWT               | `eyJ...eyJ...`                  |
| Slack             | `xox[bpors]-`                   |
| Google API Key    | `AIza`                          |
| Stripe            | `sk_(live\|test)_`              |
| Twilio            | `SK` + 32 hex chars             |
| SendGrid          | `SG.`                           |
| Discord Bot       | `[MN]...(dot-separated)`        |
| Mailgun           | `key-`                          |
| npm               | `npm_`                          |
| PyPI              | `pypi-`                         |
| Shopify           | `shpat_`                        |
| Square            | `sq0atp-`                       |
| Anthropic         | `sk-ant-api03-`                 |
| OpenAI            | `sk-...T3BlbkFJ...`             |
| DigitalOcean      | `dop_v1_`                       |
| Linear            | `lin_api_`                      |
| PostHog           | `ph[cx]_`                       |

### Keyword patterns: service-specific (4)

Match by a service name in the variable name (e.g. `heroku_api_key=...`).

AWS Secret Key, Heroku, Azure Subscription Key, Datadog.

### Keyword patterns: generic dev words (3)

Match by common developer variable names (e.g. `api_key=...`, `authorization: Bearer ...`).

Generic API Key, Bearer Token, Generic API Token.

### Entropy-based fallback (2)

Broad keyword match (`key`, `token`, `secret`, `password`, etc.) with Shannon entropy validation (min 3.5 bits/char) to catch secrets that don't match any known prefix or service keyword.

## Build

Requires [Rust](https://rustup.rs/) and [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/).

```bash
./scripts/build.sh
```

This compiles the Rust core to WASM and outputs it to `extension/wasm/`.

## Install

1. Run the build script
2. Open `chrome://extensions/`
3. Enable **Developer mode**
4. Click **Load unpacked** → select the `extension/` folder

## Usage

Browse any website. The extension icon badge shows the count of secrets found. Click the icon to view findings grouped by severity, with redacted previews and copy-to-clipboard for full values.

## Release

Tagged versions (`v*`) trigger the [release workflow](.github/workflows/release.yml), which builds the WASM core and publishes a packaged extension ZIP as a GitHub release artifact.

## License

Secrets Spotter is licensed under either of

- [MIT License](LICENSE-MIT)
- [Apache License 2.0](LICENSE-APACHE)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in **Secrets Spotter** by you, as defined in the Apache-2.0 license, shall be dually licensed as above, without any additional terms or conditions.
