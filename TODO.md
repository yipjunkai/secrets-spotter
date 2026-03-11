# TODO

## Detection

- [ ] Handle CORS failures on external script fetching (fall back without credentials)
- [ ] Support scanning inside `<iframe>` content
- [ ] More known-prefix patterns:
  - [ ] GitLab PAT — `glpat-[A-Za-z0-9_-]{20}`
  - [ ] Cloudflare API Token — `cf_[A-Za-z0-9_-]{37}`
  - [ ] Supabase Service Key — `sbp_[a-f0-9]{40}`
  - [ ] GCP OAuth Access Token — `ya29.[A-Za-z0-9_-]{50,}`
  - [ ] Hashicorp Vault Token — `hvs.[A-Za-z0-9_-]{24,}`
  - [ ] Doppler Token — `dp\.(st|sa|ct)\.[A-Za-z0-9_-]{40,}`
  - [ ] Vercel Token — `vercel_[A-Za-z0-9_-]{24,}`
  - [ ] Database connection strings (postgres://, mongodb://, redis://)
  - [ ] Databricks Token — `dapi[0-9a-f]{32}`
  - [ ] Grafana API Key / Service Account — `glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}`
  - [ ] Confluent Cloud API Key — prefix-based
  - [ ] Pulumi Access Token — `pul-[A-Za-z0-9]{40}`
  - [ ] Firebase Service Account — `AIza[A-Za-z0-9_-]{33}`
- [ ] Custom user-defined rules via options page
- [ ] **Bearer token minimum length too restrictive** — `patterns.rs:269` requires 20+ chars for bearer values; many valid tokens are shorter. Consider lowering to 10+

## False Positives

- [ ] Reduce high-entropy false positives (CSS class hashes, webpack chunk IDs) — add minimum length or context check
- [ ] Add allowlisting for known-safe values (public keys, test fixtures)
- [ ] Avoid matching generic patterns inside URL paths vs. query param leaks
- [ ] **Hardcoded entropy threshold** — `detector.rs:102` uses `3.5` without documentation of why; different secret types may benefit from different thresholds
- [x] **Filter out developer-like variable names** — `detector.rs` `CODE_IDENTIFIER` regex rejects camelCase, PascalCase, snake_case, SCREAMING_SNAKE, kebab-case, and dot-notation values (with optional `_`/`__` prefixes/suffixes) across all 5 generic SecretKinds

## Performance

- [ ] **O(n^2) dedup via `Vec::remove`** — `detector.rs:145-157` shifts all elements on each removal. Use `retain()` for a single-pass approach
- [ ] **Needless `String` alloc before false-positive check** — `detector.rs:38` move `to_string()` after `is_false_positive` to skip allocation for discarded matches
- [ ] **Triple char-class iteration** — `detector.rs:103-106` three separate `.chars().any()` loops can be folded into one pass
- [ ] **Hashing can exceed scan cap** — `content.js` hashes full text even though scan is capped at 2MB; hash the truncated text to cut CPU on huge pages
- [ ] **Mutation batches can blow past 2MB** — `content.js` concatenates added node text without a cap; clamp combined text before hashing/sending
- [ ] **`scannedHashes` grows unbounded** — `content.js:8` on long-lived SPAs the Set grows forever. Add a size cap
- [ ] **`pendingNodes` holds detached DOM refs** — `content.js:166-187` store text content instead of node references to avoid preventing GC
- [ ] **`scannedUrls` linear search** — `service-worker.js:114` `Array.includes` is O(n). Use a Set for in-memory checks
- [ ] **Duplicate fetch scans for same endpoint** — `interceptor.js` sends every fetch response for scanning even if the same URL has already been scanned. Dedup intercepted fetches by URL (or URL + method) to avoid redundant WASM calls on repeated API requests
- [ ] **`extractStructuredSecrets` queries all elements** — `content.js:79` `querySelectorAll('*')` iterates every DOM node. On large pages this is expensive
- [ ] Hash text before sending to service worker to skip already-scanned content
- [ ] **`document.documentElement.cloneNode(true)` on large pages** — `content.js:19` clones the entire DOM tree; on 20MB+ pages this can cause OOM or long freezes
- [ ] **No WASM return size limit** — `lib.rs:21` converts findings to `JsValue` without capping; a page with thousands of matches produces a huge serialized payload

## Architecture

- [ ] Scope `window.postMessage` — use a nonce or check `event.origin` to prevent spoofed messages
- [ ] **Origin-less pages break postMessage** — `file://`/`null` origins will fail strict origin checks; add a nonce handshake to allow safe `'*'` in those cases
- [ ] Add retry/fallback if WASM fails to load
- [ ] Fix WebSocket wrapper breaking `instanceof` checks

## UX

- [ ] Per-site disable toggle
- [ ] Severity filtering in popup
- [ ] Color badge by highest severity, not just count
- [ ] Copy-all / export findings (JSON/CSV)
- [ ] Options page for configuration (toggle patterns, manage allowlist, domain settings)
- [ ] Onboarding page shown on first install
- [ ] "Rate this extension" prompt after N findings detected
- [ ] **Mask secrets by default in popup** — show redacted `full_match` with a per-item reveal toggle to reduce shoulder-surfing
- [x] **Popup has no loading state** — popup now shows "Scanning page..." indicator based on `lastScanTs` recency, and polls for updated findings every 2s while open
- [ ] **Very long secrets overflow popup** — `popup.js:46-83` renders `full_match` without truncation; a 100KB+ match will break the popup layout
- [ ] **No accessibility** — `popup.html` lacks ARIA labels, semantic landmarks, keyboard navigation, and screen reader support
- [ ] **Clipboard "Copied!" shown even on failure** — `popup.js:63-68` shows success feedback before the `writeText` promise resolves; if clipboard access is denied, feedback is incorrect

## Error Handling

- [ ] **`setTabData` silently fails on quota exceeded** — `service-worker.js:51` `chrome.storage.session.set()` has no `.catch()`. Default session storage quota is 10MB; if many tabs accumulate large findings (including raw `full_match` values), writes silently fail and findings are lost
- [ ] **Badge API unhandled rejections** — `service-worker.js:36-37` `setBadgeText`/`setBadgeBackgroundColor` can throw if the tab is closed
- [ ] **Clipboard `.catch()` missing** — `popup.js:63-66` `writeText` rejection is unhandled
- [ ] **WASM init failure is not retried properly** — `service-worker.js:26` resets `wasmInitPromise` to null on failure, but concurrent callers can stampede on re-init (thundering herd)
- [ ] **Missing null check in popup tab query** — `popup.js:2-3` assumes `chrome.tabs.query` returns a valid tab; if it returns empty, the popup silently does nothing with no feedback

## Testing

- [ ] Integration tests with sample HTML pages containing known secrets
- [ ] CI test step in GitHub Actions
- [ ] Performance benchmarks for pattern matching (`benches/` directory + CI regression checks)
- [ ] Code coverage tracking (e.g. cargo-tarpaulin + Codecov integration)

### Test coverage gaps

- [ ] `extract_value` — edge cases: no separator, empty value after `=`
- [ ] `shannon_entropy` — boundary values near 3.5 threshold, unicode input
- [ ] `is_false_positive` — test with `GenericSecret` and `GenericToken`, not just `GenericApiKey`
- [ ] `deduplicate` — 3+ overlapping findings
- [ ] `merge_findings` — verify deterministic sort order
- [ ] `scan` — multiple secrets in one text, secrets embedded in surrounding prose
- [ ] Pattern tests with realistic context (HTML/JS/JSON), not just isolated tokens
- [ ] Keyword patterns with different separators (`:` vs `=`), with/without quotes and spaces
- [ ] Bearer token edge cases (short values near 20-char minimum)
- [ ] Discord token — more true positive cases
- [ ] Unit tests for `filter.rs` (`should_scan`)
- [ ] Unit tests for `cookies.rs` (`parse_cookies`)
- [ ] Unit tests for `attributes.rs` (`format_attributes`)

## Distribution

- [ ] Publish to Chrome Web Store
- [ ] Privacy policy (required for store listing)
- [ ] Promotional screenshots and demo GIF
- [ ] Firefox support (Manifest V3)
- [ ] Landing page (GitHub Pages)

## Maintainability & Adaptability

- [ ] **Large monolithic JS files** — `content.js`, `interceptor.js`, and `service-worker.js` each handle multiple responsibilities. Split `service-worker.js` into separate modules (e.g. `wasm-lifecycle.js`, `storage.js`, `badge.js`, `message-router.js`)
- [ ] **No TypeScript** — all extension JS is untyped; message shapes between content scripts, service worker, and popup are implicit contracts with no schema enforcement. Add at minimum JSDoc type annotations for message interfaces, or migrate to TypeScript
- [ ] **Version sync is manual** — `Cargo.toml` and `manifest.json` versions must be updated in lockstep with no automation; add a CI check or build-time sync script
- [ ] **No plugin/rule system** — adding a new secret pattern requires modifying `patterns.rs` + `types.rs` (new `SecretKind` variant), recompiling WASM, and rebuilding. Consider a config-driven pattern format (TOML/JSON) that can be loaded at runtime
- [ ] **Chrome-only** — Manifest V3 + `chrome.*` APIs used throughout with no abstraction layer. Abstract browser APIs behind a compatibility shim if Firefox/Safari support is planned
- [ ] **No configuration surface** — no options page, no allowlisting, no per-site toggles. Every behavioral change requires code modification (see UX section for options page)

## CI/CD

- [ ] **Release artifact path broken** — `release.yml:92-93` references flat artifact filenames but `actions/download-artifact` nests them in subdirectories
- [ ] **Release job skips verification** — `release.yml` depends only on the `build` job, not the full `verify` pipeline; untested code can ship
- [ ] **No dependency vulnerability scanning** — no `cargo-audit`, `cargo-deny`, or Dependabot config; vulnerable dependencies go undetected
- [ ] **TruffleHog pinned to `@main`** — `verify.yml:18` uses a floating tag; pin to a specific release for reproducibility
- [ ] **Build script not used in CI** — `scripts/build.sh` and CI `wasm-pack` commands can diverge; CI should invoke the same script
- [ ] **No MSRV declared** — `Cargo.toml` specifies `edition = "2021"` but no minimum Rust version; builds may break silently on older toolchains
- [ ] Add CHANGELOG.md for tracking releases
- [ ] Add SECURITY.md with vulnerability disclosure policy
- [ ] Add CONTRIBUTING.md with development setup and guidelines
