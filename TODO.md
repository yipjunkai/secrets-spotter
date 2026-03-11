# TODO

## Detection

- [x] Handle CORS failures on external script fetching — changed `credentials: 'include'` to `credentials: 'same-origin'` in `interceptor.js`; additionally, external resource scanning is now disabled by default (`SCAN_EXTERNAL_RESOURCES = false`) because the MAIN world fetches are subject to the page's CSP `connect-src` directive, causing console errors on strict-CSP sites. To fully fix, external fetches would need to be moved to the service worker (extension origin, not subject to page CSP)
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

- [x] **O(n^2) dedup via `Vec::remove`** — `detector.rs` now uses a single-pass `drain` + `Vec::with_capacity` approach instead of shifting elements on each removal
- [x] **Needless `String` alloc before false-positive check** — `detector.rs` now borrows `mat.as_str()` for `is_false_positive` and `redact`; `.to_string()` deferred until after the match is confirmed
- [x] **Triple char-class iteration** — `detector.rs` now uses a single `for c in value.chars()` loop with early exit once 2 character classes are found
- [x] **Hashing can exceed scan cap** — `content.js` now truncates text to 2MB (`MAX_SCAN_SIZE`) before hashing and sending, matching the WASM cap in `lib.rs`
- [x] **Mutation batches can blow past 2MB** — covered by the `MAX_SCAN_SIZE` truncation in `sendForScan`; all text flows through this function before hashing/sending
- [x] **`scannedHashes` grows unbounded** — `content.js` now caps `scannedHashes` at 500 entries (`MAX_HASHES`); clears and accepts a re-scan burst when exceeded
- [x] **`pendingNodes` holds detached DOM refs** — `content.js` now extracts `textContent` eagerly in the MutationObserver callback and stores strings (`pendingTexts`) instead of node references
- [x] **`scannedUrls` linear search** — kept as `Array.includes`; the array rarely exceeds ~100 entries per tab, making O(n) `includes` negligible in practice. A `Set`-based approach was tested and reverted as it introduced an O(n) construction + O(n) spread on every `SCAN_TEXT` message — a net regression for the common repeated-URL case
- [ ] **Duplicate fetch scans for same endpoint** — `interceptor.js` sends every fetch response for scanning even if the same URL has already been scanned. Dedup intercepted fetches by URL (or URL + method) to avoid redundant WASM calls on repeated API requests
- [ ] **`extractStructuredSecrets` queries all elements** — `content.js:79` `querySelectorAll('*')` iterates every DOM node. On large pages this is expensive
- [ ] Hash text before sending to service worker to skip already-scanned content
- [x] **`document.documentElement.cloneNode(true)` on large pages** — removed; `getPageSource()` now returns `document.documentElement.outerHTML` directly (the clone was only needed to strip highlight wrappers, which no longer exist)
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
- [x] **Clipboard "Copied!" shown even on failure** — fixed in error handling hardening; `popup.js` copy button now awaits the `writeText` promise and shows "Failed" on rejection

## Error Handling

- [x] **`setTabData` silently fails on quota exceeded** — `setTabData` now catches storage errors, logs them, and attempts recovery by truncating findings to 50, then to 0 if still failing
- [x] **Badge API unhandled rejections** — all 5 `setBadgeText`/`setBadgeBackgroundColor` call sites now have `.catch(() => {})` to handle closed-tab errors
- [x] **Clipboard `.catch()` missing** — `popup.js` copy button now catches `writeText` rejection and shows "Failed" feedback instead of leaving the button unchanged
- [x] **WASM init failure is not retried properly** — `initWasm` now keeps the failed promise cached for a 5-second cooldown before allowing retry, preventing thundering herd on concurrent callers
- [x] **Missing null check in popup tab query** — popup now shows "Unable to access this tab." message instead of an infinite loading spinner when `chrome.tabs.query` returns empty

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
