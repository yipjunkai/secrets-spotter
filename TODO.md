# TODO

## Detection

- [ ] Support scanning inside `<iframe>` content
- [ ] More known-prefix patterns
- [ ] Custom user-defined rules via options page
- [ ] **Bearer token minimum length too restrictive** — `patterns.rs:269` requires 20+ chars for bearer values; many valid tokens are shorter. Consider lowering to 10+
- [ ] **Twilio `SK` prefix collides with random hex strings** — `patterns.rs:131` matches `SK[0-9a-fA-F]{32}` with no word boundary; any 34-char hex string starting with `SK` (e.g. a CSS color hash or SHA fragment) triggers a Critical finding
- [ ] **GenericToken requires quoted values but GenericApiKey doesn't** — `patterns.rs:312` ends with mandatory closing quote, so `access_token=abc123...` without quotes is never matched, creating inconsistent coverage
- [ ] **No false-positive filtering on keyword service patterns** — `is_false_positive` only filters `GenericSecret|GenericApiKey|GenericToken|HighEntropyString|BearerToken`; keyword patterns like `AwsSecretKey` and `HerokuApiKey` can match placeholder values like `aws_secret_access_key="YOUR_KEY_HERE"` unchecked

## False Positives

- [ ] Reduce high-entropy false positives (CSS class hashes, webpack chunk IDs) — add minimum length or context check
- [ ] Add allowlisting for known-safe values (public keys, test fixtures)
- [ ] Avoid matching generic patterns inside URL paths vs. query param leaks
- [ ] **Hardcoded entropy threshold** — `detector.rs:102` uses `3.5` without documentation of why; different secret types may benefit from different thresholds

## Performance

- [ ] **Duplicate fetch scans for same endpoint** — `interceptor.js` sends every fetch response for scanning even if the same URL has already been scanned. Dedup intercepted fetches by URL (or URL + method) to avoid redundant WASM calls on repeated API requests
- [ ] **`extractStructuredSecrets` queries all elements** — `content.js:79` `querySelectorAll('*')` iterates every DOM node. On large pages this is expensive
- [ ] Hash text before sending to service worker to skip already-scanned content
- [ ] **No WASM return size limit** — `lib.rs:21` converts findings to `JsValue` without capping; a page with thousands of matches produces a huge serialized payload
- [ ] **`extractStructuredSecrets` scans all elements redundantly** — `content.js:104` `querySelectorAll('*')` iterates every element for `data-*` attrs, but `scanPage()` already sends the full `outerHTML`; any data-attr secret is caught by the DOM scan, making the structured scan redundant work
- [ ] **`merge_findings` clones `full_match` for every HashMap insert** — `detector.rs:269` `best.insert(f.full_match.clone(), f)` allocates a clone even though `f` already owns the string; restructure to avoid the double allocation
- [ ] **RegexSet + individual regex double-match** — `detector.rs:57-65` first matches all patterns via `REGEX_SET`, then re-runs each matching pattern's individual `Regex`. For patterns without prefixes (keyword/generic), this is always double work
- [ ] **`pendingTexts` cap of 1000 entries has no size limit** — `content.js:157` caps array length but not total byte size; 1000 nodes with 100KB textContent each = 100MB pending in memory

## Architecture

- [ ] Scope `window.postMessage` — use a nonce or check `event.origin` to prevent spoofed messages
- [ ] **Origin-less pages break postMessage** — `file://`/`null` origins will fail strict origin checks; add a nonce handshake to allow safe `'*'` in those cases
- [ ] Add retry/fallback if WASM fails to load
- [ ] Fix WebSocket wrapper breaking `instanceof` checks
- [ ] **`badgeSettleTimers` leaks on rapid tab switching** — `service-worker.js:67` stores timers by tabId but if a tab navigates multiple times before closing, stale timers from `updateBadge` and `onCommitted` accumulate
- [ ] **`scannedUrls` grows unbounded per tab** — `service-worker.js:213` pushes URLs into `tabData.scannedUrls` with no cap; a long-lived SPA tab making API calls will accumulate thousands of URL strings in session storage
- [ ] **`withTabLock` promise chains never clean up** — `service-worker.js:122` stores promise chains in `tabLocks` but never deletes entries for active tabs; the Map grows with every new tab that triggers a scan
- [ ] **Cookie scan happens only once at page load** — `interceptor.js:368-373` calls `scanCookies()` once; cookies set later via `Set-Cookie` headers or `document.cookie` assignments are never rescanned
- [ ] **SPA navigation doesn't rescan cookies from interceptor** — `interceptor.js:404` calls `scanCookies()` on URL change, but new cookies set between navigations aren't picked up until the next URL change

## Security

- [ ] **WASM files are web-accessible to all origins** — `manifest.json:37` exposes WASM resources with `matches: ["<all_urls>"]`, meaning any website can load and probe the scanner. Restrict to extension origin only if not needed by content scripts
- [ ] **`serde_wasm_bindgen::to_value().unwrap()` panics on serialization failure** — `lib.rs:33` panics if a finding contains data that can't be serialized, crashing the entire service worker. Use `unwrap_or` with an empty `JsValue`
- [ ] **`merge_findings` double-unwrap** — `lib.rs:58-61` calls `.unwrap()` on both deserialization and serialization; malformed input from a compromised content script panics the WASM module instead of returning an empty result

## UX

- [ ] Per-site disable toggle
- [ ] Severity filtering in popup
- [ ] Color badge by highest severity, not just count
- [ ] Copy-all / export findings (JSON/CSV)
- [ ] Options page for configuration (toggle patterns, manage allowlist, domain settings)
- [ ] Onboarding page shown on first install
- [ ] "Rate this extension" prompt after N findings detected
- [ ] **Mask secrets by default in popup** — show redacted `full_match` with a per-item reveal toggle to reduce shoulder-surfing
- [ ] **Very long secrets overflow popup** — `popup.js:46-83` renders `full_match` without truncation; a 100KB+ match will break the popup layout
- [ ] **No accessibility** — `popup.html` lacks ARIA labels, semantic landmarks, keyboard navigation, and screen reader support
- [ ] **Popup renders raw secrets in plain text** — `popup.js:166` sets `code.textContent = f.full_match`, showing the complete secret in the popup. The redacted `matched_text` field exists but is never used — shoulder-surfing risk
- [ ] **No dark mode support** — `popup.css` hardcodes light colors (`#fafafa`, `#333`, `#fff`); no `prefers-color-scheme: dark` media query
- [ ] **Severity summary order is non-deterministic** — `popup.js:141` iterates `Object.entries(grouped)` which follows insertion order from the findings array, not severity order; Critical might appear after Low
- [ ] **Badge always shows red regardless of severity** — `service-worker.js:75` hardcodes `#e74c3c`; a page with only Low findings gets the same alarming red badge as one with Critical findings
- [ ] **Debug log timestamps lack dates** — `popup.js:233` uses `toLocaleTimeString()` only, so entries from different days are indistinguishable
- [ ] **No way to dismiss/acknowledge individual findings** — once a finding is detected, it stays until navigation; users can't mark false positives or hide known secrets

## Testing

- [ ] Integration tests with sample HTML pages containing known secrets
- [ ] CI test step in GitHub Actions
- [ ] Performance benchmarks for pattern matching (`benches/` directory + CI regression checks)
- [ ] Code coverage tracking (e.g. cargo-tarpaulin + Codecov integration)

### Test coverage gaps

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
- [ ] **Duplicate filter lists between Rust and JS** — `filter.rs:6` `SKIP_EXTENSIONS` and `interceptor.js:19` define identical skip lists independently; adding a new extension requires updating both and they can silently diverge
- [ ] **No `#[cfg(test)]` modules in any Rust source file** — all source files lack inline tests and the `tests/` directory doesn't exist; `cargo test` runs zero unit tests
- [ ] **`release.yml` opt-level `"s"` conflicts with benchmarking** — `Cargo.toml:28` sets `opt-level = "s"` (size-optimized) in release profile, which is correct for the extension but gives misleading numbers if someone runs `cargo bench` with `--release`

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
- [ ] **Release uses `actions/checkout@v6` which doesn't exist** — `release.yml:70` references `@v6` but the latest stable is `@v4`; the release job will fail
- [ ] **Test job unnecessarily depends on build** — `verify.yml:70` `test` needs `build`, but `cargo test` doesn't need WASM output; the dependency adds unnecessary CI latency
- [ ] **No tests for `wasm32` target** — `verify.yml:86` runs `cargo test` on native target only; panics or compile errors specific to wasm32 go undetected
- [ ] **Checksum file format is non-standard** — `release.yml:51` writes `filename|path|hash` with pipe separators instead of the standard `sha256sum` format (`hash  filename`); verification tools won't understand it
