# TODO

## Security

- [x] **XSS via `innerHTML`** — `popup.js` now uses `createElement`/`textContent` instead of `innerHTML`
- [x] **`postMessage` uses `'*'` target origin** — `interceptor.js` now uses `window.location.origin`; `content.js` validates `event.origin`
- [x] **Raw secret leaked in `full_match`** — storage access tightened from `TRUSTED_AND_UNTRUSTED_CONTEXTS` to `TRUSTED_CONTEXTS`; `full_match` kept in storage for popup display/copy
- [x] **Unescaped attribute output** — `attributes.rs:18` now escapes `"` as `&quot;` in values passed to `format_attributes`
- [x] **Cookie value quote injection** — `cookies.rs:11` now escapes `"` as `\"` in cookie values before formatting
- [x] **No input size limit on `scan_text`** — `lib.rs` now caps input at 2MB with UTF-8-safe truncation
- [x] **ReDoS risk in keyword patterns** — `patterns.rs` unbounded `{20,}` quantifiers now capped to `{20,512}`; `{32,256}` was already bounded

## Correctness

- [x] **Highlight `break` outside `try`** — `content.js` `break` moved inside `try` block after `surroundContents()`
- [x] **`scannedUrls` accumulates `undefined`** — `service-worker.js` now guards `push` with `message.url` truthiness check
- [x] **SPA navigation doesn't clear service worker tab data** — content.js now sends `CLEAR_TAB` message to service worker on SPA navigation, resetting findings and badge
- [x] **`tabLocks` Map leaks entries** — `service-worker.js` `onRemoved` now deletes the tab's entry from `tabLocks` Map
- [x] **EventSource scanning listeners can't be removed** — `interceptor.js` now wraps `removeEventListener` with ref-counting to clean up `onMessage` when last listener is removed
- [x] **WASM `unwrap()` panics on malformed data** — `lib.rs` `merge_findings` now uses `unwrap_or_default()` for deserialization, falling back to empty vec
- [x] **Shannon entropy uses bytes, not chars** — `detector.rs` now iterates `s.chars()` with a `HashMap<char, u32>` for correct multi-byte UTF-8 entropy
- [x] **Char-class check ignores non-ASCII** — `detector.rs` now counts a 4th class for non-alphanumeric chars (symbols, punctuation, non-ASCII)
- [x] **Tab lock error recovery is broken** — `service-worker.js` now uses `prev.catch(() => {}).then(fn)` so each operation starts from a clean state
- [x] **`merge_findings` deduplicates by label+match, losing position** — Now deduplicates by `full_match` value only, keeping highest severity
- [x] **Mutation observer `pendingNodes` grows unbounded** — `content.js` now caps `pendingNodes` at 1000 entries
- [x] **Missing message validation from MAIN world** — `content.js` now validates `typeof text === 'string'` before passing to scanner

## Regressions from recent fixes

- [x] **`merge_findings` output order is non-deterministic** — output now sorted by severity then `full_match` for deterministic display
- [x] **SPA `CLEAR_TAB` briefly shows zero findings** — replaced with `CLEAR_DOM_FINDINGS` that only removes DOM-sourced findings, preserving network findings; re-scans immediately
- [x] **Char-class relaxation may increase false positives** — diversity check now counts only alphanumeric classes (upper/lower/digit), requiring 2 of 3; symbols/non-ASCII no longer count toward the threshold
- [x] **EventSource ref-counting is imprecise** — switched from counter to Set-based listener tracking, matching browser dedup semantics
- [x] **`pagehide` may not fire on extension context invalidation** — `content.js` checks `chrome.runtime.id` liveness every 5s; on invalidation, dispatches `__SECRETS_SPOTTER_CLEANUP__` event to signal MAIN world `interceptor.js` to abort fetches

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
- [ ] **Filter out developer-like variable names** — generic/entropy patterns match camelCase (`myApiKey`), PascalCase (`ApiKeyManager`), and snake*case (`api_key_value`) identifiers that are clearly code symbols, not secrets. Add a false-positive check that rejects values matching common naming conventions (e.g. `^[a-z]+([A-Z][a-z]+)+$`, `^[A-Z][a-z]+([A-Z][a-z]+)+$`, `^[a-z]+(*[a-z]+)+$`)

## Performance

- [ ] **O(n^2) dedup via `Vec::remove`** — `detector.rs:145-157` shifts all elements on each removal. Use `retain()` for a single-pass approach
- [ ] **Needless `String` alloc before false-positive check** — `detector.rs:38` move `to_string()` after `is_false_positive` to skip allocation for discarded matches
- [ ] **Triple char-class iteration** — `detector.rs:103-106` three separate `.chars().any()` loops can be folded into one pass
- [ ] **`scannedHashes` grows unbounded** — `content.js:8` on long-lived SPAs the Set grows forever. Add a size cap
- [ ] **`pendingNodes` holds detached DOM refs** — `content.js:166-187` store text content instead of node references to avoid preventing GC
- [ ] **`scannedUrls` linear search** — `service-worker.js:114` `Array.includes` is O(n). Use a Set for in-memory checks
- [ ] **`extractStructuredSecrets` queries all elements** — `content.js:79` `querySelectorAll('*')` iterates every DOM node. On large pages this is expensive
- [ ] Track existing highlights instead of removing and re-walking the entire DOM
- [ ] Hash text before sending to service worker to skip already-scanned content
- [x] Add input size limit for scanning — `lib.rs` caps input at 2MB with UTF-8-safe truncation
- [ ] **All 37 patterns run sequentially** — `detector.rs:36` iterates patterns in a `for` loop, scanning the full text 37 times. Use `regex::RegexSet` to test all patterns in a single pass, then only run individual regexes for matches. Additionally, pre-screen known-prefix patterns with fast `aho-corasick` / `memchr` substring search before invoking full regex, and reorder patterns so cheap fixed-prefix checks run before expensive generic/entropy patterns
- [ ] **`document.documentElement.cloneNode(true)` on large pages** — `content.js:19` clones the entire DOM tree; on 20MB+ pages this can cause OOM or long freezes
- [ ] **Highlight loop is O(findings × text nodes)** — `content.js:138-160` iterates all text nodes per finding; build a single text-node index and look up matches
- [ ] **No WASM return size limit** — `lib.rs:21` converts findings to `JsValue` without capping; a page with thousands of matches produces a huge serialized payload

## Cleanup / Resource Leaks

- [x] **MutationObserver never disconnected** — `content.js` now disconnects observer, clears `scanTimeout`, and empties `pendingNodes` on `pagehide`
- [x] **WebSocket listener + timer leak** — `interceptor.js` now listens for `close` and `error` events to clear `flushTimer` and flush remaining buffer
- [x] **EventSource listener + timer leak** — `interceptor.js` now listens for `error` with `readyState === CLOSED` check to clear `flushTimer` and flush buffer
- [x] **No page unload cleanup in interceptor** — WebSocket/EventSource close handlers clean up their own timers; `pagehide` aborts in-flight fetch requests. API patches are acceptable since page is unloading
- [x] **External script/stylesheet fetches not abortable** — `interceptor.js` now uses a shared `AbortController` aborted on `pagehide`

## Architecture

- [ ] Scope `window.postMessage` — use a nonce or check `event.origin` to prevent spoofed messages
- [ ] Add retry/fallback if WASM fails to load
- [ ] Fix WebSocket wrapper breaking `instanceof` checks

## UX

- [ ] Per-site disable toggle
- [ ] Severity filtering in popup
- [ ] Color badge by highest severity, not just count
- [ ] Copy-all / export findings (JSON/CSV)
- [ ] Preserve highlights across SPA navigation (React/Vue route changes)
- [ ] Options page for configuration (toggle patterns, manage allowlist, domain settings)
- [ ] Onboarding page shown on first install
- [ ] "Rate this extension" prompt after N findings detected
- [ ] **Popup has no loading state** — `popup.js` fetches findings asynchronously but shows no spinner or "Loading…" indicator; the popup appears empty until data arrives
- [ ] **Very long secrets overflow popup** — `popup.js:46-83` renders `full_match` without truncation; a 100KB+ match will break the popup layout
- [ ] **Highlight causes layout shift** — `content.css` uses `border` which shifts surrounding content; use `outline` or `box-shadow` instead
- [x] **JWT decoder in popup** — when a JWT is detected, add an expandable section that decodes and displays the header and payload (base64-decoded JSON), showing claims like `exp`, `iat`, `sub`, `iss` with expiration status. Decode client-side only, no external calls
- [ ] **No accessibility** — `popup.html` lacks ARIA labels, semantic landmarks, keyboard navigation, and screen reader support
- [ ] **Clipboard "Copied!" shown even on failure** — `popup.js:63-68` shows success feedback before the `writeText` promise resolves; if clipboard access is denied, feedback is incorrect

## Error Handling

- [ ] **`setTabData` silently fails on quota exceeded** — `service-worker.js:51` `chrome.storage.session.set()` has no `.catch()`. Default session storage quota is 10MB; if many tabs accumulate large findings (including raw `full_match` values), writes silently fail and findings are lost
- [ ] **Badge API unhandled rejections** — `service-worker.js:36-37` `setBadgeText`/`setBadgeBackgroundColor` can throw if the tab is closed
- [ ] **Clipboard `.catch()` missing** — `popup.js:63-66` `writeText` rejection is unhandled
- [ ] **WASM init failure is not retried properly** — `service-worker.js:26` resets `wasmInitPromise` to null on failure, but concurrent callers can stampede on re-init (thundering herd)
- [ ] **Missing null check in popup tab query** — `popup.js:2-3` assumes `chrome.tabs.query` returns a valid tab; if it returns empty, the popup silently does nothing with no feedback

## Testing

- [x] Rust unit tests for detector and false positive logic
- [x] Rust unit tests for regex patterns (true/false positive cases)
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

- [ ] **No test coverage** — no unit tests exist in the repo; any refactor or pattern change can silently break detection. The 37 regex patterns are especially fragile without regression tests (see Testing section)
- [ ] **Large monolithic JS files** — `content.js`, `interceptor.js`, and `service-worker.js` each handle multiple responsibilities. Split `service-worker.js` into separate modules (e.g. `wasm-lifecycle.js`, `storage.js`, `badge.js`, `message-router.js`)
- [ ] **No TypeScript** — all extension JS is untyped; message shapes between content scripts, service worker, and popup are implicit contracts with no schema enforcement. Add at minimum JSDoc type annotations for message interfaces, or migrate to TypeScript
- [ ] **Version sync is manual** — `Cargo.toml` and `manifest.json` versions must be updated in lockstep with no automation; add a CI check or build-time sync script
- [ ] **No plugin/rule system** — adding a new secret pattern requires modifying `patterns.rs` + `types.rs` (new `SecretKind` variant), recompiling WASM, and rebuilding. Consider a config-driven pattern format (TOML/JSON) that can be loaded at runtime
- [ ] **Chrome-only** — Manifest V3 + `chrome.*` APIs used throughout with no abstraction layer. Abstract browser APIs behind a compatibility shim if Firefox/Safari support is planned
- [ ] **No configuration surface** — no options page, no allowlisting, no per-site toggles. Every behavioral change requires code modification (see UX section for options page)
- [ ] **Tightly coupled highlighting** — DOM highlighting logic is interleaved with scanning in `content.js` rather than a separate module; extract into a `highlighter.js` module that can be swapped, themed, or disabled independently
- [ ] **Pattern scaling bottleneck** — all 37 patterns run sequentially with no `RegexSet` pre-filter; adding more patterns linearly degrades performance (see Performance section for `RegexSet` item)

## CI/CD

- [x] **Version mismatch** — versions now aligned at `1.0.1`; build script should sync `manifest.json` from `Cargo.toml`
- [ ] **Release artifact path broken** — `release.yml:92-93` references flat artifact filenames but `actions/download-artifact` nests them in subdirectories
- [ ] **Release job skips verification** — `release.yml` depends only on the `build` job, not the full `verify` pipeline; untested code can ship
- [ ] **No dependency vulnerability scanning** — no `cargo-audit`, `cargo-deny`, or Dependabot config; vulnerable dependencies go undetected
- [ ] **TruffleHog pinned to `@main`** — `verify.yml:18` uses a floating tag; pin to a specific release for reproducibility
- [ ] **Build script not used in CI** — `scripts/build.sh` and CI `wasm-pack` commands can diverge; CI should invoke the same script
- [ ] **No MSRV declared** — `Cargo.toml` specifies `edition = "2021"` but no minimum Rust version; builds may break silently on older toolchains
- [ ] Add CHANGELOG.md for tracking releases
- [ ] Add SECURITY.md with vulnerability disclosure policy
- [ ] Add CONTRIBUTING.md with development setup and guidelines
