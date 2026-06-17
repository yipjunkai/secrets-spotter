# Fuzzing

Coverage-guided fuzzing of the core scanner's input-facing surface — the code
the browser extension feeds untrusted page text, network bodies, cookies, and
URLs into. The scanner's job *is* parsing hostile input, so this is a primary
correctness lane, not an edge-case afterthought.

This is a standalone Cargo workspace (excluded from the root one) so its
nightly + `libfuzzer-sys` toolchain never touches normal `cargo check`/`test`/`build`.

## Targets

| Target | Entry point | Invariant (beyond "no panic") |
|---|---|---|
| `scan_text` | `scan_text_limited` | finding spans are ordered, in-bounds, on char boundaries, and `full_match == text[start..end]`; scanning is deterministic |
| `merge_findings` | `merge_findings` | no previously-held finding is ever dropped (the PR #16 regression, frozen) |
| `parse_cookies` | `cookies::parse_cookies` | no panic on arbitrary cookie headers |
| `format_attributes` | `attributes::format_attributes` | no panic on adversarial JSON |
| `should_scan` | `filter::should_scan` | no panic on degenerate URL / content-type pairs |

## Running locally

```sh
# from the repo root
just fuzz scan_text 60        # run one target for 60s
# or directly (corpus/ first = writable working set, seeds/ = read-only input;
# never pass seeds/ first or libFuzzer writes evolved inputs into it):
cd fuzz && mkdir -p corpus/scan_text && \
    cargo fuzz run scan_text corpus/scan_text seeds/scan_text -- -max_total_time=60
```

`cargo fuzz` installs the pinned nightly automatically from `rust-toolchain.toml`.

## Corpus policy

Three layers, deliberately separated so no secret-shaped literal is ever
committed (the repo's fixture policy — see `crates/core/src/test_fixtures.rs`):

- **`seeds/<target>/`** (committed, code-reviewed): benign, secret-free inputs.
  The `scan_text` seeds are the synthetic web payloads from the bench corpus;
  they contain no real tokens, so `just scan-self` stays clean.
- **`scan_text.dict`** (committed): the literal detector *prefixes*. A bare
  prefix is not a secret shape, so it gives the fuzzer a cold-start path to the
  match logic without tripping secret scanning.
- **`corpus/<target>/`** (gitignored): the evolving working set libFuzzer grows.
  In CI it is cached and compounds across nightly runs; locally it is yours.
  Never committed — and because it is gitignored, the CLI's `scan-self` walk
  skips it, so an evolved input that happens to look secret-shaped can't trip
  the dogfood scan.

Never seed from `crates/core/benches/sites/` (gitignored real-page dumps):
captured real-world data must not leak into fuzz artifacts or the cache.

## When a crash is found

The reproducing input is written under `artifacts/<target>/`. Reproduce with
`cargo fuzz run <target> artifacts/<target>/<crash-file>`, minimize with
`cargo fuzz cmin`, fix the bug, and add the minimized reproducer to
`seeds/<target>/` so the case is regression-tested forever.
