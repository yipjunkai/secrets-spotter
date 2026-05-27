# Contributing to Secrets Spotter

Thanks for your interest. Secrets Spotter is solo-maintained — clear, focused contributions help enormously. Issues and pull requests are the primary inbound channels.

## Quick start

```bash
git clone https://github.com/yipjunkai/secrets-spotter
cd secrets-spotter

# Build CLI + WASM extension in parallel
just build

# Run all workspace tests
just test
```

Required toolchain:

- [Rust (stable)](https://rustup.rs/) — workspace declares `edition = "2021"`
- [`just`](https://github.com/casey/just) — command runner used by all recipes
- [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/) — only needed to build the Chrome extension

## Pull request checklist

- [ ] `just lint` passes (`cargo fmt --check` + clippy on core/cli/wasm)
- [ ] `just test` passes
- [ ] If adding or changing a detection pattern: inline `#[cfg(test)]` tests for at least one positive and one negative case (see the `ghs_` pattern in `crates/core/src/patterns.rs` for the worked example)
- [ ] If touching the extension: manually loaded `extension/` in `chrome://extensions/` and verified the change works on a real page
- [ ] If touching the CLI: README examples still accurate
- [ ] `README.md` pattern table and pattern count updated when adding/removing a pattern
- [ ] No live secrets in test fixtures — use `concat!("pre", "fix_...")` to defeat GitHub Push Protection if needed

## Adding a new detection pattern

The recent `ghs_` (GitHub App Installation Token) split in `crates/core/src/patterns.rs` is the worked example. Copy its structure.

1. Add a `SecretKind` variant in `crates/core/src/types.rs` if the pattern represents a new credential class. Reuse an existing variant when adding a sibling format of the same credential (e.g. legacy + new GitHub App tokens both share `SecretKind::GitHubAppToken`).
2. Add a `SecretPattern` entry to the `PATTERNS` array in `patterns.rs`. Pick the lowest-severity tier the pattern actually warrants — most known-prefix patterns are `Critical`, keyword patterns are `Medium`, entropy-only is `Low`.
3. Add tests covering at least:
   - One positive case (matches a realistic example)
   - One negative case (a similar-looking string that should NOT match)
4. Update `README.md`:
   - The pattern count in the headline, Features bullet, and "Detection Strategy" intro
   - The relevant table under Detection Strategy
5. If the pattern is keyword-based or generic, verify `crates/core/src/detector.rs::is_false_positive` covers the new kind, otherwise placeholders like `YOUR_API_KEY` will trigger false positives.

## Style

- Rust: `cargo fmt` (rustfmt defaults) + the lints enforced by `just lint`
- Conventional commits (`feat:` / `fix:` / `docs:` / `chore:` / `perf:` / `refactor:` / `test:`) are encouraged — they will become required if and when release-please is wired up

## Before large PRs

For anything beyond a single pattern addition or small bug fix, please open a draft issue first describing the proposed change. The maintenance budget is finite; up-front scope alignment avoids wasted work.
