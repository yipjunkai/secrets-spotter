# Security Policy

## Supported versions

Secrets Spotter is solo-maintained: only the **latest released
minor version** receives security fixes. Older minors are not patched —
upgrade to the most recent [release][rel] before reporting.

[rel]: https://github.com/yipjunkai/secrets-spotter/releases/latest

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use GitHub's private security advisory mechanism:

1. Go to <https://github.com/yipjunkai/secrets-spotter/security/advisories>
2. Click "Report a vulnerability"
3. Fill in the form with as much detail as you can share

Acknowledgement is targeted within 72 hours. There is no separate email contact at this stage; the GitHub advisory channel is the only supported route.

## What to report

- Pattern bypasses that let real secrets evade detection in ways an attacker could exploit (e.g. encoding tricks, unicode normalization edge cases that escape the regex set)
- Memory safety issues in the Rust core or WASM bindings — panics, infinite loops, or unbounded allocations triggered by crafted input
- Browser extension issues that could expose scanned content to other origins, leak secrets between tabs, or be used by a hostile page to deanonymize the user
- Supply chain concerns (dependency vulnerabilities not yet flagged by Dependabot or `cargo audit`)

## What is not in scope

- Missing patterns for services not yet supported (open a regular feature request)
- False positives on production-like inputs (open a regular bug report)
- Performance issues (open a regular issue)
- Feature requests
