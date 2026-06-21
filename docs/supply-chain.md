# Supply-Chain Checks

Zelynic uses two complementary Rust dependency checks in the local quality gate.

## Local Quality Gate

Run this before commits and pull requests that touch Rust/core code:

```bash
./scripts/build.sh check-all
```

`check-all` runs formatting, clippy, tests, `cargo audit`, and `cargo deny` when the optional tools are installed. Missing `cargo-audit` or `cargo-deny` is reported as a warning and skipped so contributors can still run the core checks. If `cargo-deny` is installed and `deny.toml` is present, a deny failure fails `check-all`.

The CI policy gate also runs:

```bash
python3 scripts/check-policy.py
```

That script enforces the source rules documented in [`RULES.md`](../RULES.md),
including the 1000 LOC hard limit for checked core/code files and required
copyright/SPDX headers.

Manual fallback:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo audit
cargo deny check all
python3 scripts/check-policy.py
```

If `cargo-nextest` is installed, `build.sh` uses it for faster tests. Otherwise it falls back to `cargo test`.

## What The Tools Check

- `cargo audit` checks RustSec advisories and known vulnerability reports for the resolved dependency graph.
- `cargo deny` checks advisories, licenses, banned or duplicate crates, and dependency source policy.
- `Cargo.lock` is committed so dependency resolution is reproducible across local and CI runs.

## License Policy

Zelynic itself is licensed as `GPL-3.0-only`. Dependencies may use normal GPL-compatible permissive licenses such as MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, MPL-2.0, or Unlicense when accepted by `deny.toml`.

MIT, Apache, BSD, ISC, Unicode, Zlib, MPL, and Unlicense dependencies are normal in Rust projects and are not automatically supply-chain attacks. They still remain subject to advisory, source, and duplicate-version checks.

## Source Policy

The trusted registry is crates.io. Unknown registries and unknown git sources are denied by `cargo deny` unless explicitly reviewed and configured.

Supply-chain security reduces risk, but it cannot make third-party dependencies zero-risk. Review unusual dependency changes carefully.
