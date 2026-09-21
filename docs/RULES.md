<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Zelynic Project Rules

## File Size

- Rust source files must stay under `500` lines (hard cap, owner rule).
- This applies to every `.rs` file under `src/` AND `test/` (both
  recursive) plus `build.rs` (NIGHT-docs-4 — the test tree is code
  too, and it grew past the cap: the old 770-line integration file
  was split into `test/integration/`, one file per surface).
  NIGHT-hunt-17 tightened the layout further: every test file lives
  under the single top-level `test/` tree (cosmostrix Pattern C),
  Cargo autodiscovery is off (`autotests = false`), and the one
  integration target is declared explicitly in `Cargo.toml`.
- It excludes `*.md`, `*.txt`, generated files, lockfiles, assets, release
  artifacts, `.git/`, and `target/`.
- `src/main.rs` has a soft target of `100-300` LOC in a mature project and
  should remain bootstrap/wiring only.
- A file that legitimately cannot be split self-declares an exemption at
  the top of the file:

  ```rust
  // LOC_EXEMPT: <one-line justification>
  ```

  The marker is tracked migration debt — removing it is deleting the
  comment, nothing else. There is no hardcoded exemption list in the
  checker (lists drift out of sync; markers live with the file).

### Enforcement

`scripts/check-loc.sh` (wired into `scripts/gate-keepers.sh`) scans the
policy scope, prints every file's count, and fails on any file over the
cap without an exemption marker.

## Rust Toolchain Pin

- `rust-toolchain.toml` pins a concrete `X.Y.Z` version — never a
  channel alias (`stable` drifts; a future release could silently
  break the build). This is the dormant-mode policy.
- The pin must agree with `Cargo.toml` `rust-version` (MSRV, major.minor)
  and every workflow `RUST_VERSION` env that installs a toolchain.
- Bump everything in one command: `./scripts/rust-version-to.sh <X.Y.Z>`
  (idempotent, refuses dirty trees, audits docs for stale references,
  verifies sync as its final gate).
- `scripts/check-rust-version-sync.sh` (wired into `gate-keepers.sh`)
  fails the gate on any disagreement or on a channel alias.

## Documentation Disclaimer

- Every living `.md` file carries the stale-data disclaimer at the
  bottom (`<!-- ZELYNIC-DISCLAIMER -->` block).
- `CHANGELOG.md` and `CHANGELOG-V11-ERA.md` are excluded — frozen
  historical records, never rewritten (the same exclusion policy as
  every other gate).
- Inject with `./scripts/inject-disclaimer.sh`; verify with
  `./scripts/inject-disclaimer.sh --check` (wired into
  `gate-keepers.sh`; the gatekeeper's `--fix` auto-injects).

Rationale: maintainers (and AI agents) update source code but forget to
sync every doc that references a number, path, or symbol. Chasing
perfect sync has diminishing returns; the uniform disclaimer asks
readers to cross-check the source instead.

## Language Discipline

- The repository is English-only: comments, docs, script text, and
  string literals. Chat may be mixed-language; committed artifacts
  never are.
- Non-Latin scripts (CJK, Cyrillic, Arabic, ...) appear ONLY as
  intentional Unicode coverage data, and the carrying file
  self-declares with a marker comment (the same discipline as
  `LOC_EXEMPT` — no hardcoded allowlist, the exemption lives with
  the file, removing it means deleting the comment):

  ```rust
  // NON_LATIN_FIXTURE: <one-line justification>
  ```

- Indonesian vocabulary has no exemption path: fixtures are
  CJK/Cyrillic, never Indonesian prose.
- Frozen historical records (both CHANGELOG files, git history) are
  never rewritten — a non-English quote inside them stays as history
  (the NIGHT-improve-1 commit body quoting the owner's directive
  verbatim is the known example).

### Enforcement

`scripts/check-language.sh` (wired into `scripts/gate-keepers.sh`
section 14 and mirrored in the CI `workflow_quality` job) scans every
text file for non-Latin scripts outside marker-declared fixtures and
for a curated, case-sensitive Indonesian word list. The emoji sweep
(gate-keepers section 8) is the sibling gate for emoji codepoints.

## Manual Workflow

Use a test-first loop:

1. Run the relevant test/check.
2. Review the output.
3. Fix the issue or continue only after understanding the result.

Do not guess past failing checks.

## Release Honesty

- The validated limiter paths are `zelynic strict-single` and
  `zelynic strict-multi`.
- The `zelynic block-*` family shares the same pinned-map enforcement
  mechanism (zero-rate policy).
- Do not overclaim enforcement beyond what the pinned maps + watchdog
  actually guarantee.

## Test Discipline

Tests must verify **behavior**, never **identity**. A test assertion that
a constant value matches itself (tautology) provides zero information and
breaks the suite on every unrelated change.

### Forbidden: tautological version assertions

```rust
// FORBIDDEN — Cargo.toml always contains its own version field.
// Always true, zero information.
assert!(include_str!("../Cargo.toml").contains("version = \"3.1.1\""));
```

### Forbidden: test-on-test meta-pattern

Tests must not assert that **other test files** contain a particular
literal string. Every version bump would force manual edits across
multiple test files just to satisfy one meta-test.

```rust
// FORBIDDEN — tests that another test file contains a literal version.
let p14 = include_str!("ledger_p14_tests.rs");
assert!(p14.contains("1.2.3"), "p14 tests must assert 1.2.3");
```

### Allowed: dynamic version assertions

```rust
// ALLOWED — env!() injects the compile-time package version from
// Cargo.toml [package] version. Single source of truth.
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
assert!(include_str!("../Cargo.toml")
    .contains(&format!("version = \"{}\"", CURRENT_VERSION)));
```

### Allowed: historical CHANGELOG assertions

Asserting that a past release has an entry in CHANGELOG is legitimate —
those entries are immutable historical record and remain valid forever.

```rust
// ALLOWED — verifies CHANGELOG has an entry for a historical release.
let changelog = include_str!("../CHANGELOG.md");
assert!(changelog.contains("## v3.0.1"));
```

### Enforcement

`scripts/check-version-anti-patterns.sh` (run by `build.sh check-all`)
scans `src/**/*.rs` for forbidden patterns and fails the build if any
are detected. The guard catches:

- `contains("version = \"X.Y.Z\"")` and `contains(r#"version = "X.Y.Z""#)`
- Test-on-test meta-pattern: `include_str!()` another test file followed
  by `contains("X.Y.Z")` semver literal

If a future test genuinely needs the current package version, use
`env!("CARGO_PKG_VERSION")` — never hardcode the literal string. The
current package version is already verified by
`test/integration/smoke.rs::test_version` (which uses the `--version` CLI
flag), so per-module version assertions are redundant anyway.

<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
