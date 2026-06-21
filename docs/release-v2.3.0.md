# Zelynic v2.3.0 Release Notes

Zelynic v2.3.0 "Distro Matrix" is a documentation, policy, and architecture
hygiene release that establishes the foundation for tracking distribution support
across Linux environments. It introduces no changes to strict limiter runtime
behavior.

## What Changed

### Policy and Enforcement

- Added `RULES.md` with project-wide source policy rules, including a 1000 LOC
  limit per core code file and mandatory copyright/SPDX headers on all checked
  source files.
- Added `scripts/check-policy.py` to enforce policy rules automatically as part
  of the quality gate.
- `./scripts/build.sh check-all` now runs policy checks alongside fmt, clippy, test,
  audit, and deny checks.

### CI/CD Maturity

- Added `deny.toml` for structured cargo-deny dependency policy checks covering
  licenses, bans, advisories, and sources.
- Added `docs/supply-chain.md` documenting the supply-chain check policy.
- CI pipeline now includes cargo-audit and cargo-deny as quality gates.

### Architecture Hygiene

- Slimmed `src/main.rs` from 926 LOC to 94 LOC by extracting command handlers
  into a `src/commands/` module with focused domain files:
  `mod.rs` (dispatch), `strict.rs`, `run.rs`, `profile.rs`, `monitor.rs`,
  `backend.rs`, `help.rs`.
- All core Rust files remain under the 1000 LOC policy limit.

### Distro Matrix Foundation

- Added `docs/distro-matrix.md` with distribution support status labels
  (Validated, Candidate, Partial, Unsupported, Not tested), required kernel and
  runtime capabilities, and a per-distro manual validation checklist.
- Added `scripts/collect-host-facts.sh`, a non-mutating, no-sudo shell script
  that collects kernel, distro, cgroup, userspace tool, and default route
  information for host capability assessment.
- Added `docs/validation-reports/` with a structured per-distribution
  validation report template and an initial Arch/CachyOS report documenting the
  v2.0.0 strict limiter test evidence.
- Added `docs/validation-reports/README.md` explaining report types (read-only
  host capability vs privileged strict limiter validation), filing instructions,
  and a clear warning that privileged tests must be run manually.
- Updated `docs/validation.md` with a structured two-step distro validation flow
  covering non-root read-only capability checks and privileged strict limiter
  testing.

## Validation

This release passed all quality gates:

- `cargo fmt --all -- --check` — formatting clean
- `cargo test --locked` — 127 unit tests, 4 integration tests passed
- `cargo clippy --all-targets --all-features -- -D warnings` — no warnings
- `python3 scripts/check-policy.py` — 54 files checked, all under 1000 LOC,
  all copyright/SPDX headers present
- `git diff --check` — no whitespace errors
- GitHub Actions CI — green

## Honesty and Caveats

- **Strict limiter validated on Arch/CachyOS only:** The `zelynic strict`
  command has been tested and confirmed working on a single modern cgroup v2
  host (CachyOS/Arch, kernel `6.18.33-1-cachyos-lts`, nftables `v1.1.6`,
  tc/iproute2 `7.0.0`, pure cgroup v2, interface `wlp1s0`). This is not a
  claim of universal Linux distribution support.
- **Fedora, Ubuntu, Debian are candidate/pending:** These distributions are
  expected to work based on their kernel and userspace stacks but have not been
  explicitly validated. They remain listed as "Candidate" in the distro matrix
  until real testing is performed and documented.
- **WSL and containers are partial/unsupported by default:** WSL2 and container
  environments typically lack writable cgroup hierarchies, nftables socket
  matching, or tc privileges required for the strict limiter path. They should
  not be used without first verifying capabilities with `zelynic backend doctor`.
- **Live systemd-run execution is not implemented:** `zelynic run --execute`
  remains non-mutating. It prints a preflight summary and returns "not
  implemented yet." No live `systemd-run` execution occurs in this release.
- **`zelynic run` remains experimental groundwork:** The run mode is a planning
  and preview tool. `--dry-run` is the safe path. The strict limiter path
  (`zelynic strict`) remains the only validated active backend.
- **No runtime limiter behavior changes:** The commits in this release are
  documentation, policy enforcement, CI/CD hardening, and code organization.
  No changes to the strict limiter, monitoring, QoS, profile, or auto-throttle
  behavior are intended or expected.

## Release Compare

Use the previous stable release baseline:

```text
https://github.com/oxyzenQ/zelynic/compare/v2.2.0...v2.3.0
```
