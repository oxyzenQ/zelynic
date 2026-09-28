<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# zelynic Documentation Index

Master index of all zelynic documentation. Use this as your map when
returning to the project after a long break — every doc answers one
question well, and this page says which.

## Quick Navigation

| I want to... | Go to |
|-------------|-------|
| Understand what zelynic is | [README.md](../README.md) |
| Understand the design philosophy | [PHILOSOPHY.md](PHILOSOPHY.md) |
| Install or use a command | [USAGE.md](USAGE.md) |
| Get answers to common questions | [FAQ.md](FAQ.md) |
| Check whether my kernel works | [KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md) + `zelynic doctor` |
| Verify a downloaded release | [VERIFY_RELEASE.md](VERIFY_RELEASE.md) |
| Know if zelynic is safe to run | [SAFETY_ANALYSIS.md](SAFETY_ANALYSIS.md) |
| Report a bug / contribute | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Understand licensing (GPL vs commercial) | [LICENSING_FAQ.md](LICENSING_FAQ.md) |
| Release a new version | [VERIFY_RELEASE.md](VERIFY_RELEASE.md) § owner procedures + [MAINTENANCE.md](MAINTENANCE.md) |
| Keep the project healthy long-term | [MAINTENANCE.md](MAINTENANCE.md) |
| Read the project rules | [RULES.md](RULES.md) |
| See how the v11 era compares to v10 | [research/NIGHT_DINNER_5_V10_V11_ERA_COMPARISON.md](research/NIGHT_DINNER_5_V10_V11_ERA_COMPARISON.md) |

## Architecture & Design

| Doc | Covers |
|-----|--------|
| [COSMIC_DRAGON_ARCHITECTURE.md](COSMIC_DRAGON_ARCHITECTURE.md) | Pure-eBPF architecture: single hooking layer, cgroup v2, why Linux-only |
| [PHILOSOPHY.md](PHILOSOPHY.md) | The design canon: cgroup as the unit, observation before enforcement, frozen CLI grammar, local-first |
| [PURE_RUST_EVALUATION.md](PURE_RUST_EVALUATION.md) | The full C-to-Rust eBPF migration record (aya, no C toolchain) |
| [RULES.md](RULES.md) | Source tree layout, naming, comment discipline, the frozen v11 CLI surface |
| [RESEARCH_TOOLCHAIN_AND_MONITORING.md](RESEARCH_TOOLCHAIN_AND_MONITORING.md) | Toolchain dating rationale + monitoring-coverage research answers |

## Trust, Safety & Claims

| Doc | Covers |
|-----|--------|
| [CLAIMS_VERIFICATION.md](CLAIMS_VERIFICATION.md) | The ledger: every public claim maps to the mechanism that verifies it |
| [SAFETY_ANALYSIS.md](SAFETY_ANALYSIS.md) | Malware-question analysis, crash behavior, pin cleanup, recovery |
| [STABILITY.md](STABILITY.md) | The dated nightly eBPF toolchain pin and the LTS reasoning |
| [DEPENDENCY_AUDIT.md](DEPENDENCY_AUDIT.md) | Supply-chain posture: why each dependency exists, deny.toml policy |
| [SANDBOX.md](SANDBOX.md) | The local KVM micro-VM for root testing without touching the host |

## Performance & Validation

| Doc | Covers |
|-----|--------|
| [PERFORMANCE.md](PERFORMANCE.md) | Measured overhead on real hardware, benchmark methodology |
| [CROSS_DISTRO_RESULTS.md](CROSS_DISTRO_RESULTS.md) | Validation matrix across distributions and kernels |

## Research

Dated research and comparison records — questions answered with live
evidence rather than opinion. The naming convention is
`docs/research/<TASK>_<SUBJECT>.md`.

| Research | Covers |
|----------|--------|
| [research/NIGHT_DINNER_5_V10_V11_ERA_COMPARISON.md](research/NIGHT_DINNER_5_V10_V11_ERA_COMPARISON.md) | The v10 vs v11 era comparison, answered live in the sandbox micro-VM: engine, limiter, monitoring, distribution — with the enforced-rate numbers from both eras |
| [research/NIGHT_DINNER_14_PRICING_RESEARCH.md](research/NIGHT_DINNER_14_PRICING_RESEARCH.md) | The tier-pricing decision brief: consumer and commercial comparables with sourced prices, analysis against the current Individual/Business/Company tiers, and the owner's option matrix — research only, no price changed by it |

## Release & Distribution

| Doc | Covers |
|-----|--------|
| [VERIFY_RELEASE.md](VERIFY_RELEASE.md) | Checksums (SHA-512 / BLAKE2b / SHAKE256), GPG verification, the crates.io lane, owner publish procedures |
| [MAINTENANCE.md](MAINTENANCE.md) | Owner playbook: secret inventory, key rotation, release recovery, gate refresh cadence |

## Audits

Dated, immutable records of real incidents and deep audits — the
project's institutional memory. The naming convention is
`docs/audits/<SUBJECT>_<YYYY-MM-DD>.md`.

| Audit | Covers |
|-------|--------|
| [audits/RELEASE_ASSET_REGRESSION_2026-09-27.md](audits/RELEASE_ASSET_REGRESSION_2026-09-27.md) | The beta.3/beta.4 asset-less release regression: root cause, three-arm fix, healing procedure |
| [audits/LIMITER_EAGLE_EYES_DEPTH_AUDIT_2026-09-27.md](audits/LIMITER_EAGLE_EYES_DEPTH_AUDIT_2026-09-27.md) | The limiter and eagle-eyes depth audit: per-dimension verdicts against the eBPF ceiling, two userspace fixes (recover's dead-group sweep, the byte-ranked top consumer), seven doc truths corrected, the counter-map eviction gap deferred to the prebuilt-refresh cycle |

## Project Meta

| Doc | Covers |
|-----|--------|
| [BRANDING.md](BRANDING.md) | Visual identity: the purple, the dragon, the tone |
| [../QA.md](../QA.md) | Owner question ledger — questions asked and answered, with dates |
| [../CHANGELOG.md](../CHANGELOG.md) + [../CHANGELOG-V11-ERA.md](../CHANGELOG-V11-ERA.md) | What shipped, per release and per era |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute: the gate battery, commit discipline |
| [../CLA.md](../CLA.md), [../COMMERCIAL_LICENSE.md](../COMMERCIAL_LICENSE.md), [../TRADEMARK.md](../TRADEMARK.md), [../NOTICE](../NOTICE) | Contribution licensing, commercial terms, trademark policy, root legal notice |
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
