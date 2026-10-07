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
| [INNOVATIONS.md](INNOVATIONS.md) | The innovation ledger: the thirteen research wins that define the engine (AMMSP through time windows), plus the two retired by verdict |
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
| [research/NIGHT_PRIVATE_RESEARCH_2_AMMSP_DESIGN.md](research/NIGHT_PRIVATE_RESEARCH_2_AMMSP_DESIGN.md) | The AMMSP design brief: the owner's subtree-coverage directive, the verified root cause (a child cgroup escapes the limit entirely — not separately bucketed), the four candidate designs with the fentry plan's rejection record, the chosen ancestor-walk + LRU memo, the risk register, and the 32-level bound stated plainly |
| [research/NIGHT_DINNER_14_PRICING_RESEARCH.md](research/NIGHT_DINNER_14_PRICING_RESEARCH.md) | The tier-pricing decision brief: consumer and commercial comparables with sourced prices, analysis against the Individual/Business/Company tiers, and the owner's option matrix — with section 7 recording the executed decision (Business $1,990/yr, Company $14,990/yr, Individual holds), superseded 2026-09-30 by NIGHT-dinner-25's owner calibration: Business $2,199/yr, Company $20,199/yr, the masterpiece rationale — current list in COMMERCIAL_LICENSE.md |
| [research/NIGHT_PRIVATE_RESEARCH_4_TIME_WINDOWED_POLICIES_DESIGN.md](research/NIGHT_PRIVATE_RESEARCH_4_TIME_WINDOWED_POLICIES_DESIGN.md) | The time-windowed policies design brief (the owner's `--time 10:10` question answered): the three grammar candidates with the single-instant flag rejected on the record (a future actor is a daemon; deferred start is a window), the wall-clock wall of BPF and the offset bridge that crosses it daemonlessly, the side-map placement with the rate_ring sketch's correction, the honest LOC, and the `--until` then `--during` sequencing recommendation — research only, no implementation |

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
| [audits/NIGHT_HUNT_Z10_UID_LANE_SWEEP_2026-10-03.md](audits/NIGHT_HUNT_Z10_UID_LANE_SWEEP_2026-10-03.md) | The uid-lane sweep (the CI-repair follow-up, "until all peak no remainings"): every binary-driving instrument crossed with every CI leg and its uid — verdict zero remainings, the Z9 shadow rows were the class's only instance; v3's both-direction lane split, the fail-fast refusals (exits 2/2/1/2 verified live), nonroot-depth's refuse-root inverse guard, and the Rust tree's lane-adaptive assertions on the record with the declined investments |
| [audits/NIGHT_TOTAL_LTS_4_AUDIT_2026-10-03.md](audits/NIGHT_TOTAL_LTS_4_AUDIT_2026-10-03.md) | The total-infra cross-check audit: the infrastructure no prior pass covered end to end (the crash-recovery stack, the raw-fd input parsing, the harnesses themselves), the v4 battery's binary resolution returned to the shared discipline (no more 75-row false-red walls on fresh clones, no more ungated foreign-binary testing), every instrument run fresh, and the peak-skip list on the record |
| [audits/NIGHT_TOTAL_LTS_5_AUDIT_2026-10-03.md](audits/NIGHT_TOTAL_LTS_5_AUDIT_2026-10-03.md) | The killer-features depth audit round two: the surfaces lts-3 never named read line by line (the kernel observer modules, the ingestion path, the diff engine), the dinner-6/lts-5 audit seam found and closed — the LRU eviction restart read as a u64 wrap produced an 18-EB phantom on the rate column, the session leaderboard, and the --depth shadow audit, killed by the half-space discriminator in the one boundary every poll delta flows through (plus the stale "backwards step is a wrap" claim rewritten, the wrap pins 5 -> 9, and the byte-exact A/B) |
| [audits/NIGHT_HUNT_Z7_ENFORCEMENT_LEDGER_AUDIT_2026-10-03.md](audits/NIGHT_HUNT_Z7_ENFORCEMENT_LEDGER_AUDIT_2026-10-03.md) | The enforcement-ledger depth audit (the owner's dual-limit find): the probe's two false-negative shapes (counter-direction ACK starvation, the unsaturable ceiling) closed by graduating the ledger's dropped counters to verdict evidence — the ledger-refusal proof, the leak lane, the reason stack, the budget-truth note — plus exact config-rate display, the measured-zero/BLOCKED fix, and the comma repairs |
| [audits/NIGHT_HUNT_Z9_CLI_ECHO_BOUNDARY_AUDIT_2026-10-03.md](audits/NIGHT_HUNT_Z9_CLI_ECHO_BOUNDARY_AUDIT_2026-10-03.md) | The CLI echo-boundary hardening audit (total CLI sweep after Z7): terminal injection through the CLI's own error/warn echoes closed at the one render boundary every path flows through, the shadowed positional rate parsed-and-named (the silent drop and the unparsed typo), the hidden probe roles pulled from clap's typo suggestions — plus the v4 battery's stage 9 (32 rows: hostile payload families x echo paths, shadowed-positional ladder, hidden-vocabulary cases) and the verified-clean list |
| [audits/NIGHT_TOTAL_LTS_1_AUDIT_2026-10-02.md](audits/NIGHT_TOTAL_LTS_1_AUDIT_2026-10-02.md) | The total-infra LTS sweep: the owner's five areas (stability & crash, code hygiene, optimization, security hardening, LTS stability) audited per-stage across the root repo at the locked v20.0.0 LTS baseline, the peak-skip protocol in force |
| [audits/NIGHT_TOTAL_LTS_2_AUDIT_2026-10-02.md](audits/NIGHT_TOTAL_LTS_2_AUDIT_2026-10-02.md) | The fresh-instrument cross-check: every load-bearing claim of the total-lts-1 verdict re-verified against source and fresh runs at HEAD — never against the earlier doc's own claim |
| [audits/NIGHT_TOTAL_LTS_3_AUDIT_2026-10-02.md](audits/NIGHT_TOTAL_LTS_3_AUDIT_2026-10-02.md) | The killer-features pass: the total-infra lens narrowed to the product's two killer surfaces first (the limiter engine and the eagle-eyes monitor), then the UX/CLI surface and the remaining Rust code, under the same five areas |
| [audits/NIGHT_THINK_LIKE_LIGHT_YEARS_3_AUDIT_2026-09-30.md](audits/NIGHT_THINK_LIKE_LIGHT_YEARS_3_AUDIT_2026-09-30.md) | The extreme-burst endurance re-audit: the init-path wholesale reset closed with schema v11 (BPF_NOEXIST — no token resurrection or stamp rollback at a fresh bucket's birth under many-CPU fire), the dense-host poll merge goes linear, and the three LTS questions (endurance, ultra-scale, adaptive flex) answered against the source with the declined investments on the record |
| [audits/NIGHT_PERF_2_AMMSP_ENDURANCE_ULTRA_SCALE_AUDIT_2026-09-30.md](audits/NIGHT_PERF_2_AMMSP_ENDURANCE_ULTRA_SCALE_AUDIT_2026-09-30.md) | The AMMSP endurance and ultra-scale audit (the perf trilogy): the per-packet cost budget at HEAD, the trillion-packet math (what accumulates — nothing; what wraps — every counter with its horizon), the memo hit-rate model with the dense-host regime, the mutation-storm lane after the O(1) bump, and the ready-but-untaken lifts with the reasons on the record |
| [audits/NIGHT_PRIVATE_RESEARCH_2_AMMSP_AUDIT_2026-09-30.md](audits/NIGHT_PRIVATE_RESEARCH_2_AMMSP_AUDIT_2026-09-30.md) | The AMMSP implementation audit: what shipped (the walk, the memo, the flush, the LRU lane twin, the schema-v10 split), the decisions made in the building (nested roots shipped now, the stale GPL comment corrected), the local verification battery, and the honest residuals |
| [audits/NIGHT_PRIVATE_RESEARCH_3_AUDIT_2026-09-30.md](audits/NIGHT_PRIVATE_RESEARCH_3_AUDIT_2026-09-30.md) | The depth-traffic focus and report-compaction audit: the depth report's basic-census gap closed with the observer focus window (`--focus 1s..30s`), the compact-and-simple pass over status/list-apps/depth, the honest bounds of kernel totals vs endpoint attribution, and the frame A/B parity proof |
| [audits/NIGHT_UPGRADE_CHARGER_CORE_1C_PROBE_CI_FIND_2026-09-30.md](audits/NIGHT_UPGRADE_CHARGER_CORE_1C_PROBE_CI_FIND_2026-09-30.md) | The probe's CI find: the open lane on the record — what the red supermassive legs showed, the harness-lane bypass (`--no-probe` in proof-claims), and why the lane's bug stays OPEN pending a root machine to debug |
| [audits/RELEASE_PARSER_EMPTY_VALUE_2026-09-29.md](audits/RELEASE_PARSER_EMPTY_VALUE_2026-09-29.md) | The v11.0.0 stable publish regression: the release body parser's empty-value crash — root cause, the same-session heal (NIGHT-dinner-26), and the one-run regression window |
| [audits/RELEASE_ASSET_REGRESSION_2026-09-27.md](audits/RELEASE_ASSET_REGRESSION_2026-09-27.md) | The beta.3/beta.4 asset-less release regression: root cause, three-arm fix, healing procedure |
| [audits/LIMITER_EAGLE_EYES_DEPTH_AUDIT_2026-09-27.md](audits/LIMITER_EAGLE_EYES_DEPTH_AUDIT_2026-09-27.md) | The limiter and eagle-eyes depth audit: per-dimension verdicts against the eBPF ceiling, two userspace fixes (recover's dead-group sweep, the byte-ranked top consumer), seven doc truths corrected, the counter-map eviction gap deferred to the prebuilt-refresh cycle |

## Archive

Frozen historical records relocated out of the living tree —
readable in every checkout, never rewritten.

| Archive | Covers |
|---------|--------|
| [archive/CHANGELOG_PRE_V11.md](archive/CHANGELOG_PRE_V11.md) | The pre-v11 release history: changelog entries [1.0.0] (2026-01-01) through [7.0.0] (2026-07-11) — the deleted v10-era file, restored byte-identical from git history into docs/archive/ by NIGHT-dinner-15 (2026-09-28), superseding NIGHT-hunt-18's git-history-only call |

## Project Meta

| Doc | Covers |
|-----|--------|
| [BRANDING.md](BRANDING.md) | Visual identity: the purple, the dragon, the tone |
| [../QA.md](../QA.md) | Owner question ledger — questions asked and answered, with dates |
| [../CHANGELOG.md](../CHANGELOG.md) + [archive/CHANGELOG_PRE_V11.md](archive/CHANGELOG_PRE_V11.md) | What shipped: the v11-era active file and the pre-v11 archive (the frozen v11 campaign history lives in git history alone — NIGHT-dinner-19 removed the root duplicate) |
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
