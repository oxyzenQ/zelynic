<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Claims Verification (the ledger)

Every claim zelynic makes maps to a mechanism that verifies it —
this is the ledger of that mapping, born from the NIGHT-lts-6
mandate: *"proof of 0.00% error rate … verify ram, cpu, io, etc
usage. be honest this project is critical infra not a toy/gimmick …
all claim on zelynic need verify and report to docs."*

A claim with no mechanism is marketing; the rule here is that no
row ships without one. The mechanisms come in three strengths:

- **LIVE** — proven on a real kernel by a harness you can run:
  `sudo ./scripts/bench/proof-claims.sh` (the five headline claims,
  ~1 min; `--quick` for 30 s windows). Since NIGHT-lts-6 this
  harness also runs LIVE inside both supermassive CI legs on every
  push (the impish 5.13 floor kernel and the dynamically resolved
  latest kernel).
- **PIN** — a rootless test that fails the suite if the claim
  regresses: `cargo test --features ebpf` (the `test/` tree).
- **CI** — a workflow surface that enforces the claim on every push
  or release.

## The five headline claims (the proof harness)

| # | Claim | LIVE row (proof-claims) | PIN / CI |
|---|-------|------------------------|----------|
| 1 | **No daemon** — enforcement survives process exit | `no-daemon`: process set must not grow across an attach; a download stays policed after the CLI exits | supermassive v1 reload/sustain rows; the pinned-link surface in `pin.rs` |
| 2 | **Pure eBPF** — no tc/nft/LD_PRELOAD | `pure-eBPF`: ruleset structure snapshot + kernel drop counters + bpftool's attach-mechanism-independent surfaces | nft/tc normalization pins (engine self-test); CI runs the engine self-test on every push |
| 3 | **Per-app per-cgroup** | `per-app`: cgroup A shaped at its rate while its unlimited neighbor rides ≥50x above, same moment | witness-floor pins; strict-multi shared-bucket rows (supermassive v1) |
| 4 | **Precision 0.00%** | `precision`: kernel-admitted bytes vs configured rate × wall time over a saturating window, cross-checked against the client counter — the row prints the residual (the status-read spawn latency), it rounds nothing | the token math pinned rootlessly: `test/ebpf/limiter/math_tests.rs` (steady-state exactness, fractional carry) + the budget-covers pair (lts-8, contention) |
| 5 | **Resource honesty** — the CLI's own RAM/CPU/IO + kernel cost (lts-6) | `footprint`: wait4 rusage of a canonical attach (peak RSS, CPU seconds, block IO — real numbers printed) + bpftool `run_time_ns`/`run_cnt` (average ns per attached-prog run) | verdict-math pins (engine self-test); idle-frame zero-emit: `test/terminal/diff_tests.rs` |

The 0.00% claim told honestly (the two levels): the CONTRACT is
the token math — long-run admitted bytes equal rate × elapsed
exactly, with sub-byte fractional carry, pinned by rootless tests;
the LIVE row measures what a process boundary can measure
(kernel-admitted vs configured over a wall-clock window) and prints
its actual residual instead of claiming a round zero. A number that
cannot be measured at a boundary is not claimed at that boundary.

## The full inventory

| Claim | Where | Mechanism | Status |
|-------|-------|-----------|--------|
| Pinned `bpf_links`, zero battery drain | README "What makes zelynic sharp" | claims 1 + 5 (LIVE); link pinning in `src/ebpf/pin.rs` | verified |
| Fractional precision 0.00% | README sharp table + vs-table | claim 4 (LIVE + PIN) | verified |
| Schema migration auto-detected + auto-cleaned | README sharp table | schema-version mismatch → reload: `src/ebpf/limiter/types.rs` + `SCHEMA_VERSION_EXPECTED` pin | verified |
| Crash recovery (`zelynic recover`) | README sharp table | `scripts/depth/crash-recovery-test.sh` (root run) + supermassive v2's crash-family teardown | verified |
| Discovery workflow (eagle-eyes) | README sharp table | supermassive v2 TUI lanes on a pty; monitor/surface pins in `test/` | verified |
| Box mode, clean exit, responsive layout | README sharp table | diff/guard pins (`test/terminal/`); v2 kill-tui battery | verified |
| Diff-based rendering, idle frames cost zero I/O | README sharp table | `idle_frame_emits_zero_bytes` + the tall-regime twin (`test/terminal/diff_tests.rs`) | verified |
| `--interval 1s..60s`, session totals, footer speed pair | README sharp table | interval bounds pins (`monitor.rs` tests); footer/session render pins | verified |
| Eagle-eyes detail rows (pid → endpoint) | README sharp table | detail render pins (`test/ebpf/render/detail_tests.rs`) | verified |
| Strict dependency diet: 7 direct deps, 54 lockfile crates | README + DEPENDENCY_AUDIT | counted live at audit time: `anyhow aya clap libc nix serde serde_json` = 7; Cargo.lock = 54 packages; `cargo deny check all` on every push | verified (re-count on demand: see below) |
| Kernel 5.13+ floor, cgroup v2, root | README requirements | `doctor`; KERNEL_COMPATIBILITY matrix; supermassive boots the true 5.13 floor kernel + latest on every push | verified |
| Release tarballs: 3 checksums + GPG, four arch baselines | README release section | release.yml verifies checksums and signatures before upload; lts-9's version/parity/passphrase invariants; VERIFY_RELEASE.md's user flow | verified (CI-enforced) |
| Local alias builds reproduce the release tier | README arch-baseline section | gate 17 `check-release-parity.sh` on every push | verified (lts-9) |
| Scale contract: wrap-coherent counters, u128 ledger, ZB/QB ladder | USAGE (lts-5) | wrap-coherence + wide-ladder pins (`loader_wrap_tests.rs`, `format_wide_tests.rs`, footer census pin) | verified |
| Extreme-burst: no false drops of affordable packets; every packet class admissible | USAGE/STABILITY (lts-8) | budget-covers pin pair; burst floor boundary pins; harness window model pins | verified |
| Group lifecycle: 256-slot maps stay proportional; no silent-unlimited | USAGE/STABILITY (lts-7) | dead-group decision pins; BPF fallback (schema v8); supermassive strict-multi rows | verified |
| Theme accuracy: brand/ok on computed nearest cube cells | BRANDING 2.2 (lts-9) | the computed walk pins (`test/output/theme_palette_tests.rs`) | verified |
| Monitor survives boot-edge start (no epoch underflow panic) | STABILITY Time row (lts-7) | beat-epoch floor pin (`mouse_contract_tests.rs`) | verified |
| Sudo rescue does not fight the user's shell | USAGE/SAFETY_ANALYSIS (improve-34) | discrimination-matrix pins + the live sudo-interposer harness (scratch, owner-runnable) | verified |

## Re-proving, on demand

```bash
# the five headline claims, live on your kernel (~1 min):
sudo ./scripts/bench/proof-claims.sh

# every rootless pin (all tables above):
cargo test --features ebpf

# the dependency count, counted fresh:
python3 - <<'PY'
import re, tomllib
t = tomllib.load(open("Cargo.toml", "rb"))
print("direct deps:", len(t["dependencies"]))
print("lockfile packages:", len(re.findall(r'\[\[package\]\]\nname', open("Cargo.lock").read())))
PY
```

CI re-proves continuously: the engine self-test and the full gate
suite on every push (ci.yml + gate-keepers.yml), the claims harness
LIVE on both supermassive legs, the release invariants on every
tag, and CodeQL on every push.

## The honest residuals (claimed limits, not hidden ones)

- The BIG TCP corner: opt-in per-link `gro-max-size` above 64 KiB
  (kernel 6.x) can still hand the hook a super-packet above the
  burst floor — an inherent property of any bounded bucket
  (STABILITY honest limit 4).
- The loopback window regime: a measurement window whose refill
  cannot bank a whole 64 KiB skb sees bimodal delivery on loopback
  — physics, window-aware in the harness model.
- The live precision residual: the status-read spawn latency
  against the window, printed by the row, never rounded away.
- The footprint bounds are regression fences, not bragging rights:
  the rows print the real numbers they measured.

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
