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
  latest kernel). Since NIGHT-improve-48 the VM rootfs ships the
  battery's own diagnostic tools (nftables plus a staged
  /usr/bin/bpftool — the real-user shape, both one apt away on any
  desktop), so the pure-eBPF ruleset snapshot, the bpftool
  visibility row, and the footprint's kernel run-time numbers run
  on every leg instead of skipping tool-absent; a host without the
  tools still answers honestly (the row names the missing tool,
  never guesses).
- **PIN** — a rootless test that fails the suite if the claim
  regresses: `cargo test --features ebpf` (the `test/` tree).
- **CI** — a workflow surface that enforces the claim on every push
  or release.

## The five headline claims (the proof harness)

| # | Claim | LIVE row (proof-claims) | PIN / CI |
|---|-------|------------------------|----------|
| 1 | **No daemon** — enforcement survives process exit | `no-daemon`: process set must not grow across an attach; a download stays policed after the CLI exits (the ceiling verdict: un-policed traffic would blow through 1.30x the rate at baseline and fail immediately; under-delivery is TCP recovery physics — the Z5 doctrine — with a silent-zero guard failing a window that delivered under one GSO skb) | supermassive v1 reload/sustain rows; the pinned-link surface in `pin.rs` |
| 2 | **Pure eBPF** — no tc/nft/LD_PRELOAD | `pure-eBPF`: ruleset structure snapshot + kernel drop counters + bpftool's attach-mechanism-independent surfaces | nft/tc normalization pins (engine self-test); CI runs the engine self-test on every push |
| 3 | **Per-app per-cgroup** | `per-app`: cgroup A stays inside its configured rate (the ceiling — an unshaped A reads baseline and fails immediately) while its unlimited neighbor rides ≥50x above, same moment; every patience sample rides the row detail | witness-floor pins; group-lane shared-bucket rows (supermassive v1) |
| 4 | **Precision 0.00%** | `precision`: kernel-admitted bytes vs configured rate × wall time over a saturating window, cross-checked against the client counter — the row prints the residual and the PASS bound's derivation (estimator floor + the token bank's one-burst wander, `burst/(rate × window)`; under-side windows re-attempt bounded — the quick-row closure v3), it rounds nothing; the offer-test discriminator (improve-48, v2 by mitigate-2): an under-band window whose hook-level offer (admitted + refused) never reached the budget is offer-limited — refusals or not, a sagging offer's bursts refuse without presenting a budget-scale surplus — so it re-attempts at 80% of its own offer and SKIPs honestly on a repeat (an offer-limited window measures the offer, not the policer), while under-band AT budget scale stays the red real-regression signature | the token math pinned rootlessly: `test/ebpf/limiter/math_tests.rs` (steady-state exactness, fractional carry) + the budget-covers pair (lts-8, contention) |
| 5 | **Resource honesty** — the CLI's own RAM/CPU/IO + kernel cost (lts-6) | `footprint`: wait4 rusage of a canonical attach (peak RSS, CPU seconds, block IO — real numbers printed) + bpftool `run_time_ns`/`run_cnt` (average ns per attached-prog run; the kernel collects those fields only while `kernel.bpf_stats_enabled` is on, so the harness turns the knob on for its window and writes the original value back — lts-6 followup 3) | verdict-math + stats-knob-plan pins (engine self-test); idle-frame zero-emit: `test/terminal/diff_tests.rs` |

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
| Group lifecycle: 256-slot maps stay proportional; no silent-unlimited | USAGE/STABILITY (lts-7) | dead-group decision pins; BPF fallback (schema v8); supermassive group-lane rows | verified |
| Theme accuracy: brand/ok on computed nearest cube cells | BRANDING 2.2 (lts-9) | the computed walk pins (`test/output/theme_palette_tests.rs`) | verified |
| Monitor survives boot-edge start (no epoch underflow panic) | STABILITY Time row (lts-7) | beat-epoch floor pin (`mouse_contract_tests.rs`) | verified |
| Sudo rescue does not fight the user's shell | USAGE/SAFETY_ANALYSIS (improve-34) | discrimination-matrix pins + the live sudo-interposer harness (scratch, owner-runnable) | verified |
| Package lifecycle: install verifies the binary before landing; uninstall clears enforcement first, never under `--user` | README "the package scripts" note (improve-15) | `scripts/depth/install-flow-test.sh` (root run, blade-8: the 6-row lifecycle — `--user` and root-without-sudo installs, enforcement-before-uninstall, the no-escalation `--user` uninstall, enforcement-first `--all`, idempotent re-run) | verified |

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

CI re-proves continuously: the wholesale gate suite on every push
(gate-keepers.yml, unfiltered), the engine self-test and the Rust
matrix on every code-surface push (ci.yml, path-filtered), the
claims harness LIVE on the supermassive legs when their surface
moves, the release invariants on every tag, and CodeQL weekly plus
on every Rust-surface push — the cadence row names the filters
every lane actually carries (NIGHT-hunt-Z8: the former "on every
push" wording claimed surfaces the path filters never woke).

## The honest residuals (claimed limits, not hidden ones)

- The starved-window closure (improve-48, the runs 224/228
  lesson): the shared runners' busy hours can leave the precision
  row's four-flow aggregate unable to OFFER the 100mb refill —
  the long-run row read 21.297%/29.775% under with zero
  refusals while admitted==client held at ratio 1.004 (the
  policer passed every offered byte; the offer itself integrated
  under the rate — the same host's quieter hours read 1.921% on
  the same kernel, and the 5.13 floor legs read 3.606% on the
  same runs). The row discriminates before it verdicts, and
  mitigate-2 refined the gate from refusals to the budget scale
  itself: an under-band window whose hook-level offer (admitted
  and refused summed) never reached the budget is offer-limited — the
  2b269f73 best-gnu leg's mixed shape (878.8 MB offered vs a
  1000.5 MB budget, 134.1 MB refused in burst instants, admit
  ratio 1.0070) wears refusals without ever presenting a
  budget-scale surplus, a host whose fleet sagged, not a broken
  token math — so it re-attempts at 80% of its own offer (capped
  at the configured rate, floored at the 5mb loopback GSO-safe
  rung) and a second offer-limited window — or an offer below
  the floor — records the honest SKIP instead of failing the
  lane on the host's own poverty; a budget-scale under-admission
  stays red on the attempt that produced it, and a
  budget-scale reading whose re-attempt cannot present the
  budget again is inconclusive (SKIP, every number attached).
  The evidence rows (the TCP-level offer, the admit-ratio) ride
  every verdict unchanged.
- The BIG TCP corner: opt-in per-link `gro-max-size` above 64 KiB
  (kernel 6.x) can still hand the hook a super-packet above the
  burst floor — an inherent property of any bounded bucket
  (STABILITY honest limit 4).
- The loopback window regime: a measurement window whose refill
  cannot bank a whole 64 KiB skb sees bimodal delivery on loopback
  — physics, window-aware in the harness model.
- The live precision residual: the instrument's own floor, derived —
  the estimator's sampling jitter (the midpoint cancellation) plus
  the TOKEN BANK's wander: the cushion is one default_burst (a full
  second of the rate at 100mb), and under a drop-only policer the
  aggregate's AIMD dips bank tokens while the overshoots drain them,
  so a window that starts and ends at different bank levels reads
  off by up to one burst — burst/(rate x window), 10% on the quick
  10s window, 3.3% on the full 30s, measured identical across one
  flow and a four-flow aggregate on the CI legs (3.8-6.1%) while a
  tight host reads the estimator floor alone (0.945%). The PASS
  bound carries both terms and prints its derivation; the row prints
  the actual number and every under-side re-attempt, never rounded
  away. The first quick-row closure called this residual "sampling
  jitter"; the live CI legs disproved that honestly — the rounds'
  story is in the CHANGELOG's quick-row entries.
- The quick-row closure v2 (task 8, the GIL find): the quick lane's
  four red rows on the shared CI runners — no-daemon 41.9%, per-app
  30.3%, precision TCP 62.2%, token error 37.682% — were the
  HARNESS's own throttle, not enforcement. The old engine ran the
  data source as a thread inside the harness process, sharing one
  python GIL with the measuring client thread; on the shared
  runners that coupling could not feed the policer (the same legs
  read 109.0% at 100mb and 101.5% at 2mb through the limiter
  matrix's decoupled worker shape, same commit, same kernels). The
  server is now a worker subprocess — the kernel's socket buffers
  pace the pair, not a python lock — and every measured rate row
  rides the lib's one-sided patience (in-band stops, over-band
  fails now, all-under fails after the attempts, every sample
  printed). The full-mode 30 s windows amortized the coupling on
  every host the owner ran; the shared runners did not forgive it.
- The quick-mode no-daemon row measures steady state: the cold-start
  transient of a fresh attach (flow-bucket carry banking while TCP
  backs off its first losses) is attach physics, not enforcement —
  the quick lane settles past it before its measured window, and
  the window re-samples under-side through the same one-sided
  patience the matrix proved on every CI leg.
- The held-rate rows measure the fleet and verdict by the ceiling
  (NIGHT-mitigate-2 + mitigate-3, the 37583456726 and 37588414621
  lessons): a cgroup-held rate is a cgroup-level truth, so the
  no-daemon and per-app windows read the sum of `RATE_ROW_FLOWS =
  4` concurrent connections, not one AIMD sawtooth — and a
  drop-only policer promises the CEILING, never the floor (the
  hunt-Z5 doctrine, the matrix's own law for this physics class:
  its fair-share single row passes at 36.9% with "the ceiling
  carries the verdict"). The fleet's convergence assumption held
  at high rates (the precision row's 95-102%, the many24 row's
  102.4%) but the busy-hour pool reddened three legs at 36-44% of
  2-5mb policies with the policer alive and the witness holding
  11.8 GB/s side by side — the AIMD equilibrium under a drop-only
  policer is rate-dependent, flow count is not the variable. So
  the rows verdict on the ceiling (lo=0.0, hi 1.30 unchanged —
  over-delivery still fails immediately, never retried away), a
  silent-zero guard fails a window under one GSO skb (a broken
  pair, not physics), every patience sample still rides the
  detail, and the kernel-side rate-HOLDING stays where it is
  provable: the precision row's offer-tested window and the
  rootless math pins. Pinned rootlessly, both laws.
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
