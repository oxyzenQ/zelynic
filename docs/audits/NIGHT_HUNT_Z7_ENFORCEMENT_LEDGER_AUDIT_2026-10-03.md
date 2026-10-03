<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# NIGHT-hunt-Z7: the enforcement-ledger depth audit (2026-10-03)

The owner's live find, verbatim from the terminal that started this
audit: a dual-limit apply (`strict-single brave -d 1kb -u 1kb`)
answered `enforced: UNVERIFIED` with `measured: 0 B in 3s (BLOCKED)
vs 1.0 KB/s target`, `budget: 68.5 KB`, `kernel: 549 B admitted
through the ledger` — while the very next `status` grep showed the
same target's row carrying `68.4 KB 502.9 KB` in the allowed/dropped
columns. The kernel's own ledger was sitting on 731 KB of REFUSED
traffic across brave's two cgroups while the probe said it could not
verify the limit it had just written. This audit is the depth read
of that contradiction and the hardening that closed it.

## The two false-negative shapes

The probe's verdict was decided by ONE input: the client's received
bytes against the flow band (floor = 20% of the window's refill,
ceiling = budget + 5% + one GSO super-packet). Two live shapes land
under the floor while enforcement demonstrably bites:

1. **Dual-direction starvation.** The probe client nests UNDER the
   target; its TCP acknowledgments are EGRESS traffic of the same
   policed subtree. With `-d 1kb -u 1kb`, the ACK stream spends the
   upload bucket beside the browser's own chatter — and the target's
   own traffic competes for the download bucket's 1 KB/s refill
   beside the probe's data. The flow collapses to ~0 B; the floor
   (600 B) is never crossed; the verdict reads UNVERIFIED. The
   owner's own status output carried the refutation the whole time:
   228.8 KB and 502.9 KB dropped (the status table's `dropped`
   column is `cgroup_limiter_stats.bytes_dropped` — the kernel's
   own record of what it refused).

2. **The unsaturable ceiling.** `-d 1tb`: the floor is 20% of
   3 TB = 600 GB; the window's loopback moved 807 MB (269 MB/s —
   the path, not the policy, was the constraint). No flow this
   machine can generate crosses that floor, so the verdict is
   structurally UNVERIFIED — and nothing refused (drops 0: the
   budget is never binding), so the old output had no way to say
   WHICH untestable it was.

## The close: the ledger graduates to verdict evidence

`LimiterStatsRaw` has carried `bytes_dropped` since schema v5 (the
drop-booking lane) — the probe read the map and threw the refused
half away, keeping only `bytes_allowed` for the display row. The
hardening is pure userspace (zero BPF changes, zero schema
movement):

- **The full snapshot.** The orchestrator now reads both counters
  for EVERY leaf the target resolved to (one map iteration), before
  and after the window, and computes per-leaf allowed/dropped
  deltas.
- **The ledger-refusal proof.** A starved flow (under the floor)
  whose window shows refusals inside the combined envelope is
  VERIFIED — the kernel refused offered traffic beyond the budget;
  the refusal IS the enforcement, booked by the kernel itself. A
  new `proof:` row names the basis (and the starved flow check) so
  it is never conflated with the flow's own numbers. The owner's
  dual-limit transcript now answers VERIFIED with the refused
  count in the kernel row.
- **The leak lane.** A ledger that ADMITS beyond the envelope is
  FAILED — exit 1, the headline naming the kernel's over-admission
  — whatever the flow measured (the leak a starved flow could never
  see; a passing flow over a leaking ledger fails too: the leak
  veto outranks the flow band). The envelope deliberately carries
  (window + 2s) of refill per direction plus the 5% + super-packet
  slack, because the ledger delta brackets the 3s window with spawn
  grace, connect retries, and teardown — a veto that false-fires on
  boundary effects would be worse than the silence it replaced.
  Per-socket policies skip the leak lane (every connection spends
  its own bucket; the count is unknown at probe time) but keep the
  refusal proof (drops need no envelope).
- **The honest reasons.** The single `note:` slot became a stack:
  the counter-direction starvation note (the probe's own ACKs ride
  the policed upload at 1.0 KB/s), the unsaturable-ceiling note
  (the flow floor exceeds what this path delivered, nothing
  refused), the per-leaf window ledger on the multi-cgroup note
  (`cg:A X in / Y refused, cg:B ...`), and the budget-truth note —
  the DRR pool's own token count at window open, read through the
  new `read_pool_tokens` (a re-apply inherits a spent bucket; the
  nominal "budget: 68.5 KB" line no longer pretends the burst was
  there). The concurrent-traffic note keeps its old wording but now
  runs only on single-direction applies (with both legs policed,
  the ledger's combined-direction bookings inflate the gap by
  construction).
- **The teardown belt widened.** A dual apply's premise is both
  legs — the belt now re-reads every policed leg of the probe's
  leaf, not just the probed direction.

## The display lies, closed beside them

The same transcript exposed three display seams, all closed:

- **Configured rates rounded.** `-d 100.51kb` displayed as
  "100.5 KB/s" on every surface (the one-decimal formatter's
  rounding hid 10 B/s of the owner's typed number). New
  `format_bytes_exact`/`format_rate_exact`: minimal decimals that
  round-trip through the production parser (pinned as a property
  test), honest-tier walk (999,950 stays "999.95 KB", never the
  one-decimal twin's "1.0 MB" round-up), exact-B fallback at the
  u64 extreme. Wired into the apply trace, the status table's rate
  cells, and the verify block; MEASURED values (counters, measured
  flows, the monitor's live rates) keep the one-decimal display —
  the split is config-exact vs measured-approximate.
- **A measured zero rendered "(BLOCKED)".** `figures(0, 3)` called
  `format_rate(0)` — the policy surface's BLOCKED sentinel — so the
  measured row read "0 B in 3s (BLOCKED)" as if the policy were a
  block. Measured zero is `0 B/s` (the render footer's own
  documented discipline).
- **The comma non-repair.** `100,50kb` died with "expected digits
  before the decimal point, got '100,50'" — the digits were there;
  the separator was the crime. The number layer now diagnoses the
  comma's shape: the locale decimal (`100,50` → write `100.50`), the
  thousands grouping (`1,000` → write `1000`; the dot suggestion
  would silently scale the value 1000x), a leading comma (`,5` →
  `0.5`), and the malformed rest (the rule, no fabricated repair).
  The tip engine stands down on comma inputs — one input, one
  repair.

## What was checked and found healthy

- The rate PARSER was already exact (u128 mantissa/scale, no f64
  anywhere — NIGHT-boost-15's contract held; the 31-digit fraction
  the owner typed parsed to exactly 100,510 B/s). The display was
  the liar, not the grammar.
- The status table's columns were already honest (`allowed` /
  `dropped` — the dropped column is what made this audit possible).
- `--res` answering with the `--reset-terminal` tip (the owner's
  first transcript line) is clap's own suggestion engine working as
  designed — no action.
- Leading zeros (`01kb`), the sub-minimum guard (`0.1kb` → the
  --force-this hint), and the 64-bit overflow guard were all
  already correct.

## Verification

- 666 unit tests passed, 0 failed (the 19 new pins: the dual-limit
  starvation block, the leak lane and its span-allowance edge, the
  per-socket lane skip, the unsaturable ceiling, the starved-notes
  stack, the exact-formatter pins, the round-trip property, the
  comma repairs, the exact status cells, the exact apply trace).
- clippy clean, rustfmt clean, every touched file under the 500-LOC
  owner cap (probe.rs 492, probe_report.rs 491, probe_role.rs 422 —
  the cgroup mechanics and map-read families moved to the role
  module under the same split discipline the waiting family set).
- The supermassive battery's probe rows updated to the new kernel
  row (both counters) and the third failure lane; the direction-lane
  pins keep their intent (a nonzero admission the ledger booked).

## Residuals, on the record

- The ledger is combined dl+ul per leaf — the refusal proof on a
  dual apply names the PAIR's engagement, not the per-direction
  split (a per-direction dropped counter would need a schema bump;
  declined: the note says what the ledger can honestly say).
- The second probe leg (probing the upload side when the download
  flow starves) was considered and declined: the refusal proof
  covers engagement without doubling the starved path's latency.

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
