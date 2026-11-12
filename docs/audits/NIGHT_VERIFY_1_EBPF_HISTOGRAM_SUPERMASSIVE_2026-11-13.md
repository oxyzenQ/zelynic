<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# night-verify-1 — the eBPF histogram's supermassive proof (and the two perpetually Skipped rows)

Date: 2026-11-13. Owner's two asks in one session: (1) "run CI with
contains schedule matrix to verify fail or not" — the two
`matrix.title` rows that answered Skipped on every push; (2)
"night-verify-1: need verify after implemented this innovation put
on supermassive test — 1. ebpf histogram".

## Find 1: the Skipped rows were schedule-only lanes never exercised by push CI

The two rows the owner always saw Skipped are the night trains:
`supermassive-desktop` (Dragon Guard - Supermassive) and
`supermassive-e2e-endurance` (Dragon Guard - Supermassive E2E),
both `if: github.event_name == 'schedule' || workflow_dispatch`
since night-T-1 — a push can never run them, so the check renders
as the literal unresolved `matrix.title` with verdict Skipped.

Verification of "fail or not": both workflows were dispatched by
hand on main (workflow_dispatch passes both jobs' gates) before the
conversion — and the answer was NOT green. The E2E dispatch run
completed FAILURE: all three endurance-clock legs (the jammy floor
kernel, the archive's latest kernel, the native arm64 host) failed
on the same row —

    X  pin-family: pin set — 48 pins after first apply, expected 44,
       extra: depth_hist_dl, depth_hist_ul, hist_sample_tick,
       hist_zero_row

— while the fast and surface legs passed. The endurance suite's
PIN_FAMILY set (scripts/depth/endurance-test.py) was never grown
with schema v34 (night-frontier-2B added the histogram's four
pinned objects: the depth_hist_dl/ul LRU pair, the per-CPU
hist_sample_tick array, the hist_zero_row template), and the lane
that owns the check rode the schedule only, so every scheduled run
had failed invisibly. The fix grows the set to the 48-object family
(40 maps + 4 programs + 4 links, names verified against pin.rs and
the loader's pinned object declarations) with the growth-history comment
carried forward. The Supermassive dispatch run was still in flight
at conversion time; its next scheduled-equivalent verdicts land on
the push runs below.

The conversion then retired the schedule trigger whole on both lanes
(crons `30 19 * * *` and `0 20 * * *` removed), removed the
schedule-only `if`s, collapsed concurrency to ci.yml's one-group
law, and renamed the titles (the stale "(night train)" prefix). The
shards ride every push now; no check on a push can answer Skipped.
`supermassive-verify.yml` keeps its own nightly clock (no push
trigger, never a Skipped row) and its comments no longer anchor
that clock to the e2e lane's retired cadence.
docs/CROSS_DISTRO_RESULTS.md names the new shape.

## Find 2: the histogram's "CI proof" was a claim with no leg

INNOVATIONS.md #17 ended with: "CI proof: the supermassive lane's
Phase 1.5 leg (limit, traffic, assert non-zero buckets)." The hunt:

- `rg -i hist` across `scripts/depth/`, `scripts/ci/`,
  `scripts/supermassive/` — ZERO hits (one unrelated match in a
  comment about history).
- `rg "Phase 1.5"` across the whole repo — the only hit is the
  claim itself.
- The CLI ships the histogram JSON block
  (`src/ebpf/render/depth_json/write.rs`, schema v34) and the pure
  core carries rootless pins (`test/ebpf/limiter/hist_tests.rs`,
  `hist_raw_tests.rs`, the render pins in `depth_json_tests.rs`) —
  but no harness ever limited, drove traffic, and asserted live
  buckets.

Verdict: the claim was unverifiable as written — exactly the class
the owner's honesty pass hunts. The innovation itself is real and
pinned rootless; what was missing is the live proof the doc sold.

## The fix: stage_server_histogram (the real leg)

`scripts/supermassive/supermassive-test.py` gains
`stage_server_histogram()`, called LAST in `run_server_phase()`
(after the zombie sweep's clean-slate teardown). The physics it
proves is the sampler's own law, read off the code before writing
the leg:

- `ebpf/src/enforce.rs:102` — `hist_sample_due()` runs BEFORE the
  policy lookup and unconditionally: every packet the cgroup-root
  hooks see ticks the per-CPU counter, every 1024th is recorded
  against `bpf_skb_cgroup_id` (the socket's OWN cgroup). Recording
  is policy-independent — the 1tb clamp the leg applies below
  exists for the session, never for the recording.
- `ebpf/src/hist.rs` — the cadence constants (HIST_SAMPLE_SHIFT 10,
  the mask), the 32-bucket log2 law, the 512-byte row.

The leg's shape (after three live CI iterations taught the order):
the leg builds its OWN session first — `strict <A> 1tb`, a ceiling
loopback physics cannot touch, so the clamp never engages and the
traffic stays the unlimited maximum-packet lane while the full pin
skeleton (programs, links, maps) is alive for BOTH the traffic and
the read — then drives bulk loopback download through cgroup A on a
WORKER THREAD and reads `ee <A> --depth --print-json` MID-TRAFFIC
(the report's 3s focus window measures the real moving traffic),
joins the worker, tears its own policy down (`u <A>`, best-effort,
before the verdict records), and asserts, on the row the traffic
filled: `histogram` non-null; `sample_shift == 10`; the download
size half non-null with `samples == sum(buckets) > 0` and non-null
p50/p95 (samples is computed as the bucket sum in
`depth_json/mod.rs::hist_stats_json`, so the equality is the
userspace mirror's own arithmetic, checked end to end). Seconds of
unlimited loopback bulk are tens of thousands of GSO skbs on every
profile the harness runs — samples ~= skbs/1024, far past the
stochastic floor for a >0 assert.

The three live iterations, named: (1) the first run read
`--depth --json` — no such flag (the depth JSON flag is
`--print-json`, the server phase's own headless probe has used it
all along); (2) the second run exited 1 on the depth read — the leg
had run AFTER the zombie sweep's `u --all`, and NIGHT-hunt-20's
unpin-if-no-policies law had removed the pin skeleton whole, so the
read answered without a session (the hq probe never hits this — it
runs mid-phase with policies live); (3) the third run's
both-streams note finally surfaced the real verdict —
`{"error": "No live cgroup matches 'cg:31' — nothing to inspect"}`:
the depth command's liveness gate refuses a cgroup whose members
are gone, and a FINISHED worker leaves cgroup A empty (the first
run's traffic was a synchronous call, so the worker had exited
before the read). The redesign drives the traffic on a worker
thread and reads mid-flight — the worker is the subject's live
member, exactly the state every passing live-inspection stage
presents. A read failure still surfaces BOTH streams in the verdict
note (in print-json mode the error verdict rides stdout).

Honesty boundaries named, not hidden: the upload and srtt halves
ride loopback's request direction and the RTT lane's harvest —
physics the bulk stream does not guarantee — so their sample counts
are NAMED in the verdict note, never asserted. The leg runs on the
two x86 engine shards (the engine battery on both kernel
envelopes); the arm64 host has no KVM, so the arm lane stays the
e2e-native suites — same boundary every micro-VM stage already
carries.

INNOVATIONS.md #17 now states the real leg name and its real
assertions.

## Verification

- `python3 -m py_compile scripts/supermassive/supermassive-test.py` — OK.
- check-timeout-caps: 30 jobs, all capped, no new CI job (the leg
  rides the existing engine shards, ~15 s of VM time each).
- The live verdicts land on the next push's engine shards (both
  kernel envelopes) — CI-owned, as every micro-VM leg in this
  estate is.

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
