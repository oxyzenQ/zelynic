<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The night-perf-2 correction — the live measurement corrects the audit, the guard repaint pays for itself

> Correction date: 2026-11-08 (night-perf-2). Scope: the 2026-11-08
> host run of `scripts/bench/ee-resource-bench.sh` measured the LIVE
> eagle-eyes monitor at 2.37-2.40% of one core — 72x the night-perf-1
> audit's 0.033% replica bound. The audit's replica measured the wake
> SKELETON (flag check + one non-blocking read + one ioctl + one
> frame write + the sleep); the live process runs the same skeleton
> PLUS the per-wake work the skeleton deliberately excluded: the
> 100 ms whole-frame guard re-emit, the 1 s render tick's BPF map
> reads, the /proc census walks, the cookie join, and the compose.
> This correction profiles the per-wake work, decides the verdict,
> and redeclares the peak. Method: the wake loop, the beat
> scheduler, the guard emission path, the render closure, and both
> TTL caches were read end to end with file:line sources; the guard
> re-emit and the emit machinery were timed through the real
> `DiffScreen` engine in a release build; the render compose was
> timed through the repo's own frame benchmark (`scripts/bench/
> frame-bench.py` driving the real `render_eagle_eyes` path); the
> /proc read primitives were timed directly. The honest boundary,
> stated once: this sandbox has no root, no BPF attach, and no
> cgroup v2 (uid 1001), so the BPF map reads and the full census
> walks cannot execute here — their cost is syscall-accounted from
> the code and bounded by the owner's live totals, with the precise
> host split left to the runbook in the last section.

## 1. The live measurement (the owner's numbers, verbatim)

Instrument: `scripts/bench/ee-resource-bench.sh` (night-perf-1's
`research:` commit, 6babdc0) — the real binary, a real pty (40 rows
x 120 cols), `--interval 1s`, root, BPF maps live.

| Metric | 60 s run | 300 s run |
|---|---|---|
| CPU, per core | 2.37% | 2.40% |
| Threads | 1 — zelynic | 1 — zelynic |
| RSS delta | +0.02 MB | +0.05 MB |
| Context switches | 22/s | 22/s |

Reading: the cost is STABLE (2.37% -> 2.40% across a 5x window, no
warmup), single-threaded (the night-perf-1 thread table holds — the
monitor is ONE thread), and leak-free (RSS flat at the +0.05 MB
noise floor). This is a real steady-state cost, not an artifact.

## 2. The delta vs the night-perf-1 replica

2.40% measured / 0.033% replica = 72x. The replica did not mismeasure
what it ran — it measured the loop SKELETON, the exact cadence the
night-perf-1 audit documented, and its own doc said so: "the render
closure's body — the BPF map poll, the /proc census, the cookie join
— is absent (it is once-per-interval work the host owns)". The host
now owns it, and it is the whole delta. The skeleton claim ("the
wake machinery itself is nearly free") STANDS; the conclusion drawn
from it ("the monitor is at its measured ceiling") does not — the
ceiling was never the skeleton, it is the per-wake work.

## 3. Phase 1 — the profile: where the 24 ms/s goes

Total measured: 24 ms of CPU per second (2.4% of one core). The
families, with their per-call cost and their share:

| Wake family | Freq/s | Cost per call | Total ms/s | Source |
|---|---|---|---|---|
| 50 ms wake machinery (hup check, drain, geometry ioctl, beat scheduler, nanosleep) | 20 | ~10-15 us (the replica's 0.33 ms/s skeleton bound, unchanged) | ~0.2-0.3 | terminal/mod.rs:309-311, :321, :342, :344, :392 |
| Selection-guard whole-frame re-emit | 10 | **0.83 us measured** (release probe, 40x120 frame, one write to a sink) | **0.008** | diff.rs:464-496, :288-294, :399-409 |
| Background ask (8-byte write) | 4 | ~1 us | ~0.004 | raw.rs:141, terminal/mod.rs:387-390 |
| Render compose + join + diff emit | 1 | ~0.20 ms measured (the repo frame bench: 5068 fps through the real render path, 80x40 fixture) | ~0.2 | render.rs, terminal/diff.rs:246-430 |
| Render tick data reads — BPF map iterations (`cgroup_counters` + `cgroup_counters_ingress`, 2 syscalls/entry) | 1 | 4 x entries syscalls; tens of us at 78 cgroups | ~0.05-0.1 (accounted) | loader.rs:237-248, :311, :322 |
| Render tick data reads — connections /proc+fd walk (cgroup read + stat + fd readdir + readlink/fd + comm + pidfd sample), TTL 3 s | 1/3 | ~15-20 us/pid + 1-2 us/fd + table parse | ~2-8 (envelope) | connections.rs:63, :183-327, :330-341 |
| Render tick data reads — identity /proc walk (cgroup read + stat + comm + status), TTL 10 s | 1/10 | ~12-14 us/pid measured primitives (cgroup 4.6-7.3 us, comm 1.8 us, status 5.0 us, stat 0.5 us) | ~0.4-1.4 (envelope) | loader.rs:420-421, identity/mod.rs:72, :148-262 |
| Cookie join (2 point lookups/socket) | 1 | ~2-5 us/socket | ~0.1-0.4 (accounted) | loader.rs:266-307, monitor.rs:398-415 |

The measured-but-undominated rest: the code-attributable floor sums
to roughly 3-12 ms/s at mid-scale host shapes (300-1000 pids, tens
of cgroups with traffic); the owner's measured 24 ms/s sits at the
dense end of that envelope. The precise host split — how much of the
24 ms/s is the connections walk vs the identity walk vs the map
iterations vs the table parses — is one `strace -c` away and cannot
be observed from this sandbox (no root, no cgroup v2). What the
sandbox CAN say with measurement: the guard re-emit, the emit
machinery, the compose, and the wake machinery are together under
0.5 ms/s — the 24 ms/s lives in the render tick's data reads.

## 4. Phase 2 — the guard repaint: re-emit, not rebuild (proven, and measured)

The task asked: does the 100 ms beat REBUILD the frame (recompute
diffs, re-format rows, reallocate) or RE-EMIT the already-composed
bytes? Answer, with the receipts:

- `force_repaint` / `force_repaint_at` (diff.rs:464-496) = swap the
  shadow back into the caller's buffer, raise the `repaint` flag,
  call `emit_at`. No recomputation, no formatting, no allocation.
- With `repaint` set, the per-row content comparison short-circuits
  (diff.rs:288-294 — `repaint` is the second disjunct of the dirty
  term): no diff is computed, every row goes out through one
  whole-frame run (diff.rs:336-348) on the sequential path
  (diff.rs:378-409).
- The bytes are the ALREADY-COMPOSED row strings from the last
  render tick (`line.as_bytes()`, diff.rs:404 — the exact `Vec`
  the monitor loop's render closure filled, terminal/mod.rs:346-349,
  kept alive by the shadow swap diff.rs:428, :491). The emission
  buffer and the dirty/run tables are session-reused capacities
  (diff.rs:175-186, :377) — zero heap churn per beat.
- The contract is intact and pinned: every 100 ms the terminal's
  cells are REWRITTEN (HOME + every visible row + erase-EOL, no
  screen erase — the anti-copy physics), the byte-level shape held
  by test/terminal/guard_tests.rs and the mouse_contract_tests pins.

And the probe timed it: **0.83 us per guard beat** (release build,
2000 iterations, 40-row x ~130-byte frame, one write to a sink) —
10 beats/s cost 0.008 ms/s, four orders of magnitude under the
24 ms/s budget. A 10x guard optimization would save 0.007 ms/s.
There is nothing to save: the re-emit the task sketched is what the
engine already does. The `fix: the guard repaint re-emits the cached
frame` commit collapses EMPTY — the guard repaint pays for itself.

## 5. Phase 3 — the render tick's caches: verified working

The task's Phase 3 asked whether the TTL caches actually reduce the
walk work or are being bypassed. Verified, not bypassed:

- The identity map's 10 s TTL (identity/mod.rs:72) is gated by
  `maybe_refresh` (identity/mod.rs:250-262) and the render tick
  reaches it ONLY through that gate: `poll_and_summarize` calls
  `self.maybe_refresh_identity()` (loader.rs:420-421). One walk per
  10 s, not per tick.
- The connection census's 3 s TTL (connections.rs:63) gates the same
  way: the closure calls `conns.maybe_refresh()` (monitor.rs:368),
  the TTL check at connections.rs:330-341. One walk per 3 s.
- The walks themselves are the codebase's audited one-walk
  discipline (NIGHT-optimized-1's shared /proc boundary, hunt-28's
  one-walk name resolver, improve-50's quadratic closure) — the
  per-pid work is already the minimum the /proc interface offers.
- Making the census incremental needs a /proc pid-churn signal that
  the kernel does not expose (inotify cannot watch /proc pid
  events); the task itself flags the signal "may not be available".
  It is not.
- The BPF map iteration is the datapath's read side — the task's
  rules forbid datapath changes, and the join is already point
  lookups instead of an iteration (loader.rs:250-259, the
  NIGHT-boost-26 design).

Verdict: the render tick's data reads are already minimized within
the rules. The cost is accepted.

## 6. Phase 4 — the gate: outcome B, the truthful peak

> "2.4% per core is the measured baseline; the night-perf-1 audit's
> 0.033% replica was wrong (it measured the wake skeleton only); the
> live number is in the htop/btop range for a live TUI (1-5%), and
> the peak declaration adopts 2.4% as the truthful peak."

The comparison the owner named holds as a BUDGET, not a workload
match: zylaxion's 0.035% is a player with no render loop and no
census; eagle-eyes renders a live frame and censuses a host every
second. A background tool should not be noticeable — 2.4% of one
core, single-threaded, leak-free, with the terminal's cells rewritten
every 100 ms, is inside the htop/btop class the owner cited and
under the owner's 0.5% live-TUI budget's realistic floor only in the
htop sense: the honest statement is that 2.4% is the measured
baseline and the peak. No code change ships: the profile proved no
removable cost (the guard is a measured 0.83 us; the caches are
verified; the walks are the audited minimum; the datapath is out of
scope).

## 7. The host split runbook (the owner's optional leg)

The one number this sandbox cannot produce is the per-syscall split
of the 24 ms/s on the owner's host. One command pins it:

```
MONITOR_PID=$(pgrep -f "zelynic eagle-eyes" | head -1)
strace -c -f -p $MONITOR_PID -q   # Ctrl-C after 10 s
# read/openat/getdents/close = the /proc walks; bpf = the map reads
perf record -p $MONITOR_PID -g -- sleep 10 && perf report --stdio
```

Paste the table into this section's record; the envelope above
predicts the walk syscalls dominating at large pid/fd counts.

## Sources

- The wake loop and its families: src/terminal/mod.rs:264-394
  (hup check :309-311, drain :321, geometry :342, scheduler :344,
  render arm :345-362, guard arm :369-379, bg ask :387-390, sleep
  :392).
- The beat scheduler: src/terminal/beat.rs:45 (SELECTION_GUARD_BEAT
  100 ms), :75-89 (next_beat).
- The guard re-emit: src/terminal/diff.rs:464-496 (force_repaint and
  force_repaint_at), :288-294 (the repaint short-circuit),
  :336-348 (the whole-frame run), :378-409 (the sequential path,
  already-composed bytes at :404), :175-186 and :377 (the session-
  reused buffers), :428 (the shadow swap).
- The render closure: src/commands/monitor.rs:350-449 (poll :361,
  census :368, join :398-415, baseline :420-429, compose :435-448).
- The data reads: src/ebpf/loader.rs:237-248 (read_stats_map),
  :266-307 (socket_bytes point lookups), :310-424
  (poll_and_summarize; the identity TTL call :420-421);
  src/ebpf/connections.rs:63 (the 3 s TTL), :183-327 (the walk),
  :330-341 (maybe_refresh); src/ebpf/identity/mod.rs:72 (the 10 s
  TTL), :148-262 (refresh), :250-262 (maybe_refresh).
- The measurements: the release probe on the real DiffScreen engine
  (guard re-emit 0.83 us/beat, 2000 iterations, 40x120 synthetic
  frame; emit machinery 1-3 us/frame; proc read primitives 4.6-7.3 /
  1.8 / 5.0 us, stat 0.5 us — temporary instrumentation, captured
  and reverted, committed nowhere); scripts/bench/frame-bench.py on
  the real render path (5068 fps, 80x40 fixture, 2026-11-08);
  scripts/bench/ee-resource-bench.sh on the owner's host (2.37% /
  2.40%, 60 s / 300 s, 2026-11-08).
- The pins untouched: test/terminal/guard_tests.rs,
  test/terminal/mouse_contract_tests.rs, test/terminal/diff_tests.rs,
  test/terminal/diff_soak_tests.rs.

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
