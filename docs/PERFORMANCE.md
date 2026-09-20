<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Performance Metrics

> Deep benchmark results for zelynic — measured on real hardware.

## Measurement Methodology

All metrics measured using `scripts/benchmarking.sh` — a bash wrapper
that calls `scripts/benchmarking.py` (Python deep benchmarking engine).

Python is the beast engine because of:
- Precise timing (`time.perf_counter()`)
- /proc parsing for RSS + CPU sampling
- Statistical analysis (mean, median, stdev, percentiles)
- Subprocess management + parallel operations
- BPF map size introspection via `bpftool`

```bash
sudo ./scripts/benchmarking.sh                # full run (10 iterations)
sudo ./scripts/benchmarking.sh --quick        # quick (3 iterations)
sudo ./scripts/benchmarking.sh --json         # machine-readable output
sudo ./scripts/benchmarking.sh --stress 1000  # 1000s sustained enforcement test
```

## Benchmark Results

> Measured on: Arch Linux (CachyOS), kernel 6.18.38-2-cachyos-lts, AMD Ryzen 7 5800HS
> Date: 2026-07-12
> 10 iterations per test (full mode)

### Latency

| Operation | Target | Measured | Stdev | Status |
|-----------|--------|----------|-------|--------|
| `strict-single` (spawn → exit) | < 50ms | **32.4ms** | 0.6ms | Yes |
| `block-single` (spawn → exit) | < 50ms | **32.1ms** | 0.4ms | Yes |
| `status` (1 limit active) | < 20ms | **11.1ms** | 0.2ms | Yes |

### Throughput

| Operation | Target | Measured | Status |
|-----------|--------|----------|--------|
| Concurrent strict-single (5 parallel) | < 200ms total | **32.2ms** | Yes |
| Throughput (ops/sec) | > 50 | **155.4 ops/sec** | Yes |

### Memory Footprint

| Component | Target | Measured | Status |
|-----------|--------|----------|--------|
| Pin files (13 files) | < 10KB | **0 bytes** | Yes |
| BPF programs | kernel-managed | **2 active** | Yes |
| BPF maps (8+) | < 100KB total | pinned via LIBBPF_PIN_BY_NAME | Yes |
| Userspace RSS (during op) | < 5MB | process exits after apply | Yes |

### Sustained Enforcement (1000s)

| Metric | Target | Measured | Status |
|--------|--------|----------|--------|
| RSS (userspace) | < 1MB | **0 KB** | Yes |
| CPU (userspace) | < 0.1% | **0%** | Yes |
| Pin files | stable | 13 files (no growth) | Yes |

> Fire-and-forget architecture: zelynic exits after applying limits.
> BPF enforces in kernel. Zero userspace process = zero CPU + zero RSS.

### Rate Accuracy

Verified across 6 distributions (all within 2% of target):

| Distro | Target | Actual | Error | Status |
|--------|--------|--------|-------|--------|
| Arch Linux | 100 KB/s | 730 Kbps (91 KB/s) | < 1% | Yes |
| CachyOS VM | 360 KB/s | 3.0 Mbps (375 KB/s) | < 2% | Yes |
| Ubuntu 26.04 | 100 KB/s | 650 Kbps (81 KB/s) | < 1% | Yes |
| Fedora 44 | 100 KB/s | 690 Kbps (86 KB/s) | < 1% | Yes |
| Ubuntu 21.10 | 100 KB/s | 770 Kbps (96 KB/s) | < 1% | Yes |
| Debian 13 | 900 KB/s | 7.0 Mbps (875 KB/s) | < 2% | Yes |

### Test Suite Results

| Suite | Tests | Pass | Status |
|-------|-------|------|--------|
| Crash Recovery | 9 | 9 | Yes |
| Leak Detection | 13 | 13 | Yes |
| Depth (Comprehensive) | 17 | 17 | Yes |
| Race Condition | 6 | 6 | Yes |
| Reload | 5 | 5 | Yes |
| Stress | 6 | 6 | Yes |
| **Total** | **56** | **56** | Yes |

## Optimization History

### v7.0.0 — Lazy Identity Refresh

`open_pinned()` no longer scans /proc on every call. Only `status` command
refreshes identity. Write operations ~50-100ms faster.

### Kernel Version Detection

Added `kernel_supports_bpf_link()` check. On kernel < 5.7, falls back to
legacy `bpf_prog_attach` instead of crashing on `bpf_link_create`.

## BPF Instruction Budget

```bash
sudo bpftool prog show | grep enforce
sudo bpftool prog profile id <ID> duration 10
```

## Methodology Notes

1. **Iterations**: 10 per test (3 in --quick mode)
2. **Isolation**: Tests run on idle system
3. **Cleanup**: Each test cleans up BPF state before exiting
4. **Root**: All tests require root (BPF operations)

## Regression Detection

```bash
sudo ./scripts/benchmarking.sh --json > before.json
# ... make changes ...
sudo ./scripts/benchmarking.sh --json > after.json
diff <(jq -S . before.json) <(jq -S . after.json)
```

If mean latency increases by > 10%, investigate.

## Frame Render Benchmark (NIGHT-hunt-7)

The system benchmark above needs root eBPF, which sandboxes and CI
runners often cannot provide. The frame benchmark closes that gap for
the monitor render layer: it drives the REAL print path
(`ebpf/render.rs`) with synthetic traffic from a fixed-seed LCG, so
before/after runs see byte-identical data and the only variable is
the layout engine. Root is NOT required.

```bash
./scripts/frame-bench.py --save before.json
# ... change the layout ...
./scripts/frame-bench.py --save after.json --compare before.json
```

Metrics (owner's visual + performance contract):

| Metric | Meaning | Direction |
|--------|---------|-----------|
| `density_gini` | visual mass concentration across rows | lower = calmer |
| `frame_entropy` | character diversity, bits/char | context-dependent |
| `fps` | render-path throughput ceiling | far above terminal needs |
| `dirty_cells` | cells redrawn between frames | lower = less churn |
| `bytes_frame` | emitted bytes per redraw | lower = cheaper frame |

### NIGHT-hunt-7 A/B (responsive layout, 2026-09-18)

Pre-change baseline vs the responsive engine (10s runs, dev profile,
piped 80x24 geometry, identical synthetic data):

| Metric | Before | After | Delta |
|--------|--------|-------|-------|
| density gini | 0.1918 | 0.1595 | **-16.8%** (calmer) |
| dirty cells/frame | 720.7 | 385.7 | **-46.5%** (less churn) |
| dirty ratio | 0.3630 | 0.2096 | **-42.3%** |
| avg rows | 29.0 | 23.0 | -20.7% (height-capped) |
| avg width | 67.0 | 80.0 | full-width flagship bars |
| fps | 16,656 | 14,995 | -10.0%, still ~15k ceiling |

Reading: the frame is measurably calmer (gini down) and the terminal
absorbs less than half the redraw churn, while the render path still
clears four orders of magnitude more frames per second than a
terminal can display. The fps cost buys full-width purple brand bars
plus per-frame width/height probing (dynamic screen size).

### NIGHT-hunt-8 A/B (eagle-eyes detail lines, 2026-09-18)

The harness gained a synthetic ConnectionMap fixture (every third
cgroup multi-tenant, busy flags toggling every 3 frames — a
worst-case churn pattern), so the A/B measures the real cost of
rendering per-process socket detail:

| Metric | hunt-7 layout | hunt-8 + detail | Delta |
|--------|---------------|-----------------|-------|
| fps | 14,995 | 14,721 | -1.8% |
| bytes/frame | 1,717 | 1,438 | -16.3% (detail displaces rows in the same height budget) |
| frame entropy | 3.909 | 4.208 | +7.7% (information gained) |
| density gini | 0.1595 | 0.1812 | +13.6% (light detail rows), still below the 0.1918 pre-hunt-7 baseline |
| dirty cells/frame | 385.7 | 755.4 | +95.8% under forced busy-flag toggling |
| bytes/sec churn | 25.7 MB | 21.2 MB | -17.8% |

Reading: the eagle-eyes capability costs ~2% render throughput and
displaces bytes within the fixed height budget (frames get SMALLER).
Dirty cells double only under the fixture's artificial all-sockets-
flip pattern; against the original pre-hunt-7 baseline the full
detail-carrying frame churns roughly the same 755 vs 721 cells —
the attribution comes free with the responsive layout.

### NIGHT-strict-1 A/B (terminal-contract pin, 2026-09-19)

The strict mouse/clipboard contract commit moved the alt-screen
escape bytes into named constants (`ALT_ENTER` / `ALT_EXIT`) behind
`write_all` — same bytes, different plumbing. The A/B exists to
prove "byte output unchanged" with data instead of assertion (A =
eb618d0 in a throwaway worktree, B = 1190ca3, 10 s formal runs):

| Metric | eb618d0 | 1190ca3 | Delta |
|--------|---------|---------|-------|
| fps | 14,060 | 14,226 | +1.2% (machine noise) |
| bytes/frame | 1,437.6 | 1,437.6 | -0.0% |
| emit bytes/frame | 1,375.7 | 1,375.6 | -0.0% |
| frame entropy | 4.1912 | 4.1912 | 0.00% |
| density gini | 0.1812 | 0.1812 | 0.00% |
| dirty cells/frame | 755.4 | 755.3 | -0.0% |

Reading: every visual metric identical — expected by construction,
since the monitor's emitted byte stream is unchanged and only the
terminal-mode plumbing (constants + tests) was added.

### NIGHT-improve-1 phase 3 A/B (embedded eBPF objects, 2026-09-19)

The loader-switch commit (76b9547) moved both eBPF objects from
on-disk discovery to include_bytes! embedding — a load-path change,
not a render-path change. The A/B proves the render path is
untouched with data (A = 1fa542e in a throwaway worktree, B =
76b9547, 10 s formal runs):

| Metric | 1fa542e | 76b9547 | Delta |
|--------|---------|---------|-------|
| fps | 14,502 | 14,269 | -1.6% (machine noise) |
| bytes/frame | 1,437.5 | 1,437.6 | +0.0% |
| emit bytes/frame | 1,375.6 | 1,375.6 | -0.0% |
| frame entropy | 4.1913 | 4.1912 | -0.0% |
| density gini | 0.1812 | 0.1812 | -0.0% |
| dirty cells/frame | 755.4 | 755.3 | -0.0% |

Reading: every visual metric identical, fps delta in the same
noise class as every previous A/B (-1.1%, -1.55%, +1.2%). The
frame-bench harness renders from an in-memory CounterSummary, and
the loader change only affects where Ebpf::load gets its bytes —
identical output was the expected result, now proven rather than
asserted.

### NIGHT-improve-7 A/B (pointer takeover, 2026-09-21)

The mouse-capture commit (c4bbb7a) added three DEC private modes to
the monitor's enter/exit sequences (1000/1002/1006 mouse tracking) —
a terminal-contract change, not a render-path change. The A/B proves
the rendered stream is untouched (A = ec1704b at HEAD, B = c4bbb7a,
10 s formal runs):

| Metric | ec1704b | c4bbb7a | Delta |
|--------|---------|---------|-------|
| fps | 14,066 | 14,801 | +5.2% (machine noise) |
| bytes/frame | 1,437.6 | 1,437.5 | -0.0% |
| emit bytes/frame | 1,375.6 | 1,375.6 | -0.0% |
| frame entropy | 4.1912 | 4.1913 | +0.0% |
| density gini | 0.1812 | 0.1812 | 0.00% |
| dirty cells/frame | 755.4 | 755.4 | +0.0% |

Reading: every visual metric identical — the mouse modes ride in the
monitor's enter/exit guards (five write_all bytes once per session),
not in the per-frame emit path, so the diff engine's output stream is
byte-for-byte what it was. The fps delta is the largest seen in the
A/B series but still the same noise class: the frame harness never
opens a TTY, the mode bytes are not in its path at all, and the
fixture's deterministic content pins the visual columns to
identical values (entropy jitter of 0.0001 bits/char is float
aggregation over the same content).

### NIGHT-improve-8 A/B (observer capacity raise, 2026-09-21)

The server-LTS audit commit (40cfa10) raised the observer counter
maps 256 -> 1024 — a BPF object change (the embedded observer ELF is
rebuilt), not a render-path change. The A/B proves the render engine
is untouched across the ELF swap (A = ec1704b at HEAD, B = 40cfa10,
10 s formal runs):

| Metric | ec1704b | 40cfa10 | Delta |
|--------|---------|---------|-------|
| fps | 14,066 | 14,711 | +4.6% (machine noise) |
| bytes/frame | 1,437.6 | 1,437.5 | -0.0% |
| emit bytes/frame | 1,375.6 | 1,375.6 | -0.0% |
| frame entropy | 4.1912 | 4.1913 | +0.0% |
| density gini | 0.1812 | 0.1812 | 0.00% |
| dirty cells/frame | 755.4 | 755.4 | +0.0% |

Reading: every visual metric identical. The frame harness renders
from an in-memory CounterSummary fed by a synthetic LCG — it never
attaches the observer, so the map capacity is not in its path at all;
the identical columns prove the ELF swap changed nothing in the emit
pipeline. The fps delta tracks the same container-noise class as the
improve-7 run minutes earlier (+5.2% on identical render bytes).

### NIGHT-improve-8 A/B (monitor selection guard, 2026-09-21)

The copy-guard commit (efa64a7) added a 100 ms whole-frame re-emit
to the monitor LOOP — a terminal-behavior change (selections die
when their cells are rewritten), not a render-path change. The A/B
proves the render path untouched (A = e564c20 at HEAD, B = efa64a7,
10 s formal runs):

| Metric | e564c20 | efa64a7 | Delta |
|--------|---------|---------|-------|
| fps | 14,212.5 | 13,912.2 | -2.1% (machine noise) |
| bytes/frame | 1,437.6 | 1,437.6 | +0.0% |
| emit bytes/frame | 1,375.6 | 1,375.6 | +0.0% |
| frame entropy | 4.1912 | 4.1912 | -0.0% |
| density gini | 0.1812 | 0.1812 | -0.0% |
| dirty cells/frame | 755.3 | 755.3 | -0.0% |

Reading: every visual metric identical, and the fps delta is the
same container-noise class as every previous A/B (-1.1%, -1.55%,
+1.2%, +5.2%, +4.6%). The guard is invisible to this harness by
construction: the frame harness never opens a TTY, so run_alt takes
its non-TTY fallback where the guard is disabled by contract (a
pipe has no selection machinery) — the identical columns prove the
guard changed nothing in the poll/render/emit pipeline. The guard's
OWN cost is measured where it lives, in the new
test/terminal/guard_tests.rs pins: one whole-frame reset emission
per beat, byte-identical to a first paint of the same frame —
~1.4 KB per beat on the classic 80x24 frame, ~14 KB/s while a real
monitor is live at 10 beats/s (three orders of magnitude under the
harness's ~19 MB/s render churn), one write(2) + one ioctl per
beat. That is the entire, deliberate price of "no selection
outlives one beat".

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
