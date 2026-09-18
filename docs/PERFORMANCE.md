<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Performance Metrics

> Deep benchmark results for zelynic v10.0.0 — measured on real hardware.

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

### v10.0.0 — Kernel Version Detection

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

<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `bpf/*.bpf.c`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
