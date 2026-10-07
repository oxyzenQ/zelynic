#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""
zelynic deep benchmarking engine — accurate system-level metrics.

Python is the beast engine because of subprocess management, /proc
parsing, timing precision, and statistical analysis — things bash
can't do well.

Metrics collected (NIGHT-hunt-32: the list now states what the code
actually measures — the old list promised BPF map sizes never
collected, per-process CPU of a process that never exists, and a
60s default the flag did not carry):
  1. Startup latency (strict spawn → exit)
  2. Block latency (block spawn → exit)
  3. Status query latency
  4. Memory footprint (pin files/bytes; bpftool program + map counts
     when bpftool is installed — skipped loudly, never printed as 0)
  5. Concurrent throughput (admitted and lock-refused counted apart:
     the lock is non-blocking, a refusal is not an op)
  6. Sustained enforcement window: enforcement liveness at every
     sample, the zero-daemon fact MEASURED (no zelynic process),
     system CPU context via /proc/stat, and pin stability.
     Per-program KERNEL cost is proof-claims.py's lane (bpftool
     run_time_ns behind kernel.bpf_stats_enabled).

Usage:
  sudo ./scripts/bench/benchmarking.sh                # full run
  sudo ./scripts/bench/benchmarking.sh --quick        # quick (3 iterations)
  sudo ./scripts/bench/benchmarking.sh --json         # machine-readable
  sudo ./scripts/bench/benchmarking.sh --stress 60    # 60s stress window

ZELYNIC_BINARY points at a build (sudo strips it without -E); the
engine resolves repo builds first and gates the pick on -V vs
Cargo.toml (the shared lib's resolve_binary — a stale decoy build
is refused, never benchmarked silently).
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path

# The shared engine lib lives in scripts/lib/ (NIGHT-refactor-1) — bound
# by ABSOLUTE path so the harness works from any CWD.
_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)
import zelynic_harness_lib as lib  # noqa: E402 - needs the lib/ path bootstrap above

# Bound by lib.resolve_binary() in main() — never a CWD-relative guess.
BINARY = ""
PIN_DIR = "/sys/fs/bpf/zelynic"
ITERATIONS = 10
QUICK_ITERATIONS = 3


def run(cmd, timeout=10, capture=True):
    """Run an argv LIST (never a shell string — NIGHT-hunt-32: the old
    shell=True form interpolated comm names and binary paths into a
    shell; argv lists need no quoting games and no injection edge)."""
    start = time.perf_counter()
    result = subprocess.run(cmd, capture_output=capture, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr, time.perf_counter() - start


def system_cpu_percent(duration_s=1.0):
    """System-wide CPU% over a window, from /proc/stat — the docstring's
    original promise, restored (the old loop sampled /proc/PID/stat of a
    zelynic process that never exists: the CLI is one-shot, so every
    sample was vacuous and the summary printed zeros as measurements)."""

    def read_ticks():
        with open("/proc/stat") as f:
            parts = f.readline().split()[1:]
        vals = [int(x) for x in parts[:7]]
        return vals[3] + vals[4], sum(vals)

    idle1, total1 = read_ticks()
    time.sleep(duration_s)
    idle2, total2 = read_ticks()
    dt = total2 - total1
    if dt <= 0:
        return None
    return round((1.0 - (idle2 - idle1) / dt) * 100.0, 2)


def get_pin_dir_size():
    pin_path = Path(PIN_DIR)
    if not pin_path.exists():
        return 0, 0
    total = sum(f.stat().st_size for f in pin_path.iterdir() if f.is_file())
    count = len(list(pin_path.iterdir()))
    return total, count


def cleanup():
    run([BINARY, "unstrict-all"], timeout=5)


def bench_startup(iterations):
    print("\n━━━ 1. Startup Latency ━━━")
    print(f"  Measuring strict spawn→exit ({iterations} iterations)")
    cleanup()
    times = []
    for i in range(iterations):
        sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
        try:
            comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
            rc, _, _, elapsed = run([BINARY, "strict", comm, "100kb"], timeout=10)
            if rc == 0:
                times.append(elapsed * 1000)
                print(f"  [{i + 1}/{iterations}] {elapsed * 1000:.1f}ms")
        finally:
            sleep_proc.kill()
            sleep_proc.wait()
            cleanup()
    if not times:
        return {"name": "startup_latency", "error": "all failed"}
    result = {
        "name": "startup_latency",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "median_ms": round(statistics.median(times), 1),
        "stdev_ms": round(statistics.stdev(times), 1) if len(times) > 1 else 0,
        "min_ms": round(min(times), 1),
        "max_ms": round(max(times), 1),
    }
    print(f"\n  Mean:   {result['mean_ms']:.1f}ms")
    print(f"  Median: {result['median_ms']:.1f}ms")
    print(f"  Stdev:  {result['stdev_ms']:.1f}ms")
    print(f"  Range:  {result['min_ms']:.1f}–{result['max_ms']:.1f}ms")
    return result


def bench_block_latency(iterations):
    print("\n━━━ 2. Block Latency ━━━")
    print(f"  Measuring block spawn→exit ({iterations} iterations)")
    cleanup()
    times = []
    for i in range(iterations):
        sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
        try:
            comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
            rc, _, _, elapsed = run([BINARY, "block", comm], timeout=10)
            if rc == 0:
                times.append(elapsed * 1000)
                print(f"  [{i + 1}/{iterations}] {elapsed * 1000:.1f}ms")
        finally:
            sleep_proc.kill()
            sleep_proc.wait()
            cleanup()
    if not times:
        return {"name": "block_latency", "error": "all failed"}
    result = {
        "name": "block_latency",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "median_ms": round(statistics.median(times), 1),
    }
    print(f"\n  Mean: {result['mean_ms']:.1f}ms")
    return result


def bench_status(iterations):
    print("\n━━━ 3. Status Query Latency ━━━")
    print(f"  Measuring 'zelynic status' ({iterations} iterations)")
    sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
    comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
    run([BINARY, "strict", comm, "100kb"], timeout=10)
    times = []
    for i in range(iterations):
        rc, _, _, elapsed = run([BINARY, "status"], timeout=5)
        if rc == 0:
            times.append(elapsed * 1000)
            print(f"  [{i + 1}/{iterations}] {elapsed * 1000:.1f}ms")
    sleep_proc.kill()
    cleanup()
    if not times:
        return {"name": "status_latency", "error": "all failed"}
    result = {
        "name": "status_latency",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "median_ms": round(statistics.median(times), 1),
    }
    print(f"\n  Mean: {result['mean_ms']:.1f}ms")
    return result


def bench_memory():
    print("\n━━━ 4. Memory Footprint ━━━")
    cleanup()
    pin_bytes_base, pin_count_base = get_pin_dir_size()
    sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
    comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
    run([BINARY, "strict", comm, "100kb"], timeout=10)
    time.sleep(0.5)
    pin_bytes_active, pin_count_active = get_pin_dir_size()
    # NIGHT-hunt-32: bpftool absence is a SKIP said out loud — the old
    # form printed "BPF programs: 0" / "BPF maps: 0" as facts when the
    # tool was simply not installed (rc 127, empty stdout).
    bpf_progs = None
    bpf_maps = None
    if shutil.which("bpftool"):
        rc, bpftool_out, _, _ = run(["bpftool", "prog", "show"], timeout=5)
        if rc == 0:
            bpf_progs = [line for line in bpftool_out.split("\n") if "enforce" in line]
        rc, map_out, _, _ = run(["bpftool", "map", "show"], timeout=5)
        if rc == 0:
            bpf_maps = [line for line in map_out.split("\n") if "zelynic" in line.lower()]
    sleep_proc.kill()
    cleanup()
    result = {
        "name": "memory_footprint",
        "baseline_pin_files": pin_count_base,
        "baseline_pin_bytes": pin_bytes_base,
        "active_pin_files": pin_count_active,
        "active_pin_bytes": pin_bytes_active,
        "bpf_programs_loaded": len(bpf_progs) if bpf_progs is not None else None,
        "bpf_maps_loaded": len(bpf_maps) if bpf_maps is not None else None,
    }
    print(f"  Pin files: {result['active_pin_files']} ({result['active_pin_bytes']} bytes)")
    print(
        f"  BPF programs: {len(bpf_progs) if bpf_progs is not None else 'skipped — bpftool not installed'}"
    )
    print(
        f"  BPF maps: {len(bpf_maps) if bpf_maps is not None else 'skipped — bpftool not installed'}"
    )
    return result


def bench_concurrent(iterations):
    print("\n━━━ 5. Concurrent Throughput ━━━")
    print(f"  Measuring 5 parallel strict ({iterations} rounds)")
    print("  The lock is non-blocking: refusals are fast errors, not ops —")
    print("  admitted and refused are counted apart (NIGHT-hunt-32: the")
    print("  old ops/sec counted every refusal as a successful op).")
    cleanup()
    times = []
    admitted_total = 0
    for round_num in range(iterations):
        sleep_procs = [
            subprocess.Popen(["sleep", "60"], stdout=subprocess.DEVNULL) for _ in range(5)
        ]
        start = time.perf_counter()
        procs = []
        for p in sleep_procs:
            comm = open(f"/proc/{p.pid}/comm").read().strip()
            procs.append(
                subprocess.Popen(
                    [BINARY, "strict", comm, "100kb"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
        admitted = 0
        for p in procs:
            if p.wait() == 0:
                admitted += 1
        elapsed = time.perf_counter() - start
        times.append(elapsed * 1000)
        admitted_total += admitted
        print(
            f"  [Round {round_num + 1}/{iterations}] {elapsed * 1000:.1f}ms wall, "
            f"{admitted}/5 admitted, {5 - admitted} lock-refused"
        )
        for p in sleep_procs:
            p.kill()
            p.wait()
        cleanup()
    if not times:
        return {"name": "concurrent_throughput", "error": "failed"}
    result = {
        "name": "concurrent_throughput",
        "iterations": len(times),
        "mean_ms": round(statistics.mean(times), 1),
        "ops_admitted": admitted_total,
        "ops_attempted": len(times) * 5,
        "ops_per_sec": round(admitted_total / (statistics.mean(times) / 1000.0), 1),
    }
    print(f"\n  Mean: {result['mean_ms']:.1f}ms per 5-op volley")
    print(f"  Admitted: {admitted_total}/{len(times) * 5} calls (the rest: fast lock refusals)")
    print(f"  Admission rate: {result['ops_per_sec']} admitted ops/sec")
    return result


def bench_stress(duration_sec):
    print(f"\n━━━ 6. Sustained Enforcement ({duration_sec}s) ━━━")
    print("  One-shot design: enforcement lives in the kernel. The window")
    print("  measures enforcement LIVENESS, the zero-daemon fact, system CPU")
    print("  context, and pin stability (per-program kernel cost is")
    print("  proof-claims.py's lane — bpftool run_time_ns).")
    cleanup()
    sleep_proc = subprocess.Popen(["sleep", "300"], stdout=subprocess.DEVNULL)
    comm = open(f"/proc/{sleep_proc.pid}/comm").read().strip()
    run([BINARY, "strict", comm, "100kb"], timeout=10)
    time.sleep(0.5)
    pin_bytes0, pin_count0 = get_pin_dir_size()
    alive_checks = 0
    zel_proc_max = 0
    cpu_samples = []
    start = time.perf_counter()
    while time.perf_counter() - start < duration_sec:
        # Liveness: the limit row must answer at every sample.
        rc, out, _, _ = run([BINARY, "status"], timeout=5)
        if rc == 0 and out and "no active limits" not in out:
            alive_checks += 1
        # The no-daemon fact, MEASURED (an exact-name pgrep — the old
        # -f form matched any cmdline carrying the path, editors
        # included, and reported THEIR rss as zelynic's).
        try:
            pgrep = subprocess.run(
                ["pgrep", "-x", "zelynic"], capture_output=True, text=True, timeout=2
            )
            zel_proc_max = max(zel_proc_max, len(pgrep.stdout.split()))
        except Exception:
            pass
        cpu = system_cpu_percent(1.0)
        if cpu is not None:
            cpu_samples.append(cpu)
    pin_bytes1, pin_count1 = get_pin_dir_size()
    sleep_proc.kill()
    cleanup()
    result = {
        "name": "sustained_enforcement",
        "duration_sec": duration_sec,
        "alive_samples": alive_checks,
        "enforcement_alive": alive_checks > 0,
        "zelynic_procs_max": zel_proc_max,
        "sys_cpu_mean_percent": round(statistics.mean(cpu_samples), 2) if cpu_samples else None,
        "sys_cpu_max_percent": round(max(cpu_samples), 2) if cpu_samples else None,
        "pin_files": pin_count1,
        "pin_bytes": pin_bytes1,
        "pin_stable": (pin_count0, pin_bytes0) == (pin_count1, pin_bytes1),
    }
    print(f"  Enforcement alive at {alive_checks} sample(s) over {duration_sec}s")
    print(
        f"  zelynic processes seen at any sample: {zel_proc_max} (0 expected — a live monitor session would show here honestly)"
    )
    print(
        f"  System CPU (context, /proc/stat): mean={result['sys_cpu_mean_percent']}%, max={result['sys_cpu_max_percent']}%"
    )
    print(f"  Pin files: {pin_count1} ({pin_bytes1} bytes), stable: {result['pin_stable']}")
    return result


def main():
    parser = argparse.ArgumentParser(description="zelynic deep benchmarking")
    parser.add_argument("--quick", action="store_true", help="quick mode (3 iterations)")
    parser.add_argument("--json", action="store_true", help="JSON output")
    parser.add_argument("--stress", type=int, default=30, help="stress test duration in seconds")
    args = parser.parse_args()

    if os.geteuid() != 0:
        print("ERROR: Requires root. Run with sudo.", file=sys.stderr)
        sys.exit(1)

    # NIGHT-hunt-32: the shared resolver — repo builds outrank PATH, the
    # pick is version-GATED against Cargo.toml, and a missing binary
    # prints the one-command fix instead of benchmarking nothing.
    if not lib.resolve_binary(None, "./scripts/bench/benchmarking.sh --binary <path>"):
        sys.exit(1)
    global BINARY
    BINARY = lib.BINARY

    iters = QUICK_ITERATIONS if args.quick else ITERATIONS

    print("━━━ zelynic Deep Benchmark ━━━")
    print(f"Binary: {BINARY}")
    print(f"Iterations: {iters}")
    print(f"Stress: {args.stress}s")
    print(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Kernel: {subprocess.check_output(['uname', '-r'], text=True).strip()}")

    results = []
    results.append(bench_startup(iters))
    results.append(bench_block_latency(iters))
    results.append(bench_status(iters))
    results.append(bench_memory())
    results.append(bench_concurrent(iters if not args.quick else 3))
    if not args.quick:
        results.append(bench_stress(args.stress))

    print("\n━━━ Summary ━━━")
    for r in results:
        name = r.get("name", "?")
        if "error" in r:
            print(f"  {name}: ERROR ({r['error']})")
        elif "mean_ms" in r:
            print(f"  {name}: {r['mean_ms']}ms mean")
        else:
            print(f"  {name}: see details above")

    if args.json:
        print("\n" + json.dumps(results, indent=2))

    cleanup()


if __name__ == "__main__":
    main()
