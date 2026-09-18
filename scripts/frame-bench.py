#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""
zelynic frame-level render benchmark (NIGHT-hunt-7 A/B protocol).

Drives the in-Rust frame harness (the `frame_bench_observe` ignored
test in src/ebpf/render.rs) and computes the owner's visual and
performance metrics over the captured frames:

  Visual:
    density_gini   Gini coefficient of non-space visual mass across
                   rows (0.0 = perfectly even, 1.0 = all mass in one
                   row). Lower = calmer, more scannable frame.
    frame_entropy  Shannon entropy of the character distribution, in
                   bits/char. Higher = more information per cell.
  Performance:
    fps            frames per second through the REAL print path
                   (println_safe! + per-line flush, piped stdout).
    dirty_cells    average cells that change between consecutive
                   frames (grid-aligned diff, space-padded). Lower =
                   less redraw churn for the terminal.
    bytes_frame    average frame size in bytes (what the terminal
                   must absorb per redraw).

The Rust harness renders synthetic traffic from a fixed-seed LCG, so a
`--save` run BEFORE a layout change and one AFTER are directly
comparable: identical data, only the layout engine differs.

Root/eBPF is NOT required — the harness runs in sandboxes where
`observe` cannot attach (the same constraint the NIGHT-hunt-6 commit
documented for the system benchmark).

Usage:
  ./scripts/frame-bench.py --save before.json
  ... apply the layout change ...
  ./scripts/frame-bench.py --save after.json --compare before.json

  ./scripts/frame-bench.py --quick              # 1s budget (smoke)
  ./scripts/frame-bench.py --frames <file>      # metrics from a saved
                                                # raw capture instead of
                                                # running cargo
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TEST_NAME = "frame_bench_observe"
DELIM = "###FRAME###"
META_RE = re.compile(r"###META### frames=(\d+) elapsed_ms=(\d+)")
DEFAULT_TIMEOUT_SECS = 600  # build + link + 10s render budget


def run_harness(quick: bool, timeout: int):
    """Run the ignored Rust frame harness, return raw stdout text."""
    cmd = [
        "cargo", "test", "--features", "ebpf", TEST_NAME,
        "--", "--ignored", "--nocapture",
    ]
    env = dict(os.environ)
    env.setdefault("ZELYNIC_FRAME_BENCH_QUICK", "")
    if quick:
        env["ZELYNIC_FRAME_BENCH_QUICK"] = "1"
    print(f"[frame-bench] running: {' '.join(cmd)}" + (" (quick)" if quick else ""),
          file=sys.stderr)
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, cwd=REPO_ROOT, env=env, capture_output=True, text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"[frame-bench] FATAL: harness timed out after {timeout}s", file=sys.stderr)
        sys.exit(1)
    wall = time.perf_counter() - start
    if proc.returncode != 0:
        print(f"[frame-bench] FATAL: cargo test exited {proc.returncode}", file=sys.stderr)
        print(proc.stderr[-4000:], file=sys.stderr)
        sys.exit(1)
    print(f"[frame-bench] harness wall time: {wall:.1f}s (includes build)", file=sys.stderr)
    return proc.stdout


def split_frames(stdout: str):
    """Split harness stdout into (frames, meta) using the delimiters."""
    frames = []
    meta = None
    current = None
    for line in stdout.splitlines():
        if line.strip() == DELIM:
            if current is not None:
                frames.append("\n".join(current))
            current = []
            continue
        m = META_RE.search(line)
        if m:
            meta = {"frames": int(m.group(1)), "elapsed_ms": int(m.group(2))}
            continue
        if current is not None:
            current.append(line)
    if current is not None:
        frames.append("\n".join(current))
    if not frames:
        print("[frame-bench] FATAL: no frames captured (delimiter not found)",
              file=sys.stderr)
        sys.exit(1)
    return frames, meta


def gini(values):
    """Gini coefficient over non-negative values (0 = even, 1 = concentrated)."""
    v = sorted(x for x in values if x >= 0)
    n = len(v)
    if n == 0 or sum(v) == 0:
        return 0.0
    cum = 0.0
    for i, x in enumerate(v):
        cum += (i + 1) * x
    return (2.0 * cum) / (n * sum(v)) - (n + 1.0) / n


def shannon_entropy(text):
    """Shannon entropy of the character distribution, bits/char."""
    if not text:
        return 0.0
    freq = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def frame_metrics(frame):
    """Visual metrics for one frame."""
    rows = frame.split("\n")
    row_mass = [sum(1 for ch in r if ch != " ") for r in rows]
    return {
        "rows": len(rows),
        "width": max((len(r) for r in rows), default=0),
        "chars": len(frame),
        "density_gini": gini(row_mass),
        "frame_entropy": shannon_entropy(frame),
    }


def dirty_cells(a, b):
    """Cells differing between two frames, grid-aligned + space-padded."""
    ra, rb = a.split("\n"), b.split("\n")
    width = max(max((len(r) for r in ra), default=0),
                max((len(r) for r in rb), default=0))
    dirty = 0
    for i in range(max(len(ra), len(rb))):
        la = ra[i] if i < len(ra) else ""
        lb = rb[i] if i < len(rb) else ""
        la = la.ljust(width)
        lb = lb.ljust(width)
        dirty += sum(1 for x, y in zip(la, lb) if x != y)
    return dirty, width * max(len(ra), len(rb))


def compute(frames, meta):
    """Full metric set over the captured frames."""
    per_frame = [frame_metrics(f) for f in frames]

    dirty = []
    total_cells = 0
    for i in range(1, len(frames)):
        d, cells = dirty_cells(frames[i - 1], frames[i])
        dirty.append(d)
        total_cells += cells

    result = {
        "frames_captured": len(frames),
        "avg_rows": sum(m["rows"] for m in per_frame) / len(per_frame),
        "avg_width": sum(m["width"] for m in per_frame) / len(per_frame),
        "bytes_frame": sum(m["chars"] for m in per_frame) / len(per_frame),
        "density_gini": sum(m["density_gini"] for m in per_frame) / len(per_frame),
        "frame_entropy": sum(m["frame_entropy"] for m in per_frame) / len(per_frame),
        "dirty_cells": (sum(dirty) / len(dirty)) if dirty else 0.0,
        "dirty_ratio": (sum(dirty) / total_cells) if total_cells else 0.0,
    }

    if meta:
        result["fps"] = meta["frames"] / (meta["elapsed_ms"] / 1000.0)
        result["harness_frames"] = meta["frames"]
        result["harness_elapsed_ms"] = meta["elapsed_ms"]
    else:
        result["fps"] = None
        print("[frame-bench] WARNING: ###META### line not found; fps unknown",
              file=sys.stderr)

    # bytes the terminal absorbs per second (redraw churn rate)
    if result["fps"]:
        result["bytes_per_sec"] = result["bytes_frame"] * result["fps"]
    return result


def report(result, label):
    fps = result.get("fps")
    fps_s = f"{fps:10.1f}" if fps else "        n/a"
    print(f"\n  frame benchmark — {label}")
    print("  " + "-" * 52)
    print(f"  frames captured      {result['frames_captured']:>10}")
    print(f"  fps (render path)    {fps_s}")
    print(f"  avg rows             {result['avg_rows']:>10.1f}")
    print(f"  avg width            {result['avg_width']:>10.1f}")
    print(f"  bytes/frame          {result['bytes_frame']:>10.1f}")
    print(f"  density gini         {result['density_gini']:>10.4f}")
    print(f"  frame entropy        {result['frame_entropy']:>10.4f} bits/char")
    print(f"  dirty cells/frame    {result['dirty_cells']:>10.1f}")
    print(f"  dirty ratio          {result['dirty_ratio']:>10.4f}")
    if result.get("bytes_per_sec"):
        print(f"  bytes/sec churn      {result['bytes_per_sec']:>10.1f}")


def compare(before, after):
    """Side-by-side A/B table with deltas."""
    rows = [
        ("fps (render path)", "fps", "{:.1f}", "higher"),
        ("avg rows", "avg_rows", "{:.1f}", "lower"),
        ("avg width", "avg_width", "{:.1f}", "context"),
        ("bytes/frame", "bytes_frame", "{:.1f}", "lower"),
        ("density gini", "density_gini", "{:.4f}", "lower"),
        ("frame entropy", "frame_entropy", "{:.4f}", "higher"),
        ("dirty cells/frame", "dirty_cells", "{:.1f}", "lower"),
        ("dirty ratio", "dirty_ratio", "{:.4f}", "lower"),
        ("bytes/sec churn", "bytes_per_sec", "{:.1f}", "lower"),
    ]
    print("\n  A/B comparison (before -> after)")
    print("  " + "-" * 68)
    for name, key, fmt, better in rows:
        a, b = before.get(key), after.get(key)
        if a is None or b is None:
            print(f"  {name:<22}{'n/a':>12}{'n/a':>12}   (missing)")
            continue
        delta = b - a
        pct = (delta / a * 100.0) if a else 0.0
        marker = ""
        if delta != 0:
            if better == "higher":
                marker = "+" if delta > 0 else "-"
            elif better == "lower":
                marker = "+" if delta < 0 else "-"
        print(f"  {name:<22}{fmt.format(a):>12}{fmt.format(b):>12}"
              f"   {delta:+.4f} ({pct:+.1f}%) {marker}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--save", metavar="JSON", help="write metrics to this file")
    ap.add_argument("--compare", metavar="JSON",
                    help="compare against a saved metrics file")
    ap.add_argument("--quick", action="store_true",
                    help="1s render budget (smoke run)")
    ap.add_argument("--frames", metavar="FILE",
                    help="compute metrics from a raw capture instead of running cargo")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECS,
                    help=f"harness timeout in seconds (default {DEFAULT_TIMEOUT_SECS})")
    ap.add_argument("--label", default=None, help="label for the report")
    args = ap.parse_args()

    if args.frames:
        stdout = Path(args.frames).read_text()
        frames, meta = split_frames(stdout)
    else:
        stdout = run_harness(args.quick, args.timeout)
        frames, meta = split_frames(stdout)

    result = compute(frames, meta)
    label = args.label or ("quick" if args.quick else "full 10s")
    report(result, label)

    if args.save:
        Path(args.save).write_text(json.dumps(result, indent=2) + "\n")
        print(f"\n  metrics saved: {args.save}")

    if args.compare:
        before = json.loads(Path(args.compare).read_text())
        compare(before, result)


if __name__ == "__main__":
    main()
