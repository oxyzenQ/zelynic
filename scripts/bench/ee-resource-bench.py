#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
"""Measure the live eagle-eyes monitor's resource cost.

Spawns eagle-eyes in a real pty, lets it settle, samples /proc/<pid>/*
over a fixed window, prints CPU%, RSS, thread count, context switches,
and a verdict against the owner's target (under 0.1% of one core).

Usage:
    sudo ./scripts/bench/ee-resource-bench.sh
    sudo ./scripts/bench/ee-resource-bench.sh --duration 60
    sudo ./scripts/bench/ee-resource-bench.sh --binary ./target/release/zelynic
"""

import argparse
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time


def fail(msg):
    print(f"ee-resource-bench: cannot run — {msg}", file=sys.stderr, flush=True)
    sys.exit(2)


def read_stat(pid):
    """(utime_jiffies, stime_jiffies) from /proc/<pid>/stat."""
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().split()
    return int(fields[13]), int(fields[14])


def read_status(pid):
    """All /proc/<pid>/status key:value pairs into a dict."""
    out = {}
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if ":" in line:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    return out


def read_thread_names(pid):
    names = []
    try:
        for tid in os.listdir(f"/proc/{pid}/task"):
            try:
                with open(f"/proc/{pid}/task/{tid}/comm") as f:
                    names.append(f.read().strip())
            except OSError:
                pass
    except OSError:
        pass
    return names


def resolve_binary(explicit):
    if explicit:
        if not (os.path.isfile(explicit) and os.access(explicit, os.X_OK)):
            fail(f"binary not executable: {explicit}")
        return explicit
    for c in ("/usr/bin/zelynic",):
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    fail("no zelynic binary found — pass --binary PATH or install to /usr/bin/zelynic")


def main():
    ap = argparse.ArgumentParser(
        prog="ee-resource-bench",
        description="measure live eagle-eyes CPU/RSS/threads over a fixed window",
    )
    ap.add_argument("--binary", help="path to zelynic (default /usr/bin/zelynic)")
    ap.add_argument(
        "--settle", type=int, default=3, help="seconds to wait before sampling (default 3)"
    )
    ap.add_argument(
        "--duration", type=int, default=30, help="sampling window in seconds (default 30)"
    )
    ap.add_argument("--interval", default="1s", help="eagle-eyes --interval (default 1s)")
    ap.add_argument(
        "--target",
        type=float,
        default=0.1,
        help=(
            "CPU budget, percent of one core (default 0.1 — the night-perf-1 "
            "wake-skeleton budget; the owner's live-TUI budget is 0.5 and the "
            "htop/btop range for live TUIs is 1-5)"
        ),
    )
    args = ap.parse_args()

    if os.geteuid() != 0:
        fail("eagle-eyes reads BPF maps — run with sudo")
    binary = resolve_binary(args.binary)
    if args.duration < 5:
        fail("--duration must be >= 5 (shorter windows are noise)")

    # Real pty so eagle-eyes enters its TUI path (it refuses pipes).
    master_fd, slave_fd = pty.openpty()
    fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))

    print(f">> spawning {binary} eagle-eyes --interval {args.interval} ...", flush=True)
    proc = subprocess.Popen(
        [binary, "eagle-eyes", "--interval", args.interval],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
    )
    os.close(slave_fd)
    pid = proc.pid

    def drain(timeout=0.1):
        while select.select([master_fd], [], [], timeout)[0]:
            try:
                os.read(master_fd, 65536)
            except OSError:
                break

    try:
        print(f">> settling {args.settle}s ...", flush=True)
        t_end = time.time() + args.settle
        while time.time() < t_end:
            drain(0.1)
            if proc.poll() is not None:
                fail(f"eagle-eyes exited early with code {proc.returncode}")

        # Snapshot before
        u0, s0 = read_stat(pid)
        st0 = read_status(pid)
        names_before = read_thread_names(pid)
        rss0_kb = int(st0.get("VmRSS", "0 kB").split()[0])
        vcs0 = int(st0.get("voluntary_ctxt_switches", "0"))
        ivcs0 = int(st0.get("nonvoluntary_ctxt_switches", "0"))

        print(f">> sampling {args.duration}s ...", flush=True)
        t_start = time.time()
        while time.time() - t_start < args.duration:
            drain(0.1)
            if proc.poll() is not None:
                fail(f"eagle-eyes exited early with code {proc.returncode}")
        elapsed = time.time() - t_start

        # Snapshot after
        u1, s1 = read_stat(pid)
        st1 = read_status(pid)
        names_after = read_thread_names(pid)
        rss1_kb = int(st1.get("VmRSS", "0 kB").split()[0])
        vcs1 = int(st1.get("voluntary_ctxt_switches", "0"))
        ivcs1 = int(st1.get("nonvoluntary_ctxt_switches", "0"))

        clk_tck = os.sysconf("SC_CLK_TCK")
        n_cores = os.cpu_count() or 1
        cpu_s = ((u1 + s1) - (u0 + s0)) / clk_tck
        pct_per_core = (cpu_s / elapsed) * 100
        pct_of_all = pct_per_core / n_cores

        # Report
        print()
        print("━━━ eagle-eyes resource report ━━━")
        print(f"  binary:              {binary}")
        print(f"  host cores:          {n_cores}")
        print(f"  settle / duration:   {args.settle}s / {elapsed:.1f}s")
        print(f"  interval:            {args.interval}")
        print()
        print(f"  CPU time used:       {cpu_s * 1000:.2f} ms")
        print(f"  CPU % (per core):    {pct_per_core:.4f} %")
        print(f"  CPU % (of all cores):{pct_of_all:.4f} %")
        print()
        print(f"  RSS (before):        {rss0_kb / 1024:.2f} MB")
        print(f"  RSS (after):         {rss1_kb / 1024:.2f} MB")
        rss_delta_mb = (rss1_kb - rss0_kb) / 1024
        print(f"  RSS delta:           {rss_delta_mb:+.2f} MB")
        rss_verdict = (
            "no leak detected" if rss_delta_mb < 0.1 else "REVIEW — RSS grew over the window"
        )
        print(f"  RSS verdict:         {rss_verdict}")
        print()
        print(f"  threads (before):    {len(names_before)} — {', '.join(names_before)}")
        print(f"  threads (after):     {len(names_after)} — {', '.join(names_after)}")
        print()
        dvcs = vcs1 - vcs0
        divcs = ivcs1 - ivcs0
        print(f"  ctx switches (vol):  {dvcs} ({dvcs / elapsed:.1f}/s)")
        print(f"  ctx switches (inv):  {divcs} ({divcs / elapsed:.1f}/s)")
        print()
        verdict = (
            "PEAK" if pct_per_core < args.target else f"REVIEW — above the {args.target:g}% target"
        )
        print(f"  verdict:             {verdict}")
        print(f"  (target: <{args.target:g}% per core; the htop/btop range for live TUIs is 1-5%)")

    finally:
        try:
            os.write(master_fd, b"q")
        except OSError:
            pass
        try:
            rc = proc.wait(timeout=5)
            print(f"\n>> eagle-eyes exited cleanly (code {rc})")
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                print("\n>> eagle-eyes had to be killed (did not exit on 'q' within 7s)")
        os.close(master_fd)


if __name__ == "__main__":
    sys.exit(main())
