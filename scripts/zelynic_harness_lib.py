# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic test-harness shared engine (NIGHT-improve-11 / security-4).

The two flagship harnesses — supermassive-test.py (NIGHT-master-2,
the command-surface matrix) and limiter-depth-test.py (NIGHT-master-1,
the limiter accuracy depth test) — grew the SAME engine helpers by
copy-paste: verdict recording, zelynic subprocess control, status-JSON
reading, environment probes, binary resolution, and the final report.
Fourteen near-identical functions across two 1000-line files is the
classic drift trap: the brutal twin got the kernfs-inode fix
(NIGHT-hunt-31) days before the depth twin, and the same week the
brutal twin gained the target/pro-native-gnu binary candidate the
depth twin never saw. This module is the single engine both import.

Contract:
  * python3 stdlib only (the cross-distro minimum both harnesses
    promise — no curl requirement, no pip requirement).
  * Module-level state (RESULTS, BINARY, BAND_LO/HI) is owned HERE
    and lives in this module's namespace; each harness process
    imports this module exactly once, so per-process state is safe.
    Harnesses keep their own cgroup fleet, traffic server, and mode
    string — those shapes genuinely differ.
  * `from zelynic_harness_lib import *` binds the helpers into a
    harness namespace; state overrides (band, binary) must go
    through `zelynic_harness_lib.BINARY = ...` style writes so the
    functions defined here observe them.
"""

import json
import os
import shutil
import subprocess
import sys
import time

# ── shared constants ────────────────────────────────────────────────────────

CGROUP_ROOT = "/sys/fs/cgroup"
PIN_DIR = "/sys/fs/bpf/zelynic"
CHUNK = 256 * 1024

# Verdict band for measured-vs-configured rates (overridable via --band).
BAND_LO = 0.65
BAND_HI = 1.30

# Harness state (see the module docstring's ownership contract).
RESULTS = []
BINARY = ""


# ── output + verdict recording ──────────────────────────────────────────────

def out(msg=""):
    print(msg, flush=True)


def fmt_bps(n):
    if n >= 1e9:
        return f"{n / 1e9:.2f} GB/s"
    if n >= 1e6:
        return f"{n / 1e6:.2f} MB/s"
    if n >= 1e3:
        return f"{n / 1e3:.1f} KB/s"
    return f"{n:.0f} B/s"


def mbps(n):
    return f"{n * 8 / 1e6:.2f} Mbps"


def record(name, verdict, detail="", metrics=None):
    RESULTS.append(
        {"test": name, "verdict": verdict, "detail": detail, "metrics": metrics or {}}
    )
    mark = {"PASS": "  OK ", "FAIL": "  X  ", "SKIP": "  -- "}[verdict]
    out(f"{mark}{name}" + (f" — {detail}" if detail else ""))
    return verdict


# ── zelynic subprocess control ──────────────────────────────────────────────

def run_zel(args, timeout=30):
    try:
        p = subprocess.run([BINARY] + args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except OSError as e:
        return 127, "", str(e)


def status_json():
    rc, stdout, _ = run_zel(["status", "--print-json"])
    if rc != 0:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return None


def limit_entry(doc, cgroup_id):
    if not doc:
        return None
    for entry in doc.get("limits", []):
        if entry.get("cgroup_id") == cgroup_id:
            return entry
    return None


# ── environment probes ──────────────────────────────────────────────────────

def pretty_name():
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown distro"


def cpu_model():
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "unknown"


def cgroup2_mounted():
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == CGROUP_ROOT:
                    return parts[2] == "cgroup2"
    except OSError:
        pass
    return False


def bpffs_mounted_at(path="/sys/fs/bpf"):
    """True when `path` is a MOUNTED bpf filesystem (fstype "bpf").

    NIGHT-improve-11 / security-4 fix: the old env check tested
    os.path.isdir(PIN_DIR) — the zelynic PIN DIRECTORY, which exists
    only after zelynic has pinned maps — and labeled it "BPF
    filesystem mounted". On a fresh-but-healthy host (bpffs mounted,
    zelynic never run yet) the check failed and stopped the whole
    harness at the environment gate: the exact "what the hell bro"
    run of 2026-09-21. The filesystem mount is the requirement; the
    pin directory is zelynic's own state and materializes on first
    attach. Mirrors zelynic's own attach preflight
    (capabilities::bpffs_mounted_at, NIGHT-hunt-28).
    """
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == path:
                    return parts[2] == "bpf"
    except OSError:
        pass
    return False


def binary_version():
    """First line of `zelynic -V`, for the env banner — catches the
    stale-distro-install trap next to the binary path itself."""
    rc, stdout, _ = run_zel(["-V"])
    lines = (stdout or "").strip().splitlines()
    if rc == 0 and lines:
        return lines[0]
    return "version unreadable"


# ── binary resolution ───────────────────────────────────────────────────────

def resolve_binary(explicit, script_hint):
    """Resolve the zelynic binary under test into BINARY.

    NIGHT-improve-11 fix (both twins had it): repo-local builds now
    OUTRANK the system PATH. The old order put `which zelynic` first,
    so a harness run from a fresh checkout tested the STALE distro
    install (/usr/bin/zelynic, months old) while the just-built
    target/pro-native-gnu/zelynic sat unused — the owner's 2026-09-21
    run tested v1.98-era code against a v11 working tree without
    knowing. Order now: --binary flag, ZELYNIC_BINARY env, then the
    repo-local candidates, then the PATH — an explicit choice always
    wins, but nothing silent outranks the checkout being tested.
    """
    global BINARY
    candidates = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("ZELYNIC_BINARY"):
        candidates.append(os.environ["ZELYNIC_BINARY"])
    candidates += ["./zelynic", "./target/pro-native-gnu/zelynic", "./target/release/zelynic"]
    found = shutil.which("zelynic")
    if found:
        candidates.append(found)
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            BINARY = cand
            return True
    out("zelynic binary not found. Tried: " + ", ".join(candidates))
    out("Build it first:  cargo build --release --features ebpf")
    out(f"Or point at one: sudo {script_hint} --binary ./zelynic")
    return False


# ── verdict band ────────────────────────────────────────────────────────────

def band_check(name, measured_bps, configured_bps, extra=""):
    ratio = measured_bps / configured_bps if configured_bps else 0.0
    verdict = "PASS" if BAND_LO <= ratio <= BAND_HI else "FAIL"
    detail = (
        f"configured {fmt_bps(configured_bps)} ({mbps(configured_bps)}), "
        f"measured {fmt_bps(measured_bps)} ({ratio * 100:.1f}%)"
        + (f"; {extra}" if extra else "")
    )
    record(name, verdict, detail, {"measured_bps": round(measured_bps), "ratio": round(ratio, 3)})
    return verdict


# ── shared stages (identical in both twins) ─────────────────────────────────

def doctor_check():
    rc, stdout, _ = run_zel(["doctor", "--print-json"])
    if rc != 0:
        return record("doctor: eBPF support", "FAIL", f"exit {rc}") == "PASS"
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError:
        return record("doctor: eBPF support", "FAIL", "doctor JSON could not be parsed") == "PASS"
    supported = bool(doc.get("ebpf_supported"))
    warnings = "; ".join(doc.get("warnings", []))
    return record(
        "doctor: eBPF support", "PASS" if supported else "FAIL", warnings or "no warnings"
    ) == "PASS"


def dmesg_scan():
    try:
        p = subprocess.run(["dmesg", "--color=never"], capture_output=True,
                           text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return record("dmesg: kernel log clean", "SKIP", "dmesg unavailable or restricted") == "PASS"
    lines = p.stdout.splitlines()[-200:]
    bad = [
        line for line in lines
        if any(k in line.lower() for k in ("bpf", "zelynic"))
        and any(k in line.lower() for k in ("error", "fail", "warn", "bug", "oops"))
    ]
    return record(
        "dmesg: kernel log clean", "PASS" if not bad else "FAIL",
        "; ".join(bad[:3]) if bad else "no BPF errors in the last 200 lines",
    ) == "PASS"


def final_report(start, mode, ok_line):
    elapsed = time.perf_counter() - start
    counts = {v: sum(1 for r in RESULTS if r["verdict"] == v) for v in ("PASS", "FAIL", "SKIP")}
    out()
    out("━━━ verdict ━━━")
    out(
        f"  {counts['PASS']} passed, {counts['FAIL']} failed, "
        f"{counts['SKIP']} skipped — {mode} mode, {elapsed:.0f}s total"
    )
    if counts["FAIL"] == 0:
        out(f"  {ok_line}")
    else:
        out("  FAILURES present — see the marked rows above; run with --json for")
        out("  machine-readable output and file the numbers in CROSS_DISTRO_RESULTS.")
    return counts["FAIL"] == 0
