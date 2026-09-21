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

# Loopback hands the cgroup hooks ~64 KiB GSO skbs (lo MTU 65536, no NIC
# segmentation). A policer whose token bucket — burst = rate clamped to
# the 4096-byte floor — is smaller than ONE skb can only admit control
# packets: a 1kb/s rung delivers ~0 payload on loopback no matter how
# healthy the kernel code is (a real NIC's 1448-byte MSS never hits
# this). NIGHT-improve-12: rungs below this line get a zero floor on the
# measured-rate band (kernel drops still prove enforcement) and skip
# the byte-accounting cross-check (per-skb headers dominate delivered
# bytes there).
LOOPBACK_GSO_SKB = 65_536

# Below this delivered payload the accounting cross-check compares
# header noise against nothing — SKIP instead of FAIL
# (NIGHT-improve-12).
ACCOUNTING_FLOOR_BYTES = 64 * 1024

# NIGHT-improve-15: the second loopback physics regime. default_burst
# (src/ebpf/limiter/format.rs) banks "1 second of traffic, clamped
# 4KB-100MB": up to 100 MB/s the burst is a full second of tokens, but
# at 1 GB/s the clamp leaves only 0.1 s. A cgroup policer DROPS, it
# never queues — hungry flows burst-drain the cushion, lose whole
# 64 KiB loopback MSS in one shot (lo MTU 65536: one skb = one loss
# event), and stall on the 200 ms Linux min-RTO, during which the
# bucket re-banks at most one cushion. The AIMD aggregate therefore
# bottoms at cushion / min-RTO (~500 MB/s wherever the clamp binds),
# regardless of flow count. The 2026-09-21 nightpc evidence: 1gb
# measured 55.7% single-flow AND 53.9% six-flow (flow count is not
# the variable — the improve-14 "staggered dips" theory died there)
# while the cap was never exceeded and the drops + accounting rows
# held. Real networks (RTT in milliseconds) do not hit this: on
# loopback's 30 us RTT one +1-MSS probe is worth ~2 GB/s of
# overshoot. Under-delivery there is physics, so the ladder's floor
# follows the model; the cap, kernel drops, and byte accounting
# still carry the enforcement verdict.
DEFAULT_BURST_CAP = 100_000_000  # mirror of format.rs default_burst clamp
TCP_MIN_RTO_S = 0.2              # Linux TCP_RTO_MIN floor

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

def loopback_rate_floor(rate_bps):
    """Effective BAND_LO for a configured rate on the loopback engine.

    0.0 for rates whose token bucket (burst = rate clamped to >= 4096)
    can never admit a single loopback GSO skb — under-delivery there is
    loopback physics, not an enforcement miss, so the ceiling and the
    kernel-drop proof carry the verdict alone. Rates at or above the
    skb size refill enough tokens per skb to reach steady state — but
    once default_burst's 100 MB clamp binds, the cushion shrinks below
    one min-RTO of refill and a dropper's AIMD aggregate bottoms at
    cushion / min-RTO: the floor follows that model instead of the
    full band (NIGHT-improve-15; DEFAULT_BURST_CAP's comment carries
    the physics and the nightpc evidence). Both regimes still cap at
    BAND_HI — a policer must never over-deliver past the band.
    """
    if rate_bps < LOOPBACK_GSO_SKB:
        return 0.0
    cushion = min(rate_bps, DEFAULT_BURST_CAP)
    return min(BAND_LO, cushion / (TCP_MIN_RTO_S * rate_bps))


def band_check(name, measured_bps, configured_bps, extra="", lo=None, hi=None):
    """Record a measured-vs-configured rate verdict.

    lo/hi override the module band for a single call (the GSO floor
    passes lo=0.0 for starved rungs); both default to the live module
    state so --band keeps working.
    """
    ratio = measured_bps / configured_bps if configured_bps else 0.0
    lo_eff = BAND_LO if lo is None else lo
    hi_eff = BAND_HI if hi is None else hi
    verdict = "PASS" if lo_eff <= ratio <= hi_eff else "FAIL"
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
