# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic test-harness shared engine (NIGHT-improve-11 / security-4).

The flagship harnesses — supermassive-test.py (NIGHT-master-2, the
command-surface matrix), limiter-depth-test.py (NIGHT-master-1, the
limiter accuracy depth test), and supermassive-test-v2.py
(NIGHT-improve-23, the daily-use E2E simulation; imports the v1
matrix whole and adds the real-internet lane) — grew the SAME
engine helpers by copy-paste back when there were two: verdict
recording, zelynic subprocess control, status-JSON reading,
environment probes, binary resolution, and the final report.
Fourteen near-identical functions across two 1000-line files was the
classic drift trap: the brutal twin got the kernfs-inode fix
(NIGHT-hunt-31) days before the depth twin, and the same week the
brutal twin gained the target/pro-native-gnu binary candidate the
depth twin never saw. This module is the single engine all three
import.

Contract:
  * python3 stdlib only (the cross-distro minimum every harness
    promises — no curl requirement, no pip requirement).
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
import re
import shutil
import subprocess
import time

# ── shared constants ────────────────────────────────────────────────────────

CGROUP_ROOT = "/sys/fs/cgroup"
PIN_DIR = "/sys/fs/bpf/zelynic"
CHUNK = 256 * 1024

# Verdict band for measured-vs-configured rates (overridable via --band).
BAND_LO = 0.65
BAND_HI = 1.30

# Loopback hands the cgroup hooks ~64 KiB GSO skbs (lo MTU 65536, no NIC
# segmentation). TWO regimes key off this constant. (1) NIGHT-lts-8
# closed the sub-skb BUCKET regime: default_burst's floor is now one
# full skb (BURST_FLOOR_BYTES, 64 KiB), so every rate's bucket can
# admit a whole skb — no rung is barred from its own packet class
# anymore (a real NIC's 1448-byte MSS never hit this; loopback did).
# (2) The sub-skb WINDOW regime survives and is physics, not
# enforcement: when one measurement window's refill cannot bank a
# whole skb (rate x window < 64 KiB), delivery is bimodal (a skb
# lands or nothing does), so the band floor drops to zero there and
# the ceiling plus kernel-drop proof carry the verdict
# (NIGHT-improve-12; window-aware since lts-8).
LOOPBACK_GSO_SKB = 65_536

# Below this delivered payload the accounting cross-check compares
# header noise against nothing — SKIP instead of FAIL
# (NIGHT-improve-12).
ACCOUNTING_FLOOR_BYTES = 64 * 1024

# NIGHT-improve-15: the second loopback physics regime. default_burst
# (src/ebpf/limiter/format.rs) banks "1 second of traffic, clamped
# 64KB-100MB" (the floor raised from 4 KB by NIGHT-lts-8, the GSO
# super-packet admissibility fix): up to 100 MB/s the burst is a full
# second of tokens, but
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
DEFAULT_BURST_CAP = 100_000_000  # mirror of the default_burst 100 MB ceiling
DEFAULT_BURST_FLOOR = 65_536  # mirror of types.rs BURST_FLOOR_BYTES (NIGHT-lts-8)
TCP_MIN_RTO_S = 0.2  # Linux TCP_RTO_MIN floor


def default_burst(rate_bps):
    """Mirror of format.rs default_burst — the burst the CLI writes.

    One second of traffic (rate bytes read straight), clamped between
    the 64 KiB GSO super-packet floor and the 100 MB ceiling. The
    harness must predict the same burst the kernel bucket carries or
    its budget/ratio models drift from reality (NIGHT-lts-8 made the
    floor explicit here for exactly that reason).
    """
    return min(max(rate_bps, DEFAULT_BURST_FLOOR), DEFAULT_BURST_CAP)


# Harness state (see the module docstring's ownership contract).
RESULTS = []
BINARY = ""

# The checkout under test: the parent of scripts/ (the same anchor
# bootstrap-ebpf.sh and build.sh resolve their repo root from). Since
# NIGHT-refactor-1 this lib lives one directory deeper, in scripts/lib/,
# so the anchor is two levels up. Everything the harness resolves —
# build outputs, the expected version — anchors HERE, never to the
# caller's CWD (NIGHT-improve-16).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Repo-local build outputs of the canonical build commands, absolute
# and therefore CWD-independent (.cargo/config.toml is the source of
# truth for where each command lands):
#   root copy          — ./zelynic (legacy dev convenience)
#   pro-native-gnu     — cargo pro-native-gnu
#   pro-native-musl    — cargo pro-native-musl (NEW in improve-16: the
#                        musl alias output was never a candidate, so a
#                        static build could only be tested via --binary)
#   plain release      — cargo build --release --features ebpf
# NIGHT-improve-22 adds the four arch-baseline alias outputs
# (pro-linux-amd64-v3/v4-gnu, pro-linux-amd64-v3/v4-musl) so a freshly built
# release-shape binary outranks a stale native build of older code —
# the same newest-mtime rule below picks whatever was just built.
# Among the candidates that exist, resolution picks the NEWEST mtime
# ("test what was just built"): versions can match while code differs,
# and a fresh musl build should outrank a stale gnu binary from an
# older commit (NIGHT-improve-16).
REPO_BINARY_CANDIDATES = [
    os.path.join(REPO_ROOT, "zelynic"),
    os.path.join(REPO_ROOT, "target", "pro-native-gnu", "zelynic"),
    os.path.join(REPO_ROOT, "target", "x86_64-unknown-linux-musl", "pro-native-musl", "zelynic"),
    os.path.join(REPO_ROOT, "target", "pro-linux-amd64-v3-gnu", "zelynic"),
    os.path.join(REPO_ROOT, "target", "pro-linux-amd64-v4-gnu", "zelynic"),
    os.path.join(
        REPO_ROOT, "target", "x86_64-unknown-linux-musl", "pro-linux-amd64-v3-musl", "zelynic"
    ),
    os.path.join(
        REPO_ROOT, "target", "x86_64-unknown-linux-musl", "pro-linux-amd64-v4-musl", "zelynic"
    ),
    os.path.join(REPO_ROOT, "target", "release", "zelynic"),
]

# A version-shaped token inside a `-V` header line. Accepts both
# shapes the wild has shown: the current "zelynic: v11.0.0-dev.1" and
# the legacy "Version: v4.0.0-alpha" (the stale distro install that
# slipped past the 2026-09-21 debian13 run).
_VERSION_TOKEN = re.compile(r"v?([0-9]+(?:\.[0-9]+)+(?:[-+][0-9A-Za-z.-]+)*)")


# ── output + verdict recording ──────────────────────────────────────────────


def out(msg=""):
    print(msg, flush=True)


def fmt_bps(n):
    # One decimal on every tier + a TB tier, mirroring the Rust-side
    # format_bytes contract (limiter/format.rs): the harness's verdict
    # details are cross-read against `zelynic status` output, so the
    # two surfaces must not disagree on digit counts or units.
    if n >= 1e12:
        return f"{n / 1e12:.1f} TB/s"
    if n >= 1e9:
        return f"{n / 1e9:.1f} GB/s"
    if n >= 1e6:
        return f"{n / 1e6:.1f} MB/s"
    if n >= 1e3:
        return f"{n / 1e3:.1f} KB/s"
    return f"{n:.0f} B/s"


def mbps(n):
    return f"{n * 8 / 1e6:.2f} Mbps"


def record(name, verdict, detail="", metrics=None):
    RESULTS.append({"test": name, "verdict": verdict, "detail": detail, "metrics": metrics or {}})
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


def version_token(first_line):
    """Extract the version token from a `zelynic -V` header line, or
    None when no version-shaped token is present. Feeds the resolve
    gate; see _VERSION_TOKEN for the accepted shapes."""
    m = _VERSION_TOKEN.search(first_line or "")
    return m.group(1) if m else None


def repo_version():
    """The [package] version of the checkout under test, or None.

    Stdlib-only scan (this module's no-dependency contract): track the
    current [section] and take the first `version = "..."` under
    [package], before any dependency table can shadow it. This is the
    version resolve_binary demands from the binary it is about to
    test — the checkout's own CARGO_PKG_VERSION.
    """
    path = os.path.join(REPO_ROOT, "Cargo.toml")
    try:
        section = ""
        with open(path, encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if stripped.startswith("[") and stripped.endswith("]"):
                    section = stripped
                    continue
                if section == "[package]":
                    m = re.match(r'version\s*=\s*"([^"]+)"', stripped)
                    if m:
                        return m.group(1)
    except OSError:
        pass
    return None


# ── binary resolution ───────────────────────────────────────────────────────


def resolve_binary(explicit, script_hint):
    """Resolve the zelynic binary under test into BINARY, then GATE it.

    NIGHT-improve-11 made repo-local builds outrank the system PATH;
    NIGHT-improve-16 closes the two holes that left in practice:

      * The candidates were CWD-relative and missed the musl alias
        output entirely. They are now absolute, anchored at REPO_ROOT
        (CWD-independent), cover all four build outputs, and when
        several exist the NEWEST mtime wins — test what was just
        built, not what was built longest ago.
      * The PATH fallback survived as a silent escape hatch: on the
        2026-09-21 debian13 run every repo candidate was missing (the
        build had never succeeded there), `which zelynic` found a
        stale /usr/bin/zelynic v4.0.0-alpha, and the harness happily
        tested a v4 CLI surface against the v11 schema — 12 of 23
        rows failed on decoy mismatches (unrecognized subcommand,
        old rate guards, no status-JSON rows). The banner SHOWED the
        version but nothing enforced it. Now a version GATE runs
        before any test: the binary's -V token must equal the
        checkout's Cargo.toml version, or resolution aborts with the
        one-command fix. Explicit choices (--binary / ZELYNIC_BINARY)
        still win the selection, but they pass the same gate — the
        harness tests THIS checkout, never a foreign one.
    """
    global BINARY
    repo_hits = [c for c in REPO_BINARY_CANDIDATES if os.path.isfile(c) and os.access(c, os.X_OK)]
    repo_hits.sort(key=os.path.getmtime, reverse=True)
    candidates = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("ZELYNIC_BINARY"):
        candidates.append(os.environ["ZELYNIC_BINARY"])
    candidates += repo_hits
    found = shutil.which("zelynic")
    if found:
        candidates.append(found)
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            BINARY = cand
            break
    else:
        out("zelynic binary not found. Tried (repo builds first):")
        out("  " + (", ".join(candidates) or "no repo build, nothing on PATH"))
        out("One command: ./scripts/dev/bootstrap-ebpf.sh")
        out("  (installs the eBPF toolchain pair AND builds the flagship")
        out("   binary — clone, bootstrap, test, done)")
        out(f"Or point at one: {script_hint} --binary ./target/pro-native-gnu/zelynic")
        return False

    # ── version gate: this harness tests THIS checkout ────────────────
    rc, stdout, _ = run_zel(["-V"])
    first = (stdout or "").strip().splitlines()
    first = first[0] if rc == 0 and first else ""
    got = version_token(first)
    want = repo_version()
    if want is None:
        # A checkout without a parsable [package] version cannot happen
        # in this repo; if the parser drifts, say so and stay out of the
        # way rather than blocking every harness on a parser bug.
        out(f"  warning: version gate unavailable — no parsable version in {REPO_ROOT}/Cargo.toml")
        return True
    if got != want:
        out("BINARY GATE: refusing to test a zelynic that is not this checkout's build.")
        out(f"  {BINARY} reports: {first or '(no version line)'}")
        out(f"  this checkout is: v{want} (Cargo.toml) — a wrong version means a")
        out("  wrong CLI surface and a wrong status schema: every verdict would")
        out("  be decoy noise (the 2026-09-21 debian13 run lost 12 of 23 rows")
        out("  to a stale /usr/bin/zelynic v4.0.0-alpha this way).")
        out("One command: ./scripts/dev/bootstrap-ebpf.sh   (prerequisites + flagship build)")
        out(f"Or point at a matching build: {script_hint} --binary ./target/pro-native-gnu/zelynic")
        return False
    return True


# ── verdict band ────────────────────────────────────────────────────────────


def loopback_rate_floor(rate_bps, window_s=1.0):
    """Effective BAND_LO for a configured rate on the loopback engine.

    0.0 for rates whose ONE-WINDOW refill cannot bank a whole loopback
    GSO skb (rate x window_s < 64 KiB — delivery is bimodal there:
    a skb lands or nothing does, loopback physics, not an enforcement
    miss, so the ceiling and the kernel-drop proof carry the verdict
    alone). The sub-skb BUCKET regime retired with NIGHT-lts-8's floor
    (burst >= 64 KiB for every rate now); the window regime survives.
    Rates whose window refill covers a skb reach steady state — but
    once default_burst's 100 MB clamp binds, the cushion shrinks below
    one min-RTO of refill and a dropper's AIMD aggregate bottoms at
    cushion / min-RTO: the floor follows that model instead of the
    full band (NIGHT-improve-15; DEFAULT_BURST_CAP's comment carries
    the physics and the nightpc evidence). Both regimes still cap at
    BAND_HI — a policer must never over-deliver past the band.
    """
    if rate_bps * window_s < LOOPBACK_GSO_SKB:
        return 0.0
    cushion = default_burst(rate_bps)
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
        f"measured {fmt_bps(measured_bps)} ({ratio * 100:.1f}%)" + (f"; {extra}" if extra else "")
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
    return (
        record("doctor: eBPF support", "PASS" if supported else "FAIL", warnings or "no warnings")
        == "PASS"
    )


def dmesg_scan():
    try:
        p = subprocess.run(["dmesg", "--color=never"], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return (
            record("dmesg: kernel log clean", "SKIP", "dmesg unavailable or restricted") == "PASS"
        )
    lines = p.stdout.splitlines()[-200:]
    bad = [
        line
        for line in lines
        if any(k in line.lower() for k in ("bpf", "zelynic"))
        and any(k in line.lower() for k in ("error", "fail", "warn", "bug", "oops"))
    ]
    return (
        record(
            "dmesg: kernel log clean",
            "PASS" if not bad else "FAIL",
            "; ".join(bad[:3]) if bad else "no BPF errors in the last 200 lines",
        )
        == "PASS"
    )


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
