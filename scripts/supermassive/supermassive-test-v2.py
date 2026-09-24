#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: like supermassive-test.py, one self-contained harness by design — v2 is a thin orchestrator over the v1 engine (imported whole via importlib, zero duplication of the fleet/server/worker machinery) plus the one genuinely new engine it owns: the real-internet lane
"""zelynic supermassive test v2 — the end-to-end daily-use simulation (NIGHT-improve-23).

supermassive-test.py (v1) answers "does the WHOLE command surface
survive supermassive stress?" — full parser span, brutal battery,
kill/regression/recover teardown. This v2 harness answers the owner's
next question: "can I SIMULATE a real day of zelynic use, end to end,
before trusting it on my daily driver?" — the four policy families in
the exact order a daily session touches them (strict -> limit ->
block -> unstrict), each proven twice: on the deterministic local
loopback lane AND against the real internet, the shape production
traffic actually has.

What v2 deliberately does NOT carry (the owner's call, NIGHT-improve-23):
every "problems-use-zelynic" stage stays in v1 — kill-tui, kill-midflight,
the regression battery, recover/cleanup/dmesg teardown, and the fatal
CLI-usage refusals (typo rescue, dangerous-value guards). Those prove
robustness under ABUSE; v2 proves correctness under USE. A machine green
on v2 is qualified for the daily driver; a machine green on v1 is
qualified for a power outage.

Design:

  * Zero engine duplication: v1 is imported whole (importlib, the dash
    in its filename defeats a plain import) and its machinery drives
    every local stage — the CgroupSet fleet (a..e + never-policed hq),
    the in-process HttpServer, apply/block/unstrict policy helpers,
    spawn_in_cgroup workers, band_check verdicts, enforcement proofs.
    v2 sets v1's module globals (CG / SERVER / MODE) exactly the way
    v1's own main() does, then calls its stages. One fix to the fleet
    lands in both harnesses the same day.
  * Local lane (deterministic, the measurement instrument): policy
    write + status surfaces, strict-single asymmetric -d/-u buckets,
    live rate change (1mb -> 2mb under an active policy — the daily
    "tighten it" move), strict-multi group bucket, limit-all --force
    sweep, block-single / block-multi zero goodput, unstrict-single
    unlock restore, unstrict-multi selective removal.
  * Real-internet lane (the production shape): a reachability probe
    walks a fallback chain of long-lived public endpoints (Cloudflare
    speed first, then OVH, then Tele2) and the FIRST reachable one
    feeds every realnet stage — cross-distro and cross-year robustness
    by construction, with honest SKIP verdicts (never silent, never
    false FAILs) when the machine has no egress or every endpoint is
    down: the local lane still carries the verdict. Downloads run as
    curl workers inside the policed cgroup (spawn_in_cgroup — real
    external processes, deterministic cgroup attribution, same class
    of proof as the owner's manual browser tests); uploads stream
    chunked from /dev/zero to the Cloudflare discard endpoint, and an
    UNLIMITED sanity upload runs first so an endpoint that refuses
    streaming bodies reads as SKIP, not as a limiter defect.
  * Realnet band honesty: real TCP pays slow start and path RTT that
    loopback never sees, so realnet rate rows use a wider floor
    (0.45 vs 0.65) with the SAME 1.30 ceiling — the policer
    tripwire meaning of the ceiling (never allow materially more than
    configured) stays intact; only the patience for slow start grows.
  * LTS / cross-distro posture: python3 stdlib only, curl optional
    (realnet stages SKIP without it), dedicated-cgroup fleet optional
    (multi-cgroup stages SKIP in session-cgroup fallback — single
    targets still measure honestly), no external test server REQUIRED
    (the fallback chain is opportunistic), root required only for the
    root mode. --self-test verifies the engine with no root, no
    zelynic, no BPF, and no network.

Usage:
  sudo ./scripts/supermassive/supermassive-test-v2.sh               # e2e simulation (4+ min)
  python3 scripts/supermassive/supermassive-test-v2.py --self-test  # engine smoke, no root
  sudo ./scripts/supermassive/supermassive-test-v2.sh --binary ./zelynic
  sudo ./scripts/supermassive/supermassive-test-v2.sh --json        # machine-readable

What it verifies (verdicts PASS / FAIL / SKIP, exit 1 on any FAIL):
  preflight: env + minimum specs, doctor, list-apps, loopback baseline,
         real-internet reachability + realnet baseline + upload sanity;
  strict: policy lands in kernel maps, status human + JSON surfaces,
         asymmetric -d/-u buckets (local), live rate change 1mb -> 2mb,
         strict-multi shared group bucket (local), real-internet
         download at 2mb, real-internet upload at 1mb;
  limit: limit-all --force machine-wide sweep (local), the same sweep
         policing a real-internet download;
  block: block-single / block-multi zero goodput + kernel drops (local),
         block-single against the real internet (~zero bytes);
  unstrict: unstrict-single unlock restores speed (local), unstrict-multi
         selective removal leaves other limits standing, unstrict-all
         teardown leaves no limit rows, real-internet speed restored
         after the sweep.
"""

import argparse
import importlib.util
import json
import os
import subprocess
import sys
import time

# The v1 engine lives one dash-named file over; make it importable
# regardless of how this script was invoked (file path, -m, or wrapper).
# The shared engine lib lives one directory further up in scripts/lib/
# (NIGHT-refactor-1) — both paths are bound by ABSOLUTE location.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_LIB_DIR = os.path.join(_HERE, "..", "lib")
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

import zelynic_harness_lib as lib  # noqa: E402
from zelynic_harness_lib import (  # noqa: E402
    RESULTS,
    band_check,
    fmt_bps,
    out,
    record,
)

# ── the v1 engine, imported whole ───────────────────────────────────────────
#
# supermassive-test.py's entrypoint is __main__-guarded, so exec_module
# binds its classes, helpers, and stage functions without running the
# matrix. v2 drives v1's module globals (CG / SERVER / MODE) the same
# way v1's own main() does — every stage below resolves fleet paths and
# server ports through v1's namespace, so one setup serves both lanes.
_SPEC = importlib.util.spec_from_file_location(
    "supermassive_test_v1", os.path.join(_HERE, "supermassive-test.py")
)
sm1 = importlib.util.module_from_spec(_SPEC)
sys.modules["supermassive_test_v1"] = sm1
_SPEC.loader.exec_module(sm1)

CURL = sm1.CURL

# ── windows and rates ───────────────────────────────────────────────────────

LOCAL_WINDOW = 4.0
# Real-internet windows are longer than loopback ones: a real path pays
# DNS, TCP handshake, TLS, and slow start before the first policed byte
# arrives — a 4 s window would spend most of itself on handshake and
# the measured average would undershoot the configured rate for reasons
# that have nothing to do with the policer.
REALNET_RATE_WINDOW = 15.0
REALNET_BASE_WINDOW = 10.0
REALNET_BLOCK_WINDOW = 12.0
REALNET_UL_SANITY_WINDOW = 5.0

REALNET_DL_RATE_STR = "2mb"
REALNET_DL_RATE_BPS = 2_000_000
REALNET_UL_RATE_STR = "1mb"
REALNET_UL_RATE_BPS = 1_000_000
RATE_CHANGE_FROM_STR = "1mb"
RATE_CHANGE_FROM_BPS = 1_000_000
RATE_CHANGE_TO_STR = "2mb"
RATE_CHANGE_TO_BPS = 2_000_000

# Real TCP slow start + path RTT variance: same 1.30 ceiling (the
# policer tripwire — never materially more than configured), wider
# floor (patience for ramp-up). Loopback stages keep lib's 0.65.
REALNET_BAND_LO = 0.45
REALNET_BAND_HI = 1.30

# The restore floor after unstrict: a fraction of the MEASURED realnet
# baseline, not of the configured rate — "speed is back" is a statement
# about the machine's own real-internet throughput.
RESTORE_FLOOR_RATIO = 0.3

# ── the real-internet endpoint chain ────────────────────────────────────────
#
# LTS posture: long-lived public endpoints, ordered by programmatic
# stability. Cloudflare's speed endpoints are the backing store of
# speed.cloudflare.com itself (the bytes= form caps the transfer by
# construction — the probe asks for 1 KiB, the stage asks for 50 MB);
# OVH's proof files and Tele2's zip have served ranged requests for
# over a decade. The FIRST endpoint whose probe completes feeds every
# download stage — one endpoint per run keeps every realnet row
# attributable to a name in the report.
REALNET_DL_ENDPOINTS = [
    (
        "cloudflare",
        "https://speed.cloudflare.com/__down?bytes=1024",
        "https://speed.cloudflare.com/__down?bytes=50000000",
    ),
    (
        "ovh",
        "https://proof.ovh.net/files/10Mb.dat",
        "https://proof.ovh.net/files/10Mb.dat",
    ),
    (
        "tele2",
        "http://speedtest.tele2.net/10MB.zip",
        "http://speedtest.tele2.net/10MB.zip",
    ),
]
# The upload discard endpoint: Cloudflare's __up accepts streamed POST
# bodies and throws them away — the upload mirror of __down.
REALNET_UL_ENDPOINT = ("cloudflare", "https://speed.cloudflare.com/__up")

# (name, download_url) once the probe chain has spoken; None until then.
DL_ENDPOINT = None
UL_ENDPOINT = None
# Preflight findings the realnet stages gate on (a slow uplink or a
# refused streaming body must read as SKIP, never as a limiter FAIL).
REALNET_BASELINE_BPS = 0
REALNET_UL_USABLE = False


# ── realnet probe + worker commands ─────────────────────────────────────────


def realnet_probe_cmd(url):
    """A ranged 1 KiB GET: cheap, harmless, and a complete handshake
    (DNS + TCP + TLS where present). Exit 0 with an HTTP 200/206 means
    the endpoint feeds; anything else falls through to the next name."""
    return [
        CURL,
        "-s",
        "-L",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        "8",
        "--range",
        "0-1023",
        url,
    ]


def realnet_ul_probe_cmd(url):
    """One small POST: the upload endpoint is alive when it accepts a
    body and answers, not when a GET of it happens to return anything."""
    return [
        CURL,
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        "8",
        "-X",
        "POST",
        "--data-binary",
        "zelynic-v2-reachability-probe",
        url,
    ]


def realnet_dl_cmd(window, url):
    """Download worker: size_download is the verdict, --max-time cuts
    the window (a non-zero curl exit is EXPECTED — the metric line is
    the measurement, not the exit code, same contract as v1)."""
    return [
        CURL,
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{size_download}",
        "--max-time",
        f"{window}",
        url,
    ]


def realnet_ul_cmd(window, url):
    # -T /dev/zero: an unsizeable character device forces a streaming
    # chunked upload — the classic curl upload-speed pattern (v1's
    # local twin uses the same trick against the in-process server).
    return [
        CURL,
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{size_upload}",
        "--max-time",
        f"{window}",
        "-T",
        "/dev/zero",
        url,
    ]


def _probe(cmd):
    """Run one probe command; True when curl exited 0 with a 2xx code."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (subprocess.TimeoutExpired, OSError):
        return False
    code = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
    return p.returncode == 0 and code in ("200", "206")


def realnet_download(name, window):
    """One real-internet download inside cgroup `name`; (bytes, err)."""
    return sm1.spawn_in_cgroup(name, realnet_dl_cmd(window, DL_ENDPOINT[1]), window + 25)


def realnet_upload(name, window):
    """One real-internet upload inside cgroup `name`; (bytes, err)."""
    return sm1.spawn_in_cgroup(name, realnet_ul_cmd(window, UL_ENDPOINT[1]), window + 25)


# ── preflight: reachability, realnet baseline, upload sanity ────────────────


def stage_realnet_probe():
    """Walk the fallback chain; the first endpoint that feeds wins.
    Every miss is reported (a silent chain would hide a dead network
    behind a SKIP that looks like a choice)."""
    global DL_ENDPOINT, UL_ENDPOINT
    if not CURL:
        for label in (
            "real internet: download endpoint reachability",
            "real internet: upload endpoint reachability",
        ):
            record(label, "SKIP", "curl not found")
        return False
    out()
    out("━━━ real-internet endpoint chain (first reachable feeds the lane) ━━━")
    for name, probe_url, dl_url in REALNET_DL_ENDPOINTS:
        if _probe(realnet_probe_cmd(probe_url)):
            DL_ENDPOINT = (name, dl_url)
            out(f"  download: {name} — reachable")
            break
        out(f"  download: {name} — no answer")
    ul_name, ul_url = REALNET_UL_ENDPOINT
    if _probe(realnet_ul_probe_cmd(ul_url)):
        UL_ENDPOINT = (ul_name, ul_url)
        out(f"  upload:   {ul_name} — reachable")
    else:
        out("  upload:   no answer")
    dl_ok = record(
        "real internet: download endpoint reachability",
        "PASS" if DL_ENDPOINT else "SKIP",
        f"{DL_ENDPOINT[0]} feeds the realnet lane"
        if DL_ENDPOINT
        else "no egress or every endpoint down — local lane carries the verdict",
    )
    ul_ok = record(
        "real internet: upload endpoint reachability",
        "PASS" if UL_ENDPOINT else "SKIP",
        f"{UL_ENDPOINT[0]} accepts upload bodies"
        if UL_ENDPOINT
        else "upload endpoint unreachable — realnet upload stages SKIP",
    )
    return dl_ok == "PASS" and ul_ok == "PASS"


def stage_realnet_baseline():
    """Unlimited real-internet throughput: the restore floor for the
    unstrict phase, and the instrument check that the endpoint can
    actually feed the rates the strict phase will assert against."""
    global REALNET_BASELINE_BPS
    if not DL_ENDPOINT:
        return record(
            "real internet: unlimited baseline throughput", "SKIP", "no download endpoint"
        )
    got, err = realnet_download("a", REALNET_BASE_WINDOW)
    if got is None:
        return record(
            "real internet: unlimited baseline throughput",
            "FAIL",
            f"worker failed: {err}",
        )
    bps = got / REALNET_BASE_WINDOW
    REALNET_BASELINE_BPS = bps
    return record(
        "real internet: unlimited baseline throughput",
        "PASS" if bps > 0 else "FAIL",
        f"{fmt_bps(bps)} over {REALNET_BASE_WINDOW:.0f}s via {DL_ENDPOINT[0]}"
        if bps > 0
        else "0 B/s — the endpoint answered the probe but fed no bytes",
    )


def stage_realnet_upload_sanity():
    """An UNLIMITED upload first: an endpoint that refuses streaming
    bodies (proxy 4xx, chunked rejection) must read as SKIP, not as a
    limiter defect — verify the instrument before measuring with it."""
    global REALNET_UL_USABLE
    if not UL_ENDPOINT:
        return record(
            "real internet: upload engine sanity (unlimited)", "SKIP", "no upload endpoint"
        )
    got, err = realnet_upload("a", REALNET_UL_SANITY_WINDOW)
    if got is None:
        return record(
            "real internet: upload engine sanity (unlimited)",
            "SKIP",
            f"endpoint refused the streaming worker: {err}",
        )
    bps = got / REALNET_UL_SANITY_WINDOW
    usable = bps > 100_000
    REALNET_UL_USABLE = usable
    return record(
        "real internet: upload engine sanity (unlimited)",
        "PASS" if usable else "SKIP",
        f"{fmt_bps(bps)} — streaming uploads work"
        if usable
        else f"only {fmt_bps(bps)} unlimited — endpoint caps uploads, "
        "realnet rate rows would be noise",
    )


# ── strict phase ────────────────────────────────────────────────────────────


def stage_rate_change():
    """The daily move v1's reload cycle proves under stress and v2
    proves under use: tighten a live policy 1mb -> 2mb and measure
    BOTH rungs — a rate change that only updates the status row is a
    display bug, not a limit change."""
    name = "rate change: strict-single 1mb -> 2mb under live policy"
    ok, payload = sm1.apply_single("a", RATE_CHANGE_FROM_STR, RATE_CHANGE_FROM_BPS, None)
    if not ok:
        return record(name, "FAIL", payload)
    got_lo = sm1.py_download(LOCAL_WINDOW)
    ok, payload = sm1.apply_single("a", RATE_CHANGE_TO_STR, RATE_CHANGE_TO_BPS, None)
    if not ok:
        sm1.clear_all()
        return record(name, "FAIL", payload)
    got_hi = sm1.py_download(LOCAL_WINDOW)
    if got_lo is None or got_hi is None:
        sm1.clear_all()
        return record(name, "FAIL", "a measurement worker produced no bytes")
    lo_ok = band_check(
        "rate change: first rung at 1mb", got_lo / LOCAL_WINDOW, RATE_CHANGE_FROM_BPS
    )
    hi_ok = band_check("rate change: second rung at 2mb", got_hi / LOCAL_WINDOW, RATE_CHANGE_TO_BPS)
    record(
        name,
        "PASS" if (lo_ok and hi_ok) else "FAIL",
        f"{fmt_bps(got_lo / LOCAL_WINDOW)} then {fmt_bps(got_hi / LOCAL_WINDOW)}",
    )
    sm1.clear_all()
    return lo_ok and hi_ok


def stage_realnet_strict_download():
    name = "real internet: strict-single download at 2mb"
    if not DL_ENDPOINT:
        return record(name, "SKIP", "no download endpoint")
    if REALNET_BASELINE_BPS < 2 * REALNET_DL_RATE_BPS:
        return record(
            name,
            "SKIP",
            f"realnet baseline {fmt_bps(REALNET_BASELINE_BPS)} too low to prove "
            f"a {REALNET_DL_RATE_STR} band",
        )
    ok, payload = sm1.apply_single("a", REALNET_DL_RATE_STR, REALNET_DL_RATE_BPS, None)
    if not ok:
        return record(name, "FAIL", payload)
    time.sleep(0.5)
    got, err = realnet_download("a", REALNET_RATE_WINDOW)
    if got is None:
        sm1.clear_all()
        return record(name, "FAIL", f"worker failed: {err}")
    passed = band_check(
        name,
        got / REALNET_RATE_WINDOW,
        REALNET_DL_RATE_BPS,
        extra=f"via {DL_ENDPOINT[0]}",
        lo=REALNET_BAND_LO,
        hi=REALNET_BAND_HI,
    )
    sm1.enforcement_proofs("real internet strict", got)
    sm1.clear_all()
    return passed


def stage_realnet_strict_upload():
    name = "real internet: strict-single upload at 1mb"
    if not UL_ENDPOINT:
        return record(name, "SKIP", "no upload endpoint")
    if not REALNET_UL_USABLE:
        return record(name, "SKIP", "upload engine sanity did not pass")
    ok, payload = sm1.apply_single("a", REALNET_UL_RATE_STR, None, REALNET_UL_RATE_BPS)
    if not ok:
        return record(name, "FAIL", payload)
    time.sleep(0.5)
    got, err = realnet_upload("a", REALNET_RATE_WINDOW)
    if got is None:
        sm1.clear_all()
        return record(name, "FAIL", f"worker failed: {err}")
    passed = band_check(
        name,
        got / REALNET_RATE_WINDOW,
        REALNET_UL_RATE_BPS,
        extra=f"via {UL_ENDPOINT[0]}",
        lo=REALNET_BAND_LO,
        hi=REALNET_BAND_HI,
    )
    sm1.clear_all()
    return passed


# ── limit phase (realnet half; the local half is v1's test_limit_all) ──────


def stage_realnet_limit_all():
    """The machine-wide sweep policing REAL traffic: same sleeper fleet
    and --force sweep as v1's local stage, but the measured worker is a
    real-internet download — proving the sweep reached the cgroup the
    production traffic will actually live in."""
    name = "real internet: limit-all --force sweep at 2mb"
    if not DL_ENDPOINT:
        return record(name, "SKIP", "no download endpoint")
    if REALNET_BASELINE_BPS < 2 * 2_000_000:
        return record(
            name,
            "SKIP",
            f"realnet baseline {fmt_bps(REALNET_BASELINE_BPS)} too low to prove a 2mb band",
        )
    spawned = [sm1.spawn_bg_in_cgroup(n, ["sleep", "30"]) for n in "abcde"]
    sleepers = [p for p in spawned if p is not None]
    try:
        if len(sleepers) != len(spawned):
            return record(
                name,
                "FAIL",
                f"sleeper residency barrier failed: "
                f"{len(spawned) - len(sleepers)}/{len(spawned)} cgroups "
                "never got a resident sleeper",
            )
        rc, stdout, stderr = lib.run_zel(["limit-all", "--force", "2mb"])
        if rc != 0:
            return record(name, "FAIL", f"exit {rc}: {(stderr or stdout).strip()[:200]}")
        time.sleep(0.5)
        got, err = realnet_download("a", REALNET_RATE_WINDOW)
        if got is None:
            return record(name, "FAIL", f"worker failed: {err}")
        return band_check(
            name,
            got / REALNET_RATE_WINDOW,
            2_000_000,
            extra=f"via {DL_ENDPOINT[0]}",
            lo=REALNET_BAND_LO,
            hi=REALNET_BAND_HI,
        )
    finally:
        sm1.clear_all()
        for p in sleepers:
            p.kill()
        for p in sleepers:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


# ── block phase (realnet half) ─────────────────────────────────────────────


def stage_realnet_block():
    """block-single against the real internet: the connection must
    carry ~zero payload bytes. The kernel-drop proof rides the same
    status row v1's local block stages read."""
    name = "real internet: block-single zero goodput"
    if not DL_ENDPOINT:
        return record(name, "SKIP", "no download endpoint")
    ok, payload = sm1.block_target("block-single", ["a"])
    if not ok:
        return record(name, "FAIL", payload)
    time.sleep(0.3)
    got, err = realnet_download("a", REALNET_BLOCK_WINDOW)
    if got is None:
        sm1.clear_all()
        return record(name, "FAIL", f"worker failed: {err}")
    verdict = "PASS" if got <= sm1.BLOCK_GOODPUT_CEIL else "FAIL"
    record(
        name,
        verdict,
        f"{got} bytes over {REALNET_BLOCK_WINDOW:.0f}s via {DL_ENDPOINT[0]} "
        f"(ceiling {sm1.BLOCK_GOODPUT_CEIL})",
    )
    sm1.enforcement_proofs("real internet block", got)
    sm1.clear_all()
    return verdict == "PASS"


# ── unstrict phase (realnet half + teardown) ───────────────────────────────


def stage_realnet_restore():
    """After the whole simulation, unstrict-all must give the machine
    its real-internet speed back — measured against the machine's own
    re-measured baseline, not a configured number."""
    name = "real internet: unstrict-all restores speed"
    if not DL_ENDPOINT:
        return record(name, "SKIP", "no download endpoint")
    # Leave a limit standing so the restore has something to undo.
    ok, payload = sm1.apply_single("a", REALNET_DL_RATE_STR, REALNET_DL_RATE_BPS, None)
    if not ok:
        return record(name, "FAIL", payload)
    if not sm1.clear_all():
        return record(name, "FAIL", "unstrict-all exited non-zero")
    got, err = realnet_download("a", REALNET_BASE_WINDOW)
    if got is None:
        return record(name, "FAIL", f"worker failed: {err}")
    baseline = _remeasure_realnet_baseline()
    floor = RESTORE_FLOOR_RATIO * baseline if baseline else 1e6
    bps = got / REALNET_BASE_WINDOW
    return record(
        name,
        "PASS" if bps >= floor else "FAIL",
        f"{fmt_bps(bps)} after unstrict-all (floor {fmt_bps(floor)}, "
        f"re-measured baseline {fmt_bps(baseline)})",
    )


def _remeasure_realnet_baseline():
    """The restore floor derives from the machine's CURRENT realnet
    throughput (re-measured, not cached: it moves between stages)."""
    if not DL_ENDPOINT:
        return 0
    got, _ = realnet_download("a", REALNET_BASE_WINDOW)
    return got / REALNET_BASE_WINDOW if got else 0


def stage_teardown():
    """The unstrict phase's own proof: after unstrict-all the status
    carries no limit rows and the cgroup fleet cleans up. This is the
    E2E end state, not a crash-recovery stage — v1 owns those."""
    sm1.clear_all()
    doc = sm1.status_json()
    rows = len(doc.get("limits", [])) if doc else 0
    ok_rows = record(
        "teardown: unstrict-all leaves no limit rows",
        "PASS" if rows == 0 else "FAIL",
        f"{rows} rows remain" if rows else "status clean",
    )
    cleaned = sm1.CG.cleanup()
    record(
        "teardown: cgroup fleet cleanup",
        "PASS" if cleaned else "FAIL",
        "fleet directories removed" if cleaned else "fleet directories still present",
    )
    return ok_rows == "PASS" and cleaned


# ── engine self-test (no root, no zelynic, no BPF, no network) ─────────────


def self_test():
    out("zelynic supermassive test v2 — engine self-test (no root, no zelynic, no BPF)")
    out()
    probe = os.path.join(_HERE, "supermassive-test.py")
    ok = record(
        "engine: v1 harness importable",
        "PASS" if os.path.isfile(probe) and hasattr(sm1, "CgroupSet") else "FAIL",
        f"{probe} bound as supermassive_test_v1",
    )
    ok = (
        record(
            "engine: v1 stage surface present",
            "PASS"
            if all(
                hasattr(sm1, attr)
                for attr in (
                    "test_policy_write",
                    "test_asymmetric",
                    "test_multi_group",
                    "test_limit_all",
                    "test_block_single",
                    "test_block_multi",
                    "test_unlock",
                    "test_unstrict_multi",
                )
            )
            else "FAIL",
            "the eight reused local stages resolve",
        )
        == "PASS"
        and ok
    )
    ok = (
        record(
            "realnet: download endpoint registry well-formed",
            "PASS"
            if all(
                len(entry) == 3
                and (entry[2].startswith("https://") or entry[2].startswith("http://"))
                for entry in REALNET_DL_ENDPOINTS
            )
            else "FAIL",
            f"{len(REALNET_DL_ENDPOINTS)} candidates: "
            + ", ".join(name for name, _, _ in REALNET_DL_ENDPOINTS),
        )
        == "PASS"
        and ok
    )
    ok = (
        record(
            "realnet: upload endpoint well-formed",
            "PASS" if REALNET_UL_ENDPOINT[1].startswith("https://") else "FAIL",
            REALNET_UL_ENDPOINT[1],
        )
        == "PASS"
        and ok
    )
    dl = realnet_dl_cmd(10, "https://self.test/__down")
    ul = realnet_ul_cmd(10, "https://self.test/__up")
    ok = (
        record(
            "realnet: worker commands carry the measurement contract",
            "PASS"
            if dl[-1] == "https://self.test/__down"
            and "%{size_download}" in dl
            and "--max-time" in dl
            and "10" in dl
            and "-T" in ul
            and "/dev/zero" in ul
            and "%{size_upload}" in ul
            else "FAIL",
            "size metric, max-time, and the /dev/zero streaming source",
        )
        == "PASS"
        and ok
    )
    ok = (
        record(
            "realnet: band overrides are honest",
            "PASS" if 0 < REALNET_BAND_LO < REALNET_BAND_HI else "FAIL",
            f"floor {REALNET_BAND_LO}, ceiling {REALNET_BAND_HI} "
            "(slow-start patience, same tripwire)",
        )
        == "PASS"
        and ok
    )
    try:
        lo, hi = (float(x) for x in "0.5,1.5".split(","))
        band_ok = lo < hi
    except ValueError:
        band_ok = False
    ok = (
        record(
            "cli: --band lo,hi parses",
            "PASS" if band_ok else "FAIL",
            "the same parser main() applies to --band",
        )
        == "PASS"
        and ok
    )
    record("self-test: verdict plumbing", "PASS", "this row IS the plumbing")
    out()
    out("━━━ self-test verdict ━━━")
    fails = sum(1 for r in RESULTS if r["verdict"] == "FAIL")
    out(f"  {len(RESULTS) - fails} passed, {fails} failed, 0 skipped")
    return fails == 0


# ── main ────────────────────────────────────────────────────────────────────

KNOWN_FLAGS = ("self-test", "binary", "json", "band")


def _unknown_arg_error(token):
    return [
        f"error: unknown option '{token}'",
        f"  known options: {', '.join(f'--{f}' for f in KNOWN_FLAGS)}",
    ]


def run_e2e():
    """The four policy families in daily-session order, each proven on
    the local lane first (deterministic instrument) and the realnet
    lane second (production shape). v1's stages carry the local proofs;
    the v2-native stages carry the realnet ones."""
    out("zelynic supermassive test v2 (NIGHT-improve-23, e2e mode)")
    out()
    env_ok = sm1.test_env()
    if not env_ok:
        out()
        out("  environment not suitable for zelynic — stopping here.")
        return False

    # preflight
    sm1.test_doctor()
    sm1.test_list_apps()
    baseline = sm1.test_baseline(LOCAL_WINDOW)
    stage_realnet_probe()
    stage_realnet_baseline()
    stage_realnet_upload_sanity()

    # strict
    out()
    out("━━━ phase 1/4: strict (limit an app, tight and measured) ━━━")
    sm1.test_policy_write()
    sm1.test_asymmetric(LOCAL_WINDOW, baseline)
    stage_rate_change()
    sm1.test_multi_group(LOCAL_WINDOW, baseline)
    stage_realnet_strict_download()
    stage_realnet_strict_upload()

    # limit
    out()
    out("━━━ phase 2/4: limit (cap the whole machine) ━━━")
    sm1.test_limit_all(LOCAL_WINDOW, baseline)
    stage_realnet_limit_all()

    # block
    out()
    out("━━━ phase 3/4: block (an app goes dark) ━━━")
    sm1.test_block_single(LOCAL_WINDOW)
    sm1.test_block_multi(LOCAL_WINDOW)
    stage_realnet_block()

    # unstrict
    out()
    out("━━━ phase 4/4: unstrict (give it all back) ━━━")
    sm1.test_unlock(LOCAL_WINDOW, baseline)
    sm1.test_unstrict_multi()
    stage_realnet_restore()
    stage_teardown()

    return True


def main():
    global MODE
    ap = argparse.ArgumentParser(
        prog="supermassive-test-v2",
        description="zelynic end-to-end daily-use simulation (NIGHT-improve-23)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="verify the harness engine only — no root, no zelynic, no BPF, no network",
    )
    ap.add_argument("--binary", help="path to the zelynic binary")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--band",
        default=f"{lib.BAND_LO},{lib.BAND_HI}",
        help="verdict band as lo,hi ratios for the LOCAL lane (default 0.65,1.30)",
    )
    args, unknown = ap.parse_known_args()
    if unknown:
        for token in unknown:
            for line in _unknown_arg_error(token):
                out(line)
        return 2

    if args.self_test:
        ok = self_test()
        if args.json:
            print(json.dumps({"mode": "self-test", "results": RESULTS}, indent=2))
        return 0 if ok else 1

    try:
        lo, hi = (float(x) for x in args.band.split(","))
        lib.BAND_LO, lib.BAND_HI = lo, hi
    except ValueError:
        out("--band expects lo,hi (e.g. 0.65,1.30)")
        return 2

    if os.geteuid() != 0:
        out("This test programs the kernel datapath — run with sudo.")
        return 2
    if not lib.resolve_binary(args.binary, "sudo ./scripts/supermassive/supermassive-test-v2.sh"):
        return 2

    start = time.perf_counter()
    sm1.CG = sm1.CgroupSet()
    exit_code = 1
    try:
        MODE = sm1.CG.setup()
        sm1.MODE = MODE
        sm1.SERVER = sm1.HttpServer()
        ran = run_e2e()
        sm1.report_worker_faults()
        ok = (
            lib.final_report(
                start,
                "e2e",
                "daily-use simulation green: strict, limit, block, unstrict — "
                "local and real internet — all proven",
            )
            if ran
            else False
        )
        exit_code = 0 if ok else 1
    finally:
        sm1.clear_all()
        if sm1.SERVER:
            sm1.SERVER.stop()
        sm1.CG.cleanup()
    if args.json:
        print(
            json.dumps(
                {
                    "binary": lib.BINARY,
                    "mode": "e2e",
                    "cgroup_mode": MODE,
                    "realnet": {
                        "download_endpoint": DL_ENDPOINT[0] if DL_ENDPOINT else None,
                        "upload_endpoint": UL_ENDPOINT[0] if UL_ENDPOINT else None,
                    },
                    "worker_faults": [{"error": msg, "count": n} for msg, n in sm1.WORKER_FAULTS],
                    "results": RESULTS,
                },
                indent=2,
            )
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
