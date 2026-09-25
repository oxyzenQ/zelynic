#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: one self-contained claims harness by design — the four
# NIGHT-boost-12 false-negative fixes live with their evidence (the
# owner-run numbers that motivated them, the mechanism comments, and
# the rootless self-test pins that carry the contract in CI);
# splitting the proof across modules would scatter the told-once
# claim narrative the harness exists to carry (the engine helpers it
# truly shares with the depth/supermassive twins already live in
# zelynic_harness_lib.py, NIGHT-improve-11; over the 1000 scripts cap under NIGHT-lts-2 — tracked debt, the split is its own NIGHT task)
"""zelynic claims proof harness (NIGHT-boost-8) — honesty, enforced.

The README makes four headline claims. This harness proves every one
of them LIVE on the machine it runs on — same loopback engine, same
cgroup discipline, and the same verdict discipline as the depth and
supermassive twins (stdlib-only python3, no external test server,
root required for the live run, --self-test for CI without root):

  claim 1 — no daemon. zelynic is a one-shot CLI: attach and exit.
    Proven by snapshotting every zelynic-named process BEFORE the
    first invocation, attaching a limit, then scanning /proc again:
    the set must not have grown (a pre-existing interactive zelynic —
    an eagle-eyes in another terminal — is the operator's, not a
    daemon of this attach; a spawn would appear as a NEW pid),
    asserting no pid file exists, and then measuring a download that
    is STILL policed. Enforcement alive with no new zelynic process
    IS the claim: the pinned bpf_links carry it in the kernel.

  claim 2 — pure eBPF. No tc qdisc, no nftables rule, no LD_PRELOAD
    wrapper — the kernel datapath does the shaping. Proven by
    snapshotting `tc qdisc show` and `nft list ruleset` before the
    attach and comparing STRUCTURE during enforcement — kernel-
    maintained runtime state (rule byte/packet counters, set element
    expiries) is normalized away first, because any traffic through
    a rule that predates the proof advances its counters without
    zelynic touching netfilter at all (the owner's live Arch run
    tripped exactly that). A tool that is not even installed also
    cannot be shaping anything — that is a SKIP with the reason
    spelled out. LD_PRELOAD asserted unset, the kernel's own verdict
    shown (packets_dropped > 0 in the BPF counters), and the
    cgroup_skb truth visible on bpftool's attach-mechanism-
    independent surfaces (prog show; link show names the pinned
    schema-v6 links; cgroup show lists only legacy attaches).

  claim 3 — per-app per-cgroup. Proven with a pair: cgroup A
    (this harness, policed) and cgroup B (a witness subprocess with
    its own server+client, unlimited) measured SIMULTANEOUSLY on
    the same machine — A lands on its configured rate while B
    rides far above it: at least 50x A's rate (a scope bug would
    clamp B to the rate itself) and within an order of magnitude
    of the machine's own baseline (single-stream loopback varies;
    an order of magnitude does not). One shaped, one free, same
    moment.

  claim 4 — precision 0.00%. Told honestly at two levels:
    * The 0.00% contract is the token math: long-run admitted bytes
      equal rate x elapsed EXACTLY, sub-byte fractional carry (the
      frac_rem machinery, pinned rootlessly in
      test/ebpf/limiter/math_tests.rs — steady-state exactness).
    * The LIVE row measures what a process boundary can measure:
      kernel-admitted bytes (the BPF counter deltas) against
      configured rate x wall time over a long saturating window,
      cross-checked against the client's own byte counter. The
      residual is the status-read spawn latency, not limiter math,
      and the row prints the actual number — nothing is rounded
      into honesty.

  claim 5 — resource honesty (NIGHT-lts-6: the owner's "verify ram,
    cpu, io, etc usage — this project is critical infra not a
    toy" ask). The one-shot CLI's OWN footprint is measured with
    the kernel's own accounting: wait4(2) rusage of a canonical
    strict-single attach — peak RSS (ru_maxrss), CPU seconds
    (ru_utime + ru_stime), block IO (ru_inblock + ru_oublock)
    against generous bounds, the real numbers printed. The
    kernel-side cost is measured where it lives: bpftool's
    run_time_ns / run_cnt on the attached programs (average
    nanoseconds per run after a saturating window) — the "no
    daemon, no battery drain" claim's quantitative half. Rootless
    pins: the verdict math (self-test) and the claims ledger
    (docs/CLAIMS_VERIFICATION.md).

Usage:
  sudo ./scripts/bench/proof-claims.sh               # full claims audit (~1 min)
  sudo ./scripts/bench/proof-claims.sh --quick        # faster windows (~30s)
  ./scripts/bench/proof-claims.sh --self-test         # engine smoke, no root
  sudo ./scripts/bench/proof-claims.sh --json         # machine-readable
  sudo ./scripts/bench/proof-claims.sh --binary ./target/pro-native-gnu/zelynic

Exit code: 0 = every verdict PASS or SKIP, 1 = any FAIL, 2 = usage
or environment not suitable.
"""

import argparse
import difflib
import inspect
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time

# The shared engine lib lives in scripts/lib/ (NIGHT-refactor-1) — bound
# by ABSOLUTE path so the harness works from any CWD.
_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

import zelynic_harness_lib as lib  # noqa: E402 - needs the lib/ path bootstrap above

CGROUP_A = os.path.join(lib.CGROUP_ROOT, "zelynic-proof-a")
CGROUP_B = os.path.join(lib.CGROUP_ROOT, "zelynic-proof-b")
PID_FILE = "/tmp/zelynic.pid"

# Windows (seconds). Full mode totals ~1 minute of measurements.
BASELINE_WINDOW = 3.0
NO_DAEMON_WINDOW = 8.0
PURE_WINDOW = 5.0
PER_APP_WINDOW = 10.0
PRECISION_WINDOW = 30.0
PRECISION_SETTLE = 3.0  # saturating seconds before the first counter read

NO_DAEMON_RATE = 5_000_000  # 5mb: above the loopback GSO floor, quick to prove
PURE_RATE = 5_000_000
PER_APP_RATE = 2_000_000  # 2mb: the witness contrasts hardest against this
# The precision rate adapts down when the baseline cannot saturate 100mb.
PRECISION_RATE = 100_000_000
PRECISION_RATE_FALLBACK = 20_000_000

# The live accounting row's PASS bound: the residual is dominated by
# the status-read spawn latency (tens of ms) against the window.
ACCOUNTING_ERR_MAX_FULL = 0.01  # 1.0% over a 30s window
ACCOUNTING_ERR_MAX_QUICK = 0.02  # 2.0% over a 10s window

# NIGHT-lts-6 claim 5 bounds: the one-shot CLI's own footprint. The
# bounds are deliberately generous — the rows PRINT the real numbers
# (nothing rounded into honesty); a bound exists only to fail a
# REGRESSION loudly (a leak, a pathological load path).
FOOTPRINT_RSS_MAX_MIB = 64.0  # static musl binary + embedded eBPF objects
FOOTPRINT_CPU_MAX_S = 5.0  # the attach window: load + pin + policy write
FOOTPRINT_BLOCK_IO_MAX = 256  # ru_inblock+oublock: no data-plane IO belongs here
FOOTPRINT_KRUN_MAX_NS = 20_000  # avg ns per attached-prog run (bpftool)

SERVER = None
CG = None
# zelynic-named processes alive when the proof started (the no-daemon
# DELTA baseline, NIGHT-boost-12 hunt): the owner's live run flagged
# a pre-existing interactive zelynic as a "resident daemon" — an
# absolute count cannot tell the operator's eagle-eyes in another
# terminal from a spawn of THIS attach. Only growth of the set is a
# daemon; the delta sees exactly that.
PROCS_AT_START = []
WORKER_SENTRY = "-"  # witness-worker cgroup path meaning "skip the move"

# The claim registry: every README headline claim maps to the stage
# that proves it. The self-test asserts the registry is complete —
# a claim without a stage is an unproven promise.
CLAIM_STAGES = (
    ("no-daemon", "attach, exit, stay enforced"),
    ("pure-eBPF", "no tc, no nft, no LD_PRELOAD, kernel drops"),
    ("per-app", "one cgroup shaped, its neighbor free"),
    ("precision", "kernel-admitted bytes vs configured rate"),
    ("footprint", "the CLI's own RAM/CPU/IO + kernel run time"),
)


def bps_to_rate_str(bps):
    """Inverse of zelynic's rate parser (decimal SI: kb=1000, mb=1e6)."""
    if bps >= 1e9:
        return f"{round(bps / 1e9)}gb"
    if bps >= 1e6:
        return f"{round(bps / 1e6)}mb"
    return f"{round(bps / 1e3)}kb"


def accounting_error(admitted, expected):
    """|admitted - expected| / expected, as a fraction (0.0 on equal)."""
    if expected <= 0:
        return 1.0
    return abs(admitted - expected) / expected


# Kernel-maintained runtime state inside `nft list ruleset` output:
# rule byte/packet counters advance with any matching traffic, and
# set elements carry expiry timestamps that tick on their own. Both
# are state, not structure — zelynic installing a netfilter PATH
# would add or change tables/chains/rules, which these patterns
# preserve verbatim.
NFT_VOLATILE = (
    (re.compile(r"counter packets \d+ bytes \d+"), "counter"),
    (re.compile(r"expires \d+[smhd]?"), "expires"),
)


def nft_normalize(text):
    """Strip volatile kernel state from an `nft list ruleset` snapshot.

    NIGHT-boost-12 hunt: the owner's live Arch run flagged "ruleset
    changed" while zelynic provably touched no netfilter path —
    traffic through rules that predate the proof had advanced their
    counter bytes between the two snapshots. The comparison must be
    structure vs structure; a raw string compare sees the host's own
    traffic as a zelynic change.
    """
    for pattern, repl in NFT_VOLATILE:
        text = pattern.sub(repl, text)
    return text


def footprint_verdict(maxrss_kib, cpu_s, block_io):
    """(ok, detail) for the one-shot CLI's own footprint (claim 5).

    Pure over its inputs so the self-test pins the bounds' shape:
    each dimension fails alone, and the detail prints the real
    numbers — the verdict's job is to fail a regression loudly, not
    to round anything into honesty.
    """
    rss_mib = maxrss_kib / 1024.0
    ok = (
        rss_mib <= FOOTPRINT_RSS_MAX_MIB
        and cpu_s <= FOOTPRINT_CPU_MAX_S
        and block_io <= FOOTPRINT_BLOCK_IO_MAX
    )
    detail = (
        f"peak RSS {rss_mib:.1f} MiB (bound {FOOTPRINT_RSS_MAX_MIB:.0f}), "
        f"CPU {cpu_s:.2f}s (bound {FOOTPRINT_CPU_MAX_S:.0f}), "
        f"block IO {block_io} (bound {FOOTPRINT_BLOCK_IO_MAX})"
    )
    return ok, detail


def witness_floor(baseline, rate_bps):
    """The minimum bps the unlimited witness must show.

    NIGHT-boost-12 hunt: the old floor (half the baseline) demanded
    the witness single-stream match half the baseline single-stream
    — loopback variance alone misses that by 3x (the owner's live
    run: B measured 4.2 GB/s against a 13.2 GB/s baseline while
    riding 2000x above A's rate, and the row still failed). The
    isolation claim needs two things: B far above A's configured
    rate (a scope bug clamps B to the rate itself) and B not an
    order of magnitude below the machine's own unlimited speed.
    """
    floor = 50 * rate_bps
    if baseline:
        floor = max(floor, 0.1 * baseline)
    return floor


# ── loopback traffic engine (the depth harness contract, compact) ─────────


class TrafficServer:
    """Threaded raw-socket GET server on 127.0.0.1: streams CHUNKs
    until the peer closes. Same protocol as limiter-depth-test.py."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn):
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            try:
                conn.recv(8)  # the "GET\n" line
            except OSError:
                return
            blob = b"\x00" * lib.CHUNK
            try:
                while True:
                    conn.sendall(blob)
            except OSError:
                pass  # peer closed the window: normal termination
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def tracked_download(window, port, progress=None):
    """Read from the server for `window` seconds; returns bytes received.

    `progress` is an optional one-element list the recv loop keeps at
    the cumulative byte count — the precision stage reads it between
    counter snapshots so client-side numbers cover the same window
    the kernel counter does. Connect failures are ZERO GOODPUT, not a
    crash (the depth harness contract).
    """
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
    except (socket.timeout, OSError):
        return 0
    with s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(b"GET\n")
        deadline = time.perf_counter() + window
        total = 0
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            s.settimeout(remaining)
            try:
                data = s.recv(lib.CHUNK)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            total += len(data)
            if progress is not None:
                progress[0] = total
    return total


# ── the proof pair: cgroup A (policed) + cgroup B (witness) ───────────────


class PairCgroups:
    """A dedicated under-limit cgroup for this process and an unlimited
    witness cgroup for the worker subprocess. The per-app claim needs
    BOTH; a machine where root cannot mkdir cgroups cannot prove it,
    and this class says so instead of degrading silently."""

    def __init__(self):
        self.a_id = None
        self.b_id = None

    def setup(self):
        for path in (CGROUP_A, CGROUP_B):
            self._absorb_leftover(path)
        try:
            os.mkdir(CGROUP_A)
            os.mkdir(CGROUP_B)
            with open(os.path.join(CGROUP_A, "cgroup.procs"), "w") as f:
                f.write(str(os.getpid()))
            self.a_id = self._read_id(CGROUP_A)
            self.b_id = self._read_id(CGROUP_B)
        except OSError as e:
            raise RuntimeError(f"dedicated cgroup pair not creatable: {e}") from e
        if self.a_id is None or self.b_id is None:
            raise RuntimeError("cgroup ID resolution failed (kernfs inode unreadable)")

    def cleanup(self):
        """Idempotent: move self to the root cgroup, then drop both."""
        self._absorb_leftover(CGROUP_B)
        self._absorb_leftover(CGROUP_A)
        return not os.path.isdir(CGROUP_A) and not os.path.isdir(CGROUP_B)

    @staticmethod
    def _absorb_leftover(path):
        # Move any survivor processes to the root cgroup, then rmdir.
        try:
            procs = os.path.join(path, "cgroup.procs")
            if os.path.exists(procs):
                with open(procs) as f:
                    pids = [p for p in f.read().split() if p]
                for pid in pids:
                    try:
                        with open(os.path.join(lib.CGROUP_ROOT, "cgroup.procs"), "w") as dst:
                            dst.write(pid)
                    except OSError:
                        pass
            for _ in range(3):
                try:
                    os.rmdir(path)
                    return
                except OSError:
                    time.sleep(0.3)
        except OSError:
            pass

    @staticmethod
    def _read_id(path):
        # The kernfs inode IS the cgroup ID (NIGHT-hunt-31), truncated
        # to the BPF map's u32 key — mirrors zelynic's own resolution.
        try:
            return os.stat(path).st_ino & 0xFFFFFFFF
        except OSError:
            return None


def witness_worker(cgroup_path, window):
    """The unlimited witness: move self into cgroup B (unless the path
    is the self-test sentry '-'), then run a server AND a client inside
    it for `window` seconds and print one JSON line with the measured
    bps. Sockets are created AFTER the move so every byte classifies
    under the witness cgroup."""
    if cgroup_path != WORKER_SENTRY:
        with open(os.path.join(cgroup_path, "cgroup.procs"), "w") as f:
            f.write(str(os.getpid()))
    server = TrafficServer()
    got = tracked_download(window, server.port)
    server.stop()
    print(json.dumps({"bps": got / window, "bytes": got, "window": window}))


# ── evidence helpers ───────────────────────────────────────────────────────


def zelynic_processes():
    """Every live process whose comm is the zelynic binary's basename.
    A daemon would live here; a one-shot CLI leaves nothing behind.
    The no-daemon verdict is the DELTA against PROCS_AT_START (see
    the stage-1 call site): processes that predate the proof are the
    operator's, not this attach's residents."""
    want = os.path.basename(lib.BINARY)[:15]
    found = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/comm", encoding="utf-8") as f:
                comm = f.read().strip()
        except OSError:
            continue
        if comm == want:
            found.append(pid)
    return found


def tool_snapshot(argv):
    """Run a diagnostic tool; returns (ran, combined output)."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    return True, (p.stdout or "") + (p.stderr or "")


def apply_and_verify(rate_bps, cgroup_id):
    """Attach strict-single -d to the cgroup and verify the policy row.
    -d only: one policed hook per stream keeps the accounting 1:1
    (the NIGHT-improve-12 discipline the depth harness pinned)."""
    rate_str = bps_to_rate_str(rate_bps)
    rc, stdout, stderr = lib.run_zel(["strict-single", str(cgroup_id), "-d", rate_str])
    if rc != 0:
        return False, f"strict-single exit {rc}: {(stderr or stdout).strip()[:200]}"
    doc = lib.status_json()
    entry = lib.limit_entry(doc, cgroup_id)
    if entry is None:
        return False, "no limit row for the proof cgroup in status JSON"
    if entry.get("download_bps") != rate_bps:
        return False, f"download_bps {entry.get('download_bps')} != {rate_bps}"
    if doc.get("watchdog") not in ("enforcing", "active"):
        return False, f"watchdog state {doc.get('watchdog')!r}"
    return True, entry


def bytes_allowed_now(cgroup_id):
    """The cgroup's current kernel-admitted byte counter, or None."""
    entry = lib.limit_entry(lib.status_json(), cgroup_id)
    if entry is None:
        return None
    return entry.get("bytes_allowed", 0)


# ── stages ────────────────────────────────────────────────────────────────


def stage_env():
    out = lib.out
    out()
    out("━━━ environment ━━━")
    out(f"  distro:   {lib.pretty_name()}")
    out(f"  kernel:   {os.uname().release}  arch: {os.uname().machine}")
    out(f"  cpu:      {lib.cpu_model()}")
    out(f"  python:   {sys.version.split()[0]}")
    out(f"  binary:   {lib.BINARY} ({lib.binary_version()})")
    out(f"  pair:     A={CG.a_id} (policed)  B={CG.b_id} (witness)")
    ok = True
    ok = (
        lib.record(
            "cgroup v2 unified hierarchy",
            "PASS" if lib.cgroup2_mounted() else "FAIL",
            lib.CGROUP_ROOT if lib.cgroup2_mounted() else f"{lib.CGROUP_ROOT} is not cgroup2fs",
        )
        == "PASS"
        and ok
    )
    ok = (
        lib.record(
            "cgroup pair resolved (kernfs inodes)",
            "PASS" if CG.a_id is not None and CG.b_id is not None else "FAIL",
            f"A {CG.a_id}, B {CG.b_id}",
        )
        == "PASS"
        and ok
    )
    bpffs_ok = lib.bpffs_mounted_at("/sys/fs/bpf")
    ok = (
        lib.record(
            "BPF filesystem mounted",
            "PASS" if bpffs_ok else "FAIL",
            "/sys/fs/bpf (fstype bpf)"
            if bpffs_ok
            else "/sys/fs/bpf is not a mounted bpf filesystem — tip: "
            "sudo mount -t bpf bpf /sys/fs/bpf",
        )
        == "PASS"
        and ok
    )
    if os.geteuid() != 0:
        lib.record("root privilege", "FAIL", "re-run with sudo — BPF needs CAP_BPF")
        return False
    lib.record("root privilege", "PASS")
    lib.doctor_check()
    return ok


def stage_no_daemon():
    out = lib.out
    out()
    out("━━━ claim 1: no daemon ━━━")
    ok, payload = apply_and_verify(NO_DAEMON_RATE, CG.a_id)
    if not ok:
        return lib.record("no-daemon: attach limit", "FAIL", payload) == "PASS"
    lib.record(
        "no-daemon: attach limit",
        "PASS",
        f"strict-single {bps_to_rate_str(NO_DAEMON_RATE)} -d on cgroup A",
    )
    # Every zelynic invocation above has returned. A daemon spawned by
    # this attach would appear as a NEW zelynic-named pid against the
    # PROCS_AT_START baseline; processes that predate the proof are the
    # operator's (an interactive eagle-eyes in another terminal is the
    # owner's own live case that tripped the old absolute count).
    time.sleep(0.3)
    procs = zelynic_processes()
    new_residents = [p for p in procs if p not in PROCS_AT_START]
    if not new_residents:
        note = "one-shot CLI: no new zelynic process since the proof started"
        if len(procs) > len(new_residents):
            note += (
                f" ({len(procs) - len(new_residents)} pre-existing zelynic"
                " process(es) on this machine predate the proof —"
                " interactive use, not a daemon)"
            )
    else:
        note = f"new resident processes since attach: {', '.join(new_residents[:5])}"
    ok_all = (
        lib.record(
            "no-daemon: zero zelynic processes after attach",
            "PASS" if not new_residents else "FAIL",
            note,
        )
        == "PASS"
    )
    ok_all = (
        lib.record(
            "no-daemon: no pid file",
            "PASS" if not os.path.exists(PID_FILE) else "FAIL",
            f"{PID_FILE} absent — nothing daemonized",
        )
        == "PASS"
        and ok_all
    )
    pins = sorted(os.listdir(lib.PIN_DIR)) if os.path.isdir(lib.PIN_DIR) else []
    ok_all = (
        lib.record(
            "no-daemon: enforcement pinned in bpffs",
            "PASS" if pins else "FAIL",
            f"{len(pins)} pinned object(s) under {lib.PIN_DIR}"
            + (f": {', '.join(pins[:6])}" if pins else ""),
        )
        == "PASS"
        and ok_all
    )
    got = tracked_download(NO_DAEMON_WINDOW, SERVER.port)
    verdict = lib.band_check(
        "no-daemon: enforcement alive with zero zelynic processes",
        got / NO_DAEMON_WINDOW,
        NO_DAEMON_RATE,
        "traffic still policed after the CLI exited — the kernel holds the law",
    )
    return verdict == "PASS" and ok_all


def stage_pure_ebpf():
    out = lib.out
    out()
    out("━━━ claim 2: pure eBPF ━━━")
    # Snapshots BEFORE the attach (no limit is live at stage entry).
    tc_ran, tc_before = tool_snapshot(["tc", "qdisc", "show"])
    nft_ran, nft_before = tool_snapshot(["nft", "list", "ruleset"])
    ok, payload = apply_and_verify(PURE_RATE, CG.a_id)
    if not ok:
        return lib.record("pure-eBPF: attach limit", "FAIL", payload) == "PASS"
    tracked_download(PURE_WINDOW, SERVER.port)  # put the policer to work
    ok_all = True
    if tc_ran:
        _, tc_during = tool_snapshot(["tc", "qdisc", "show"])
        ok_all = (
            lib.record(
                "pure-eBPF: tc qdiscs unchanged (no traffic-control shaper)",
                "PASS" if tc_before == tc_during else "FAIL",
                "identical output before and during enforcement"
                if tc_before == tc_during
                else "qdisc set changed — something installed a shaper",
            )
            == "PASS"
            and ok_all
        )
    else:
        lib.record(
            "pure-eBPF: tc qdiscs unchanged (no traffic-control shaper)",
            "SKIP",
            "tc not installed — a tool that is not present cannot shape anything",
        )
    if nft_ran:
        _, nft_during = tool_snapshot(["nft", "list", "ruleset"])
        # NIGHT-boost-12 hunt: structure vs structure. The raw string
        # compare saw the host's own traffic churn (counter bytes on
        # rules that predate the proof) as a zelynic change — the
        # owner's live Arch run failed exactly there.
        norm_before = nft_normalize(nft_before)
        norm_during = nft_normalize(nft_during)
        if norm_before == norm_during:
            ok_all = (
                lib.record(
                    "pure-eBPF: nftables ruleset unchanged (no netfilter path)",
                    "PASS",
                    "identical structure before and during enforcement "
                    "(kernel counter/expiry state normalized)",
                )
                == "PASS"
                and ok_all
            )
        else:
            delta = [
                ln
                for ln in difflib.unified_diff(
                    norm_before.splitlines(), norm_during.splitlines(), lineterm="", n=0
                )
                if ln[:1] in "+-" and not ln.startswith(("+++", "---"))
            ][:6]
            ok_all = (
                lib.record(
                    "pure-eBPF: nftables ruleset unchanged (no netfilter path)",
                    "FAIL",
                    "ruleset structure changed — something added/removed a "
                    "netfilter rule: " + " | ".join(delta[:4]),
                )
                == "PASS"
                and ok_all
            )
    else:
        lib.record(
            "pure-eBPF: nftables ruleset unchanged (no netfilter path)",
            "SKIP",
            "nft not installed — a tool that is not present cannot filter anything",
        )
    ld = os.environ.get("LD_PRELOAD", "")
    ok_all = (
        lib.record(
            "pure-eBPF: no LD_PRELOAD wrapper",
            "PASS" if not ld else "FAIL",
            "unset — and claim 1 already proved enforcement outlives every "
            "zelynic process, which no preload wrapper can do"
            if not ld
            else f"LD_PRELOAD={ld}",
        )
        == "PASS"
        and ok_all
    )
    entry = lib.limit_entry(lib.status_json(), CG.a_id)
    dropped = entry.get("packets_dropped", 0) if entry else 0
    ok_all = (
        lib.record(
            "pure-eBPF: kernel drops engaged (the datapath IS the limiter)",
            "PASS" if dropped > 0 else "FAIL",
            f"{dropped} packets dropped in-kernel, "
            f"{entry.get('bytes_allowed', 0) if entry else 0} bytes admitted",
        )
        == "PASS"
        and ok_all
    )
    # NIGHT-boost-12 hunt: `bpftool cgroup show` walks only the
    # LEGACY attach list, and zelynic's schema-v6 attaches ride
    # pinned BPF links — that subcommand does not list them (the
    # owner's live Arch run flagged exactly this false negative
    # while enforcement was provably alive). The program inventory
    # (`prog show`) is attach-mechanism-independent; `link show`
    # names the links themselves. Any surface carrying the
    # cgroup_skb truth proves the visibility claim.
    prog_ran, prog_out = tool_snapshot(["bpftool", "prog", "show"])
    link_ran, link_out = tool_snapshot(["bpftool", "link", "show"])
    cg_ran, cg_out = tool_snapshot(["bpftool", "cgroup", "show", lib.CGROUP_ROOT])
    if prog_ran or link_ran or cg_ran:
        surfaces = []
        if prog_ran and "cgroup_skb" in prog_out:
            surfaces.append(f"{prog_out.count('cgroup_skb')} cgroup_skb program(s) in prog show")
        if link_ran:
            links = sum(1 for ln in link_out.splitlines() if "cgroup" in ln)
            if links:
                surfaces.append(f"{links} cgroup link(s) in link show")
        if cg_ran and "cgroup_skb" in cg_out:
            surfaces.append(f"{cg_out.count('cgroup_skb')} attach(es) in cgroup show")
        ok_all = (
            lib.record(
                "pure-eBPF: cgroup_skb programs visible to bpftool",
                "PASS" if surfaces else "FAIL",
                "; ".join(surfaces)
                if surfaces
                else "bpftool ran but no surface shows a cgroup_skb program",
            )
            == "PASS"
            and ok_all
        )
    else:
        lib.record(
            "pure-eBPF: cgroup_skb programs visible to bpftool",
            "SKIP",
            "bpftool not installed — the pin row (claim 1) and the kernel-drop "
            "row above carry the same fact",
        )
    return ok_all


def stage_per_app(baseline):
    out = lib.out
    out()
    out("━━━ claim 3: per-app per-cgroup ━━━")
    if baseline and baseline < 10 * PER_APP_RATE:
        return (
            lib.record(
                "per-app: witness contrast",
                "SKIP",
                f"baseline {lib.fmt_bps(baseline)} too close to the limit to "
                "show a clear contrast between A and B",
            )
            == "PASS"
        )
    ok, payload = apply_and_verify(PER_APP_RATE, CG.a_id)
    if not ok:
        return lib.record("per-app: limit cgroup A", "FAIL", payload) == "PASS"
    lib.record(
        "per-app: limit cgroup A", "PASS", f"strict-single {bps_to_rate_str(PER_APP_RATE)} -d"
    )
    worker = subprocess.Popen(
        [
            sys.executable,
            os.path.abspath(__file__),
            "--witness-worker",
            CGROUP_B,
            str(PER_APP_WINDOW),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    holder = {}

    def a_side():
        holder["a_bytes"] = tracked_download(PER_APP_WINDOW, SERVER.port)

    t = threading.Thread(target=a_side)
    t.start()
    try:
        worker_out, worker_err = worker.communicate(timeout=PER_APP_WINDOW + 60)
    except subprocess.TimeoutExpired:
        worker.kill()
        worker_out, worker_err = worker.communicate()
    t.join()
    b_bps = None
    try:
        b_bps = json.loads(worker_out.strip().splitlines()[-1])["bps"]
    except (ValueError, KeyError, IndexError):
        pass
    a_bps = holder.get("a_bytes", 0) / PER_APP_WINDOW
    ok_a = (
        lib.band_check(
            "per-app: policed cgroup A held at its configured rate",
            a_bps,
            PER_APP_RATE,
        )
        == "PASS"
    )
    if b_bps is None:
        return (
            lib.record(
                "per-app: witness cgroup B unlimited (same machine, same moment)",
                "FAIL",
                f"witness worker produced no measurement: {(worker_err or '').strip()[:200]}",
            )
            == "PASS"
            and ok_a
        )
    floor = witness_floor(baseline, PER_APP_RATE)
    ok_b = (
        lib.record(
            "per-app: witness cgroup B unlimited (same machine, same moment)",
            "PASS" if b_bps >= floor else "FAIL",
            f"A measured {lib.fmt_bps(a_bps)} while B measured {lib.fmt_bps(b_bps)} "
            f"side by side — one cgroup shaped, its neighbor untouched "
            f"(B rides {b_bps / PER_APP_RATE:.0f}x A's configured rate; witness "
            f"floor {lib.fmt_bps(floor)})"
            if b_bps >= floor
            else f"B measured {lib.fmt_bps(b_bps)}, under the witness floor "
            f"{lib.fmt_bps(floor)} while A measured {lib.fmt_bps(a_bps)} — B is "
            "either shaped (a scope bug) or the machine is too loaded for a "
            "clean witness run",
            {"a_bps": round(a_bps), "b_bps": round(b_bps)},
        )
        == "PASS"
    )
    return ok_a and ok_b


def stage_precision(baseline, quick):
    out = lib.out
    out()
    out("━━━ claim 4: precision 0.00% ━━━")
    rate = PRECISION_RATE
    if baseline and baseline < 2 * rate:
        rate = PRECISION_RATE_FALLBACK
        if baseline and baseline < 2 * rate:
            return (
                lib.record(
                    "precision: long-run accounting",
                    "SKIP",
                    f"baseline {lib.fmt_bps(baseline)} cannot saturate even "
                    f"{lib.fmt_bps(rate)} — nothing honest to measure",
                )
                == "PASS"
            )
    ok, payload = apply_and_verify(rate, CG.a_id)
    if not ok:
        return lib.record("precision: attach limit", "FAIL", payload) == "PASS"
    window = 10.0 if quick else PRECISION_WINDOW
    bound = ACCOUNTING_ERR_MAX_QUICK if quick else ACCOUNTING_ERR_MAX_FULL
    progress = [0]
    t = threading.Thread(
        target=tracked_download,
        args=(window + PRECISION_SETTLE + 8.0, SERVER.port, progress),
        daemon=True,
    )
    t.start()
    time.sleep(PRECISION_SETTLE)  # saturating steady state before the first read
    e0 = bytes_allowed_now(CG.a_id)
    c0 = progress[0]
    t0 = time.perf_counter()
    time.sleep(window)
    e1 = bytes_allowed_now(CG.a_id)
    c1 = progress[0]
    t1 = time.perf_counter()
    # The client thread is a daemon with its own window margin: every
    # verdict above reads counters captured at t0/t1, so the tail of
    # the saturating stream needs no join — cleanup is safe to run
    # while it drains (no verdict depends on post-t1 bytes).
    if e0 is None or e1 is None:
        return (
            lib.record(
                "precision: long-run accounting",
                "FAIL",
                "status JSON lost the limit row mid-window",
            )
            == "PASS"
        )
    elapsed = t1 - t0
    expected = rate * elapsed
    admitted = e1 - e0
    client_delta = c1 - c0
    lib.band_check(
        "precision: TCP-level throughput (honest — drops cost, a policer never queues)",
        client_delta / elapsed,
        rate,
        "the socket sees TCP back-off; the kernel accounting below does not",
    )
    ratio = admitted / client_delta if client_delta else 0.0
    lib.record(
        "precision: kernel-admitted bytes match client-received bytes",
        "PASS" if 0.9 <= ratio <= 1.1 else "FAIL",
        f"{admitted} B admitted at the hook vs {client_delta} B received "
        f"at the socket — ratio {ratio:.4f}",
    )
    err = accounting_error(admitted, expected)
    return (
        lib.record(
            "precision: long-run token accounting vs configured rate",
            "PASS" if err <= bound else "FAIL",
            f"admitted {admitted} B over {elapsed:.1f}s vs configured "
            f"rate x time {expected:.0f} B — error {err * 100:.3f}% (bound "
            f"{bound * 100:.1f}%). The 0.00% contract is the token math: "
            "long-run admitted = rate x elapsed exactly, sub-byte frac_rem "
            "carry, pinned rootlessly in test/ebpf/limiter/math_tests.rs "
            "(steady-state exactness); the residual here is the status-read "
            "spawn latency, not limiter math",
            {"error_pct": round(err * 100, 4), "admitted": admitted, "expected": round(expected)},
        )
        == "PASS"
    )


def stage_footprint(quick):
    """Claim 5 — resource honesty (NIGHT-lts-6): the one-shot CLI's
    own RAM/CPU/IO and the attached programs' kernel run time.

    The userspace half rides the kernel's own accounting: wait4(2)
    hands the finished child's rusage — peak RSS, CPU seconds, block
    IO — with no sampling races and no /proc parsing. The kernel
    half reads bpftool's per-program run_time_ns / run_cnt after a
    saturating window: the average nanoseconds one attached enforce
    invocation costs, the number the "no daemon, no battery drain"
    claim quietly stands on (enforcement is kernel-resident; the
    CLI exited long before the measurement).
    """
    window = 2.5 if quick else 5.0
    rate_str = bps_to_rate_str(PURE_RATE)

    # The measured attach: fork the canonical strict-single, reap
    # with wait4 for the rusage (Popen's own wait is bypassed — the
    # pid is reaped here, the returncode handed back so Popen's
    # destructor never double-reaps).
    # CG.a_id (this harness's PairCgroups API — the supermassive
    # twin's ids-DICT shape does not exist here; the first live VM
    # run caught the mixup, and the self-test's source pin now
    # guards the vocabulary).
    argv = [lib.BINARY, "strict-single", str(CG.a_id), "-d", rate_str]
    try:
        child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _, status, ru = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
    except OSError as e:
        lib.record("footprint: attach", "FAIL", f"spawn failed: {e}")
        return
    if child.returncode != 0:
        lib.record("footprint: attach", "FAIL", f"exit {child.returncode}")
        return
    cpu_s = ru.ru_utime + ru.ru_stime
    block_io = ru.ru_inblock + ru.ru_oublock
    ok, detail = footprint_verdict(ru.ru_maxrss, cpu_s, block_io)
    lib.record("footprint: the one-shot CLI's own cost", "PASS" if ok else "FAIL", detail)

    # The kernel half: traffic through the policed hook, then the
    # attached programs' own average run time.
    tracked_download(window, SERVER.port)
    ran, out = tool_snapshot(["bpftool", "-j", "prog", "show"])
    kruns = []
    if ran:
        try:
            for prog in json.loads(out or ""):
                name = prog.get("name", "")
                if name.startswith("enforce_"):
                    run_ns = prog.get("run_time_ns")
                    run_cnt = prog.get("run_cnt")
                    if run_ns and run_cnt:
                        kruns.append((name, run_ns / run_cnt, run_cnt))
        except (ValueError, AttributeError, TypeError):
            kruns = []
    if kruns:
        worst = max(avg_ns for _, avg_ns, _ in kruns)
        detail = "; ".join(
            f"{name} {avg_ns:.0f}ns/run x{cnt:,}" for name, avg_ns, cnt in sorted(kruns)
        )
        lib.record(
            "footprint: kernel enforcement cost",
            "PASS" if worst <= FOOTPRINT_KRUN_MAX_NS else "FAIL",
            f"avg per attached-prog run {worst:.0f}ns "
            f"(bound {FOOTPRINT_KRUN_MAX_NS:,}ns) — {detail}",
        )
    else:
        lib.record(
            "footprint: kernel enforcement cost",
            "SKIP",
            "bpftool absent or no run_time_ns (kernel < 5.1) — "
            "the CLI footprint row above still stands",
        )

    # Leave the maps as the other stages found them.
    lib.run_zel(["unstrict-all"])


def stage_cleanup():
    out = lib.out
    out()
    out("━━━ cleanup ━━━")
    rc, _, _ = lib.run_zel(["unstrict-all"])
    ok_all = (
        lib.record(
            "cleanup: unstrict-all exits clean",
            "PASS" if rc == 0 else "FAIL",
            f"exit {rc}",
        )
        == "PASS"
    )
    pins = os.listdir(lib.PIN_DIR) if os.path.isdir(lib.PIN_DIR) else []
    ok_all = (
        lib.record(
            "cleanup: zero BPF pins remain",
            "PASS" if not pins else "FAIL",
            f"{lib.PIN_DIR} empty" if not pins else f"leftover: {', '.join(pins[:5])}",
        )
        == "PASS"
        and ok_all
    )
    ok_all = (
        lib.record(
            "cleanup: no pid file",
            "PASS" if not os.path.exists(PID_FILE) else "FAIL",
            f"{PID_FILE} absent",
        )
        == "PASS"
        and ok_all
    )
    pair_gone = CG.cleanup()
    ok_all = (
        lib.record(
            "cleanup: proof cgroups removed",
            "PASS" if pair_gone else "FAIL",
            "A and B both rmdir'd" if pair_gone else "a proof cgroup survived",
        )
        == "PASS"
        and ok_all
    )
    lib.dmesg_scan()
    return ok_all


# ── engine self-test (no root, no binary — CI lane) ───────────────────────


def self_test():
    out = lib.out
    out("zelynic proof-claims engine self-test (NIGHT-boost-8)")
    ok = True
    for bps, want in ((100_000, "100kb"), (5_000_000, "5mb"), (2_000_000_000, "2gb")):
        got = bps_to_rate_str(bps)
        ok = (
            lib.record(
                f"selftest: rate string {want}",
                "PASS" if got == want else "FAIL",
                f"bps_to_rate_str -> {got!r}",
            )
            == "PASS"
            and ok
        )
    err = accounting_error(1_000_000, 1_000_000)
    ok = (
        lib.record(
            "selftest: exact accounting error is 0.000%",
            "PASS" if err == 0.0 else "FAIL",
            f"{err * 100:.4f}%",
        )
        == "PASS"
        and ok
    )
    err = accounting_error(999_000, 1_000_000)
    ok = (
        lib.record(
            "selftest: accounting error math (0.1% case)",
            "PASS" if abs(err - 0.001) < 1e-12 else "FAIL",
            f"{err * 100:.4f}%",
        )
        == "PASS"
        and ok
    )
    # Loopback engine smoke: bytes must move without root or cgroups.
    server = TrafficServer()
    got = tracked_download(0.7, server.port)
    server.stop()
    ok = (
        lib.record(
            "selftest: loopback engine moves bytes",
            "PASS" if got > 0 else "FAIL",
            f"{got} B in 0.7s",
        )
        == "PASS"
        and ok
    )
    # Witness worker protocol end to end (sentry path: no cgroup move).
    p = subprocess.run(
        [sys.executable, os.path.abspath(__file__), "--witness-worker", WORKER_SENTRY, "0.7"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    witness_ok = False
    witness_detail = f"exit {p.returncode}: {(p.stderr or '').strip()[:200]}"
    try:
        doc = json.loads((p.stdout or "").strip().splitlines()[-1])
        witness_ok = doc.get("bytes", 0) > 0
        witness_detail = f"worker measured {doc.get('bytes')} B over {doc.get('window')}s"
    except (ValueError, KeyError, IndexError):
        pass
    ok = (
        lib.record(
            "selftest: witness worker protocol (spawn -> JSON line)",
            "PASS" if p.returncode == 0 and witness_ok else "FAIL",
            witness_detail,
        )
        == "PASS"
        and ok
    )
    # NIGHT-boost-12 hunt pins (rootless, CI-carried): the pure
    # functions behind the four false negatives of the owner's live
    # Arch run. Counter churn is state, not structure; the witness
    # floor is isolation-based, not half-baseline.
    rule = "ip saddr 192.168.1.2 counter packets {} bytes {} accept"
    ok = (
        lib.record(
            "selftest: nft normalization ignores counter churn",
            "PASS"
            if nft_normalize(rule.format(12345, 9876543))
            == nft_normalize(rule.format(12999, 9912111))
            else "FAIL",
            f"normalized: {nft_normalize(rule.format(12345, 9876543))!r}",
        )
        == "PASS"
        and ok
    )
    ok = (
        lib.record(
            "selftest: nft normalization preserves structure",
            "PASS"
            if nft_normalize(rule.format(1, 1)) != nft_normalize("ip saddr 192.168.1.2 accept")
            else "FAIL",
            "a missing counter clause is a structural difference",
        )
        == "PASS"
        and ok
    )
    ok = (
        lib.record(
            "selftest: witness floor is isolation-based, not half-baseline",
            "PASS"
            if witness_floor(13.2e9, 2e6) == 1.32e9 and witness_floor(0, 2e6) == 1e8
            else "FAIL",
            f"floor(13.2 GB/s baseline) = {witness_floor(13.2e9, 2e6):.3g}; "
            f"floor(no baseline) = {witness_floor(0, 2e6):.3g}",
        )
        == "PASS"
        and ok
    )
    ok = (
        lib.record(
            "selftest: witness verdict on the owner's live numbers",
            "PASS" if 4.2e9 >= witness_floor(13.2e9, 2e6) else "FAIL",
            "B 4.2 GB/s vs floor 1.32 GB/s (baseline 13.2 GB/s, A configured "
            "2 MB/s) — the run that motivated the fix now passes",
        )
        == "PASS"
        and ok
    )
    ok = (
        lib.record(
            "selftest: claim registry complete",
            "PASS" if len(CLAIM_STAGES) == 5 else "FAIL",
            f"{len(CLAIM_STAGES)} claims registered: "
            + ", ".join(name for name, _ in CLAIM_STAGES),
        )
        == "PASS"
        and ok
    )
    # NIGHT-lts-6 claim 5 pins: the footprint verdict's shape — the
    # healthy attach passes, each dimension fails alone (a bound that
    # cannot fail is a rubber stamp), and the detail prints the real
    # numbers it was handed.
    ok5, detail5 = footprint_verdict(8_192, 0.42, 7)
    ok = (
        lib.record(
            "selftest: footprint verdict passes a healthy attach",
            "PASS" if ok5 else "FAIL",
            detail5,
        )
        == "PASS"
        and ok
    )
    for label, rss, cpu, io in (
        ("RSS", 512 * 1024, 0.4, 5),
        ("CPU", 8_192, 30.0, 5),
        ("block IO", 8_192, 0.4, 9_999),
    ):
        bad, detail_bad = footprint_verdict(rss, cpu, io)
        ok = (
            lib.record(
                f"selftest: footprint verdict fails on {label} alone",
                "PASS" if not bad else "FAIL",
                detail_bad,
            )
            == "PASS"
            and ok
        )
    # NIGHT-lts-6 followup 2: the first live VM run crashed the
    # footprint stage on a supermassive-API mixup (CG.ids["a"] — a
    # shape this harness's PairCgroups never had; the twin harness
    # speaks it). A source pin: the stage must speak THIS harness's
    # API, or the next API drift fails rootlessly instead of in the
    # VM.
    fp_src = inspect.getsource(stage_footprint)
    ok = (
        lib.record(
            "selftest: footprint stage speaks this harness's cgroup API",
            "PASS" if "CG.a_id" in fp_src and "CG.ids" not in fp_src else "FAIL",
            "PairCgroups exposes a_id/b_id — the supermassive CG.ids shape does not exist here",
        )
        == "PASS"
        and ok
    )
    # NIGHT-blade-1: the first live VM failure printed a lying
    # verdict — a harness error aborted the footprint stage before
    # its rows, the counts read "0 failed", and final_report's
    # success line claimed the five claims proven while the CI
    # verdict said FAIL. The abort path now speaks its own honest
    # line; this pin holds it: the "proven" line belongs to the
    # success path alone, and the except path must name the abort.
    main_src = inspect.getsource(main)
    ok = (
        lib.record(
            "selftest: an aborted proof never claims proven",
            "PASS"
            if main_src.count("proven on this machine") == 1 and "ABORTED mid-run" in main_src
            else "FAIL",
            "the success path alone says proven; the except path names the abort",
        )
        == "PASS"
        and ok
    )
    return lib.final_report(time.perf_counter(), "self-test", "the claims-proof engine is sound.")


# ── main ──────────────────────────────────────────────────────────────────


def main():
    global SERVER, CG, PROCS_AT_START
    ap = argparse.ArgumentParser(
        prog="proof-claims",
        description="zelynic claims proof harness (NIGHT-boost-8)",
    )
    ap.add_argument("--binary", help="path to the zelynic binary")
    ap.add_argument("--quick", action="store_true", help="shorter windows (~30s)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--self-test", action="store_true", help="engine smoke, no root")
    ap.add_argument(
        "--witness-worker",
        nargs=2,
        metavar=("CGROUP", "WINDOW"),
        help=argparse.SUPPRESS,  # internal: the unlimited B-side lane
    )
    args = ap.parse_args()

    if args.witness_worker:
        witness_worker(args.witness_worker[0], float(args.witness_worker[1]))
        return 0
    if args.self_test:
        return 0 if self_test() else 1

    if os.geteuid() != 0:
        lib.out("This proof programs the kernel datapath — run with sudo.")
        return 2
    if not lib.resolve_binary(args.binary, "sudo ./scripts/bench/proof-claims.sh"):
        return 2
    # The no-daemon DELTA baseline (claim 1): every zelynic-named
    # process alive RIGHT NOW predates the proof. The gate's own -V
    # probe above has returned; anything still running is the
    # operator's (an interactive eagle-eyes in another terminal),
    # not something this proof spawned.
    PROCS_AT_START = zelynic_processes()

    quick = args.quick
    if quick:
        globals()["BASELINE_WINDOW"] = 1.5
        globals()["NO_DAEMON_WINDOW"] = 4.0
        globals()["PURE_WINDOW"] = 2.5
        globals()["PER_APP_WINDOW"] = 4.0
        globals()["PRECISION_SETTLE"] = 1.5

    start = time.perf_counter()
    CG = PairCgroups()
    exit_code = 1
    try:
        CG.setup()
        SERVER = TrafficServer()
        lib.out("zelynic claims proof harness (NIGHT-boost-8)")
        lib.out(f"  proving: {'; '.join(f'{n} ({d})' for n, d in CLAIM_STAGES)}")
        lib.out()
        env_ok = stage_env()
        if not env_ok:
            lib.out()
            lib.out("  environment not suitable for the proof — stopping here.")
        else:
            baseline = tracked_download(BASELINE_WINDOW, SERVER.port)
            lib.record(
                "baseline: unlimited loopback throughput",
                "PASS",
                f"{lib.fmt_bps(baseline)} over {BASELINE_WINDOW:.1f}s",
                {"bps": round(baseline)},
            )
            stage_no_daemon()
            stage_pure_ebpf()
            stage_per_app(baseline)
            stage_precision(baseline, quick)
            stage_footprint(quick)
            stage_cleanup()
        ok = lib.final_report(
            start,
            "quick" if quick else "full",
            "zelynic's five headline claims: proven on this machine, live.",
        )
        exit_code = 0 if ok else 1
    except Exception as e:  # noqa: BLE001 - report, then still clean up
        lib.out(f"  harness error: {e}")
        try:
            lib.run_zel(["unstrict-all"])
            CG.cleanup()
        except Exception:
            pass
        lib.final_report(
            start,
            "quick" if quick else "full",
            "the proof ABORTED mid-run on a harness error — the row "
            "counts above are the completed rows only; the interrupted "
            "claim never reached its verdict rows, so the exit is FAIL "
            "regardless of the counts.",
        )
        exit_code = 1
    finally:
        if SERVER:
            SERVER.stop()
    if args.json:
        print(json.dumps({"binary": lib.BINARY, "results": lib.RESULTS}, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
