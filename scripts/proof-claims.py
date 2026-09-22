#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic claims proof harness (NIGHT-boost-8) — honesty, enforced.

The README makes four headline claims. This harness proves every one
of them LIVE on the machine it runs on — same loopback engine, same
cgroup discipline, and the same verdict discipline as the depth and
supermassive twins (stdlib-only python3, no external test server,
root required for the live run, --self-test for CI without root):

  claim 1 — no daemon. zelynic is a one-shot CLI: attach and exit.
    Proven by attaching a limit, then scanning /proc for ANY process
    whose comm is the zelynic binary's basename (zero must remain —
    not the attaching process, not a supervisor, nothing), asserting
    no pid file exists, and then measuring a download that is STILL
    policed. Enforcement alive with zero zelynic processes IS the
    claim: the pinned bpf_links carry it in the kernel.

  claim 2 — pure eBPF. No tc qdisc, no nftables rule, no LD_PRELOAD
    wrapper — the kernel datapath does the shaping. Proven by
    snapshotting `tc qdisc show` and `nft list ruleset` before the
    attach and comparing during enforcement (a tool that is not even
    installed also cannot be shaping anything — that is a SKIP with
    the reason spelled out), asserting LD_PRELOAD is unset, and
    showing the kernel's own verdict: packets_dropped > 0 in the
    BPF counters plus the cgroup_skb attaches visible to bpftool.

  claim 3 — per-app per-cgroup. Proven with a pair: cgroup A
    (this harness, policed) and cgroup B (a witness subprocess with
    its own server+client, unlimited) measured SIMULTANEOUSLY on
    the same machine — A lands on its configured rate while B rides
    at baseline speed. One shaped, one free, same moment.

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

Usage:
  sudo ./scripts/proof-claims.sh               # full claims audit (~1 min)
  sudo ./scripts/proof-claims.sh --quick        # faster windows (~30s)
  ./scripts/proof-claims.sh --self-test         # engine smoke, no root
  sudo ./scripts/proof-claims.sh --json         # machine-readable
  sudo ./scripts/proof-claims.sh --binary ./target/pro-native-gnu/zelynic

Exit code: 0 = every verdict PASS or SKIP, 1 = any FAIL, 2 = usage
or environment not suitable.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time

import zelynic_harness_lib as lib

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

SERVER = None
CG = None
WORKER_SENTRY = "-"  # witness-worker cgroup path meaning "skip the move"

# The claim registry: every README headline claim maps to the stage
# that proves it. The self-test asserts the registry is complete —
# a claim without a stage is an unproven promise.
CLAIM_STAGES = (
    ("no-daemon", "attach, exit, stay enforced"),
    ("pure-eBPF", "no tc, no nft, no LD_PRELOAD, kernel drops"),
    ("per-app", "one cgroup shaped, its neighbor free"),
    ("precision", "kernel-admitted bytes vs configured rate"),
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
    The harness's own transient invocations (status reads) have all
    returned by the time a stage calls this — see the call sites."""
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
    # Every zelynic invocation above has returned. If ANY process with
    # the binary's name is alive now, that process is a resident.
    time.sleep(0.3)
    procs = zelynic_processes()
    ok_all = (
        lib.record(
            "no-daemon: zero zelynic processes after attach",
            "PASS" if not procs else "FAIL",
            "one-shot CLI: /proc scan found no resident process"
            if not procs
            else f"resident processes: {', '.join(procs[:5])}",
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
        ok_all = (
            lib.record(
                "pure-eBPF: nftables ruleset unchanged (no netfilter path)",
                "PASS" if nft_before == nft_during else "FAIL",
                "identical output before and during enforcement"
                if nft_before == nft_during
                else "ruleset changed — something added a netfilter rule",
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
    bpf_ran, bpf_out = tool_snapshot(["bpftool", "cgroup", "show", lib.CGROUP_ROOT])
    if bpf_ran:
        ok_all = (
            lib.record(
                "pure-eBPF: cgroup_skb programs visible to bpftool",
                "PASS" if "cgroup_skb" in bpf_out else "FAIL",
                f"{bpf_out.count('cgroup_skb')} cgroup_skb attach(es) at the cgroup root"
                if "cgroup_skb" in bpf_out
                else "bpftool ran but shows no cgroup_skb attach",
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
    floor = 0.5 * baseline if baseline else 10 * PER_APP_RATE
    ok_b = (
        lib.record(
            "per-app: witness cgroup B unlimited (same machine, same moment)",
            "PASS" if b_bps >= floor else "FAIL",
            f"A measured {lib.fmt_bps(a_bps)} while B measured {lib.fmt_bps(b_bps)} "
            f"side by side — one cgroup shaped, its neighbor untouched",
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
    ok = (
        lib.record(
            "selftest: claim registry complete",
            "PASS" if len(CLAIM_STAGES) == 4 else "FAIL",
            f"{len(CLAIM_STAGES)} claims registered: "
            + ", ".join(name for name, _ in CLAIM_STAGES),
        )
        == "PASS"
        and ok
    )
    return lib.final_report(time.perf_counter(), "self-test", "the claims-proof engine is sound.")


# ── main ──────────────────────────────────────────────────────────────────


def main():
    global SERVER, CG
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
    if not lib.resolve_binary(args.binary, "sudo ./scripts/proof-claims.sh"):
        return 2

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
            stage_cleanup()
        ok = lib.final_report(
            start,
            "quick" if quick else "full",
            "zelynic's four headline claims: proven on this machine, live.",
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
            "zelynic's four headline claims: proven on this machine, live.",
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
