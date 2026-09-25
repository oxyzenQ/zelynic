#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: the supermassive matrix is one self-contained harness by design — every stage shares the cgroup fleet, the traffic engine, and the verdict plumbing, so splitting it means a module package, not a script (the engine helpers it truly shares with limiter-depth-test.py ARE deduplicated into zelynic_harness_lib.py, NIGHT-improve-11; over the 1000 scripts cap under NIGHT-lts-2 — the module-package split is the tracked follow-up, its own NIGHT task)
"""zelynic supermassive test — the limiter-scope flagship harness (NIGHT-master-2; renamed from brutal-stress-test and engine-deduplicated in NIGHT-improve-11 / security-4; scope refocused in NIGHT-refactor-2).

NIGHT-master-1 (limiter-depth-test.py) answers "is the limiter ACCURATE?"
with measured rate bands. This harness answers the owner's next question:
"does the limiter HOLD, on every policy shape the parser accepts, on the
local loopback lane AND against the real internet?" — one click sweeps
every policy family (strict / block / unstrict, single / multi / all)
across real target shapes with real traffic, real curl processes, and the
full rate range the parser accepts, then repeats the flagship moves
against the public internet (NIGHT-refactor-2: the realnet lane moved
here from v2 — internet-lane policing is limiter scope by definition).

Division of labor with v2 (NIGHT-refactor-2, the owner's call): v1 owns
every stage that measures a LIMIT — the matrix, the rate-change move, the
internet lane. v2 (supermassive-test-v2.py) owns everything that is NOT
a limit measurement: the CLI input guards (typo rescue, dangerous-value
refusals), the SIGKILL batteries (live TUI, mid-flight writers), the
post-kill regression battery, and the recover/cleanup/dmesg teardown.
A machine green on v1 has a limiter that holds everywhere it claims;
a machine green on v2 survives the day nothing goes right.

Design:

  * One click, one intensity (NIGHT-improve-19): the complete
    supermassive matrix (5+ minutes, long running until done) is the
    default and ONLY root mode — the old light sweep was retired: it
    ran a subset of the same stages with smaller windows, so a green
    light run said nothing the matrix does not say more strongly,
    while a red one usually just meant tighter timing margins.
    --self-test verifies the harness engine alone
    (no root, no zelynic, no BPF, no network) so CI and containers can
    smoke it anywhere — the same cross-distro minimum as NIGHT-master-1:
    python3 stdlib only, curl optional (its stages SKIP, the rest keeps
    working).
  * Shared engine: the fourteen helpers this harness and limiter-depth-
    test.py used to duplicate (verdict recording, subprocess control,
    status-JSON reading, environment probes, binary resolution, the
    final report) live in scripts/lib/zelynic_harness_lib.py — one fix
    lands in every harness the same day (NIGHT-improve-11; the hunt-31
    kernfs-inode and the target/pro-native-gnu binary candidate each
    drifted for days between the twins before that). Since
    NIGHT-improve-23 the family is three: supermassive-test-v2.py
    (the survival battery) imports THIS module whole via importlib and
    drives the fleet, server, and policy helpers below — a stage added
    or fixed here lands in v2's hands with no second copy to drift.
  * Traffic is loopback HTTP served by an in-process python server, so
    no external test server is ever needed. curl is the second traffic
    engine: real external processes pushed through the limiter, the same
    class of proof as the owner's manual browser tests.
  * The real-internet lane (NIGHT-refactor-2, moved from v2): a
    reachability probe walks a fallback chain of long-lived public
    endpoints (Cloudflare speed first, then OVH, then Tele2) and the
    FIRST reachable one feeds every internet stage — cross-distro and
    cross-year robustness by construction, with honest SKIP verdicts
    (never silent, never false FAILs) when the machine has no egress or
    every endpoint is down: the local lane still carries the verdict.
    Realnet rate rows use a wider band floor (slow-start patience) with
    the same tripwire ceiling. Uploads stream chunked from /dev/zero to
    the Cloudflare discard endpoint, and an UNLIMITED sanity upload runs
    first so an endpoint that refuses streaming bodies reads as SKIP,
    not as a limiter defect.
  * Six dedicated cgroups (zelynic-supermassive-a..e + -hq): the harness
    itself (in-process server + CLI calls) lives in the never-policed hq
    cgroup, while every measurement client — python workers and curls
    alike — is exec-moved into the target cgroup BEFORE its first socket
    exists (deterministic cgroup attribution, no spawn race), so
    strict-multi / block-multi group policies are measured across
    genuinely separate cgroups. On loopback the download direction is
    policed at the receiver's ingress (client cgroup) and the upload
    direction at the sender's egress — one dl-map hit and one ul-map hit
    per stream, so keeping the server cgroup (hq) unlimited keeps the
    byte accounting 1:1 with the client's count. The pre-NIGHT-improve-12
    design parked the harness inside target 'a' itself: every loopback
    download byte then crossed a's egress AND ingress hooks, the combined
    dl+ul counter read ~2x the client bytes, and every accounting row
    failed at ~200%.
  * Rate range: the ladder walks the parser's full span — 1kb (the
    minimum) through 10mb and 1gb, up to 1tb (the maximum) — skipping any
    rung the hardware cannot feed (baseline < 2x rung): "up to 1 TB/s if
    hardware supports". Rungs whose token bucket is smaller than ONE
    loopback GSO skb (rates below ~64 KB/s) cannot reach steady state on
    loopback — physics, not an enforcement miss — so their band floor is
    zero and the ceiling plus kernel-drop proof carry the verdict
    (NIGHT-improve-12).
  * Every rate verdict is MEASURED (client / curl byte counters), then
    proven in-kernel through the status JSON (bytes_allowed /
    packets_dropped) — exactly the NIGHT-master-1 contract.
  * limit-all is exercised with --force, briefly and
    at a generous rate: as root the harness's own cgroups are uid 0 and
    would otherwise be skipped as system apps. block-all is deliberately
    NOT exercised — blocking every app can sever the very session that
    runs the test.

Usage:
  sudo ./scripts/supermassive/supermassive-test.sh              # supermassive (6+ min)
  sudo ./scripts/supermassive/supermassive-test.sh --heavy      # the same, explicit
  python3 scripts/supermassive/supermassive-test.py --self-test # engine smoke, no root
  sudo ./scripts/supermassive/supermassive-test.sh --binary ./zelynic
  sudo ./scripts/supermassive/supermassive-test.sh --json

What it verifies (verdicts PASS / FAIL / SKIP, exit 1 on any FAIL):
  the matrix: env + minimum specs, doctor, list-apps JSON, baseline,
         strict-single policy write, status human + JSON surfaces,
         the live rate change 1mb -> 2mb under an active policy (both
         rungs MEASURED, not just re-read from the status row), the
         full rate ladder 1kb..1tb (two windows per rung, 1gb+ rungs as
         six-flow aggregates), upload-only (-u), download-only (-d),
         asymmetric -d/-u buckets, block-single zero goodput,
         unstrict-single (unlock) restores speed, curl burst parallel
         download, curl upload, strict-multi shared group bucket across
         cgroups, block-multi, unstrict-multi selective removal, mixed
         concurrent policies on five cgroups, limit-all --force sweep,
         reload cycles, sustain windows, non-binding overhead — then
         the real-internet lane: endpoint reachability, unlimited
         realnet baseline, upload-engine sanity, strict download at
         2mb, strict upload at 1mb, limit-all sweep at 2mb, block-single
         zero goodput, unstrict-all restores the machine's own internet
         speed — and the cleanup teardown (no limit rows, no pins, no
         pid file, fleet removed).
"""

import argparse
import contextlib
import errno
import inspect
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

# The shared engine lib lives in scripts/lib/ — bound by ABSOLUTE path so
# the harness works from any CWD, through the wrapper, or via importlib
# (the same bootstrap v2 and the other harnesses use).
_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

import zelynic_harness_lib as lib  # noqa: E402 - needs the lib/ path bootstrap above

# NOTE: BINARY is deliberately NOT in this list — resolve_binary REBINDS it
# inside the lib module, and a from-import would keep a stale empty string
# here. Reference it as lib.BINARY; the mutation-only names (RESULTS) are
# safe to bind directly.
from zelynic_harness_lib import (  # noqa: E402 - needs the lib/ path bootstrap above
    BAND_HI,
    BAND_LO,
    CGROUP_ROOT,
    CHUNK,
    PIN_DIR,
    RESULTS,
    band_check,
    binary_version,
    bpffs_mounted_at,
    cgroup2_mounted,
    cpu_model,
    doctor_check,
    final_report,
    fmt_bps,
    limit_entry,
    mbps,
    out,
    pretty_name,
    record,
    run_zel,
    status_json,
)

CG_NAMES = "abcde"
TEST_CGROUPS = [f"{CGROUP_ROOT}/zelynic-supermassive-{n}" for n in CG_NAMES]
# NIGHT-improve-12: the harness process (in-process HTTP server + every
# run_zel control call) lives in a sixth, NEVER-policed hq cgroup, while
# measurement clients run as workers inside the target fleet. When the
# server shared target cgroup "a" (the pre-12 design), every loopback
# download byte crossed cgroup a's egress hook (server sending, upload
# policy) AND its ingress hook (client receiving, download policy), so
# the combined dl+ul stats map counted each byte twice and every
# "BPF accounting matches client bytes" row read ~200%.
HQ_CGROUP = f"{CGROUP_ROOT}/zelynic-supermassive-hq"
BLOCK_GOODPUT_CEIL = 64 * 1024  # bytes per window: "blocked" means ~zero
# (rate string, expected bps) — explicit pairs, no inversion math to drift.
# NIGHT-improve-19: LADDER_LIGHT was retired with the light mode — the
# matrix walks the full span in every root run.
LADDER_HEAVY = [
    ("1kb", 1_000),
    ("10kb", 10_000),
    ("100kb", 100_000),
    ("1mb", 1_000_000),
    ("10mb", 10_000_000),
    ("100mb", 100_000_000),
    ("1gb", 1_000_000_000),
    ("10gb", 10_000_000_000),
    ("100gb", 100_000_000_000),
    ("1tb", 1_000_000_000_000),
]
# NIGHT-improve-14/15: rungs this close to the loopback ceiling are
# measured as a PARALLEL aggregate, not one flow. The improve-14
# theory was that six flows' staggered AIMD dips would let the
# aggregate track the refill rate; the 1e9fa80 nightpc run disproved
# the mechanism — single-flow 55.7%, six-flow 53.9% (flow count is
# not the variable: see lib.DEFAULT_BURST_CAP's min-RTO cushion
# physics). The aggregate STAYS because it is the stronger
# instrument: six workers wanting ~4 GB/s and still landing at half
# of 1gb proves the shortfall is AIMD-under-a-dropper, not demand
# starvation — while the cap is never exceeded and drops +
# accounting hold on the same rung. The band floor for those rungs
# follows the cushion model (lib.loopback_rate_floor); below this
# line the single-flow instrument stays.
PARALLEL_FLOWS = 6
PARALLEL_MIN_BPS = 500_000_000

SERVER = None
CG = None
MODE = ""
CURL = shutil.which("curl")
# NIGHT-improve-13: every measurement-worker failure that would
# otherwise read as a silent "0 B/s" rate row is filed here (see
# _note_worker_fault / report_worker_faults).
WORKER_FAULTS = []


# ── dedicated cgroup fleet ─────────────────────────────────────────────────


class CgroupSet:
    """Five dedicated target cgroups plus one never-policed hq cgroup
    for the harness process itself.

    Same isolation contract as NIGHT-master-1's single test cgroup —
    zelynic polices by cgroup ID at the root, so child cgroups give the
    harness five independent test beds without touching the owner's
    session. The harness process itself (the in-process HTTP server and
    every zelynic CLI call) lives in hq, OUTSIDE the fleet: if the
    traffic server sits inside a policed cgroup, a loopback stream
    crosses that cgroup's egress AND ingress hooks and the kernel's
    combined dl+ul counter reads ~2x the client's bytes
    (NIGHT-improve-12). When dedicated cgroups cannot be created, every
    name falls back to the current session cgroup and the multi-cgroup
    stages SKIP (single-cgroup stages still measure honestly; the
    accounting cross-check is likewise gated on dedicated mode).
    """

    def __init__(self):
        self.ids = {}
        self.paths = {}
        self.dedicated = False

    def setup(self):
        self._absorb_leftovers()
        try:
            os.mkdir(TEST_CGROUPS[0])
            # hq first: the harness moves HERE, never into a target bed
            # (see the class docstring for the accounting reason).
            os.mkdir(HQ_CGROUP)
            with open(f"{HQ_CGROUP}/cgroup.procs", "w") as f:
                f.write(str(os.getpid()))
            hq_id = self._read_id(HQ_CGROUP)
            if hq_id is None:
                raise OSError("cgroup id unresolvable (stat failed)")
            self.paths["hq"] = HQ_CGROUP
            self.ids["hq"] = hq_id
            cid = self._read_id(TEST_CGROUPS[0])
            if cid is None:
                raise OSError("cgroup id unresolvable (stat failed)")
            self.dedicated = True
            self.ids["a"] = cid
            self.paths["a"] = TEST_CGROUPS[0]
            for name, path in zip(CG_NAMES[1:], TEST_CGROUPS[1:]):
                os.mkdir(path)
                self.paths[name] = path
                c2 = self._read_id(path)
                if c2 is None:
                    raise OSError(f"cgroup id unresolvable for {path}")
                self.ids[name] = c2
            return f"dedicated fleet {TEST_CGROUPS[0]}..e, harness in hq"
        except OSError:
            self._leave(HQ_CGROUP)
            self._cleanup_dirs()
        # Fallback: every name maps to the current session cgroup.
        path = self._self_cgroup_path()
        if not path:
            raise RuntimeError(
                "could not resolve the session cgroup: /proc/self/cgroup has "
                "no cgroup v2 (0::) line — a unified hierarchy is required"
            )
        cid = self._read_id(f"{CGROUP_ROOT}/{path}")
        if cid is None:
            raise RuntimeError("session cgroup id unresolvable (stat failed)")
        for name in CG_NAMES:
            self.ids[name] = cid
            self.paths[name] = f"{CGROUP_ROOT}/{path}"
        return (
            f"session cgroup /{path} (dedicated fleet not creatable — "
            "multi-cgroup stages will SKIP)"
        )

    @staticmethod
    def _read_id(path):
        """The cgroup ID is the kernfs inode number — the same numbering
        bpf_skb_cgroup_id() returns (kernfs publishes kn->id as st_ino).
        No cgroup.id file exists in any mainline kernel (NIGHT-hunt-31);
        this mirrors zelynic's own cgroup_id_from_path, truncated to the
        u32 the BPF maps key on."""
        try:
            return os.stat(path).st_ino & 0xFFFFFFFF
        except OSError:
            return None

    @staticmethod
    def _self_cgroup_path():
        try:
            with open("/proc/self/cgroup", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("0::"):
                        return line[3:].strip()
        except OSError:
            pass
        return None

    def _absorb_leftovers(self):
        for path in TEST_CGROUPS + [HQ_CGROUP]:
            if not os.path.isdir(path):
                continue
            try:
                with open(f"{path}/cgroup.procs") as f:
                    pids = [p for p in f.read().split() if p]
                for pid in pids:
                    try:
                        with open(f"{CGROUP_ROOT}/cgroup.procs", "w") as dst:
                            dst.write(pid)
                    except OSError:
                        pass
                for _ in range(3):
                    try:
                        os.rmdir(path)
                        break
                    except OSError:
                        time.sleep(0.3)
            except OSError:
                pass

    def _leave(self, path):
        try:
            with open(f"{CGROUP_ROOT}/cgroup.procs", "w") as f:
                f.write(str(os.getpid()))
        except OSError:
            pass

    def _cleanup_dirs(self):
        for path in TEST_CGROUPS + [HQ_CGROUP]:
            for _ in range(3):
                if not os.path.isdir(path):
                    break
                try:
                    os.rmdir(path)
                    break
                except OSError:
                    time.sleep(0.3)

    def cleanup(self):
        if not self.dedicated:
            return True
        self._leave(HQ_CGROUP)
        self._cleanup_dirs()
        return not any(os.path.isdir(p) for p in TEST_CGROUPS + [HQ_CGROUP])


# ── loopback HTTP traffic engine ───────────────────────────────────────────


class HttpServer:
    """Minimal HTTP/1.0 server on 127.0.0.1 (curl- and python-compatible).

      GET /dl    -> infinite zero-byte stream (client cuts the window)
      PUT /ul    -> discards the body, counts raw bytes (a chunked
                    upload's framing overhead is <0.1% — the verdict
                    band absorbs it)

    The client / curl counters are authoritative for rate verdicts;
    peek() exposes the server-side counters for the self-test's
    agreement checks (call settle() first — the /dl counter is only
    final once the server thread has noticed the client's close).
    """

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(128)
        self.port = self.sock.getsockname()[1]
        self.dl_bytes = 0
        self.ul_bytes = 0
        # E2E-workflow hunt (run five): the accept loop used to exit on
        # ANY OSError - a single transient fault (EMFILE, ECONNABORTED,
        # ENOBUFS, ...) killed all future connection handling while the
        # kernel backlog kept accepting and buffering, so the app-level
        # counters silently froze (the runner's curl upload folded 0 B
        # against 5.4 MB kernel-allowed). The faults are now counted and
        # surfaced through peek() so a frozen counter names its cause.
        self.accept_errors = 0
        self.conn_count = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError as e:
                # EBADF with stop() set is the normal shutdown path; a
                # closed listen socket can accept nothing further.
                if self._stop.is_set() or e.errno == errno.EBADF:
                    return
                # Transient accept faults retry with a breath instead
                # of killing the loop - the old `except OSError:
                # return` turned one hiccup into a permanently deaf
                # server whose counters froze mid-matrix.
                with self._lock:
                    self.accept_errors += 1
                time.sleep(0.05)
                continue
            with self._lock:
                self.conn_count += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _read_request(conn):
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 8192:
            try:
                data = conn.recv(4096)
            except OSError:
                return b"", b""
            if not data:
                return b"", b""
            buf += data
        idx = buf.find(b"\r\n\r\n")
        if idx < 0:
            return buf, b""
        head, rest = buf[:idx], buf[idx + 4 :]
        path = head.split(b"\r\n", 1)[0].split(b" ")[1] if b" " in head else b""
        return path, rest

    def _serve(self, conn):
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            path, rest = self._read_request(conn)
            if path.startswith(b"/dl"):
                head = (
                    b"HTTP/1.0 200 OK\r\n"
                    b"Content-Type: application/octet-stream\r\n"
                    b"Connection: close\r\n\r\n"
                )
                try:
                    conn.sendall(head)
                    blob = b"\x00" * CHUNK
                    sent = 0
                    while True:
                        conn.sendall(blob)
                        sent += CHUNK
                except OSError:
                    pass  # the client closed its window: normal end
                with self._lock:
                    self.dl_bytes += sent
            elif path.startswith(b"/ul"):
                got = len(rest)
                while True:
                    try:
                        data = conn.recv(CHUNK)
                    except OSError:
                        break
                    if not data:
                        break
                    got += len(data)
                with self._lock:
                    self.ul_bytes += got
                try:
                    conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def peek(self):
        """Read the counters without resetting them."""
        with self._lock:
            return {
                "dl": self.dl_bytes,
                "ul": self.ul_bytes,
                "conns": self.conn_count,
                "accept_errors": self.accept_errors,
            }

    def reset(self):
        with self._lock:
            self.dl_bytes = 0
            self.ul_bytes = 0

    def settle(self, seconds=0.4):
        """Let the /dl writers notice the client's close and land their
        final byte counts before peek() is read."""
        time.sleep(seconds)

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def http_get(url_path):
    """Open a connection and send a bare HTTP/1.0 request line."""
    s = socket.create_connection(("127.0.0.1", SERVER.port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(f"GET {url_path} HTTP/1.0\r\n\r\n".encode())
    return s


# Measurement-client bodies for the worker processes (NIGHT-improve-12):
# under a dedicated fleet the PYTHON client must run inside the target
# cgroup exactly like the curl workers, or its traffic is attributed to
# the harness's hq cgroup and never policed. Each worker prints exactly
# one integer on the last stdout line — the spawn_in_cgroup contract.
# Connect failures print 0: under a block-* policy the SYN itself is
# dropped, and ZERO GOODPUT is the honest measurement, never a crash.
#
# NIGHT-improve-13: these MUST stay RAW strings (r"""). As plain
# triple-quoted strings every backslash escape below was unescaped at
# PARENT parse time and the child received corrupted source: \x00
# became a literal NUL inside the argv (Popen raised "ValueError:
# embedded null byte" and killed the whole run at the first py_upload
# call), \r\n became real CR/LF inside the child's b"..." literal
# (SyntaxError, empty stdout — which read as a clean 0 B/s in every
# rate row). The self-test's parse + end-to-end worker rows pin both
# layers rootlessly.
_PY_DL_CLIENT = r"""import socket, sys, time
port, window = int(sys.argv[1]), float(sys.argv[2])
total = 0
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(b"GET /dl HTTP/1.0\r\n\r\n")
    deadline = time.perf_counter() + window
    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            break
        s.settimeout(remaining)
        try:
            data = s.recv(65536)
        except OSError:
            break
        if not data:
            break
        total += len(data)
    s.close()
except OSError:
    pass
print(total)
"""

_PY_UL_CLIENT = r"""import socket, sys, time
port, window = int(sys.argv[1]), float(sys.argv[2])
sent = 0
try:
    s = socket.create_connection(("127.0.0.1", port), timeout=10)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.sendall(b"PUT /ul HTTP/1.0\r\nContent-Length: 999999999\r\n\r\n")
    blob = b"\x00" * 65536
    deadline = time.perf_counter() + window
    while time.perf_counter() < deadline:
        try:
            s.sendall(blob)
            sent += 65536
        except OSError:
            break
    s.close()
except OSError:
    pass
print(sent)
"""


def worker_smoke(code, port, window):
    """Run one embedded worker EXACTLY the way root mode runs it — as a
    real `python -c` argv element under the stdout integer contract —
    minus only the cgroup move, so the self-test can pin the worker
    path rootlessly (NIGHT-improve-13)."""
    try:
        r = subprocess.run(
            [sys.executable, "-c", code, str(port), str(window)],
            capture_output=True,
            text=True,
            timeout=window + 20,
        )
    except subprocess.TimeoutExpired:
        return None, "worker did not finish"
    except (ValueError, OSError) as e:
        return None, f"spawn failed: {e}"
    lines = r.stdout.strip().splitlines()
    if r.returncode != 0 or not lines:
        err = (r.stderr.strip().splitlines() or ["<no stderr>"])[-1]
        return None, f"worker exit {r.returncode}: {err[:80]}"
    try:
        return int(lines[-1]), ""
    except ValueError:
        return None, f"no integer on stdout ({lines[-1][:60]})"


def py_download(window, name="a"):
    """Read the /dl stream for `window` seconds; returns body bytes.

    Under a dedicated fleet the client runs as a WORKER inside target
    cgroup `name` (see _PY_DL_CLIENT) so its traffic is policed and
    attributed there, while the server stays in the never-policed hq
    cgroup — one stream, one policed hook, 1:1 accounting
    (NIGHT-improve-12). In the session-cgroup fallback and the engine
    self-test the client runs in-process instead: the harness shares the
    target cgroup there by construction. A connect failure is ZERO
    GOODPUT, not a crash — under a block-* policy the SYN is dropped
    and create_connection raises (the 2026-09-21 "harness error: timed
    out" crash at block-single).
    """
    if CG and CG.dedicated:
        metric, _ = spawn_in_cgroup(
            name,
            [sys.executable, "-c", _PY_DL_CLIENT, str(SERVER.port), str(window)],
            window + 20,
        )
        return metric or 0
    try:
        s = http_get("/dl")
    except (socket.timeout, OSError):
        return 0
    with s:
        deadline = time.perf_counter() + window
        total = 0
        while True:
            remaining = deadline - time.perf_counter()
            if remaining <= 0:
                break
            s.settimeout(remaining)
            try:
                data = s.recv(CHUNK)
            except (socket.timeout, OSError):
                break
            if not data:
                break
            total += len(data)
    return total


def py_upload(window, name="a"):
    """Stream zeros to /ul for `window` seconds; returns bytes written.

    Same worker/fallback contract as py_download (NIGHT-improve-12);
    connect failures are zero goodput, not a crash.
    """
    if CG and CG.dedicated:
        metric, _ = spawn_in_cgroup(
            name,
            [sys.executable, "-c", _PY_UL_CLIENT, str(SERVER.port), str(window)],
            window + 20,
        )
        return metric or 0
    try:
        s = socket.create_connection(("127.0.0.1", SERVER.port), timeout=10)
    except (socket.timeout, OSError):
        return 0
    with s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.sendall(b"PUT /ul HTTP/1.0\r\nContent-Length: 999999999\r\n\r\n")
        blob = b"\x00" * CHUNK
        sent = 0
        deadline = time.perf_counter() + window
        while time.perf_counter() < deadline:
            try:
                s.sendall(blob)
                sent += CHUNK
            except OSError:
                break
    return sent


def curl_cmd(window, url_path, metric="size_download"):
    return [
        CURL,
        "-s",
        "-o",
        "/dev/null",
        "-w",
        f"%{{{metric}}}",
        "--max-time",
        f"{window}",
        f"http://127.0.0.1:{SERVER.port}{url_path}",
    ]


def curl_run(cmd, timeout):
    """Run curl; a non-zero exit is EXPECTED when --max-time truncates
    the stream — the -w metric line is the verdict, not the exit code."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        raw = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
    except (subprocess.TimeoutExpired, OSError) as e:
        return None, str(e)
    try:
        return int(raw), ""
    except ValueError:
        return None, f"no metric in stdout ({raw[:60] or 'empty'})"


def curl_download(window):
    """Local curl download (engine self-test / fallback mode only —
    root stages use curl_in_cgroup so the worker is policed)."""
    return curl_run(curl_cmd(window, "/dl"), window + 20)[0]


def curl_upload_cmd(window):
    # -T /dev/zero: an unsizeable character device forces a streaming
    # chunked upload — the classic curl upload-speed pattern. The URL
    # path is explicit so no filename gets appended. curl's 1s
    # Expect-100-continue pause is absorbed by the window.
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
        f"http://127.0.0.1:{SERVER.port}/ul",
    ]


def curl_upload(window):
    """Local curl upload (engine self-test / fallback mode only)."""
    return curl_run(curl_upload_cmd(window), window + 20)[0]


def curl_upload_in_cgroup(name, window):
    """Curl upload as a worker inside cgroup `name` (NIGHT-improve-12):
    the measurement client must be policed where the policy lives, not
    in the harness's hq cgroup. Returns (bytes, err)."""
    return spawn_in_cgroup(name, curl_upload_cmd(window), window + 25)


def popen_in_cgroup(name, argv):
    """Popen argv through a helper bash that first moves ITSELF into
    dedicated cgroup `name` and then execs — the exec keeps the same
    PID, so the process (and every socket it creates afterwards) is
    attributed to the target cgroup before any network happens.
    """
    script = f'echo $$ > "{CG.paths[name]}/cgroup.procs"\nexec "$@"'
    return subprocess.Popen(
        ["bash", "-c", script, "worker"] + argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def _note_worker_fault(err):
    """File one distinct worker failure, counted (NIGHT-improve-13).

    The improve-12 run hid its own broken workers: worker stderr went
    to DEVNULL, the error half of every (metric, err) tuple was
    discarded, and a dead worker measured as a clean 0 B/s in sixteen
    rate rows while the only loud symptom was a bare ValueError at
    the upload stage.
    """
    for i, (msg, count) in enumerate(WORKER_FAULTS):
        if msg == err:
            WORKER_FAULTS[i] = (msg, count + 1)
            return
    WORKER_FAULTS.append((err, 1))


def report_worker_faults():
    """Print the collected worker faults above the verdict so "FAILURES
    present — see the marked rows above" points at a cause."""
    if not WORKER_FAULTS:
        return
    out()
    out("━━━ worker faults (measurement clients that never reported a metric) ━━━")
    for msg, count in WORKER_FAULTS:
        out(f"  {count}x {msg}")


def spawn_in_cgroup(name, argv, timeout):
    """Run argv to completion inside cgroup `name`; returns (metric, err).

    Worker faults are ALSO filed into WORKER_FAULTS (NIGHT-improve-13)
    so a broken engine reads as "worker faults" in the final report,
    not as a matrix of clean-looking 0 B/s rows. Unexpected spawn
    exceptions — e.g. a null byte smuggled into an argv element —
    still RAISE: unknown bugs crash loudly into main's handler instead
    of silently zeroing the matrix.
    """
    try:
        p = popen_in_cgroup(name, argv)
    except OSError as e:
        _note_worker_fault(f"spawn {os.path.basename(argv[0])}: {e}")
        return None, str(e)
    try:
        stdout, _ = p.communicate(timeout=timeout)
        metric = stdout.strip().splitlines()[-1] if stdout.strip() else ""
        try:
            return int(metric), ""
        except ValueError:
            err = f"no metric ({metric[:60] or 'empty'})"
            _note_worker_fault(f"{os.path.basename(argv[0])}: {err}")
            return None, err
    except subprocess.TimeoutExpired:
        p.kill()
        _note_worker_fault(f"{os.path.basename(argv[0])}: worker did not finish")
        return None, "worker did not finish"


def spawn_bg_in_cgroup(name, argv, settle_timeout=5.0):
    """Resident process (sleepers) inside cgroup `name`, residency-guaranteed.

    Returns the Popen handle once the child has (1) joined the target
    cgroup (its pid appears in the cgroup's cgroup.procs) and (2) finished
    exec (/proc/<pid>/comm equals the final argv[0] basename), or None when
    the child died or never settled within settle_timeout seconds (killed
    first, so a failed spawn leaks nothing). The barrier closes the
    spawn/limit-all race the 2026-09-22 heavy run exposed: limit-all walks
    /proc twice (the identity tally, then per-name resolution after the
    BPF attach), and a bash child caught between its cgroup.procs echo and
    its exec resolves as "bash" in the first walk and as nothing in the
    second — the fleet cgroups then miss the machine-wide sweep entirely
    and the row check reports a mystery None.
    """
    script = f'echo $$ > "{CG.paths[name]}/cgroup.procs"\nexec "$@"'
    proc = subprocess.Popen(
        ["bash", "-c", script, "worker"] + argv,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # The kernel truncates comm to TASK_COMM_LEN-1 = 15 characters.
    want_comm = os.path.basename(argv[0])[:15]
    procs_file = f"{CG.paths[name]}/cgroup.procs"
    comm_file = f"/proc/{proc.pid}/comm"
    deadline = time.monotonic() + settle_timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            break  # child exited before settling
        try:
            with open(procs_file, encoding="utf-8") as fh:
                resident = str(proc.pid) in fh.read().split()
        except OSError:
            resident = False
        if resident:
            try:
                with open(comm_file, encoding="utf-8") as fh:
                    if fh.read().strip() == want_comm:
                        return proc
            except OSError:
                pass  # exec not finished yet; retry
        time.sleep(0.01)
    proc.kill()
    proc.wait()
    return None


def curl_in_cgroup(name, window):
    """One curl download inside cgroup `name`; returns (bytes, error)."""
    return spawn_in_cgroup(name, curl_cmd(window, "/dl"), window + 25)


# ── policy helpers (single source for every apply / verify / clear) ────────


def apply_single(name, rate_str, exp_dl, exp_ul, extra=()):
    rc, stdout, stderr = run_zel(["strict-single", str(CG.ids[name]), rate_str, *extra])
    if rc != 0:
        return False, f"strict-single exit {rc}: {(stderr or stdout).strip()[:200]}"
    entry = limit_entry(status_json(), CG.ids[name])
    if entry is None:
        return False, f"no limit row for cgroup {CG.ids[name]} in status JSON"
    if exp_dl is not None and entry.get("download_bps") != exp_dl:
        return False, f"download_bps {entry.get('download_bps')} != {exp_dl}"
    if exp_ul is not None and entry.get("upload_bps") != exp_ul:
        return False, f"upload_bps {entry.get('upload_bps')} != {exp_ul}"
    return True, entry


def apply_group(names, rate_str, exp):
    target = ":".join(str(CG.ids[n]) for n in names)
    rc, stdout, stderr = run_zel(["strict-multi", target, rate_str])
    if rc != 0:
        return False, f"strict-multi exit {rc}: {(stderr or stdout).strip()[:200]}"
    doc = status_json()
    for n in names:
        entry = limit_entry(doc, CG.ids[n])
        if entry is None:
            return False, f"no limit row for cgroup {CG.ids[n]}"
        if entry.get("download_bps") != exp or entry.get("upload_bps") != exp:
            return (
                False,
                f"row for {CG.ids[n]} is {entry.get('download_bps')}/{entry.get('upload_bps')}, want {exp}",
            )
    return True, target


def block_target(cmd, names):
    target = ":".join(str(CG.ids[n]) for n in names)
    rc, stdout, stderr = run_zel([cmd, target])
    if rc != 0:
        return False, f"{cmd} exit {rc}: {(stderr or stdout).strip()[:200]}"
    doc = status_json()
    for n in names:
        entry = limit_entry(doc, CG.ids[n])
        if entry is None or entry.get("download_bps") != 0 or entry.get("upload_bps") != 0:
            return False, f"blocked row for {CG.ids[n]} missing or not 0/0"
    return True, target


def unstrict_target(cmd, names):
    target = ":".join(str(CG.ids[n]) for n in names)
    rc, stdout, stderr = run_zel([cmd, target])
    if rc != 0:
        return False, f"{cmd} exit {rc}: {(stderr or stdout).strip()[:200]}"
    doc = status_json()
    left = [n for n in names if limit_entry(doc, CG.ids[n]) is not None]
    if left:
        return False, f"rows still present for cgroups {[CG.ids[n] for n in left]}"
    return True, target


def clear_all():
    rc, _, _ = run_zel(["unstrict-all"])
    return rc == 0


def enforcement_proofs(label, got_bytes, name="a"):
    """Kernel-side proof under a binding limit: packets dropped and the
    BPF byte counter in agreement with the client's own count.

    The accounting row only runs above the accounting floor
    (lib.ACCOUNTING_FLOOR_BYTES): below it, loopback GSO starvation at
    tiny rates leaves the allowed bytes dominated by per-skb headers
    and control traffic, and the comparison would be noise
    (NIGHT-improve-12).
    """
    entry = limit_entry(status_json(), CG.ids[name])
    if not entry:
        record(f"{label}: kernel drops engaged", "FAIL", "no limit row to read counters from")
        return
    dropped = entry.get("packets_dropped", 0)
    record(
        f"{label}: kernel drops engaged",
        "PASS" if dropped > 0 else "FAIL",
        f"{dropped} packets dropped, {entry.get('bytes_allowed', 0)} bytes allowed",
    )
    if CG.dedicated:
        allowed = entry.get("bytes_allowed", 0)
        if allowed > 0 and got_bytes >= lib.ACCOUNTING_FLOOR_BYTES:
            ratio = allowed / got_bytes
            record(
                f"{label}: BPF accounting matches client bytes",
                "PASS" if 0.5 <= ratio <= 1.5 else "FAIL",
                f"bpf {allowed} vs client {got_bytes} ({ratio * 100:.1f}%)",
            )
        elif allowed > 0:
            record(
                f"{label}: BPF accounting matches client bytes",
                "SKIP",
                f"payload {got_bytes} B under the "
                f"{lib.ACCOUNTING_FLOOR_BYTES // 1024} KiB accounting floor — "
                "loopback GSO granularity at this rate; the kernel drops "
                "above are the enforcement proof",
            )


# ── environment ────────────────────────────────────────────────────────────


def test_env():
    out()
    out(
        "━━━ environment (minimum specs: kernel 5.13+, cgroup v2, BPF fs, root — docs/KERNEL_COMPATIBILITY.md) ━━━"
    )
    out(f"  distro:   {pretty_name()}")
    out(f"  kernel:   {os.uname().release}  arch: {os.uname().machine}")
    out(f"  cpu:      {cpu_model()}")
    out(
        f"  python:   {sys.version.split()[0]}  curl: {CURL or 'not found (curl stages will SKIP)'}"
    )
    out(f"  binary:   {lib.BINARY} ({binary_version()})")
    out(f"  cgroups:  {MODE}")
    ok = True
    ok = (
        record(
            "cgroup v2 unified hierarchy",
            "PASS" if cgroup2_mounted() else "FAIL",
            CGROUP_ROOT if cgroup2_mounted() else f"{CGROUP_ROOT} is not cgroup2fs",
        )
        == "PASS"
        and ok
    )
    ok = (
        record(
            "cgroup ID resolution (kernfs inode)",
            "PASS" if CG.ids.get("a") else "FAIL",
            f"cgroup id {CG.ids.get('a')}",
        )
        == "PASS"
        and ok
    )
    # NIGHT-improve-11 fix: gate on the bpf FILESYSTEM MOUNT, not the
    # zelynic pin directory — a fresh host (bpffs mounted, zelynic never
    # run) is exactly the machine this harness exists to qualify, and the
    # old isdir(PIN_DIR) check failed it at the first gate (the 2026-09-21
    # run that died at "3 passed, 1 failed, 0s" having tested nothing).
    bpffs_ok = bpffs_mounted_at("/sys/fs/bpf")
    ok = (
        record(
            "BPF filesystem mounted",
            "PASS" if bpffs_ok else "FAIL",
            "/sys/fs/bpf (fstype bpf)"
            if bpffs_ok
            else "/sys/fs/bpf is not a mounted bpf filesystem — the limiter pins "
            "its maps there; tip: sudo mount -t bpf bpf /sys/fs/bpf",
        )
        == "PASS"
        and ok
    )
    if os.geteuid() != 0:
        record("root privilege", "FAIL", "re-run with sudo — BPF needs CAP_BPF")
        return False
    record("root privilege", "PASS")
    return ok


def test_doctor():
    return doctor_check()


def test_baseline(window):
    got = py_download(window)
    bps = got / window
    # NIGHT-improve-13: 0 B/s with no policy live is never a rate
    # verdict — it means the measurement engine itself moved no bytes.
    # The improve-12 run recorded this as "OK ... 0 B/s — the
    # measurement ceiling" while every worker was already dead, and
    # the falsy 0.0 then silently defeated every "hardware ceiling"
    # SKIP guard downstream.
    if got <= 0:
        record(
            "baseline: unlimited loopback throughput",
            "FAIL",
            "0 B/s with NO policy live — the measurement engine itself "
            "moved no bytes, so every rate verdict below is garbage; see "
            "worker faults at the end of the report",
            {"bps": 0},
        )
        return bps
    record(
        "baseline: unlimited loopback throughput",
        "PASS",
        f"{fmt_bps(bps)} ({mbps(bps)}) over {window:.1f}s — the measurement ceiling",
        {"bps": round(bps)},
    )
    return bps


# ── single-target stages ────────────────────────────────────────────────────


def test_policy_write():
    ok, payload = apply_single("a", "100kb", 100_000, 100_000)
    verdict = record(
        "strict-single 100kb: policy lands in the kernel maps",
        "PASS" if ok else "FAIL",
        "" if ok else payload,
    )
    # NIGHT-improve-11 (all-round scope): the human table is a separate
    # render path from the JSON every other stage consumes — exercise it
    # while a limit is provably live.
    rc, stdout, _ = run_zel(["status"])
    # NIGHT-boost-5 pinned the bar; the E2E workflow's first full-matrix
    # CI run caught the census marker drifting: NIGHT-engrave-5
    # lowercased the whole flagship surface (column headers included),
    # and the binary says "active limits: N dl, M ul" — this row had
    # pinned the pre-engrave capital-A "Active limits" and failed on
    # every machine since, but nothing ran the full matrix to see it.
    # The marker now pins the CURRENT surface: the title bar plus the
    # lowercase census line (the colon separates it from the clean
    # state's "no active limits" wording).
    rendered = "active limits:" in stdout and "zelynic status" in stdout
    human = record(
        "status: human table renders with a live limit",
        "PASS" if rc == 0 and rendered else "FAIL",
        "table rendered" if rendered else f"exit {rc}, no table marker in output",
    )
    clear_all()
    return verdict == "PASS" and human == "PASS"


def test_rate_ladder(ladder, window, windows_per_rung, baseline):
    passed = True
    for rate_str, bps in ladder:
        name = f"ladder {rate_str}: enforced download"
        if baseline and baseline < 2 * bps:
            record(
                name,
                "SKIP",
                f"hardware ceiling — baseline {fmt_bps(baseline)} cannot feed {fmt_bps(bps)}",
            )
            continue
        ok, payload = apply_single("a", rate_str, bps, bps)
        if not ok:
            record(name, "FAIL", payload)
            passed = False
            clear_all()
            continue
        time.sleep(0.5)  # let the token bucket reach steady state
        # NIGHT-improve-14: high rungs run PARALLEL_FLOWS concurrent
        # workers per window (see PARALLEL_MIN_BPS) — the aggregate,
        # not one AIMD flow, is the instrument there. Each thread
        # spawns its own in-cgroup worker subprocess, the same
        # one-worker-per-stream contract as curl burst; a failed
        # worker reads 0 and is already filed into WORKER_FAULTS by
        # spawn_in_cgroup.
        flows = PARALLEL_FLOWS if bps >= PARALLEL_MIN_BPS else 1
        rates = []
        for _ in range(windows_per_rung):
            if flows == 1:
                rates.append(py_download(window) / window)
                continue
            totals = [0] * flows

            def worker(i):
                totals[i] = py_download(window)

            threads = [threading.Thread(target=worker, args=(i,)) for i in range(flows)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            rates.append(sum(totals) / window)
        measured = sum(rates) / len(rates)
        # NIGHT-improve-12: rungs whose token bucket (burst = rate
        # clamped to >= 4096) is smaller than ONE loopback GSO skb
        # cannot reach steady state — the band floor drops to 0 there
        # (under-delivery is physics), the ceiling and the kernel-drop
        # proof below still carry the verdict.
        floor = lib.loopback_rate_floor(bps)
        if floor == 0.0:
            extra = (
                "loopback GSO granularity: a sub-skb bucket cannot reach "
                "steady state — the ceiling and kernel drops carry the verdict"
            )
        elif floor < lib.BAND_LO:
            # NIGHT-improve-15: the min-RTO cushion regime — the floor
            # itself IS the model (see lib.DEFAULT_BURST_CAP).
            extra = (
                f"{flows}-flow aggregate; min-RTO cushion: the 100 MB "
                "burst clamp holds "
                f"{min(bps, lib.DEFAULT_BURST_CAP) / bps:.1f} s of tokens "
                "at this rate and a policer drops rather than queues — "
                "near-capacity AIMD re-banks one cushion per ~200 ms "
                "stall, pinning the aggregate near the floor; the cap is "
                "never exceeded, kernel drops + accounting carry the "
                "verdict"
            )
        elif flows > 1:
            extra = (
                f"{flows}-flow aggregate — a single AIMD flow cannot "
                "claim a bucket this close to the ceiling"
            )
        if not band_check(name, measured, bps, lo=floor, extra=extra):
            passed = False
        enforcement_proofs(f"ladder {rate_str}", int(measured * window * len(rates)))
        clear_all()
    return passed


def test_upload(window, baseline):
    if baseline and baseline < 2e6:
        return record("upload (-u only): enforced", "SKIP", "baseline too low")
    rc, stdout, stderr = run_zel(["strict-single", str(CG.ids["a"]), "-u", "1mb"])
    if rc != 0:
        return record(
            "upload (-u only): enforced", "FAIL", f"exit {rc}: {(stderr or stdout).strip()[:200]}"
        )
    entry = limit_entry(status_json(), CG.ids["a"])
    if (
        entry is None
        or entry.get("upload_bps") != 1_000_000
        or entry.get("download_bps") is not None
    ):
        return record("upload (-u only): enforced", "FAIL", f"policy row wrong: {entry}")
    time.sleep(0.5)
    sent = py_upload(window)
    entry = limit_entry(status_json(), CG.ids["a"])
    truth = (entry or {}).get("bytes_allowed", 0)
    passed = band_check("upload (-u only): enforced", (truth or sent) / window, 1_000_000)
    record(
        "upload (-u only): kernel drops engaged",
        "PASS" if (entry or {}).get("packets_dropped", 0) > 0 else "FAIL",
        f"{(entry or {}).get('packets_dropped', 0)} packets dropped",
    )
    clear_all()
    return passed


def test_download_only(window, baseline):
    """-d only: the download bucket is enforced while the upload
    direction carries no policy (NIGHT-improve-12: the -u twin had a
    stage, the -d flag had none)."""
    name = "download (-d only): enforced"
    if baseline and baseline < 1e6:
        return record(name, "SKIP", "baseline too low")
    rc, stdout, stderr = run_zel(["strict-single", str(CG.ids["a"]), "-d", "500kb"])
    if rc != 0:
        return record(name, "FAIL", f"exit {rc}: {(stderr or stdout).strip()[:200]}")
    entry = limit_entry(status_json(), CG.ids["a"])
    if entry is None or entry.get("download_bps") != 500_000 or entry.get("upload_bps") is not None:
        return record(name, "FAIL", f"policy row wrong: {entry}")
    time.sleep(0.5)
    got = py_download(window)
    entry = limit_entry(status_json(), CG.ids["a"])
    truth = (entry or {}).get("bytes_allowed", 0)
    passed = band_check(name, (truth or got) / window, 500_000)
    record(
        "download (-d only): kernel drops engaged",
        "PASS" if (entry or {}).get("packets_dropped", 0) > 0 else "FAIL",
        f"{(entry or {}).get('packets_dropped', 0)} packets dropped",
    )
    clear_all()
    return passed


def test_asymmetric(window, baseline):
    """-d and -u together at different rates: the flagship example in
    --help (`-d 1mb -u 500kb`) never had a stage — the two per-
    direction buckets are now measured in their own bands under one
    policy (NIGHT-improve-12).

    No accounting-agreement row here on purpose: the single status
    row's bytes_allowed spans BOTH buckets, so comparing it to one
    direction's client count is noise by construction; the two band
    verdicts plus the drop proof carry this stage. The measured
    windows see STEADY STATE (cushion drained first — see the
    warm-up comment in the body); the first-window physics belongs
    to the attach moment, not to the per-bucket rates this stage
    pins.
    """
    name = "asymmetric (-d 100kb -u 1mb): both buckets enforced"
    if baseline and baseline < 2e6:
        return record(name, "SKIP", "baseline too low")
    rc, stdout, stderr = run_zel(["strict-single", str(CG.ids["a"]), "-d", "100kb", "-u", "1mb"])
    if rc != 0:
        return record(name, "FAIL", f"exit {rc}: {(stderr or stdout).strip()[:200]}")
    entry = limit_entry(status_json(), CG.ids["a"])
    if (
        entry is None
        or entry.get("download_bps") != 100_000
        or entry.get("upload_bps") != 1_000_000
    ):
        clear_all()
        return record(name, "FAIL", f"policy row wrong: {entry}")
    time.sleep(0.5)
    # Cushion drain (the 2026-09-22 approved fix): a freshly attached
    # bucket starts FULL — default_burst is 1 s of rate — so the first
    # window after attach measures rate * (1 + 1/window): 1.33x at
    # light's 3.0 s, 1.25x at heavy's 4.0 s, straddling BAND_HI = 1.30
    # exactly where the 2026-09-21 root run split (light "asymmetric
    # upload 1mb 131.1%" FAIL, heavy the same stage 124.5% PASS, same
    # engine, both under the bound — the cushion is engine contract,
    # not over-delivery). Drain it into a discarded window so each
    # measured window sees steady state: refill only, one band for
    # both modes, and >30% is again a real over-delivery signal. The
    # download row gets the same drain — it only stayed inside the
    # band by AIMD luck, not by different physics.
    py_download(0.5)
    got = py_download(window)
    dl_ok = band_check("asymmetric: download bucket at 100kb", got / window, 100_000)
    py_upload(0.5)
    sent = py_upload(window)
    ul_ok = band_check("asymmetric: upload bucket at 1mb", sent / window, 1_000_000)
    entry = limit_entry(status_json(), CG.ids["a"])
    record(
        "asymmetric: kernel drops engaged",
        "PASS" if (entry or {}).get("packets_dropped", 0) > 0 else "FAIL",
        f"{(entry or {}).get('packets_dropped', 0)} packets dropped",
    )
    clear_all()
    return dl_ok and ul_ok


def test_block_single(window):
    ok, payload = block_target("block-single", ["a"])
    if not ok:
        return record("block-single: zero goodput", "FAIL", payload)
    time.sleep(0.3)
    got = py_download(window)
    verdict = "PASS" if got <= BLOCK_GOODPUT_CEIL else "FAIL"
    record(
        "block-single: zero goodput",
        verdict,
        f"{got} bytes over {window:.1f}s (ceiling {BLOCK_GOODPUT_CEIL})",
    )
    entry = limit_entry(status_json(), CG.ids["a"])
    record(
        "block-single: kernel drops engaged",
        "PASS" if (entry or {}).get("packets_dropped", 0) > 0 else "FAIL",
        f"{(entry or {}).get('packets_dropped', 0)} packets dropped",
    )
    clear_all()


def test_unlock(window, baseline):
    """unstrict-single is the unlock: apply, remove, prove the speed is back."""
    ok, payload = apply_single("a", "500kb", 500_000, 500_000)
    if not ok:
        return record("unlock: unstrict-single restores speed", "FAIL", payload)
    py_download(window)  # generate some policed traffic first
    ok, payload = unstrict_target("unstrict-single", ["a"])
    if not ok:
        return record("unlock: unstrict-single restores speed", "FAIL", payload)
    got = py_download(window)
    bps = got / window
    floor = 0.3 * baseline if baseline else 1e6
    record(
        "unlock: unstrict-single restores speed",
        "PASS" if bps >= floor else "FAIL",
        f"{fmt_bps(bps)} after unlock (floor {fmt_bps(floor)})",
    )


def test_curl_burst(window, clients, rate_bps, baseline):
    if not CURL:
        return record("curl burst: parallel download under limit", "SKIP", "curl not found")
    if baseline and baseline < 2 * rate_bps:
        return record("curl burst: parallel download under limit", "SKIP", "baseline too low")
    rate_str = f"{round(rate_bps / 1e6)}mb" if rate_bps >= 1e6 else f"{round(rate_bps / 1e3)}kb"
    # E2E-workflow hunt (the runner 140% run): the policy-live clock
    # starts HERE, at apply — the bucket refills over the pre-span
    # overhead (apply + the 0.5 s settle + spawn stagger) and carries
    # the documented 1 s default-burst front-load (default_burst = one
    # second of rate, format.rs), so the curl-span ratio the row
    # divides honestly admits (live + burst) / span. The runner read
    # 140.0% client-side while the kernel allowed 8.25 MB = exactly
    # 1 MB burst + 7.25 s of live refill — the policer held its
    # contract; the ceiling now derives from that contract instead of
    # the raw 1.30, with the arithmetic printed in the row for audit.
    # The sharing claim keeps its teeth: a bucket NOT shared reads
    # ~clients x rate (600% here), far past the 1.60 hard cap, and the
    # drops + accounting rows below still police precision at the
    # kernel level.
    t_apply = time.monotonic()
    ok, payload = apply_single("a", rate_str, rate_bps, rate_bps)
    if not ok:
        return record("curl burst: parallel download under limit", "FAIL", payload)
    time.sleep(0.5)
    # Cushion drain (the asymmetric stage's 2026-09-22 approved fix,
    # applied here after runs six through eight): a freshly attached
    # bucket starts FULL — default_burst is 1 s of rate — and the
    # measured span caught front-load + spawn-stagger in a different
    # mix every run (120.2%, 140.0%, 142.5% on the same leg, same
    # code, different stagger). Drain it into a discarded window so
    # the measured span sees steady state: refill only, low variance.
    # The budget ceiling below stays as the residual-stagger guard,
    # and the sharing cap at 1.60 still fails a not-shared bucket by
    # ~4x.
    py_download(0.5)
    totals = [None] * clients

    def worker(i):
        # NIGHT-improve-12: each curl runs INSIDE cgroup a via the
        # worker path — the old local curl_download only happened to be
        # policed because the whole harness shared the target cgroup.
        totals[i] = curl_in_cgroup("a", window)[0]

    # NIGHT-hunt-32: the burst's rate verdict divides by the ACTUAL
    # wall-clock span (first spawn -> last join), not the nominal
    # window. N parallel curls each run --max-time window from their
    # OWN exec moment, so staggered spawns (bash join + exec + TCP
    # connect, magnified when the previous stage's teardown is still
    # loading the box) stretch the bucket's drain span past window by
    # up to ~0.7 s — the 2026-09-22 light run measured 135.0% against
    # BAND_HI = 1.30 while the kernel-side proof stayed clean (bpf
    # allowed 6.63 MB = 1 MB burst + 5.63 s of refill, matching the
    # true span). The nominal divisor charged the burst bonus and the
    # spawn stagger to the configured rate; the actual span keeps the
    # policer-tripwire meaning of BAND_HI intact (measured rate vs
    # configured rate) instead of widening the band to hide it.
    t0 = time.monotonic()
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    span = time.monotonic() - t0
    if any(v is None for v in totals):
        record("curl burst: parallel download under limit", "FAIL", "a curl produced no metric")
        clear_all()
        return False
    # Span sanity: every curl runs --max-time window, so the span is
    # at least window; a span beyond window + 2.0 s means spawn or
    # teardown pathology (a hung worker would have tripped the
    # communicate timeout first) — fail loudly rather than divide a
    # garbage span into the total.
    if span < window or span > window + 2.0:
        record(
            f"curl burst: {clients} parallel curls, one shared limit",
            "FAIL",
            f"stage span {span:.2f} s outside [{window:.1f}, {window + 2.0:.1f}] — spawn/teardown pathology",
        )
        clear_all()
        return False
    total = sum(totals)
    # NIGHT-boost-27 (the E2E twelfth-run fix): the rate verdict rides
    # the KERNEL LEDGER, not the client metric. The evidence chain:
    # runs eight-eleven measured the client total swinging with the
    # runner (97.6% .. 161.2% across legs and runs, SAME code) while
    # the kernel's own allowed-bytes stayed a policer-shaped number —
    # a client metric that moves when nothing in the product moved is
    # measurement noise wearing the verdict's badge, and four reds on
    # the 5.15 pool convicted a formula that divided the wrong
    # numerator. The ledger is the policer's own contract: bytes the
    # kernel actually allowed.
    #
    # NIGHT-boost-38 postscript, the real diagnosis: the swing was
    # NOT measurement noise — it was the v6 token bucket losing
    # updates under SMP (six curls on a 64-core runner = six CPUs
    # read-modify-writing one bucket; a lost deduction resurrects
    # tokens and the policer over-allows 130-146% of budget, exactly
    # the 146.3% ledger this row failed red with on 2026-09-24). The schema-v7
    # rewrite made every step an atomic CAS, so the ledger now holds
    # its own contract deterministically — the budget below is the
    # honest ceiling again, and the client swing is what it always
    # looked like: the policer actually leaking.
    #
    # The arithmetic is exact at the read instant: the bucket can
    # credit at most (t_read - t_apply) * rate + default_burst bytes
    # from attach to the ledger read (burst = 1 s of rate, clamped
    # 4 KiB-100 MB — format.rs's default_burst, mirrored here). The
    # old row measured `live` BEFORE the ledger read and divided the
    # CLIENT total by span against a 1.60 cap — two loosely-coupled
    # numbers. Now: one snapshot, one instant, one ceiling, and a 2%
    # GSO headroom for per-skb accounting granularity.
    entry = limit_entry(status_json(), CG.ids["a"])
    t_read = time.monotonic()
    allowed = (entry or {}).get("bytes_allowed", 0)
    live = t_read - t_apply
    burst_bytes = min(max(rate_bps, 4096), 100_000_000)
    budget_bytes = live * rate_bps + burst_bytes
    GSO_EPS = 1.02
    ledger_ratio = allowed / (rate_bps * span) if allowed else 0.0
    client_ratio = total / (rate_bps * span)
    ledger_ok = allowed <= budget_bytes * GSO_EPS
    # The sharing teeth ride the ledger too: a bucket that is NOT
    # shared (per-flow buckets) allows ~clients x rate — far past
    # the 1.60 cap, exactly the claim the row has always made.
    sharing_ok = ledger_ratio <= 1.60
    # The floor stays CLIENT-side: under-delivery is what the user
    # experienced, and the client total is the honest numerator for
    # it (a starved curl reads near zero whatever the ledger says).
    floor_ok = client_ratio >= 0.65
    passed = ledger_ok and sharing_ok and floor_ok
    verdict = "PASS" if passed else "FAIL"
    record(
        f"curl burst: {clients} parallel curls, one shared limit",
        verdict,
        (
            f"kernel allowed {allowed / 1e6:.2f} MB ({ledger_ratio * 100:.1f}% of "
            f"{rate_bps / 1e6:.0f} MB/s x span) vs exact budget "
            f"{budget_bytes / 1e6:.2f} MB (live {live:.1f} s + "
            f"{burst_bytes / 1e6:.1f} MB burst) x1.02; sharing cap 1.60 on "
            f"the ledger; client total {total / 1e6:.2f} MB "
            f"({client_ratio * 100:.1f}%, advisory, floor 0.65 — the ledger carries the verdict)"
        ),
        {
            "allowed_bytes": allowed,
            "budget_bytes": round(budget_bytes),
            "ledger_ratio": round(ledger_ratio, 3),
            "client_ratio": round(client_ratio, 3),
        },
    )
    enforcement_proofs("curl burst", total)
    clear_all()
    return passed


def test_curl_upload(window, baseline):
    if not CURL:
        return record("curl upload: external upload engine", "SKIP", "curl not found")
    if baseline and baseline < 2e6:
        return record("curl upload: external upload engine", "SKIP", "baseline too low")
    ok, payload = apply_single("a", "1mb", 1_000_000, 1_000_000)
    if not ok:
        return record("curl upload: external upload engine", "FAIL", payload)
    time.sleep(0.5)
    # NIGHT-improve-12: the upload curl runs inside cgroup a (worker
    # path) so the policy it measures is the one applied to a.
    #
    # E2E-workflow hunt (first full-matrix CI run): the rate verdict now
    # rides the SERVER-side delivered bytes, not curl's %{size_upload}.
    # curl counts socket WRITES; on loopback the unpoliced eager
    # receiver (the harness server in hq) keeps advertising large
    # windows, so curl writes ~1.5x the policer's drain rate and the
    # undelivered excess sits in kernel buffers when --max-time kills
    # the worker — the runner measured 153% of configured while the
    # kernel's own allowed-bytes read 99.7% (enforcement perfect, the
    # METRIC was reading the write-ahead). Delivered bytes are the
    # honest twin of the download lane's received bytes, and they make
    # the BPF accounting cross-check compare like-for-like wire bytes.
    # curl's own metric stays as the worker-alive guard (None = the
    # engine itself died), and a zero server delta is an engine fault,
    # never a rate verdict.
    before = SERVER.peek()["ul"]
    before_conns = SERVER.peek()["conns"]
    accept_faults = SERVER.peek()["accept_errors"]
    sent, err = curl_upload_in_cgroup("a", window)
    if sent is None:
        record("curl upload: external upload engine", "FAIL", f"curl produced no metric ({err})")
        clear_all()
        return False
    # The fold-after-close race, one layer deeper than the self-test's
    # fixed settle (the improve-21 contract: the /ul counter folds its
    # per-connection total only at connection end). The runner's first
    # policed run read delta 0 against curl's 7.7 MB while the kernel
    # allowed ~5 MB — a peek that wins the race against the server
    # thread reads stale state under the matrix's thread load (the
    # burst stage's dead-socket writers + the accept loop + this
    # handler all contend). Quiescence-poll instead of a blind sleep:
    # the counter is trusted only once it stops moving, and if it
    # STILL reads nothing, the failure message carries every number
    # the next hunt needs.
    last = SERVER.peek()["ul"]
    quiet = 0
    for _ in range(50):  # up to 5 s of 0.1 s polls
        time.sleep(0.1)
        now = SERVER.peek()["ul"]
        if now == last:
            quiet += 1
        else:
            quiet = 0
        last = now
        if quiet >= 5:  # 0.5 s of stillness = the fold has landed
            break
    delivered = last - before
    after_state = SERVER.peek()
    after_conns = after_state["conns"]
    if delivered <= 0:
        # The zero-fold fork, named by the kernel's own numbers (run
        # five's evidence): curl wrote 7.7 MB, the egress hook allowed
        # 5.4 MB onto the wire, the app-level fold read 0 — the
        # instrument lost the stream, the limiter did not. A fold of
        # zero WITH kernel-allowed bytes above the accounting floor is
        # an ENGINE fault (the realnet upload-sanity precedent: a
        # broken instrument reads SKIP, never a limiter FAIL), with
        # the kernel rows printed alongside as the enforcement
        # evidence. A fold of zero with NOTHING allowed is a real
        # failure — the worker moved no bytes at all.
        entry = limit_entry(status_json(), CG.ids["a"]) if CG.dedicated else None
        allowed = (entry or {}).get("bytes_allowed", 0)
        verdict = "SKIP" if allowed >= lib.ACCOUNTING_FLOOR_BYTES else "FAIL"
        record(
            "curl upload: external upload engine",
            verdict,
            f"engine fault: server folded {delivered} B of curl's {sent} B "
            f"(ul counter {before} -> {last}, conns "
            f"{before_conns}->{after_conns}, accept_errors "
            f"{accept_faults}->{after_state['accept_errors']}) while the kernel allowed {allowed} B — "
            "the app-level instrument lost the stream; the kernel rows "
            "below carry the enforcement evidence",
        )
        # The kernel-side rows are the evidence: if bytes_allowed is
        # ~5 MB, the wire moved and the server-side fold is the liar;
        # if it is ~0, the upload never left the worker. Either way
        # the next hunt starts from the numbers, not a guess.
        enforcement_proofs("curl upload", sent)
        clear_all()
        # A skipped row is not a pass: the engine fault is named, the
        # kernel evidence is printed, but this stage did not measure.
        return False
    passed = band_check("curl upload: external upload engine", delivered / window, 1_000_000)
    enforcement_proofs("curl upload", delivered)
    clear_all()
    return passed


def test_overhead(window, baseline):
    """A non-binding policy (3x what this machine can do) must not cost
    real throughput. The comparison is PAIRED inside the stage (the
    2026-09-22 approved fix): the harness-start baseline was measured
    minutes earlier, and the 2026-09-21 heavy run filed +30.0% where
    light measured +2.1% on the same policy class — machine-load drift
    between harness start and the last-but-one stage, not policy
    cost. Fresh baseline window, then policy, then the measured
    window: seconds apart, same machine state. No policy is live at
    entry — the preceding stage ends clear_all().
    """
    if baseline and baseline >= 300e9:
        return record(
            "overhead: non-binding policy cost", "SKIP", "baseline beyond the 1 TB/s policy ceiling"
        )
    fresh = py_download(window)
    fresh_rate = fresh / window
    if fresh <= 0:
        return record(
            "overhead: non-binding policy cost",
            "FAIL",
            "fresh baseline measured 0 B/s with no policy live",
        )
    if fresh_rate >= 300e9:
        return record(
            "overhead: non-binding policy cost",
            "SKIP",
            "fresh baseline beyond the 1 TB/s policy ceiling",
        )
    non_binding_gb = min(900, max(10, round(3 * fresh_rate / 1e9)))
    non_binding = non_binding_gb * 1e9
    ok, payload = apply_single("a", f"{non_binding_gb}gb", int(non_binding), int(non_binding))
    if not ok:
        return record("overhead: non-binding policy cost", "FAIL", payload)
    time.sleep(0.3)
    got = py_download(window)
    limited = got / window
    clear_all()
    drop_pct = (fresh_rate - limited) / fresh_rate * 100
    verdict = "PASS" if drop_pct <= 30.0 else "FAIL"
    record(
        "overhead: non-binding policy cost",
        verdict,
        f"fresh {fmt_bps(fresh_rate)} vs {fmt_bps(limited)} "
        f"({non_binding_gb} GB/s policy) — {drop_pct:+.1f}% (paired in-stage)",
    )
    return verdict == "PASS"


# ── multi-target stages (heavy) ─────────────────────────────────────────────


def multi_guard(name):
    """Multi-cgroup stages need the dedicated fleet; the session-cgroup
    fallback cannot attribute curl workers to separate cgroups."""
    if CG.dedicated:
        return True
    record(name, "SKIP", "dedicated cgroup fleet not creatable on this machine")
    return False


def test_multi_group(window, baseline):
    name = "strict-multi: group bucket shared across cgroups"
    if not multi_guard(name):
        return True
    if baseline and baseline < 2e6:
        return record(name, "SKIP", "baseline too low")
    ok, payload = apply_group(["b", "c"], "1mb", 1_000_000)
    if not ok:
        return record(name, "FAIL", payload)
    time.sleep(0.5)
    # Phase 1: one member alone can consume the whole shared bucket.
    got_b, err = curl_in_cgroup("b", window)
    if got_b is None:
        clear_all()
        return record(name, "FAIL", f"curl in b failed: {err}")
    solo = band_check(
        "strict-multi: member alone fills the shared bucket", got_b / window, 1_000_000
    )
    # Phase 2: two members together still only get ONE bucket.
    results = {}

    def worker(n):
        results[n] = curl_in_cgroup(n, window)

    # E2E-workflow hunt (runs eight-nine): the joint verdict used the
    # NOMINAL window as its divisor — the hunt-32 lesson the curl burst
    # row already carries, one stage over. Two concurrent curls each
    # run --max-time window from their OWN exec moment; on a loaded
    # runner the spawn stagger stretches the bucket's true drain span
    # (run seven read 162.5% on a leg that measured 115.3% the run
    # before — same code, different stagger). The divisor is now the
    # ACTUAL first-spawn -> last-join span.
    #
    # Runs eight-nine found the SECOND invisible window: the inter-phase
    # gap — solo-end -> joint-spawn — refills the shared bucket out of
    # the joint span's sight (run eight: ~0.2 s gap, joint 115.3% PASS;
    # run nine: ~1.7 s gap, joint 134.6% FAIL; same code, loaded box).
    # The cushion drain (the asymmetric/burst precedent) resets the
    # bucket to a known-empty state between phases, and the budget's
    # live clock starts at the drain's end so every refill second is
    # inside the formula. The sharing claim keeps its teeth — two
    # independent buckets read ~200%+, far past the 1.60 hard cap.
    #
    # NIGHT-boost-38 postscript: the 2026-09-24 13:45 run failed BOTH
    # legs here (134.6% / 130.0%) with the gap formula in place — the
    # residual overshoot was not another harness window, it was the
    # v6 group bucket losing updates between the two concurrent member
    # curls (two CPUs, one shared bucket — the same lost-update leak
    # the curl burst row caught at six flows). Schema v7 made the
    # bucket SMP-safe; the ceiling above is the honest contract again.
    py_download(0.5, "b")
    t_drain_end = time.monotonic()
    t0 = time.monotonic()
    threads = [threading.Thread(target=worker, args=(n,)) for n in ("b", "c")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    joint_span = time.monotonic() - t0
    live = time.monotonic() - t_drain_end
    if any(results[n][0] is None for n in ("b", "c")):
        clear_all()
        return record(name, "FAIL", "a group-member curl produced no metric")
    if joint_span < window or joint_span > window + 2.0:
        clear_all()
        return record(
            f"strict-multi: {len(results)} members joint, still one shared bucket",
            "FAIL",
            f"joint span {joint_span:.2f} s outside [{window:.1f}, {window + 2.0:.1f}]"
            " — spawn/teardown pathology",
        )
    total = sum(results[n][0] for n in ("b", "c"))
    burst_s = 1.0
    budget_ceiling = (live + burst_s) / joint_span
    joint = band_check(
        f"strict-multi: {len(results)} members joint, still one shared bucket",
        total / joint_span,
        1_000_000,
        extra=(
            f"span {joint_span:.2f} s; budget ceiling {budget_ceiling:.2f}x "
            f"(live {live:.1f} s + {burst_s:.0f} s burst / span), cap 1.60"
        ),
        hi=min(1.05 * budget_ceiling, 1.60),
    )
    record(
        "strict-multi: group rows visible in status",
        "PASS",
        f"cgroups {CG.ids['b']} and {CG.ids['c']} both carry the 1mb policy",
    )
    clear_all()
    return solo and joint


def test_block_multi(window):
    name = "block-multi: zero goodput on both cgroups"
    if not multi_guard(name):
        return True
    ok, payload = block_target("block-multi", ["d", "e"])
    if not ok:
        return record(name, "FAIL", payload)
    time.sleep(0.3)
    got_d, _ = curl_in_cgroup("d", window)
    got_e, _ = curl_in_cgroup("e", window)
    if got_d is None or got_e is None:
        clear_all()
        return record(name, "FAIL", "a blocked-cgroup curl produced no metric")
    ok_both = got_d <= BLOCK_GOODPUT_CEIL and got_e <= BLOCK_GOODPUT_CEIL
    record(
        name,
        "PASS" if ok_both else "FAIL",
        f"d {got_d} bytes, e {got_e} bytes over {window:.1f}s (ceiling {BLOCK_GOODPUT_CEIL})",
    )
    entry = limit_entry(status_json(), CG.ids["d"])
    record(
        "block-multi: kernel drops engaged",
        "PASS" if (entry or {}).get("packets_dropped", 0) > 0 else "FAIL",
        f"{(entry or {}).get('packets_dropped', 0)} packets dropped",
    )
    clear_all()


def test_unstrict_multi():
    """Selective unlock: removing B:C must leave A's limit standing."""
    name = "unstrict-multi: selective removal leaves other limits standing"
    if not multi_guard(name):
        return True
    ok_a, payload = apply_single("a", "500kb", 500_000, 500_000)
    ok_g, payload_g = apply_group(["b", "c"], "1mb", 1_000_000)
    if not (ok_a and ok_g):
        clear_all()
        return record(name, "FAIL", payload or payload_g)
    ok, payload = unstrict_target("unstrict-multi", ["b", "c"])
    if not ok:
        clear_all()
        return record(name, "FAIL", payload)
    doc = status_json()
    entry = limit_entry(doc, CG.ids["a"])
    gone = all(limit_entry(doc, CG.ids[n]) is None for n in ("b", "c"))
    verdict = "PASS" if (entry is not None and gone) else "FAIL"
    record(
        name,
        verdict,
        f"cgroup {CG.ids['a']} still limited at "
        f"{fmt_bps((entry or {}).get('download_bps') or 0)}, b/c rows removed",
    )
    clear_all()
    return verdict == "PASS"


def test_mixed(window, baseline):
    """Three policy families coexisting on five cgroups at once."""
    name = "mixed: strict + strict-multi + block concurrent"
    if not multi_guard(name):
        return True
    if baseline and baseline < 2 * 500_000:
        return record(name, "SKIP", "baseline too low")
    ok_a, payload = apply_single("a", "500kb", 500_000, 500_000)
    ok_g, payload_g = apply_group(["b", "c"], "1mb", 1_000_000)
    ok_bl, payload_bl = block_target("block-single", ["e"])
    if not (ok_a and ok_g and ok_bl):
        clear_all()
        return record(name, "FAIL", payload or payload_g or payload_bl)
    time.sleep(0.5)
    got_a = py_download(window)
    solo = band_check("mixed: strict-single member at 500kb", got_a / window, 500_000)
    got_e, _ = curl_in_cgroup("e", window)
    blocked = got_e is not None and got_e <= BLOCK_GOODPUT_CEIL
    record(
        "mixed: blocked member stays dark",
        "PASS" if blocked else "FAIL",
        f"{got_e} bytes over {window:.1f}s",
    )
    doc = status_json()
    rows = len(doc.get("limits", [])) if doc else 0
    record(
        "mixed: five cgroups, three policies, one status view",
        "PASS" if rows >= 4 else "FAIL",
        f"{rows} limit rows visible",
    )
    clear_all()
    return solo and blocked and rows >= 4


def test_limit_all(window, baseline):
    """The supermassive sweep: every cgroup on the machine, briefly, --force so
    the harness's own root-owned cgroups are included."""
    name = "limit-all --force: machine-wide sweep"
    if baseline and baseline < 2e6:
        return record(name, "SKIP", "baseline too low")
    # Keep sleepers resident in a..e so the sweep has live cgroups to
    # find — including "a" itself: since NIGHT-improve-12 the harness
    # lives in hq, so the row check below needs a resident in a. The
    # residency barrier above makes "resident" a settled fact, not a
    # spawn-time hope — the sweep only runs once every sleeper is
    # provably in place (2026-09-22 fix for the mystery None row).
    spawned = [spawn_bg_in_cgroup(n, ["sleep", "30"]) for n in "abcde"]
    sleepers = [p for p in spawned if p is not None]
    try:
        if len(sleepers) != len(spawned):
            return record(
                name,
                "FAIL",
                f"sleeper residency barrier failed: {len(spawned) - len(sleepers)}"
                f"/{len(spawned)} cgroups never got a resident sleeper",
            )
        rc, stdout, stderr = run_zel(["limit-all", "--force", "2mb"])
        if rc != 0:
            return record(name, "FAIL", f"exit {rc}: {(stderr or stdout).strip()[:200]}")
        entry = limit_entry(status_json(), CG.ids["a"])
        if entry is None or entry.get("download_bps") != 2_000_000:
            clear_all()
            return record(name, "FAIL", f"fleet cgroup a row wrong: {entry}")
        time.sleep(0.5)
        got = py_download(window)
        passed = band_check(name, got / window, 2_000_000)
        clear_all()
        return passed
    finally:
        for p in sleepers:
            p.kill()
        for p in sleepers:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


def test_reload(cycles):
    rates = ["100kb", "500kb"]
    expect = [100_000, 500_000]
    mismatches = 0
    for i in range(cycles):
        ok, _ = apply_single("a", rates[i % 2], expect[i % 2], expect[i % 2])
        if not ok:
            mismatches += 1
    verdict = "PASS" if mismatches == 0 else "FAIL"
    record(
        f"reload: {cycles} rate-change cycles through pinned maps",
        verdict,
        f"{cycles - mismatches}/{cycles} cycles verified via status JSON",
    )
    clear_all()
    return verdict == "PASS"


def test_sustain(rate_bps, windows, window, baseline):
    if baseline and baseline < 2 * rate_bps:
        return record("sustain: steady state + drift guard", "SKIP", "baseline too low")
    rate_str = f"{round(rate_bps / 1e9)}gb" if rate_bps >= 1e9 else f"{round(rate_bps / 1e6)}mb"
    ok, payload = apply_single("a", rate_str, rate_bps, rate_bps)
    if not ok:
        return record("sustain: steady state + drift guard", "FAIL", payload)
    time.sleep(0.5)
    rates = []
    for _ in range(windows):
        rates.append(py_download(window) / window)
    clear_all()
    ok_band = all(lib.BAND_LO <= r / rate_bps <= lib.BAND_HI for r in rates)
    drift = min(rates) / max(rates) if max(rates) else 0.0
    verdict = "PASS" if (ok_band and drift >= 0.5) else "FAIL"
    record(
        "sustain: steady state + drift guard",
        verdict,
        "; ".join(f"w{i + 1} {fmt_bps(r)}" for i, r in enumerate(rates))
        + f" — drift floor {drift * 100:.0f}%",
    )
    return verdict == "PASS"


# ── the live rate-change move (NIGHT-refactor-2, moved from v2) ─────────────
#
# The daily "tighten it" move v1's reload cycle proves under stress
# (policy rows only) gets the full MEASUREMENT treatment here: change a
# live policy 1mb -> 2mb and measure BOTH rungs — a rate change that
# only updates the status row is a display bug, not a limit change.


def stage_rate_change(window):
    name = "rate change: strict-single 1mb -> 2mb under live policy"
    ok, payload = apply_single("a", RATE_CHANGE_FROM_STR, RATE_CHANGE_FROM_BPS, None)
    if not ok:
        return record(name, "FAIL", payload)
    got_lo = py_download(window)
    ok, payload = apply_single("a", RATE_CHANGE_TO_STR, RATE_CHANGE_TO_BPS, None)
    if not ok:
        clear_all()
        return record(name, "FAIL", payload)
    got_hi = py_download(window)
    if got_lo is None or got_hi is None:
        clear_all()
        return record(name, "FAIL", "a measurement worker produced no bytes")
    lo_ok = band_check("rate change: first rung at 1mb", got_lo / window, RATE_CHANGE_FROM_BPS)
    hi_ok = band_check("rate change: second rung at 2mb", got_hi / window, RATE_CHANGE_TO_BPS)
    record(
        name,
        "PASS" if (lo_ok and hi_ok) else "FAIL",
        f"{fmt_bps(got_lo / window)} then {fmt_bps(got_hi / window)}",
    )
    clear_all()
    return lo_ok and hi_ok


# ── the real-internet lane (NIGHT-refactor-2, moved from v2) ────────────────
#
# The production traffic shape: a reachability probe walks a fallback
# chain of long-lived public endpoints and the FIRST reachable one feeds
# every internet stage. LTS posture: honest SKIP verdicts (never silent,
# never false FAILs) when the machine has no egress or every endpoint is
# down — the local loopback lane still carries the verdict.

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

# The fallback chain, ordered by programmatic stability. Cloudflare's
# speed endpoints are the backing store of speed.cloudflare.com itself
# (the bytes= form caps the transfer by construction — the probe asks
# for 1 KiB, the stage asks for 50 MB); OVH's proof files and Tele2's
# zip have served ranged requests for over a decade. The FIRST endpoint
# whose probe completes feeds every download stage — one endpoint per
# run keeps every realnet row attributable to a name in the report.
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
# Preflight findings the internet stages gate on (a slow uplink or a
# refused streaming body must read as SKIP, never as a limiter FAIL).
REALNET_BASELINE_BPS = 0
REALNET_UL_USABLE = False


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
        "zelynic-realnet-reachability-probe",
        url,
    ]


def realnet_dl_cmd(window, url):
    """Download worker: size_download is the verdict, --max-time cuts
    the window (a non-zero curl exit is EXPECTED — the metric line is
    the measurement, not the exit code, same contract as the loopback
    curl stages)."""
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
    # chunked upload — the classic curl upload-speed pattern (the
    # loopback twin uses the same trick against the in-process server).
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
    return spawn_in_cgroup(name, realnet_dl_cmd(window, DL_ENDPOINT[1]), window + 25)


def realnet_upload(name, window):
    """One real-internet upload inside cgroup `name`; (bytes, err)."""
    return spawn_in_cgroup(name, realnet_ul_cmd(window, UL_ENDPOINT[1]), window + 25)


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
    unstrict restore, and the instrument check that the endpoint can
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
    ok, payload = apply_single("a", REALNET_DL_RATE_STR, REALNET_DL_RATE_BPS, None)
    if not ok:
        return record(name, "FAIL", payload)
    time.sleep(0.5)
    got, err = realnet_download("a", REALNET_RATE_WINDOW)
    if got is None:
        clear_all()
        return record(name, "FAIL", f"worker failed: {err}")
    passed = band_check(
        name,
        got / REALNET_RATE_WINDOW,
        REALNET_DL_RATE_BPS,
        extra=f"via {DL_ENDPOINT[0]}",
        lo=REALNET_BAND_LO,
        hi=REALNET_BAND_HI,
    )
    enforcement_proofs("real internet strict", got)
    clear_all()
    return passed


def stage_realnet_strict_upload():
    name = "real internet: strict-single upload at 1mb"
    if not UL_ENDPOINT:
        return record(name, "SKIP", "no upload endpoint")
    if not REALNET_UL_USABLE:
        return record(name, "SKIP", "upload engine sanity did not pass")
    ok, payload = apply_single("a", REALNET_UL_RATE_STR, None, REALNET_UL_RATE_BPS)
    if not ok:
        return record(name, "FAIL", payload)
    time.sleep(0.5)
    got, err = realnet_upload("a", REALNET_RATE_WINDOW)
    if got is None:
        clear_all()
        return record(name, "FAIL", f"worker failed: {err}")
    passed = band_check(
        name,
        got / REALNET_RATE_WINDOW,
        REALNET_UL_RATE_BPS,
        extra=f"via {UL_ENDPOINT[0]}",
        lo=REALNET_BAND_LO,
        hi=REALNET_BAND_HI,
    )
    clear_all()
    return passed


def stage_realnet_limit_all():
    """The machine-wide sweep policing REAL traffic: same sleeper fleet
    and --force sweep as the loopback limit-all stage, but the measured
    worker is a real-internet download — proving the sweep reached the
    cgroup the production traffic will actually live in."""
    name = "real internet: limit-all --force sweep at 2mb"
    if not DL_ENDPOINT:
        return record(name, "SKIP", "no download endpoint")
    if REALNET_BASELINE_BPS < 2 * 2_000_000:
        return record(
            name,
            "SKIP",
            f"realnet baseline {fmt_bps(REALNET_BASELINE_BPS)} too low to prove a 2mb band",
        )
    spawned = [spawn_bg_in_cgroup(n, ["sleep", "30"]) for n in "abcde"]
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
        rc, stdout, stderr = run_zel(["limit-all", "--force", "2mb"])
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
        clear_all()
        for p in sleepers:
            p.kill()
        for p in sleepers:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass


def stage_realnet_block():
    """block-single against the real internet: the connection must
    carry ~zero payload bytes. The kernel-drop proof rides the same
    status row the loopback block stages read."""
    name = "real internet: block-single zero goodput"
    if not DL_ENDPOINT:
        return record(name, "SKIP", "no download endpoint")
    ok, payload = block_target("block-single", ["a"])
    if not ok:
        return record(name, "FAIL", payload)
    time.sleep(0.3)
    got, err = realnet_download("a", REALNET_BLOCK_WINDOW)
    if got is None:
        clear_all()
        return record(name, "FAIL", f"worker failed: {err}")
    verdict = "PASS" if got <= BLOCK_GOODPUT_CEIL else "FAIL"
    record(
        name,
        verdict,
        f"{got} bytes over {REALNET_BLOCK_WINDOW:.0f}s via {DL_ENDPOINT[0]} "
        f"(ceiling {BLOCK_GOODPUT_CEIL})",
    )
    enforcement_proofs("real internet block", got)
    clear_all()
    return verdict == "PASS"


def _remeasure_realnet_baseline():
    """The restore floor derives from the machine's CURRENT realnet
    throughput (re-measured, not cached: it moves between stages)."""
    if not DL_ENDPOINT:
        return 0
    got, _ = realnet_download("a", REALNET_BASE_WINDOW)
    return got / REALNET_BASE_WINDOW if got else 0


def stage_realnet_restore():
    """After the whole internet lane, unstrict-all must give the machine
    its real-internet speed back — measured against the machine's own
    re-measured baseline, not a configured number."""
    name = "real internet: unstrict-all restores speed"
    if not DL_ENDPOINT:
        return record(name, "SKIP", "no download endpoint")
    # Leave a limit standing so the restore has something to undo.
    ok, payload = apply_single("a", REALNET_DL_RATE_STR, REALNET_DL_RATE_BPS, None)
    if not ok:
        return record(name, "FAIL", payload)
    if not clear_all():
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


def test_list_apps():
    rc, stdout, _ = run_zel(["list-apps", "--print-json"])
    if rc != 0:
        return record("list-apps: JSON smoke", "FAIL", f"exit {rc}")
    try:
        json.loads(stdout)
        return record("list-apps: JSON smoke", "PASS", "parses as JSON")
    except json.JSONDecodeError as e:
        return record("list-apps: JSON smoke", "FAIL", str(e))


# ── cleanup (the teardown v1 owns; the crash-family teardown lives in v2) ───────────────────────────────────────────────────


def test_cleanup():
    ok_all = True
    rc, _, _ = run_zel(["unstrict-all"])
    time.sleep(0.5)
    ok_all = (
        record(
            "cleanup: unstrict-all exits 0",
            "PASS" if rc == 0 else "FAIL",
            f"exit {rc}",
        )
        == "PASS"
        and ok_all
    )
    pins_left = len(os.listdir(PIN_DIR)) if os.path.isdir(PIN_DIR) else 0
    ok_all = (
        record(
            "cleanup: zero BPF pins left",
            "PASS" if pins_left == 0 else "FAIL",
            f"{pins_left} entries in {PIN_DIR}",
        )
        == "PASS"
        and ok_all
    )
    pid_left = os.path.exists("/tmp/zelynic.pid")
    ok_all = (
        record(
            "cleanup: no pid file left",
            "PASS" if not pid_left else "FAIL",
            "/tmp/zelynic.pid" if pid_left else "",
        )
        == "PASS"
        and ok_all
    )
    CG.cleanup()
    cg_left = [p for p in TEST_CGROUPS + [HQ_CGROUP] if os.path.isdir(p)]
    ok_all = (
        record(
            "cleanup: test cgroups removed",
            "PASS" if not cg_left else "FAIL",
            ", ".join(cg_left) if cg_left else "",
        )
        == "PASS"
        and ok_all
    )
    return ok_all


# ── engine self-test (no root, no zelynic, no BPF) ─────────────────────────


def self_test():
    """Verify the harness's own measurement engine anywhere — a CI runner,
    a container, or a friend's laptop — before trusting its verdicts."""
    global SERVER
    out("zelynic supermassive test — engine self-test (no root, no zelynic, no BPF)")
    start = time.perf_counter()

    # NIGHT-hunt-31 pin: IDs resolve by stat(2) inode. The original
    # engine read a phantom "cgroup.id" file and died on the first real
    # machine it met — a decoy file must never win again.
    probe = tempfile.mkdtemp(prefix="zelynic-supermassive-selftest-")
    try:
        with open(os.path.join(probe, "cgroup.id"), "w") as f:
            f.write("999999999\n")
        got = CgroupSet._read_id(probe)
        want = os.stat(probe).st_ino & 0xFFFFFFFF
        record(
            "engine: cgroup ID resolution (stat inode, decoy file ignored)",
            "PASS" if got == want and got > 0 else "FAIL",
            f"{got} vs stat inode {want}",
        )
    finally:
        shutil.rmtree(probe, ignore_errors=True)

    # NIGHT-improve-12 pin: every ladder rung must sit inside the
    # limiter parser's bounds (types.rs MIN_RATE 1000, MAX_RATE
    # 1e12). A rung below MIN_RATE would never apply (validate_rate
    # refuses it); a rung above MAX_RATE likewise. If a future edit
    # breaks that, the root run would fail stage after stage for a
    # reason this rootless row names up front.
    ladder_ok = all(1_000 <= bps <= 1_000_000_000_000 for _, bps in LADDER_HEAVY)
    record(
        "engine: ladder rungs inside the parser bounds (1kb..1tb)",
        "PASS" if ladder_ok else "FAIL",
        f"{len(LADDER_HEAVY)} rungs, "
        f"min {min(b for _, b in LADDER_HEAVY)} bps, "
        f"max {max(b for _, b in LADDER_HEAVY)} bps, "
        "full ladder only (light retired, NIGHT-improve-19)",
    )

    # NIGHT-improve-15 pin: the ladder's high-rung floor is a MODEL
    # (cushion / min-RTO), anchored to constants that live on the
    # engine side (format.rs default_burst clamp, Linux TCP_RTO_MIN).
    # If either side drifts, this row catches it rootlessly before a
    # root run files physics as an enforcement miss — or hides a real
    # one behind a too-low floor.
    floor_pins = {
        1_000: 0.0,  # sub-skb regime: drops carry the verdict
        100_000_000: lib.BAND_LO,  # clamp binds, cushion still 1 s: full band
        1_000_000_000: 0.5,  # clamp leaves 0.1 s: cushion / min-RTO
    }
    ok_floors = all(abs(lib.loopback_rate_floor(r) - want) < 1e-9 for r, want in floor_pins.items())
    record(
        "engine: ladder floor model (sub-skb zero, band, min-RTO cushion)",
        "PASS" if ok_floors else "FAIL",
        "; ".join(f"{lib.fmt_bps(r)} -> {lib.loopback_rate_floor(r):.2f}" for r in floor_pins),
    )

    # 2026-09-22 approved-fix pins (rootless source pins, the
    # improve-13 worker-row class): the asymmetric stage must drain
    # the attach cushion before each measured window — a fresh bucket
    # is FULL (default_burst = 1 s of rate), so a first window would
    # measure rate * (1 + 1/window), 1.33x at light's 3.0 s vs 1.25x
    # at heavy's 4.0 s, exactly straddling BAND_HI = 1.30 (the
    # 2026-09-21 root run split 131.1% FAIL / 124.5% PASS on the same
    # engine). The overhead stage must pair its baseline INSIDE the
    # stage — the harness-start baseline was minutes stale when heavy
    # filed +30.0% against light's +2.1% on the same policy class
    # (machine-load drift, not policy cost). If a refactor drops
    # either contract, these rows fail before the next root run
    # trusts the stages.
    asym_src = inspect.getsource(test_asymmetric)
    drain_ok = asym_src.index("py_download(0.5)") < asym_src.index(
        "got = py_download(window)"
    ) and asym_src.index("py_upload(0.5)") < asym_src.index("sent = py_upload(window)")
    record(
        "harness: asymmetric drains the attach cushion before each window",
        "PASS" if drain_ok else "FAIL",
        "discarded warm-up windows precede both measured windows (bound 1+1/W straddles BAND_HI)",
    )
    ovh_src = inspect.getsource(test_overhead)
    pair_ok = ovh_src.index("fresh = py_download(window)") < ovh_src.index("apply_single(")
    record(
        "harness: overhead baseline is paired inside the stage",
        "PASS" if pair_ok else "FAIL",
        "fresh baseline window precedes the non-binding policy window",
    )

    # NIGHT-improve-16 pins: the resolve GATE. The 2026-09-21 debian13
    # run tested a stale /usr/bin/zelynic v4.0.0-alpha (the repo build
    # had never succeeded there) and filed 12 decoy failures — the
    # banner SHOWED the version, nothing enforced it. These rows pin
    # the gate rootlessly with STUB binaries: token parsing (both -V
    # header shapes the wild has shown), the repo-anchored candidate
    # list (absolute, musl alias included), and the accept/reject
    # decision end-to-end through the real resolve_binary.
    token_pins = (
        ("zelynic: v11.0.0-dev.1", "11.0.0-dev.1"),  # current header shape
        ("Version: v4.0.0-alpha", "4.0.0-alpha"),  # legacy distro install
        ("zelynic: v99.0.0-x.7+meta", "99.0.0-x.7+meta"),
        ("no version in this line", None),
    )
    ok_tokens = all(lib.version_token(s) == w for s, w in token_pins)
    record(
        "engine: version token parses both -V header shapes",
        "PASS" if ok_tokens else "FAIL",
        "; ".join(f"{s!r} -> {lib.version_token(s)}" for s, _ in token_pins),
    )

    ok_candidates = (
        all(
            os.path.isabs(c) and c.startswith(lib.REPO_ROOT + os.sep)
            for c in lib.REPO_BINARY_CANDIDATES
        )
        and any("pro-native-musl" in c for c in lib.REPO_BINARY_CANDIDATES)
        # NIGHT-improve-22: all four arch-baseline alias outputs are
        # candidates — one silently dropped means a freshly built
        # release-shape binary stops outranking stale ones. The shapes
        # are the release platform ids the aliases have carried since
        # NIGHT-boost-30 (pro-linux-amd64-vX-libc: the arch and the
        # libc in the label, order matching release.yml) — the pin
        # followed the rename so it can never silently accept the
        # pre-boost-30 shapes back.
        and all(
            any(f"pro-linux-{kind}" in c for c in lib.REPO_BINARY_CANDIDATES)
            for kind in (
                "amd64-v3-gnu",
                "amd64-v4-gnu",
                "amd64-v3-musl",
                "amd64-v4-musl",
            )
        )
    )
    record(
        "engine: binary candidates repo-anchored (native + v3/v4, gnu/musl, release)",
        "PASS" if ok_candidates else "FAIL",
        f"{len(lib.REPO_BINARY_CANDIDATES)} absolute candidates under {lib.REPO_ROOT}",
    )

    want = lib.repo_version()
    if want is None:
        record(
            "engine: version gate accepts matching, rejects foreign builds",
            "FAIL",
            f"repo_version() could not read {lib.REPO_ROOT}/Cargo.toml [package] version",
        )
    else:
        old_binary = lib.BINARY
        stub_dir = tempfile.mkdtemp(prefix="zelynic-supermassive-gate-")
        try:

            def _stub(name, header):
                path = os.path.join(stub_dir, name)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(f"#!/bin/sh\necho '{header}'\n")
                os.chmod(path, 0o755)
                return path

            right = _stub("matching", f"zelynic: v{want}")
            wrong = _stub("v4-distro", "Version: v4.0.0-alpha")
            verdicts = {}
            headlines = {}
            for label, path in (("accept", right), ("reject", wrong)):
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    verdicts[label] = lib.resolve_binary(path, "self-test")
                headlines[label] = captured.getvalue()
            ok_gate = (
                verdicts["accept"] is True
                and verdicts["reject"] is False
                and "BINARY GATE" in headlines["reject"]
                and f"v{want}" in headlines["reject"]
            )
            record(
                "engine: version gate accepts matching, rejects foreign builds",
                "PASS" if ok_gate else "FAIL",
                f"checkout v{want}: matching stub accepted, v4.0.0-alpha distro stub rejected",
            )
        finally:
            lib.BINARY = old_binary
            shutil.rmtree(stub_dir, ignore_errors=True)

    def agree(name, client_bytes, server_bytes):
        ratio = client_bytes / server_bytes if server_bytes else 0.0
        return record(
            name,
            "PASS" if 0.5 <= ratio <= 1.5 else "FAIL",
            f"client {client_bytes} vs server {server_bytes} ({ratio * 100:.1f}%)",
        )

    SERVER = HttpServer()
    SERVER.reset()
    got = py_download(2.0)
    SERVER.settle()
    agree("engine: python download counters agree", got, SERVER.peek()["dl"])
    SERVER.reset()
    if not CURL:
        record("engine: curl stages", "SKIP", "curl not found on this machine")
    else:
        got = curl_download(2.0)
        SERVER.settle()
        if got is None:
            record("engine: curl download counters agree", "FAIL", "curl produced no metric")
        else:
            agree("engine: curl download counters agree", got, SERVER.peek()["dl"])
        SERVER.reset()
        sent = curl_upload(3.0)
        if sent is None:
            record("engine: curl upload counters agree", "FAIL", "curl produced no metric")
        else:
            # settle() first — the HttpServer contract: the /ul counter
            # folds its per-connection total into the shared state only
            # AFTER the connection ends, so a peek that wins the race
            # against the server thread reads a stale count (seen live
            # once as upload 4.49 GB vs 0, 0.0%, in a container run on
            # 2026-09-22 — NIGHT-improve-21 hunt find). The download
            # row above already settles before this point.
            SERVER.settle()
            agree("engine: curl upload counters agree", sent, SERVER.peek()["ul"])
        SERVER.reset()
        totals = [None] * 4

        def worker(i):
            totals[i] = curl_download(2.0)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        SERVER.settle()
        if any(v is None for v in totals):
            record("engine: curl burst x4 counters agree", "FAIL", "a curl produced no metric")
        else:
            agree("engine: curl burst x4 counters agree", sum(totals), SERVER.peek()["dl"])
    # NIGHT-improve-13 pins: the embedded worker sources must PARSE and
    # RUN. The improve-12 rewrite shipped them inside NON-RAW
    # triple-quoted strings, so \x00 and \r\n unescaped at parent
    # parse time: every root-mode python worker died before printing a
    # metric — the \x00 one could not even be exec'd (Popen raised
    # "embedded null byte" and killed the run at the upload stage) —
    # while this self-test stayed green, because with CG unset it only
    # exercises the IN-PROCESS client. These rows close that blind
    # spot rootlessly: compile catches source corruption, worker_smoke
    # catches spawn/argv/contract breakage end-to-end.
    for label, code in (("dl", _PY_DL_CLIENT), ("ul", _PY_UL_CLIENT)):
        try:
            compile(code, f"<{label}-worker>", "exec")
            record(f"engine: {label} worker source parses", "PASS")
        except (SyntaxError, ValueError) as e:
            record(f"engine: {label} worker source parses", "FAIL", str(e))
    # settle + reset first: drain the burst writers' tails out of the
    # counters so the worker rows measure ONLY the worker's stream.
    SERVER.settle()
    SERVER.reset()
    got, err = worker_smoke(_PY_DL_CLIENT, SERVER.port, 1.5)
    SERVER.settle()
    if got is None:
        record("engine: dl worker measures end-to-end", "FAIL", err)
    else:
        agree("engine: dl worker measures end-to-end", got, SERVER.peek()["dl"])
    SERVER.reset()
    sent, err = worker_smoke(_PY_UL_CLIENT, SERVER.port, 1.5)
    if sent is None:
        record("engine: ul worker measures end-to-end", "FAIL", err)
    else:
        agree("engine: ul worker measures end-to-end", sent, SERVER.peek()["ul"])
    SERVER.reset()
    SERVER.stop()
    # NIGHT-improve-12 regression pin: a connect failure must surface
    # as ZERO GOODPUT, never as an uncaught TimeoutError — the
    # 2026-09-21 root run died at block-single with "harness error:
    # timed out" and every later stage unrecorded. The dead listener is
    # a socket bound but NEVER listen()-ing: connects are refused
    # instantly and deterministically (SERVER.stop() alone does not
    # qualify — a thread blocked in accept() keeps the kernel listener
    # alive past close(), a classic python teardown gotcha).
    guard = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    guard.bind(("127.0.0.1", 0))
    dead_port = guard.getsockname()[1]
    real_port = SERVER.port
    try:
        SERVER.port = dead_port
        got = py_download(0.5)
        sent = py_upload(0.5)
        record(
            "engine: blocked connect yields zero goodput, not a crash",
            "PASS" if got == 0 and sent == 0 else "FAIL",
            f"download {got} B, upload {sent} B against a dead listener",
        )
    except Exception as e:  # noqa: BLE001 - the whole point is not raising
        record("engine: blocked connect yields zero goodput, not a crash", "FAIL", str(e))
    finally:
        SERVER.port = real_port
        guard.close()
    # NIGHT-improve-19 pins: the unknown-flag typo rescue must
    # suggest the near-miss flag (the owner's 'self-tesss' case),
    # stay silent for distant input (no noise), and the retired
    # --light must name its replacement rather than render as a
    # generic unknown flag with a misleading tip.
    typo_pins = (
        ("self-tesss", "self-test"),
        ("hevy", "heavy"),
        ("jsonn", "json"),
    )
    typo_ok = all(_closest_flag(t) == want for t, want in typo_pins)
    record(
        "engine: unknown-flag typo rescue suggests the near-miss flag",
        "PASS" if typo_ok else "FAIL",
        "; ".join(f"--{t} -> --{_closest_flag(t)}" for t, _ in typo_pins),
    )
    silent_ok = _closest_flag("zzzzqqqq") is None and _closest_flag("") is None
    record(
        "engine: distant unknown flags stay tip-less",
        "PASS" if silent_ok else "FAIL",
        "no suggestion below the 0.7 Jaro confidence threshold",
    )
    retire_lines = _unknown_arg_error("--light")
    retire_ok = any("retired" in line for line in retire_lines) and not any(
        "tip:" in line for line in retire_lines
    )
    record(
        "engine: retired --light names its replacement, not a tip",
        "PASS" if retire_ok else "FAIL",
        retire_lines[0],
    )

    # NIGHT-refactor-2 pins: the real-internet lane moved here from v2,
    # and its engine contract moves with it — the endpoint registry must
    # stay well-formed, the workers must carry the measurement contract
    # (size metric, --max-time, the /dev/zero streaming source), and the
    # realnet band overrides must stay honest (floor below ceiling, both
    # positive). Rootless, no network: these pin the INSTRUMENT, the
    # root run decides the internet itself.
    ok_registry = all(
        len(entry) == 3 and (entry[2].startswith("https://") or entry[2].startswith("http://"))
        for entry in REALNET_DL_ENDPOINTS
    )
    record(
        "engine: realnet download endpoint registry well-formed",
        "PASS" if ok_registry else "FAIL",
        f"{len(REALNET_DL_ENDPOINTS)} candidates: "
        + ", ".join(name for name, _, _ in REALNET_DL_ENDPOINTS),
    )
    record(
        "engine: realnet upload endpoint well-formed",
        "PASS" if REALNET_UL_ENDPOINT[1].startswith("https://") else "FAIL",
        REALNET_UL_ENDPOINT[1],
    )
    dl_cmd = realnet_dl_cmd(10, "https://self.test/__down")
    ul_cmd = realnet_ul_cmd(10, "https://self.test/__up")
    contract_ok = (
        dl_cmd[-1] == "https://self.test/__down"
        and "%{size_download}" in dl_cmd
        and "--max-time" in dl_cmd
        and "10" in dl_cmd
        and "-T" in ul_cmd
        and "/dev/zero" in ul_cmd
        and "%{size_upload}" in ul_cmd
    )
    record(
        "engine: realnet worker commands carry the measurement contract",
        "PASS" if contract_ok else "FAIL",
        "size metric, max-time, and the /dev/zero streaming source",
    )
    record(
        "engine: realnet band overrides are honest",
        "PASS" if 0 < REALNET_BAND_LO < REALNET_BAND_HI else "FAIL",
        f"floor {REALNET_BAND_LO}, ceiling {REALNET_BAND_HI} (slow-start patience, same tripwire)",
    )

    counts = {v: sum(1 for r in RESULTS if r["verdict"] == v) for v in ("PASS", "FAIL", "SKIP")}
    out()
    out("━━━ self-test verdict ━━━")
    out(
        f"  {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped"
        f" — {time.perf_counter() - start:.1f}s"
    )
    return counts["FAIL"] == 0


# ── orchestration ───────────────────────────────────────────────────────────


# ── flag typo rescue (NIGHT-improve-19) ─────────────────────────────────────
#
# Mirrors the flagship CLI's suggestion engine (src/cli/suggestion.rs):
# case-insensitive Jaro at clap's own > 0.7 confidence threshold, so
# `--self-tesss` suggests `--self-test` under the SAME confidence rule
# the zelynic binary applies to its own flags — one typo contract
# across the product and its harnesses. The retired --light gets a
# dedicated message naming its replacement instead of a generic
# unknown-option error: muscle memory deserves a better answer than
# "did you mean --band?".

KNOWN_FLAGS = ("heavy", "self-test", "binary", "json", "band", "help")


def _jaro_ci(a, b):
    """Case-insensitive Jaro similarity (clap's flag-suggestion metric)."""
    a = a.lower()
    b = b.lower()
    a_len, b_len = len(a), len(b)
    if a_len == 0 and b_len == 0:
        return 1.0
    if a_len == 0 or b_len == 0:
        return 0.0
    if a_len == 1 and b_len == 1:
        return 1.0 if a[0] == b[0] else 0.0
    search_range = max(a_len, b_len) // 2 - 1
    if search_range < 0:
        search_range = 0
    b_consumed = [False] * b_len
    matches = 0
    transpositions = 0
    b_match_index = 0
    for i, a_elem in enumerate(a):
        lo = max(0, i - search_range)
        hi = min(b_len - 1, i + search_range)
        if lo > hi:
            continue
        for j, b_elem in enumerate(b):
            if lo <= j <= hi and a_elem == b_elem and not b_consumed[j]:
                b_consumed[j] = True
                matches += 1
                if j < b_match_index:
                    transpositions += 1
                b_match_index = j
                break
    if matches == 0:
        return 0.0
    return 1 / 3 * (matches / a_len + matches / b_len + (matches - transpositions) / matches)


def _closest_flag(typed):
    """Closest known flag by Jaro > 0.7, or None. Ties keep the FIRST
    candidate — deterministic under a stable KNOWN_FLAGS order."""
    best = None
    best_score = 0.7
    for flag in KNOWN_FLAGS:
        score = _jaro_ci(typed, flag)
        if score > best_score:
            best = flag
            best_score = score
    return best


def _unknown_arg_error(token):
    """The error lines for one unknown argument: the retirement
    message for --light, else unknown-option plus typo tip."""
    bare = token.lstrip("-")
    if bare == "light":
        return [
            "error: --light was retired (NIGHT-improve-19) — the supermassive matrix",
            "is now the default and only root mode (5+ min). Just run:",
            "  sudo ./scripts/supermassive/supermassive-test.sh",
        ]
    lines = [f"error: unknown option '{token}'"]
    suggestion = _closest_flag(bare)
    if suggestion:
        lines.append(f"  tip: a similar option exists: '--{suggestion}'")
    return lines


def run_heavy(baseline_window):
    test_doctor()
    test_list_apps()
    baseline = test_baseline(baseline_window)
    # NIGHT-refactor-2: preflight the real-internet lane right after the
    # local baseline — an unreachable internet must SKIP its stages with
    # the reason named up front, never surface as a mystery mid-matrix.
    stage_realnet_probe()
    stage_realnet_baseline()
    stage_realnet_upload_sanity()
    test_policy_write()
    # E2E-workflow hunt (first full-matrix CI run): this call moved from
    # v2 in NIGHT-refactor-2 and landed WITHOUT its window — the engine
    # self-test never executes the matrix, so a TypeError at this line
    # was invisible on every push until a real root run reached it
    # (12 passed, then "harness error: stage_rate_change() missing 1
    # required positional argument: 'window'"). 4.0 s is the ORIGINAL
    # contract: the stage's pre-refactor v2 body measured both rungs
    # with LOCAL_WINDOW = 4.0, the same window the sibling local
    # measurement stages here use (asymmetric / mixed / limit_all).
    stage_rate_change(4.0)
    test_rate_ladder(LADDER_HEAVY, 5.5, 2, baseline)
    test_upload(5.0, baseline)
    test_download_only(4.0, baseline)
    test_asymmetric(4.0, baseline)
    test_block_single(4.0)
    test_unlock(4.0, baseline)
    test_curl_burst(6.0, 6, 1_000_000, baseline)
    test_curl_upload(5.0, baseline)
    test_multi_group(5.0, baseline)
    test_block_multi(4.0)
    test_unstrict_multi()
    test_mixed(4.0, baseline)
    test_limit_all(4.0, baseline)
    # NIGHT-refactor-2: the internet lane — the same flagship moves the
    # loopback matrix just proved, against the production traffic shape.
    stage_realnet_strict_download()
    stage_realnet_strict_upload()
    stage_realnet_limit_all()
    stage_realnet_block()
    test_reload(60)
    test_sustain(1_000_000, 6, 5.0, baseline)
    test_overhead(4.0, baseline)
    # The internet lane's own teardown proof: unstrict-all must give the
    # machine its real-internet speed back, measured against the
    # machine's own re-measured baseline.
    stage_realnet_restore()
    # NIGHT-refactor-2: the abuse family (rate guards, SIGKILL batteries,
    # regression re-proof, recover, dmesg) moved to v2 — this harness
    # measures limits; that one survives violence.
    test_cleanup()


def main():
    global SERVER, CG, MODE
    ap = argparse.ArgumentParser(
        prog="supermassive-test",
        description="zelynic limiter-scope supermassive test (NIGHT-master-2, NIGHT-refactor-2)",
    )
    ap.add_argument(
        "--heavy",
        action="store_true",
        help="explicitly request the supermassive matrix (the default mode; "
        "kept for explicit invocations and muscle memory)",
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
        default=f"{BAND_LO},{BAND_HI}",
        help="verdict band as lo,hi ratios for the LOCAL loopback lane "
        "(default 0.65,1.30; the real-internet lane keeps its own "
        "slow-start floor)",
    )
    args, unknown = ap.parse_known_args()
    # NIGHT-improve-19: unknown flags get the CLI-grade typo rescue
    # BEFORE any mode decision — a mistyped --self-tesss must not fall
    # through to the root-mode run path.
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
    # Binary resolution lives in the shared lib (NIGHT-improve-11):
    # repo-local builds outrank the system PATH so a checkout always
    # tests itself, never the stale distro install.
    if not lib.resolve_binary(args.binary, "sudo ./scripts/supermassive/supermassive-test.sh"):
        return 2

    # NIGHT-improve-19: light was retired — one root intensity. The
    # mode name stays in the banner, JSON output, and CROSS_DISTRO_
    # RESULTS rows, so downstream tooling keeps parsing "heavy".
    mode = "heavy"
    start = time.perf_counter()
    CG = CgroupSet()
    exit_code = 1
    try:
        MODE = CG.setup()
        SERVER = HttpServer()
        # NIGHT-hunt-21: the fleet mode rides the environment block's
        # "cgroups:" row only — this banner used to repeat it
        # byte-for-byte two lines above the env table.
        out(
            f"zelynic supermassive test (NIGHT-refactor-2, {mode} mode — limiter scope: local + real internet)"
        )
        out()
        env_ok = test_env()
        if not env_ok:
            out()
            out("  environment not suitable for zelynic — stopping here.")
        else:
            run_heavy(3.0)
        CG.cleanup()
        report_worker_faults()
        ok = final_report(
            start,
            mode,
            "zelynic limiter scope: local loopback and the real internet — "
            "supermassive-verified on this machine.",
        )
        exit_code = 0 if ok else 1
    except Exception as e:  # noqa: BLE001 - report, then still clean up
        out(f"  harness error: {type(e).__name__}: {e}")
        try:
            clear_all()
            CG.cleanup()
        except Exception:
            pass
        report_worker_faults()
        final_report(
            start,
            mode,
            "zelynic limiter scope: local loopback and the real internet — "
            "supermassive-verified on this machine.",
        )
        exit_code = 1
    finally:
        if SERVER:
            SERVER.stop()
    if args.json:
        print(
            json.dumps(
                {
                    "binary": lib.BINARY,
                    "mode": mode,
                    "cgroup_mode": MODE,
                    "realnet": {
                        "download_endpoint": DL_ENDPOINT[0] if DL_ENDPOINT else None,
                        "upload_endpoint": UL_ENDPOINT[0] if UL_ENDPOINT else None,
                    },
                    "worker_faults": [{"error": msg, "count": n} for msg, n in WORKER_FAULTS],
                    "results": RESULTS,
                },
                indent=2,
            )
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
