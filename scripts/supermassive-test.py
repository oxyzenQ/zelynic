#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: the supermassive matrix is one self-contained harness by design — every stage shares the cgroup fleet, the traffic engine, and the verdict plumbing, so splitting it means a module package, not a script (the engine helpers it truly shares with limiter-depth-test.py ARE deduplicated into zelynic_harness_lib.py, NIGHT-improve-11)
"""zelynic supermassive test — the one-click flagship harness (NIGHT-master-2; renamed from brutal-stress-test and engine-deduplicated in NIGHT-improve-11 / security-4).

NIGHT-master-1 (limiter-depth-test.py) answers "is the limiter ACCURATE?"
with measured rate bands. This harness answers the owner's next question:
"does the WHOLE command surface survive supermassive stress?" — one click sweeps
every policy family (strict / block / unstrict, single / multi / all)
across real target shapes with real traffic, real curl processes, and the
full rate range the parser accepts.

Design:

  * One click, two intensities: default light mode (~2 min, basic limiting
    sweep) and --heavy (the complete supermassive matrix, 5+ minutes, long
    running until done). --self-test verifies the harness engine alone
    (no root, no zelynic, no BPF) so CI and containers can smoke it
    anywhere — the same cross-distro minimum as NIGHT-master-1: python3
    stdlib only, curl optional (its stages SKIP, the rest keeps working).
  * Shared engine: the fourteen helpers this harness and limiter-depth-
    test.py used to duplicate (verdict recording, subprocess control,
    status-JSON reading, environment probes, binary resolution, the
    final report) live in zelynic_harness_lib.py — one fix lands in both
    harnesses the same day (NIGHT-improve-11; the hunt-31 kernfs-inode
    and the target/pro-native-gnu binary candidate each drifted for days
    between the twins before that).
  * Traffic is loopback HTTP served by an in-process python server, so
    no external test server is ever needed. curl is the second traffic
    engine: real external processes pushed through the limiter, the same
    class of proof as the owner's manual browser tests.
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
  * limit-all is exercised with --force in heavy mode only, briefly and
    at a generous rate: as root the harness's own cgroups are uid 0 and
    would otherwise be skipped as system apps. block-all is deliberately
    NOT exercised — blocking every app can sever the very session that
    runs the test.

Usage:
  sudo ./scripts/supermassive-test.sh                # light (~2 min)
  sudo ./scripts/supermassive-test.sh --heavy       # supermassive (5+ min)
  python3 scripts/supermassive-test.py --self-test   # engine smoke, no root
  sudo ./scripts/supermassive-test.sh --binary ./zelynic
  sudo ./scripts/supermassive-test.sh --json

What it verifies (verdicts PASS / FAIL / SKIP, exit 1 on any FAIL):
  light: env + minimum specs, doctor, baseline, strict-single policy
         write, status human + JSON surfaces, rate ladder
         (1kb/100kb/1mb/10mb), upload-only (-u), block-single zero
         goodput, unstrict-single (unlock) restores speed, curl burst
         download x4, curl upload, non-binding overhead, cleanup, dmesg
  heavy: + full ladder to 1tb (two windows per rung), strict-multi
         shared group bucket across cgroups, block-multi, unstrict-multi
         selective removal, mixed concurrent policies on five cgroups,
         limit-all --force sweep, reload cycles, sustain windows,
         recover clean-state, list-apps JSON
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

import zelynic_harness_lib as lib
# NOTE: BINARY is deliberately NOT in this list — resolve_binary REBINDS it
# inside the lib module, and a from-import would keep a stale empty string
# here. Reference it as lib.BINARY; the mutation-only names (RESULTS) are
# safe to bind directly.
from zelynic_harness_lib import (
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
    dmesg_scan,
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
LADDER_LIGHT = [
    ("1kb", 1_000), ("100kb", 100_000), ("1mb", 1_000_000), ("10mb", 10_000_000),
]
LADDER_HEAVY = [
    ("1kb", 1_000), ("10kb", 10_000), ("100kb", 100_000),
    ("1mb", 1_000_000), ("10mb", 10_000_000), ("100mb", 100_000_000),
    ("1gb", 1_000_000_000), ("10gb", 10_000_000_000),
    ("100gb", 100_000_000_000), ("1tb", 1_000_000_000_000),
]
# NIGHT-improve-14: rungs this close to the loopback ceiling are
# measured as a PARALLEL aggregate, not one flow. A single TCP stream
# through a dropper cannot CLAIM a bucket that large: default_burst
# clamps at 100 MB, which at 100mb is a full SECOND of tokens but at
# 1gb only 0.1 s — every post-drop cwnd recovery then dips below the
# refill rate and single-flow goodput settles around half of
# configured on a ~5 GB/s loopback without ever exceeding the cap
# (the 2026-09-21 nightpc heavy run: 55.7% measured while kernel
# drops AND byte accounting both held). AIMD physics, not an
# enforcement miss. Six concurrent workers share the bucket the same
# way curl burst and strict-multi do; their staggered dips let the
# aggregate track the refill rate, so the band verdict keeps its
# meaning. Below this line the single-flow instrument stays.
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
        self._lock = threading.Lock()
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
        head, rest = buf[:idx], buf[idx + 4:]
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
            return {"dl": self.dl_bytes, "ul": self.ul_bytes}

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
            capture_output=True, text=True, timeout=window + 20,
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
            name, [sys.executable, "-c", _PY_DL_CLIENT, str(SERVER.port), str(window)],
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
            name, [sys.executable, "-c", _PY_UL_CLIENT, str(SERVER.port), str(window)],
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
        CURL, "-s", "-o", "/dev/null", "-w", f"%{{{metric}}}",
        "--max-time", f"{window}", f"http://127.0.0.1:{SERVER.port}{url_path}",
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
        CURL, "-s", "-o", "/dev/null", "-w", "%{size_upload}",
        "--max-time", f"{window}", "-T", "/dev/zero",
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
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
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


def spawn_bg_in_cgroup(name, argv):
    """Fire-and-forget resident process (sleepers) inside cgroup `name`."""
    script = f'echo $$ > "{CG.paths[name]}/cgroup.procs"\nexec "$@"'
    return subprocess.Popen(
        ["bash", "-c", script, "worker"] + argv,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


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
            return False, f"row for {CG.ids[n]} is {entry.get('download_bps')}/{entry.get('upload_bps')}, want {exp}"
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
    out("━━━ environment (minimum specs: kernel 5.13+, cgroup v2, BPF fs, root — docs/KERNEL_COMPATIBILITY.md) ━━━")
    out(f"  distro:   {pretty_name()}")
    out(f"  kernel:   {os.uname().release}  arch: {os.uname().machine}")
    out(f"  cpu:      {cpu_model()}")
    out(f"  python:   {sys.version.split()[0]}  curl: {CURL or 'not found (curl stages will SKIP)'}")
    out(f"  binary:   {lib.BINARY} ({binary_version()})")
    out(f"  cgroups:  {MODE}")
    ok = True
    ok = record(
        "cgroup v2 unified hierarchy", "PASS" if cgroup2_mounted() else "FAIL",
        CGROUP_ROOT if cgroup2_mounted() else f"{CGROUP_ROOT} is not cgroup2fs",
    ) == "PASS" and ok
    ok = record(
        "cgroup ID resolution (kernfs inode)",
        "PASS" if CG.ids.get("a") else "FAIL",
        f"cgroup id {CG.ids.get('a')}",
    ) == "PASS" and ok
    # NIGHT-improve-11 fix: gate on the bpf FILESYSTEM MOUNT, not the
    # zelynic pin directory — a fresh host (bpffs mounted, zelynic never
    # run) is exactly the machine this harness exists to qualify, and the
    # old isdir(PIN_DIR) check failed it at the first gate (the 2026-09-21
    # run that died at "3 passed, 1 failed, 0s" having tested nothing).
    bpffs_ok = bpffs_mounted_at("/sys/fs/bpf")
    ok = record(
        "BPF filesystem mounted", "PASS" if bpffs_ok else "FAIL",
        "/sys/fs/bpf (fstype bpf)" if bpffs_ok else
        "/sys/fs/bpf is not a mounted bpf filesystem — the limiter pins "
        "its maps there; tip: sudo mount -t bpf bpf /sys/fs/bpf",
    ) == "PASS" and ok
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
            "baseline: unlimited loopback throughput", "FAIL",
            "0 B/s with NO policy live — the measurement engine itself "
            "moved no bytes, so every rate verdict below is garbage; see "
            "worker faults at the end of the report",
            {"bps": 0},
        )
        return bps
    record(
        "baseline: unlimited loopback throughput", "PASS",
        f"{fmt_bps(bps)} ({mbps(bps)}) over {window:.1f}s — the measurement ceiling",
        {"bps": round(bps)},
    )
    return bps


# ── single-target stages ────────────────────────────────────────────────────

def test_policy_write():
    ok, payload = apply_single("a", "100kb", 100_000, 100_000)
    verdict = record(
        "strict-single 100kb: policy lands in the kernel maps",
        "PASS" if ok else "FAIL", "" if ok else payload,
    )
    # NIGHT-improve-11 (all-round scope): the human table is a separate
    # render path from the JSON every other stage consumes — exercise it
    # while a limit is provably live.
    rc, stdout, _ = run_zel(["status"])
    rendered = "Active limits" in stdout and "zelynic Status" in stdout
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
                name, "SKIP",
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
        extra = (
            "loopback GSO granularity: a sub-skb bucket cannot reach "
            "steady state — the ceiling and kernel drops carry the verdict"
            if floor == 0.0 else ""
        )
        if flows > 1 and not extra:
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
        return record("upload (-u only): enforced", "FAIL",
                      f"exit {rc}: {(stderr or stdout).strip()[:200]}")
    entry = limit_entry(status_json(), CG.ids["a"])
    if entry is None or entry.get("upload_bps") != 1_000_000 or entry.get("download_bps") is not None:
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


def test_block_single(window):
    ok, payload = block_target("block-single", ["a"])
    if not ok:
        return record("block-single: zero goodput", "FAIL", payload)
    time.sleep(0.3)
    got = py_download(window)
    verdict = "PASS" if got <= BLOCK_GOODPUT_CEIL else "FAIL"
    record(
        "block-single: zero goodput", verdict,
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
    ok, payload = apply_single("a", rate_str, rate_bps, rate_bps)
    if not ok:
        return record("curl burst: parallel download under limit", "FAIL", payload)
    time.sleep(0.5)
    totals = [None] * clients

    def worker(i):
        # NIGHT-improve-12: each curl runs INSIDE cgroup a via the
        # worker path — the old local curl_download only happened to be
        # policed because the whole harness shared the target cgroup.
        totals[i] = curl_in_cgroup("a", window)[0]

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(clients)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if any(v is None for v in totals):
        record("curl burst: parallel download under limit", "FAIL", "a curl produced no metric")
        clear_all()
        return False
    total = sum(totals)
    passed = band_check(
        f"curl burst: {clients} parallel curls, one shared limit",
        total / window, rate_bps,
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
    sent, err = curl_upload_in_cgroup("a", window)
    if sent is None:
        record("curl upload: external upload engine", "FAIL", f"curl produced no metric ({err})")
        clear_all()
        return False
    passed = band_check("curl upload: external upload engine", sent / window, 1_000_000)
    enforcement_proofs("curl upload", sent)
    clear_all()
    return passed


def test_overhead(window, baseline):
    if baseline and baseline >= 300e9:
        return record("overhead: non-binding policy cost", "SKIP",
                      "baseline beyond the 1 TB/s policy ceiling")
    non_binding_gb = min(900, max(10, round((3 * baseline if baseline else 10e9) / 1e9)))
    non_binding = non_binding_gb * 1e9
    ok, payload = apply_single("a", f"{non_binding_gb}gb", int(non_binding), int(non_binding))
    if not ok:
        return record("overhead: non-binding policy cost", "FAIL", payload)
    time.sleep(0.3)
    got = py_download(window)
    limited = got / window
    clear_all()
    if not baseline:
        return record("overhead: non-binding policy cost", "SKIP", "no baseline")
    drop_pct = (baseline - limited) / baseline * 100 if baseline else 0.0
    verdict = "PASS" if drop_pct <= 30.0 else "FAIL"
    record(
        "overhead: non-binding policy cost", verdict,
        f"baseline {fmt_bps(baseline)} vs {fmt_bps(limited)} "
        f"({non_binding_gb} GB/s policy) — {drop_pct:+.1f}%",
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
    solo = band_check("strict-multi: member alone fills the shared bucket",
                      got_b / window, 1_000_000)
    # Phase 2: two members together still only get ONE bucket.
    results = {}

    def worker(n):
        results[n] = curl_in_cgroup(n, window)

    threads = [threading.Thread(target=worker, args=(n,)) for n in ("b", "c")]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if any(results[n][0] is None for n in ("b", "c")):
        clear_all()
        return record(name, "FAIL", "a group-member curl produced no metric")
    total = sum(results[n][0] for n in ("b", "c"))
    joint = band_check(
        f"strict-multi: {len(results)} members joint, still one shared bucket",
        total / window, 1_000_000,
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
        name, "PASS" if ok_both else "FAIL",
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
        name, verdict,
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
        "mixed: blocked member stays dark", "PASS" if blocked else "FAIL",
        f"{got_e} bytes over {window:.1f}s",
    )
    doc = status_json()
    rows = len(doc.get("limits", [])) if doc else 0
    record(
        "mixed: five cgroups, three policies, one status view",
        "PASS" if rows >= 4 else "FAIL", f"{rows} limit rows visible",
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
    # lives in hq, so the row check below needs a resident in a.
    sleepers = [spawn_bg_in_cgroup(n, ["sleep", "30"]) for n in "abcde"]
    try:
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
        verdict, f"{cycles - mismatches}/{cycles} cycles verified via status JSON",
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
        "sustain: steady state + drift guard", verdict,
        "; ".join(f"w{i + 1} {fmt_bps(r)}" for i, r in enumerate(rates))
        + f" — drift floor {drift * 100:.0f}%",
    )
    return verdict == "PASS"


def test_recover():
    rc, stdout, stderr = run_zel(["recover"])
    detail = (stderr or stdout).strip()[:120] or f"exit {rc}"
    return record(
        "recover: clean state after unstrict-all", "PASS" if rc == 0 else "FAIL", detail
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


# ── cleanup + kernel log ────────────────────────────────────────────────────

def test_cleanup():
    ok_all = True
    rc, _, _ = run_zel(["unstrict-all"])
    time.sleep(0.5)
    ok_all = record(
        "cleanup: unstrict-all exits 0", "PASS" if rc == 0 else "FAIL", f"exit {rc}",
    ) == "PASS" and ok_all
    pins_left = len(os.listdir(PIN_DIR)) if os.path.isdir(PIN_DIR) else 0
    ok_all = record(
        "cleanup: zero BPF pins left",
        "PASS" if pins_left == 0 else "FAIL", f"{pins_left} entries in {PIN_DIR}",
    ) == "PASS" and ok_all
    pid_left = os.path.exists("/tmp/zelynic.pid")
    ok_all = record(
        "cleanup: no pid file left", "PASS" if not pid_left else "FAIL",
        "/tmp/zelynic.pid" if pid_left else "",
    ) == "PASS" and ok_all
    CG.cleanup()
    cg_left = [p for p in TEST_CGROUPS + [HQ_CGROUP] if os.path.isdir(p)]
    ok_all = record(
        "cleanup: test cgroups removed", "PASS" if not cg_left else "FAIL",
        ", ".join(cg_left) if cg_left else "",
    ) == "PASS" and ok_all
    return ok_all


def test_dmesg():
    return dmesg_scan()


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

    def agree(name, client_bytes, server_bytes):
        ratio = client_bytes / server_bytes if server_bytes else 0.0
        return record(
            name, "PASS" if 0.5 <= ratio <= 1.5 else "FAIL",
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
    counts = {v: sum(1 for r in RESULTS if r["verdict"] == v) for v in ("PASS", "FAIL", "SKIP")}
    out()
    out("━━━ self-test verdict ━━━")
    out(f"  {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped"
        f" — {time.perf_counter() - start:.1f}s")
    return counts["FAIL"] == 0


# ── orchestration ───────────────────────────────────────────────────────────

def run_light(baseline_window):
    test_doctor()
    baseline = test_baseline(baseline_window)
    test_policy_write()
    test_rate_ladder(LADDER_LIGHT, 4.0, 1, baseline)
    test_upload(4.0, baseline)
    test_block_single(3.0)
    test_unlock(3.0, baseline)
    test_curl_burst(5.0, 4, 1_000_000, baseline)
    test_curl_upload(4.0, baseline)
    test_overhead(3.5, baseline)
    test_cleanup()
    test_dmesg()


def run_heavy(baseline_window):
    test_doctor()
    test_list_apps()
    baseline = test_baseline(baseline_window)
    test_policy_write()
    test_rate_ladder(LADDER_HEAVY, 5.5, 2, baseline)
    test_upload(5.0, baseline)
    test_block_single(4.0)
    test_unlock(4.0, baseline)
    test_curl_burst(6.0, 6, 1_000_000, baseline)
    test_curl_upload(5.0, baseline)
    test_multi_group(5.0, baseline)
    test_block_multi(4.0)
    test_unstrict_multi()
    test_mixed(4.0, baseline)
    test_limit_all(4.0, baseline)
    test_reload(60)
    test_sustain(1_000_000, 6, 5.0, baseline)
    test_overhead(4.0, baseline)
    test_recover()
    test_cleanup()
    test_dmesg()


def main():
    global SERVER, CG, MODE
    ap = argparse.ArgumentParser(
        prog="supermassive-test",
        description="zelynic one-click supermassive test (NIGHT-master-2)",
    )
    ap.add_argument("--heavy", action="store_true",
                    help="the complete supermassive matrix (5+ min; default is light ~2 min)")
    ap.add_argument("--self-test", action="store_true",
                    help="verify the harness engine only — no root, no zelynic, no BPF")
    ap.add_argument("--binary", help="path to the zelynic binary")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--band", default=f"{BAND_LO},{BAND_HI}",
                    help="verdict band as lo,hi ratios (default 0.65,1.30)")
    args = ap.parse_args()

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
    if not lib.resolve_binary(args.binary, "sudo ./scripts/supermassive-test.sh"):
        return 2

    mode = "heavy" if args.heavy else "light"
    start = time.perf_counter()
    CG = CgroupSet()
    exit_code = 1
    try:
        MODE = CG.setup()
        SERVER = HttpServer()
        out(f"zelynic supermassive test (NIGHT-improve-11, {mode} mode)")
        out(f"  target cgroup fleet: {MODE}")
        out()
        env_ok = test_env()
        if not env_ok:
            out()
            out("  environment not suitable for zelynic — stopping here.")
        elif mode == "heavy":
            run_heavy(3.0)
        else:
            run_light(2.5)
        CG.cleanup()
        report_worker_faults()
        ok = final_report(start, mode,
                          "zelynic command surface: supermassive-verified on this machine.")
        exit_code = 0 if ok else 1
    except Exception as e:  # noqa: BLE001 - report, then still clean up
        out(f"  harness error: {type(e).__name__}: {e}")
        try:
            clear_all()
            CG.cleanup()
        except Exception:
            pass
        report_worker_faults()
        final_report(start, mode,
                     "zelynic command surface: supermassive-verified on this machine.")
        exit_code = 1
    finally:
        if SERVER:
            SERVER.stop()
    if args.json:
        print(json.dumps({
            "binary": lib.BINARY,
            "mode": mode,
            "cgroup_mode": MODE,
            "worker_faults": [{"error": msg, "count": n} for msg, n in WORKER_FAULTS],
            "results": RESULTS,
        }, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
