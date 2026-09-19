#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic limiter depth test — flagship cross-distro stress harness.

Design (NIGHT-master-1): the owner needs ONE script to depth-stress the
limiter on any machine — own hardware, a VirtualBox, or a friend's
ubuntu/arch/gentoo install — and get a peak-performance / stability /
LTS verdict with minimum requirements. That rules out external
speedtest servers (flaky, metered, not always reachable from a VM) and
rules out anything beyond the python3 standard library.

How it stays self-contained and honest:

  * Traffic is generated on loopback by an in-process raw-socket server
    (chunked GET stream for downloads, PUT-discard for uploads). No
    external network, no disk writes, no third-party tools.
  * The whole test process is moved into a dedicated cgroup
    (/sys/fs/cgroup/zelynic-depth), so ONLY test traffic is policed —
    the owner's session keeps full speed and the measurements stay
    clean. If a dedicated cgroup cannot be created, the harness falls
    back to the current session cgroup and says so (measurements then
    include any other session traffic; rate verdicts are still taken
    from client-side byte counters, which only the test controls).
  * Limits are applied by cgroup ID (the exact Target::CgroupId path
    zelynic itself exposes), so target resolution is deterministic —
    no comm-majority ambiguity, no /proc walk luck.
  * Every rate verdict is MEASURED (bytes over time at the client or
    server socket), then cross-checked against zelynic's own BPF
    counters from `status --print-json` (bytes_allowed / packets
    dropped) — proving the enforcement actually ran in the kernel,
    not just that a policy row exists.

Usage:
  sudo ./scripts/limiter-depth-test.sh               # full run (~2 min)
  sudo ./scripts/limiter-depth-test.sh --quick       # fast pass (~45s)
  sudo ./scripts/limiter-depth-test.sh --json        # machine-readable
  sudo ./scripts/limiter-depth-test.sh --binary ./zelynic
  ZELYNIC_BINARY=./zelynic sudo -E ./scripts/limiter-depth-test.sh

What it verifies (verdicts PASS / FAIL / SKIP, exit 1 on any FAIL):
  env      cgroup v2, cgroup.id, BPF fs, binary, doctor eBPF support
  baseline unlimited loopback throughput (the measurement ceiling)
  policy   strict-single writes the exact policy (status JSON fields)
  rate     enforced download rate at 100kb / 1mb / 10mb (adaptive skip)
  upload   enforced upload rate (-u only) at 1mb
  drops    packets_dropped > 0 under a binding limit (kernel proof)
  cross    BPF bytes_allowed vs client-measured bytes agreement
  multi    5 parallel connections aggregate under one shared limit
  sustain  20s steady-state: per-window rate + drift guard
  overhead non-binding-policy throughput vs baseline (BPF cost)
  reload   25 rate-change cycles verified through the status JSON
  cleanup  unstrict-all leaves zero pins, no pid file, no test cgroup
  dmesg    kernel log stayed clean of BPF errors during the run
"""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

CGROUP_ROOT = "/sys/fs/cgroup"
TEST_CGROUP = os.path.join(CGROUP_ROOT, "zelynic-depth")
PIN_DIR = "/sys/fs/bpf/zelynic"
PID_FILE = "/tmp/zelynic.pid"
CHUNK = 256 * 1024
DOWNLOAD_WINDOW = 12.0   # seconds, full mode
UPLOAD_WINDOW = 10.0
MULTI_WINDOW = 8.0
SUSTAIN_WINDOWS = 4
SUSTAIN_WINDOW = 5.0
BASELINE_WINDOW = 3.0
OVERHEAD_WINDOW = 4.0
RELOAD_CYCLES = 25
MULTI_CLIENTS = 5
# Verdict band: measured/configured must land in [lo, hi]. The floor
# absorbs TCP back-off under drop-based enforcement; the ceiling
# absorbs the token-bucket's initial burst amortized over the window.
# Field data (CROSS_DISTRO_RESULTS.md) lands ~0.9.
BAND_LO = 0.65
BAND_HI = 1.30

RESULTS = []
SERVER = None
CG = None
BINARY = ""
MODE = ""


# ── small helpers ───────────────────────────────────────────────────────────

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


def bps_to_rate_str(bps):
    """Inverse of zelynic's rate parser (decimal SI: kb=1000, mb=1e6)."""
    if bps >= 1e9:
        return f"{round(bps / 1e9)}gb"
    if bps >= 1e6:
        return f"{round(bps / 1e6)}mb"
    return f"{round(bps / 1e3)}kb"


def record(name, verdict, detail="", metrics=None):
    RESULTS.append(
        {"test": name, "verdict": verdict, "detail": detail, "metrics": metrics or {}}
    )
    mark = {"PASS": "  OK ", "FAIL": "  X  ", "SKIP": "  -- "}[verdict]
    out(f"{mark}{name}" + (f" — {detail}" if detail else ""))
    return verdict


def run_zel(args, timeout=30):
    """Run the zelynic binary; returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            [BINARY] + args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
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


# ── environment fingerprint ────────────────────────────────────────────────

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
    # stat -fc %T equivalent without shelling out: read /proc/mounts.
    try:
        with open("/proc/mounts", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == CGROUP_ROOT:
                    return parts[2] == "cgroup2"
    except OSError:
        pass
    return False


# ── dedicated test cgroup (fallback: current session cgroup) ──────────────

class TestCgroup:
    """Move the whole test process into an isolated cgroup.

    zelynic attaches its cgroup_skb programs at the cgroup v2 root and
    keys policy by cgroup ID, so a child cgroup's traffic is policed
    without touching anything else on the machine. If mkdir is not
    permitted, fall back to the current cgroup (measurements then
    include unrelated session traffic; the report says so).
    """

    def __init__(self):
        self.dedicated = False
        self.id = None
        self.path = ""

    def setup(self):
        # Self-heal a leftover from a crashed previous run.
        if os.path.isdir(TEST_CGROUP):
            self._absorb_leftover()
        try:
            os.mkdir(TEST_CGROUP)
            with open(os.path.join(TEST_CGROUP, "cgroup.procs"), "w") as f:
                f.write(str(os.getpid()))
            cgid = self._read_id(TEST_CGROUP)
            if cgid is not None:
                self.dedicated = True
                self.path = TEST_CGROUP
                self.id = cgid
                return "dedicated cgroup " + TEST_CGROUP
            # cgroup.id unreadable: undo and fall through to fallback.
            self._leave_dedicated()
        except OSError:
            pass
        # Fallback: resolve the cgroup this process already lives in.
        path = self._self_cgroup_path()
        if path:
            cgid = self._read_id(os.path.join(CGROUP_ROOT, path))
            if cgid is not None:
                self.dedicated = False
                self.path = path
                self.id = cgid
                return (
                    "session cgroup /{} (dedicated cgroup not creatable — "
                    "unrelated session traffic joins the counters)".format(path)
                )
        raise RuntimeError(
            "could not resolve a cgroup ID: cgroup v2 with the cgroup.id "
            "file is required (kernel 5.13+)"
        )

    def _absorb_leftover(self):
        # Move any survivor processes to the root cgroup, then rmdir.
        try:
            procs = os.path.join(TEST_CGROUP, "cgroup.procs")
            if os.path.exists(procs):
                with open(procs) as f:
                    pids = [p for p in f.read().split() if p]
                for pid in pids:
                    try:
                        with open(os.path.join(CGROUP_ROOT, "cgroup.procs"), "w") as dst:
                            dst.write(pid)
                    except OSError:
                        pass
            for _ in range(3):
                try:
                    os.rmdir(TEST_CGROUP)
                    return
                except OSError:
                    time.sleep(0.3)
        except OSError:
            pass

    def _leave_dedicated(self):
        try:
            with open(os.path.join(CGROUP_ROOT, "cgroup.procs"), "w") as f:
                f.write(str(os.getpid()))
        except OSError:
            pass
        for _ in range(3):
            try:
                os.rmdir(TEST_CGROUP)
                return
            except OSError:
                time.sleep(0.3)

    @staticmethod
    def _read_id(path):
        try:
            with open(os.path.join(path, "cgroup.id")) as f:
                return int(f.read().strip()) & 0xFFFFFFFF
        except (OSError, ValueError):
            return None

    @staticmethod
    def _self_cgroup_path():
        # The v2 entry is the "0::" line — hybrid layouts list many
        # v1 lines first, so scanning for the prefix is the robust read.
        try:
            with open("/proc/self/cgroup", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("0::"):
                        return line[3:].strip()
        except OSError:
            pass
        return None

    def cleanup(self):
        """Idempotent: safe to call from both the test and the main flow."""
        if not self.dedicated or not os.path.isdir(TEST_CGROUP):
            return True
        self._leave_dedicated()
        return not os.path.isdir(TEST_CGROUP)


# ── loopback traffic engine ────────────────────────────────────────────────

class TrafficServer:
    """Threaded raw-socket server on 127.0.0.1.

    Protocol (one line, then a byte stream):
      "GET\n"  -> server streams 256 KiB chunks until the peer closes
      "PUT\n"  -> peer streams; server discards, then replies with the
                  authoritative byte count as a final line
    """

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.bytes_sent = 0       # GET direction (server egress)
        self.bytes_received = 0   # PUT direction (server ingress)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._acceptor = threading.Thread(target=self._accept_loop, daemon=True)
        self._acceptor.start()

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _read_command(conn):
        """Read the one-line command; return (command, leftover).

        TCP has no message boundary, so a single recv can return the
        command AND the first bytes of a PUT stream that coalesced with
        it. The bytes after the newline are stream payload: returning
        them as `leftover` keeps the server-side count in exact
        agreement with what the client wrote, byte for byte.
        """
        buf = b""
        while b"\n" not in buf and len(buf) < 8:
            try:
                data = conn.recv(8 - len(buf))
            except OSError:
                return b"", b""
            if not data:
                return b"", b""
            buf += data
        if b"\n" in buf:
            idx = buf.index(b"\n")
            return buf[:idx], buf[idx + 1:]
        return buf, b""

    def _serve(self, conn):
        try:
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            cmd, leftover = self._read_command(conn)
            if cmd.startswith(b"GET"):
                blob = b"\x00" * CHUNK
                sent = 0
                try:
                    while True:
                        conn.sendall(blob)
                        sent += CHUNK
                except OSError:
                    pass  # peer closed the window: normal termination
                with self._lock:
                    self.bytes_sent += sent
            elif cmd.startswith(b"PUT"):
                got = len(leftover)
                while True:
                    try:
                        data = conn.recv(CHUNK)
                    except OSError:
                        break
                    if not data:
                        break
                    got += len(data)
                with self._lock:
                    self.bytes_received += got
                try:
                    conn.sendall(f"{got}\n".encode())
                except OSError:
                    pass
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


def download(window, port):
    """Read from the server for `window` seconds; returns bytes received."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
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
                data = s.recv(CHUNK)
            except socket.timeout:
                break
            except OSError:
                break
            if not data:
                break
            total += len(data)
    return total


def upload(window, port):
    """Write to the server for `window` seconds.

    Returns (client_bytes, server_bytes, elapsed): the server's reply
    line is the authoritative count, elapsed covers the full stream
    including the tail drain, so the rate is honest end to end.
    """
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        start = time.perf_counter()
        s.sendall(b"PUT\n")
        blob = b"\x00" * CHUNK
        sent = 0
        deadline = start + window
        while time.perf_counter() < deadline:
            try:
                s.sendall(blob)
                sent += CHUNK
            except OSError:
                break
        s.shutdown(socket.SHUT_WR)
        server_count = None
        s.settimeout(30)
        try:
            while True:
                data = s.recv(64)
                if not data:
                    break
                text = data.decode(errors="replace").strip()
                if text.isdigit():
                    server_count = int(text)
        except OSError:
            pass
        elapsed = time.perf_counter() - start
    return sent, server_count, elapsed


def parallel_download(window, clients, port):
    threads = []
    totals = [0] * clients

    def worker(i):
        totals[i] = download(window, port)

    for i in range(clients):
        t = threading.Thread(target=worker, args=(i,))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return sum(totals)


# ── test stages ─────────────────────────────────────────────────────────────

def test_env():
    out()
    out("━━━ environment ━━━")
    kernel = os.uname().release
    out(f"  distro:   {pretty_name()}")
    out(f"  kernel:   {kernel}  arch: {os.uname().machine}")
    out(f"  cpu:      {cpu_model()}")
    out(f"  python:   {sys.version.split()[0]}")
    out(f"  binary:   {BINARY}")
    out(f"  cgroup:   {MODE}")
    ok = True
    ok = record(
        "cgroup v2 unified hierarchy", "PASS" if cgroup2_mounted() else "FAIL",
        CGROUP_ROOT if cgroup2_mounted() else f"{CGROUP_ROOT} is not cgroup2fs",
    ) == "PASS" and ok
    has_id_file = os.path.exists(os.path.join(CG.path if CG.dedicated else CGROUP_ROOT, "cgroup.id")) or CG.id is not None
    ok = record(
        "cgroup.id resolution (kernel 5.13+)", "PASS" if has_id_file else "FAIL",
        f"cgroup id {CG.id}",
    ) == "PASS" and ok
    ok = record(
        "BPF filesystem mounted", "PASS" if os.path.isdir(PIN_DIR) else "FAIL",
        PIN_DIR,
    ) == "PASS" and ok
    if os.geteuid() != 0:
        record("root privilege", "FAIL", "re-run with sudo — BPF needs CAP_BPF")
        return False
    record("root privilege", "PASS")
    return ok


def test_doctor():
    rc, stdout, _ = run_zel(["doctor", "--print-json"])
    if rc != 0:
        return record("doctor: eBPF support", "FAIL", f"exit {rc}")
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError:
        return record("doctor: eBPF support", "FAIL", "doctor JSON could not be parsed")
    supported = bool(doc.get("ebpf_supported"))
    warnings = "; ".join(doc.get("warnings", []))
    return record(
        "doctor: eBPF support",
        "PASS" if supported else "FAIL",
        warnings or "no warnings",
    )


def test_baseline(window):
    bytes_ = download(window, SERVER.port)
    bps = bytes_ / window
    record(
        "baseline: unlimited loopback throughput",
        "PASS",
        f"{fmt_bps(bps)} over {window:.1f}s",
        {"bps": round(bps)},
    )
    return bps


def apply_and_verify(rate_str, expect_dl, expect_ul):
    """Apply strict-single to the test cgroup and verify the write."""
    target = str(CG.id)
    rc, stdout, stderr = run_zel(["strict-single", target, rate_str])
    if rc != 0:
        return False, f"strict-single exit {rc}: {(stderr or stdout).strip()[:200]}"
    doc = status_json()
    entry = limit_entry(doc, CG.id)
    if entry is None:
        return False, "no limit row for the test cgroup in status JSON"
    if expect_dl is not None and entry.get("download_bps") != expect_dl:
        return False, f"download_bps {entry.get('download_bps')} != {expect_dl}"
    if expect_ul is not None and entry.get("upload_bps") != expect_ul:
        return False, f"upload_bps {entry.get('upload_bps')} != {expect_ul}"
    if doc.get("watchdog") not in ("enforcing", "active"):
        return False, f"watchdog state {doc.get('watchdog')!r}"
    return True, entry


def clear_limits():
    rc, _, _ = run_zel(["unstrict-all"])
    return rc == 0


def test_policy_write():
    ok, payload = apply_and_verify("100kb", 100_000, 100_000)
    verdict = record(
        "policy write: strict-single 100kb lands in the kernel maps",
        "PASS" if ok else "FAIL",
        "" if ok else payload,
    )
    return verdict == "PASS"


def band_check(name, measured_bps, configured_bps, extra=""):
    ratio = measured_bps / configured_bps if configured_bps else 0.0
    verdict = "PASS" if BAND_LO <= ratio <= BAND_HI else "FAIL"
    detail = (
        f"configured {fmt_bps(configured_bps)}, measured {fmt_bps(measured_bps)} "
        f"({ratio * 100:.1f}%)" + (f"; {extra}" if extra else "")
    )
    record(name, verdict, detail, {"measured_bps": round(measured_bps), "ratio": round(ratio, 3)})
    return verdict == "PASS"


def test_rate(rate_bps, window, baseline, label):
    if baseline and baseline < 2 * rate_bps:
        return record(
            f"rate {label}: enforced download",
            "SKIP",
            f"baseline {fmt_bps(baseline)} too close to {fmt_bps(rate_bps)}",
        )
    rate_str = bps_to_rate_str(rate_bps)
    ok, payload = apply_and_verify(rate_str, rate_bps, rate_bps)
    if not ok:
        return record(f"rate {label}: enforced download", "FAIL", payload)
    time.sleep(0.5)  # let the bucket reach steady state
    got = download(window, SERVER.port)
    measured = got / window
    name = f"rate {label}: enforced download"
    passed = band_check(name, measured, rate_bps)
    # Kernel-side proof: under a binding limit, packets must have been
    # dropped, and the BPF byte counter must agree with the client.
    entry = limit_entry(status_json(), CG.id)
    if entry:
        dropped = entry.get("packets_dropped", 0)
        record(
            f"rate {label}: kernel drops engaged (packets_dropped > 0)",
            "PASS" if dropped > 0 else "FAIL",
            f"{dropped} packets dropped, {entry.get('bytes_allowed', 0)} bytes allowed",
        )
        if CG.dedicated:
            allowed = entry.get("bytes_allowed", 0)
            if allowed > 0:
                ratio = allowed / got if got else 0.0
                record(
                    f"rate {label}: BPF accounting matches client bytes",
                    "PASS" if 0.5 <= ratio <= 1.5 else "FAIL",
                    f"bpf {allowed} vs client {got} ({ratio * 100:.1f}%)",
                )
    clear_limits()
    return passed


def test_upload(rate_bps, window, baseline):
    if baseline and baseline < 2 * rate_bps:
        return record("upload rate: enforced (-u only)", "SKIP",
                      f"baseline {fmt_bps(baseline)} too close")
    rate_str = bps_to_rate_str(rate_bps)
    rc, stdout, stderr = run_zel(["strict-single", str(CG.id), "-u", rate_str])
    if rc != 0:
        return record("upload rate: enforced (-u only)", "FAIL",
                      f"exit {rc}: {(stderr or stdout).strip()[:200]}")
    doc = status_json()
    entry = limit_entry(doc, CG.id)
    if entry is None or entry.get("upload_bps") != rate_bps or entry.get("download_bps") is not None:
        return record("upload rate: enforced (-u only)", "FAIL",
                      f"policy row wrong: {entry}")
    time.sleep(0.5)
    client_bytes, server_bytes, elapsed = upload(window, SERVER.port)
    truth = server_bytes if server_bytes is not None else client_bytes
    passed = band_check("upload rate: enforced (-u only)", truth / elapsed, rate_bps)
    entry = limit_entry(status_json(), CG.id)
    if entry and entry.get("packets_dropped", 0) > 0:
        record("upload rate: kernel drops engaged", "PASS",
               f"{entry['packets_dropped']} packets dropped")
    else:
        record("upload rate: kernel drops engaged", "FAIL",
               "no dropped packets under a binding upload limit")
    clear_limits()
    return passed


def test_multi(rate_bps, window, baseline):
    if baseline and baseline < 2 * rate_bps:
        return record("multi-connection: shared limit aggregate", "SKIP",
                      "baseline too low")
    rate_str = bps_to_rate_str(rate_bps)
    ok, payload = apply_and_verify(rate_str, rate_bps, rate_bps)
    if not ok:
        return record("multi-connection: shared limit aggregate", "FAIL", payload)
    time.sleep(0.5)
    total = parallel_download(window, MULTI_CLIENTS, SERVER.port)
    passed = band_check(
        f"multi-connection: {MULTI_CLIENTS} clients, one shared limit",
        total / window, rate_bps,
    )
    clear_limits()
    return passed


def test_sustain(rate_bps, windows, window, baseline):
    if baseline and baseline < 2 * rate_bps:
        return record("sustain: steady state + drift guard", "SKIP",
                      "baseline too low")
    rate_str = bps_to_rate_str(rate_bps)
    ok, payload = apply_and_verify(rate_str, rate_bps, rate_bps)
    if not ok:
        return record("sustain: steady state + drift guard", "FAIL", payload)
    time.sleep(0.5)
    rates = []
    for i in range(windows):
        got = download(window, SERVER.port)
        rates.append(got / window)
    ok_band = all(BAND_LO <= r / rate_bps <= BAND_HI for r in rates)
    drift = min(rates) / max(rates) if max(rates) else 0.0
    verdict = "PASS" if (ok_band and drift >= 0.5) else "FAIL"
    record(
        "sustain: steady state + drift guard",
        verdict,
        "; ".join(f"w{i + 1} {fmt_bps(r)}" for i, r in enumerate(rates))
        + f" — drift floor {drift * 100:.0f}%",
        {"rates": [round(r) for r in rates], "drift": round(drift, 3)},
    )
    clear_limits()
    return verdict == "PASS"


def test_overhead(baseline, window):
    if baseline and baseline >= 300e9:
        return record("overhead: non-binding policy cost", "SKIP",
                      "baseline beyond the 1 TB/s policy ceiling")
    # Whole-GB multiples only: the generated rate string and the
    # expected bps stay in exact agreement (10gb -> 10_000_000_000).
    non_binding_gb = min(900, max(10, round((3 * baseline if baseline else 10e9) / 1e9)))
    non_binding = non_binding_gb * 1e9
    rate_str = bps_to_rate_str(non_binding)
    ok, payload = apply_and_verify(rate_str, int(non_binding), int(non_binding))
    if not ok:
        return record("overhead: non-binding policy cost", "FAIL", payload)
    time.sleep(0.3)
    got = download(window, SERVER.port)
    limited = got / window
    clear_limits()
    if not baseline:
        return record("overhead: non-binding policy cost", "SKIP", "no baseline")
    drop_pct = (baseline - limited) / baseline * 100 if baseline else 0.0
    verdict = "PASS" if drop_pct <= 30.0 else "FAIL"
    record(
        "overhead: non-binding policy cost",
        verdict,
        f"baseline {fmt_bps(baseline)} vs {fmt_bps(limited)} "
        f"({non_binding / 1e9:.0f} GB/s policy) — {drop_pct:+.1f}%",
        {"limited_bps": round(limited), "drop_pct": round(drop_pct, 2)},
    )
    return verdict == "PASS"


def test_reload(cycles):
    rates = ["100kb", "500kb"]
    mismatches = 0
    apply_rc_fail = 0
    for i in range(cycles):
        rate_str = rates[i % 2]
        expect = 100_000 if rate_str == "100kb" else 500_000
        ok, _ = apply_and_verify(rate_str, expect, expect)
        if not ok:
            mismatches += 1
    verdict = "PASS" if mismatches == 0 else "FAIL"
    record(
        f"reload: {cycles} rate-change cycles through pinned maps",
        verdict,
        f"{cycles - mismatches}/{cycles} cycles verified via status JSON",
    )
    return verdict == "PASS"


def test_cleanup():
    ok_all = True
    rc, _, _ = run_zel(["unstrict-all"])
    time.sleep(0.5)
    ok_all = record(
        "cleanup: unstrict-all exits 0", "PASS" if rc == 0 else "FAIL",
        f"exit {rc}",
    ) == "PASS" and ok_all
    pins_left = 0
    if os.path.isdir(PIN_DIR):
        pins_left = len(os.listdir(PIN_DIR))
    ok_all = record(
        "cleanup: zero BPF pins left",
        "PASS" if pins_left == 0 else "FAIL",
        f"{pins_left} entries in {PIN_DIR}",
    ) == "PASS" and ok_all
    pid_left = os.path.exists(PID_FILE)
    ok_all = record(
        "cleanup: no pid file left",
        "PASS" if not pid_left else "FAIL",
        PID_FILE if pid_left else "",
    ) == "PASS" and ok_all
    # Leave the dedicated cgroup before asserting it is gone (the
    # helper is idempotent, so the main-flow call stays safe).
    CG.cleanup()
    cg_left = os.path.isdir(TEST_CGROUP)
    ok_all = record(
        "cleanup: test cgroup removed",
        "PASS" if not cg_left else "FAIL",
        TEST_CGROUP if cg_left else "",
    ) == "PASS" and ok_all
    return ok_all


def test_dmesg():
    try:
        p = subprocess.run(["dmesg", "--color=never"], capture_output=True,
                           text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return record("dmesg: kernel log clean", "SKIP",
                      "dmesg unavailable or restricted")
    lines = p.stdout.splitlines()[-200:]
    bad = [
        line for line in lines
        if any(k in line.lower() for k in ("bpf", "zelynic"))
        and any(k in line.lower() for k in ("error", "fail", "warn", "bug", "oops"))
    ]
    return record(
        "dmesg: kernel log clean",
        "PASS" if not bad else "FAIL",
        "; ".join(bad[:3]) if bad else "no BPF errors in the last 200 lines",
    )


# ── orchestration ───────────────────────────────────────────────────────────

def resolve_binary(explicit):
    global BINARY
    candidates = []
    if explicit:
        candidates.append(explicit)
    if os.environ.get("ZELYNIC_BINARY"):
        candidates.append(os.environ["ZELYNIC_BINARY"])
    found = shutil.which("zelynic")
    if found:
        candidates.append(found)
    candidates += ["./zelynic", "./target/release/zelynic"]
    for cand in candidates:
        if cand and os.path.isfile(cand) and os.access(cand, os.X_OK):
            BINARY = cand
            return True
    out("zelynic binary not found. Tried: " + ", ".join(candidates))
    out("Build it first:  cargo build --release --features ebpf")
    out("Or point at one: sudo ./scripts/limiter-depth-test.sh --binary ./zelynic")
    return False


def final_report(start):
    elapsed = time.perf_counter() - start
    counts = {v: sum(1 for r in RESULTS if r["verdict"] == v) for v in ("PASS", "FAIL", "SKIP")}
    out()
    out("━━━ verdict ━━━")
    out(
        f"  {counts['PASS']} passed, {counts['FAIL']} failed, "
        f"{counts['SKIP']} skipped — {elapsed:.0f}s total"
    )
    if counts["FAIL"] == 0:
        out("  zelynic limiter: depth-verified on this machine (peak, stable, clean).")
    else:
        out("  FAILURES present — see the marked rows above; run with --json for")
        out("  machine-readable output and file the numbers in CROSS_DISTRO_RESULTS.")
    return counts["FAIL"] == 0


def main():
    global SERVER, CG, MODE, BAND_LO, BAND_HI
    ap = argparse.ArgumentParser(
        prog="limiter-depth-test",
        description="zelynic limiter depth stress test (NIGHT-master-1)",
    )
    ap.add_argument("--binary", help="path to the zelynic binary")
    ap.add_argument("--quick", action="store_true", help="shorter windows, fewer cycles")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--band", default=f"{BAND_LO},{BAND_HI}",
                    help="verdict band as lo,hi ratios (default 0.65,1.30)")
    args = ap.parse_args()

    try:
        lo, hi = (float(x) for x in args.band.split(","))
        BAND_LO, BAND_HI = lo, hi
    except ValueError:
        out("--band expects lo,hi (e.g. 0.65,1.30)")
        return 2

    if os.geteuid() != 0:
        out("This test programs the kernel datapath — run with sudo.")
        return 2
    if not resolve_binary(args.binary):
        return 2

    quick = args.quick
    if quick:
        globals()["DOWNLOAD_WINDOW"] = 6.0
        globals()["UPLOAD_WINDOW"] = 5.0
        globals()["MULTI_WINDOW"] = 4.0
        globals()["SUSTAIN_WINDOWS"] = 3
        globals()["SUSTAIN_WINDOW"] = 3.0
        globals()["BASELINE_WINDOW"] = 1.5
        globals()["OVERHEAD_WINDOW"] = 2.0
        globals()["RELOAD_CYCLES"] = 10

    start = time.perf_counter()
    CG = TestCgroup()
    exit_code = 1
    try:
        MODE = CG.setup()
        SERVER = TrafficServer()
        out("zelynic limiter depth test (NIGHT-master-1)")
        out(f"  target cgroup: {CG.id} via {MODE}")
        out()

        env_ok = test_env()
        if not env_ok:
            out()
            out("  environment not suitable for zelynic — stopping here.")
        else:
            test_doctor()
            baseline = test_baseline(BASELINE_WINDOW)
            test_policy_write()
            test_rate(100_000, DOWNLOAD_WINDOW, baseline, "100kb")
            test_rate(1_000_000, DOWNLOAD_WINDOW, baseline, "1mb")
            test_rate(10_000_000, DOWNLOAD_WINDOW, baseline, "10mb")
            test_upload(1_000_000, UPLOAD_WINDOW, baseline)
            test_multi(2_000_000, MULTI_WINDOW, baseline)
            test_sustain(1_000_000, SUSTAIN_WINDOWS, SUSTAIN_WINDOW, baseline)
            test_overhead(baseline, OVERHEAD_WINDOW)
            test_reload(RELOAD_CYCLES)
            test_cleanup()
            test_dmesg()
        CG.cleanup()
        ok = final_report(start)
        exit_code = 0 if ok else 1
    except Exception as e:  # noqa: BLE001 - report, then still clean up
        out(f"  harness error: {e}")
        try:
            clear_limits()
            CG.cleanup()
        except Exception:
            pass
        final_report(start)
        exit_code = 1
    finally:
        if SERVER:
            SERVER.stop()
    if args.json:
        print(json.dumps({
            "binary": BINARY,
            "cgroup_mode": MODE,
            "results": RESULTS,
        }, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
