#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: the brutal matrix is one self-contained harness by design — every stage shares the cgroup fleet, the traffic engine, and the verdict plumbing, so splitting it means a module package, not a script
"""zelynic brutal stress test — the one-click flagship harness (NIGHT-master-2).

NIGHT-master-1 (limiter-depth-test.py) answers "is the limiter ACCURATE?"
with measured rate bands. This harness answers the owner's next question:
"does the WHOLE command surface survive brutal stress?" — one click sweeps
every policy family (strict / block / unstrict, single / multi / all)
across real target shapes with real traffic, real curl processes, and the
full rate range the parser accepts.

Design:

  * One click, two intensities: default light mode (~2 min, basic limiting
    sweep) and --heavy (the complete brutal matrix, 5+ minutes, long
    running until done). --self-test verifies the harness engine alone
    (no root, no zelynic, no BPF) so CI and containers can smoke it
    anywhere — the same cross-distro minimum as NIGHT-master-1: python3
    stdlib only, curl optional (its stages SKIP, the rest keeps working).
  * Traffic is loopback HTTP served by an in-process python server, so
    no external test server is ever needed. curl is the second traffic
    engine: real external processes pushed through the limiter, the same
    class of proof as the owner's manual browser tests.
  * Five dedicated cgroups (zelynic-brutal-a..e): the harness lives in
    'a' (its own loopback traffic is the single-target test bed); curl
    workers are exec-moved into b..e BEFORE their first socket exists
    (deterministic cgroup attribution, no spawn race), so strict-multi /
    block-multi group policies are measured across genuinely separate
    cgroups. On loopback the download direction is policed at the
    receiver's ingress (client cgroup) and the upload direction at the
    sender's egress — one dl-map hit and one ul-map hit per stream, so
    keeping the server cgroup unlimited makes multi-target measurement
    exact.
  * Rate range: the ladder walks the parser's full span — 1kb (the
    minimum) through 10mb and 1gb, up to 1tb (the maximum) — skipping any
    rung the hardware cannot feed (baseline < 2x rung): "up to 1 TB/s if
    hardware supports".
  * Every rate verdict is MEASURED (client / curl byte counters), then
    proven in-kernel through the status JSON (bytes_allowed /
    packets_dropped) — exactly the NIGHT-master-1 contract.
  * limit-all is exercised with --force in heavy mode only, briefly and
    at a generous rate: as root the harness's own cgroups are uid 0 and
    would otherwise be skipped as system apps. block-all is deliberately
    NOT exercised — blocking every app can sever the very session that
    runs the test.

Usage:
  sudo ./scripts/brutal-stress-test.sh                # light (~2 min)
  sudo ./scripts/brutal-stress-test.sh --heavy       # brutal (5+ min)
  python3 scripts/brutal-stress-test.py --self-test   # engine smoke, no root
  sudo ./scripts/brutal-stress-test.sh --binary ./zelynic
  sudo ./scripts/brutal-stress-test.sh --json

What it verifies (verdicts PASS / FAIL / SKIP, exit 1 on any FAIL):
  light: env + minimum specs, doctor, baseline, strict-single policy
         write, rate ladder (1kb/100kb/1mb/10mb), upload-only (-u),
         block-single zero goodput, unstrict-single (unlock) restores
         speed, curl burst download x4, curl upload, non-binding
         overhead, cleanup, dmesg
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
import threading
import time

CGROUP_ROOT = "/sys/fs/cgroup"
CG_NAMES = "abcde"
TEST_CGROUPS = [f"{CGROUP_ROOT}/zelynic-brutal-{n}" for n in CG_NAMES]
PIN_DIR = "/sys/fs/bpf/zelynic"
CHUNK = 256 * 1024
BLOCK_GOODPUT_CEIL = 64 * 1024  # bytes per window: "blocked" means ~zero
BAND_LO = 0.65
BAND_HI = 1.30
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

RESULTS = []
SERVER = None
CG = None
BINARY = ""
MODE = ""
CURL = shutil.which("curl")


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


def mbps(n):
    return f"{n * 8 / 1e6:.2f} Mbps"


def record(name, verdict, detail="", metrics=None):
    RESULTS.append(
        {"test": name, "verdict": verdict, "detail": detail, "metrics": metrics or {}}
    )
    mark = {"PASS": "  OK ", "FAIL": "  X  ", "SKIP": "  -- "}[verdict]
    out(f"{mark}{name}" + (f" — {detail}" if detail else ""))
    return verdict


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


# ── dedicated cgroup fleet ─────────────────────────────────────────────────

class CgroupSet:
    """Five dedicated cgroups; the harness process lives in the first.

    Same isolation contract as NIGHT-master-1's single test cgroup —
    zelynic polices by cgroup ID at the root, so child cgroups give the
    harness five independent test beds without touching the owner's
    session. When dedicated cgroups cannot be created, every name falls
    back to the current session cgroup and the multi-cgroup stages SKIP
    (single-cgroup stages still measure honestly).
    """

    def __init__(self):
        self.ids = {}
        self.paths = {}
        self.dedicated = False

    def setup(self):
        self._absorb_leftovers()
        try:
            os.mkdir(TEST_CGROUPS[0])
            with open(f"{TEST_CGROUPS[0]}/cgroup.procs", "w") as f:
                f.write(str(os.getpid()))
            cid = self._read_id(TEST_CGROUPS[0])
            if cid is None:
                self._leave(TEST_CGROUPS[0])
                raise OSError("cgroup.id unreadable")
            self.dedicated = True
            self.ids["a"] = cid
            self.paths["a"] = TEST_CGROUPS[0]
            for name, path in zip(CG_NAMES[1:], TEST_CGROUPS[1:]):
                os.mkdir(path)
                self.paths[name] = path
                c2 = self._read_id(path)
                if c2 is None:
                    raise OSError(f"cgroup.id unreadable for {path}")
                self.ids[name] = c2
            return f"dedicated fleet {TEST_CGROUPS[0]}..e"
        except OSError:
            self._cleanup_dirs()
        # Fallback: every name maps to the current session cgroup.
        path = self._self_cgroup_path()
        if not path:
            raise RuntimeError(
                "could not resolve a cgroup ID: cgroup v2 with the cgroup.id "
                "file is required (kernel 5.13+)"
            )
        cid = self._read_id(f"{CGROUP_ROOT}/{path}")
        if cid is None:
            raise RuntimeError("cgroup.id unreadable for the session cgroup")
        for name in CG_NAMES:
            self.ids[name] = cid
            self.paths[name] = f"{CGROUP_ROOT}/{path}"
        return (
            f"session cgroup /{path} (dedicated fleet not creatable — "
            "multi-cgroup stages will SKIP)"
        )

    @staticmethod
    def _read_id(path):
        try:
            with open(f"{path}/cgroup.id") as f:
                return int(f.read().strip()) & 0xFFFFFFFF
        except (OSError, ValueError):
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
        for path in TEST_CGROUPS:
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
        for path in TEST_CGROUPS:
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
        self._leave(TEST_CGROUPS[0])
        self._cleanup_dirs()
        return not any(os.path.isdir(p) for p in TEST_CGROUPS)


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


def py_download(window):
    """Read the /dl stream for `window` seconds; returns body bytes."""
    with http_get("/dl") as s:
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


def py_upload(window):
    """Stream zeros to /ul for `window` seconds; returns bytes written."""
    with socket.create_connection(("127.0.0.1", SERVER.port), timeout=10) as s:
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
    return curl_run(curl_cmd(window, "/dl"), window + 20)[0]


def curl_upload(window):
    # -T /dev/zero: an unsizeable character device forces a streaming
    # chunked upload — the classic curl upload-speed pattern. The URL
    # path is explicit so no filename gets appended. curl's 1s
    # Expect-100-continue pause is absorbed by the window.
    cmd = [
        CURL, "-s", "-o", "/dev/null", "-w", "%{size_upload}",
        "--max-time", f"{window}", "-T", "/dev/zero",
        f"http://127.0.0.1:{SERVER.port}/ul",
    ]
    return curl_run(cmd, window + 20)[0]


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


def spawn_in_cgroup(name, argv, timeout):
    """Run argv to completion inside cgroup `name`; returns (metric, err)."""
    try:
        p = popen_in_cgroup(name, argv)
    except OSError as e:
        return None, str(e)
    try:
        stdout, _ = p.communicate(timeout=timeout)
        metric = stdout.strip().splitlines()[-1] if stdout.strip() else ""
        try:
            return int(metric), ""
        except ValueError:
            return None, f"no metric ({metric[:60] or 'empty'})"
    except subprocess.TimeoutExpired:
        p.kill()
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


def band_check(name, measured_bps, configured_bps, extra=""):
    ratio = measured_bps / configured_bps if configured_bps else 0.0
    verdict = "PASS" if BAND_LO <= ratio <= BAND_HI else "FAIL"
    detail = (
        f"configured {fmt_bps(configured_bps)} ({mbps(configured_bps)}), "
        f"measured {fmt_bps(measured_bps)} ({ratio * 100:.1f}%)"
        + (f"; {extra}" if extra else "")
    )
    record(name, verdict, detail, {"measured_bps": round(measured_bps), "ratio": round(ratio, 3)})
    return verdict == "PASS"


def enforcement_proofs(label, got_bytes, name="a"):
    """Kernel-side proof under a binding limit: packets dropped and the
    BPF byte counter in agreement with the client's own count."""
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
        if allowed > 0 and got_bytes:
            ratio = allowed / got_bytes
            record(
                f"{label}: BPF accounting matches client bytes",
                "PASS" if 0.5 <= ratio <= 1.5 else "FAIL",
                f"bpf {allowed} vs client {got_bytes} ({ratio * 100:.1f}%)",
            )


# ── environment ────────────────────────────────────────────────────────────

def test_env():
    out()
    out("━━━ environment (minimum specs: kernel 5.13+, cgroup v2, BPF fs, root — docs/KERNEL_COMPATIBILITY.md) ━━━")
    out(f"  distro:   {pretty_name()}")
    out(f"  kernel:   {os.uname().release}  arch: {os.uname().machine}")
    out(f"  cpu:      {cpu_model()}")
    out(f"  python:   {sys.version.split()[0]}  curl: {CURL or 'not found (curl stages will SKIP)'}")
    out(f"  binary:   {BINARY}")
    out(f"  cgroups:  {MODE}")
    ok = True
    ok = record(
        "cgroup v2 unified hierarchy", "PASS" if cgroup2_mounted() else "FAIL",
        CGROUP_ROOT if cgroup2_mounted() else f"{CGROUP_ROOT} is not cgroup2fs",
    ) == "PASS" and ok
    ok = record(
        "cgroup.id resolution (kernel 5.13+)", "PASS" if CG.ids.get("a") else "FAIL",
        f"cgroup id {CG.ids.get('a')}",
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
        "doctor: eBPF support", "PASS" if supported else "FAIL", warnings or "no warnings"
    )


def test_baseline(window):
    got = py_download(window)
    bps = got / window
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
    clear_all()
    return verdict == "PASS"


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
        rates = []
        for _ in range(windows_per_rung):
            rates.append(py_download(window) / window)
        measured = sum(rates) / len(rates)
        if not band_check(name, measured, bps):
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
        totals[i] = curl_download(window)

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
    sent = curl_upload(window)
    if sent is None:
        record("curl upload: external upload engine", "FAIL", "curl produced no metric")
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
    """The brutal sweep: every cgroup on the machine, briefly, --force so
    the harness's own root-owned cgroups are included."""
    name = "limit-all --force: machine-wide sweep"
    if baseline and baseline < 2e6:
        return record(name, "SKIP", "baseline too low")
    # Keep sleepers resident in b..e so the sweep has live cgroups to find.
    sleepers = [spawn_bg_in_cgroup(n, ["sleep", "30"]) for n in "bcde"]
    try:
        rc, stdout, stderr = run_zel(["limit-all", "--force", "2mb"])
        if rc != 0:
            return record(name, "FAIL", f"exit {rc}: {(stderr or stdout).strip()[:200]}")
        entry = limit_entry(status_json(), CG.ids["a"])
        if entry is None or entry.get("download_bps") != 2_000_000:
            clear_all()
            return record(name, "FAIL", f"harness cgroup row wrong: {entry}")
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
    ok_band = all(BAND_LO <= r / rate_bps <= BAND_HI for r in rates)
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
    cg_left = [p for p in TEST_CGROUPS if os.path.isdir(p)]
    ok_all = record(
        "cleanup: test cgroups removed", "PASS" if not cg_left else "FAIL",
        ", ".join(cg_left) if cg_left else "",
    ) == "PASS" and ok_all
    return ok_all


def test_dmesg():
    try:
        p = subprocess.run(["dmesg", "--color=never"], capture_output=True,
                           text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return record("dmesg: kernel log clean", "SKIP", "dmesg unavailable or restricted")
    lines = p.stdout.splitlines()[-200:]
    bad = [
        line for line in lines
        if any(k in line.lower() for k in ("bpf", "zelynic"))
        and any(k in line.lower() for k in ("error", "fail", "warn", "bug", "oops"))
    ]
    return record(
        "dmesg: kernel log clean", "PASS" if not bad else "FAIL",
        "; ".join(bad[:3]) if bad else "no BPF errors in the last 200 lines",
    )


# ── engine self-test (no root, no zelynic, no BPF) ─────────────────────────

def self_test():
    """Verify the harness's own measurement engine anywhere — a CI runner,
    a container, or a friend's laptop — before trusting its verdicts."""
    global SERVER
    out("zelynic brutal stress test — engine self-test (no root, no zelynic, no BPF)")
    start = time.perf_counter()

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
    SERVER.stop()
    counts = {v: sum(1 for r in RESULTS if r["verdict"] == v) for v in ("PASS", "FAIL", "SKIP")}
    out()
    out("━━━ self-test verdict ━━━")
    out(f"  {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped"
        f" — {time.perf_counter() - start:.1f}s")
    return counts["FAIL"] == 0


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
    out("Or point at one: sudo ./scripts/brutal-stress-test.sh --binary ./zelynic")
    return False


def final_report(start, mode):
    elapsed = time.perf_counter() - start
    counts = {v: sum(1 for r in RESULTS if r["verdict"] == v) for v in ("PASS", "FAIL", "SKIP")}
    out()
    out("━━━ verdict ━━━")
    out(
        f"  {counts['PASS']} passed, {counts['FAIL']} failed, "
        f"{counts['SKIP']} skipped — {mode} mode, {elapsed:.0f}s total"
    )
    if counts["FAIL"] == 0:
        out("  zelynic command surface: brutal-verified on this machine.")
    else:
        out("  FAILURES present — see the marked rows above; run with --json for")
        out("  machine-readable output and file the numbers in CROSS_DISTRO_RESULTS.")
    return counts["FAIL"] == 0


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
    global SERVER, CG, MODE, BAND_LO, BAND_HI
    ap = argparse.ArgumentParser(
        prog="brutal-stress-test",
        description="zelynic one-click brutal stress test (NIGHT-master-2)",
    )
    ap.add_argument("--heavy", action="store_true",
                    help="the complete brutal matrix (5+ min; default is light ~2 min)")
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
        BAND_LO, BAND_HI = lo, hi
    except ValueError:
        out("--band expects lo,hi (e.g. 0.65,1.30)")
        return 2

    if os.geteuid() != 0:
        out("This test programs the kernel datapath — run with sudo.")
        return 2
    if not resolve_binary(args.binary):
        return 2

    mode = "heavy" if args.heavy else "light"
    start = time.perf_counter()
    CG = CgroupSet()
    exit_code = 1
    try:
        MODE = CG.setup()
        SERVER = HttpServer()
        out(f"zelynic brutal stress test (NIGHT-master-2, {mode} mode)")
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
        ok = final_report(start, mode)
        exit_code = 0 if ok else 1
    except Exception as e:  # noqa: BLE001 - report, then still clean up
        out(f"  harness error: {e}")
        try:
            clear_all()
            CG.cleanup()
        except Exception:
            pass
        final_report(start, mode)
        exit_code = 1
    finally:
        if SERVER:
            SERVER.stop()
    if args.json:
        print(json.dumps({
            "binary": BINARY,
            "mode": mode,
            "cgroup_mode": MODE,
            "results": RESULTS,
        }, indent=2))
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
