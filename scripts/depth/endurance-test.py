#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic endurance test — the ultra-long-horizon audit harness (NIGHT-blade-6).

Design: the owner's blade-6 ask is a depth audit for ULTRA LONG
ENDURANCE — no memory leaks, no overhead creep, no regressions, no
fatal surprises across the weeks a pinned enforcement or a days-long
monitor session can live. A wall-clock soak cannot prove that in CI
time, so this harness AMPLIFIES the two endurance clocks instead:

  * The LTS-budget clock (the pinned maps). Every apply/unstrict
    cycle churns slots in the 1024-entry policy/bucket/stats maps
    and the 256-entry group-bucket map. A leak of even ONE slot per
    cycle is fatal on a long-lived host (the map fills, new applies
    fail). The default run turns 300 cycles — 5 slots a single
    round, 2 more a group round — through maps capped at 1024/256,
    so ANY per-cycle slot leak exhausts a cap mid-run and the next
    apply FAILS LOUDLY (the maps' own fail-loud contract, turned
    into the proof). Every odd round is a strict-multi GROUP round
    (two traffic-bearing cgroups under one shared bucket), so the
    lts-7 group-reclaim path churns 300 group slots against its
    256 cap — the same mathematical proof for the smallest map.
    Each round also rides a full BPF load/pin + unpin/unload cycle,
    so pin residue and load churn are exercised 300 times over.
  * The monitor clock (the userspace TUI). A live `zelynic ee`
    session renders on a pty for a soak window while loopback
    traffic flows, sampled at 1 Hz for resident memory, open file
    descriptors, and thread count. The render loop's collections are
    rebuild-per-frame by design (the audit trail); this stage turns
    that design into a MEASURED verdict: any unbounded collection,
    fd leak, or per-frame accumulation shows up as monotonic growth
    inside the window.

Verdicts (PASS / FAIL / SKIP, exit 1 on any FAIL — the family
contract): env, pin-family, row-churn, monitor-soak, residue, dmesg.

Self-contained like the flagship depth twin: stdlib only, loopback
traffic only (an in-process socketpair burst loop in the test
cgroup, a forked twin in the group cgroup), no external servers, no
bpftool (the status JSON is the map-row window; the apply's own
success is the cap proof).

Usage:
  sudo ./scripts/depth/endurance-test.sh                # full run (~100s)
  sudo ./scripts/depth/endurance-test.sh --quick        # fast pass (~40s)
  sudo ./scripts/depth/endurance-test.sh --json         # machine-readable
  sudo ./scripts/depth/endurance-test.sh --binary ./target/pro-native-gnu/zelynic
  ZELYNIC_BINARY=./target/pro-native-gnu/zelynic sudo -E ./scripts/depth/endurance-test.sh

Quick mode runs fewer cycles (120) and a shorter soak (10s) — a
smoke of the same proof, not the full exhaustion math (the 1024-cap
exhaustion needs the full 300).
"""

import argparse
import json
import os
import pty
import select
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

# ── knobs ───────────────────────────────────────────────────────────────────

FULL_ROUNDS = 300  # > 1024 slots / 5 per single round: any leak exhausts a cap
QUICK_ROUNDS = 120
FULL_SOAK_S = 30.0
QUICK_SOAK_S = 10.0
# The full attach surface pinned under /sys/fs/bpf/zelynic after the
# first apply — as a NAME SET, not a count (NIGHT-harness-1: the old
# count-only pin said 9 while the real family has been 13 — 9 maps
# plus the 2 enforcement programs and their 2 bpf_links — and the
# mismatch surfaced only on this harness's first-ever VM run; a set
# pin now also catches a WRONG-member family, not just a count
# drift, and the failure names the diff).
PIN_FAMILY = {
    # the 9 pinned maps (the LTS budget surfaces)
    "cgroup_policy_dl",
    "cgroup_policy_ul",
    "cgroup_bucket_dl",
    "cgroup_bucket_ul",
    "group_bucket_dl",
    "group_bucket_ul",
    "watchdog_deadline",
    "cgroup_limiter_stats",
    "schema_version",
    # the 2 enforcement programs + their 2 bpf_links (the 5.7+
    # capability rung pins links beside the programs)
    "enforce_dl",
    "enforce_ul",
    "enforce_dl_link",
    "enforce_ul_link",
}
RSS_BUDGET_MB = 12.0  # post-warmup growth allowance for the TUI process
FD_DRIFT = 3  # max open-fd drift across the soak window
THREAD_DRIFT = 1  # max thread-count drift
BURST = 256 * 1024  # socketpair burst payload (mirrors lib.CHUNK)
BEAT_S = 0.05  # traffic cadence inside a round

CG_A = os.path.join(lib.CGROUP_ROOT, "zelynic-endurance-a")
CG_B = os.path.join(lib.CGROUP_ROOT, "zelynic-endurance-b")
LOCK_DIR = "/run/zelynic"
LOCK_FILE = "/run/zelynic/zelynic.lock"


def cgroup_id_of(path):
    # The kernfs inode IS the cgroup ID (bpf_skb_cgroup_id returns
    # kn->id, published as st_ino) — same rule as the flagship twin.
    return os.stat(path).st_ino & 0xFFFFFFFF


class BurstLoop(threading.Thread):
    """Loopback socketpair bursts from the calling thread's cgroup."""

    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()

    def run(self):
        a, b = socket.socketpair()
        a.setblocking(True)
        b.setblocking(True)
        payload = b"x" * BURST
        while not self.stop.is_set():
            try:
                a.sendall(payload)
                b.recv(BURST)
                b.sendall(payload)
                a.recv(BURST)
            except OSError:
                break
            time.sleep(BEAT_S)


def spawn_cgroup_b_twin():
    """Fork a burst-loop child into cgroup B (the strict-multi second
    member). Returns (proc, in_b) — in_b False means the host refused
    the pre-exec migration and the group rounds degrade honestly."""
    script = (
        "import socket,time\n"
        "a,b=socket.socketpair()\n"
        "p=b'x'*%d\n"
        "while True:\n"
        "    try:\n"
        "        a.sendall(p);b.recv(%d);b.sendall(p);a.recv(%d)\n"
        "    except OSError:\n"
        "        break\n"
        "    time.sleep(%r)\n" % (BURST, BURST, BURST, BEAT_S)
    )

    def _migrate():
        try:
            with open(os.path.join(CG_B, "cgroup.procs"), "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
        except OSError:
            pass  # degraded: the child stays in the parent's cgroup

    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        preexec_fn=_migrate,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.4)  # let the migration + first bursts land
    in_b = False
    try:
        with open(f"/proc/{proc.pid}/cgroup", encoding="utf-8") as f:
            in_b = "zelynic-endurance-b" in f.read()
    except OSError:
        pass
    return proc, in_b


def pid_stat(pid, field):
    """One VmRSS/Threads-style field from /proc/<pid>/status, in kB/units."""
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as f:
            for line in f:
                if line.startswith(field + ":"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def pid_fd_count(pid):
    try:
        return len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        return None


def spawn_tui_on_pty(cgroup_id):
    """The v2 battery's pty shape, minimal: ee --interval 1 on an 80x24
    pty, Enter to pass the smooth open, frames flowing while we sample."""
    import fcntl
    import struct
    import termios

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM": "xterm-256color",
        "NO_COLOR": "1",
    }
    proc = subprocess.Popen(
        [lib.BINARY, "ee", "--interval", "1"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        start_new_session=True,
    )
    os.close(slave)
    # The smooth open: Enter starts the session (the alt screen + the
    # loading frame). Written after a short settle so the TUI's key
    # reader is armed.
    time.sleep(0.5)
    os.write(master, b"\r")
    return proc, master


def drain(master, seconds):
    """Keep the pty drainable while sampling — a blocked child stops
    rendering and the soak would measure a stall, not endurance."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        readable, _, _ = select.select([master], [], [], 0.2)
        if readable:
            try:
                os.read(master, 65536)
            except OSError:
                break


# ── stages ──────────────────────────────────────────────────────────────────


def stage_env():
    if os.geteuid() != 0:
        lib.out("ERROR: this test requires root. Run with sudo.")
        sys.exit(1)
    if not lib.cgroup2_mounted():
        lib.record("env: cgroup v2", "FAIL", "cgroup2 not mounted at /sys/fs/cgroup")
        return False
    lib.record("env: cgroup v2", "PASS")
    if not lib.bpffs_mounted_at("/sys/fs/bpf"):
        lib.record("env: bpffs", "FAIL", "bpf not mounted at /sys/fs/bpf")
        return False
    lib.record("env: bpffs", "PASS")
    return lib.doctor_check()


def setup_cgroups():
    try:
        os.makedirs(CG_A, exist_ok=True)
        os.makedirs(CG_B, exist_ok=True)
        # The whole harness (and every zelynic child it spawns) rides
        # in cgroup A: its loopback traffic is what enforcement books.
        with open(os.path.join(CG_A, "cgroup.procs"), "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        return True
    except OSError as e:
        lib.record("env: test cgroups", "FAIL", str(e))
        return False


def teardown_cgroups(original_cgroup):
    try:
        with open(os.path.join(original_cgroup, "cgroup.procs"), "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
    except OSError:
        pass
    for path in (CG_B, CG_A):
        try:
            os.rmdir(path)
        except OSError:
            pass


def stage_pin_family(cg_id):
    rc, _, err = lib.run_zel(["strict-single", f"cg:{cg_id}", "10mb"])
    if rc != 0:
        lib.record("pin-family: first apply", "FAIL", err.strip()[:120])
        return False
    pins = set()
    try:
        pins = set(os.listdir(lib.PIN_DIR))
    except OSError:
        pass
    if pins != PIN_FAMILY:
        missing = sorted(PIN_FAMILY - pins)
        extra = sorted(pins - PIN_FAMILY)
        detail = f"{len(pins)} pins after first apply, expected {len(PIN_FAMILY)}"
        if missing:
            detail += f", missing: {','.join(missing)}"
        if extra:
            detail += f", extra: {','.join(extra)}"
        lib.record("pin-family: pin set", "FAIL", detail)
        return False
    lib.record(
        "pin-family: pin set",
        "PASS",
        f"exactly the {len(PIN_FAMILY)}-member family (9 maps + 2 programs + 2 links)",
    )
    return True


def stage_row_churn(cg_a, cg_b, rounds, group_ok):
    """The LTS-budget proof: `rounds` apply/unstrict cycles, half of
    them group rounds. Any per-cycle slot leak exhausts a cap and the
    next apply fails loudly — the maps' own contract as the oracle."""
    started = time.perf_counter()
    fails = 0

    # The shape is pinned once, at the first of each kind.
    rc, _, err = lib.run_zel(["unstrict-all"])
    if rc != 0:
        lib.record("row-churn: unstrict-all", "FAIL", err.strip()[:120])
        return False

    kinds = ["single", "group"] if group_ok else ["single"]
    for i in range(rounds):
        kind = kinds[i % len(kinds)]
        if kind == "single":
            rc, _, err = lib.run_zel(["strict-single", f"cg:{cg_a}", "5mb"])
        else:
            rc, _, err = lib.run_zel(["strict-multi", f"cg:{cg_a}:cg:{cg_b}", "5mb"])
        if rc != 0:
            fails += 1
            lib.record(
                "row-churn: apply cycle",
                "FAIL",
                f"round {i + 1} ({kind}) apply failed: {err.strip()[:100]}",
            )
            break
        if i == 0:
            doc = lib.status_json()
            rows = len(doc.get("limits", [])) if doc else -1
            want = 1 if kind == "single" else 2
            if rows != want:
                fails += 1
                lib.record(
                    "row-churn: row shape",
                    "FAIL",
                    f"first {kind} apply showed {rows} limit rows, expected {want}",
                )
                break
        rc, _, err = lib.run_zel(["unstrict-all"])
        if rc != 0:
            fails += 1
            lib.record(
                "row-churn: unstrict cycle",
                "FAIL",
                f"round {i + 1} unstrict-all failed: {err.strip()[:100]}",
            )
            break

    if fails:
        return False
    doc = lib.status_json()
    rows = len(doc.get("limits", [])) if doc else -1
    if rows != 0:
        lib.record("row-churn: zero rows after churn", "FAIL", f"{rows} rows remain")
        return False
    elapsed = time.perf_counter() - started
    slots = rounds * (5 if not group_ok else 7)
    lib.record(
        "row-churn: LTS budget held",
        "PASS",
        f"{rounds} apply/unstrict cycles ({rounds // 2} group) in {elapsed:.0f}s — "
        f"~{slots} map slots churned against the 1024/256 caps, zero rows left",
    )
    return True


def stage_monitor_soak(cg_a, soak_s):
    """The userspace clock: a live ee TUI on a pty, sampled at 1 Hz for
    resident memory, fds, and threads. Growth inside the window is the
    leak signal; the budget allowance covers allocator warmup noise."""
    proc, master = spawn_tui_on_pty(cg_a)
    try:
        # Warmup: the BPF load, the first identity walk, and the first
        # renders allocate before the steady state — 5s, then baseline.
        drain(master, 5.0)
        samples = []
        deadline = time.monotonic() + soak_s
        while time.monotonic() < deadline:
            samples.append(
                {
                    "rss_kb": pid_stat(proc.pid, "VmRSS"),
                    "fds": pid_fd_count(proc.pid),
                    "threads": pid_stat(proc.pid, "Threads"),
                }
            )
            drain(master, 1.0)
        if not samples or proc.poll() is not None:
            lib.record("monitor-soak: session stayed live", "FAIL", "the TUI exited early")
            return False
        rss = [s["rss_kb"] for s in samples if s["rss_kb"] is not None]
        fds = [s["fds"] for s in samples if s["fds"] is not None]
        thr = [s["threads"] for s in samples if s["threads"] is not None]
        if not rss or not fds or not thr:
            lib.record("monitor-soak: sampling", "FAIL", "a sample window came back empty")
            return False
        rss_growth_mb = (max(rss) - min(rss)) / 1024.0
        if rss_growth_mb > RSS_BUDGET_MB:
            lib.record(
                "monitor-soak: resident memory",
                "FAIL",
                f"RSS spanned {min(rss)}->{max(rss)} kB ({rss_growth_mb:.1f} MB), "
                f"budget {RSS_BUDGET_MB:.0f} MB",
            )
            return False
        lib.record(
            "monitor-soak: resident memory",
            "PASS",
            f"RSS {min(rss)}->{max(rss)} kB across {len(rss)} samples "
            f"({rss_growth_mb:.1f} MB span, budget {RSS_BUDGET_MB:.0f} MB)",
        )
        if max(fds) - min(fds) > FD_DRIFT:
            lib.record(
                "monitor-soak: file descriptors",
                "FAIL",
                f"fd count {min(fds)}->{max(fds)}, drift budget {FD_DRIFT}",
            )
            return False
        lib.record(
            "monitor-soak: file descriptors",
            "PASS",
            f"fd count steady at {fds[-1]} (drift {max(fds) - min(fds)}, budget {FD_DRIFT})",
        )
        if max(thr) - min(thr) > THREAD_DRIFT:
            lib.record(
                "monitor-soak: threads",
                "FAIL",
                f"thread count {min(thr)}->{max(thr)}, budget {THREAD_DRIFT}",
            )
            return False
        lib.record(
            "monitor-soak: threads",
            "PASS",
            f"threads steady at {thr[-1]} (drift {max(thr) - min(thr)})",
        )
        # Clean exit: q is the only quit key — a hung TUI is its own
        # endurance failure.
        os.write(master, b"q")
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            lib.record("monitor-soak: clean exit", "FAIL", "the TUI did not exit on q within 10s")
            return False
        if proc.returncode != 0:
            lib.record("monitor-soak: clean exit", "FAIL", f"exit {proc.returncode}")
            return False
        lib.record("monitor-soak: clean exit", "PASS", "q exits 0")
        return True
    finally:
        if proc.poll() is None:
            proc.kill()
        try:
            os.close(master)
        except OSError:
            pass


def stage_residue():
    pins = []
    try:
        pins = os.listdir(lib.PIN_DIR)
    except OSError:
        pass
    ok_pins = not pins
    lib.record(
        "residue: pin dir empty",
        "PASS" if ok_pins else "FAIL",
        "no pins left" if ok_pins else f"leftovers: {pins[:4]}",
    )
    # NIGHT-harness-1: the lock anchor is PERSISTENT BY DESIGN — the
    # flock guard lives in /run/zelynic/zelynic.lock inside the
    # root-owned 0700 dir (SAFETY_ANALYSIS's access matrix; the smoke
    # battery pins the same contract as "only the flock anchor"). The
    # old pin demanded the anchor be gone and could only ever pass on
    # a machine where nothing ever ran — this harness's first live VM
    # run is where the contradiction surfaced. The endurance residue
    # contract is now: the anchor may remain, and NOTHING else may —
    # no pid files, no state, no strays.
    strays = []
    try:
        strays = [n for n in os.listdir(LOCK_DIR) if n != os.path.basename(LOCK_FILE)]
    except OSError:
        pass
    ok_lock = not strays
    lib.record(
        "residue: lock dir",
        "PASS" if ok_lock else "FAIL",
        "only the persistent flock anchor" if ok_lock else f"strays: {strays[:4]}",
    )
    return ok_pins and ok_lock


# ── main ────────────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser(
        prog="endurance-test",
        description="zelynic ultra-long-endurance audit harness (NIGHT-blade-6)",
    )
    ap.add_argument("--binary", help="path to the zelynic binary")
    ap.add_argument("--quick", action="store_true", help="fewer cycles, shorter soak")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--rounds",
        type=int,
        default=None,
        help="override the churn cycle count (default 300, quick 120)",
    )
    ap.add_argument(
        "--soak",
        type=float,
        default=None,
        help="override the monitor soak window in seconds (default 30, quick 10)",
    )
    ap.add_argument(
        "--rss-budget-mb",
        type=float,
        default=RSS_BUDGET_MB,
        help=f"post-warmup RSS growth allowance in MB (default {RSS_BUDGET_MB:.0f})",
    )
    args = ap.parse_args()
    globals()["RSS_BUDGET_MB"] = args.rss_budget_mb
    started = time.perf_counter()
    if not lib.resolve_binary(args.binary, "sudo ./scripts/depth/endurance-test.sh"):
        return 2

    rounds = (
        args.rounds if args.rounds is not None else (QUICK_ROUNDS if args.quick else FULL_ROUNDS)
    )
    soak_s = args.soak if args.soak is not None else (QUICK_SOAK_S if args.quick else FULL_SOAK_S)

    with open("/proc/self/cgroup", encoding="utf-8") as f:
        original_cgroup_field = f.read().strip()
    original_cgroup = "/sys/fs/cgroup" + original_cgroup_field.split("::")[-1]

    burst = None
    twin = None
    ok = True
    try:
        ok = stage_env()
        if ok:
            ok = setup_cgroups()
        if ok:
            cg_a = cgroup_id_of(CG_A)
            cg_b = cgroup_id_of(CG_B)
            # The twin spawns BEFORE the burst thread starts:
            # preexec_fn runs between fork and exec, which Python
            # documents as unsafe in the presence of threads — zero
            # threads at spawn time is the safe shape.
            twin, in_b = spawn_cgroup_b_twin()
            burst = BurstLoop()
            burst.start()
            if not in_b:
                lib.record(
                    "env: group twin cgroup",
                    "SKIP",
                    "the host refused the pre-exec migration — group rounds degrade "
                    "to single-target churn (the lts-7 group path rides unproven)",
                )
            ok = stage_pin_family(cg_a)
            if ok:
                ok = stage_row_churn(cg_a, cg_b, rounds, in_b)
            if ok:
                ok = stage_monitor_soak(cg_a, soak_s)
            if ok:
                ok = stage_residue()
            lib.dmesg_scan()
    finally:
        if burst is not None:
            burst.stop.set()
        if twin is not None:
            twin.kill()
            twin.wait()
        lib.run_zel(["unstrict-all"])
        teardown_cgroups(original_cgroup)

    ok_line = (
        "ultra-long endurance: the LTS budget held under churn amplification, "
        "the monitor soaked flat, zero residue"
    )
    all_ok = lib.final_report(started, "quick" if args.quick else "full", ok_line) and ok
    if args.json:
        print(
            json.dumps(
                {
                    "binary": lib.BINARY,
                    "results": lib.RESULTS,
                },
                indent=2,
            )
        )
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
