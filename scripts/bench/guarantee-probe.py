#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic guarantee live probe (improve-40/improve-40-b follow-up) —
the DRR pool's per-leaf floor/ceiling bracket, measured in REAL
cgroups on the running kernel.

The guarantee lane (improve-40, schema v24) says: a bracketed row's
epoch allowance is the fair split clamped between the floor's and
the ceiling's own shares — a PRIORITY, not a reservation (the pool
itself is the lender), a cap that binds even a lone drawer. The
rootless battery (test/ebpf/limiter/drr_guarantee_tests.rs) pins
the arithmetic on the sim engine; this harness pins the KERNEL side
on the real cgroup tree the lane was built for — the owner's
"battery root-gated for a floor measured in real cgroups" ask:

  row 1 — the instrument (rootless, --self-test): the leaf
    machinery itself — a forked child, its own receiver socket, the
    address pipe, the go byte, the counted drain, the report pipe —
    round-trips one datagram pair without root or policy. Without
    this row a live FAIL could always be blamed on the measurement,
    never the kernel — the instrument is pinned FIRST, the same
    discipline every claims harness here carries.

  row 2 — the floor's promise holds per leaf (live): four REAL leaf
    cgroups under one bracketed target, every leaf blasted past the
    budget, every leaf's delivered volume at or above the floor's
    own share of its measured window (the BAND_LO slack the refill
    cadence earns — measured, never asserted).

  row 3 — the ceiling binds per leaf (live): the same leg's floor
    == ceil geometry pins every leaf BETWEEN the bracket's two
    sides — no leaf above the ceiling's share plus the honest
    slack (BAND_HI, the burst and the accounting floor inside).

  row 4 — the pool law holds (live): the leaves' SUM stays inside
    the pool's own refill x window + the shared burst — the bracket
    redistributes the budget, it never creates one (the law the
    whole lane stands on, read off a running kernel).

  row 5 — the per-direction split lands in the ledger
    (improve-40-b, live): a --floor-download/--ceil-download apply
    rides the JSON's additive download_floor_bps /
    download_ceil_bps fields with the merged floor_bps honestly
    ABSENT — the split's own read-surface contract, verified on the
    row the kernel is actually enforcing.

  row 6 — the split's floor holds per leaf (live): the same split
    leg's blast, every leaf at or above the download floor's share
    — the per-direction spelling is the same law, one leg over.

Honesty contracts: the LEAVES are real child cgroups (the DRR
lane's own unit — a leaf cgroup under the target, never a bare
process), each leaf child creates its receiver socket AFTER its
move (sk_cgroup_data pins the leaf cgroup at creation), the
senders live in the unpoliced root (created before any move, pinned
there forever — the blast egresses unlimited); each child blasts
ONLY on the explicit go byte, which the parent writes AFTER the
policy stands — the blast never races the attach; every leaf's
window is its OWN measured drain-until-quiet span (go byte to
silence), so the bounds read the kernel's clock, not a guess;
teardown is best-effort and never fails a verdict. A pool that
cannot cover the floors (the over-subscription the per-leaf
validation cannot see coming) is NOT this harness's shape — the
geometry is chosen coverable (4 x 100kb <= 512kb), the degradation
law is the rootless battery's own pinned row.

Root required for the live run; --self-test is the CI lane.
"""

import argparse
import json
import os
import socket
import sys
import time

# The shared engine lib lives in scripts/lib/ (NIGHT-refactor-1) — bound
# by ABSOLUTE path so the harness works from any CWD.
_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

import zelynic_harness_lib as lib  # noqa: E402 - needs the lib/ path bootstrap above

# The probe's cgroup geometry: one TARGET (the policy root) with four
# REAL leaf cgroups under it — the DRR lane's own unit of fair share.
TARGET = os.path.join(lib.CGROUP_ROOT, "zelynic-guarantee")
LEAF_NAMES = ("l0", "l1", "l2", "l3")
N_LEAVES = len(LEAF_NAMES)

# The bracket geometry: rate 512kb split across four leaves (the fair
# share 128kb), the bracket pinned at 100kb on BOTH sides — the
# ceiling must pull every leaf DOWN from 128 to 100, the floor must
# hold every leaf AT 100, and the pool law bounds the sum well under
# the refill. Coverable by construction (4 x 100kb <= 512kb).
RATE_STR = "512kb"
RATE_BPS = 512_000
FLOOR_STR = "100kb"
FLOOR_BPS = 100_000
CEIL_STR = "100kb"
CEIL_BPS = 100_000

# The blast geometry: QUIC-shaped 1200-byte datagrams (RFC 9000's
# minimum, one skb per plain python send — no GSO batching), 500 per
# leaf (600 KiB — past the whole pool's burst, so the bracket must
# engage on every leaf).
PKT = 1200
PACKETS_PER_LEAF = 500
BLAST_PER_LEAF = PKT * PACKETS_PER_LEAF
BURST = 64 * 1024  # the GSO admit floor the default burst rides at these rates

# The drain clock: quiet ends the window, capped hard.
SETTLE_QUIET = 0.8
SETTLE_MAX = 10.0

# The verdict rows the harness owns (name, what it proves).
ROWS = (
    "instrument: the leaf machinery round-trips (child, pipes, counted drain)",
    "the floor's promise holds per leaf (real cgroups, live)",
    "the ceiling binds per leaf (the bracket's own cap)",
    "the pool law holds (the sum inside the refill + burst)",
    "the per-direction split lands in the ledger (download_floor_bps, merged pair absent)",
    "the split's floor holds per leaf (the download-only leg)",
)


# ── the instrument lane (rootless) ─────────────────────────────────────────


def self_test():
    """CI lane: pin the leaf machinery without root or policy.

    One forked child with its own receiver, the address pipe, the go
    byte, a counted drain, the report pipe — the exact machinery the
    live rows depend on, minus the cgroup move and the policy. Plus
    the constant sanity pair (the geometry stays coverable).
    """
    go_r, go_w = os.pipe()
    rep_r, rep_w = os.pipe()
    addr_r, addr_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(go_w)
        os.close(rep_r)
        os.close(addr_r)
        os._exit(leaf_main(addr_w=addr_w, go_r=go_r, rep_w=rep_w, drain_cap=2.0))
    os.close(go_r)
    os.close(rep_w)
    os.close(addr_w)
    rx_addr = rx_addr_decode(os.read(addr_r, 64))
    os.close(addr_r)
    # The go byte FIRST (the blast never races the arm — the same
    # law the live legs carry), then one datagram through the exact
    # send shape the live blast uses.
    os.write(go_w, b"g")
    os.close(go_w)
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20)
    tx.connect(rx_addr)
    tx.send(b"z" * PKT)
    tx.close()
    report = os.read(rep_r, 128)
    os.close(rep_r)
    _, status = os.waitpid(pid, 0)
    ok = False
    detail = f"child report {report!r}, wait status {status}"
    try:
        counted = json.loads(report)
        ok = counted.get("bytes") == PKT and counted.get("pkts") == 1
        detail = f"one datagram in, one counted out: {counted}"
    except (ValueError, AttributeError):
        pass
    lib.record(ROWS[0], "PASS" if ok else "FAIL", detail)
    coverable = N_LEAVES * FLOOR_BPS <= RATE_BPS
    lib.record(
        "instrument: the geometry stays coverable (the over-subscription law is the sim's row)",
        "PASS" if coverable else "FAIL",
        f"{N_LEAVES} leaves x {FLOOR_BPS} bps floor vs {RATE_BPS} bps pool",
    )
    return ok and coverable


def rx_addr_decode(raw):
    """The child's (ip, port) off the address pipe."""
    host, port = raw.decode().split(":")
    return (host, int(port))


# ── the leaf child ─────────────────────────────────────────────────────────


def leaf_main(addr_w, go_r, rep_w, drain_cap=SETTLE_MAX):
    """One leaf's measuring half, forked from the harness.

    Called INSIDE the child process: bind the receiver, report the
    address up the pipe, block on the go byte, then drain until
    quiet and report (bytes, pkts, window). The socket is created
    HERE — after the caller's cgroup move, so sk_cgroup_data pins
    the leaf the measurement belongs to. Returns the child's exit
    code (the caller wraps it in os._exit).
    """
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
    rx.bind(("127.0.0.1", 0))
    host, port = rx.getsockname()
    if addr_w is not None:
        os.write(addr_w, f"{host}:{port}".encode())
        os.close(addr_w)
    if os.read(go_r, 1) != b"g":  # a closed pipe is the abort signal, never a blast
        rx.close()
        return 0
    window_start = time.monotonic()
    total_bytes = 0
    total_pkts = 0
    rx.settimeout(SETTLE_QUIET)
    deadline = window_start + drain_cap
    while time.monotonic() < deadline:
        try:
            data = rx.recv(65536)
        except socket.timeout:
            break
        if not data:
            break
        total_bytes += len(data)
        total_pkts += 1
    window = time.monotonic() - window_start
    rx.close()
    os.write(
        rep_w, json.dumps({"bytes": total_bytes, "pkts": total_pkts, "window": window}).encode()
    )
    os.close(rep_w)
    os.close(go_r)
    return 0


# ── the live run ───────────────────────────────────────────────────────────


def _read_id(path):
    """The kernfs inode number (the cgroup id the kernel's helpers use)."""
    return os.stat(path).st_ino


def _spawn_leaves():
    """Fork the N leaf children, each already moved into its OWN leaf
    cgroup (the DRR lane's unit), each with its receiver bound and
    its address reported. Returns (children, addrs) where children
    is a list of (pid, go_w, rep_r) triples."""
    children = []
    addrs = []
    for name in LEAF_NAMES:
        leaf_cg = os.path.join(TARGET, name)
        try:
            os.mkdir(leaf_cg)
        except FileExistsError:
            pass
        go_r, go_w = os.pipe()
        rep_r, rep_w = os.pipe()
        addr_r, addr_w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(go_w)
            os.close(rep_r)
            os.close(addr_r)
            # The move: self into THIS leaf cgroup, before the socket
            # pins its attribution (sk_cgroup_data rides creation).
            with open(os.path.join(leaf_cg, "cgroup.procs"), "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
            os._exit(leaf_main(addr_w=addr_w, go_r=go_r, rep_w=rep_w))
        os.close(go_r)
        os.close(rep_w)
        os.close(addr_w)
        addrs.append(rx_addr_decode(os.read(addr_r, 64)))
        os.close(addr_r)
        children.append((pid, go_w, rep_r))
    return children, addrs


def _blast_leg(children, addrs):
    """Release the go bytes, blast every leaf round-robin past the
    budget, and collect each leaf's own counted report. Returns the
    list of {bytes, pkts, window} dicts, children reaped."""
    senders = []
    for addr in addrs:
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tx.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 21)
        tx.connect(addr)
        senders.append(tx)
    for _pid, go_w, _rep_r in children:
        os.write(go_w, b"g")
        os.close(go_w)
    payload = b"z" * PKT
    for _ in range(PACKETS_PER_LEAF):
        for tx in senders:
            tx.send(payload)
    for tx in senders:
        tx.close()
    reports = []
    for pid, _go_w, rep_r in children:
        raw = os.read(rep_r, 256)
        os.close(rep_r)
        os.waitpid(pid, 0)
        try:
            reports.append(json.loads(raw))
        except ValueError:
            reports.append({"bytes": 0, "pkts": 0, "window": 0.0})
    return reports


def _teardown():
    """Best-effort: lift the policy, empty and remove the leaf
    cgroups, then the target. Never fails a verdict."""
    lib.run_zel(["u", "--all"], timeout=30)
    # Adopt any strays UP the tree (a leaf's cgroup.procs read after
    # its child died is usually empty; a live stray would block the
    # rmdir), then rmdir deepest-first.
    for name in reversed(LEAF_NAMES):
        leaf_cg = os.path.join(TARGET, name)
        try:
            with open(os.path.join(leaf_cg, "cgroup.procs"), encoding="utf-8") as f:
                for line in f:
                    pid = line.strip()
                    if pid:
                        with open(
                            os.path.join(TARGET, "cgroup.procs"), "w", encoding="utf-8"
                        ) as out_f:
                            out_f.write(pid)
            os.rmdir(leaf_cg)
        except OSError:
            pass
    try:
        with open(os.path.join(TARGET, "cgroup.procs"), encoding="utf-8") as f:
            for line in f:
                pid = line.strip()
                if pid:
                    with open(
                        os.path.join(lib.CGROUP_ROOT, "cgroup.procs"), "w", encoding="utf-8"
                    ) as out_f:
                        out_f.write(pid)
        os.rmdir(TARGET)
    except OSError:
        pass


def run_live():
    """The live proof: one target cgroup, four real leaves, two legs."""
    if os.geteuid() != 0:
        lib.out("FAIL: the live probe needs root (cgroup mkdir + BPF policy)")
        lib.out("      run --self-test for the rootless instrument lane")
        return False
    if not lib.cgroup2_mounted():
        lib.record("cgroup v2 mounted", "FAIL", "no /sys/fs/cgroup unified hierarchy")
        return False

    try:
        os.mkdir(TARGET)
    except FileExistsError:
        pass
    target_id = _read_id(TARGET)

    ok_all = True
    try:
        # ── leg A: the merged bracket, both directions ────────────────
        children, addrs = _spawn_leaves()
        rc, out_, err = lib.run_zel(
            [
                "strict",
                str(target_id),
                RATE_STR,
                "--floor",
                FLOOR_STR,
                "--ceil",
                CEIL_STR,
                "--no-test",
            ]
        )
        if rc != 0:
            for pid, go_w, _rep_r in children:
                os.close(go_w)
                os.waitpid(pid, 0)
            lib.record(
                "apply the bracketed policy", "FAIL", f"exit {rc}: {(err or out_).strip()[:200]}"
            )
            return False
        reports = _blast_leg(children, addrs)

        # row 2 — the floor's promise, per leaf, each on its OWN window.
        floor_ok = True
        details = []
        for i, rep in enumerate(reports):
            floor_share = FLOOR_BPS / 8 * rep["window"] * lib.BAND_LO
            leaf_ok = rep["bytes"] >= floor_share
            floor_ok = floor_ok and leaf_ok
            details.append(
                f"leaf {i}: {rep['bytes']} B in {rep['window']:.2f}s "
                f"({rep['bytes'] * 8 / rep['window'] / 1000:.0f} kb/s vs floor share "
                f"{floor_share:.0f} B)"
            )
        lib.record(
            ROWS[1],
            "PASS" if floor_ok else "FAIL",
            "; ".join(details),
        )

        # row 3 — the ceiling binds, per leaf (the fair share is 128kb;
        # no leaf may ride past the 100kb ceiling's own share + slack).
        ceil_ok = True
        details = []
        for i, rep in enumerate(reports):
            ceil_bound = (
                CEIL_BPS / 8 * rep["window"] * lib.BAND_HI + BURST + lib.ACCOUNTING_FLOOR_BYTES
            )
            leaf_ok = rep["bytes"] <= ceil_bound
            ceil_ok = ceil_ok and leaf_ok
            details.append(f"leaf {i}: {rep['bytes']} B vs bound {ceil_bound:.0f} B")
        lib.record(
            ROWS[2],
            "PASS" if ceil_ok else "FAIL",
            "; ".join(details),
        )

        # row 4 — the pool law: the sum inside the refill x window + the
        # shared burst (the bracket redistributes, never creates).
        max_window = max(rep["window"] for rep in reports)
        pool_bound = (
            RATE_BPS / 8 * max_window + BURST + lib.ACCOUNTING_FLOOR_BYTES * N_LEAVES
        ) * lib.LEDGER_EPS
        total = sum(rep["bytes"] for rep in reports)
        pool_ok = total <= pool_bound
        lib.record(
            ROWS[3],
            "PASS" if pool_ok else "FAIL",
            f"sum {total} B over {max_window:.2f}s vs pool bound {pool_bound:.0f} B",
        )
        ok_all = floor_ok and ceil_ok and pool_ok

        # ── leg B: the per-direction split (improve-40-b) ──────────────
        children, addrs = _spawn_leaves()
        rc, out_, err = lib.run_zel(
            [
                "strict",
                str(target_id),
                "-d",
                RATE_STR,
                "--floor-download",
                FLOOR_STR,
                "--ceil-download",
                CEIL_STR,
                "--no-test",
            ]
        )
        if rc != 0:
            for pid, go_w, _rep_r in children:
                os.close(go_w)
                os.waitpid(pid, 0)
            lib.record(
                "apply the split policy", "FAIL", f"exit {rc}: {(err or out_).strip()[:200]}"
            )
            return False
        reports = _blast_leg(children, addrs)

        # row 5 — the split lands in the ledger: the JSON's additive
        # per-direction fields present, the merged pair honestly absent.
        doc = lib.status_json()
        entry = lib.limit_entry(doc, target_id)
        split_ok = False
        detail = "status row not found"
        if entry is not None:
            split_ok = (
                entry.get("download_floor_bps") == FLOOR_BPS
                and entry.get("download_ceil_bps") == CEIL_BPS
                and "floor_bps" not in entry
                and "ceil_bps" not in entry
                and entry.get("upload_floor_bps") is None
                and entry.get("download_bps") == RATE_BPS
            )
            detail = (
                f"download_floor_bps={entry.get('download_floor_bps')} "
                f"download_ceil_bps={entry.get('download_ceil_bps')} "
                f"merged floor_bps {'present' if 'floor_bps' in entry else 'absent'} "
                f"(the honest absence)"
            )
        lib.record(ROWS[4], "PASS" if split_ok else "FAIL", detail)

        # row 6 — the split's floor holds per leaf (the download-only
        # leg, the same law one spelling over).
        split_floor_ok = True
        details = []
        for i, rep in enumerate(reports):
            floor_share = FLOOR_BPS / 8 * rep["window"] * lib.BAND_LO
            leaf_ok = rep["bytes"] >= floor_share
            split_floor_ok = split_floor_ok and leaf_ok
            details.append(f"leaf {i}: {rep['bytes']} B vs floor share {floor_share:.0f} B")
        lib.record(
            ROWS[5],
            "PASS" if split_floor_ok else "FAIL",
            "; ".join(details),
        )
        ok_all = ok_all and split_ok and split_floor_ok
    finally:
        _teardown()
    return ok_all


def main():
    ap = argparse.ArgumentParser(
        description="zelynic guarantee live probe (the per-leaf floor/ceiling bracket)"
    )
    ap.add_argument("--self-test", action="store_true", help="instrument lane only, no root")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--binary", default=None, help="zelynic binary to drive")
    args = ap.parse_args()

    hint = "sudo ./scripts/bench/guarantee-probe.sh (or --self-test for the rootless lane)"
    if not lib.resolve_binary(args.binary, hint):
        return 1
    start = time.perf_counter()
    ok = self_test() if args.self_test else run_live()
    rc = (
        0
        if lib.final_report(
            start,
            "self-test" if args.self_test else "live",
            "the per-leaf guarantee bracket holds in real cgroups on this kernel"
            if ok
            else "see the FAIL rows above",
        )
        else 1
    )
    if args.json:
        lib.out(json.dumps(lib.RESULTS, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
