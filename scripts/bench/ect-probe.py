#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
"""zelynic ECT live probe (NIGHT-private-research-4 follow-up) — the
per-socket lane's ECN marking, proven on the running kernel.

The ECN-first lane (schemas v19/v21, carried by the QUIC-aware v22
object) says: a budgeted lane's over-budget packet is DELIVERED
CE-marked instead of dropped whenever the kernel helper can set the
codepoint on an ECT-capable packet, and the marked bytes charge a
debt the budget stream pays back — the closed form
delivered <= burst + rate*t + 64 KiB (+ one packet). The rootless
battery (test/ebpf/limiter/ecn_tests.rs, ecn_socket_tests.rs) pins
the arithmetic; this harness pins the KERNEL side of the contract
on the per-socket path (--per-socket, one UDP socket = one
connection bucket):

  row 1 — the instrument (rootless, --self-test): an ECT(0) UDP
    datagram on loopback carries its codepoint end to end and the
    receiver's IP_RECVTOS cmsg reads it back. Without this row a
    live FAIL could always be blamed on the measurement, never the
    kernel — the instrument is pinned FIRST, the same discipline
    every claims harness here carries.

  row 2 — the mark lands: ECT(0) UDP blasted through a
    --per-socket 8kb policy (well past the 64 KiB burst) shows
    CE-marked datagrams (TOS low bits 11) at the receiver — the
    in-kernel bpf_skb_ecn_set_ce call on the per-socket lane, live.

  row 3 — the debt cap bites: the CE-marked volume stays inside
    ECN_DEBT_CAP (64 KiB) plus what the window's refill re-armed
    (rate x window) plus one packet — the cap that keeps a
    CE-ignoring hammer at drop-lane parity, measured not asserted.

  row 4 — the control leg drops: the SAME blast shape without ECT
    (TOS 0) delivers only the burst + refill window and drops the
    rest — the helper's refusal IS the legacy verdict, live.

  row 5 — the goodput gain: the ECT leg delivers strictly more than
    the control leg (the local, single-pair shape of the campaign's
    "~30%+ goodput under cap" claim — measured on this kernel, this
    loopback, this window).

  row 6 — the budget law's closed form, live: ECT-leg delivered <=
    burst + rate x window + 64 KiB + one packet. The exact bound the
    rootless proof derives, read off a running kernel.

  row 7 — the ledger cross-check: the kernel's own bookkeeping
    (zelynic status --print-json) shows refusals booked (dropped >
    0 — the schema-v9 booking law) and allowed >= the receiver's
    own count (book_rescue moved the marked drops into the allowed
    column; the kernel never under-books what the receiver read).

Honesty contracts: the SENDER sockets are created before the cgroup
move (sk_cgroup_data pins at creation, so they stay unpoliced no
matter which cgroup the blasting child process sits in — the
datapath attributes by SOCKET, not by task); the RECEIVER sockets
are created after the move (they pin the policed cgroup) and the
pair is CONNECTED both ways (the connected-UDP shape the ingress
hook's early demux resolves — the attribution the per-socket lane
keys by; a kernel that still hands the hook a zero cookie rides the
documented DRR fallback, and every marking law below is the same
law there); the child blasts ONLY on the explicit go byte, which
the parent writes AFTER the policy stands — the blast never races
the attach; the window is the measured drain-until-quiet time, so
the refill term in every bound is the kernel's own clock, not a
guess; teardown is best-effort and never fails a verdict. A kernel
that refuses the helper (non-writable ingress skbs, no CONFIG_INET)
reports CE=0 and FAILS row 2 with the reason spelled out — never a
silent pass.

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

CGROUP = os.path.join(lib.CGROUP_ROOT, "zelynic-ect")

# The blast geometry: 280 x 1200-byte datagrams per leg (336 KiB — five
# times the 64 KiB burst, so the drop verdict must engage), QUIC-shaped
# size on purpose (1200 is RFC 9000's minimum datagram size; a plain
# python send is one skb, one consume, one verdict — no GSO batching).
RATE_STR = "8kb"
RATE_BPS = 8000
PKT = 1200
PACKETS = 280
BURST = 65536
DEBT_CAP = 65536
SETTLE_QUIET = 0.8  # drain ends after this much silence
SETTLE_MAX = 8.0  # ... but never longer than this
ECT0 = 0x02  # the ECN field bits: ECT(0) = 0b10
CE = 0x03  # Congestion Experienced = 0b11
IP_RECVTOS_OPT = 13  # the setsockopt that requests the codepoint cmsg (Python does
# not export it on every build; linux/in.h's value, pinned by the
# self-test's own loopback read-back)
# The cmsg itself arrives as (SOL_IP, IP_TOS, one byte) — the type is
# the socket.IP_TOS constant, NOT the IP_RECVTOS option number (the
# two numbers differ, and the self-test pins the pair end to end).

# The verdict rows the harness owns (name, what it proves).
ROWS = (
    "instrument: ECT(0) survives loopback and the cmsg reads it",
    "ect marked delivered (the per-socket lane, live)",
    "the debt cap bites (CE bytes bounded)",
    "not-ect control drops beyond the burst (the refusal verdict)",
    "the goodput gain (ECT leg beats the control leg)",
    "the budget law closed form (delivered <= burst+rate*t+debt)",
    "ledger cross-check (kernel books refusals and rescues)",
)


# ── the instrument row (rootless) ──────────────────────────────────────────


def tos_of_cmsg(cmsgs):
    """The IP_TOS byte out of one recvmsg ancillary list, or None."""
    for level, ctype, data in cmsgs:
        if level == socket.SOL_IP and ctype == socket.IP_TOS:
            return data[0]
    return None


def self_test():
    """CI lane: pin the measurement instrument without root or policy.

    An ECT(0) datagram on plain loopback must arrive with its codepoint
    intact and be readable through the IP_RECVTOS cmsg — the exact
    read path the live rows depend on. Plus the constant sanity pair
    (the burst floor and the debt cap ride the same 64 KiB law).
    """
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    rx.setsockopt(socket.SOL_IP, IP_RECVTOS_OPT, 1)
    rx.bind(("127.0.0.1", 0))
    port = rx.getsockname()[1]
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.SOL_IP, socket.IP_TOS, ECT0)
    tx.sendto(b"z" * PKT, ("127.0.0.1", port))
    data, anc, _flags, _addr = rx.recvmsg(PKT + 64, 512)
    tos = tos_of_cmsg(anc)
    bits = tos & 0x03 if tos is not None else None
    ok = tos is not None and bits == ECT0 and len(data) == PKT
    lib.record(ROWS[0], "PASS" if ok else "FAIL",
               f"sent ECT(0) (IP_TOS={ECT0}), read TOS={tos} (low bits {bits})")
    cap_ok = BURST == DEBT_CAP == 65536
    lib.record("instrument: the 64 KiB floor/cap pair", "PASS" if cap_ok else "FAIL",
               f"burst {BURST}, ECN debt cap {DEBT_CAP} — the GSO admit "
               f"floor the ecn.rs law rides")
    return ok and cap_ok


# ── the live run ───────────────────────────────────────────────────────────


def _residency_ok():
    """The process's own cgroup line names the probe cgroup."""
    try:
        with open("/proc/self/cgroup", encoding="utf-8") as f:
            return "zelynic-ect" in f.read()
    except OSError:
        return False


def _read_id(path):
    """The kernfs inode number (the cgroup id the kernel's helpers use)."""
    return os.stat(path).st_ino


def _blast(sa, sb):
    """Send both legs as fast as the loopback allows, on the CONNECTED
    sender sockets the child inherited (their cgroup pinned at creation
    — unpoliced, wherever the child process sits)."""
    payload = b"e" * PKT
    for _ in range(PACKETS):
        sa.send(payload)
        sb.send(payload)


def _drain(rx, sink):
    """Receive until quiet, counting per-TOS totals into sink dict."""
    rx.settimeout(SETTLE_QUIET)
    quiet = 0.0
    last = time.monotonic()
    deadline = last + SETTLE_MAX
    while True:
        try:
            data, anc, _flags, _addr = rx.recvmsg(PKT + 64, 512)
        except socket.timeout:
            now = time.monotonic()
            quiet += now - last
            last = now
            if quiet >= SETTLE_QUIET or now >= deadline:
                break
            continue
        except OSError:
            break
        last = time.monotonic()
        quiet = 0.0
        tos = tos_of_cmsg(anc)
        bits = (tos & 0x03) if tos is not None else -1
        sink["pkts"] += 1
        sink["bytes"] += len(data)
        sink["by_bits"][bits] = sink["by_bits"].get(bits, 0) + 1


def run_live():
    """The live proof: one cgroup, one --per-socket policy, two legs."""
    if os.geteuid() != 0:
        lib.out("FAIL: the live probe needs root (cgroup mkdir + BPF policy)")
        lib.out("      run --self-test for the rootless instrument lane")
        return False
    if not lib.cgroup2_mounted():
        lib.record("cgroup v2 mounted", "FAIL", "no /sys/fs/cgroup unified hierarchy")
        return False

    # 1. The SENDER sockets, created while the harness is unpoliced:
    #    sk_cgroup_data pins at creation, so they carry the unpoliced
    #    root forever — the blast egresses unlimited no matter which
    #    cgroup the blasting child sits in (the datapath attributes by
    #    SOCKET, never by task).
    sa = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sa.setsockopt(socket.SOL_IP, socket.IP_TOS, ECT0)  # the ECT(0) leg
    sb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # the Not-ECT control
    for tx in (sa, sb):
        tx.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 21)
    sa.bind(("127.0.0.1", 0))
    sb.bind(("127.0.0.1", 0))

    # 2. The move: self into the probe cgroup, verified from /proc.
    try:
        os.mkdir(CGROUP)
    except FileExistsError:
        pass
    with open(os.path.join(CGROUP, "cgroup.procs"), "w", encoding="utf-8") as f:
        f.write(str(os.getpid()))
    if not _residency_ok():
        lib.record("residency in the probe cgroup", "FAIL",
                   "/proc/self/cgroup does not name zelynic-ect")
        return False
    cgroup_id = _read_id(CGROUP)

    # 3. The RECEIVER pair, created AFTER the move (they pin the policed
    #    cgroup), bound and CONNECTED to the senders — both directions of
    #    the pair carry only local state (UDP connect sends nothing), and
    #    the connected shape is what the ingress hook's early demux
    #    resolves: the socket the per-socket lane keys by.
    rxa, rxb = socket.socket(socket.AF_INET, socket.SOCK_DGRAM), \
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for rx in (rxa, rxb):
        rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
        rx.setsockopt(socket.SOL_IP, IP_RECVTOS_OPT, 1)
        rx.bind(("127.0.0.1", 0))
    rxa.connect(sa.getsockname())
    rxb.connect(sb.getsockname())
    sa.connect(rxa.getsockname())
    sb.connect(rxb.getsockname())

    # 4. The armed child: forked with everything wired, blocked on the
    #    go byte. It moves ONLY on the byte — a closed pipe is the abort
    #    signal, never a blast.
    pipe_r, pipe_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(pipe_w)
        if os.read(pipe_r, 1) != b"g":
            os._exit(0)
        _blast(sa, sb)
        os._exit(0)
    os.close(pipe_r)
    sa.close()
    sb.close()

    # 5. The policy (--no-probe: this harness IS the probe).
    rc, out_, err = lib.run_zel(["strict-single", str(cgroup_id), RATE_STR,
                                 "--per-socket", "--no-probe"])
    if rc != 0:
        os.close(pipe_w)
        os.waitpid(pid, 0)
        rxa.close()
        rxb.close()
        lib.record("apply the --per-socket policy", "FAIL",
                   f"exit {rc}: {(err or out_).strip()[:200]}")
        return False

    # 6. The window: the policy stands, the receiver is resident, the
    #    sender is armed — the go byte releases the blast, and the
    #    drain-until-quiet clock IS the window every bound reads.
    window_start = time.monotonic()
    os.write(pipe_w, b"g")
    os.close(pipe_w)
    sink_a = {"pkts": 0, "bytes": 0, "by_bits": {}}
    sink_b = {"pkts": 0, "bytes": 0, "by_bits": {}}
    _drain(rxa, sink_a)
    _drain(rxb, sink_b)
    window = time.monotonic() - window_start
    os.waitpid(pid, 0)
    rxa.close()
    rxb.close()

    ce_pkts = sink_a["by_bits"].get(CE, 0)
    ce_bytes = ce_pkts * PKT
    ect0_pkts = sink_a["by_bits"].get(ECT0, 0)
    allowed = sink_a["bytes"]
    plain = sink_b["bytes"]
    refill = RATE_BPS // 8 * window

    # row 2 — the mark lands (past the burst, so marks must exist).
    lib.record(ROWS[1], "PASS" if ce_pkts >= 32 else "FAIL",
               f"{ce_pkts} CE-marked datagrams of {PACKETS} sent "
               f"({sink_a['pkts']} ECT-leg delivered: {ce_pkts} CE + "
               f"{ect0_pkts} unmarked-allowed)")

    # row 3 — the debt cap bites (plus the refill's re-arm + one pkt).
    cap_hi = DEBT_CAP + refill + PKT
    lib.record(ROWS[2], "PASS" if ce_bytes <= cap_hi else "FAIL",
               f"CE bytes {ce_bytes} <= cap {DEBT_CAP} + refill "
               f"{int(refill)} + 1 pkt (window {window:.1f}s)")

    # row 4 — the control leg: the burst + refill window only, drops booked.
    ctrl_hi = BURST + refill + PKT
    lib.record(ROWS[3], "PASS" if plain <= ctrl_hi and sink_b["pkts"] < PACKETS else "FAIL",
               f"not-ect delivered {plain} B of {PACKETS * PKT} sent "
               f"(bound {int(ctrl_hi)} B; {PACKETS - sink_b['pkts']} dropped)")

    # row 5 — the goodput gain: the ECT leg strictly beats the control.
    gain = allowed / plain if plain else 0.0
    lib.record(ROWS[4], "PASS" if gain >= 1.5 else "FAIL",
               f"ECT leg {allowed} B vs control {plain} B "
               f"({gain:.2f}x — the mark-before-drop gain, this kernel)")

    # row 6 — the closed form, live.
    law_hi = BURST + refill + DEBT_CAP + PKT
    lib.record(ROWS[5], "PASS" if allowed <= law_hi else "FAIL",
               f"ECT-leg delivered {allowed} <= burst {BURST} + "
               f"rate*window {int(refill)} + debt {DEBT_CAP} + 1 pkt")

    # row 7 — the kernel's own ledger (refusals booked, rescues moved).
    doc = lib.status_json()
    entry = lib.limit_entry(doc, cgroup_id) if doc else None
    if entry is None:
        lib.record(ROWS[6], "FAIL", "status --print-json carries no row for the target")
    else:
        kb_dropped = entry.get("bytes_dropped", 0)
        kb_allowed = entry.get("bytes_allowed", 0)
        ok = kb_dropped > 0 and kb_allowed >= allowed + plain - PKT
        lib.record(ROWS[6], "PASS" if ok else "FAIL",
                   f"kernel: {kb_allowed} B allowed (>= receiver's "
                   f"{allowed + plain}), {kb_dropped} B dropped "
                   f"(booked refusals, the v9 law)")

    # Teardown: best-effort, never fails a verdict.
    lib.run_zel(["unstrict-single", str(cgroup_id)])
    try:
        with open(os.path.join(lib.CGROUP_ROOT, "cgroup.procs"), "w", encoding="utf-8") as f:
            f.write(str(os.getpid()))
        os.rmdir(CGROUP)
    except OSError:
        pass
    return all(r.get("verdict") != "FAIL" for r in lib.RESULTS)


def main():
    ap = argparse.ArgumentParser(description="zelynic ECT live probe (per-socket lane)")
    ap.add_argument("--self-test", action="store_true", help="instrument lane only, no root")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    start = time.perf_counter()
    ok = self_test() if args.self_test else run_live()
    rc = 0 if lib.final_report(start, "self-test" if args.self_test else "live",
                               "the per-socket ECN marking contract holds on this kernel"
                               if ok else "see the FAIL rows above") else 1
    if args.json:
        lib.out(json.dumps(lib.RESULTS, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
