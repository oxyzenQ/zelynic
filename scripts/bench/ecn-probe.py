#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# LOC_EXEMPT: one self-contained verification harness by design — the
# cgroup worker, the cmsg instrument, the tcpdump witness and the
# ledger cross-check share one docstring contract, and the kernel
# truths live in the header the .sh wrapper points at; splitting the
# probe across modules would scatter the told-once recipe (the
# recwn-probe.py precedent).
"""zelynic ECN live probe (night-spark-4 — Layer 2 of the quota
saver, ECN CE-marking on the CGROUP lanes), measured on the running
kernel.

The ECN-first lanes (schemas v19/v21, carried by the QUIC-aware v22
object) say: a budgeted lane's over-budget packet is DELIVERED
CE-marked instead of dropped whenever the kernel helper
bpf_skb_ecn_set_ce can set the codepoint on an ECT-capable packet,
and the marked bytes charge a debt the budget stream pays back —
the closed form delivered <= burst + rate*t + 64 KiB (+ one packet).
The rootless battery (test/ebpf/limiter/ecn_tests.rs,
ecn_socket_tests.rs) pins the arithmetic; the ect-probe pins the
PER-SOCKET lane live; this harness pins the KERNEL side of the
CGROUP lane (the schema-v26 ledger row `zelynic status --print-json`
now names) and the QUIC/UDP story the Layer 2 scale exists for:

  row 1 — the instrument (rootless, --self-test): the ECN codepoint
    decode table (Not-ECT / ECT(1) / ECT(0) / CE), the tcpdump
    witness filter the owner's recipe names, the status-JSON CE
    ledger field contract, the empty-ledger pre-flight verdict (a
    clean host carries no limit rows, so the probe plants its own
    and re-reads — an empty limits[] never reads as pre-v26), and
    the cap bound's live form. Without this row a live FAIL could
    always be blamed on the measurement, never the kernel — the
    instrument is pinned FIRST, the discipline every claims harness
    here carries.

  row 2 — the cgroup ingress lane marks (live): the worker rides in
    the policed cgroup with ONLY a download policy standing; its
    ECT(0) UDP datagrams loop back and the RECEIVER's IP_RECVTOS
    cmsg reads CE (0x03) on the over-budget ones — the cgroup lane's
    in-kernel bpf_skb_ecn_set_ce call, live, attributed by cgroup.

  row 3 — the control leg drops: the SAME blast shape without ECT
    (TOS 0) delivers only the burst + refill window and marks
    nothing — the helper's refusal IS the legacy verdict, live, and
    the ECT leg out-delivers it (the goodput shape, one pair).

  row 4 — the ledger cross-check: `zelynic status --print-json`
    names limits[].ce_marked_packets / .ce_marked_bytes > 0 (the
    schema-v26 columns) and the CE byte volume stays inside the
    budget law's bound: cap + rate x window + one packet, the
    window measured drain-until-quiet, not a guess.

  row 5 — the tcpdump witness: the task's own recipe, run where the
    kernel serves it. The witness window RE-PLANTS the download
    policy BESIDE the upload one — one invocation carrying BOTH legs
    (the CLI's unset-leg law removes a direction the apply spec
    leaves unset, so a `-u`-alone plant strips the standing download
    row and the internet legs ride an unpoliced lane — the nightpc
    live find: 793 kB/s past the 100kb lane with a silent ledger,
    the row blaming a join that was never broken) — and tcpdump
    counts `ip[1] & 0x3 == 0x3` packets on loopback — the egress
    hook marks BEFORE the dev-layer tap (verified against v5.15
    source: net/ipv4/ip_output.c:306,325), so the witness is
    tap-visible on every kernel this floor supports. The INGRESS
    marks of rows 2-4 are a different story and the header below
    owns it.

  row 6 — the internet TCP leg: `net.ipv4.tcp_ecn=1` (saved and
    restored), a curl child joined INTO the policed cgroup the
    recwn-probe way (fork, join cgroup.procs, execv — curl IS the
    cgroup member, every socket it makes is born policed; the
    21:53 recwn run's lesson, restated for the NIC path) drives
    the asia ladder under the standing policies. The verdict is
    four-branch: the ladder answering and the ledger's CE columns
    moved is the full PASS; a transfer throttled to the lane over
    a silent ledger is the honest SKIP (a non-ECN hop rode the
    drop lane); a transfer that ran PAST the lane's rate with a
    silent ledger is the bypass FAIL — with the join in place,
    speed far above the policy names non-engagement, not a path
    property (night-spark-4 part 2); a failed transfer is the
    leg's own FAIL.

  row 7 — the QUIC leg: `curl --http3-only https://cloudflare-quic.com/`
    — QUIC endpoints send ECT(0) by default (RFC 9000), so the
    policer's CE marks reach the QUIC stack's own congestion
    controller without a single dropped datagram: retransmit storm
    prevention, live. An honest SKIP when the local curl cannot
    speak HTTP/3 (most distro builds) — the skip names the reason,
    never a silent pass.

Kernel truths (verified against v5.15 source, recorded here the
ebpf/src/recwn.rs way — the version-dependence is stated, never
glossed): the dev-layer RX tap loop (tcpdump's ingress delivery
point) sits in __netif_receive_skb_core (net/core/dev.c:5287-5295 on
v5.15), and NO cgroup-skb hook precedes it in dev.c, ip_input.c,
tcp_ipv4.c, or udp.c — the INGRESS mark lands in the L3/L4 receive
path AFTER the tap, so a local tcpdump cannot witness rows 2-4's
marks on the 5.13-5.15 floor (the receiver's IP_RECVTOS cmsg and the
v26 ledger are the ingress witnesses — both stronger: they read the
packet the stack actually delivered). The EGRESS hook runs in the L3
output path (net/ipv4/ip_output.c:306,325 on v5.15) BEFORE the
dev-layer tap, so row 5's marks are tap-visible on every kernel this
floor supports. A tap-order shift on newer kernels changes nothing
this harness asserts: every verdict rides the cmsg and the ledger.

Honesty contracts: the worker's sockets are created AFTER the cgroup
join (sk_cgroup_data pins at creation, so a socket born outside
stays unpoliced no matter which cgroup it later sits in — the
ect-probe discipline); the blasts run ONLY on the explicit go byte,
which the parent writes AFTER the policy stands (the blast never
races the attach); the ingress phase plants the DOWNLOAD policy
ALONE, so a CE at the receiver can only come from the ingress hook
(an upload policy standing would let the egress hook mark first and
the cmsg witness would not attribute); the tcpdump phase RE-PLANTS
the download policy beside the upload one in ONE invocation — the
CLI's unset-leg law (a direction the spec leaves unset is REMOVED,
not left stale) makes a single-direction plant strip the other leg,
so the both-legs spelling is the only shape that keeps the internet
legs policed (night-spark-5's live find on nightpc); the internet
boundary reads the download leg back off the status document and a
bypass FAIL with the policy gone names the POLICY as the bypass,
never the join; the sysctl flip is
saved-and-restored around its leg only; teardown is best-effort and
never fails a verdict; a pre-v26 binary (no CE columns on a limit
row that IS active) fails the schema row with the reason spelled out
— never a silent pass; an EMPTY limits[] is a clean host, not a
pre-v26 object — the schema row plants the probe's own download
policy first and reads the columns off the fresh row it booked
itself (night-spark-4 hot-fix 3); the worker flushes ONE REPORT PER
PHASE and the parent's every wait on it is deadline-bounded — the
pair can never park face-to-face on each other's pipes, and a lost
worker is an honest FAIL row plus the teardown's SIGKILL
(night-spark-4 hot-fix 3 follow-up); the internet legs join the
policed cgroup the recwn way — fork, join cgroup.procs, execv, so
curl itself is the member and its sockets are born policed, each
leg behind a hard wall that kills and names — and the internet
TCP row's verdict is four-branch: FAIL when the transfer fails,
PASS when the ledger books the marks, SKIP when a throttled
transfer books nothing (a non-ECN hop rode the drop lane), FAIL
again when the transfer ran past the lane's rate (the bypass —
non-engagement is a defect, not a path property)
(night-spark-4 part 2).

Root required for the live run; --self-test is the CI lane.
"""

import argparse
import json
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import time

# The shared engine lib lives in scripts/lib/ (NIGHT-refactor-1) — bound
# by ABSOLUTE path so the harness works from any CWD.
_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, _LIB_DIR)

sys.dont_write_bytecode = True  # root-owned pycache guard, docs/MAINTENANCE.md 7
import zelynic_harness_lib as lib  # noqa: E402

# The lane geometry mirrors the recwn probe's: the 100kb band is the
# quota saver's own demo policy, and every bound below derives from it.
RATE_STR = "100kb"
RATE_BPS = 100_000
# The ecn.rs debt cap's userspace mirror (the ECN_DEBT_CAP law — the
# one-time convergence slack the budget law grants a CE-reactive lane).
DEBT_CAP_BYTES = 65_536
# The loopback blast: 512 KiB of 1200-byte datagrams — well past the
# burst and the debt cap together, so the over-budget phase (the marks)
# is guaranteed to open on every run.
PKT_BYTES = 1200
BLAST_BYTES = 512 * 1024
# The drain-until-quiet detector (the ect-probe shape): the refill
# window is the kernel's own clock, measured, never guessed.
DRAIN_QUIET_S = 1.0
DRAIN_MAX_S = 30.0
# The parent's wait deadlines (night-spark-4 hot-fix 3 follow-up):
# every read the parent does on the worker's pipes is select-bounded —
# the ready handshake, the ingress report, the internet report. A
# worker that dies or stalls ends as an honest FAIL row plus the
# teardown's SIGKILL, never a parked probe. The ingress bound covers
# two drain-capped blast legs; the internet bound covers the ladder's
# own curl max-times (three rungs plus the QUIC leg at their worst).
READY_TIMEOUT_S = 15.0
INGRESS_REPORT_TIMEOUT_S = 90.0
INTERNET_REPORT_TIMEOUT_S = 480.0
CG_ROOT = "/sys/fs/cgroup"
CG_NAME = "zelynic-ecn-probe"
TCP_ECN_SYSCTL = "/proc/sys/net/ipv4/tcp_ecn"
TCP_ECN_ON = b"1\n"
# The tcpdump witness filter, verbatim from the owner's recipe: the ECN
# field is the TOS byte's low two bits, CE is 0b11 (IPv4; the loopback
# witness legs are forced IPv4 so one filter tells the whole truth).
TCPDUMP_FILTER = "udp and ip[1] & 0x3 == 0x3"
# The internet leg's byte cap and its ladder — the same
# aliveness-verified rungs the recwn probe rides (2026-11-04 sweep),
# cloudflare first because the {bytes} template caps the transfer by
# construction (the lane measures the ledger, not the payload).
INTERNET_BYTES = 3 * 1024 * 1024
INTERNET_LADDER = [
    ("cloudflare", "https://speed.cloudflare.com/__down?bytes={bytes}"),
    ("vultr-singapore", "http://sgp-ping.vultr.com/vultr.com.1000MB.bin"),
    ("biznet-jakarta", "https://mirror.biznetgio.com/ubuntu/ls-lR.gz"),
]
QUIC_URL = "https://cloudflare-quic.com/"
CONNECT_TIMEOUT_S = 10
CURL_MAX_TIME_S = 90
# The cgroup membership file the internet legs join through (the
# recwn-probe join: fork, join, execv — curl is the cgroup member,
# every socket it creates is born policed; a child of a joined
# parent inherits the membership, but the join on the exec'd pid
# itself is the contract the attribution stands on — the recwn
# probe's 21:53 run lesson, restated for the NIC path).
CG_PROCS = os.path.join(CG_ROOT, CG_NAME, "cgroup.procs")
# The internet leg's hard wall: curl's own max-time plus the slack
# the parent's wait adds before it kills the child — a stalled
# mirror dies named, never a parked leg.
LEG_WALL_SLACK_S = 15
CODEPOINT_NAMES = {0: "Not-ECT", 1: "ECT(1)", 2: "ECT(0)", 3: "CE"}


# ── the pure instrument ───────────────────────────────────────────────


def ecn_codepoint(tos_byte):
    """The ECN field is the IPv4 TOS byte's two low bits (the IPv6
    Traffic Class byte's same two) — the decode every witness below
    rides, pinned on the full byte range in --self-test."""
    return tos_byte & 0x3


def cap_bound_bytes(window_s):
    """The budget law's live form (ecn.rs's closed shape): the CE byte
    volume one marked lane can deliver is the one-time cap plus what
    the window's refill re-armed plus one packet."""
    return DEBT_CAP_BYTES + int(RATE_BPS * window_s) + PKT_BYTES


def parse_ce_ledger(doc):
    """Read the v26 CE ledger out of a `status --print-json` document:
    the SUM across the limit rows (the probe's cgroup is one row; the
    sum keeps the verdict honest if the host carries others). A
    pre-v26 binary carries no such fields — the caller must see the
    difference between zero and absent."""
    marked_p = 0
    marked_b = 0
    present = False
    for row in (doc or {}).get("limits", []):
        if "ce_marked_packets" in row and "ce_marked_bytes" in row:
            present = True
            marked_p += row["ce_marked_packets"]
            marked_b += row["ce_marked_bytes"]
    return present, marked_p, marked_b


def download_leg_standing(doc, cg_id, rate_bps):
    """True when the status document's limits[] carries THIS cgroup's
    download leg at the policy rate — the internet boundary's own
    witness, so a bypass FAIL never blames the join while the POLICY
    is the missing leg. A None document (status unreachable) reads
    not-standing, the safe direction for a detail string."""
    for row in (doc or {}).get("limits") or []:
        if row.get("cgroup_id") == cg_id:
            return row.get("download_bytes_per_sec") == rate_bps
    return False


def schema_check(doc):
    """The pre-flight verdict the schema row rides: classify a
    `status --print-json` document BEFORE judging the pinned object.
    'empty' — limits[] carries no rows (a clean host: the v26 columns
    have nothing to ride, absence proves nothing, the caller plants
    its own row and re-reads); 'stale' — a limit row IS active but
    the CE columns are gone (a pre-v26 pinned object); 'present' —
    the columns ride, with the ledger sums. The distinction the
    clean-host false FAIL taught: absence on an empty ledger is not
    evidence."""
    limits = (doc or {}).get("limits") or []
    if not limits:
        return "empty", 0, 0
    present, marked_p, marked_b = parse_ce_ledger(doc)
    if not present:
        return "stale", 0, 0
    return "present", marked_p, marked_b


def internet_tcp_verdict(size_b, delta_p, speed_bps):
    """The internet TCP row's verdict (night-spark-4 part 2): a
    transfer that failed is the leg's own FAIL; marks booked on the
    ledger is the full PASS; a transfer that ran PAST the lane's rate
    with a silent ledger is the bypass — with the legs joined into
    the policed cgroup, speed far above the policy names
    non-engagement, not a path property; a transfer throttled to the
    lane with a silent ledger is the honest SKIP (a non-ECN hop rode
    the drop lane, the marking lane never saw it). The same witness
    discipline the tcpdump row rides: the skip names the reason,
    never a silent pass."""
    if size_b <= 0:
        return "FAIL"
    if delta_p > 0:
        return "PASS"
    if speed_bps > RATE_BPS * 3:
        return "FAIL"
    return "SKIP"


def self_test():
    """The rootless instrument lane: the law, the decoder, the filter,
    the JSON contract."""
    lib.out("  RECWN/ECN instrument — the rootless pins (night-spark-4)")
    rows = []

    # The decode table: every TOS byte's low two bits, the full range.
    decode_ok = (
        all(ecn_codepoint(b) == (b & 3) for b in range(256))
        and CODEPOINT_NAMES[ecn_codepoint(0x00)] == "Not-ECT"
        and (
            CODEPOINT_NAMES[ecn_codepoint(0x02)] == "ECT(0)"
            and CODEPOINT_NAMES[ecn_codepoint(0x01)] == "ECT(1)"
            and CODEPOINT_NAMES[ecn_codepoint(0x03)] == "CE"
        )
    )
    rows.append(
        (
            "instrument: the ECN codepoint decode table",
            decode_ok,
            "0x00 Not-ECT, 0x01 ECT(1), 0x02 ECT(0), 0x03 CE — the two "
            "low bits of the TOS/Traffic-Class byte, full-range pinned",
        )
    )

    # The witness filter: the owner's recipe, byte-exact, plus the
    # meaning each side carries.
    rows.append(
        (
            "instrument: the tcpdump witness filter",
            TCPDUMP_FILTER == "udp and ip[1] & 0x3 == 0x3",
            f"'{TCPDUMP_FILTER}' — ip[1] is the TOS byte, & 0x3 the ECN "
            "field, == 0x3 CE only (the loopback witness legs are IPv4, "
            "so one filter tells the whole truth)",
        )
    )

    # The status-JSON contract: the v26 fields parse off a fixture
    # document the live ledger rows will read the same way.
    fixture = {
        "limits": [
            {"cgroup_id": 1, "ce_marked_packets": 12, "ce_marked_bytes": 17432},
            {"cgroup_id": 2, "ce_marked_packets": 3, "ce_marked_bytes": 3600},
        ]
    }
    present, marked_p, marked_b = parse_ce_ledger(fixture)
    fixture_absent = {"limits": [{"cgroup_id": 1}]}
    absent_present, _, _ = parse_ce_ledger(fixture_absent)
    rows.append(
        (
            "instrument: the v26 CE ledger field contract",
            present and marked_p == 15 and marked_b == 21032 and not absent_present,
            "fixture sums 12+3 packets / 17432+3600 bytes; a pre-v26 "
            "document reads present=False (absence never fakes zero)",
        )
    )

    # The pre-flight verdict table: the schema row's three states,
    # classified before any verdict is spoken. An empty limits[] is a
    # clean host ('empty': plant a fresh row, re-read, proceed — the
    # shape that once false-FAILed a perfect v26 binary), a row with
    # the columns gone is the stale-pinned-object verdict ('stale'),
    # the columns riding is 'present' with the ledger sums. The row
    # also proves no document shape panics the classifier: None, a
    # missing limits key, and an empty list all ride.
    empty_verdicts = (
        schema_check({"limits": []}),
        schema_check({}),
        schema_check(None),
    )
    rows.append(
        (
            "instrument: the empty-ledger pre-flight verdict",
            all(v == ("empty", 0, 0) for v in empty_verdicts)
            and schema_check(fixture_absent) == ("stale", 0, 0)
            and schema_check(fixture) == ("present", 15, 21032),
            "limits[] empty/absent/None -> 'empty' (the clean-host "
            "proceed: the probe plants its own row and re-reads, never "
            "a panic, never a pre-v26 verdict); a row with the columns "
            "gone -> 'stale'; the columns present -> 'present' "
            "(15 pkts / 21032 B)",
        )
    )

    # The internet TCP row's verdict: the verdict the live row rides,
    # pinned before the path can argue. A transfer that fails is the
    # leg's FAIL; marks booked is the full PASS; a throttle-rate
    # transfer over a silent ledger is the SKIP (the non-ECN-hop
    # shape the first full nightpc run rode); a transfer far PAST the
    # lane's rate with a silent ledger is the bypass FAIL the
    # in-cgroup join exists to kill (night-spark-4 part 2).
    rows.append(
        (
            "instrument: the internet TCP witness verdict",
            internet_tcp_verdict(0, 0, RATE_BPS) == "FAIL"
            and internet_tcp_verdict(-1, 5, RATE_BPS) == "FAIL"
            and internet_tcp_verdict(INTERNET_BYTES, 5, RATE_BPS) == "PASS"
            and internet_tcp_verdict(INTERNET_BYTES, 0, RATE_BPS * 10) == "FAIL"
            and internet_tcp_verdict(INTERNET_BYTES, 0, RATE_BPS) == "SKIP",
            "no bytes -> FAIL (the leg broke, no rung answered); bytes "
            "with marks booked -> PASS (the policed lane's own columns "
            "moved); bytes at the lane's rate with a silent ledger -> "
            "SKIP (a non-ECN hop rode the drop lane); bytes far past "
            "the lane's rate with a silent ledger -> FAIL (the lane "
            "never engaged — the bypass the in-cgroup join kills)",
        )
    )

    # The plant's one-invocation both-legs form: the CLI's unset-leg
    # removal law makes a single-direction re-plant strip the other
    # leg — the exact shape that sent the nightpc internet legs past
    # an unpoliced lane (793 kB/s, silent ledger). The witness plant
    # carries BOTH legs in ONE invocation; the single-leg form stays
    # the phase-1 attribution shape.
    rows.append(
        (
            "instrument: the plant's one-invocation both-legs form",
            _plant_args(7, "d") == ["strict", "cg:7", "-d", "100kb", "--no-test"]
            and _plant_args(7, "du")
            == ["strict", "cg:7", "-d", "100kb", "-u", "100kb", "--no-test"],
            "the witness phase re-plants -d BESIDE -u in one strict "
            "invocation — both legs are SET, so the unset-leg removal "
            "law has nothing to remove; the download-alone form stays "
            "the phase-1 attribution shape",
        )
    )

    # The download-leg standing witness: the internet boundary reads
    # the download leg back off the status document, so a bypass FAIL
    # names a vanished policy as the policy's bypass (a concurrent
    # unstrict, a failed plant) and never blames the join while the
    # POLICY is the missing leg.
    standing = {"limits": [{"cgroup_id": 7, "download_bytes_per_sec": RATE_BPS}]}
    rows.append(
        (
            "instrument: the download-leg standing witness",
            download_leg_standing(standing, 7, RATE_BPS)
            and not download_leg_standing(
                {"limits": [{"cgroup_id": 7, "download_bytes_per_sec": 200_000}]},
                7,
                RATE_BPS,
            )
            and not download_leg_standing({"limits": [{"cgroup_id": 9}]}, 7, RATE_BPS)
            and not download_leg_standing({"limits": []}, 7, RATE_BPS)
            and not download_leg_standing(None, 7, RATE_BPS),
            "the probe cgroup's row at the policy rate reads standing; a "
            "different rate, a foreign row, an empty limits[], and a None "
            "document all read not-standing (the safe direction for a "
            "detail string)",
        )
    )

    # The cap bound's live form: the law at this lane's own geometry.
    bound = cap_bound_bytes(5.0)
    law_ok = bound == DEBT_CAP_BYTES + 5 * RATE_BPS + PKT_BYTES
    rows.append(
        (
            "law: the cap bound's live form",
            law_ok,
            f"cap {DEBT_CAP_BYTES} + rate*t ({RATE_BPS} x 5s) + one packet "
            f"({PKT_BYTES}) = {bound} — the ecn.rs closed shape, live form",
        )
    )

    # The witness attribution rule: the ingress phase plants the
    # download policy ALONE (an upload policy standing would let the
    # egress hook mark first and the cmsg would not attribute).
    rows.append(
        (
            "law: the cmsg witness's attribution isolation",
            True,
            "phase 1 plants -d alone: the sender's egress path is "
            "unpoliced, so a CE at the receiver names the INGRESS hook; "
            "the upload policy joins only for the tap-visible witness",
        )
    )

    ok = 0
    for name, verdict, detail in rows:
        lib.record(name, "PASS" if verdict else "FAIL", detail)
        ok += 1 if verdict else 0
    lib.out()
    lib.out(f"  {ok} passed, {len(rows) - ok} failed — self-test instrument")
    return 0 if ok == len(rows) else 1


# ── the worker (the cgroup member: every socket it makes is policed) ──


def _recv_ce_stats(rsock, expect_bytes):
    """Drain one loopback leg until quiet; return (delivered, ce_packets,
    ce_bytes, drain_s). The TOS rides the IP_RECVTOS cmsg — the packet
    the stack actually delivered, tap-order immune."""
    delivered = 0
    ce_packets = 0
    ce_bytes = 0
    started = time.monotonic()
    last = started
    while True:
        remaining = DRAIN_MAX_S - (time.monotonic() - started)
        if remaining <= 0:
            break
        ready, _, _ = select.select([rsock], [], [], min(DRAIN_QUIET_S, remaining))
        if not ready:
            break  # quiet — the lane drained
        data, cmsgs, _, _ = rsock.recvmsg(PKT_BYTES * 2, socket.CMSG_SPACE(1))
        delivered += len(data)
        tos = 0
        for lvl, typ, val in cmsgs:
            if lvl == socket.SOL_IP and typ == socket.IP_TOS:
                tos = val[0]
        if ecn_codepoint(tos) == 3:
            ce_packets += 1
            ce_bytes += len(data)
        last = time.monotonic()
    drain = max(last - started, 0.0)
    _ = expect_bytes
    return delivered, ce_packets, ce_bytes, drain


def _blast_leg(tos_byte):
    """One loopback leg: connected UDP pair, the sender's TOS set, the
    blast out, drain-until-quiet, the cmsg witness counted."""
    r = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r.setsockopt(socket.SOL_IP, socket.IP_RECVTOS, 1)
    r.bind(("127.0.0.1", 0))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos_byte)
    s.connect(r.getsockname())
    pkt = b"z" * PKT_BYTES
    sent = 0
    while sent < BLAST_BYTES:
        try:
            s.send(pkt)
            sent += PKT_BYTES
        except OSError:
            break  # the policer's drops backpressure the socket buffer
    s.close()
    delivered, ce_p, ce_b, drain = _recv_ce_stats(r, BLAST_BYTES)
    r.close()
    return {"delivered": delivered, "ce_packets": ce_p, "ce_bytes": ce_b, "drain_s": drain}


def _curl_leg_args(url, quic=False):
    """One capped transfer's curl argument list — the TCP ladder leg
    (a range request) or the QUIC leg (--http3-only). The -w line is
    the whole report: size first, speed second, one line."""
    args = [
        "curl",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{size_download} %{speed_download}",
    ]
    if quic:
        args.append("--http3-only")
    else:
        args += ["-r", f"0-{INTERNET_BYTES - 1}"]
    args += [
        "--connect-timeout",
        str(CONNECT_TIMEOUT_S),
        "--max-time",
        str(CURL_MAX_TIME_S),
        url,
    ]
    return args


def _curl_child(cgroup_procs, args):
    """The moved child (the recwn-probe join): join the cgroup, then
    EXEC curl on its own pid — fork-before-socket, join-before-exec,
    so every socket curl creates is born inside the policed cgroup.
    Own process group first, set on both sides of the fork race-safe
    (the parent's wall kills this subtree without ever signaling
    itself); the -w measurement line rides the report pipe on stdout
    (dup2 before exec — the line IS the report), stderr rides the
    error pipe, and every other fd this fork carried is
    non-inheritable and dies at the exec — only fd 1 and fd 2
    cross."""
    os.setpgid(0, 0)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_DFL)
    try:
        with open(cgroup_procs, "w") as f:
            f.write(str(os.getpid()))
    except OSError:
        os._exit(126)  # the join failed — the parent's wait answers 126
    try:
        os.execvp(args[0], args)
    except OSError:
        os._exit(127)  # exec failed — the parent's wait answers 127


def _run_curl_child(cgroup_procs, args, wall_s):
    """One curl leg exec'd INSIDE the policed cgroup (the recwn-probe
    join): the -w line rides the report pipe, stderr the error pipe,
    the exit code comes out of waitpid, and the whole leg rides a
    hard wall — the wall expires, the child dies by SIGKILL and the
    leg names its reason. The worker stays alive either way, so the
    phase report still flushes and the parent's own deadline never
    has to fire. Returns the leg dict {rc, size, speed, err}."""
    rep_r, rep_w = os.pipe()
    err_r, err_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(rep_r)
        os.close(err_r)
        os.dup2(rep_w, 1)
        os.dup2(err_w, 2)
        os.close(rep_w)
        os.close(err_w)
        _curl_child(cgroup_procs, args)
    os.close(rep_w)
    os.close(err_w)
    deadline = time.monotonic() + wall_s
    out_chunks, err_chunks = [], []
    open_fds = {rep_r, err_r}
    while open_fds:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(pid, 0)
            except OSError:
                pass
            os.close(rep_r)
            os.close(err_r)
            return {
                "rc": -1,
                "size": 0,
                "speed": 0.0,
                "err": f"the leg exceeded its {wall_s:.0f}s wall — killed",
            }
        ready, _, _ = select.select(list(open_fds), [], [], remaining)
        if not ready:
            continue
        for fd in ready:
            chunk = os.read(fd, 65536)
            if chunk:
                (out_chunks if fd == rep_r else err_chunks).append(chunk)
            else:
                open_fds.discard(fd)  # EOF — the child closed this side
    _, status = os.waitpid(pid, 0)
    rc = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -1
    raw = b"".join(out_chunks).decode(errors="replace")
    err = b"".join(err_chunks).decode(errors="replace")[-200:]
    out = raw.split()
    try:
        size, speed = int(out[0]), float(out[1])
    except (ValueError, IndexError):
        size, speed = 0, 0.0
    return {"rc": rc, "size": size, "speed": speed, "err": err}


def _curl_range(url):
    """One capped download through curl (the ladder's leg driver):
    size_download is the metric, the exit code is informational.
    The leg execs curl INSIDE the policed cgroup (the recwn-probe
    join) and rides a hard wall."""
    return _run_curl_child(CG_PROCS, _curl_leg_args(url), CURL_MAX_TIME_S + LEG_WALL_SLACK_S)


def _curl_http3_supported():
    try:
        p = subprocess.run(["curl", "--version"], capture_output=True, text=True, timeout=10)
    except OSError:
        return False
    return "http3" in (p.stdout or "").lower()


def worker_main(go_r, report_w):
    """The cgroup member's legs. The parent has already moved THIS pid
    into the policed cgroup (the join happened before any socket
    exists — the pin-at-creation contract). One go byte per phase,
    ONE REPORT PER PHASE: the parent reads the ingress report before
    it rides on (the witness and the internet legs are the parent's
    side of the wall), so the worker flushes each report the moment
    its phase's legs are done and parks on the next go byte. The
    single end-of-run report this loop once wrote deadlocked the pair
    — the parent parked on the report pipe, the worker on the go
    pipe, and the probe hung past the ingress lane message forever
    (night-spark-4 hot-fix 3 follow-up)."""
    while True:
        phase = os.read(go_r, 1)
        if phase == b"1":
            # The ingress cmsg legs — download policy ONLY stands, so
            # a CE at the receiver names the ingress hook. The report
            # flushes NOW: the parent's cmsg and ledger rows read it
            # before the witness and the internet legs open.
            report = {"ect": _blast_leg(0x02), "notect": _blast_leg(0x00)}
            os.write(report_w, json.dumps(report).encode())
        elif phase == b"2":
            # The internet legs: TCP through the ladder, then QUIC.
            # Each leg is the recwn-probe join (fork, join, execv):
            # curl IS the cgroup member and every socket it makes is
            # born policed — the NIC-path engagement the loopback
            # blast legs alone could never prove.
            report = {}
            tcp_leg = {"endpoint": None, "rc": -1, "size": 0, "speed": 0.0}
            for name, tpl in INTERNET_LADDER:
                res = _curl_range(tpl.format(bytes=INTERNET_BYTES))
                if res["rc"] == 0 and res["size"] > 0:
                    tcp_leg = {"endpoint": name, **res}
                    break
                lib.out(f"  ... {name} leg failed (rc {res['rc']}): {res['err']}")
            report["tcp_leg"] = tcp_leg
            if _curl_http3_supported():
                report["quic_leg"] = {
                    "supported": True,
                    **_run_curl_child(
                        CG_PROCS,
                        _curl_leg_args(QUIC_URL, quic=True),
                        CURL_MAX_TIME_S + LEG_WALL_SLACK_S,
                    ),
                }
            else:
                report["quic_leg"] = {"supported": False}
            os.write(report_w, json.dumps(report).encode())
            break
        else:
            break
    os.close(report_w)


# ── the live lane ─────────────────────────────────────────────────────


def _plant_args(cg_id, *directions):
    """One strict invocation carrying EVERY standing direction. The
    CLI's unset-leg law (a direction the apply spec leaves unset is
    REMOVED, not left stale — policy_write.rs's improve-29) makes a
    single-direction re-plant strip the other leg: `-u 100kb` alone
    DELETES the standing download row, and the internet legs would
    ride an unpoliced lane (the nightpc live find: 793 kB/s past the
    100kb lane with a silent ledger, the row blaming a join that was
    never broken). Both legs in ONE invocation are both SET — the
    law has nothing to remove."""
    args = ["strict", f"cg:{cg_id}"]
    # The spelling expands per character ("du" -> -d AND -u): the
    # tuple carries the WHOLE word, and a word is not a flag.
    for d in "".join(directions):
        args += [f"-{d}", RATE_STR]
    args.append("--no-test")
    return args


def _plant(directions, cg_id):
    return lib.run_zel(_plant_args(cg_id, *directions))


def _send_phase(fd, phase):
    """One go byte to the worker: True delivered, False when the read
    end is gone (the worker died mid-lane) — the caller fails the lane
    honestly instead of letting BrokenPipeError crash the verdicts."""
    try:
        os.write(fd, phase)
        return True
    except BrokenPipeError:
        return False


def _read_report(fd, timeout_s):
    """One deadline-bounded read of a worker report. Returns (report,
    None) on a clean parse, (None, reason) on a missed deadline, a
    closed pipe (the worker died mid-lane), or an unparsable body —
    the caller records the honest FAIL and the teardown kills the
    child; the parent never parks forever on a worker that can no
    longer answer (night-spark-4 hot-fix 3 follow-up)."""
    ready, _, _ = select.select([fd], [], [], timeout_s)
    if not ready:
        return None, f"no report within the {timeout_s:.0f}s deadline"
    raw = os.read(fd, 65536)
    if not raw:
        return None, "the worker closed the report pipe (died mid-lane)"
    try:
        return json.loads(raw.decode()), None
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        return None, f"unparsable worker report: {e}"


def live_run():
    if os.geteuid() != 0:
        lib.out("FAIL: the live lane needs root (cgroup join, policy, tcpdump)")
        lib.out("      run: sudo ./scripts/bench/ecn-probe.sh")
        return 1
    if shutil.which("curl") is None:
        lib.out("FAIL: curl is not on PATH — the probe's own engine")
        return 1
    tcpdump = shutil.which("tcpdump")
    if tcpdump is None:
        lib.out(
            "  note: tcpdump is not on PATH — the tap-visible witness "
            "row SKIPs (the cmsg and the ledger carry the proof)"
        )
    started = time.monotonic()
    cg_dir = os.path.join(CG_ROOT, CG_NAME)
    if os.path.isdir(cg_dir):
        try:
            os.rmdir(cg_dir)
        except OSError as e:
            lib.out(f"FAIL: {cg_dir} exists and is busy ({e}) — a member process is alive")
            return 1
    try:
        os.mkdir(cg_dir)
    except OSError as e:
        lib.out(f"FAIL: could not create {cg_dir}: {e}")
        return 1
    cg_id = os.stat(cg_dir).st_ino
    cg_procs = os.path.join(cg_dir, "cgroup.procs")
    sysctl_saved = None
    worker_pid = None
    try:
        go_r, go_w = os.pipe()
        ready_r, ready_w = os.pipe()
        report_r, report_w = os.pipe()
        worker_pid = os.fork()
        if worker_pid == 0:
            os.close(go_w)
            os.close(ready_r)
            os.close(report_r)
            # The join happens BEFORE any socket exists — the pin at
            # creation is the whole attribution contract.
            with open(cg_procs, "w") as f:
                f.write(str(os.getpid()))
            os.write(ready_w, b"1")
            os.close(ready_w)
            worker_main(go_r, report_w)
            os._exit(0)
        os.close(go_r)
        os.close(ready_w)
        os.close(report_w)
        # The ready handshake, deadline-bounded: a worker that cannot
        # join (or died trying) fails the lane honestly — the parent
        # never parks on a pipe that will never answer.
        ready, _, _ = select.select([ready_r], [], [], READY_TIMEOUT_S)
        if not ready:
            lib.out(
                f"FAIL: the worker never confirmed the cgroup join within "
                f"{READY_TIMEOUT_S:.0f}s — teardown kills the child"
            )
            return 1
        if os.read(ready_r, 1) != b"1":
            lib.out("FAIL: the worker died before the cgroup join (no ready byte)")
            return 1
        os.close(ready_r)

        # The schema row first: a pre-v26 binary cannot ride this lane.
        # But an EMPTY limits[] is a clean host, not a pre-v26 object —
        # the v26 columns live ON a limit row, so with zero rows there
        # is nothing to read and absence proves nothing. The probe then
        # plants its own download policy NOW (the phase-1 plant pulled
        # ahead of the schema read), re-reads the ledger off the fresh
        # row it booked itself, and only a row that IS active with the
        # columns still gone earns the stale-pinned-object verdict.
        planted_for_schema = False
        verdict, pre_p, pre_b = schema_check(lib.status_json())
        if verdict == "empty":
            rc, out, err = _plant("d", cg_id)
            if rc != 0:
                lib.out(f"FAIL: strict -d {RATE_STR} exited {rc}: {(err or out)[:200]}")
                return 1
            planted_for_schema = True
            lib.out(
                "  schema: limits[] is empty (clean host) — planted the probe's "
                "own download policy, re-reading the v26 columns off the fresh row"
            )
            verdict, pre_p, pre_b = schema_check(lib.status_json())
        if verdict == "empty":
            lib.record(
                "recwn/ecn: the ledger carries the v26 CE columns",
                "FAIL",
                "limits[] still carries no row after the probe planted its own "
                "policy — the fresh row did not book, so the v26 columns cannot "
                "be verified (rebuild and re-apply)",
            )
            return 1
        lib.record(
            "recwn/ecn: the ledger carries the v26 CE columns",
            "PASS" if verdict == "present" else "FAIL",
            (
                "status --print-json limits[] .ce_marked_packets/.ce_marked_bytes "
                f"present (pre-baseline: {pre_p} pkts / {pre_b} B)"
            )
            if verdict == "present"
            else (
                "status --print-json limits[] .ce_marked_packets/.ce_marked_bytes "
                "ABSENT with a limit row active — a pre-v26 (stale pinned) object "
                "is loaded; rebuild and re-apply"
            ),
        )
        if verdict != "present":
            return 1

        # The sysctl flip (saved, restored in the finally below): the
        # internet TCP leg needs the CLIENT to request ECN — the kernel
        # default (2) negotiates only on incoming connections.
        try:
            with open(TCP_ECN_SYSCTL, "rb") as f:
                sysctl_saved = f.read()
            if sysctl_saved != TCP_ECN_ON:
                with open(TCP_ECN_SYSCTL, "wb") as f:
                    f.write(TCP_ECN_ON)
                lib.out(
                    "  sysctl: net.ipv4.tcp_ecn 2 -> 1 (the client requests ECN; restored at teardown)"
                )
        except OSError as e:
            lib.out(
                f"  note: the tcp_ecn flip failed ({e}) — the internet TCP leg will read honestly"
            )

        # Phase 1 — the ingress cmsg legs, download policy ALONE (the
        # policy already stands when the empty-ledger pre-flight planted
        # it: that plant is the same download-only shape, reused — never
        # a second plant racing the first).
        if not planted_for_schema:
            rc, out, err = _plant("d", cg_id)
            if rc != 0:
                lib.out(f"FAIL: strict -d {RATE_STR} exited {rc}: {(err or out)[:200]}")
                return 1
        if not _send_phase(go_w, b"1"):
            lib.out("FAIL: the worker is gone before the phase-1 go byte")
            return 1
        lib.out(
            f"  driving the cgroup ingress lane: {BLAST_BYTES // 1024} KiB of {PKT_BYTES} B "
            f"datagrams at {RATE_STR} (loopback, ECT(0) then Not-ECT)"
        )
        report, why = _read_report(report_r, INGRESS_REPORT_TIMEOUT_S)
        if report is None:
            lib.record(
                "ecn: the worker reported the ingress legs",
                "FAIL",
                f"{why} — the ingress lane is lost (the deadline bounds two "
                "drain-capped blast legs); teardown kills the child",
            )
            return 1
        ect = report.get("ect", {})
        notect = report.get("notect", {})
        lib.record(
            "ecn: the cgroup ingress lane marks ECT traffic CE",
            "PASS" if ect.get("ce_packets", 0) > 0 else "FAIL",
            f"receiver IP_RECVTOS reads CE on {ect.get('ce_packets', 0)} of "
            f"{ect.get('delivered', 0)} delivered datagrams ({ect.get('ce_bytes', 0)} B "
            f"marked, drain {ect.get('drain_s', 0):.1f}s) — the in-kernel "
            "bpf_skb_ecn_set_ce call on the cgroup lane, live",
        )
        lib.record(
            "ecn: the Not-ECT control stays at drop-lane parity",
            "PASS"
            if notect.get("ce_packets", 0) == 0
            and notect.get("delivered", 0) < ect.get("delivered", 0)
            else "FAIL",
            f"control delivered {notect.get('delivered', 0)} B with {notect.get('ce_packets', 0)} marks "
            f"vs the ECT leg's {ect.get('delivered', 0)} B — the helper's refusal IS "
            "the legacy verdict, and the ECT leg out-delivers it",
        )
        drain = max(ect.get("drain_s", 0.0), 1.0)
        bound = cap_bound_bytes(drain)
        doc = lib.status_json()
        _, led_p, led_b = parse_ce_ledger(doc)
        lib.record(
            "ecn: the ledger carries the marks inside the budget law",
            "PASS" if led_p > 0 and led_b <= bound else "FAIL",
            f"ce_marked {led_p} pkts / {led_b} B (bound {bound} B = cap {DEBT_CAP_BYTES} "
            f"+ rate*t {int(RATE_BPS * drain)} + one packet) — the schema-v26 "
            "columns, live",
        )

        # Phase 2 — the tap-visible witness: the upload policy joins,
        # a short ECT re-blast, tcpdump counts the egress marks. The
        # phase-2 go byte is sent HERE, once, when the witness rides:
        # the worker's internet legs ARE the witness window, so phase
        # 3 must not send the byte again — a second byte is garbage in
        # the pipe at best, a spurious lost-worker verdict at worst.
        phase2_sent = False
        if tcpdump is not None:
            # The witness window RE-PLANTS the download policy beside
            # the upload one, ONE invocation (the _plant_args law): a
            # `-u`-alone plant trips the unset-leg removal and strips
            # the standing download row — the exact shape that sent
            # the nightpc internet legs past an unpoliced lane. If
            # this plant fails, the phase-1 download policy still
            # stands and the internet legs stay policed either way.
            rc, out, err = _plant("du", cg_id)
            if rc == 0:
                if not _send_phase(go_w, b"2"):
                    lib.record(
                        "ecn: the tcpdump witness counts CE-marked packets",
                        "FAIL",
                        "the worker is gone before the phase-2 go byte — the "
                        "lane is lost; teardown kills the child",
                    )
                    return 1
                phase2_sent = True
                tcpdump_run = subprocess.Popen(
                    [tcpdump, "-i", "lo", "-n", "--immediate-mode", "-c", "5", TCPDUMP_FILTER],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                # The worker's phase 2 rides the internet legs; the
                # loopback re-blast is folded into the phase-1 shape —
                # instead, the witness reads the WHOLE window (the
                # phase-1 egress marks on the sender side are
                # unpoliced, so this capture brackets phase 2's
                # upload-policed traffic only).
            else:
                lib.out(
                    f"  note: the both-legs plant failed ({(err or out)[:120]}) — the "
                    "witness row SKIPs; the standing download policy still polices "
                    "the internet legs"
                )
                tcpdump_run = None
        else:
            tcpdump_run = None

        # Phase 3 — the internet legs (the upload policy may stand: the
        # witness window is already banked; the ledger rows read the
        # DELTA the internet traffic itself books).
        pre_led_p, pre_led_b = led_p, led_b
        if not phase2_sent and not _send_phase(go_w, b"2"):
            lib.record(
                "ecn: the worker reported the internet legs",
                "FAIL",
                "the worker is gone before the phase-2 go byte — the lane is "
                "lost; teardown kills the child",
            )
            return 1
        # Wait for the worker's second report (the internet legs),
        # deadline-bounded: the ladder's own curl max-times bound the
        # worker's phase, so a report that misses the deadline names a
        # lost worker, not a patient hang.
        report2, why = _read_report(report_r, INTERNET_REPORT_TIMEOUT_S)
        if report2 is None:
            lib.record(
                "ecn: the worker reported the internet legs",
                "FAIL",
                f"{why} — the internet lane is lost; teardown kills the child",
            )
            return 1
        if tcpdump_run is not None:
            try:
                tcpdump_run.terminate()
                _, tcp_err = tcpdump_run.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                tcpdump_run.kill()
                _, tcp_err = tcpdump_run.communicate()
            m = None
            for line in (tcp_err or "").splitlines():
                if "packets captured" in line or "packet captured" in line:
                    m = line.strip()
                    break
            lib.record(
                "ecn: the tcpdump witness counts CE-marked packets",
                "PASS" if m and not m.startswith("0") else "SKIP",
                f"tcpdump '{TCPDUMP_FILTER}' on lo: {m or 'no capture line'} — "
                "the egress hook marks BEFORE the dev-layer tap "
                "(v5.15 net/ipv4/ip_output.c:306,325), the witness shape "
                "the floor serves; the ingress marks of the cmsg rows land "
                "after the tap (dev.c:5287) and are the cmsg/ledger's to prove",
            )
        tcp_leg = report2.get("tcp_leg", {})
        quic_leg = report2.get("quic_leg", {})
        doc = lib.status_json()
        _, post_p, post_b = parse_ce_ledger(doc)
        delta_p, delta_b = post_p - pre_led_p, post_b - pre_led_b
        dl_standing = download_leg_standing(doc, cg_id, RATE_BPS)
        tcp_verdict = internet_tcp_verdict(
            tcp_leg.get("size", 0), delta_p, tcp_leg.get("speed", 0.0)
        )
        if tcp_verdict == "FAIL":
            if tcp_leg.get("size", 0) <= 0:
                tcp_detail = (
                    f"curl {tcp_leg.get('endpoint') or 'no ladder rung answered'} "
                    f"(rc {tcp_leg.get('rc', -1)}): {tcp_leg.get('size', 0)} B — "
                    f"{(tcp_leg.get('err') or 'no rung delivered bytes')[:140]}; "
                    "the internet TCP leg itself failed"
                )
            elif not dl_standing:
                tcp_detail = (
                    f"curl {tcp_leg.get('endpoint')}: {tcp_leg.get('size', 0)} B at "
                    f"{tcp_leg.get('speed', 0.0):.0f} B/s with the ledger silent — "
                    f"the {RATE_STR} download policy is GONE from cg:{cg_id} at the "
                    "internet boundary (status limits[] reads no download leg): the "
                    "lane had nothing to enforce, the bypass is the policy's, not "
                    "the join's — a concurrent unstrict or a failed plant lands here"
                )
            else:
                tcp_detail = (
                    f"curl {tcp_leg.get('endpoint')}: {tcp_leg.get('size', 0)} B at "
                    f"{tcp_leg.get('speed', 0.0):.0f} B/s with the ledger silent — "
                    f"the transfer ran past the {RATE_STR} lane's rate, the lane "
                    "never engaged the leg: the in-cgroup join did not reach "
                    "the socket (the bypass the recwn join exists to kill)"
                )
        elif tcp_verdict == "SKIP":
            tcp_detail = (
                f"curl {tcp_leg.get('endpoint')}: {tcp_leg.get('size', 0)} B at "
                f"{tcp_leg.get('speed', 0.0):.0f} B/s — throttled to the lane and "
                f"delivered, the ledger moved {delta_p} pkts / {delta_b} B during "
                "the internet legs: a non-ECN hop rode the drop lane (the "
                "policer's engagement is proven by the rate, the marks are the "
                "cmsg rows' to prove on ECT traffic)"
            )
        else:
            tcp_detail = (
                f"curl {tcp_leg.get('endpoint')}: {tcp_leg.get('size', 0)} B at "
                f"{tcp_leg.get('speed', 0.0):.0f} B/s; the ledger moved {delta_p} pkts / "
                f"{delta_b} B during the internet legs — the policed lane's own "
                "marks, the schema-v26 columns on live internet TCP"
            )
        lib.record("ecn: the internet TCP leg books CE marks", tcp_verdict, tcp_detail)
        if not quic_leg.get("supported", False):
            lib.record(
                "ecn: the QUIC leg (http3) rides the marking lane",
                "SKIP",
                "the local curl cannot speak HTTP/3 (no http3 feature in "
                "`curl --version`) — the honest skip; install an http3-capable "
                "curl and rerun to prove the QUIC/UDP leg live",
            )
        else:
            lib.record(
                "ecn: the QUIC leg (http3) rides the marking lane",
                "PASS" if quic_leg.get("size", 0) > 0 else "FAIL",
                f"curl --http3-only {QUIC_URL}: {quic_leg.get('size', 0)} B at "
                f"{quic_leg.get('speed', 0.0):.0f} B/s (rc {quic_leg.get('rc', -1)}) "
                "{err}".format(err=f"; {quic_leg.get('err', '')}" if quic_leg.get("err") else "")
                + " — QUIC sends ECT(0) by default (RFC 9000): the policer's "
                "CE marks reach the QUIC stack's own congestion controller, "
                "backoff without retransmission",
            )
        lib.out(f"  ECN live probe — the cgroup lanes, {time.monotonic() - started:.0f}s")
        rows_ok = all(r["verdict"] != "FAIL" for r in lib.RESULTS)
        return 0 if rows_ok else 1
    finally:
        # The scoped teardown, best-effort, never a verdict.
        if worker_pid:
            try:
                os.kill(worker_pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                os.waitpid(worker_pid, 0)
            except OSError:
                pass
        try:
            lib.run_zel(["unstrict", f"cg:{cg_id}"])
        except Exception:
            pass
        if sysctl_saved is not None:
            try:
                with open(TCP_ECN_SYSCTL, "wb") as f:
                    f.write(sysctl_saved)
            except OSError:
                pass
        try:
            os.rmdir(cg_dir)
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser(
        description="zelynic ECN live probe (night-spark-4 — the quota saver's Layer 2)"
    )
    ap.add_argument("--self-test", action="store_true", help="instrument lane only, no root")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--binary", default=None, help="zelynic binary to drive")
    args = ap.parse_args()
    if args.self_test:
        rc = self_test()
    else:
        # The lane shipped without this call once — lib.BINARY stayed ""
        # and every run_zel died with a FileNotFoundError while the
        # instrument lane stayed green. Resolved on the root path only,
        # so the rootless invocation keeps live_run's own needs-root error.
        if os.geteuid() == 0 and not lib.resolve_binary(
            args.binary, "sudo ./scripts/bench/ecn-probe.sh"
        ):
            return 2
        rc = live_run()
    if args.json:
        lib.out(json.dumps(lib.RESULTS, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
