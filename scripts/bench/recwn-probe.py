#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
"""zelynic RECWN live probe (night-spark-2 — Receive Window Control,
the quota saver's Layer 1), measured on the running kernel with the
owner's own verification recipe.

The RECWN lane (schema v25) says: a policed cgroup's own sockets
advertise a receive window shaped like the policy's bandwidth-delay
product (rate x 200 ms, clamped to [2 x MSS, 1 MiB]) — the
sender-side slowdown that stops download quota burning BEFORE the
ingress link bills the bytes. The rootless battery
(test/ebpf/limiter/recwn_tests.rs) pins the window law on the pure
core; this harness pins the KERNEL side of the lane on a real
cgroup, a real curl child, and the real internet:

  row 1 — the instrument (rootless, --self-test): the window law's
    own clamp table, the `ss -ti` field parser round-tripped on
    fixture lines, and the owner-defined recwn_limits JSON schema
    checked on a fixture document. Without this row a live FAIL
    could always be blamed on the measurement, never the kernel —
    the instrument is pinned FIRST, the discipline every claims
    harness here carries.

  row 2 — the lane plants with the owner's schema (live): a real
    cgroup, `zelynic strict cg:<id> -d 100kb --no-test`, and
    `status --print-json` carrying EXACTLY
    recwn_limits {"enabled":true,"window_bytes":5000,
    "rtt_estimate_us":50000} — the task brief's own numbers.

  row 3 — the advertised window is clamped to the RECWN scale
    (live): a curl child moved INTO the policed cgroup (its sockets
    created after the move — the attribution contract) downloading
    through the real internet while the parent samples `ss -tip`
    scoped to the curl child's own pid: rcv_space / rcv_ssthresh
    bounded at the clamped buffer's own scale, decisively below the
    ~128 KiB the unpoliced default auto-tunes to.

  row 4 — the throughput rides the policy band (live): curl's own
    measured average download speed inside the realnet band around
    the 100 kb/s target — the policer held the line while the
    sender slowed itself.

  row 5 — retransmits are near zero (live): the connection's
    retransmit count against its segment count, read from ss's
    `retrans:A/B` cumulative second member on the curl child's own
    sockets (the pair's first member is the instantaneous in-flight
    count; ss omits the pair entirely on clean connections, and
    absence there means zero) — the whole point of shaping the
    window instead of letting the drops teach the sender.

Honesty contracts: the child is forked BEFORE any socket exists and
writes its own pid into the target's cgroup.procs only AFTER the
policy stands (the curl sockets are born policed — the same
attribution contract every leaf battery here carries); the download
is the real internet (the tele2 endpoint the owner's own command
names, the cloudflare __down mirror as the fallback); the ss samples
read the kernel's own tcp_info fields while the transfer runs, and
every raw number the verdicts rode prints in the row detail;
teardown is best-effort and never fails a verdict. The transfer is
capped at 3 MiB by default (~30 s at 100 kb/s — the owner's full
10MB run rides --bytes 10485760).

Runtime contract (the 2026-11-03 owner run's lesson: tele2 sat
through the flat 240 s max-time with zero output, and ^C never
reached the parent — the retry note printed after the first one):
every leg is self-bounded (curl --connect-timeout 10, --max-time
scaled to the byte cap), progress prints every 15 s so a dead mirror
can never read as a hang, and the abort path is owned outright — the
curl child rides its own process group, the first
SIGINT/SIGTERM/SIGHUP kills that group, runs the scoped teardown,
and exits 128+signum (a second signal hard-exits), so the probe never
depends on terminal signal delivery surviving sudo's relay.

Instrument contract (the 2026-11-03 18:23 run's lesson: the band
held at 98.7 KB/s while BOTH evidence rows read FAIL): the ss sweep
kept every socket on the desktop that carried a tcp_info line —
~175 bystanders a snapshot — so a browser's auto-tuned 131072-byte
rcv_space answered for the lane's advertised window (row 3) and the
last bystander's retrans-less 18-segment history answered for the
lane's own retransmits (row 5, the -1/18 read). The sampler now
carries the curl child's own pid, and every verdict rides the
child's sockets alone.

Root required for the live run; --self-test is the CI lane.
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

# The shared engine lib lives in scripts/lib/ (NIGHT-refactor-1) — bound
# by ABSOLUTE path so the harness works from any CWD.
_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, _LIB_DIR)

sys.dont_write_bytecode = True  # root-owned pycache guard, docs/MAINTENANCE.md 7
import zelynic_harness_lib as lib  # noqa: E402

# The task brief's own geometry, carried through the estimate the
# live E2E evidence set: 100 kb/s download-only, the 200 ms
# delivery-cadence estimate (raised from the briefed 50 ms after the
# E2E legs measured 29-37% under-delivery on all three CI kernels —
# recwn.rs's doc owns the record), the 20_000-byte window it derives.
RATE_STR = "100kb"
RATE_BPS = 100_000
EXPECTED_WINDOW_BYTES = 20_000
EXPECTED_RTT_ESTIMATE_US = 200_000
# The clamp evidence bound: the kernel sets sk_rcvbuf to twice the
# passed window (sock_setsockopt's val * 2), and rcv_space /
# rcv_ssthresh auto-tune inside that buffer — anything at or below
# 64 KiB is the clamped lane's own scale (the 100 kb window of
# 20_000 B doubles to a 40 KiB buffer); the unpoliced default
# auto-tunes rcv_space to 128 KiB and beyond, so the bound separates
# the regimes decisively.
CLAMP_BOUND_BYTES = 65_536
# The retransmit verdict: near zero means under 1% of the segments
# the connection moved (the drop-policer's own retransmit cadence is
# the baseline this lane exists to beat).
RETRANS_FRACTION_MAX = 0.01
# The realnet download candidates — the owner's own command first
# (tele2 10MB.zip, range-capped), the cloudflare __down mirror
# second (the supermassive realnet registry's own family). Both legs
# carry the SAME byte cap: the .zip side rides a range request, the
# __down side sizes itself through the {bytes} template (the first
# cut hardcoded 10 MiB there, silently tripling the fallback leg's
# policy-time).
DL_CANDIDATES = [
    ("tele2", "http://speedtest.tele2.net/10MB.zip"),
    ("cloudflare", "https://speed.cloudflare.com/__down?bytes={bytes}"),
]
DEFAULT_BYTES = 3 * 1024 * 1024
# The runtime bounds (the 2026-11-03 owner run: tele2 sat through the
# flat 240 s max-time with zero output and a Ctrl-C that never landed,
# so a dead mirror read as a hang). --connect-timeout kills an
# unreachable mirror in seconds; --max-time scales with the byte cap —
# twice the policy-time transfer plus handshake/slow-start slack — so
# every leg self-terminates and a below-band leg fails fast onto the
# next mirror instead of stalling the whole probe.
CONNECT_TIMEOUT_S = 10
MAX_TIME_SLACK_S = 45


def curl_max_time_s(byte_cap):
    """curl's --max-time for one leg: 2x the capped transfer + slack."""
    return max(60, 2 * byte_cap // RATE_BPS + MAX_TIME_SLACK_S)


CG_ROOT = "/sys/fs/cgroup"
CG_NAME = "zelynic-recwn-probe"


# ── The abort contract (the 2026-11-03 owner run's lesson) ───────
# The live lane sat through a dead mirror for minutes with no output,
# and Ctrl-C could not break it — the retry note still printed after
# the first ^C, so the parent never saw the signal at all. The
# contract now stops depending on terminal signal delivery surviving
# sudo's relay: the curl child rides its OWN process group, the first
# SIGINT/SIGTERM/SIGHUP kills that group outright, the scoped
# teardown runs, and the exit code is 128+signum; a second signal
# hard-exits immediately. Combined with the per-leg bounds above, the
# probe terminates on its own even when no signal ever arrives.
_CHILD_PG = [0]
_ABORT_SIGNUM = [0]


def _abort(signum, _frame):
    if _CHILD_PG[0]:
        try:
            os.killpg(_CHILD_PG[0], signal.SIGKILL)
        except OSError:
            pass
    if _ABORT_SIGNUM[0]:
        lib.out(f"  abort: second signal {signum} — hard exit, teardown abandoned")
        os._exit(128 + signum)
    _ABORT_SIGNUM[0] = signum
    raise KeyboardInterrupt


def _install_abort_handlers():
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _abort)


# ── The instrument (rootless) ─────────────────────────────────────


def parse_ss_tcp_info(text):
    """Parse `ss -tip` output into per-connection dicts, each carrying
    BOTH the header row's identity and the tcp_info line's counters.

    Identity fields: pid (int or None — ss shows no owner for a
    socket the uid cannot attribute), local / peer (the header's
    address columns, verbatim — the grouping key when a leg samples
    more than one socket). Counter fields: rcv_space, rcv_ssthresh,
    segs_out, retrans_out, retrans_total. The retrans pair's two
    members are NOT interchangeable: ss feeds them tcp_info's
    tcpi_retrans (the INSTANTANEOUS in-flight retransmit count — it
    goes down as well as up) and tcpi_total_retrans (the
    connection's CUMULATIVE total — the only member a verdict may
    divide), and iproute2 prints the pair ONLY when at least one
    member is nonzero (ss.c v6.15: `if (s->retrans ||
    s->retrans_total)`), so a clean connection carries no pair at
    all — absence reads as 0/0, never as a missing measurement.
    Only connections carrying a detailed info line yield entries,
    and every entry is the socket that OWNS the header above it —
    the 18:23 owner run's live FAIL read the whole desktop's
    sockets as the lane's own.
    """
    conns = []

    def _close(header, fields):
        if header is None or not fields:
            return
        pid = None
        proc = None
        m = re.search(r'users:\(\("([^"]*)",pid=(\d+)', header)
        if m:
            proc = m.group(1)
            pid = int(m.group(2))
        # The address columns: the header before `users:` splits into
        # [Netid] State Recv-Q Send-Q local peer — a space-named
        # process (users:(("Web Content",...)) never leaks tokens
        # into the address side because the users: tail is
        # partitioned off before the split.
        addr_side = header.split("users:")[0].split()
        entry = dict(fields)
        entry["pid"] = pid
        entry["proc"] = proc
        entry["local"] = addr_side[-2] if len(addr_side) >= 2 else ""
        entry["peer"] = addr_side[-1] if addr_side else ""
        conns.append(entry)

    header = None
    fields = {}
    for line in text.splitlines():
        if not line.startswith(("\t", " ")):
            _close(header, fields)
            header, fields = line, {}
            continue
        for name, pattern in [
            ("rcv_space", r"rcv_space:(\d+)"),
            ("rcv_ssthresh", r"rcv_ssthresh:(\d+)"),
            ("segs_out", r"segs_out:(\d+)"),
            ("retrans_out", r"retrans:(\d+)/(\d+)"),
        ]:
            m = re.search(pattern, line)
            if m:
                if name == "retrans_out":
                    fields["retrans_out"] = int(m.group(1))
                    fields["retrans_total"] = int(m.group(2))
                else:
                    fields[name] = int(m.group(1))
    _close(header, fields)
    return conns


def retrans_wholelife(samples):
    """The sampled sockets' whole-life retransmit counts: the summed
    retrans_total and segs_out over the LAST sample of each socket.

    Both counters are cumulative from each socket's own
    establishment, so the last sample of a socket carries that
    connection's entire history — no first-sample subtraction, no
    sampling-window arithmetic: the verdict reads the connection's
    own totals exactly the way the row's brief words it. A leg that
    opened more than one socket (a redirect, an address-family
    retry) sums each socket's own whole-life counters; a reused
    4-tuple answers with its newest life, the only one the counters
    ever held.
    """
    last = {}
    for s in samples:
        last[(s.get("local", ""), s.get("peer", ""))] = s
    retrans = sum(s.get("retrans_total", 0) for s in last.values())
    segs = sum(s.get("segs_out", 0) for s in last.values())
    return retrans, segs


SS_FIXTURE = """State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0 0 192.0.2.10:443 203.0.113.7:52988 users:(("curl",pid=4242,fd=3))
\t cubic wscale:8,7 rto:364 rtt:12.5/24 ato:40 mss:1448 rcv_space:131072 rcv_ssthresh:131072 segs_out:812 retrans:0/3
ESTAB 0 0 192.0.2.10:52304 198.51.100.9:80 users:(("curl",pid=4243,fd=3))
\t cubic wscale:7,7 rto:364 rtt:8.75/17.5 ato:40 mss:1448 rcv_space:6144 rcv_ssthresh:6144 segs_out:204 retrans:2/7
ESTAB 0 0 192.0.2.10:52310 198.51.100.9:80 users:(("Web Content",pid=5599,fd=67))
\t cubic wscale:7,7 rto:364 rtt:9.5/19 ato:40 mss:1448 rcv_space:131072 rcv_ssthresh:131072 segs_out:18
"""


def self_test():
    """The rootless instrument lane: the law, the parser, the schema."""
    rows = []

    # The window law's clamp table (the pure core's own pins, restated
    # on the instrument so a live FAIL cannot be blamed on the
    # formula).
    law_cases = [
        (1_000, 2920),
        (100_000, EXPECTED_WINDOW_BYTES),
        (1_000_000, 200_000),
        (0, 2920),
        (40_000_000, 1_048_576),
    ]
    for rate, expected in law_cases:
        got = min(max(rate * EXPECTED_RTT_ESTIMATE_US // 1_000_000, 2920), 1_048_576)
        rows.append(
            (
                f"law: {rate} B/s -> {expected} B",
                got == expected,
                f"window law computed {got} B",
            )
        )

    # The runtime bounds: --connect-timeout is a flat constant and
    # --max-time scales with the byte cap — the pair that keeps a dead
    # mirror from ever reading as a hang (pinned here so a live stall
    # can never be blamed on the bound math).
    for cap, expected in [
        (DEFAULT_BYTES, 107),
        (10_485_760, 254),
        (0, 60),
    ]:
        got = curl_max_time_s(cap)
        rows.append(
            (
                f"law: curl --max-time for {cap:,} B -> {expected}s",
                got == expected,
                f"computed {got}s (2x transfer + {MAX_TIME_SLACK_S}s slack, floor 60)",
            )
        )

    # The ss parser round-trip on the fixture: the column header, an
    # UNPOLICED-scale curl (another curl on the box must never ride
    # the evidence), the clamped-scale curl (the RECWN regime), and a
    # space-named bystander whose omitted retrans pair is the exact
    # shape that answered row 5 with -1/18 on the owner's box.
    conns = parse_ss_tcp_info(SS_FIXTURE)
    rows.append(
        (
            "ss parser: three connections parsed with owner identity",
            len(conns) == 3,
            f"parsed {len(conns)} connections with tcp_info lines",
        )
    )
    if len(conns) == 3:
        rows.append(
            (
                "ss parser: each entry owns its header's identity",
                conns[0].get("pid") == 4242
                and conns[0].get("local") == "192.0.2.10:443"
                and conns[1].get("pid") == 4243
                and conns[2].get("pid") == 5599
                and conns[2].get("peer") == "198.51.100.9:80",
                f"pids={[c.get('pid') for c in conns]} "
                f"locals={[c.get('local') for c in conns]}",
            )
        )
        mine = [c for c in conns if c.get("pid") == 4243]
        rows.append(
            (
                "ss parser: the pid filter keeps the policed curl alone",
                len(mine) == 1 and mine[0].get("rcv_space") == 6144,
                f"pid 4243 -> {[c.get('rcv_space') for c in mine]} "
                f"(the 131072-scale curl 4242 and the bystander stay out)",
            )
        )
        rows.append(
            (
                "ss parser: retrans reads out=2 total=7, an absent pair reads 0",
                conns[1].get("retrans_out") == 2
                and conns[1].get("retrans_total") == 7
                and conns[2].get("retrans_total", 0) == 0,
                f"pair out={conns[1].get('retrans_out')}/total={conns[1].get('retrans_total')}; "
                f"bystander total={conns[2].get('retrans_total', 0)} (ss omits the pair when "
                f"both members are zero)",
            )
        )

    # The retrans verdict's own law: whole-life cumulative counters,
    # summed across the sockets the leg actually sampled.
    clean = [
        {"local": "10.0.0.1:40000", "peer": "198.51.100.9:443", "segs_out": 5317},
        {"local": "10.0.0.1:40000", "peer": "198.51.100.9:443", "segs_out": 8123},
    ]
    r, s = retrans_wholelife(clean)
    rows.append(
        (
            "law: a clean sampled socket reads 0 retranss over its segments",
            (r, s) == (0, 8123),
            f"retrans_wholelife -> {r}/{s} (the omitted pair is zero, never a sentinel)",
        )
    )
    lossy = [
        {
            "local": "10.0.0.1:40001",
            "peer": "198.51.100.9:443",
            "segs_out": 300,
            "retrans_out": 0,
            "retrans_total": 9,
        },
        {
            "local": "10.0.0.1:40002",
            "peer": "198.51.100.9:443",
            "segs_out": 100,
            "retrans_out": 0,
            "retrans_total": 0,
        },
    ]
    r, s = retrans_wholelife(lossy)
    rows.append(
        (
            "law: whole-life retrans sums each socket's own counters",
            (r, s) == (9, 400) and r / s > RETRANS_FRACTION_MAX,
            f"retrans_wholelife -> {r}/{s} = {r / s * 100:.2f}% (two sockets, last sample each)",
        )
    )

    # The owner-defined recwn_limits schema on a fixture document:
    # the exact three-field object, the enabled:false absent-window
    # shape, and the additive absence.
    fixture = (
        '{"watchdog":"enforcing","active_limits":1,"limits":[],"recwn_limits":'
        '{"enabled":true,"window_bytes":20000,"rtt_estimate_us":200000}}'
    )
    doc = json.loads(fixture)
    rows.append(
        (
            "schema: the owner's exact object parses",
            doc["recwn_limits"]
            == {
                "enabled": True,
                "window_bytes": EXPECTED_WINDOW_BYTES,
                "rtt_estimate_us": EXPECTED_RTT_ESTIMATE_US,
            },
            f"recwn_limits={doc['recwn_limits']}",
        )
    )
    fixture_disabled = (
        '{"watchdog":"enforcing","active_limits":0,"limits":[],"recwn_limits":'
        '{"enabled":false,"rtt_estimate_us":200000}}'
    )
    doc = json.loads(fixture_disabled)
    rows.append(
        (
            "schema: enabled:false carries no fabricated window",
            doc["recwn_limits"] == {"enabled": False, "rtt_estimate_us": EXPECTED_RTT_ESTIMATE_US}
            and "window_bytes" not in doc["recwn_limits"],
            f"recwn_limits={doc['recwn_limits']}",
        )
    )
    rows.append(
        (
            "schema: the clean document carries no recwn_limits at all",
            "recwn_limits" not in json.loads('{"watchdog":"clean","limits":[]}'),
            "additive absence held",
        )
    )

    # The abort contract: SIGINT must land as KeyboardInterrupt with
    # the child-group kill armed — pinned by signaling a forked twin
    # that carries this module's own handler setup (a live hang can
    # then be the kernel or the network, never a broken abort path).
    ar, aw = os.pipe()
    apid = os.fork()
    if apid == 0:
        os.close(ar)
        _install_abort_handlers()
        try:
            os.kill(os.getpid(), signal.SIGINT)
            time.sleep(5)  # a lost signal shows up as the 5 s silence
        except KeyboardInterrupt:
            try:
                os.write(aw, b"ok")
            except OSError:
                pass
        os._exit(0)
    os.close(aw)
    with os.fdopen(ar) as f:
        abort_got = f.read()
    os.waitpid(apid, 0)
    rows.append(
        (
            "abort: SIGINT raises KeyboardInterrupt (the handler contract)",
            abort_got == "ok",
            f"the forked twin reported {abort_got!r}",
        )
    )

    for name, verdict, detail in rows:
        # lib.record feeds lib.RESULTS so --json carries the instrument
        # rows exactly as it carries the live ones (the ect-probe shape).
        lib.record(name, "PASS" if verdict else "FAIL", detail)
    ok = all(v for _, v, _ in rows)
    lib.out()
    lib.out(
        f"  {sum(1 for _, v, _ in rows if v)} passed, "
        f"{sum(1 for _, v, _ in rows if not v)} failed — self-test instrument"
    )
    return 0 if ok else 1


# ── The live lane ─────────────────────────────────────────────────


def ensure_root():
    if os.geteuid() != 0:
        lib.out("error: the live RECWN probe needs root (cgroup + eBPF attach)")
        lib.out("      run --self-test for the rootless instrument lane")
        return False
    if not lib.cgroup2_mounted():
        lib.out("error: cgroup v2 is not mounted at /sys/fs/cgroup")
        return False
    return True


def curl_child(cgroup_procs, url, byte_cap, report_fd, max_time_s):
    """The moved child: join the cgroup, then exec curl.

    Its OWN process group first (set on both sides of the fork,
    race-safe): the parent's abort kills this whole subtree with one
    killpg without ever signaling itself, and the parent's terminal
    signals stay the parent's alone — the parent owns this subtree's
    fate, whatever the sudo/tty relay does with ^C. The policy stood
    before the fork (row 2), so the sockets curl creates are born
    inside the policed cgroup (the attribution contract). Writes
    curl's own measurement line (speed_download size_download) to
    report_fd.
    """
    os.setpgid(0, 0)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_DFL)
    with open(cgroup_procs, "w") as f:
        f.write(str(os.getpid()))
    # Range-cap the transfer when the endpoint honors ranges (tele2
    # does; the cloudflare __down mirror sizes itself to the cap).
    if byte_cap and url.endswith(".zip"):
        curl_args = ["curl", "-fsSL", "-r", f"0-{byte_cap - 1}"]
    else:
        curl_args = ["curl", "-fsSL"]
    curl_args += [
        "-o",
        "/dev/null",
        "-w",
        "%{speed_download} %{size_download}\\n",
        "--connect-timeout",
        str(CONNECT_TIMEOUT_S),
        "--max-time",
        str(max_time_s),
        url,
    ]
    out = subprocess.run(curl_args, capture_output=True, text=True, timeout=max_time_s + 15)
    with os.fdopen(report_fd, "w") as f:
        f.write(f"{out.returncode} {out.stdout.strip()}\n")
    os._exit(0)


def _ss_snapshot_curl(child_pid):
    """One `ss -tip` sweep, keeping ONLY the curl child's own sockets.

    The 18:23 owner run's lesson: this sweep used to keep EVERY
    connection on the box that carried a tcp_info line — on the
    owner's daily-driver desktop that was ~175 sockets a snapshot,
    so a bystander's auto-tuned 131072-byte rcv_space answered for
    the lane's advertised window (row 3 FAIL) and the last
    bystander's retrans-less 18-segment history answered for the
    lane's own retransmits (row 5 FAIL) while the lane itself held
    the band at 98.7 KB/s. The scope is the child's own pid — not a
    name match, so another curl on the box can never ride the
    evidence.
    """
    try:
        text = subprocess.run(["ss", "-tip"], capture_output=True, text=True, timeout=5).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []
    return [
        c
        for c in parse_ss_tcp_info(text)
        if c.get("pid") == child_pid and c.get("rcv_space") is not None
    ]


def _run_leg(name, url, byte_cap, cg_dir, sample_s):
    """Drive one download leg: fork the moved child, sample `ss -tip`
    beside the transfer (scoped to the child's own pid — the
    instrument contract), heartbeat while it runs, collect its report.

    The wait is a WNOHANG poll, not a blocking waitpid: the leg stays
    readable for its whole life (a heartbeat every 15 s — the owner's
    2026-11-03 run sat silent through a dead mirror and read as a
    hang), and the abort handler's KeyboardInterrupt lands inside the
    poll loop instead of parking inside the kernel.
    """
    max_time_s = curl_max_time_s(byte_cap)
    lib.out(
        f"  driving the {name} lane: {byte_cap:,} B at {RATE_STR} "
        f"(connect {CONNECT_TIMEOUT_S}s, max {max_time_s}s)"
    )
    rep_r, rep_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        curl_child(os.path.join(cg_dir, "cgroup.procs"), url, byte_cap, rep_w, max_time_s)
    os.close(rep_w)
    try:
        os.setpgid(pid, pid)
    except OSError:
        pass  # the child's own setpgid already won the race
    _CHILD_PG[0] = pid

    samples = []
    leg_start = time.monotonic()
    sample_deadline = leg_start + sample_s
    last_beat = leg_start
    while True:
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            wpid = pid
        if wpid == pid:
            break
        now = time.monotonic()
        if now < sample_deadline:
            samples.extend(_ss_snapshot_curl(pid))
        if now - last_beat >= 15:
            lib.out(f"  ... {name} leg {now - leg_start:.0f}s in, {len(samples)} curl-socket samples")
            last_beat = now
        time.sleep(0.5)
    _CHILD_PG[0] = 0

    # The child's own measurement. A report that never arrived (the
    # child died before its write) reads as a failed leg, not an
    # unhandled IndexError.
    with os.fdopen(rep_r) as f:
        report = f.read().strip().split(" ", 1)
    curl_rc = int(report[0]) if report and report[0].isdigit() else 1
    speed_bps = float(report[1].split()[0]) if len(report) > 1 and report[1] else 0.0
    size_bytes = int(report[1].split()[1]) if len(report) > 1 and len(report[1].split()) > 1 else 0
    lib.out(f"  ... {name} leg done: curl rc {curl_rc}, {size_bytes:,} B, {lib.fmt_bps(speed_bps)}")
    return curl_rc, speed_bps, size_bytes, samples


def live_run(byte_cap):
    if not ensure_root():
        return 1
    started = time.monotonic()
    if shutil.which("curl") is None:
        lib.out("FAIL: curl is not on PATH — the probe's own engine")
        return 1

    cg_dir = os.path.join(CG_ROOT, CG_NAME)
    # Pre-clean (a crashed predecessor's leftover): a cgroup v2 dir
    # comes out with rmdir — the control files are kernfs and refuse
    # unlink, so rmtree can never remove one. An EMPTY leftover
    # removes cleanly; a BUSY one means a member process is alive —
    # another probe run is mid-flight and this one must not stomp it.
    if os.path.isdir(cg_dir):
        try:
            os.rmdir(cg_dir)
        except OSError as e:
            lib.out(f"FAIL: {cg_dir} exists and is busy ({e}) — a member process is alive")
            lib.out("      another probe run mid-flight? sudo pkill -9 -f recwn-probe.py")
            return 1
    try:
        os.mkdir(cg_dir)
    except OSError as e:
        lib.out(f"FAIL: could not create {cg_dir}: {e}")
        return 1
    cg_id = os.stat(cg_dir).st_ino

    try:
        # Row 2 — the apply and the owner's exact schema.
        rc, stdout, stderr = lib.run_zel(["strict", f"cg:{cg_id}", "-d", RATE_STR, "--no-test"])
        if rc != 0:
            lib.out(f"FAIL: strict -d {RATE_STR} exited {rc}: {(stderr or stdout)[:200]}")
            return 1
        doc = lib.status_json()
        recwn = (doc or {}).get("recwn_limits")
        schema_ok = recwn == {
            "enabled": True,
            "window_bytes": EXPECTED_WINDOW_BYTES,
            "rtt_estimate_us": EXPECTED_RTT_ESTIMATE_US,
        }
        lib.record(
            "recwn: status carries the owner's schema",
            "PASS" if schema_ok else "FAIL",
            f"recwn_limits={json.dumps(recwn, sort_keys=True)} (expected enabled=true, "
            f"window_bytes={EXPECTED_WINDOW_BYTES}, rtt_estimate_us={EXPECTED_RTT_ESTIMATE_US})",
        )
        if not schema_ok:
            return 1

        # Rows 3-5 — the download under the policy, ss sampling beside.
        # The endpoint ladder: the owner's own command first, the
        # cloudflare __down mirror second — every leg self-bounded and
        # heartbeaten, and a dead mirror retries the lane instead of
        # failing it.
        curl_rc, speed_bps, size_bytes, samples, endpoint = 1, 0.0, 0, [], None
        for idx, (name, template) in enumerate(DL_CANDIDATES):
            endpoint = (name, template)
            url = template.format(bytes=byte_cap)
            curl_rc, speed_bps, size_bytes, samples = _run_leg(
                name, url, byte_cap, cg_dir, 25 if byte_cap == DEFAULT_BYTES else 90
            )
            if curl_rc == 0 and size_bytes > 0:
                break
            if idx + 1 < len(DL_CANDIDATES):
                lib.out(
                    f"  note: the {name} endpoint failed (curl rc {curl_rc}) — "
                    f"retrying the lane on the {DL_CANDIDATES[idx + 1][0]} mirror"
                )

        # Row 3 — the clamp evidence: every curl-owned sample's
        # rcv_space / rcv_ssthresh at the clamped scale. The sampler
        # is pid-scoped, so the verdict rides the child's own socket
        # — the 18:23 run judged the whole desktop instead (~175
        # bystander sockets a snapshot) and a browser's auto-tuned
        # 131072-byte window answered for the lane.
        max_space = max((s.get("rcv_space", 0) for s in samples), default=0)
        max_ssthresh = max((s.get("rcv_ssthresh", 0) for s in samples), default=0)
        offenders = [
            s
            for s in samples
            if s.get("rcv_space", 1 << 62) > CLAMP_BOUND_BYTES
            or s.get("rcv_ssthresh", 1 << 62) > CLAMP_BOUND_BYTES
        ]
        clamp_ok = bool(samples) and not offenders
        seen_space = [s.get("rcv_space") for s in samples[:4]]
        if not samples:
            clamp_detail = (
                "no curl-owned ss samples — the sampler never saw the child's socket "
                "(another probe run mid-flight?)"
            )
        else:
            clamp_detail = (
                f"max rcv_space {max_space:,} B / max rcv_ssthresh {max_ssthresh:,} B over "
                f"{len(samples)} curl-owned samples (bound {CLAMP_BOUND_BYTES:,} B; "
                f"first: {seen_space}; the unpoliced default auto-tunes to 131072+)"
            )
            if offenders:
                o = offenders[0]
                clamp_detail = (
                    f"first offender rcv_space={o.get('rcv_space')} "
                    f"rcv_ssthresh={o.get('rcv_ssthresh')} — {clamp_detail}"
                )
        lib.record(
            "recwn: the advertised window is clamped to the RECWN scale",
            "PASS" if clamp_ok else "FAIL",
            clamp_detail,
        )

        # Row 4 — the throughput band (the realnet band's own floor).
        band_ok = curl_rc == 0 and speed_bps >= 0.45 * RATE_BPS and speed_bps <= 1.3 * RATE_BPS
        lib.record(
            "recwn: the download rides the 100kb band",
            "PASS" if band_ok else "FAIL",
            f"curl measured {lib.fmt_bps(speed_bps)} ({size_bytes:,} B over its own window) "
            f"vs the {RATE_STR} policy via {endpoint[0]}",
        )

        # Row 5 — retransmits near zero: the connection's own
        # CUMULATIVE counters — ss's `retrans:A/B` second member
        # (tcp_info's tcpi_total_retrans), whole-life per socket. The
        # 18:23 run read the pair's FIRST member (the instantaneous
        # in-flight count) off an arbitrary bystander socket whose
        # clean history prints no pair at all, and answered -1/18
        # segments; the verdict now reads the curl child's own
        # sockets, where a missing pair means zero retransmits.
        retrans, segs = retrans_wholelife(samples)
        sockets = len({(s.get("local", ""), s.get("peer", "")) for s in samples})
        retrans_ok = bool(samples) and retrans <= RETRANS_FRACTION_MAX * max(segs, 1)
        lib.record(
            "recwn: retransmits are near zero",
            "PASS" if retrans_ok else "FAIL",
            f"retrans {retrans}/{segs} segments ({retrans / max(segs, 1) * 100:.2f}% — bound "
            f"{RETRANS_FRACTION_MAX * 100:.0f}%) on the connection's own whole-life counters "
            f"({sockets} socket{'s' if sockets != 1 else ''}, last sample each)",
        )
        ok = schema_ok and clamp_ok and band_ok and retrans_ok
    finally:
        # Teardown (best-effort, never fails a verdict) — scoped to the
        # probe's own cgroup ONLY: `unstrict --all` is the emergency
        # reset (every limit on the machine, src/cli/surface.rs), and
        # this probe runs on the owner's daily-driver box, where the
        # standing enforcement must survive the verification. The
        # scoped shape is ect-probe's teardown precedent.
        lib.run_zel(["unstrict", f"cg:{cg_id}"])
        # An aborted leg leaves its child alive in the group: kill the
        # subtree, reap the zombie (it holds the cgroup open until
        # reaped), then rmdir — kernfs files refuse unlink, so rmdir on
        # the emptied dir is the only removal path (ect-probe's
        # precedent; rmtree never removes a cgroup).
        if _CHILD_PG[0]:
            try:
                os.killpg(_CHILD_PG[0], signal.SIGKILL)
            except OSError:
                pass
            for _ in range(6):  # ~3 s reap window
                try:
                    done, _ = os.waitpid(_CHILD_PG[0], os.WNOHANG)
                except OSError:
                    break
                if done:
                    break
                time.sleep(0.5)
        _CHILD_PG[0] = 0
        removed = False
        for _ in range(4):  # a just-reaped member takes a moment to leave
            try:
                os.rmdir(cg_dir)
                removed = True
                break
            except OSError:
                time.sleep(0.5)
        if not removed and os.path.isdir(cg_dir):
            lib.out(f"  note: {cg_dir} did not come out (a member lingered); once quiet:")
            lib.out(f"        sudo rmdir {cg_dir}")

    lib.out()
    lib.out(f"  RECWN live probe — {'PASS' if ok else 'FAIL'} in {time.monotonic() - started:.0f}s")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="zelynic RECWN live probe (the quota saver's Layer 1)")
    ap.add_argument("--self-test", action="store_true", help="instrument lane only, no root")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--binary", default=None, help="zelynic binary to drive")
    ap.add_argument(
        "--bytes",
        type=int,
        default=DEFAULT_BYTES,
        help="download byte cap (default 3 MiB; the owner's full run: --bytes 10485760)",
    )
    args = ap.parse_args()
    if args.self_test:
        rc = self_test()
    else:
        # Binary resolution, the shared engine's ladder (NIGHT-improve-11
        # / -16): repo-local builds outrank the system PATH and the pick
        # is version-gated against this checkout's Cargo.toml. The live
        # lane shipped without this call — lib.BINARY stayed "" and
        # run_zel exec'd an empty program, so every live run died at
        # row 2 as `exited 127: [Errno 13] Permission denied: ''` while
        # the instrument lane stayed green. Resolved on the root path
        # only, so the rootless invocation keeps live_run's own
        # needs-root error.
        if os.geteuid() == 0 and not lib.resolve_binary(
            args.binary, "sudo ./scripts/bench/recwn-probe.sh"
        ):
            return 2
        # The abort contract rides the live lane only.
        _install_abort_handlers()
        try:
            rc = live_run(args.bytes)
        except KeyboardInterrupt:
            # The handler already killed the child group and
            # live_run's finally ran the scoped teardown; 130 is the
            # conventional 128+SIGINT.
            lib.out(f"  abort: signal {_ABORT_SIGNUM[0]} — scoped teardown ran, exiting")
            rc = 128 + (_ABORT_SIGNUM[0] or signal.SIGINT)
    if args.json:
        lib.out(json.dumps(lib.RESULTS, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
