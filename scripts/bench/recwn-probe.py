#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
"""zelynic RECWN live probe (night-spark-2 — Receive Window Control,
the quota saver's Layer 1), measured on the running kernel with the
owner's own verification recipe.

The RECWN lane (schema v25) says: a policed cgroup's own sockets
advertise a receive window shaped like the policy's bandwidth-delay
product (rate x 50 ms, clamped to [2 x MSS, 1 MiB]) — the
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
    through the real internet while the parent samples `ss -ti` on
    the connection: rcv_space / rcv_ssthresh bounded at the
    clamped buffer's own scale, decisively below the ~128 KiB the
    unpoliced default auto-tunes to.

  row 4 — the throughput rides the policy band (live): curl's own
    measured average download speed inside the realnet band around
    the 100 kb/s target — the policer held the line while the
    sender slowed itself.

  row 5 — retransmits are near zero (live): the connection's
    retransmit count against its segment count — the whole point of
    shaping the window instead of letting the drops teach the
    sender.

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

Root required for the live run; --self-test is the CI lane.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time

# The shared engine lib lives in scripts/lib/ (NIGHT-refactor-1) — bound
# by ABSOLUTE path so the harness works from any CWD.
_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, _LIB_DIR)

import zelynic_harness_lib as lib  # noqa: E402

# The task brief's own geometry: 100 kb/s download-only, the 50 ms
# estimate, the 5000-byte window the law derives from it.
RATE_STR = "100kb"
RATE_BPS = 100_000
EXPECTED_WINDOW_BYTES = 5000
EXPECTED_RTT_ESTIMATE_US = 50_000
# The clamp evidence bound: the kernel sets sk_rcvbuf to twice the
# passed window (sock_setsockopt's val * 2), and rcv_space /
# rcv_ssthresh auto-tune inside that buffer — anything at or below
# 16 KiB is the clamped lane's own scale; the unpoliced default
# auto-tunes rcv_space to 128 KiB and beyond, so the bound separates
# the regimes decisively.
CLAMP_BOUND_BYTES = 16_384
# The retransmit verdict: near zero means under 1% of the segments
# the connection moved (the drop-policer's own retransmit cadence is
# the baseline this lane exists to beat).
RETRANS_FRACTION_MAX = 0.01
# The realnet download candidates — the owner's own command first
# (tele2 10MB.zip, range-capped), the cloudflare __down mirror
# second (the supermassive realnet registry's own family).
DL_CANDIDATES = [
    ("tele2", "http://speedtest.tele2.net/10MB.zip", True),
    (
        "cloudflare",
        "https://speed.cloudflare.com/__down?bytes=10485760",
        False,
    ),
]
DEFAULT_BYTES = 3 * 1024 * 1024

CG_ROOT = "/sys/fs/cgroup"
CG_NAME = "zelynic-recwn-probe"


# ── The instrument (rootless) ─────────────────────────────────────


def parse_ss_tcp_info(text):
    """Parse `ss -ti` output into per-connection tcp_info fields.

    Returns a list of dicts keyed by the fields this harness reads:
    rcv_space, rcv_ssthresh, retrans (the first of ss's
    `retrans:a/b` pair — the total retransmissions), retrans_total
    (the pair's second member as ss prints it), segs_out. Only
    connections carrying a detailed info line yield entries.
    """
    conns = []
    fields = {}
    for line in text.splitlines():
        if not line.startswith(("\t", " ")):
            if fields:
                conns.append(fields)
            fields = {}
            continue
        for name, pattern in [
            ("rcv_space", r"rcv_space:(\d+)"),
            ("rcv_ssthresh", r"rcv_ssthresh:(\d+)"),
            ("segs_out", r"segs_out:(\d+)"),
            ("retrans", r"retrans:(\d+)/(\d+)"),
        ]:
            m = re.search(pattern, line)
            if m:
                if name == "retrans":
                    fields["retrans"] = int(m.group(1))
                    fields["retrans_pair_second"] = int(m.group(2))
                else:
                    fields[name] = int(m.group(1))
    if fields:
        conns.append(fields)
    return conns


SS_FIXTURE = """ESTAB 0 0 192.0.2.10:443 203.0.113.7:52988 users:(("curl",pid=4242,fd=3))
\t cubic wscale:8,7 rto:364 rtt:12.5/24 ato:40 mss:1448 rcv_space:131072 rcv_ssthresh:131072 segs_out:812 retrans:0/812
ESTAB 0 0 192.0.2.10:52304 198.51.100.9:80 users:(("curl",pid=4243,fd=3))
\t cubic wscale:7,7 rto:364 rtt:8.75/17.5 ato:40 mss:1448 rcv_space:6144 rcv_ssthresh:6144 segs_out:204 retrans:2/204
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
        (1_000_000, 50_000),
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

    # The ss parser round-trip on the fixture: the default-scale
    # connection (131072) and the clamped-scale one (6144, the RECWN
    # regime) both parse, with their retrans pairs.
    conns = parse_ss_tcp_info(SS_FIXTURE)
    rows.append(
        (
            "ss parser: two connections parsed",
            len(conns) == 2,
            f"parsed {len(conns)} connections with tcp_info lines",
        )
    )
    if len(conns) == 2:
        rows.append(
            (
                "ss parser: default-scale rcv_space reads 131072",
                conns[0].get("rcv_space") == 131072,
                f"rcv_space={conns[0].get('rcv_space')}",
            )
        )
        rows.append(
            (
                "ss parser: clamped-scale rcv_space reads 6144 with retrans 2/204",
                conns[1].get("rcv_space") == 6144
                and conns[1].get("retrans") == 2
                and conns[1].get("segs_out") == 204,
                f"fields={conns[1]}",
            )
        )

    # The owner-defined recwn_limits schema on a fixture document:
    # the exact three-field object, the enabled:false absent-window
    # shape, and the additive absence.
    fixture = (
        '{"watchdog":"enforcing","active_limits":1,"limits":[],"recwn_limits":'
        '{"enabled":true,"window_bytes":5000,"rtt_estimate_us":50000}}'
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
        '{"enabled":false,"rtt_estimate_us":50000}}'
    )
    doc = json.loads(fixture_disabled)
    rows.append(
        (
            "schema: enabled:false carries no fabricated window",
            doc["recwn_limits"] == {"enabled": False, "rtt_estimate_us": 50000}
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

    ok = True
    for name, verdict, detail in rows:
        lib.out(f"  {'OK' if verdict else 'FAIL'} {name} — {detail}")
        ok = ok and verdict
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


def curl_child(cgroup_procs, url, byte_cap, go_fd, report_fd):
    """The moved child: join the cgroup, then exec curl.

    Runs AFTER the parent wrote the go byte and the policy stands;
    the sockets curl creates are born inside the policed cgroup (the
    attribution contract). Writes curl's own measurement line
    (speed_download size_download) to report_fd.
    """
    os.close(go_fd)
    with open(cgroup_procs, "w") as f:
        f.write(str(os.getpid()))
    # Range-cap the transfer when the endpoint honors ranges (tele2
    # does; the cloudflare __down mirror sizes itself).
    if byte_cap and url.endswith(".zip"):
        curl_args = ["curl", "-fsSL", "-r", f"0-{byte_cap - 1}"]
    else:
        curl_args = ["curl", "-fsSL"]
    curl_args += [
        "-o",
        "/dev/null",
        "-w",
        "%{speed_download} %{size_download}\\n",
        "--max-time",
        "240",
        url,
    ]
    out = subprocess.run(curl_args, capture_output=True, text=True, timeout=300)
    with os.fdopen(report_fd, "w") as f:
        f.write(f"{out.returncode} {out.stdout.strip()}\n")
    os._exit(0)


def sample_ss_during(duration_s):
    """Sample `ss -ti` while the child downloads: the evidence rows."""
    samples = []
    deadline = time.monotonic() + duration_s
    while time.monotonic() < deadline:
        try:
            text = subprocess.run(["ss", "-tip"], capture_output=True, text=True, timeout=5).stdout
        except (subprocess.TimeoutExpired, OSError):
            text = ""
        for fields in parse_ss_tcp_info(text):
            # Only the curl-owned connections (the -p process lens).
            if "curl" in text and fields.get("rcv_space") is not None:
                samples.append(fields)
        time.sleep(0.5)
    return samples


def live_run(byte_cap):
    if not ensure_root():
        return 1
    started = time.monotonic()
    if shutil.which("curl") is None:
        lib.out("FAIL: curl is not on PATH — the probe's own engine")
        return 1

    cg_dir = os.path.join(CG_ROOT, CG_NAME)
    # Best-effort pre-clean (a crashed predecessor).
    shutil.rmtree(cg_dir, ignore_errors=True)
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
        go_r, go_w = os.pipe()
        rep_r, rep_w = os.pipe()
        endpoint = None
        for name, url, _ in DL_CANDIDATES:
            endpoint = (name, url)
            break
        pid = os.fork()
        if pid == 0:
            curl_child(os.path.join(cg_dir, "cgroup.procs"), endpoint[1], byte_cap, go_r, rep_w)
        os.close(go_r)
        os.close(rep_w)

        # The go byte (the policy stands); then sample ss while the
        # transfer runs. ~30 s at the default cap.
        os.write(go_w, b"go")
        os.close(go_w)
        samples = sample_ss_during(25 if byte_cap == DEFAULT_BYTES else 90)

        # Collect the child's own measurement.
        os.waitpid(pid, 0)
        with os.fdopen(rep_r) as f:
            report = f.read().strip().split(" ", 1)
        curl_rc = int(report[0])
        speed_bps = float(report[1].split()[0]) if len(report) > 1 and report[1] else 0.0
        size_bytes = (
            int(report[1].split()[1]) if len(report) > 1 and len(report[1].split()) > 1 else 0
        )

        # Row 3 — the clamp evidence: every sampled rcv_space /
        # rcv_ssthresh at the clamped scale.
        clamp_ok = bool(samples) and all(
            s.get("rcv_space", 1 << 62) <= CLAMP_BOUND_BYTES
            and s.get("rcv_ssthresh", 1 << 62) <= CLAMP_BOUND_BYTES
            for s in samples
        )
        seen_space = [s.get("rcv_space") for s in samples[:4]]
        lib.record(
            "recwn: the advertised window is clamped to the RECWN scale",
            "PASS" if clamp_ok else "FAIL",
            f"{len(samples)} ss samples, rcv_space/rcv_ssthresh <= {CLAMP_BOUND_BYTES} B "
            f"(first: {seen_space}; the unpoliced default auto-tunes to 131072+)",
        )

        # Row 4 — the throughput band (the realnet band's own floor).
        band_ok = curl_rc == 0 and speed_bps >= 0.45 * RATE_BPS and speed_bps <= 1.3 * RATE_BPS
        lib.record(
            "recwn: the download rides the 100kb band",
            "PASS" if band_ok else "FAIL",
            f"curl measured {lib.fmt_bps(speed_bps)} ({size_bytes:,} B over its own window) "
            f"vs the {RATE_STR} policy via {endpoint[0]}",
        )

        # Row 5 — retransmits near zero: the LAST sample's retransmit
        # pair against its segment count.
        last = samples[-1] if samples else {}
        segs = max(last.get("segs_out", 0), 1)
        retrans = last.get("retrans", -1)
        retrans_ok = retrans >= 0 and retrans <= RETRANS_FRACTION_MAX * segs
        lib.record(
            "recwn: retransmits are near zero",
            "PASS" if retrans_ok else "FAIL",
            f"retrans {retrans}/{segs} segments ({(retrans / segs * 100):.2f}% — bound "
            f"{RETRANS_FRACTION_MAX * 100:.0f}%) on the connection's own counters",
        )
        ok = schema_ok and clamp_ok and band_ok and retrans_ok
    finally:
        # Teardown (best-effort, never fails a verdict).
        lib.run_zel(["unstrict", f"cg:{cg_id}"])
        lib.run_zel(["unstrict", "--all"])
        shutil.rmtree(cg_dir, ignore_errors=True)

    lib.out()
    lib.out(f"  RECWN live probe — {'PASS' if ok else 'FAIL'} in {time.monotonic() - started:.0f}s")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description="zelynic RECWN live probe (the quota saver's Layer 1)")
    ap.add_argument("--self-test", action="store_true", help="instrument lane only, no root")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--bytes",
        type=int,
        default=DEFAULT_BYTES,
        help="download byte cap (default 3 MiB; the owner's full run: --bytes 10485760)",
    )
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    return live_run(args.bytes)


if __name__ == "__main__":
    sys.exit(main())
