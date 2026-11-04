#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# LOC_EXEMPT: one self-contained verification harness by design — the
# cgroup join, the ss instrument, the throttle verdict and the ledger
# cross-check share one docstring contract, and the kernel truths live
# in the header the .sh wrapper points at; splitting the probe across
# modules would scatter the told-once recipe (the ecn-probe.py
# precedent).
"""zelynic EDT live probe (night-spark-5 — Layer 3 of the quota
saver, EGRESS SOCKET PACING on the CGROUP lanes), measured on the
running kernel.

Layer 3's law (ebpf/src/pace.rs, the owner's task brief verbatim):
a cgroup's UPLOAD policy, standing, is pinned onto the cgroup's
TCP sockets as SO_MAX_PACING_RATE — the kernel's own TCP pacer
spaces the outgoing stream at the policy's byte rate BEFORE the
link bills the bytes. No tc, no fq, no nftables: the stack's
internal pacer owns the clock while no pacing qdisc claims the
socket (net/ipv4/tcp_output.c's tcp_internal_pacing on the 5.15
floor). The lane is pure eBPF: the EGRESS hook primes a
cookie-keyed hint (pace_socket_hint) on the policed path, and the
sock_ops program zelynic_pace pins the rate at the connection
callbacks — the same architecture the RECWN lane (Layer 1) proved,
one layer up. This harness pins the lane LIVE:

  row 1 — the instrument (rootless, --self-test): the ss pacing
    parser (the pacing_rate token's decimal bit units — b/s, Kb/s,
    Mb/s — converted to bytes), the throttle band, the drop-free
    law, and the status-JSON pacing field contract. Without this
    row a live FAIL could always be blamed on the measurement —
    the instrument is pinned FIRST, the discipline every claims
    harness here carries.

  row 2 — the schema row (live): `zelynic status --print-json`
    names limits[].pacing_rate_bytes == the planted rate on the
    probe's own cgroup row — the schema-v27 surface, the lane's
    commanded value, readable. A pre-v27 object carries no field
    and fails this row with the reason spelled out.

  row 3 — the pacing engage (live): `ss -tip` sampled beside the
    upload leg, scoped to the uploader's own pid (the recwn-probe
    join: fork, join cgroup.procs, execv — curl IS the cgroup
    member), reads pacing_rate on the lane's sockets at the
    policy's own rate — the kernel-native pacer, live, no qdisc.

  row 4 — the throttle (live): curl -T delivers the payload at the
    lane's rate (the -w speed_upload inside the band) — strictly
    limited, the quota saved.

  row 5 — the drop-free lane (live): the ledger's dropped counters
    move ZERO during the paced upload — pacing never over-bursts
    the token bucket, so the drop verdict never speaks and the
    quota is saved without a loss event (the brief's own success
    criterion).

  row 6 — the saved quota books (live, night-spark-7 Layer 4): the
    same ledger's v28 tail moves — limits[].bytes_saved_by_edt
    grows by the preserved headroom ((rate x elapsed) - uploaded,
    the formula the pure law pins) and bytes_saved_total carries
    the row's three-lane sum. A pre-v28 object carries no fields
    and fails this row with the rebuild reason spelled out.

Honesty contracts: the upload policy is planted BEFORE the
uploader fork (the sockets curl creates are born policed — the
pin-at-creation contract, the recwn join); the ss sweep scopes on
the uploader's OWN pid (a wrapper pid owns no socket — the recwn
21:53 lesson); the ledger delta reads the probe's own cgroup row
only; a missing ss binary SKIPs the pacing row with the reason
(the throttle and the ledger still run); the tmpfile dies in the
teardown; teardown is best-effort and never fails a verdict. The
documented residue: UDP/QUIC sockets never reach the pacing
program (the dispatch is TCP-only by construction — QUIC paces
itself, RFC 9000), and the wire's own losses are not the lane's —
the drop row reads the lane's ledger, never the internet's mood.

Root required for the live run; --self-test is the CI lane.
"""

import argparse
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

# The shared engine lib lives in scripts/lib/ (NIGHT-refactor-1) — bound
# by ABSOLUTE path so the harness works from any CWD.
_LIB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib")
sys.path.insert(0, _LIB_DIR)

sys.dont_write_bytecode = True  # root-owned pycache guard, docs/MAINTENANCE.md 7
import zelynic_harness_lib as lib  # noqa: E402

# The lane geometry mirrors the ecn probe's: the 100kb band is the
# quota saver's own demo policy, and every bound below derives from it.
RATE_STR = "100kb"
RATE_BPS = 100_000
PACING_BITS = RATE_BPS * 8  # ss reports pacing_rate in BITS per second
UPLOAD_BYTES = 3 * 1024 * 1024
CG_ROOT = "/sys/fs/cgroup"
CG_NAME = "zelynic-edt-probe"
CG_PROCS = os.path.join(CG_ROOT, CG_NAME, "cgroup.procs")
TCP_UPLOAD_LADDER = [
    ("cloudflare", "https://speed.cloudflare.com/__up"),
    ("httpbin", "https://httpbin.org/put"),
]
CONNECT_TIMEOUT_S = 10
CURL_MAX_TIME_S = 120
LEG_WALL_SLACK_S = 15
SS_POLL_S = 1.0
# The pacing band: the kernel caps sk_pacing_rate at the option's own
# value, so the top sample reads AT the cap; the floor absorbs the
# samples a ramping sender takes before the pacer binds.
PACING_FLOOR = 0.75
PACING_CEIL = 1.05
# The throttle band: the transfer's AVERAGE rides under the rate (the
# handshake and the slow start bill no quota but dilute the average);
# past the ceiling the lane did not limit the leg.
THROTTLE_FLOOR = 0.75
THROTTLE_CEIL = 1.25

# The ss pacing_rate token: a decimal bit rate with an SI unit
# suffix in ONE of the two dialects iproute2 has shipped — the
# `b/s` family (`pacing_rate 800.0Kb/s`) and the `bps` family
# (iproute2 6.x: `pacing_rate 800kbps/800kbps`, the CURRENT rate,
# a slash, then the MAX pacing rate when the socket carries one —
# the pair prints ONLY for a pinned socket). Decimal thousands,
# BITS, both cases attested live (lowercase k on 6.15.0's `800kbps`,
# capital M/G on its bystanders; the pinned-max pair was measured
# on kernel 5.10.134 against a socket the harness itself pinned
# with SO_MAX_PACING_RATE — the exact kernel state the lane
# creates, the same 800000 b/s witness). The pattern captures the
# current rate in groups 1-2 and, when the pair prints, the
# pinned max in groups 3-4 — the option's own value, the
# exactness witness the verdict gate below reads.
PACING_TOKEN = re.compile(
    r"pacing_rate\s+([0-9.]+)([kKmMgGtT]?)(?:b/s|bps)"
    r"(?:\s*/\s*([0-9.]+)([kKmMgGtT]?)(?:b/s|bps))?"
)
UNIT_MULT = {
    "": 1,
    "k": 1_000,
    "K": 1_000,
    "m": 1_000_000,
    "M": 1_000_000,
    "g": 1_000_000_000,
    "G": 1_000_000_000,
    "t": 1e12,
    "T": 1e12,
}


# ── the pure instrument ───────────────────────────────────────────────


def pacing_rate_bps(token_value, token_unit):
    """One pacing token's rate in BITS per second — the decimal SI
    units ss prints in either dialect (the b/s and bps families,
    both cases of the unit letter), pinned by --self-test."""
    return float(token_value) * UNIT_MULT[token_unit]


def parse_ss_pacing(text):
    """Parse `ss -tip` output into per-connection dicts carrying the
    fields this harness judges: pid (None when ss cannot attribute),
    pacing_rate_bps (None when the token is absent — an unpaced
    socket), pacing_max_bps (None when the socket carries no pinned
    max — the bps dialect's `current/max` pair prints only for a
    socket SOMETHING pinned; an unpaced local bystander rides a
    single Gbps-scale token and no pair, so it never contaminates
    the exactness witness), retrans_total (absence reads 0 — ss
    prints the pair only when a member is nonzero, the recwn-probe
    parser's own note). Only connections carrying a detailed info
    line yield entries."""
    conns = []

    def _close(header, fields):
        if header is None or not fields:
            return
        m = re.search(r'users:\(\("[^"]*",pid=(\d+)', header)
        addr_side = header.split("users:")[0].split()
        entry = dict(fields)
        entry["pid"] = int(m.group(1)) if m else None
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
        m = PACING_TOKEN.search(line)
        if m:
            fields["pacing_rate_bps"] = pacing_rate_bps(m.group(1), m.group(2))
            if m.group(3) is not None:
                fields["pacing_max_bps"] = pacing_rate_bps(m.group(3), m.group(4))
        rm = re.search(r"retrans:(\d+)/(\d+)", line)
        if rm:
            fields["retrans_total"] = int(rm.group(2))
    _close(header, fields)
    return conns


def pacing_verdict(samples, expect_bps=PACING_BITS):
    """The pacing row's verdict from the pid-scoped samples: the top
    pacing_rate rides the band [FLOOR, CEIL] x the policy's rate —
    the kernel caps the socket's pacer at the option's own value, so
    a bound sender reads AT the cap; no paced sample at all is the
    non-engagement FAIL. The pinned-max gate (night-spark-6): any
    sample carrying the `current/max` pair names the option's OWN
    value in the max — exactly expect_bps (the live attestation:
    a socket pinned at 100000 B/s reads `800kbps/800kbps`), and a
    pinned max off the policy's bits is the option-did-not-bind
    FAIL even when the current rate rides the band. Returns
    (verdict, top_bps, detail_tail)."""
    paced = [s["pacing_rate_bps"] for s in samples if s.get("pacing_rate_bps")]
    if not paced:
        return (
            "FAIL",
            0.0,
            "no paced socket sampled — the pacing lane did not engage the uploader's sockets",
        )
    maxes = [s["pacing_max_bps"] for s in samples if s.get("pacing_max_bps")]
    # One bit per second of float dust (an `0.8Mb/s` dialect print
    # carries binary-float residue); anything past it is a real
    # off-policy pin, never rounding.
    if any(abs(m - expect_bps) > 1.0 for m in maxes):
        return (
            "FAIL",
            max(paced),
            f"the pinned max rode off the policy's own value (max "
            f"{max(maxes):.0f} b/s vs {expect_bps:.0f}) — the option did "
            "not bind at the policy's rate",
        )
    top = max(paced)
    if top > expect_bps * PACING_CEIL:
        return (
            "FAIL",
            top,
            f"the pacer rode past the policy's own cap ({top:.0f} b/s vs "
            f"{expect_bps:.0f}) — the option did not bind",
        )
    if top < expect_bps * PACING_FLOOR:
        return (
            "FAIL",
            top,
            f"the pacer never reached the policy's own band ({top:.0f} b/s vs "
            f"{expect_bps:.0f}) — the rate did not land",
        )
    pinned_tail = (
        f"; the pinned max reads {maxes[0]:.0f} b/s — the policy's own bits, exactly"
        if maxes
        else ""
    )
    return (
        "PASS",
        top,
        f"top pacing_rate {top:.0f} b/s across {len(paced)} paced samples "
        "of the uploader's own sockets" + pinned_tail,
    )


def throttle_verdict(speed_upload, rate_bps=RATE_BPS):
    """The throttle row's verdict: the leg's AVERAGE upload speed
    rides the band [FLOOR, CEIL] x the policy — under the floor the
    lane over-limited (honest, but not the brief), past the ceiling
    the lane did not limit. Returns (verdict, detail_tail)."""
    if speed_upload > rate_bps * THROTTLE_CEIL:
        return (
            "FAIL",
            f"the transfer ran at {speed_upload:.0f} B/s, past the {RATE_STR} "
            "lane's ceiling — the lane did not limit the leg",
        )
    if speed_upload < rate_bps * THROTTLE_FLOOR:
        return (
            "FAIL",
            f"the transfer ran at {speed_upload:.0f} B/s, under the {RATE_STR} "
            "lane's floor — over-limited (the honest opposite)",
        )
    return (
        "PASS",
        f"the transfer ran at {speed_upload:.0f} B/s — the lane's own rate, strictly limited",
    )


def find_row(doc, cgroup_id):
    """The probe's own cgroup row out of a `status --print-json`
    document (None when absent — the caller names the reason)."""
    for row in (doc or {}).get("limits", []):
        if row.get("cgroup_id") == cgroup_id:
            return row
    return None


# ── the moved child (the recwn-probe join) ────────────────────────────


def _upload_child(args):
    """The moved child: join the cgroup, then EXEC curl on its own
    pid — fork-before-socket, join-before-exec, so every socket curl
    creates is born inside the policed cgroup (the attribution
    contract; a wrapper pid owns no socket — the recwn 21:53
    lesson). The -w measurement line rides the report pipe on
    stdout (dup2 before exec — the line IS the report), stderr
    rides the error pipe, and every other fd this fork carried is
    non-inheritable and dies at the exec."""
    os.setpgid(0, 0)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, signal.SIG_DFL)
    try:
        with open(CG_PROCS, "w") as f:
            f.write(str(os.getpid()))
    except OSError:
        os._exit(126)  # the join failed — the parent's wait answers 126
    try:
        os.execvp(args[0], args)
    except OSError:
        os._exit(127)  # exec failed — the parent's wait answers 127


def _run_upload_leg(args, wall_s, sample_pid_box):
    """One upload leg exec'd INSIDE the policed cgroup: the -w line
    rides the report pipe, stderr the error pipe, the exit code out
    of waitpid — and the parent samples `ss -tip` BESIDE the leg
    (one sweep per quiet second, scoped to the child's own pid —
    the instrument contract), the samples landing in
    sample_pid_box[0]. The whole leg rides a hard wall: the wall
    expires, the child dies by SIGKILL and the leg names its
    reason. Returns the leg dict {rc, size, speed, err}."""
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
        _upload_child(args)
    os.close(rep_w)
    os.close(err_w)
    deadline = time.monotonic() + wall_s
    out_chunks, err_chunks = [], []
    open_fds = {rep_r, err_r}
    killed = False
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
            killed = True
            break
        ready, _, _ = select.select(list(open_fds), [], [], min(SS_POLL_S, remaining))
        if not ready:
            _ss_sweep(sample_pid_box, pid)
            continue
        for fd in ready:
            chunk = os.read(fd, 65536)
            if chunk:
                (out_chunks if fd == rep_r else err_chunks).append(chunk)
            else:
                open_fds.discard(fd)  # EOF — the child closed this side
    rc = -1
    if killed:
        err = f"the leg exceeded its {wall_s:.0f}s wall — killed"
        size, speed = 0, 0.0
        try:
            os.close(rep_r)
            os.close(err_r)
        except OSError:
            pass
    else:
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


def _ss_sweep(sample_box, child_pid):
    """One `ss -tip` sweep, keeping ONLY the uploader's own sockets
    (the recwn-probe scoping: another curl on the box can never ride
    the evidence). Sweep failures read as an empty sweep — the row's
    detail names a zero-sample leg honestly either way."""
    try:
        text = subprocess.run(["ss", "-tip"], capture_output=True, text=True, timeout=5).stdout
    except (subprocess.TimeoutExpired, OSError):
        return
    kept = [c for c in parse_ss_pacing(text) if c.get("pid") == child_pid]
    sample_box[0].extend(kept)


# ── the live lane ─────────────────────────────────────────────────────


def live_run():
    if os.geteuid() != 0:
        lib.out("FAIL: the live lane needs root (cgroup join, policy, ss)")
        lib.out("      run: sudo ./scripts/bench/edt-probe.sh")
        return 1
    if shutil.which("curl") is None:
        lib.out("FAIL: curl is not on PATH — the probe's own engine")
        return 1
    ss_on_path = shutil.which("ss") is not None
    if not ss_on_path:
        lib.out(
            "  note: ss is not on PATH — the pacing row SKIPs "
            "(the throttle and the ledger still run)"
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
    tmp_path = None
    uploader_pid = None
    try:
        # The upload policy stands BEFORE any uploader socket exists
        # (the pin-at-creation contract; the recwn join's own order).
        rc, out, err = lib.run_zel(["strict", f"cg:{cg_id}", "-u", RATE_STR, "--no-test"])
        if rc != 0:
            lib.out(f"FAIL: strict -u {RATE_STR} exited {rc}: {(err or out)[:200]}")
            return 1

        # Row 2 — the schema row: the v27 pacing column reads off the
        # row the probe planted itself.
        doc = lib.status_json()
        row = find_row(doc, cg_id)
        pacing_named = (row or {}).get("pacing_rate_bytes")
        lib.record(
            "edt: the ledger names the pacing lane",
            "PASS" if pacing_named == RATE_BPS else "FAIL",
            f"status --print-json limits[{cg_id}].pacing_rate_bytes = "
            f"{pacing_named!r} (planted {RATE_BPS}) — the schema-v27 "
            "column, live"
            + (
                ""
                if pacing_named is not None
                else " — a pre-v27 object carries no field; rebuild and re-apply"
            ),
        )
        if pacing_named is None:
            return 1

        # The ledger snapshot (the drop row's baseline): the probe's
        # own cgroup row's dropped counters, read off the same doc.
        pre_dropped = int((row or {}).get("packets_dropped", 0))
        pre_dropped_b = int((row or {}).get("bytes_dropped", 0))
        # The Layer 4 baseline (the saved row's own snapshot, the
        # same doc, the same row): the v28 tail's growth over the
        # upload is the quota-saved row's own evidence.
        pre_saved_e = (row or {}).get("bytes_saved_by_edt")
        pre_saved_t = (row or {}).get("bytes_saved_total")

        # The payload: the upload leg's own 3 MiB, discarded by the
        # endpoint, dead in the teardown.
        with tempfile.NamedTemporaryFile(prefix="zelynic-edt-", suffix=".bin", delete=False) as tmp:
            tmp.write(b"\0" * UPLOAD_BYTES)
            tmp_path = tmp.name

        # Rows 3-5 — the paced upload leg through the ladder, the
        # recwn join carrying curl into the policed cgroup.
        lib.out(
            f"  driving the cgroup egress lane: {UPLOAD_BYTES // 1024 // 1024} MiB "
            f"uploaded at {RATE_STR} (the sock_ops pacing lane, no tc qdisc)"
        )
        samples_box = [[]]
        leg = {"rc": -1, "size": 0, "speed": 0.0, "err": "no ladder rung answered"}
        endpoint = "no ladder rung answered"
        for name, url in TCP_UPLOAD_LADDER:
            args = [
                "curl",
                "-sS",
                # The ladder's endpoint is the DIRECT peer (the fast-local
                # guard, night-spark-6): a proxy env var would bend the
                # leg through a fast local hop, and that bystander — an
                # unpaced socket riding a Gbps-scale pacing_rate under
                # the uploader's OWN pid — swamps the pid-scoped sweep
                # with evidence the lane never shaped. --noproxy keeps
                # the leg's own socket the lane's witness.
                "--noproxy",
                "*",
                "-o",
                "/dev/null",
                "-w",
                "%{size_upload} %{speed_upload}",
                "--connect-timeout",
                str(CONNECT_TIMEOUT_S),
                "--max-time",
                str(CURL_MAX_TIME_S),
                "-T",
                tmp_path,
                url,
            ]
            leg = _run_upload_leg(args, CURL_MAX_TIME_S + LEG_WALL_SLACK_S, samples_box)
            if leg["rc"] == 0 and leg["size"] > 0:
                endpoint = name
                break
            lib.out(f"  ... {name} leg failed (rc {leg['rc']}): {leg['err'][:120]}")

        # Row 3 — the pacing engage (the ss instrument's own verdict;
        # a missing ss names the skip honestly).
        if ss_on_path:
            samples = samples_box[0]
            verdict, top, tail = pacing_verdict(samples)
            retrans = sum(s.get("retrans_total", 0) for s in samples)
            lib.record(
                "edt: the kernel paces the lane's sockets",
                verdict,
                f"ss -tip on the uploader's own sockets: {tail}; the policy's "
                f"rate is {PACING_BITS:.0f} b/s ({RATE_BPS} B/s) — the stack's "
                f"internal pacer, no tc qdisc (path retransmits observed: "
                f"{retrans}, not the lane's own)",
            )
        else:
            lib.record(
                "edt: the kernel paces the lane's sockets",
                "SKIP",
                "ss is not on PATH — the pacing sweep cannot run; the "
                "throttle and the ledger carry what they can",
            )

        # Row 4 — the throttle.
        t_verdict, t_tail = throttle_verdict(leg["speed"])
        lib.record(
            "edt: the upload rides the lane's own rate",
            t_verdict,
            f"curl -T {endpoint}: {leg['size']} B at {leg['speed']:.0f} B/s "
            f"(rc {leg['rc']}) — {t_tail}",
        )

        # Row 5 — the drop-free lane (the ledger's own counters, the
        # probe's cgroup row only).
        doc = lib.status_json()
        row = find_row(doc, cg_id)
        delta_p = int((row or {}).get("packets_dropped", 0)) - pre_dropped
        delta_b = int((row or {}).get("bytes_dropped", 0)) - pre_dropped_b
        lib.record(
            "edt: the paced lane drops nothing",
            "PASS" if delta_p == 0 and delta_b == 0 else "FAIL",
            f"the ledger moved {delta_p} pkts / {delta_b} B dropped during the "
            "paced upload — pacing never over-bursts the token bucket, the "
            "drop verdict never speaks, the quota is saved without a loss "
            "event",
        )

        # Row 6 — the saved quota (the Layer 4 telemetry, live): the
        # v28 tail's growth over the paced upload — the preserved
        # headroom the pacer held back while the lane delivered.
        post_e = (row or {}).get("bytes_saved_by_edt")
        post_t = (row or {}).get("bytes_saved_total")
        if post_e is None or post_t is None:
            lib.record(
                "edt: the paced lane books its saved quota",
                "FAIL",
                "status --print-json limits[] carries no bytes_saved_by_edt / "
                "bytes_saved_total — a pre-v28 (stale pinned) object is "
                "loaded; rebuild and re-apply",
            )
        else:
            delta_e = int(post_e) - int(pre_saved_e or 0)
            delta_t = int(post_t) - int(pre_saved_t or 0)
            lib.record(
                "edt: the paced lane books its saved quota",
                "PASS" if delta_e > 0 and delta_t >= delta_e else "FAIL",
                f"the ledger moved {delta_e} B saved-by-edt / {delta_t} B "
                "total during the paced upload — the v28 tail books the "
                "preserved headroom ((rate x elapsed) - uploaded), the "
                "quota saver's Layer 4, live",
            )

        lib.out(f"  EDT live probe — the egress pacing lane, {time.monotonic() - started:.0f}s")
        rows_ok = all(r["verdict"] != "FAIL" for r in lib.RESULTS)
        return 0 if rows_ok else 1
    finally:
        # The scoped teardown, best-effort, never a verdict.
        if uploader_pid:
            try:
                os.kill(uploader_pid, signal.SIGKILL)
            except OSError:
                pass
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
        try:
            lib.run_zel(["unstrict", f"cg:{cg_id}"])
        except Exception:
            pass
        try:
            os.rmdir(cg_dir)
        except OSError:
            pass


# ── the rootless instrument lane ──────────────────────────────────────


# The owner-shaped fixture carries BOTH ss dialects (night-spark-6):
# fd=3 rides the b/s family, fd=5 rides the bps family with the
# pinned-max pair iproute2 6.x prints (`800kbps/800kbps`, the live
# attestation on iproute2 6.15.0 / kernel 5.10.134), and fd=6 is
# the FAST-LOCAL bystander under the uploader's OWN pid — a
# loopback-shaped hop at Gbps scale whose single unpinned token is
# the exact hazard the pid scope and the --noproxy guard hold off.
SS_FIXTURE = """State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
ESTAB 0 1234 192.0.2.10:52304 198.51.100.9:443 users:(("curl",pid=4242,fd=3))
\t cubic wscale:7,7 rto:364 rtt:12.5/24 ato:40 mss:1448 pacing_rate 800.0Kb/s delivery_rate 796.2Kb/s segs_out:812 retrans:0/0
ESTAB 0 0 192.0.2.10:52310 198.51.100.9:443 users:(("Web Content",pid=5599,fd=67))
\t cubic wscale:7,7 rto:364 rtt:9.5/19 ato:40 mss:1448 pacing_rate 12.4Mb/s segs_out:18
ESTAB 0 0 192.0.2.10:52311 198.51.100.9:443 users:(("curl",pid=4242,fd=4))
\t cubic wscale:7,7 rto:364 rtt:8.75/17.5 ato:40 mss:1448 segs_out:204 retrans:2/7
ESTAB 0 0 192.0.2.10:52312 198.51.100.9:443 users:(("curl",pid=4242,fd=5))
\t cubic wscale:7,7 rto:364 rtt:10.2/20.4 ato:40 mss:1448 pacing_rate 800kbps/800kbps delivery_rate 790.4Kbps segs_out:99 retrans:1/3
ESTAB 0 0 192.0.2.10:52313 127.0.0.1:8080 users:(("curl",pid=4242,fd=6))
\t cubic wscale:7,7 rto:364 rtt:0.008/0.016 ato:40 mss:65483 pacing_rate 710Gbps delivery_rate 655.3Gbps segs_out:31
"""


def self_test():
    """The rootless instrument lane: the parser, the bands, the law,
    the JSON contract."""
    lib.out("  EDT instrument — the rootless pins (night-spark-5)")
    rows = []

    # The pacing token's decimal bit units (both dialects, both
    # unit-letter cases), the full suffix family the sweep can meet —
    # including the lowercase k iproute2 6.15.0 prints and the
    # capital K/M/G the b/s family carries.
    unit_ok = (
        pacing_rate_bps("800.0", "K") == 800_000.0
        and pacing_rate_bps("800", "k") == 800_000.0
        and pacing_rate_bps("12.4", "M") == 12_400_000.0
        and pacing_rate_bps("12.4", "m") == 12_400_000.0
        and pacing_rate_bps("640", "") == 640.0
        and pacing_rate_bps("1.2", "G") == 1_200_000_000.0
    )
    rows.append(
        (
            "instrument: the pacing token's decimal bit units",
            unit_ok,
            "b/s and bps dialects, both unit-letter cases — decimal "
            "thousands, BITS (ss prints the pacer's rate in bits; the "
            "policy's 100000 B/s reads 800.0Kb/s or 800kbps, the two "
            "iproute2 shapes)",
        )
    )

    # The parser on the owner-shaped fixture (both ss dialects, the
    # pinned-max pair, the fast-local bystander): the scoped pid keeps
    # its paced sockets in BOTH dialects, the bps family's
    # current/max pair yields the pinned max, an unpaced LOCAL
    # bystander under the SAME pid reads its Gbps-scale single token
    # with NO pair (it can never contaminate the exactness witness
    # — only the band's top sample, which the throttle row's own
    # verdict disambiguates), another pid never rides the evidence
    # at all, an unpaced socket reads honestly absent, and retrans
    # absence reads 0 (ss prints the pair only when a member is
    # nonzero).
    conns = parse_ss_pacing(SS_FIXTURE)
    mine = [c for c in conns if c.get("pid") == 4242]
    parser_ok = (
        len(mine) == 4
        and mine[0].get("pacing_rate_bps") == 800_000.0
        and "pacing_max_bps" not in mine[0]
        and mine[0].get("retrans_total", 0) == 0
        and "pacing_rate_bps" not in mine[1]
        and mine[1].get("retrans_total") == 7
        and mine[2].get("pacing_rate_bps") == 800_000.0
        and mine[2].get("pacing_max_bps") == 800_000.0
        and mine[2].get("retrans_total") == 3
        and mine[3].get("pacing_rate_bps") == 710_000_000_000.0
        and "pacing_max_bps" not in mine[3]
        and any(c.get("pid") == 5599 for c in conns)
        and conns[1].get("pacing_rate_bps") == 12_400_000.0
    )
    rows.append(
        (
            "instrument: the ss pacing parser",
            parser_ok,
            "pid-scoped: 4 of 5 connections carry the uploader's pid; "
            "the b/s dialect socket reads 800.0Kb/s = 800000 b/s, the "
            "bps dialect socket reads 800kbps/800kbps — current 800000 "
            "AND the pinned max 800000 (the exactness witness), the "
            "fast-local bystander's 710Gbps rides a single token with "
            "no pair, the other-pid bystander's 12.4Mb/s never rides "
            "the evidence, the unpaced socket reads absent, retrans "
            "absence reads 0",
        )
    )

    # The pinned-max exactness gate (night-spark-6, the owner's own
    # success criterion): a max pinned AT the policy's bits passes
    # with the witness named in the tail, and a max pinned off the
    # policy (the option did not bind at the lane's rate) FAILs even
    # while the current rate rides the band — the honest opposite of
    # a band-only verdict.
    v_pin, _, pin_tail = pacing_verdict(
        [{"pacing_rate_bps": PACING_BITS, "pacing_max_bps": PACING_BITS}]
    )
    v_off, _, off_tail = pacing_verdict(
        [{"pacing_rate_bps": PACING_BITS, "pacing_max_bps": PACING_BITS * 2}]
    )
    pin_ok = (
        v_pin == "PASS"
        and "the policy's own bits, exactly" in pin_tail
        and v_off == "FAIL"
        and "did not bind at the policy's rate" in off_tail
    )
    rows.append(
        (
            "law: the pinned max reads the policy's own bits",
            pin_ok,
            "the bps dialect's current/max pair names the option's own "
            "value in the max: 800000 b/s exactly -> PASS (the live "
            "attestation — a socket pinned at 100000 B/s reads "
            "800kbps/800kbps); a max at twice the policy -> FAIL even "
            "with the current rate inside the band",
        )
    )

    # The pacing verdict's band: at the cap is the PASS shape, past
    # the ceiling and under the floor are the honest FAILs, and no
    # paced sample names the non-engagement.
    at_cap = [{"pacing_rate_bps": PACING_BITS} for _ in range(3)]
    v_pass, top_pass, _ = pacing_verdict(at_cap)
    v_over, top_over, _ = pacing_verdict([{"pacing_rate_bps": PACING_BITS * 2}])
    v_under, top_under, _ = pacing_verdict([{"pacing_rate_bps": PACING_BITS * 0.3}])
    v_none, _, _ = pacing_verdict([{}])
    band_ok = (
        v_pass == "PASS"
        and top_pass == PACING_BITS
        and v_over == "FAIL"
        and top_over == PACING_BITS * 2
        and v_under == "FAIL"
        and v_none == "FAIL"
    )
    rows.append(
        (
            "law: the pacing verdict's band",
            band_ok,
            "top sample at the cap -> PASS; past the ceiling (the option "
            "did not bind) -> FAIL; under the floor (the rate did not "
            "land) -> FAIL; no paced sample (the lane never engaged) -> "
            "FAIL with the reason",
        )
    )

    # The throttle band: the lane's own rate is the PASS shape; past
    # the ceiling the lane did not limit; under the floor it
    # over-limited — both honest FAILs.
    t_pass, _ = throttle_verdict(RATE_BPS)
    t_over, _ = throttle_verdict(RATE_BPS * 2)
    t_under, _ = throttle_verdict(RATE_BPS * 0.3)
    throttle_ok = t_pass == "PASS" and t_over == "FAIL" and t_under == "FAIL"
    rows.append(
        (
            "law: the throttle verdict's band",
            throttle_ok,
            f"the average at the {RATE_STR} rate -> PASS; past the ceiling "
            "(the lane did not limit) -> FAIL; under the floor "
            "(over-limited, the honest opposite) -> FAIL",
        )
    )

    # The status-JSON pacing field contract (the schema row's shape):
    # the probe's own row carries pacing_rate_bytes == the planted
    # rate; a row without the field is the pre-v27 shape, named.
    fixture = {
        "limits": [
            {
                "cgroup_id": 4242,
                "packets_dropped": 0,
                "bytes_dropped": 0,
                "pacing_rate_bytes": 100_000,
            }
        ]
    }
    row = find_row(fixture, 4242)
    json_ok = (
        row is not None
        and row.get("pacing_rate_bytes") == RATE_BPS
        and find_row(fixture, 9999) is None
        and find_row({"limits": [{"cgroup_id": 4242}]}, 4242).get("pacing_rate_bytes") is None
    )
    rows.append(
        (
            "instrument: the v27 pacing field contract",
            json_ok,
            "limits[cg].pacing_rate_bytes reads the lane's commanded rate "
            "(100000 on the fixture); a missing row and a missing field "
            "read honestly absent — the pre-v27 shape the schema row "
            "names, never a fabricated zero",
        )
    )

    ok = 0
    for name, verdict, detail in rows:
        lib.record(name, "PASS" if verdict else "FAIL", detail)
        ok += 1 if verdict else 0
    lib.out()
    lib.out(f"  {ok} passed, {len(rows) - ok} failed — self-test instrument")
    return 0 if ok == len(rows) else 1


def main():
    ap = argparse.ArgumentParser(
        description="zelynic EDT live probe (night-spark-5 — the quota saver's Layer 3)"
    )
    ap.add_argument("--self-test", action="store_true", help="instrument lane only, no root")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--binary", default=None, help="zelynic binary to drive")
    args = ap.parse_args()
    if args.self_test:
        rc = self_test()
    else:
        if os.geteuid() == 0 and not lib.resolve_binary(
            args.binary, "sudo ./scripts/bench/edt-probe.sh"
        ):
            return 2
        rc = live_run()
    if args.json:
        lib.out(json.dumps(lib.RESULTS, indent=2))
    return rc


if __name__ == "__main__":
    sys.exit(main())
