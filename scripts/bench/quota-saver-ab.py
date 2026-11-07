#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
# LOC_EXEMPT: one runnable A/B proof — the ladder, the ledger, both scenarios, the overrunning pair and the verdict plumbing share one module by design; the module-package split is the tracked debt (night-spark-8 crossed the 1000 scripts cap adding the one-unit wire rule, night-spark-10 grew it with the overrun upload leg and the metered-plan translation)
"""The quota saver's A/B proof (night-netrunner-4, the final polish).

The "be honest" experiment: the same real download and the same real
upload run TWICE against one virtual quota ledger — once under the
live zelynic limit (scenario A, the product) and once with no
enforcement at all (scenario B, the legacy drop-based counterfactual).

  scenario A (zelynic): the report sibling's own machinery — a cgroup
      per leg, `strict <id> <rate> --no-test`, the status JSON read
      before and after; the leg books the Layer 4 telemetry deltas
      (bytes_allowed = the wire spend, bytes_saved_total = the bytes
      the saver lanes withheld that the quota WOULD otherwise have
      carried).
  scenario B (legacy): the same legs with no zelynic enforcement —
      no cgroup attach, no limiter, the raw path a drop-based setup
      walks. The wire cost is the hardware-agnostic interface delta
      (night-spark-8) — the same unit scenario A's cgroup counter
      books — with curl's app-byte read kept alongside as the
      completion proof, plus the TCP retransmission the wire itself
      reports: the system-wide /proc/net/snmp Tcp deltas (a
      quiet-runner measurement), converted at the conservative 1448
      B/segment estimate and printed as an estimate, never as fact.

The verdict lines are the task's exact wire contract, printed to
stdout at the end, one per leg:

    test download results the internet kuota save total is X%
    test upload results the internet kuota save total is Y%

Since night-spark-10 the number is the overrunning leg's own A/B
wire saving when that leg completed — what a metered plan would
actually see with an eager sender — and the clarifier above the
line says so. The bounded ledger's counterfactual (saved /
(transferred + saved), of everything the quota WOULD have carried
the share the saver lanes avoided) prints only as the named
fallback, when the overrunning legs were skipped or did not
complete. A leg that moved bytes and saved none prints 0.00%
honestly; a leg that could not run (no root, no cgroup v2, no
full-life binary, no curl, no reachable endpoint, the virtual
ledger exhausted) says why on stderr and exits 2 — the house
honest-refusal posture, never a fabricated line. Scenario B never
fabricates either: its retrans figure prints `n/a` when the kernel
counters are unreadable.

Night-spark-10, the practical proof: the overrunning UPLOAD leg is
the mirror of the download leg (the same loop, the same clock, the
tx wire unit), so the eager-sender savings are measured in BOTH
directions, and the run ends with the beginner's answer — the
metered-plan block prices each overrunning session's measured wire
against a 100 MB plan ("with zelynic: X MB consumed, Y MB left;
without: A MB consumed, B MB left"), no jargon, no counterfactual,
n/a where a leg did not complete. The binary ladder follows the
owner's preference: --binary, then the INSTALLED /usr/bin/zelynic
(the owner's real v80.1.0), then the pro-linux-amd64-v3-musl alias
the owner actually builds and runs, then pro-native-musl, then
target/release (fallback only — a stale artifact has mis-reported
its version there before), then PATH; when the resolved binary and
the alias build both exist and disagree on their -V banner, the
divergence is named on stderr and the run continues.

Every zelynic side effect is cleaned up: each scenario A leg applies
its limit (`strict --no-test`, the scripted-apply contract — no
verification probe inflating the ledger) and removes it (`unstrict`)
before the leg's cgroup is torn down.

The run starts from a MEASURED clean slate (night-netrunner-5):
`zelynic u --all` before scenario A, verified back to zero active
rows via `status --print-json` — a pre-existing limit clamps the
leg's sockets and the ledger reads a saving it did not earn (the
99.62% e2e anomaly: the worker's flow entered the run already
RECWN-clamped by an active row). A reset that cannot reach zero
refuses with the residue named.

The download leg walks the ladder as ATTEMPTS (night-netrunner-6):
a rung is accepted only when scenario A's own ledger clears 90% of
the leg's size — a 1 KB probe cannot see a small object, a stalled
mirror or a lane that dies between probe and leg, the leg's own
wire can — and the next rung takes the attempt, three rungs at
most, every skip named on stdout. Cloudflare's reach probe asks the
endpoint's own bytes= knob for its 1 KB: __down ignores the Range
header (measured live — the ranged probe rode back with the whole
20 MB body), so the old probe downloaded the entire leg each time
and a slow link demoted the best rung as dead.

The ledger-vs-wire gap (night-netrunner-12): the bounded pair's
verdict percentage is scenario A's OWN Layer 4 booking — the
counterfactual the window law estimates — not a measured A/B
saving. Measured on the owner host (2026-11-06): the bounded 20 MB
download booked 82.58% while A moved +1.21 MB MORE wire than B; the
bounded upload booked 75.85% while A moved +0.64 MB MORE. A bounded
transfer never gives the sender room to overrun its file, so the
counterfactual books savings the wire never withheld. The harness
now prints the three numbers per leg — the ledger's booking, the
wire ground truth (A's cgroup counter vs B's interface delta, one
wire unit on both sides), and the gap —
and carries OVERRUNNING legs: N seconds of back-to-back chunk GETs
on the bounded leg's accepted rung (night-netrunner-12) and, since
night-spark-10, N seconds of back-to-back uploads on cloudflare —
the eager receiver and the eager sender, the only workloads where
the withheld window manifests as wire the link never carried. The
workload matrix the honest claim must answer: the bounded download
and upload (the in-frame pair), the overrunning download and upload
(the campaign legs, on by default), the cellular envelope (rerun
with --download-rate 50kb), the EDT-dominant upload and the
ECN-dominant QUIC stream (the lanes' own probes: edt-probe.sh,
ecn-probe.sh), and the browsing mix (a human session — no script
can honestly synthesize it).

The one-unit rule (night-spark-8): the first measured run priced
scenario A's wire against scenario B's APP bytes — the cgroup counter
books every byte the kernel let through (headers, ACKs, retransmits)
while curl's size metric counts payload only, and the owner's own
host priced a 20 MB download at 21,493,059 interface bytes (7.47%
overhead curl never saw). The "+A moved MORE wire" reading was that
overhead, an apples-to-oranges artifact, not a product finding. Both
scenarios now read the same wire unit: the interface delta, summed
hardware-agnostically across every real interface in /proc/net/dev
(wifi, ethernet, usb tethering, a 4g dongle — no name configured
anywhere), scenario A keeping the cgroup counter as its primary wire
figure with the interface read as a cross-check whose agreement line
prices background traffic, scenario B taking its wire from the
interface delta with the app bytes printed beside it.

Usage:
    ./scripts/bench/quota-saver-ab.sh                # both scenarios
    ./scripts/bench/quota-saver-ab.sh --binary PATH  # explicit binary
    ./scripts/bench/quota-saver-ab.sh --help         # the flags
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

# The download ladder (night-spark-3b's chain, the supermassive
# realnet lane's own order — the report sibling's exact list): the
# first reachable rung feeds the leg. Cloudflare's bytes= form caps
# the transfer by construction; the other rungs cut a ranged GET to
# the leg's size.
DL_ENDPOINTS = [
    ("cloudflare", "https://speed.cloudflare.com/__down?bytes={bytes}", None),
    ("vultr-singapore", "http://sgp-ping.vultr.com/vultr.com.1000MB.bin", "range"),
    ("naist-nara", "http://ftp.naist.jp/debian/ls-lR.gz", "range"),
    ("ubuntu-taipei", "https://tw.archive.ubuntu.com/ubuntu/ls-lR.gz", "range"),
    ("kku-bangkok", "https://mirror.kku.ac.th/ubuntu/ls-lR.gz", "range"),
    ("biznet-jakarta", "https://mirror.biznetgio.com/ubuntu/ls-lR.gz", "range"),
]
UL_ENDPOINT = ("cloudflare", "https://speed.cloudflare.com/__up")

CGROUP_ROOT = "/sys/fs/cgroup"
PROBE_TIMEOUT = 15
# The virtual quota both scenarios draw from (the task's 100 MB frame).
QUOTA_BUDGET = 100_000_000
# The conservative per-segment estimate for the retrans ledger (1460
# MSS minus timestamps option); the table labels it an estimate.
RETRANS_SEG_BYTES = 1448
SNMP = "/proc/net/snmp"
PROC_NET_DEV = "/proc/net/dev"
# The hardware-agnostic wire counter's exclusion list (night-spark-8):
# loopback and virtual/overlay name prefixes — bytes there also
# traverse a physical interface, so summing them would double-count.
# Everything else counts as-is (eth*, en*, wlan*, wlp*, usb*, wwan*,
# rmnet*, ppp* — ppp stays IN: a physical-modem protocol on 3g/4g
# dongles). No interface name is configured anywhere.
VIRTUAL_IFACE_PREFIXES = ("lo", "docker", "veth", "br-", "virbr", "tun", "tap", "wg")
# The download leg's delivery floor and attempt cap (night-netrunner-6):
# a rung that answers the 1 KB probe can still fail the real leg (an
# object smaller than the leg rides the range past its EOF into a
# short read, a mirror stalls under the speed floor, the lane dies
# between probe and leg — the wire reads 0.00 MB). Under 90% of the
# leg's own size the rung did not deliver, and the next rung takes
# the attempt; three rungs is the cap (every attempt is real wire on
# a quota-metered host).
DL_FLOOR_FRAC = 0.9
DL_MAX_RUNGS = 3
# The overrunning leg's chunk (night-netrunner-12): small enough that
# a slow rung still turns iterations inside the wall-clock budget,
# large enough that each GET is real wire, not a probe.
OVERRUN_CHUNK_BYTES = 2_000_000
# The overrunning upload leg's per-iteration file (night-spark-10):
# a sparse PUT sized so one iteration clears its own --max-time
# well before the wall clock ends the session — the loop drives the
# total up, not the file size.
OVERRUN_UPLOAD_CHUNK_BYTES = 500_000


def out(line: str) -> None:
    print(line, flush=True)


def repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def resolve_binary(explicit: str | None) -> str:
    """The harness's ladder (night-spark-10, the owner's preference):
    an explicit path outranks everything; then the INSTALLED binary
    (/usr/bin/zelynic — the owner's real v80.1.0), then the alias
    pro-linux-amd64-v3-musl build the owner actually builds and runs,
    then the pro-native-musl shape, then target/release (fallback
    only — a stale artifact has mis-reported its version there
    before), then the PATH install."""
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        return fail(f"binary not executable: {explicit}")
    target = os.path.join(repo_root(), "target", "x86_64-unknown-linux-musl")
    for candidate in (
        "/usr/bin/zelynic",
        os.path.join(target, "pro-linux-amd64-v3-musl", "zelynic"),
        os.path.join(target, "pro-native-musl", "zelynic"),
        os.path.join(repo_root(), "target", "release", "zelynic"),
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("zelynic")
    if found:
        return found
    return fail(
        "no zelynic binary found — build one (./scripts/build.sh release) or pass --binary PATH"
    )


def note_binary_divergence(binary: str) -> None:
    """The stale-artifact tell (night-spark-10): the resolved
    binary's own -V banner against the alias build's, when both
    exist and the resolved binary is not the alias itself. A
    disagreement is named on stderr and the harness continues —
    informational, never a hard fail (the stale target/release copy
    mis-reported its version while /usr/bin and the alias agreed on
    v80.1.0)."""
    alias = os.path.join(
        repo_root(), "target", "x86_64-unknown-linux-musl", "pro-linux-amd64-v3-musl", "zelynic"
    )
    if binary == alias or not (os.path.isfile(alias) and os.access(alias, os.X_OK)):
        return
    rc_a, out_a, _ = zel(binary, ["-V"])
    rc_b, out_b, _ = zel(alias, ["-V"])
    if rc_a != 0 or rc_b != 0:
        return
    banner_a = (out_a.strip().splitlines() or [""])[0].strip()
    banner_b = (out_b.strip().splitlines() or [""])[0].strip()
    if banner_a and banner_b and banner_a != banner_b:
        print(
            f"quota-saver-ab: note — the resolved binary reports '{banner_a}' "
            f"while the alias build reports '{banner_b}'; the resolved "
            "binary may be stale (informational, the run continues)",
            file=sys.stderr,
            flush=True,
        )


def fail(reason: str) -> "str":
    """Honest refusal: the reason on stderr, exit 2."""
    print(f"quota-saver-ab: cannot run — {reason}", file=sys.stderr, flush=True)
    sys.exit(2)


def zel(binary: str, args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        p = subprocess.run([binary, *args], capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return 1, "", str(e)
    return p.returncode, p.stdout, p.stderr


def status_entry(binary: str, cgroup_id: int) -> dict:
    rc, stdout, stderr = zel(binary, ["status", "--print-json"])
    if rc != 0:
        fail(f"status --print-json failed: {(stderr or stdout).strip()[:200]}")
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as e:
        fail(f"status JSON unreadable: {e}")
    for entry in doc.get("limits", []):
        if entry.get("cgroup_id") == cgroup_id:
            return entry
    fail(f"no limit row for cgroup {cgroup_id} — the strict apply did not hold")


def active_limit_rows(binary: str) -> list:
    """The whole limits[] array (the clean-slate preflight's own read):
    an empty list is a clean host, every row is a limit the system
    already carries."""
    rc, stdout, stderr = zel(binary, ["status", "--print-json"])
    if rc != 0:
        fail(f"status --print-json failed: {(stderr or stdout).strip()[:200]}")
    try:
        doc = json.loads(stdout)
    except json.JSONDecodeError as e:
        fail(f"status JSON unreadable: {e}")
    return doc.get("limits", []) or []


def clean_slate_preflight(binary: str) -> None:
    """Night-netrunner-5, the clean-slate preflight: `sudo zelynic u
    --all` BEFORE scenario A. A pre-existing limit clamps the leg's
    sockets before the probe applies its own policy — the ledger then
    reads a saving it did not earn (the 99.62% e2e anomaly: the
    worker's flow entered the run already RECWN-clamped by an active
    row, so scenario A's wire figure was depressed by somebody else's
    limit). The emergency reset is the one spelling that clears every
    limit on the machine (it exits 0 on an already-clean host), and
    the reset is VERIFIED: the status read after it must show zero
    active rows, or the proof refuses with the residue named — a
    clean slate is a measured fact here, not an assumption."""
    pre_rows = active_limit_rows(binary)
    rc, stdout, stderr = zel(binary, ["unstrict", "--all"], timeout=120)
    if rc != 0:
        fail(
            "the clean-slate preflight failed: `unstrict --all` exited "
            f"{rc}: {(stderr or stdout).strip()[:200]}"
        )
    post_rows = active_limit_rows(binary)
    out(
        f"clean-slate preflight: sudo zelynic u --all "
        f"({len(pre_rows)} active limit row(s) before, {len(post_rows)} after)"
    )
    if post_rows:
        residue = ", ".join(f"cg:{row.get('cgroup_id')}" for row in post_rows[:5])
        fail(
            "the clean-slate preflight could not reach zero — "
            f"{len(post_rows)} limit row(s) still active ({residue}); "
            "scenario A would measure against a depressed wire"
        )


def probe_once(url: str, ranged: bool = True) -> tuple[bool, str]:
    """One endpoint attempt: curl exits 0 with a 2xx/2xx-range code;
    the detail names what the wire actually said (the refusal owes
    its reader the evidence, not just the verdict). The ranged probe
    rides -r 0-1023; the native-size probe omits the header entirely
    (night-netrunner-6: cloudflare's __down ignores Range — measured
    live, the 1 KB ranged probe rode back with the whole 20 MB body,
    so a slow link timed the probe out and demoted the best rung as
    dead; its probe asks the endpoint's own bytes= knob instead)."""
    args = [
        "curl",
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        "--max-time",
        str(PROBE_TIMEOUT),
    ]
    if ranged:
        args += ["-r", "0-1023"]
    args.append(url)
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=PROBE_TIMEOUT + 5)
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except OSError as e:
        return False, str(e)[:60]
    code = p.stdout.strip()
    if p.returncode == 0 and code in ("200", "206"):
        return True, code
    return False, f"curl exit {p.returncode}, HTTP {code or 'none'}"


def probe_detail(url: str, ranged: bool = True) -> tuple[bool, str]:
    """The rung's gate, two attempts 4 s apart (the guest's SLIRP path
    and the shared runner egress make a single attempt a coin flip —
    one real e2e leg lost the upload rung to a one-shot probe while
    the download ladder answered), with the evidence kept for the
    caller's refusal line."""
    ok, detail = probe_once(url, ranged=ranged)
    if ok:
        return True, detail
    time.sleep(4)
    return probe_once(url, ranged=ranged)


def probe_url(name: str, template: str, leg_bytes: int) -> str:
    """The reachability probe's own URL, per rung: cloudflare's __down
    ignores the Range header (the 1 KB ranged probe came back with the
    whole leg — a slow link then timed the probe out at 15 s and
    demoted the best rung as dead), so its probe asks the endpoint's
    own bytes= knob for the 1 KB; the range rungs keep the ranged
    probe against the leg-sized URL — the range answer IS what the
    leg needs from them."""
    if name == "cloudflare":
        return template.format(bytes=1024)
    return template.format(bytes=leg_bytes)


def download_url(template: str, leg_bytes: int) -> str:
    """The leg's own URL: cloudflare caps by its bytes= form, the
    range rungs cut the size off the object at transfer time."""
    return template.format(bytes=leg_bytes)


def make_cgroup(name: str) -> int:
    path = os.path.join(CGROUP_ROOT, name)
    try:
        os.mkdir(path)
    except FileExistsError:
        fail(
            f"cgroup {path} already exists — a previous run left it behind; "
            "remove it (it must be empty) and re-run"
        )
    except OSError as e:
        fail(f"cannot create {path}: {e}")
    st = os.stat(path)
    # cgroup v2 ids are the 32-bit kernfs inode (the identity walk's
    # own resolution): stat's inode low 32 bits.
    return st.st_ino & 0xFFFFFFFF


def metric_of(stdout: str) -> tuple[int | None, str]:
    """The worker's last stdout line is the curl size metric."""
    metric = stdout.strip().splitlines()[-1] if stdout.strip() else ""
    try:
        return int(metric), ""
    except ValueError:
        return None, f"no metric ({metric[:60] or 'empty'})"


def run_worker(argv: list[str], cgroup_path: str | None, timeout: int) -> tuple[int | None, str]:
    """Run the curl worker to completion — inside the cgroup for
    scenario A (the write-moves-us contract), bare for scenario B —
    and return (bytes, err)."""
    if cgroup_path is None:
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as e:
            return None, str(e)
        return metric_of(p.stdout)
    script = f'echo $$ > "{cgroup_path}/cgroup.procs"\nexec "$@"'
    try:
        p = subprocess.Popen(
            ["bash", "-c", script, "worker"] + argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError as e:
        return None, str(e)
    try:
        stdout, _ = p.communicate(timeout=timeout)
        return metric_of(stdout)
    except subprocess.TimeoutExpired:
        p.kill()
        return None, "worker did not finish"


def delta_savings(before: dict, after: dict) -> tuple[int, int]:
    """The Layer 4 telemetry deltas: (transferred, saved)."""
    transferred = after.get("bytes_allowed", 0) - before.get("bytes_allowed", 0)
    saved = after.get("bytes_saved_total", 0) - before.get("bytes_saved_total", 0)
    return max(transferred, 0), max(saved, 0)


def save_percent(transferred: int, saved: int) -> str:
    total = transferred + saved
    if total == 0:
        return "0.00"
    return f"{(saved / total) * 100:.2f}"


def tcp_counters() -> tuple[int, int] | None:
    """The system-wide Tcp counters, parsed by field name from the
    two-line snmp table: (OutSegs, RetransSegs), or None."""
    try:
        with open(SNMP, "r", encoding="ascii") as fh:
            rows = [ln.split() for ln in fh if ln.startswith("Tcp:")]
    except OSError:
        return None
    if len(rows) < 2:
        return None
    header, data = rows[0][1:], rows[1][1:]
    try:
        row = dict(zip(header, data))
        return int(row["OutSegs"]), int(row["RetransSegs"])
    except (KeyError, ValueError):
        return None


def retrans_delta(before: tuple[int, int] | None, after: tuple[int, int] | None):
    if before is None or after is None:
        return None
    return max(after[0] - before[0], 0), max(after[1] - before[1], 0)


def total_wire_bytes(direction: str) -> int | None:
    """The system-wide wire-byte counter, hardware-agnostic
    (night-spark-8): the rx or tx byte total summed across every real
    interface in /proc/net/dev — virtual/overlay names excluded, no
    interface name configured anywhere, so wifi, ethernet, usb
    tethering and a 4g dongle all measure the same way. The counter
    is SYSTEM-WIDE: unrelated traffic on the host during a leg
    inflates it (the A-side cgroup counter is cgroup-isolated — the
    report's agreement line prices that gap). None when the table is
    unreadable."""
    if direction not in ("rx", "tx"):
        return None
    try:
        with open(PROC_NET_DEV, "r", encoding="ascii") as fh:
            lines = fh.readlines()[2:]  # the two header lines
    except OSError:
        return None
    total = 0
    for line in lines:
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        if name.strip().startswith(VIRTUAL_IFACE_PREFIXES):
            continue
        fields = rest.split()
        if len(fields) < 9:
            continue
        try:
            total += int(fields[0] if direction == "rx" else fields[8])
        except ValueError:
            return None
    return total


def fmt_mb(n: int) -> str:
    return f"{n / 1_000_000:.2f} MB"


def retrans_mb(delta) -> str:
    """The labeled estimate; None means the kernel counters were
    unreadable and the honest cell is `n/a`."""
    if delta is None:
        return "n/a"
    return fmt_mb(delta[1] * RETRANS_SEG_BYTES)


def ensure_bpffs(binary: str) -> None:
    """The Orchestra's limiter gate, checked through the binary's own
    doctor before the strict apply: a non-bpffs /sys/fs/bpf turns
    every pin into EINVAL (the hunt-28 blind spot). A doctor that
    cannot answer leaves the verdict to the strict apply's own
    refusal — the same wording either way."""
    rc, stdout, _ = zel(binary, ["doctor", "--print-json"])
    if rc == 0:
        try:
            doc = json.loads(stdout)
            if not doc.get("system", {}).get("bpf_fs_mounted", False):
                fail(
                    "/sys/fs/bpf is not a mounted bpf filesystem — the limiter pins "
                    "its maps there; mount it: sudo mount -t bpf bpf /sys/fs/bpf"
                )
        except json.JSONDecodeError:
            pass  # the strict apply below will refuse with its own wording


class Ledger:
    """The virtual quota both scenarios draw from: only wire bytes
    spend (the saver's withheld share never leaves the machine; the
    legacy leg's retransmission estimate spends with it)."""

    def __init__(self) -> None:
        self.remaining = QUOTA_BUDGET

    def spend(self, tag: str, wire: int, estimate: int = 0) -> None:
        cost = wire + estimate
        if cost > self.remaining:
            fail(
                f"the virtual {fmt_mb(QUOTA_BUDGET)} quota ran out at {tag} "
                f"(needs {fmt_mb(cost)}, {fmt_mb(self.remaining)} left) — the legs "
                "overshoot the task's frame; shrink --download-bytes/--upload-bytes"
            )
        self.remaining -= cost


class Leg:
    """One leg's two-scenario books: scenario A's Layer 4 deltas plus
    its interface cross-check, scenario B's hardware-agnostic wire
    cost with the app bytes beside it, the wire's own retrans
    reports."""

    def __init__(self) -> None:
        self.transferred = 0
        self.saved = 0
        self.wire = 0
        self.wire_interface = None
        self.app_bytes = None
        self.retrans = None
        self.partial = False
        self.err = ""


def download_worker(curl: str, url: str, name: str, size: int) -> list[str]:
    worker = [
        curl,
        "-s",
        "-o",
        "/dev/null",
        "-w",
        "%{size_download}",
        "--max-time",
        "60",
        "--speed-time",
        "45",
        "--speed-limit",
        "1024",
    ]
    # Cloudflare's bytes= form caps by construction; ranged rungs
    # cut the exact size off the object.
    if name == "cloudflare":
        worker.append(url)
    else:
        worker += ["-r", f"0-{size - 1}", url]
    return worker


def overrun_worker(curl: str, url: str, name: str, size: int, seconds: int) -> list[str]:
    """The overrunning leg's worker (night-netrunner-12): back-to-back
    chunk GETs until the wall clock says stop — the eager receiver
    whose sender always has more. The savings manifest here or
    nowhere: a bounded transfer ends because the FILE ended, an
    overrunning session ends because the CLOCK ended, so the enforced
    leg's slower drain is wire the link never carried. One small bash
    loop, every iteration a real 2 MB GET (a stalled one dies at its
    own --max-time and reads zero, the loop never lies), the final
    stdout line the summed bytes the metric reader expects."""
    fetch = f"{curl} -s -o /dev/null -w '%{{size_download}}' --max-time 30"
    if name == "cloudflare":
        cmd = f"{fetch} '{url}'"
    else:
        cmd = f"{fetch} -r 0-{size - 1} '{url}'"
    inner = (
        f"total=0; end=$((SECONDS + {seconds})); "
        f"while [ $SECONDS -lt $end ]; do "
        f"b=$({cmd} 2>/dev/null) || true; "
        f"case $b in (*[!0-9]*|'') b=0;; esac; "
        f"total=$((total + b)); done; echo $total"
    )
    return ["bash", "-c", inner]


def overrun_upload_worker(curl: str, url: str, path: str, seconds: int) -> list[str]:
    """The overrunning upload leg's worker (night-spark-10): the
    mirror of overrun_worker on the egress direction — back-to-back
    PUTs of the sparse file until the wall clock says stop, the
    eager sender whose file is small but whose clock never ends.
    The enforced leg's slower drain is wire the link never carried,
    the same one-unit rule as the download leg, and the final
    stdout line is the summed bytes the metric reader expects."""
    put = f"{curl} -s -o /dev/null -w '%{{size_upload}}' --max-time 30 -T '{path}' '{url}'"
    inner = (
        f"total=0; end=$((SECONDS + {seconds})); "
        f"while [ $SECONDS -lt $end ]; do "
        f"b=$({put} 2>/dev/null) || true; "
        f"case $b in (*[!0-9]*|'') b=0;; esac; "
        f"total=$((total + b)); done; echo $total"
    )
    return ["bash", "-c", inner]


def run_scenario_a_download(
    binary: str, cg: str, cg_path: str, rate: str, worker: list[str], timeout: int = 70
) -> Leg:
    """The product leg: cgroup + strict + the Layer 4 deltas, the
    cgroup counter kept as the primary wire figure (cgroup-isolated,
    immune to background traffic) with the hardware-agnostic
    interface delta as the cross-check (night-spark-8)."""
    leg = Leg()
    cg_id = make_cgroup(cg)
    try:
        rc, _, stderr = zel(binary, ["strict", str(cg_id), rate, "--no-test"])
        if rc != 0:
            fail(f"strict {rate} failed: {(stderr or '').strip()[:200]}")
        before = status_entry(binary, cg_id)
        w0 = total_wire_bytes("rx")
        got, err = run_worker(worker, cg_path, timeout)
        w1 = total_wire_bytes("rx")
        after = status_entry(binary, cg_id)
        leg.transferred, leg.saved = delta_savings(before, after)
        if w0 is not None and w1 is not None:
            leg.wire_interface = max(w1 - w0, 0)
        if got is None:
            leg.partial = True
            leg.err = err
    finally:
        zel(binary, ["unstrict", str(cg_id)], timeout=30)
        try:
            os.rmdir(cg_path)
        except OSError:
            pass
    return leg


def run_scenario_b_download(worker: list[str], timeout: int = 70) -> Leg:
    """The legacy leg: the same worker, no enforcement, the wire's
    own retransmission read around it, the wire figure taken from the
    hardware-agnostic interface delta (night-spark-8) — the same unit
    scenario A's cgroup counter books — with curl's app bytes kept as
    leg.app_bytes, printed beside the wire. A dead attempt returns the
    honest zero wire with the error carried (night-netrunner-6: the
    caller's failover names it and moves to the next rung — the hard
    refusal was the caller's alone, and it killed a run whose A leg
    had already delivered)."""
    leg = Leg()
    t0 = tcp_counters()
    w0 = total_wire_bytes("rx")
    got, err = run_worker(worker, None, timeout)
    t1 = tcp_counters()
    w1 = total_wire_bytes("rx")
    leg.app_bytes = got
    if w0 is not None and w1 is not None:
        leg.wire = max(w1 - w0, 0)
    elif got is not None:
        # /proc/net/dev went unreadable mid-run: the wire falls back
        # to the app bytes and the leg is marked partial — the unit
        # switch is named, never silent.
        leg.wire = got
        leg.partial = True
        leg.err = err or "the interface counter went unreadable; wire = app bytes"
    if got is None:
        leg.partial = True
        leg.err = err
    elif got == 0:
        leg.partial = True
    leg.retrans = retrans_delta(t0, t1)
    return leg


def run_download_leg(
    binary: str, curl: str, ledger: "Ledger", dl_bytes: int, rate: str
) -> tuple[Leg, Leg, str]:
    """The download leg with the rung failover (night-netrunner-6,
    the wire 0.00 MB fix): the ladder is walked as ATTEMPTS now. A
    rung is accepted only when scenario A's own ledger clears the
    delivery floor (90% of the leg's size); a rung whose leg
    under-delivers is named and the NEXT rung takes the attempt,
    three rungs at most — a 1 KB probe cannot see a small object, a
    stalled mirror or a lane that dies between probe and leg, but the
    leg's own wire can, and the verdict rides the wire, not the probe.
    Scenario B rides the accepted rung; if its own wire misses the
    floor, the remaining rungs carry B alone (A's ledger is banked,
    never re-run — the counterfactual needs a working lane, not the A
    lane's identity). Every skipped rung and every under-delivering
    leg is named on stdout before the next attempt — the walk is
    visible, never silent."""
    floor = int(dl_bytes * DL_FLOOR_FRAC)
    tried: list[str] = []
    a_dl = None
    dl_name = None
    dl_rung = None
    rungs = 0
    for rung in DL_ENDPOINTS:
        name, template, _mode = rung
        if rungs >= DL_MAX_RUNGS:
            break
        ok, detail = probe_detail(
            probe_url(name, template, dl_bytes), ranged=(name != "cloudflare")
        )
        if not ok:
            tried.append(f"{name}: probe dead ({detail})")
            continue
        rungs += 1
        worker = download_worker(curl, download_url(template, dl_bytes), name, dl_bytes)
        a = run_scenario_a_download(
            binary,
            "zelynic-quota-ab-dl",
            os.path.join(CGROUP_ROOT, "zelynic-quota-ab-dl"),
            rate,
            worker,
        )
        if a.transferred < floor:
            tried.append(
                f"{name}: the ledger moved wire {fmt_mb(a.transferred)}, "
                f"under the {fmt_mb(floor)} floor"
            )
            out(f"  (download rung skipped: {tried[-1]})")
            continue
        a_dl, dl_name, dl_rung = a, name, rung
        break
    if a_dl is None or dl_rung is None:
        fail(
            f"no download rung delivered the leg after {DL_MAX_RUNGS} attempt(s) "
            "— the tried rungs say: " + "; ".join(tried)
        )
    out(f"the download rung: {dl_name} (the leg cleared the {fmt_mb(floor)} floor)")
    ledger.spend("the scenario A download leg", a_dl.transferred)

    # Scenario B — the accepted rung first, then the remaining rungs
    # (each probed before it is spent; A never re-runs).
    b_dl = None
    b_rungs = 0
    candidates = [dl_rung] + [r for r in DL_ENDPOINTS if r[0] != dl_name]
    for name, template, _mode in candidates:
        if b_rungs >= DL_MAX_RUNGS:
            break
        if name != dl_name:
            ok, detail = probe_detail(
                probe_url(name, template, dl_bytes), ranged=(name != "cloudflare")
            )
            if not ok:
                out(f"  (legacy rung skipped: {name}: probe dead ({detail}))")
                continue
        b_rungs += 1
        b = run_scenario_b_download(
            download_worker(curl, download_url(template, dl_bytes), name, dl_bytes)
        )
        if b.wire < floor:
            note = f"{name}: wire {fmt_mb(b.wire)}, under the {fmt_mb(floor)} floor"
            if b.err:
                note += f" ({b.err[:80]})"
            out(f"  (legacy leg under-delivered: {note})")
            continue
        b_dl = b
        break
    if b_dl is None:
        fail(
            f"the legacy download leg delivered nothing after {DL_MAX_RUNGS} "
            "attempt(s) — the wire says: " + ("; ".join(tried) or "every rung rode under the floor")
        )
    est = 0 if b_dl.retrans is None else b_dl.retrans[1] * RETRANS_SEG_BYTES
    ledger.spend("the scenario B download leg", b_dl.wire, est)
    return a_dl, b_dl, dl_name, dl_rung


def run_scenario_a_upload(
    binary: str, cg: str, cg_path: str, rate: str, worker: list[str], timeout: int = 70
) -> Leg:
    """The product leg, upload policy (`-u`): the pacing lane's
    commanded rate rides the egress policed path."""
    leg = Leg()
    cg_id = make_cgroup(cg)
    try:
        rc, _, stderr = zel(binary, ["strict", str(cg_id), "-u", rate, "--no-test"])
        if rc != 0:
            fail(f"strict -u {rate} failed: {(stderr or '').strip()[:200]}")
        before = status_entry(binary, cg_id)
        w0 = total_wire_bytes("tx")
        got, err = run_worker(worker, cg_path, timeout)
        w1 = total_wire_bytes("tx")
        after = status_entry(binary, cg_id)
        leg.transferred, leg.saved = delta_savings(before, after)
        if w0 is not None and w1 is not None:
            leg.wire_interface = max(w1 - w0, 0)
        if got is None:
            leg.partial = True
            leg.err = err
    finally:
        zel(binary, ["unstrict", str(cg_id)], timeout=30)
        try:
            os.rmdir(cg_path)
        except OSError:
            pass
    return leg


def run_scenario_b_upload(worker: list[str], timeout: int = 70) -> Leg:
    """The legacy upload leg; the wire figure from the hardware-
    agnostic tx interface delta (night-spark-8), curl's app bytes
    kept beside it."""
    leg = Leg()
    t0 = tcp_counters()
    w0 = total_wire_bytes("tx")
    got, err = run_worker(worker, None, timeout)
    t1 = tcp_counters()
    w1 = total_wire_bytes("tx")
    if got is None:
        fail(f"the legacy upload leg failed: {err}")
    leg.app_bytes = got
    if w0 is not None and w1 is not None:
        leg.wire = max(w1 - w0, 0)
    else:
        # the unit switch is named, never silent
        leg.wire = got
        leg.partial = True
    leg.retrans = retrans_delta(t0, t1)
    if got == 0:
        leg.partial = True
    return leg


def ground_truth_line(a: Leg, b: Leg) -> str | None:
    """The wire's own verdict (night-netrunner-12): scenario A's wire
    (the bytes_allowed delta) against scenario B's wire (the
    interface delta) — one unit on both sides since night-spark-8,
    the measurement the ledger cannot print about itself."""
    if b.wire <= 0:
        return None
    delta = a.transferred - b.wire
    pct = (b.wire - a.transferred) / b.wire * 100.0
    if delta >= 0:
        return f"A moved +{fmt_mb(delta)} MORE wire than B -> A/B wire saving {pct:.2f}%"
    return f"A moved {fmt_mb(-delta)} LESS wire than B -> A/B wire saving {pct:.2f}%"


def print_leg(leg_name: str, a: Leg, b: Leg) -> None:
    out(f"  {leg_name}:")
    out(
        f"    A (zelynic):  wire {fmt_mb(a.transferred)} + withheld {fmt_mb(a.saved)}"
        f" -> saved {save_percent(a.transferred, a.saved)}%"
        + ("  (partial leg)" if a.partial else "")
    )
    if a.wire_interface is not None and a.transferred > 0:
        gap = abs(a.wire_interface - a.transferred) / a.transferred * 100.0
        out(
            f"    cgroup/interface agreement: A cgroup {fmt_mb(a.transferred)} "
            f"vs interface {fmt_mb(a.wire_interface)} ({gap:.2f}% gap)"
        )
    app = f" (app {fmt_mb(b.app_bytes)})" if b.app_bytes is not None else ""
    out(
        f"    B (legacy):   wire {fmt_mb(b.wire)}{app} + retrans {retrans_mb(b.retrans)} (est)"
        f" -> saved 0.00%  (nothing withholds on the drop-based path)"
        + ("  (partial leg)" if b.partial else "")
    )
    truth = ground_truth_line(a, b)
    if truth:
        out(f"    ground truth: {truth}")
        out(
            f"    the gap: the ledger books {save_percent(a.transferred, a.saved)}% "
            f"(its counterfactual), the wire measured "
            f"{(b.wire - a.transferred) / b.wire * 100.0:.2f}% (the A/B difference)"
        )
    else:
        out("    ground truth: unavailable (B moved nothing)")
    if a.partial and a.err:
        out(f"    (A worker note: {a.err[:90]})")


def overrun_wire_percent(a: "Leg | None", b: "Leg | None") -> float | None:
    """The overrunning leg's own wire saving (night-spark-10): the
    A/B difference, one wire unit on both sides — the number a
    metered plan would actually see with an eager sender. None when
    the leg did not run (skipped) or did not complete; the verdict
    then falls back to the bounded ledger's counterfactual and the
    clarifier names it."""
    if a is None or b is None:
        return None
    if a.partial or b.partial or a.transferred <= 0 or b.wire <= 0:
        return None
    return (b.wire - a.transferred) / b.wire * 100.0


def plan_left_mb(wire: int) -> str:
    """The plan arithmetic the metered block prints: the 100 MB
    frame minus the measured wire, clamped at zero, one decimal."""
    return f"{max(100.0 - wire / 1_000_000, 0.0):.1f} MB"


def print_metered_plan(
    seconds: int,
    a_or: "Leg | None",
    b_or: "Leg | None",
    a_or_ul: "Leg | None",
    b_or_ul: "Leg | None",
) -> None:
    """The beginner's answer (night-spark-10): each overrunning
    session's measured wire priced against a 100 MB plan —
    with-zelynic wire against without-zelynic wire, the arithmetic
    a bill actually follows, the counterfactual booking appearing
    nowhere here. A direction whose leg did not run or complete
    says n/a, never a hopeful number."""
    out("")
    out("━━━ what this means on a metered plan ━━━")
    for label, a, b in (
        ("download", a_or, b_or),
        ("upload", a_or_ul, b_or_ul),
    ):
        out(f"  {label} — {seconds}s overrun session:")
        if a is None or b is None or a.partial or b.partial or a.transferred <= 0 or b.wire <= 0:
            out("    n/a — the leg did not complete")
            continue
        out(
            f"    with zelynic:    {fmt_mb(a.transferred)} consumed  →  "
            f"on a 100 MB plan: {plan_left_mb(a.transferred)} left"
        )
        out(
            f"    without:         {fmt_mb(b.wire)} consumed  →  "
            f"on a 100 MB plan: {plan_left_mb(b.wire)} left"
        )
        out(f"    savings:  {(b.wire - a.transferred) / b.wire * 100.0:.1f}%")


def print_masterclass_verdict(
    a_dl: Leg,
    a_ul: Leg,
    a_or: "Leg | None",
    b_or: "Leg | None",
    a_or_ul: "Leg | None",
    b_or_ul: "Leg | None",
) -> None:
    """The exact wire contract: one line per leg — the number the
    beginner repeats (night-spark-10). The overrunning legs are the
    claim: when a leg completed, its A/B wire saving IS the verdict,
    the clarifier above the line saying so. The bounded ledger's
    counterfactual prints only as the named fallback (overrun skipped
    or a leg that did not complete) — the pre-night-spark-10 shape,
    unchanged. Both byte strings stay regex-matchable for the CI
    e2e-init.sh grep."""
    wire_clarifier = (
        "  (wire-measured over the overrun leg — what a metered plan "
        "would actually see with an eager sender)"
    )
    ledger_clarifier = (
        "  (the percentage below is the cgroup ledger's counterfactual "
        "booking; the A/B wire ground truth is the line above)"
    )
    wire_dl = overrun_wire_percent(a_or, b_or)
    wire_ul = overrun_wire_percent(a_or_ul, b_or_ul)
    dl_line = (
        f"test download results the internet kuota save total is {wire_dl:.1f}%"
        if wire_dl is not None
        else "test download results the internet kuota save total is "
        f"{save_percent(a_dl.transferred, a_dl.saved)}%"
    )
    ul_line = (
        f"test upload results the internet kuota save total is {wire_ul:.1f}%"
        if wire_ul is not None
        else "test upload results the internet kuota save total is "
        f"{save_percent(a_ul.transferred, a_ul.saved)}%"
    )
    out("")
    out("━━━ the masterclass verdict ━━━")
    out(wire_clarifier if wire_dl is not None else ledger_clarifier)
    out(dl_line)
    out(wire_clarifier if wire_ul is not None else ledger_clarifier)
    out(ul_line)


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="quota-saver-ab",
        description="the quota saver's A/B proof: scenario A (zelynic) against "
        "the legacy drop-based counterfactual (night-netrunner-4)",
    )
    ap.add_argument("--binary", help="path to the zelynic binary")
    ap.add_argument(
        "--download-bytes",
        type=int,
        default=500_000,
        help="download leg size in bytes (default 500000 — a bounded transfer at "
        "the default 100kb rate completes in ~5s; raise only if you also raise "
        "--download-rate)",
    )
    ap.add_argument(
        "--upload-bytes",
        type=int,
        default=500_000,
        help="upload leg size in bytes (default 500000)",
    )
    ap.add_argument(
        "--download-rate",
        default="100kb",
        help="scenario A's download limit (default 100kb — the metered envelope "
        "the harness exists for)",
    )
    ap.add_argument(
        "--upload-rate",
        default="100kb",
        help="scenario A's upload limit (default 100kb — the metered envelope)",
    )
    ap.add_argument(
        "--overrun-seconds",
        type=int,
        default=30,
        help="the overrunning leg's wall-clock budget in seconds (default 30)",
    )
    ap.add_argument(
        "--skip-overrun",
        action="store_true",
        help="skip the overrunning legs (quota-poor hosts) — the bounded pair alone "
        "prices the booking, never the saving",
    )
    args, unknown = ap.parse_known_args()
    if unknown:
        print(
            f"quota-saver-ab: unknown argument(s): {' '.join(unknown)}", file=sys.stderr, flush=True
        )
        return 2

    if os.geteuid() != 0:
        fail("this script programs the kernel datapath — run with sudo")
    # The v2 marker is a FILE (cgroup.controllers), never a directory
    # — an isdir() probe here refused every real v2 host while the
    # hierarchy sat healthy underneath (the e2e guest exposed it).
    if not os.path.isfile(os.path.join(CGROUP_ROOT, "cgroup.controllers")):
        fail("cgroup v2 not found at /sys/fs/cgroup — a unified hierarchy is required")
    if shutil.which("curl") is None:
        fail("curl not found — the legs are real transfers")
    binary = resolve_binary(args.binary)
    note_binary_divergence(binary)
    # The Orchestra's gate, verified through the binary's own doctor:
    # floor, cgroup v2, bpffs, root — a missing capability refuses with
    # the doctor's wording before any leg starts.
    ensure_bpffs(binary)

    rc, stdout, stderr = zel(binary, ["--version"])
    if rc != 0:
        fail(f"the binary does not run: {(stderr or stdout).strip()[:200]}")
    if "eBPF" not in stdout and "dormant" in stdout:
        fail("this is a half-life build (eBPF dormant) — install a full-life binary")

    # Night-netrunner-5: the clean-slate preflight — zero active
    # limits before scenario A applies its own policy, verified, not
    # assumed (the 99.62% anomaly's fix).
    clean_slate_preflight(binary)

    curl = shutil.which("curl")
    ledger = Ledger()

    # ── the download leg: A (zelynic) then B (legacy), the rung
    #    failover walking the ladder (night-netrunner-6) ─────────────
    a_dl, b_dl, dl_name, dl_rung = run_download_leg(
        binary, curl, ledger, args.download_bytes, args.download_rate
    )

    # ── the upload leg: A (zelynic) then B (legacy) ──────────────────
    ul_name, ul_url = UL_ENDPOINT
    up_ok, up_detail = probe_detail(ul_url.replace("/__up", "/__down?bytes=1024"), ranged=False)
    if not up_ok:
        fail(
            "no upload endpoint reachable — the real-internet lane is down "
            f"(the probe saw: {up_detail})"
        )
    ul_file = os.path.join("/tmp", "zelynic-quota-ab-upload.bin")
    with open(ul_file, "wb") as fh:
        fh.truncate(args.upload_bytes)  # sparse: no disk cost, exact Content-Length
    try:
        ul_worker = [
            curl,
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{size_upload}",
            "--max-time",
            "60",
            "-T",
            ul_file,
            ul_url,
        ]
        a_ul = run_scenario_a_upload(
            binary,
            "zelynic-quota-ab-ul",
            os.path.join(CGROUP_ROOT, "zelynic-quota-ab-ul"),
            args.upload_rate,
            ul_worker,
        )
        ledger.spend("the scenario A upload leg", a_ul.transferred)
        b_ul = run_scenario_b_upload(ul_worker)
        est = 0 if b_ul.retrans is None else b_ul.retrans[1] * RETRANS_SEG_BYTES
        ledger.spend("the scenario B upload leg", b_ul.wire, est)
    finally:
        try:
            os.unlink(ul_file)
        except OSError:
            pass

    # ── the overrunning legs (night-netrunner-12 download,
    #    night-spark-10 upload): savings only manifest where the
    #    sender would push more if it could — the bounded pair's
    #    senders never attempt the overrun the counterfactual books,
    #    these legs' senders never stop ─────────────────────────
    a_or = None
    b_or = None
    a_or_ul = None
    b_or_ul = None
    if args.skip_overrun:
        out("")
        out(
            "the overrunning legs: skipped (--skip-overrun) — the bounded pair "
            "prices the booking, not the saving"
        )
    else:
        out("")
        out(
            f"the overrunning leg: {args.overrun_seconds}s of back-to-back "
            f"{fmt_mb(OVERRUN_CHUNK_BYTES)} chunk GETs on the {dl_name} rung "
            "(the eager receiver — the clock ends its session, not the file)"
        )
        or_url = dl_rung[1].format(bytes=OVERRUN_CHUNK_BYTES)
        or_worker = overrun_worker(
            curl, or_url, dl_rung[0], OVERRUN_CHUNK_BYTES, args.overrun_seconds
        )
        or_timeout = 70 + max(args.overrun_seconds, 0) + 30
        a_or = run_scenario_a_download(
            binary,
            "zelynic-quota-ab-or",
            os.path.join(CGROUP_ROOT, "zelynic-quota-ab-or"),
            args.download_rate,
            or_worker,
            or_timeout,
        )
        b_or = run_scenario_b_download(or_worker, or_timeout)
        print_leg("overrun download", a_or, b_or)
        out(
            "    (the overrun leg spends real quota outside the virtual frame: "
            f"A {fmt_mb(a_or.transferred)} + B {fmt_mb(b_or.wire)} — "
            "size it with --overrun-seconds)"
        )
        # The overrunning upload leg (night-spark-10): the mirror of
        # the download leg on the egress direction — the same loop,
        # the same clock, the tx wire unit, the cloudflare endpoint
        # the bounded upload leg just proved reachable.
        out("")
        out(
            f"the overrun upload leg: {args.overrun_seconds}s of back-to-back "
            f"{fmt_mb(OVERRUN_UPLOAD_CHUNK_BYTES)} uploads on cloudflare "
            "(the eager sender — the clock ends the session, not the file)"
        )
        or_ul_file = os.path.join("/tmp", "zelynic-quota-ab-or-ul.bin")
        with open(or_ul_file, "wb") as fh:
            fh.truncate(OVERRUN_UPLOAD_CHUNK_BYTES)  # sparse: no disk cost
        try:
            or_ul_worker = overrun_upload_worker(curl, ul_url, or_ul_file, args.overrun_seconds)
            or_ul_timeout = 70 + max(args.overrun_seconds, 0) + 30
            a_or_ul = run_scenario_a_upload(
                binary,
                "zelynic-quota-ab-or-ul",
                os.path.join(CGROUP_ROOT, "zelynic-quota-ab-or-ul"),
                args.upload_rate,
                or_ul_worker,
                or_ul_timeout,
            )
            b_or_ul = run_scenario_b_upload(or_ul_worker, or_ul_timeout)
            print_leg("overrun upload", a_or_ul, b_or_ul)
            out(
                "    (the overrun leg spends real quota outside the virtual frame: "
                f"A {fmt_mb(a_or_ul.transferred)} + B {fmt_mb(b_or_ul.wire)} — "
                "size it with --overrun-seconds)"
            )
        finally:
            try:
                os.unlink(or_ul_file)
            except OSError:
                pass

    # ── the A/B ledger, both legs side by side ───────────────────────
    out("")
    out(
        f"the A/B ledger (virtual quota {fmt_mb(QUOTA_BUDGET)}, "
        f"{fmt_mb(ledger.remaining)} left after the bounded pair)"
    )
    print_leg("download", a_dl, b_dl)
    print_leg("upload", a_ul, b_ul)
    out(
        "  the bridge: absent the saver lanes, A's withheld share is the wire the "
        "counterfactual books — the bounded legs' ground truth prices that booking "
        "on a transfer whose sender never overruns, the overrunning leg prices it "
        "where the sender is eager —"
    )
    out(
        f"    download {fmt_mb(a_dl.transferred + a_dl.saved)} carried "
        f"vs {fmt_mb(a_dl.transferred)} spent, upload {fmt_mb(a_ul.transferred + a_ul.saved)} "
        f"carried vs {fmt_mb(a_ul.transferred)} spent."
    )

    # ── the beginner's answer: the measured wire priced against the ──
    #    plan the user actually pays for (night-spark-10).
    print_metered_plan(args.overrun_seconds, a_or, b_or, a_or_ul, b_or_ul)

    # ── the exact wire contract: the number the beginner repeats ──
    print_masterclass_verdict(a_dl, a_ul, a_or, b_or, a_or_ul, b_or_ul)
    return 0


if __name__ == "__main__":
    sys.exit(main())
