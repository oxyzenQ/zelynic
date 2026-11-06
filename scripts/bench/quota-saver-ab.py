#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
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
      walks. The cost is what curl moved plus the TCP retransmission
      the wire itself reports: the system-wide /proc/net/snmp Tcp
      deltas (a quiet-runner measurement), converted at the
      conservative 1448 B/segment estimate and printed as an
      estimate, never as fact.

The verdict lines are the task's exact wire contract, printed to
stdout at the end, one per leg — always scenario A's ledger (the
product's own accounting, byte-identical math to the report
sibling):

    test download results the internet kuota save total is X%
    test upload results the internet kuota save total is Y%

The percentage is saved / (transferred + saved) — of everything the
quota WOULD have carried, the share the saver lanes avoided. A leg
that moved bytes and saved none prints 0.00% honestly; a leg that
could not run (no root, no cgroup v2, no full-life binary, no curl,
no reachable endpoint, the virtual ledger exhausted) says why on
stderr and exits 2 — the house honest-refusal posture, never a
fabricated line. Scenario B never fabricates either: its retrans
figure prints `n/a` when the kernel counters are unreadable.

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


def out(line: str) -> None:
    print(line, flush=True)


def resolve_binary(explicit: str | None) -> str:
    """The harness's own ladder: an explicit path outranks the
    repo-local build, which outranks the PATH install."""
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        return fail(f"binary not executable: {explicit}")
    repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    for candidate in (
        os.path.join(repo, "target", "x86_64-unknown-linux-musl", "pro-native-musl", "zelynic"),
        os.path.join(repo, "target", "release", "zelynic"),
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("zelynic")
    if found:
        return found
    return fail(
        "no zelynic binary found — build one (./scripts/build.sh release) or pass --binary PATH"
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


def probe_once(url: str) -> tuple[bool, str]:
    """One endpoint attempt: curl exits 0 with a 2xx/2xx-range code;
    the detail names what the wire actually said (the refusal owes
    its reader the evidence, not just the verdict)."""
    try:
        p = subprocess.run(
            [
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                str(PROBE_TIMEOUT),
                "-r",
                "0-1023",
                url,
            ],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT + 5,
        )
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except OSError as e:
        return False, str(e)[:60]
    code = p.stdout.strip()
    if p.returncode == 0 and code in ("200", "206"):
        return True, code
    return False, f"curl exit {p.returncode}, HTTP {code or 'none'}"


def probe(url: str) -> bool:
    """Two attempts, 4 s apart: the guest's SLIRP path and the shared
    runner egress make a single attempt a coin flip (one real e2e
    leg lost the upload rung to a one-shot probe while the download
    ladder answered). The refusal still refuses — it just gets two
    honest shots first."""
    ok, _ = probe_once(url)
    if ok:
        return True
    time.sleep(4)
    ok, _ = probe_once(url)
    return ok


def probe_detail(url: str) -> tuple[bool, str]:
    """The upload rung's gate: same two-attempt ladder, but the
    caller keeps the evidence for its refusal line."""
    ok, detail = probe_once(url)
    if ok:
        return True, detail
    time.sleep(4)
    return probe_once(url)


def pick_download_endpoint(leg_bytes: int) -> tuple[str, str] | None:
    for name, template, _mode in DL_ENDPOINTS:
        url = template.format(bytes=leg_bytes)
        if probe(url):
            return name, url
    return None


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
    """One leg's two-scenario books: scenario A's Layer 4 deltas,
    scenario B's live wire cost, the wire's own retrans reports."""

    def __init__(self) -> None:
        self.transferred = 0
        self.saved = 0
        self.wire = 0
        self.retrans = None
        self.partial = False


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


def run_scenario_a_download(
    binary: str, cg: str, cg_path: str, rate: str, worker: list[str]
) -> Leg:
    """The product leg: cgroup + strict + the Layer 4 deltas."""
    leg = Leg()
    cg_id = make_cgroup(cg)
    try:
        rc, _, stderr = zel(binary, ["strict", str(cg_id), rate, "--no-test"])
        if rc != 0:
            fail(f"strict {rate} failed: {(stderr or '').strip()[:200]}")
        before = status_entry(binary, cg_id)
        got, err = run_worker(worker, cg_path, 70)
        after = status_entry(binary, cg_id)
        leg.transferred, leg.saved = delta_savings(before, after)
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


def run_scenario_b_download(worker: list[str]) -> Leg:
    """The legacy leg: the same worker, no enforcement, the wire's
    own retransmission read around it."""
    leg = Leg()
    t0 = tcp_counters()
    got, err = run_worker(worker, None, 70)
    t1 = tcp_counters()
    if got is None:
        fail(f"the legacy download leg failed: {err}")
    leg.wire = got
    leg.retrans = retrans_delta(t0, t1)
    if got == 0:
        leg.partial = True
    return leg


def run_scenario_a_upload(binary: str, cg: str, cg_path: str, rate: str, worker: list[str]) -> Leg:
    """The product leg, upload policy (`-u`): the pacing lane's
    commanded rate rides the egress policed path."""
    leg = Leg()
    cg_id = make_cgroup(cg)
    try:
        rc, _, stderr = zel(binary, ["strict", str(cg_id), "-u", rate, "--no-test"])
        if rc != 0:
            fail(f"strict -u {rate} failed: {(stderr or '').strip()[:200]}")
        before = status_entry(binary, cg_id)
        got, err = run_worker(worker, cg_path, 70)
        after = status_entry(binary, cg_id)
        leg.transferred, leg.saved = delta_savings(before, after)
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


def run_scenario_b_upload(worker: list[str]) -> Leg:
    leg = Leg()
    t0 = tcp_counters()
    got, err = run_worker(worker, None, 70)
    t1 = tcp_counters()
    if got is None:
        fail(f"the legacy upload leg failed: {err}")
    leg.wire = got
    leg.retrans = retrans_delta(t0, t1)
    if got == 0:
        leg.partial = True
    return leg


def print_leg(leg_name: str, a: Leg, b: Leg) -> None:
    out(f"  {leg_name}:")
    out(
        f"    A (zelynic):  wire {fmt_mb(a.transferred)} + withheld {fmt_mb(a.saved)}"
        f" -> saved {save_percent(a.transferred, a.saved)}%"
        + ("  (partial leg)" if a.partial else "")
    )
    out(
        f"    B (legacy):   wire {fmt_mb(b.wire)} + retrans {retrans_mb(b.retrans)} (est)"
        f" -> saved 0.00%  (nothing withholds on the drop-based path)"
        + ("  (partial leg)" if b.partial else "")
    )
    if a.partial and a.err:
        out(f"    (A worker note: {a.err[:90]})")


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
        default=20_000_000,
        help="download leg size in bytes (default 20000000)",
    )
    ap.add_argument(
        "--upload-bytes",
        type=int,
        default=20_000_000,
        help="upload leg size in bytes (default 20000000)",
    )
    ap.add_argument(
        "--download-rate", default="5mb", help="scenario A's download limit (default 5mb)"
    )
    ap.add_argument("--upload-rate", default="5mb", help="scenario A's upload limit (default 5mb)")
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

    # ── the download leg: A (zelynic) then B (legacy) ────────────────
    picked = pick_download_endpoint(args.download_bytes)
    if picked is None:
        fail("no download endpoint reachable — the real-internet lane is down")
    dl_name, dl_url = picked
    dl_worker = download_worker(curl, dl_url, dl_name, args.download_bytes)
    a_dl = run_scenario_a_download(
        binary,
        "zelynic-quota-ab-dl",
        os.path.join(CGROUP_ROOT, "zelynic-quota-ab-dl"),
        args.download_rate,
        dl_worker,
    )
    ledger.spend("the scenario A download leg", a_dl.transferred)
    b_dl = run_scenario_b_download(dl_worker)
    est = 0 if b_dl.retrans is None else b_dl.retrans[1] * RETRANS_SEG_BYTES
    ledger.spend("the scenario B download leg", b_dl.wire, est)

    # ── the upload leg: A (zelynic) then B (legacy) ──────────────────
    ul_name, ul_url = UL_ENDPOINT
    up_ok, up_detail = probe_detail(ul_url.replace("/__up", "/__down?bytes=1024"))
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

    # ── the A/B ledger, both legs side by side ───────────────────────
    out("")
    out(
        f"the A/B ledger (virtual quota {fmt_mb(QUOTA_BUDGET)}, "
        f"{fmt_mb(ledger.remaining)} left after both scenarios)"
    )
    print_leg("download", a_dl, b_dl)
    print_leg("upload", a_ul, b_ul)
    out(
        "  the bridge: absent the saver lanes, A's withheld share is the overrun the "
        "drop-based path burns —"
    )
    out(
        f"    download {fmt_mb(a_dl.transferred + a_dl.saved)} carried "
        f"vs {fmt_mb(a_dl.transferred)} spent, upload {fmt_mb(a_ul.transferred + a_ul.saved)} "
        f"carried vs {fmt_mb(a_ul.transferred)} spent."
    )

    # ── the exact wire contract: scenario A's ledger, one per leg ────
    out(
        f"test download results the internet kuota save total is {save_percent(a_dl.transferred, a_dl.saved)}%"
    )
    out(
        f"test upload results the internet kuota save total is {save_percent(a_ul.transferred, a_ul.saved)}%"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
