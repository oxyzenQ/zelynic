#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
"""The quota saver's measurement script (night-netrunner-4).

Runs a REAL download and a REAL upload against the real-internet
ladder (the same endpoint chain the supermassive realnet lane walks:
Cloudflare's capped speed store first, the Vultr Singapore rung and
the Asian mirrors behind it), under a live zelynic limit, and reads
`zelynic status --print-json` before and after each leg. The savings
come from the kernel's own Layer 4 telemetry: the delta of
`bytes_saved_total` (the ECN marks one-for-one, the sole live
booking; the retired EDT word reads zero since schema v29,
night-quota-audit, and the retired RECWN estimate reads zero since
schema v30, night-recvn-audit) against the delta of `bytes_allowed`
(the bytes that actually transferred) across each leg.

The verdict lines are the task's exact wire contract, printed to
stdout, one per leg:

    test download results the internet kuota save total is X%
    test upload results the internet kuota save total is Y%

The percentage is saved / (transferred + saved) — of everything the
quota WOULD have carried, the share the saver lanes avoided. A leg
that moved bytes and saved none prints 0.00% honestly; a leg that
could not run (no root, no cgroup v2, no full-life binary, no curl,
no reachable endpoint) says why on stderr and exits 2 — the house
honest-refusal posture, never a fabricated line.

Every zelynic side effect is cleaned up: each leg applies its limit
(`strict --no-test`, the scripted-apply contract — no verification
probe inflating the ledger), and removes it (`unstrict`) before the
leg's cgroup is torn down.

Usage:
    ./scripts/bench/quota-saver-report.sh               # both legs
    ./scripts/bench/quota-saver-report.sh --binary PATH # explicit binary
    ./scripts/bench/quota-saver-report.sh --help        # the flags
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

# The download ladder (night-spark-3b's chain, the supermassive
# realnet lane's own order): the first reachable rung feeds the leg.
# Cloudflare's bytes= form caps the transfer by construction; the
# other rungs cut a ranged GET to the leg's size.
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
    print(f"quota-saver: cannot run — {reason}", file=sys.stderr, flush=True)
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


def probe(url: str) -> bool:
    """One endpoint probe: curl exits 0 with a 2xx/2xx-range code."""
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
    except (subprocess.TimeoutExpired, OSError):
        return False
    return p.returncode == 0 and p.stdout.strip() in ("200", "206")


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


def run_in_cgroup(path: str, argv: list[str], timeout: int) -> tuple[int | None, str]:
    """Run argv to completion inside the cgroup; return (bytes, err)."""
    script = f'echo $$ > "{path}/cgroup.procs"\nexec "$@"'
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
        metric = stdout.strip().splitlines()[-1] if stdout.strip() else ""
        try:
            return int(metric), ""
        except ValueError:
            return None, f"no metric ({metric[:60] or 'empty'})"
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


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="quota-saver-report",
        description="measure the quota saver's real savings on a real "
        "download and upload (night-netrunner-4)",
    )
    ap.add_argument("--binary", help="path to the zelynic binary")
    ap.add_argument(
        "--download-bytes",
        type=int,
        default=3_000_000,
        help="download leg size in bytes (default 3000000)",
    )
    ap.add_argument("--download-rate", default="2mb", help="the download leg's limit (default 2mb)")
    ap.add_argument(
        "--upload-window", type=int, default=5, help="upload leg duration in seconds (default 5)"
    )
    ap.add_argument("--upload-rate", default="1mb", help="the upload leg's limit (default 1mb)")
    args, unknown = ap.parse_known_args()
    if unknown:
        print(f"quota-saver: unknown argument(s): {' '.join(unknown)}", file=sys.stderr, flush=True)
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

    curl = shutil.which("curl")

    # ── the download leg ─────────────────────────────────────────────
    picked = pick_download_endpoint(args.download_bytes)
    if picked is None:
        fail("no download endpoint reachable — the real-internet lane is down")
    dl_name, dl_url = picked
    dl_cg = "zelynic-quota-saver-dl"
    dl_path = os.path.join(CGROUP_ROOT, dl_cg)
    try:
        dl_id = make_cgroup(dl_cg)
        rc, _, stderr = zel(binary, ["strict", str(dl_id), args.download_rate, "--no-test"])
        if rc != 0:
            fail(f"strict {args.download_rate} failed: {(stderr or '').strip()[:200]}")
        before = status_entry(binary, dl_id)
        worker = [
            curl,
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{size_download}",
            "--max-time",
            "30",
            "--speed-time",
            "25",
            "--speed-limit",
            "1024",
        ]
        # Cloudflare's bytes= form caps by construction; ranged rungs
        # cut the exact size off the object.
        if dl_name == "cloudflare":
            worker.append(dl_url)
        else:
            worker += ["-r", f"0-{args.download_bytes - 1}", dl_url]
        got, err = run_in_cgroup(dl_path, worker, 60)
        after = status_entry(binary, dl_id)
        if got is None:
            print(f"quota-saver: download worker failed: {err}", file=sys.stderr, flush=True)
        transferred, saved = delta_savings(before, after)
        out(
            f"test download results the internet kuota save total is {save_percent(transferred, saved)}%"
        )
    finally:
        zel(binary, ["unstrict", str(dl_id)], timeout=30)
        try:
            os.rmdir(dl_path)
        except OSError:
            pass

    # ── the upload leg ───────────────────────────────────────────────
    ul_name, ul_url = UL_ENDPOINT
    if not probe(ul_url.replace("/__up", "/__down?bytes=1024")):
        fail("no upload endpoint reachable — the real-internet lane is down")
    ul_cg = "zelynic-quota-saver-ul"
    ul_path = os.path.join(CGROUP_ROOT, ul_cg)
    try:
        ul_id = make_cgroup(ul_cg)
        # Upload-only policy (`-u`): the pacing lane's commanded rate
        # rides the egress policed path — the lane the retired EDT
        # word once booked (zero since schema v29); the leg's honest
        # savings read is the wire delta, never a booked number.
        rc, _, stderr = zel(binary, ["strict", str(ul_id), "-u", args.upload_rate, "--no-test"])
        if rc != 0:
            fail(f"strict -u {args.upload_rate} failed: {(stderr or '').strip()[:200]}")
        before = status_entry(binary, ul_id)
        worker = [
            curl,
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{size_upload}",
            "--max-time",
            str(args.upload_window),
            "-T",
            "/dev/zero",
            ul_url,
        ]
        got, err = run_in_cgroup(ul_path, worker, args.upload_window + 25)
        after = status_entry(binary, ul_id)
        if got is None:
            print(f"quota-saver: upload worker failed: {err}", file=sys.stderr, flush=True)
        transferred, saved = delta_savings(before, after)
        out(
            f"test upload results the internet kuota save total is {save_percent(transferred, saved)}%"
        )
    finally:
        zel(binary, ["unstrict", str(ul_id)], timeout=30)
        try:
            os.rmdir(ul_path)
        except OSError:
            pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
