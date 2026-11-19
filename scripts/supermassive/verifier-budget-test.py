#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.

"""verifier-budget-test.py — the verifier budget ledger's census and gate
(night-frontier-Z9).

The hole: the ledger records "the enforcer's budget is FULL" as prose, and
the only verifier-cost number in the tree is a failure story ("Processed
1000001 insn", the mirror's census refusal). Nothing pins what the verifier
actually charges for the six programs the estate ships, so a change to the
verdict path can eat the floor kernel's headroom silently — the one LTS
failure class that arrives without any code misbehaving on the machine
that measures it.

The instrument: the battery loads BOTH objects on the kernel it booted (a
real strict apply for the limiter's four programs, a live eagle-eyes
monitor session for the observer's two), and prices every estate program
with the kernel's own channels — no display tool's mercy: the walk runs
the bpf() syscall itself, and the price is verified_insns (UAPI
aba64c7da983, 2021-10-21 — "bpf: Add verified_insns to bpf_prog_info and
fdinfo"), read from the program fd's /proc fdinfo. The first live runs'
lessons, recorded honestly: the FIELD is kernel UAPI, the DISPLAY tool
only grew it in Oct 2026 (the guest's staged bpftool never printed the
number); the cgroup id is the kernfs inode (NIGHT-hunt-31 — no cgroup.id
file exists in any mainline kernel); and the kernel-side program NAME is
not an identity the estate can lean on (aya stamps prog_name only when its
BpfName feature probe passes — the live census saw empty names). The
identity channel that cannot lie is the estate's own pin layer and the
link metadata the kernel itself keeps.

Identity map (v2):
  * the limiter's four programs — the loader's own pinned files
    (/sys/fs/bpf/zelynic/<program>): BPF_OBJ_GET on the pin file returns
    THE program's fd; the pin file name is the loader's own program name;
    bpf_prog_info.id confirms the kernel-side identity;
  * the observer's two programs — session-scoped by design (the lazy
    camera pins nothing), alive only while a monitor session runs: the
    battery spawns the live eagle-eyes monitor on a pty (the v2
    battery's proven shape), and the census walks the kernel's link
    table — the two live cgroup links whose attach types are
    BPF_CGROUP_INET_INGRESS / BPF_CGROUP_INET_EGRESS and whose programs
    are NOT the pinned limiter set are the observer's ingress/egress
    pair, exactly the identity the kernel keeps for the attach itself.

The objects are byte-identical by construction (the parity gates), so for
one kernel the number is deterministic: the budget pins the verifier walk,
not a sample of it. The availability boundary is physics, not a gap: the
field landed in the v5.16 merge window — the 5.15 floor kernel does not
expose it, so the floor envelope prices by inventory (the load-proof IS
the floor's gate) and the head envelope prices by verified_insns.

The laws (each enforced here, validated rootlessly by --self-test):
  * the completeness law — every program the estate loads carries a row in
    the ledger (scripts/supermassive/verifier-budget-ledger.json), in both
    envelopes; a loaded program without a row fails on every run, census
    mode included. The inventory gate arms at landing; only the budget
    comparison can defer.
  * the growth law — a measured value above the pinned budget fails the
    battery; raising a budget requires the raising commit to name the new
    number and the reason in the row's history.
  * the ratchet law — a measured value below the budget never fails; it
    prints the headroom, and lowering the pin to the measured number is
    the encouraged follow-up.
  * the census law — a null budget is census debt, named honestly: the
    measured number prints (MASS-CENSUS rows) and the comparison stays
    deferred while the ledger's armed flag is false. The arming commit
    pins the numbers from a watched CI run and flips armed:true in the
    same change; armed true with any null budget is an invalid ledger.
  * the availability law — the verified_insns field is kernel UAPI since
    the v5.16 merge window; the 5.15 floor kernel does not expose it. The
    floor envelope is therefore an inventory envelope: its rows stay null
    forever (pinning one would be fabrication), its gate is the load-proof
    (every estate program seen = the objects still load on the floor), and
    the census names the absence instead of pretending. The head envelope
    prices by verified_insns.

Usage:
  sudo ./scripts/supermassive/verifier-budget-test.sh --binary /opt/zelynic/zelynic
  ./scripts/supermassive/verifier-budget-test.py --self-test   # rootless ledger audit
  sudo python3 verifier-budget-test.py --envelope floor        # override the derivation

Root/eBPF IS required for the census (the programs must be loaded for the
kernel to price them); --self-test needs none of it.
"""

import argparse
import ctypes
import fcntl
import json
import os
import platform
import pty
import re
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
LEDGER_PATH = SCRIPT_DIR / "verifier-budget-ledger.json"

# The estate's programs, in dependency order: the limiter object's four
# (the two enforcement hooks, the RECWN sock_ops lane, the pacing sock_ops
# lane) then the observer object's two. The names are the loader's own
# lookup names (src/ebpf/limiter/mod.rs, src/ebpf/pace.rs, src/ebpf/loader.rs)
# — the same literals the byte-layout theorem family pins beside their source.
PROGRAMS = [
    "enforce_dl",
    "enforce_ul",
    "zelynic_recwn",
    "zelynic_pace",
    "observe_egress",
    "observe_ingress",
]
ENVELOPES = ("floor", "head")
HISTORY_KINDS = ("pin", "raise", "lower")

CGROUP_ROOT = Path("/sys/fs/cgroup")
TEST_CGROUP = CGROUP_ROOT / "zelynic-verifier-budget"
APPLY_RATE = "1mb"

# The loader's own pinned program files (src/ebpf/pin.rs): the pin file
# name IS the loader's program name, and BPF_OBJ_GET on the file returns
# THE program's fd — the identity channel that cannot lie about which
# program is which.
LIM_PIN_PROGS = {
    "enforce_dl": "/sys/fs/bpf/zelynic/enforce_dl",
    "enforce_ul": "/sys/fs/bpf/zelynic/enforce_ul",
    "zelynic_recwn": "/sys/fs/bpf/zelynic/zelynic_recwn",
    "zelynic_pace": "/sys/fs/bpf/zelynic/zelynic_pace",
}

BPFTOOL_PATH = "/usr/bin/bpftool"

# The bpf() UAPI walk (the kernel's own channels, no display tool): the
# syscall numbers are the stable per-arch assignments, and every cmd code
# and struct offset below is read from include/uapi/linux/bpf.h (the
# frozen UAPI) — bpf_cmd from the enum's own order, bpf_prog_info's early
# fields (id at 4, name at 56) fixed since the struct's birth, bpf_link_info
# (type at 0, prog_id at 8, cgroup.attach_type at 24) from the 6.x header
# whose layout the 5.15 floor shares for these early words. bpf_attach_type:
# BPF_CGROUP_INET_INGRESS = 0, BPF_CGROUP_INET_EGRESS = 1.
BPF_SYSCALL_NR = {"x86_64": 321, "aarch64": 280}
BPF_PROG_GET_FD_BY_ID = 14
ATTR_SIZE = 128


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")
    # The annotation channel: the battery runs inside the micro-VM, its
    # stdout reaches the runner through the boot step's tee, and the
    # ::error:: workflow commands become check-run annotations - the
    # failure lines land where the API can read them without shell
    # access to the runner (the same convention reproducible.yml's
    # verdict lanes use).
    print(f"::error::{msg}")


def info(msg: str) -> None:
    print(f"Z9: {msg}")


def notice(msg: str) -> None:
    print(f"Z9: {msg}")
    print(f"::notice::{msg}")


def load_ledger(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        fail(f"the ledger at {path} cannot be read or parsed: {e}")
        sys.exit(2)
    if not isinstance(raw, dict):
        fail(f"the ledger at {path} is not a JSON object")
        sys.exit(2)
    return raw


def _validate_row(row: dict, where: str) -> list:
    errors = []
    if not isinstance(row, dict):
        return [f"{where}: row is not an object"]
    budget = row.get("budget")
    if budget is not None and (isinstance(budget, bool) or not isinstance(budget, int)):
        errors.append(f"{where}: budget must be null or a positive int, got {budget!r}")
    elif isinstance(budget, int) and budget <= 0:
        errors.append(f"{where}: budget must be positive, got {budget}")
    history = row.get("history")
    if not isinstance(history, list):
        return errors + [f"{where}: history must be a list"]
    previous = None
    for i, entry in enumerate(history):
        tag = f"{where}: history[{i}]"
        if not isinstance(entry, dict):
            errors.append(f"{tag} is not an object")
            continue
        kind = entry.get("kind")
        if kind not in HISTORY_KINDS:
            errors.append(f"{tag}: kind must be one of {HISTORY_KINDS}, got {kind!r}")
        value = entry.get("value")
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            errors.append(f"{tag}: value must be a positive int, got {value!r}")
        if not isinstance(entry.get("source"), str) or not entry.get("source"):
            errors.append(f"{tag}: source (the run or commit that measured) is required")
        if not isinstance(entry.get("reason"), str) or not entry.get("reason"):
            errors.append(f"{tag}: reason (why the pin moved) is required")
        if isinstance(previous, int) and isinstance(value, int) and value == previous:
            errors.append(f"{tag}: {kind} entry repeats the previous value {previous}")
        if kind == "pin" and i != 0:
            errors.append(f"{tag}: a second pin entry — one pin opens the chain")
        previous = value
    if history:
        first = history[0]
        if isinstance(first, dict) and first.get("kind") != "pin":
            errors.append(f"{where}: history must open with a pin entry")
        last = history[-1]
        if isinstance(last, dict) and isinstance(last.get("value"), int):
            if budget != last["value"]:
                errors.append(
                    f"{where}: budget {budget} does not match the last history value "
                    f"{last['value']} — the chain and the pin must agree"
                )
    elif budget is not None:
        errors.append(
            f"{where}: a pinned budget without a history entry is untraceable growth "
            "— the pin lands with the row that names it"
        )
    return errors


def validate_ledger(ledger: dict) -> list:
    """The rootless audit — every law the file itself must hold, nameable
    without a kernel. Returns the error list (empty = the ledger holds)."""
    errors = []
    if ledger.get("schema") != 1:
        errors.append(f"schema must be 1, got {ledger.get('schema')!r}")
    if not isinstance(ledger.get("armed"), bool):
        errors.append(f"armed must be a bool, got {ledger.get('armed')!r}")
    programs = ledger.get("programs")
    if programs != PROGRAMS:
        errors.append(f"programs must be {PROGRAMS}, got {programs!r}")
    envelopes = ledger.get("envelopes")
    if not isinstance(envelopes, dict) or set(envelopes) != set(ENVELOPES):
        errors.append(f"envelopes must be exactly {list(ENVELOPES)}, got {envelopes!r}")
        return errors
    for env_name, env in envelopes.items():
        if not isinstance(env, dict) or not isinstance(env.get("kernel_class"), str):
            errors.append(f"envelope {env_name}: kernel_class text is required")
        pricing = env.get("pricing") if isinstance(env, dict) else None
        if pricing not in ("verified_insns", "inventory"):
            errors.append(
                f"envelope {env_name}: pricing must be 'verified_insns' or "
                f"'inventory', got {pricing!r}"
            )
        rows = env.get("rows") if isinstance(env, dict) else None
        if not isinstance(rows, dict):
            errors.append(f"envelope {env_name}: rows object is required")
            continue
        if set(rows) != set(PROGRAMS):
            errors.append(
                f"envelope {env_name}: rows must cover exactly the program set, got {sorted(rows)}"
            )
            continue
        for prog, row in rows.items():
            errors.extend(_validate_row(row, f"envelope {env_name} row {prog}"))
        if pricing == "inventory":
            for prog, row in rows.items():
                if isinstance(row, dict) and (row.get("budget") is not None or row.get("history")):
                    errors.append(
                        f"envelope {env_name} row {prog}: an inventory "
                        "envelope cannot price — a pinned budget there "
                        "would be fabrication (the verified_insns field "
                        "does not exist on its kernel class)"
                    )
    if ledger.get("armed") is True:
        for env_name, env in envelopes.items():
            if not isinstance(env, dict) or env.get("pricing") != "verified_insns":
                continue
            rows = env.get("rows", {}) if isinstance(env, dict) else {}
            for prog, row in rows.items():
                if isinstance(row, dict) and row.get("budget") is None:
                    errors.append(
                        f"envelope {env_name} row {prog}: armed true with a null "
                        "budget is a half-armed ledger — pin the number first"
                    )
    return errors


def derive_envelope(release: str) -> str:
    """The envelope the battery is running on, derived from the kernel
    release itself — the floor contract is the 5.15.0-ABI line, everything
    else is the dynamically resolved head."""
    if release.startswith("5.15."):
        return "floor"
    return "head"


def slim_env() -> dict:
    """The stripped environment the report surfaces must answer under
    (the server-phase shape): PATH and TERM=dumb, nothing else."""
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "TERM": "dumb"}


def run_cmd(args: list, timeout: int = 60) -> tuple:
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            env=slim_env(),
        )
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, OSError) as e:
        return -1, "", str(e)


def _bpf(cmd: int, attr: bytes) -> tuple:
    """One bpf() syscall: (return value, the 128-byte attr tail the
    kernel may have written back). The syscall numbers are the stable
    per-arch assignments; anything else refuses instead of guessing."""
    nr = BPF_SYSCALL_NR.get(platform.machine())
    if nr is None:
        raise OSError(f"no bpf syscall number pinned for {platform.machine()}")
    libc = ctypes.CDLL(None, use_errno=True)
    buf = ctypes.create_string_buffer(ATTR_SIZE)
    ctypes.memmove(buf, attr, len(attr))
    rc = libc.syscall(ctypes.c_long(nr), ctypes.c_int(cmd), buf, ctypes.c_int(ATTR_SIZE))
    if rc < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return rc, buf.raw


def prog_fd_by_id(prog_id: int) -> int:
    """BPF_PROG_GET_FD_BY_ID — the fd itself is the syscall's return."""
    rc, _ = _bpf(BPF_PROG_GET_FD_BY_ID, struct.pack("<I", prog_id))
    return int(rc)


def fdinfo_verified_insns(fd: int):
    """The price channel: the program fd's /proc fdinfo line the kernel
    has written since aba64c7da983. None = the field does not exist on
    this kernel (the 5.15 floor — the availability law's physics)."""
    try:
        with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as f:
            for line in f:
                m = re.match(r"^verified_insns:\s*(\d+)\s*$", line)
                if m:
                    return int(m.group(1))
    except OSError:
        return None
    return None


def bpftool_prog_id(pin_path: str) -> tuple:
    """The pinned program's kernel id, read by the staged bpftool through
    the documented positional form (`bpftool prog show <pin>`). The v3
    lesson: the keyword-spelled `prog show file <pin>` refused rc=255 on
    the staged tool while the positional shape is the form the tool's
    own manpage documents and the survival battery's invocations
    resemble. Tries the JSON form, falls back to the plain text the
    claims harness's tool snapshots parse. Returns (id, tool_output)."""
    bpftool = shutil.which("bpftool") or BPFTOOL_PATH
    rc, out, err = run_cmd([bpftool, "-j", "prog", "show", pin_path], timeout=60)
    if rc == 0 and out.strip():
        try:
            rows = json.loads(out)
            if isinstance(rows, dict):
                rows = [rows]
            prog_id = rows[0].get("id") if rows else None
            if prog_id is not None:
                return prog_id, out.strip()[:200]
        except ValueError:
            pass
    rc, out, err = run_cmd([bpftool, "prog", "show", pin_path], timeout=60)
    if rc != 0:
        return None, f"rc={rc} out={out.strip()[:120]} err={err.strip()[:120]}"
    m = re.search(r"([0-9]+):\s+\w+", out)
    pid = None
    if m:
        pid = int(m.group(1))
    else:
        m2 = re.search(r"prog_id\s+(\d+)|id\s+(\d+)", out)
        pid = int(m2.group(1) or m2.group(2)) if m2 else None
    return pid, out.strip()[:200]


def bpftool_cgroup_attach_table() -> list:
    """The kernel's own attach table for the cgroup root, read by the
    staged bpftool (`cgroup show` - the exact invocation the claims
    battery proves on every survival leg). Returns
    [(attach_type_text, prog_id), ...] from the plain text rows."""
    bpftool = shutil.which("bpftool") or BPFTOOL_PATH
    rc, out, err = run_cmd([bpftool, "cgroup", "show", "/sys/fs/cgroup"], timeout=60)
    if rc != 0:
        notice(f"bpftool cgroup show refused rc={rc}: {err.strip()[:160]}")
        return []
    rows = []
    for line in out.splitlines():
        # <path>  <attach_type>  prog_id <id> [prog_name <name>] — the
        # parse rides the attach_type token and the prog_id number only.
        m = re.match(r"\S+\s+(\S+)\s+prog_id\s+(\d+)", line.strip())
        if m:
            rows.append((m.group(1), int(m.group(2))))
    return rows


def spawn_monitor_on_pty(binary: str, cgid: int) -> tuple:
    """The live eagle-eyes monitor on a fresh pseudo-terminal (the v2
    battery's proven shape: pty with a sane 80x24 geometry, stdin/out/
    err on the slave). The observer's programs live only while this
    session runs — the census prices them mid-flight."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    proc = subprocess.Popen(
        [binary, "eagle-eyes", f"cg:{cgid}"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
        env=slim_env(),
    )
    os.close(slave)
    return proc, master


def census_programs() -> dict:
    """Price every estate program through the kernel's own channels.

    The limiter's four come through their pinned files (the pin name is
    the loader's program name; BPF_OBJ_GET on the file is THE program).
    The observer's two come through the kernel's link table: with the
    live monitor session running, the two live cgroup links whose
    attach types are INET_INGRESS / INET_EGRESS and whose programs are
    NOT the pinned limiter set are the observer's pair. Returns
    name -> (fd, verified_insns-or-None); the caller closes fds."""
    census = {}
    pinned_ids = set()
    try:
        pin_listing = sorted(os.listdir("/sys/fs/bpf/zelynic"))
    except OSError as e:
        pin_listing = [f"unlistable: {e}"]
    notice(f"PIN-DIR /sys/fs/bpf/zelynic holds {pin_listing}")
    for prog, pin_path in LIM_PIN_PROGS.items():
        if not os.path.exists(pin_path):
            census[prog] = None
            continue
        pid, tool_out = bpftool_prog_id(pin_path)
        if pid is None:
            notice(f"CENSUS-PIN {prog} bpftool refused: {tool_out}")
            census[prog] = None
            continue
        pinned_ids.add(pid)
        fd = prog_fd_by_id(pid)
        price = fdinfo_verified_insns(fd)
        os.close(fd)
        census[prog] = price
        notice(f"CENSUS-PIN {prog} pin={pin_path} prog_id={pid} price={price!r}")
    return census, pinned_ids


def observer_pair(pinned_ids: set) -> dict:
    """The two live observer programs, identified from the kernel's own
    attach table: the cgroup-root ingress / egress rows whose prog ids
    are NOT the pinned limiter set are the observer's pair - the lazy
    camera pins nothing, so its attach rows exist only while the
    monitor session runs. Returns name -> prog_id (or the miss, named)."""
    result = {}
    table = bpftool_cgroup_attach_table()
    notice(f"CGROUP-ATTACH-TABLE {table}")
    for attach_text, prog_id in table:
        text = attach_text.lower()
        if prog_id in pinned_ids:
            continue
        if "ingress" in text and "observe_ingress" not in result:
            result["observe_ingress"] = prog_id
            notice(f"CENSUS-LINK observe_ingress prog_id={prog_id} (live ingress attach)")
        elif "egress" in text and "observe_egress" not in result:
            result["observe_egress"] = prog_id
            notice(f"CENSUS-LINK observe_egress prog_id={prog_id} (live egress attach)")
    return result


def setup_cgroup():
    """One dedicated bed with one live member: the target the strict apply
    polices and the liveness the monitor session wants."""
    TEST_CGROUP.mkdir(parents=True, exist_ok=True)
    member = subprocess.Popen(
        ["sleep", "300"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
    )
    with open(TEST_CGROUP / "cgroup.procs", "w", encoding="ascii") as f:
        f.write(str(member.pid))
    # The cgroup ID is the kernfs inode number — the same numbering
    # bpf_skb_cgroup_id() returns (kernfs publishes kn->id as st_ino).
    # No cgroup.id file exists in any mainline kernel (NIGHT-hunt-31 —
    # the trap the first live census run stepped into, the existing
    # harness's _read_id already knew); this mirrors zelynic's own
    # cgroup_id_from_path, truncated to the u32 the BPF maps key on.
    try:
        cgid = os.stat(TEST_CGROUP).st_ino & 0xFFFFFFFF
    except OSError as e:
        member.kill()
        member.wait()
        fail(f"the census cgroup's id is unresolvable: {e}")
        sys.exit(2)
    info(f"census bed ready: {TEST_CGROUP} (cgroup id {cgid}, member {member.pid})")
    return member, cgid


def teardown(member, cgid: int, binary: str, monitor=None) -> None:
    """The lane empties itself (best-effort hygiene, never a verdict —
    the guest is ephemeral, the host rerun deserves a clean slate)."""
    if monitor is not None:
        monitor.send_signal(signal.SIGKILL)
        monitor.wait()
    run_cmd([binary, "unstrict", str(cgid)], timeout=60)
    member.kill()
    member.wait()
    time.sleep(0.2)
    # Best-effort hygiene: a kernel-side straggler (the link teardown is
    # asynchronous to the CLI's exit) can hold the directory a moment.
    try:
        TEST_CGROUP.rmdir()
    except OSError:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="the verifier budget ledger's census and gate")
    parser.add_argument("--binary", default="/opt/zelynic/zelynic")
    parser.add_argument("--ledger", default=str(LEDGER_PATH))
    parser.add_argument(
        "--envelope",
        choices=ENVELOPES,
        default=None,
        help="override the kernel-release derivation (default: 5.15.* = floor, else head)",
    )
    parser.add_argument("--self-test", action="store_true", help="rootless ledger audit, no kernel")
    args = parser.parse_args()

    ledger = load_ledger(Path(args.ledger))
    errors = validate_ledger(ledger)
    if errors:
        print(f"FAIL: the ledger at {args.ledger} does not hold ({len(errors)} error(s)):")
        for e in errors:
            print(f"  - {e}")
        return 2
    if args.self_test:
        print(f"self-test: OK — the ledger at {args.ledger} holds ({len(PROGRAMS)} programs)")
        return 0

    envelope = args.envelope or derive_envelope(os.uname().release)
    info(f"envelope: {envelope} (kernel {os.uname().release})")
    rows = ledger["envelopes"][envelope]["rows"]
    rows_pricing = ledger["envelopes"][envelope].get("pricing", "verified_insns")

    binary = args.binary
    if not Path(binary).exists():
        fail(f"the zelynic binary is absent at {binary}")
        return 2

    failures = []

    # 1. The bed: one cgroup, one live member.
    member, cgid = setup_cgroup()

    # 2. The limiter object: a real apply loads the four enforcement programs.
    rc, out, err = run_cmd([binary, "strict", str(cgid), APPLY_RATE], timeout=90)
    if rc != 0:
        teardown(member, cgid, binary)
        fail(f"'strict {cgid} {APPLY_RATE}' refused (rc {rc}): {(err or out).strip()[:300]}")
        return 1
    info(f"strict {cgid} {APPLY_RATE} applied — the limiter object is loaded")

    # 3. The observer object: a LIVE monitor session (the pty shape the
    #    survival battery proves) — the lazy camera pins nothing, so the
    #    observer's programs exist only while this session runs.
    monitor, master_fd = spawn_monitor_on_pty(binary, cgid)
    time.sleep(3.0)
    if monitor.poll() is not None:
        teardown(member, cgid, binary, monitor)
        fail("the eagle-eyes monitor session died before the census ran")
        return 1
    info("eagle-eyes monitor session alive — the observer object is loaded")

    # 4. The census: the kernel prices every estate program.
    try:
        limiter_prices, pinned_ids = census_programs()
        observer_ids = observer_pair(pinned_ids)
    finally:
        os.close(master_fd)

    # 5. The verdict per program: the inventory, then the budget.
    armed = ledger["armed"]
    if not armed:
        info("census mode (armed:false) — the budget comparison defers, the inventory does not")
    for prog in PROGRAMS:
        where = rows.get(prog)
        if where is None:
            # The rootless validator holds this cannot happen; the runtime
            # check keeps the law standing even against a hand-edited file.
            failures.append(f"inventory: '{prog}' has no {envelope} row")
            continue
        if prog in LIM_PIN_PROGS:
            price = limiter_prices.get(prog, "missing-pin")
            if price == "missing-pin":
                failures.append(
                    f"inventory: '{prog}' has no pinned file at "
                    f"{LIM_PIN_PROGS[prog]} — the limiter object did not load"
                )
                continue
            measured = price
        else:
            prog_id = observer_ids.get(prog)
            if prog_id is None:
                failures.append(
                    f"inventory: '{prog}' never loaded — the monitor session "
                    "was alive, but the kernel holds no matching live link"
                )
                continue
            fd_probe = prog_fd_by_id(prog_id)
            measured = fdinfo_verified_insns(fd_probe)
            os.close(fd_probe)
        if isinstance(measured, bool) or not isinstance(measured, int) or measured <= 0:
            if rows_pricing == "inventory":
                # The inventory envelope: the load-proof IS the gate.
                notice(
                    f"INVENTORY {envelope} {prog} seen — the load-proof "
                    "gate holds (verified_insns not exposed on it: the "
                    "UAPI field landed in the v5.16 merge window)"
                )
                continue
            failures.append(
                f"price: '{prog}' — the kernel does not expose "
                f"verified_insns here (the UAPI field landed in the v5.16 "
                f"merge window, aba64c7da983; got {measured!r})"
            )
            continue
        print(f"MASS-CENSUS: {envelope} {prog} measured={measured}")
        notice(f"MASS-CENSUS {envelope} {prog} measured={measured}")
        budget = where.get("budget")
        if budget is None:
            notice(
                f"CENSUS-DEBT {envelope} {prog} measured={measured} - "
                "comparison deferred, the arming commit pins this number"
            )
            continue
        if measured > budget:
            failures.append(
                f"growth: '{prog}' measured {measured} insns above the pinned "
                f"budget {budget} — the walk widened; if the growth is real, "
                "raise the budget in the same commit and name the number and "
                "the reason in the row's history"
            )
        else:
            headroom = budget - measured
            if headroom == 0:
                info(f"'{prog}' = {measured} insns — exactly at the pin")
            else:
                info(
                    f"'{prog}' = {measured} insns — {headroom} under the pin "
                    "(the ratchet may lower it)"
                )

    teardown(member, cgid, binary, monitor)

    if failures:
        print(f"verifier budget: {len(failures)} failure(s)")
        for f_ in failures:
            print(f"  - {f_}")
            # The verdict-loop failures carry the annotation channel too:
            # the bullets are the only record of WHAT failed when the
            # battery's own stdout stays inside the guest console.
            print(f"::error::{f_}")
        return 1
    print("verifier budget: every estate program priced and within its ledger")
    return 0


if __name__ == "__main__":
    # The crash guard: an uncaught exception dies INSIDE the guest
    # console - invisible to every read channel this seat owns - unless
    # it names itself on the annotation channel. The verdict's own exit
    # codes pass through untouched.
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:
        import traceback

        tb = traceback.format_exc()
        print(tb)
        # One annotation per traceback line: the cap is generous, and
        # the full walk to the crash lands where the API can read it.
        for line in tb.strip().splitlines()[-10:]:
            print(f"::error::census crash | {line[:240]}")
        sys.exit(2)
