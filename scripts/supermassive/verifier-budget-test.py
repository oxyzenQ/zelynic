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
real strict apply for the limiter's four programs, the eagle-eyes --depth
one-shot for the observer's two), walks every loaded program through the
staged bpftool, and prices each one with the kernel's own number —
bpf_prog_info.verified_insns (UAPI aba64c7da983, bpf: Add verified_insns
to bpf_prog_info and fdinfo). The objects are byte-identical by
construction (the parity gates), so for one kernel the number is
deterministic: the budget pins the verifier walk, not a sample of it.

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

Usage:
  sudo ./scripts/supermassive/verifier-budget-test.sh --binary /opt/zelynic/zelynic
  ./scripts/supermassive/verifier-budget-test.py --self-test   # rootless ledger audit
  sudo python3 verifier-budget-test.py --envelope floor        # override the derivation

Root/eBPF IS required for the census (the programs must be loaded for the
kernel to price them); --self-test needs none of it.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
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
# Any loaded program whose name starts with one of these prefixes belongs
# to the estate's inventory and must carry a ledger row (the completeness
# law's runtime half — the loader's own vocabulary).
ESTATE_PREFIXES = ("zelynic", "observe")

CGROUP_ROOT = Path("/sys/fs/cgroup")
TEST_CGROUP = CGROUP_ROOT / "zelynic-verifier-budget"
APPLY_RATE = "1mb"


def fail(msg: str) -> None:
    print(f"FAIL: {msg}")


def info(msg: str) -> None:
    print(f"Z9: {msg}")


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
    if ledger.get("armed") is True:
        for env_name, env in envelopes.items():
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


def census_programs() -> dict:
    """Walk the loaded programs through bpftool and price each one with
    the kernel's own verifier number. Returns name -> list of
    verified_insns (the list shape keeps a duplicate load visible)."""
    bpftool = shutil.which("bpftool") or "/usr/bin/bpftool"
    if not Path(bpftool).exists():
        fail(
            "bpftool is not available — the census reads the kernel's own "
            "bpf_prog_info through it (the guest stages /usr/bin/bpftool; "
            "on a host: install bpftool)"
        )
        sys.exit(2)
    rc, out, err = run_cmd([bpftool, "-j", "prog", "show"], timeout=60)
    if rc != 0:
        fail(f"bpftool -j prog show refused (rc {rc}): {err.strip()[:300]}")
        sys.exit(2)
    text = out.strip()
    if not text:
        fail("bpftool reported no programs at all — nothing loaded?")
        sys.exit(2)
    try:
        rows = json.loads(text)
    except ValueError:
        # Older bpftool builds emit concatenated objects; join them.
        try:
            rows = json.loads(f"[{text.replace('}{', '},{')}]")
        except ValueError:
            fail(f"bpftool output is not JSON the census can read: {text[:300]}")
            sys.exit(2)
    if not isinstance(rows, list):
        fail(f"bpftool output is not a program list: {text[:300]}")
        sys.exit(2)
    census = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("name")
        if not isinstance(name, str):
            continue
        entry = census.setdefault(name, [])
        entry.append(row.get("verified_insns"))
    return census


def setup_cgroup(binary: str) -> tuple:
    """One dedicated bed with one live member: the target the strict apply
    polices and the liveness gate the depth one-shot demands."""
    TEST_CGROUP.mkdir(parents=True, exist_ok=True)
    member = subprocess.Popen(
        ["sleep", "300"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
    )
    with open(TEST_CGROUP / "cgroup.procs", "w", encoding="ascii") as f:
        f.write(str(member.pid))
    try:
        cgid = int((TEST_CGROUP / "cgroup.id").read_text(encoding="ascii").strip())
    except (OSError, ValueError) as e:
        member.kill()
        member.wait()
        fail(f"the census cgroup's id is unreadable: {e}")
        sys.exit(2)
    info(f"census bed ready: {TEST_CGROUP} (cgroup id {cgid}, member {member.pid})")
    return member, cgid


def teardown(member, cgid: int, binary: str) -> None:
    """The lane empties itself (best-effort hygiene, never a verdict —
    the guest is ephemeral, the host rerun deserves a clean slate)."""
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

    binary = args.binary
    if not Path(binary).exists():
        fail(f"the zelynic binary is absent at {binary}")
        return 2

    failures = []

    # 1. The bed: one cgroup, one live member.
    member, cgid = setup_cgroup(binary)

    # 2. The limiter object: a real apply loads the four enforcement programs.
    rc, out, err = run_cmd([binary, "strict", str(cgid), APPLY_RATE], timeout=90)
    if rc != 0:
        teardown(member, cgid, binary)
        fail(f"'strict {cgid} {APPLY_RATE}' refused (rc {rc}): {(err or out).strip()[:300]}")
        return 1
    info(f"strict {cgid} {APPLY_RATE} applied — the limiter object is loaded")

    # 3. The observer object: the depth one-shot attaches it (headless-safe).
    rc, out, err = run_cmd(
        [binary, "eagle-eyes", "--depth", f"cg:{cgid}", "--print-json"], timeout=90
    )
    if rc != 0:
        teardown(member, cgid, binary)
        fail(f"eagle-eyes --depth refused (rc {rc}): {(err or out).strip()[:300]}")
        return 1
    try:
        json.loads(out)
    except ValueError:
        teardown(member, cgid, binary)
        fail("eagle-eyes --depth printed no JSON the census can read")
        return 1
    info("eagle-eyes --depth answered — the observer object is loaded")

    # 4. The census: the kernel prices every loaded program.
    census = census_programs()

    # 5. The completeness law (runtime half): an estate program loaded but
    # unledgered is the one failure the census posture cannot defer.
    for name in sorted(census):
        if name.startswith(ESTATE_PREFIXES) and name not in PROGRAMS:
            failures.append(
                f"completeness: loaded program '{name}' has no ledger row — "
                "add it to both envelopes in the same commit that loaded it"
            )

    # 6. The verdict per program: the inventory, then the budget.
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
        seen = census.get(prog, [])
        if not seen:
            failures.append(
                f"inventory: '{prog}' never loaded — the object carrying it "
                "did not load, or it is missing from this kernel"
            )
            continue
        if len(seen) > 1:
            failures.append(
                f"inventory: '{prog}' loaded {len(seen)} times — the census "
                "expects exactly one copy of each estate program"
            )
            continue
        measured = seen[0]
        if isinstance(measured, bool) or not isinstance(measured, int) or measured <= 0:
            failures.append(
                f"price: '{prog}' — the kernel/bpftool pair does not expose "
                f"verified_insns here (got {measured!r})"
            )
            continue
        print(f"MASS-CENSUS: {envelope} {prog} measured={measured}")
        budget = where.get("budget")
        if budget is None:
            info(f"'{prog}' = {measured} insns — census debt, comparison deferred")
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

    teardown(member, cgid, binary)

    if failures:
        print(f"verifier budget: {len(failures)} failure(s)")
        for f_ in failures:
            print(f"  - {f_}")
        return 1
    print("verifier budget: every estate program priced and within its ledger")
    return 0


if __name__ == "__main__":
    sys.exit(main())
