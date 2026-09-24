#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: like supermassive-test.py, one self-contained harness by design — v2 is a thin orchestrator over the v1 engine (imported whole via importlib, zero duplication of the fleet/server/worker machinery) plus the abuse-family stages it owns outright (NIGHT-refactor-2: the CLI guards, the SIGKILL batteries, the regression re-proof, and the crash-family teardown moved here from v1)
"""zelynic supermassive test v2 — the survival battery (NIGHT-improve-23; scope refocused in NIGHT-refactor-2).

supermassive-test.py (v1) answers "does the limiter HOLD, locally and
against the real internet?" — the full policy matrix, the rate-change
move, the internet lane. This v2 harness answers the owner's next
question: "does everything that is NOT a limit measurement SURVIVE the
day nothing goes right?" — the CLI input guards under hostile input,
the live TUI SIGKILLed mid-render under active enforcement, one-shot
writers SIGKILLed inside the attach/pin/write window, the core
invariants re-proven after the dust settles, and the crash-family
teardown (recover, cleanup, kernel log) verifying the state the
violence leaves behind.

Division of labor with v1 (NIGHT-refactor-2, the owner's call): v1 owns
every stage that measures a LIMIT; v2 owns the abuse family — the
rate-guard refusals (bounds, typo rescue, dangerous blocklist,
override), the kill batteries, the regression battery, and the
recover/cleanup/dmesg teardown. A machine green on v1 has a limiter
that holds everywhere it claims; a machine green on v2 survives the
day nothing goes right.

Design:

  * Zero engine duplication: v1 is imported whole (importlib, the dash
    in its filename defeats a plain import) and its machinery drives
    every stage here — the CgroupSet fleet (a..e + never-policed hq),
    the in-process HttpServer, apply/block/unstrict policy helpers,
    py_download traffic, band_check verdicts, enforcement proofs.
    v2 sets v1's module globals (CG / SERVER / MODE) exactly the way
    v1's own main() does, then calls its stages. One fix to the fleet
    lands in both harnesses the same day.
  * The guard battery (moved from v1, NIGHT-refactor-2): the limiter's
    input-validation functions as CLI round-trips — rate bounds, the
    near-miss typo rescue, the dangerous-target blocklist, the
    plain-number parser branch, the below-minimum override. All
    refusals are fail-fast: they fire during argument validation,
    before any privilege or BPF work, so this stage is safe even on a
    machine where the datapath is half-attached.
  * The brutal battery (NIGHT-improve-21, moved to v2 in
    NIGHT-refactor-2): SIGKILL of the live TUI (`eagle-eyes`)
    mid-render under active strict-multi enforcement, five times over;
    jittered SIGKILLs of one-shot CLI invocations racing the
    attach/pin/write window, twelve times; then the post-kill
    regression re-proof. Killing a monitor stresses exactly the seam
    it should: the observer never pins anything (the kernel releases
    its links when it dies), while the limiter's enforcement state
    lives in PINNED maps designed to survive process death.
  * LTS / cross-distro posture: python3 stdlib only, root required
    only for the root mode. --self-test verifies the engine with no
    root, no zelynic, no BPF, and no network.

Usage:
  sudo ./scripts/supermassive/supermassive-test-v2.sh               # survival battery (4+ min)
  python3 scripts/supermassive/supermassive-test-v2.py --self-test  # engine smoke, no root
  sudo ./scripts/supermassive/supermassive-test-v2.sh --binary ./zelynic
  sudo ./scripts/supermassive/supermassive-test-v2.sh --json        # machine-readable

What it verifies (verdicts PASS / FAIL / SKIP, exit 1 on any FAIL):
  preflight: env + minimum specs, doctor, list-apps, loopback baseline
         (the engine sanity the kill stages' traffic depends on);
  guards: below-minimum refused, above-maximum refused, the typo tip
         suggesting the lowercase twin, the dangerous-name refusal,
         plain-number acceptance, the --allow-dangerous override;
  kills: the TUI renders before every SIGKILL and dies as signal 9,
         enforcement rows stay intact after every kill, post-kill
         traffic is still policed, fresh writes still land; jittered
         mid-flight kills of one-shot writers leave the status JSON
         coherent and recover restores the zero-pin state;
  regression: the guards still refuse after the kills, policy
         round-trips still land on three cgroups, doctor + list-apps
         JSON still parse, the -V token still matches the checkout;
  teardown: recover exits clean, unstrict-all leaves no limit rows,
         zero BPF pins, no pid file, the fleet is removed, and the
         kernel log stayed clean of BPF errors during the run.
"""

import argparse
import fcntl
import importlib.util
import json
import os
import pty
import signal
import struct
import subprocess
import sys
import termios
import time

# The v1 engine lives one dash-named file over; make it importable
# regardless of how this script was invoked (file path, -m, or wrapper).
# The shared engine lib lives one directory further up in scripts/lib/
# (NIGHT-refactor-1) — both paths are bound by ABSOLUTE location.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_LIB_DIR = os.path.join(_HERE, "..", "lib")
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

import zelynic_harness_lib as lib  # noqa: E402
from zelynic_harness_lib import (  # noqa: E402
    PIN_DIR,
    RESULTS,
    limit_entry,
    out,
    record,
    run_zel,
    status_json,
)

# ── the v1 engine, imported whole ───────────────────────────────────────────
#
# supermassive-test.py's entrypoint is __main__-guarded, so exec_module
# binds its classes, helpers, and stage functions without running the
# matrix. v2 drives v1's module globals (CG / SERVER / MODE) the same
# way v1's own main() does — every stage below resolves fleet paths and
# server ports through v1's namespace, so one setup serves the battery.
_SPEC = importlib.util.spec_from_file_location(
    "supermassive_test_v1", os.path.join(_HERE, "supermassive-test.py")
)
sm1 = importlib.util.module_from_spec(_SPEC)
sys.modules["supermassive_test_v1"] = sm1
_SPEC.loader.exec_module(sm1)

# The loopback baseline window: the kill stages' post-kill traffic
# proofs need a working measurement engine, and the baseline row is
# that sanity check (0 B/s with no policy live would make every later
# row garbage — the same NIGHT-improve-13 contract v1 honors).
LOCAL_WINDOW = 4.0


# ── the CLI input guards (moved from v1, NIGHT-refactor-2) ──────────────────


def refuse(row, argv, needle):
    """One refusal probe: run zelynic with `argv`, expect a non-zero
    exit whose combined output contains `needle` (case-insensitive).

    Hoisted to module level by NIGHT-improve-21 inside v1, moved to v2
    with the guard family in NIGHT-refactor-2: the guard stage and the
    post-kill regression battery run the IDENTICAL probe — a refusal
    that only one of them exercises is a contract half-checked.
    """
    rc, stdout, stderr = run_zel(argv)
    text = (stderr or stdout).strip()
    hit = rc != 0 and needle.lower() in text.lower()
    return (
        record(
            row,
            "PASS" if hit else "FAIL",
            f"exit {rc}: {text[:140]}",
        )
        == "PASS"
    )


def test_rate_guard():
    """The limiter's input-validation functions as CLI round-trips
    (NIGHT-improve-12): the rate bounds (MIN_RATE / MAX_RATE), the
    near-miss typo rescue, the dangerous-target blocklist, the
    below-minimum override, and the plain-number parser branch.

    All refusals are fail-fast: they fire during argument validation,
    before any privilege or BPF work, so this stage is safe even on a
    machine where the datapath is half-attached.
    """
    ok_all = True
    tid = str(sm1.CG.ids["a"])

    # MIN_RATE = 1000 (format.rs): 999 must be refused with the
    # below-minimum error that names the override flag.
    ok_all = (
        refuse(
            "rate guard: below-minimum refused (999 < 1kb)",
            ["strict-single", tid, "999"],
            "below minimum",
        )
        and ok_all
    )
    # MAX_RATE = 1 TB/s: 2tb must be refused with the above-maximum
    # error.
    ok_all = (
        refuse(
            "rate guard: above-maximum refused (2tb > 1tb)",
            ["strict-single", tid, "2tb"],
            "above maximum",
        )
        and ok_all
    )
    # The near-miss typo rescue (cli/ux.rs rate_tip): '1MB' fails
    # parsing and the tip must suggest the lowercase twin '1mb'.
    ok_all = (
        refuse(
            "rate guard: typo tip suggests lowercase twin (1MB -> 1mb)",
            ["strict-single", tid, "1MB"],
            "1mb",
        )
        and ok_all
    )
    # The dangerous-target blocklist (commands/safety.rs): a system
    # daemon name must be refused without --force. Only the REFUSAL is
    # exercised — the forced variant would limit the live machine's
    # actual systemd, which is exactly what the guard exists to stop.
    ok_all = (
        refuse(
            "rate guard: dangerous name refused without --force (systemd)",
            ["strict-single", "systemd", "1mb"],
            "system process",
        )
        and ok_all
    )
    # The plain-number parser branch (no unit suffix) round-trips
    # through the status JSON at full value.
    rc, stdout, stderr = run_zel(["strict-single", tid, "1000000"])
    entry = limit_entry(status_json(), sm1.CG.ids["a"]) if rc == 0 else None
    plain_ok = (
        rc == 0
        and entry is not None
        and entry.get("download_bps") == 1_000_000
        and entry.get("upload_bps") == 1_000_000
    )
    ok_all = (
        record(
            "rate guard: plain-number rate accepted (1000000 = 1mb)",
            "PASS" if plain_ok else "FAIL",
            f"exit {rc}, row {entry}" if not plain_ok else "row 1000000/1000000",
        )
        == "PASS"
        and ok_all
    )
    sm1.clear_all()
    # The below-minimum override (--allow-dangerous): 500 B/s applies
    # with the warning, visible at full value in the status row.
    rc, stdout, stderr = run_zel(["strict-single", tid, "--allow-dangerous", "500"])
    entry = limit_entry(status_json(), sm1.CG.ids["a"]) if rc == 0 else None
    override_ok = (
        rc == 0
        and entry is not None
        and entry.get("download_bps") == 500
        and entry.get("upload_bps") == 500
    )
    ok_all = (
        record(
            "rate guard: below-minimum override applies (--allow-dangerous 500)",
            "PASS" if override_ok else "FAIL",
            f"exit {rc}, row {entry}" if not override_ok else "row 500/500",
        )
        == "PASS"
        and ok_all
    )
    sm1.clear_all()
    return ok_all


# ── the brutal battery (NIGHT-improve-21; moved to v2, NIGHT-refactor-2) ────
#
# The stages above answer "does the input behave?" The battery answers
# "does it SURVIVE violence?" — the live TUI SIGKILLed mid-render while
# enforcement is active, one-shot CLI invocations SIGKILLed inside the
# attach/pin/write window, and the core invariants re-proven after the
# dust settles. It runs BEFORE the recover/cleanup/dmesg teardown, so
# the teardown stages still verify the final state the battery leaves
# behind.
#
# Safety of the kill design (verified against the source): the observer
# behind `eagle-eyes` (the NIGHT-boost-1 merge of the former top/observe)
# loads its BPF objects and attaches cgroup
# programs but NEVER pins anything — the kernel releases those links
# when the process dies — while the limiter's enforcement state lives
# in PINNED maps under /sys/fs/bpf/zelynic that are designed to survive
# process death (that is the whole pinned-map architecture). Killing the
# monitor therefore stresses exactly the seam it should: a violent
# reader death must not disturb the writer's enforcement state.

KILL_TUI_CYCLES = 5
KILL_TUI_RENDER_S = 2.6
KILL_MIDFLIGHT_KILLS = 12


def _spawn_tui_on_pty(argv):
    """Spawn the zelynic TUI on a fresh pseudo-terminal.

    The render engine needs a real terminal — a pipe gives it no
    geometry to draw on — so the kill stages run the TUI exactly the
    way an owner's terminal does: pty with a sane 80x24 geometry set
    before exec, stdin/stdout/stderr all on the slave side. Returns
    (proc, master_fd); the caller drains the master (the render
    proof), then kills and reaps the child.
    """
    master, slave = pty.openpty()
    # 24 rows x 80 cols: the default geometry every terminal starts
    # from, so the eagle-eyes renderer exercises its full layout from
    # the very first frame instead of a degenerate 0x0 grid.
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    proc = subprocess.Popen(
        [lib.BINARY] + argv,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    os.close(slave)
    return proc, master


def _drain_pty(master, seconds):
    """Read the pty master for `seconds` and return the bytes the child
    rendered — non-blocking and paced, so a chatty TUI can never fill
    the pty buffer and block on its own output while we wait for proof
    that it is alive. Any bytes at all count: attach_quiet suppresses
    the loader trace, so output on the pty means the render engine is
    producing frames."""
    got = bytearray()
    os.set_blocking(master, False)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            chunk = os.read(master, 65536)
        except BlockingIOError:
            time.sleep(0.02)
            continue
        except OSError:
            break  # master closed under us: the child is already gone
        got += chunk
    return bytes(got)


def test_kill_tui():
    """SIGKILL the live TUI (`zelynic eagle-eyes`, the NIGHT-boost-1
    merge of the former top/observe) mid-render, under active
    strict-multi enforcement, five times over.

    Each cycle: apply strict-multi on cgroups a:b:c, start the TUI on a
    pty, let it render for KILL_TUI_RENDER_S seconds (at --interval 1s
    that is at least two frames), SIGKILL it, reap it as signal 9,
    then prove the split the pinned-map architecture promises —

    (1) the status rows for all three cgroups are intact at the exact
        configured rates (enforcement state survived the death),
    (2) traffic downloaded AFTER the kill is still policed (kernel
        drops engaged, BPF accounting in agreement — the
        enforcement_proofs contract),
    (3) a fresh policy write still lands (the write path is alive).

    A monitor death that cost enforcement continuity fails here, not
    in the field.
    """
    rates = ["200kb", "1mb", "500kb", "2mb", "100kb"]
    exp = [200_000, 1_000_000, 500_000, 2_000_000, 100_000]
    completed = 0
    rendered_ok = 0
    killed_ok = 0
    rows_ok = 0
    write_ok = 0
    for cycle in range(KILL_TUI_CYCLES):
        ok, payload = sm1.apply_group(["a", "b", "c"], rates[cycle], exp[cycle])
        if not ok:
            record(
                "kill tui: strict-multi applied",
                "FAIL",
                f"cycle {cycle + 1}: {payload}",
            )
            break
        completed += 1
        proc, master = _spawn_tui_on_pty(["eagle-eyes", "--interval", "1s"])
        try:
            rendered = _drain_pty(master, KILL_TUI_RENDER_S)
            proc.kill()  # SIGKILL: the violent death under test
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass  # unreapable child: surfaced by the killed_ok row
        finally:
            os.close(master)
        if rendered:
            rendered_ok += 1
        if proc.returncode == -signal.SIGKILL:
            killed_ok += 1
        doc = status_json()
        rows_intact = doc is not None
        for n in ("a", "b", "c"):
            entry = limit_entry(doc, sm1.CG.ids[n]) if rows_intact else None
            if (
                entry is None
                or entry.get("download_bps") != exp[cycle]
                or entry.get("upload_bps") != exp[cycle]
            ):
                rows_intact = False
        if rows_intact:
            rows_ok += 1
        # Post-kill traffic: still policed by the maps the dead monitor
        # never owned. enforcement_proofs records the kernel-drop and
        # byte-accounting rows per cycle.
        got = sm1.py_download(2.5, "a")
        sm1.enforcement_proofs(f"kill tui c{cycle + 1}", got)
        # A fresh write must still land after the kill.
        ok, _ = sm1.apply_single("d", "750kb", 750_000, 750_000)
        if ok:
            write_ok += 1
        sm1.clear_all()
    record(
        "kill tui: TUI rendered before every SIGKILL",
        "PASS" if rendered_ok == completed and completed == KILL_TUI_CYCLES else "FAIL",
        f"{rendered_ok}/{completed} cycles produced pty output"
        + ("" if completed == KILL_TUI_CYCLES else f" (only {completed} cycles ran)"),
    )
    record(
        "kill tui: every kill reaped as signal 9",
        "PASS" if killed_ok == completed and completed == KILL_TUI_CYCLES else "FAIL",
        f"{killed_ok}/{completed} cycles exited -9"
        + ("" if completed == KILL_TUI_CYCLES else f" (only {completed} cycles ran)"),
    )
    record(
        "kill tui: enforcement rows intact after every kill",
        "PASS" if rows_ok == completed and completed == KILL_TUI_CYCLES else "FAIL",
        f"{rows_ok}/{completed} cycles kept the exact a:b:c rates",
    )
    record(
        "kill tui: fresh policy write lands after every kill",
        "PASS" if write_ok == completed and completed == KILL_TUI_CYCLES else "FAIL",
        f"{write_ok}/{completed} cycles wrote a new limit post-kill",
    )
    return (
        rendered_ok == completed
        and killed_ok == completed
        and rows_ok == completed
        and write_ok == completed
        and completed == KILL_TUI_CYCLES
    )


def test_kill_midflight():
    """SIGKILL one-shot CLI invocations inside the attach/pin/write
    window, twelve times, at jittered offsets.

    A strict-single invocation pins programs, writes policy maps, and
    updates the row surface — killing it at a jittered point races
    every step of that write path. The contract under test is NOT
    which side wins the race (a kill landing after the CLI finished is
    an equally legal outcome) but that a killed writer can never leave
    a state the status surface cannot read back coherently: the JSON
    parses, and every limit row carries integral rates. The stage ends
    with the restore contract — recover must bring the machine back to
    zero pins no matter where the twelve kills landed.
    """
    rates = ["300kb", "1mb", "600kb", "2mb"]
    sigkilled = 0
    finished_first = 0
    other_exit = 0
    coherent = 0
    for i in range(KILL_MIDFLIGHT_KILLS):
        proc = subprocess.Popen(
            [lib.BINARY, "strict-single", str(sm1.CG.ids["a"]), rates[i % len(rates)]],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Jitter across the attach/pin/write window (20..68 ms): early
        # kills race the pin creation, late ones race the row write,
        # and the widest offsets let the CLI finish first — the
        # coherence check below is the invariant, not winning.
        time.sleep(0.02 + 0.012 * (i % 5))
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        if proc.returncode == -signal.SIGKILL:
            sigkilled += 1
        elif proc.returncode == 0:
            finished_first += 1
        else:
            other_exit += 1
        doc = status_json()
        limit_rows = (doc or {}).get("limits", [])
        integral = (
            doc is not None
            and isinstance(limit_rows, list)
            and all(
                isinstance(e.get("download_bps"), int) and isinstance(e.get("upload_bps"), int)
                for e in limit_rows
            )
        )
        if integral:
            coherent += 1
        run_zel(["unstrict-all"])
    run_zel(["recover"])
    pins_left = len(os.listdir(PIN_DIR)) if os.path.isdir(PIN_DIR) else 0
    record(
        "kill midflight: every cycle reaped (12 kills, jittered)",
        "PASS" if (sigkilled + finished_first + other_exit) == KILL_MIDFLIGHT_KILLS else "FAIL",
        f"{sigkilled} killed mid-flight, {finished_first} finished first"
        f"{f', {other_exit} other exits' if other_exit else ''}",
    )
    record(
        "kill midflight: status JSON coherent after every kill",
        "PASS" if coherent == KILL_MIDFLIGHT_KILLS else "FAIL",
        f"{coherent}/{KILL_MIDFLIGHT_KILLS} cycles parsed with integral rate rows",
    )
    record(
        "kill midflight: recover restores the zero-pin state",
        "PASS" if pins_left == 0 else "FAIL",
        f"{pins_left} entries left in {PIN_DIR}",
    )
    return (
        coherent == KILL_MIDFLIGHT_KILLS
        and pins_left == 0
        and (sigkilled + finished_first + other_exit) == KILL_MIDFLIGHT_KILLS
    )


def test_regression_battery():
    """Re-prove the core invariants AFTER the kills.

    Every check here already ran green BEFORE the brutal battery (the
    rate guards in the guard phase, the JSON surfaces in doctor and
    list-apps, the version token at resolve time). Running them again
    after five TUI kills and twelve mid-flight kills is the regression
    contract: nothing the battery broke is allowed to stay broken, and
    nothing that was refusing before may start accepting. Three rapid
    policy round-trips across different cgroups close the battery the
    way the guard phase opened — write, verify, clear, repeat.
    """
    ok_all = True
    tid = str(sm1.CG.ids["a"])
    ok_all = (
        refuse(
            "regression: below-minimum still refused (999 < 1kb)",
            ["strict-single", tid, "999"],
            "below minimum",
        )
        and ok_all
    )
    ok_all = (
        refuse(
            "regression: above-maximum still refused (2tb > 1tb)",
            ["strict-single", tid, "2tb"],
            "above maximum",
        )
        and ok_all
    )
    ok_all = (
        refuse(
            "regression: typo tip still suggests lowercase twin (1MB -> 1mb)",
            ["strict-single", tid, "1MB"],
            "1mb",
        )
        and ok_all
    )
    ok_all = (
        refuse(
            "regression: dangerous name still refused without --force (systemd)",
            ["strict-single", "systemd", "1mb"],
            "system process",
        )
        and ok_all
    )
    trips_ok = 0
    for name, rate_str, exp in (
        ("a", "400kb", 400_000),
        ("b", "800kb", 800_000),
        ("d", "1500kb", 1_500_000),
    ):
        ok, _ = sm1.apply_single(name, rate_str, exp, exp)
        if ok:
            ok, _ = sm1.unstrict_target("unstrict-single", [name])
        if ok:
            trips_ok += 1
    ok_all = (
        record(
            "regression: policy round-trip still lands (3 cgroups)",
            "PASS" if trips_ok == 3 else "FAIL",
            f"{trips_ok}/3 write-verify-clear trips",
        )
        == "PASS"
        and ok_all
    )
    doctor_ok = False
    apps_ok = False
    rc, stdout, _ = run_zel(["doctor", "--print-json"])
    if rc == 0:
        try:
            json.loads(stdout)
            doctor_ok = True
        except json.JSONDecodeError:
            pass
    rc, stdout, _ = run_zel(["list-apps", "--print-json"])
    if rc == 0:
        try:
            json.loads(stdout)
            apps_ok = True
        except json.JSONDecodeError:
            pass
    ok_all = (
        record(
            "regression: doctor + list-apps JSON still parse",
            "PASS" if doctor_ok and apps_ok else "FAIL",
            f"doctor {'ok' if doctor_ok else 'broken'}, list-apps {'ok' if apps_ok else 'broken'}",
        )
        == "PASS"
        and ok_all
    )
    rc, stdout, _ = run_zel(["-V"])
    first = (stdout or "").strip().splitlines()
    token = lib.version_token(first[0]) if rc == 0 and first else None
    want = lib.repo_version()
    ok_all = (
        record(
            "regression: -V token still matches the checkout",
            "PASS" if token == want else "FAIL",
            f"{token or '(none)'} vs v{want}",
        )
        == "PASS"
        and ok_all
    )
    return ok_all


# ── the crash-family teardown (v2's own half; v1 keeps its light one) ──────


def test_recover():
    rc, stdout, stderr = run_zel(["recover"])
    detail = (stderr or stdout).strip()[:120] or f"exit {rc}"
    return record("recover: clean state after the battery", "PASS" if rc == 0 else "FAIL", detail)


def test_dmesg():
    return lib.dmesg_scan()


# ── engine self-test (no root, no zelynic, no BPF, no network) ─────────────


def self_test():
    out("zelynic supermassive test v2 — engine self-test (no root, no zelynic, no BPF)")
    out()
    probe = os.path.join(_HERE, "supermassive-test.py")
    ok = record(
        "engine: v1 harness importable",
        "PASS" if os.path.isfile(probe) and hasattr(sm1, "CgroupSet") else "FAIL",
        f"{probe} bound as supermassive_test_v1",
    )
    # NIGHT-refactor-2: the surface v2 drives changed with the scope —
    # the five preflight/teardown stages plus the policy helpers the
    # guard and kill batteries lean on. A missing attr means the
    # battery crashes mid-run on a distro, so it is pinned rootless.
    ok = (
        record(
            "engine: v1 stage surface present",
            "PASS"
            if all(
                hasattr(sm1, attr)
                for attr in (
                    "test_env",
                    "test_doctor",
                    "test_list_apps",
                    "test_baseline",
                    "test_cleanup",
                    "apply_single",
                    "apply_group",
                    "unstrict_target",
                    "clear_all",
                    "py_download",
                    "enforcement_proofs",
                    "CgroupSet",
                    "HttpServer",
                    "run_zel",
                    "status_json",
                    "limit_entry",
                )
            )
            else "FAIL",
            "the preflight/teardown stages and policy helpers resolve",
        )
        == "PASS"
        and ok
    )
    # NIGHT-improve-21 pin (moved from v1, NIGHT-refactor-2): the kill
    # battery's pty mechanics — spawn, render-drain, SIGKILL, reap —
    # verified rootlessly against a dummy child (a python that prints
    # one line, then sleeps on a real pty). A pty regression on any
    # distro is caught here, before a root run ever reaches the kill
    # stages.
    pty_ok = False
    pty_detail = "engine error"
    try:
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        dummy = subprocess.Popen(
            [sys.executable, "-c", "print('frame'); import time; time.sleep(30)"],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
        )
        os.close(slave)
        try:
            rendered = _drain_pty(master, 2.0)
        finally:
            os.close(master)
            dummy.kill()
            try:
                dummy.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        pty_ok = bool(rendered) and dummy.returncode == -signal.SIGKILL
        pty_detail = f"{len(rendered)} bytes rendered, exit {dummy.returncode}"
    except (OSError, subprocess.TimeoutExpired) as e:
        pty_detail = str(e)[:80]
    record(
        "engine: pty spawn + drain + SIGKILL reap (kill battery)",
        "PASS" if pty_ok else "FAIL",
        pty_detail,
    )
    try:
        lo, hi = (float(x) for x in "0.5,1.5".split(","))
        band_ok = lo < hi
    except ValueError:
        band_ok = False
    ok = (
        record(
            "cli: --band lo,hi parses",
            "PASS" if band_ok else "FAIL",
            "the same parser main() applies to --band",
        )
        == "PASS"
        and ok
    )
    record("self-test: verdict plumbing", "PASS", "this row IS the plumbing")
    out()
    out("━━━ self-test verdict ━━━")
    fails = sum(1 for r in RESULTS if r["verdict"] == "FAIL")
    out(f"  {len(RESULTS) - fails} passed, {fails} failed, 0 skipped")
    return fails == 0


# ── main ────────────────────────────────────────────────────────────────────

KNOWN_FLAGS = ("self-test", "binary", "json", "band")


def _unknown_arg_error(token):
    return [
        f"error: unknown option '{token}'",
        f"  known options: {', '.join(f'--{f}' for f in KNOWN_FLAGS)}",
    ]


def run_survival():
    """The abuse family in escalation order: guards (does bad input
    behave?), kills (does violence break anything?), regression (is
    everything that passed before still passing?), teardown (is the
    machine returned clean?). v1's stages carry the preflight; the
    batteries below are v2's own."""
    out("zelynic supermassive test v2 (NIGHT-refactor-2, survival mode)")
    out()
    env_ok = sm1.test_env()
    if not env_ok:
        out()
        out("  environment not suitable for zelynic — stopping here.")
        return False

    # preflight: the engine sanity the kill stages' traffic depends on.
    sm1.test_doctor()
    sm1.test_list_apps()
    sm1.test_baseline(LOCAL_WINDOW)

    # phase 1/4: the CLI input guards
    out()
    out("━━━ phase 1/4: guards (bad input must be refused, never fatal) ━━━")
    test_rate_guard()

    # phase 2/4: the brutal battery
    out()
    out("━━━ phase 2/4: kills (SIGKILL the TUI and the mid-flight writers) ━━━")
    test_kill_tui()
    test_kill_midflight()

    # phase 3/4: the regression re-proof
    out()
    out("━━━ phase 3/4: regression (nothing broken stays broken) ━━━")
    test_regression_battery()

    # phase 4/4: the crash-family teardown
    out()
    out("━━━ phase 4/4: teardown (recover, cleanup, kernel log) ━━━")
    test_recover()
    sm1.test_cleanup()
    test_dmesg()

    return True


def main():
    global MODE
    ap = argparse.ArgumentParser(
        prog="supermassive-test-v2",
        description="zelynic survival battery (NIGHT-improve-23, refocused NIGHT-refactor-2)",
    )
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="verify the harness engine only — no root, no zelynic, no BPF, no network",
    )
    ap.add_argument("--binary", help="path to the zelynic binary")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument(
        "--band",
        default=f"{lib.BAND_LO},{lib.BAND_HI}",
        help="verdict band as lo,hi ratios (default 0.65,1.30)",
    )
    args, unknown = ap.parse_known_args()
    if unknown:
        for token in unknown:
            for line in _unknown_arg_error(token):
                out(line)
        return 2

    if args.self_test:
        ok = self_test()
        if args.json:
            print(json.dumps({"mode": "self-test", "results": RESULTS}, indent=2))
        return 0 if ok else 1

    try:
        lo, hi = (float(x) for x in args.band.split(","))
        lib.BAND_LO, lib.BAND_HI = lo, hi
    except ValueError:
        out("--band expects lo,hi (e.g. 0.65,1.30)")
        return 2

    if os.geteuid() != 0:
        out("This test programs the kernel datapath — run with sudo.")
        return 2
    if not lib.resolve_binary(args.binary, "sudo ./scripts/supermassive/supermassive-test-v2.sh"):
        return 2

    start = time.perf_counter()
    sm1.CG = sm1.CgroupSet()
    exit_code = 1
    try:
        MODE = sm1.CG.setup()
        sm1.MODE = MODE
        sm1.SERVER = sm1.HttpServer()
        ran = run_survival()
        sm1.report_worker_faults()
        ok = (
            lib.final_report(
                start,
                "survival",
                "survival battery green: CLI guards, SIGKILL batteries, "
                "regression re-proof, teardown — all proven",
            )
            if ran
            else False
        )
        exit_code = 0 if ok else 1
    finally:
        sm1.clear_all()
        if sm1.SERVER:
            sm1.SERVER.stop()
        sm1.CG.cleanup()
    if args.json:
        print(
            json.dumps(
                {
                    "binary": lib.BINARY,
                    "mode": "survival",
                    "cgroup_mode": MODE,
                    "worker_faults": [{"error": msg, "count": n} for msg, n in sm1.WORKER_FAULTS],
                    "results": RESULTS,
                },
                indent=2,
            )
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
