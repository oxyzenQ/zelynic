#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: like supermassive-test.py, one self-contained harness by design — v2 is a thin orchestrator over the v1 engine (imported whole via importlib, zero duplication of the fleet/server/worker machinery) plus the abuse-family stages it owns outright (NIGHT-refactor-2: the CLI guards, the SIGKILL batteries, the regression re-proof, and the crash-family teardown moved here from v1; over the 1000 scripts cap under NIGHT-lts-2 — tracked debt, the split is its own NIGHT task)
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
recover/cleanup/dmesg teardown — plus, since NIGHT-blade-4, the
SERVER phase both harnesses lead with: v1 proves the limiter holds
under the server shape (headless env, dense fleet, daemon traffic,
concurrent readers), v2 proves the guards survive it. A machine
green on v1 has a limiter that holds everywhere it claims; a machine
green on v2 survives the day nothing goes right.

Design:

  * Zero engine duplication: v1 is imported whole (importlib, the dash
    in its filename defeats a plain import) and its machinery drives
    every stage here — the CgroupSet fleet (a..e + never-policed hq),
    the in-process HttpServer, apply/block/unstrict policy helpers,
    py_download traffic, band_check verdicts, enforcement proofs.
    v2 sets v1's module globals (CG / SERVER / MODE) exactly the way
    v1's own main() does, then calls its stages. One fix to the fleet
    lands in both harnesses the same day.
  * The CLI depth stresstest (NIGHT-ultimate-3): every flag surface
    end to end against hostile input — typos, wrong values, ambiguous
    argument orders, shell-injection payloads in every value
    position, and fatal usage shapes. The hardening invariants, not
    any single message, are the contract: every case must ANSWER
    (never hang), exit with the right class (0 info / non-zero
    refusal), carry its expected wording, and never leak a Rust
    panic. Safety by construction: every case is a refusal or an
    info surface — no case executes a policy or starts the monitor
    (valid executions are v1's matrix). The cosmostrix
    cli_config/suggestion stresstest lineage is the pattern.
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
  sudo ./scripts/supermassive/supermassive-test-v2.sh               # server phase + survival battery (4+ min)
  sudo ./scripts/supermassive/supermassive-test-v2.sh --server-only  # the headless guard phase alone
  sudo ./scripts/supermassive/supermassive-test-v2.sh --desktop-only # the four survival phases alone
  python3 scripts/supermassive/supermassive-test-v2.py --self-test  # engine smoke, no root
  sudo ./scripts/supermassive/supermassive-test-v2.sh --binary ./zelynic
  sudo ./scripts/supermassive/supermassive-test-v2.sh --json        # machine-readable

What it verifies (verdicts PASS / FAIL / SKIP, exit 1 on any FAIL):
  the server phase (NIGHT-blade-4, runs FIRST): the guard family under
         the stripped headless environment a production server
         carries (PATH + TERM=dumb, no DISPLAY/DBUS/XDG, every fd a
         pipe) — the info surfaces, the retired --info tipping
         --depth, the removed eagle-eye redirect, the root-refusing
         --check-update, the live TUI's piped-stdio refusal, and the
         ee --depth error ladder, every invariant identical to the
         inherited-env sweep; then, on a green server phase, the
         survival battery:
  preflight: env + minimum specs, doctor, list-apps, loopback baseline
         (the engine sanity the kill stages' traffic depends on);
  guards: the NIGHT-ultimate-3 depth sweep — 87 cases: info surfaces
         (bare invocation, --help/-h, --version/-V, global -V at
         subcommand level, --color-mode, --, doctor --print-json, the
         root-refusing --check-update pair), flag typos with their
         suggestion tips, subcommand typos and removed-name redirects,
         wrong rates/durations/intervals/color-modes, ambiguous
         argument orders, shell-injection payloads as data (never
         executed), 5000-char targets, u32-overflow cgroup ids, fatal
         usage shapes, and every alias resolving; then the rate
         guards: below-minimum refused, above-maximum refused, the
         typo tip suggesting the lowercase twin, the dangerous-name
         refusal, plain-number acceptance, the --force-this
         override;
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
    # daemon name must be refused without --force-this. Only the
    # REFUSAL is exercised — the forced variant would limit the live
    # machine's actual systemd, which is exactly what the guard
    # exists to stop.
    ok_all = (
        refuse(
            "rate guard: dangerous name refused without --force-this (systemd)",
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
    # The below-minimum override (--force-this, NIGHT-improve-30's
    # unified spelling): 500 B/s applies silently at full value in
    # the status row — the override no longer echoes its own
    # request back.
    rc, stdout, stderr = run_zel(["strict-single", tid, "--force-this", "500"])
    entry = limit_entry(status_json(), sm1.CG.ids["a"]) if rc == 0 else None
    override_ok = (
        rc == 0
        and entry is not None
        and entry.get("download_bps") == 500
        and entry.get("upload_bps") == 500
    )
    ok_all = (
        record(
            "rate guard: below-minimum override applies (--force-this 500)",
            "PASS" if override_ok else "FAIL",
            f"exit {rc}, row {entry}" if not override_ok else "row 500/500",
        )
        == "PASS"
        and ok_all
    )
    sm1.clear_all()
    return ok_all


# ── the CLI depth stresstest (NIGHT-ultimate-3) ─────────────────────────────
#
# The guard battery proves the documented refusals; this stresstest
# proves the UNDOCUMENTED ones — every flag surface end to end against
# hostile input: typos, wrong values, ambiguous argument orders,
# shell-injection payloads in every value position, and fatal usage
# shapes (missing values, stray positionals, removed spellings). The
# contract under test is the hardening invariant, not any single
# message: every case must ANSWER (never hang), exit with the right
# class (0 for info surfaces, non-zero for refusals), carry its
# expected wording, and never leak a Rust panic — no "panicked", no
# backtrace, no abort — on ANY input a hostile shell can type.
#
# Safety by construction: every case is a REFUSAL, an INFO surface,
# or a GRACEFUL NO-OP — no case writes a policy or starts the monitor
# (valid executions are v1's matrix; the guard battery owns the
# override round-trips). A hostile target that matches nothing exits
# 0 with the payload echoed VERBATIM as data ("No cgroup found for
# '$(reboot)'") — the strongest no-execution proof there is: the
# payload in the output is the literal string, never a shell's
# interpretation of it. The eagle-eyes cases all fail parse or
# interval validation, so the live TUI never starts. stdin is
# /dev/null and the environment carries NO_COLOR=1 so needles match
# plain output deterministically.
#
# The cosmostrix lineage (cli_config_stresstest.sh /
# cli_suggestion_stresstest.sh) is the pattern: a data-driven case
# table, one verdict per case, a summary row at the end.

CLI_CASE_TIMEOUT = 10.0
# A panic on hostile input is the one failure this stage exists to
# catch — the markers cover the rust runtime's three panic shapes
# (panic hook text, the backtrace hint, and the stack-overflow abort).
PANIC_MARKERS = ("panicked", "RUST_BACKTRACE", "stack overflow", "SIGABRT")

# (label, argv, exit_class, needle)
#   exit_class: "zero" (info surface, exit 0) | "nonzero" (refused) |
#               None (any exit — the invariants alone carry the case)
#   needle:     substring expected in the COMBINED output,
#               case-insensitive; None for invariant-only cases
#               (wordings the owner may retune without notice).
CLI_DEPTH_CASES = [
    # ── info surfaces (exit 0) ─────────────────────────────────────────
    ("bare invocation prints the reference", [], "zero", "zelynic"),
    ("--help prints the end-to-end reference", ["--help"], "zero", "strict-single"),
    ("-h short help", ["-h"], "zero", "zelynic"),
    ("--version banner", ["--version"], "zero", "zelynic"),
    ("-V short version", ["-V"], "zero", "zelynic"),
    ("-V stays global at subcommand level", ["status", "-V"], "zero", "zelynic"),
    ("-v rides the help surface without breaking it", ["-v", "--help"], "zero", "zelynic"),
    (
        "--color-mode 16 parses, help still answers",
        ["--color-mode", "16", "--help"],
        "zero",
        "zelynic",
    ),
    (
        "--verbose rides a refusal without changing it",
        ["strict-single", "brave", "--verbose"],
        "nonzero",
        "no rate specified",
    ),
    (
        "--force-this with no rate still needs a rate",
        ["strict-single", "brave", "--force-this"],
        "nonzero",
        "no rate specified",
    ),
    ("bare -- terminator falls back to the reference", ["--"], "zero", "zelynic"),
    ("doctor --print-json emits a JSON document", ["doctor", "--print-json"], "zero", "{"),
    # ── the network surface refuses root (the harness IS root) ────────
    (
        "--check-update refuses root with the sudo tip",
        ["--check-update"],
        "nonzero",
        "re-run without sudo",
    ),
    (
        "--check-updated alias refuses root too",
        ["--check-updated"],
        "nonzero",
        "re-run without sudo",
    ),
    # ── flag typos: the suggestion engine answers (exit 2) ────────────
    ("--json gets the cross-tool vocabulary tip", ["--json"], "nonzero", "--print-json"),
    ("--verbos gets the fuzzy flag tip", ["--verbos"], "nonzero", "--verbose"),
    ("--print-jso gets the near-miss tip", ["--print-jso"], "nonzero", "--print-json"),
    ("--color-mod gets the near-miss tip", ["--color-mod", "16"], "nonzero", "--color-mode"),
    (
        "--force-thi typo after a valid target",
        ["strict-single", "brave", "1mb", "--force-thi"],
        "nonzero",
        "--force-this",
    ),
    (
        "removed --allow-dangerous spelling is refused",
        ["strict-single", "brave", "--allow-dangerous"],
        "nonzero",
        "unexpected argument",
    ),
    (
        "removed --force spelling is refused",
        ["block-all", "--force"],
        "nonzero",
        "unexpected argument",
    ),
    ("unknown short flag -x dies as a usage error", ["-x"], "nonzero", "error"),
    ("--interva typo on the monitor", ["eagle-eyes", "--interva", "3s"], "nonzero", "--interval"),
    # ── subcommand typos + removed-name redirects (exit 2) ────────────
    ("statu near-miss suggests status", ["statu"], "nonzero", "status"),
    ("removed observe redirects to eagle-eyes", ["observe"], "nonzero", "eagle-eyes"),
    ("removed top redirects to eagle-eyes", ["top"], "nonzero", "eagle-eyes"),
    ("removed singular eagle-eye redirects", ["eagle-eye"], "nonzero", "eagle-eyes"),
    (
        "removed limit-all redirects to strict-all",
        ["limit-all"],
        "nonzero",
        "strict-all",
    ),
    ("removed la alias redirects to strict-all", ["la"], "nonzero", "strict-all"),
    ("help subcommand redirects to the flag", ["help"], "nonzero", "zelynic --help"),
    # ── wrong values (exit 1: runtime validation) ─────────────────────
    (
        "strict-single with no rate names the fix",
        ["strict-single", "brave"],
        "nonzero",
        "no rate specified",
    ),
    ("non-numeric rate is quoted back", ["strict-single", "brave", "mb"], "nonzero", "rate"),
    ("1kb/s slash unit is refused", ["strict-single", "brave", "1kb/s"], "nonzero", "rate"),
    (
        "double-dot rate 5.5.5mb is refused",
        ["strict-single", "brave", "5.5.5mb"],
        "nonzero",
        "rate",
    ),
    ("leading-dot rate .5mb is refused", ["strict-single", "brave", ".5mb"], "nonzero", "rate"),
    ("scientific notation 1e6 is not a rate", ["strict-single", "brave", "1e6"], "nonzero", "rate"),
    (
        "fullwidth unicode rate is refused",
        ["strict-single", "brave", "\uff11mb"],
        "nonzero",
        "rate",
    ),
    ("negative rate reads as a flag error", ["strict-single", "brave", "-1mb"], "nonzero", "error"),
    ("interval 0s is out of range", ["eagle-eyes", "--interval", "0s"], "nonzero", "interval"),
    ("interval 61s is out of range", ["eagle-eyes", "--interval", "61s"], "nonzero", "interval"),
    (
        "plain-number interval 100 is out of range",
        ["eagle-eyes", "--interval", "100"],
        "nonzero",
        "interval",
    ),
    (
        "non-duration interval 'abc' is refused",
        ["eagle-eyes", "--interval", "abc"],
        "nonzero",
        "duration",
    ),
    ("invalid --color-mode names the allowed set", ["--color-mode", "99"], "nonzero", "color-mode"),
    # ── ambiguous input ────────────────────────────────────────────────
    (
        "swapped (target, rate) order fails on the rate",
        ["strict-single", "100kb", "brave"],
        "nonzero",
        "rate",
    ),
    ("-d with no value is a usage error", ["strict-single", "brave", "-d"], "nonzero", "required"),
    (
        "--download with no value is a usage error",
        ["strict-single", "brave", "--download"],
        "nonzero",
        "required",
    ),
    ("-u with no value is a usage error", ["strict-single", "brave", "-u"], "nonzero", "required"),
    (
        "--upload with no value is a usage error",
        ["strict-single", "brave", "--upload"],
        "nonzero",
        "required",
    ),
    (
        "--force-this with no rate reaches the rate guard",
        ["strict-single", "--force-this", "brave"],
        "nonzero",
        "no rate specified",
    ),
    (
        "strict-multi without a rate names the fix",
        ["strict-multi", "brave:curl:pacman"],
        "nonzero",
        "no rate specified",
    ),
    ("strict-all without a rate names the fix", ["strict-all"], "nonzero", "no rate specified"),
    ("strict-all -d with no value is a usage error", ["strict-all", "-d"], "nonzero", "required"),
    # ── security injection: values are DATA, never executed ───────
    # Unknown-name targets are graceful no-ops (exit 0, "No cgroup
    # found"): the needle is the PAYLOAD ITSELF, echoed verbatim — the
    # literal string in the output is the no-execution proof.
    (
        "shell semicolon in the target is echoed as data",
        ["strict-single", "brave;rm -rf /", "1mb"],
        "zero",
        "brave;rm -rf /",
    ),
    (
        "command substitution in the target is echoed as data",
        ["strict-single", "$(reboot)", "1mb"],
        "zero",
        "$(reboot)",
    ),
    (
        "backtick substitution in the target is echoed as data",
        ["strict-single", "`id`", "1mb"],
        "zero",
        "`id`",
    ),
    (
        "path traversal as a target is echoed as data",
        ["strict-single", "../../etc/passwd", "1mb"],
        "zero",
        "../../etc/passwd",
    ),
    (
        "newline injection in the target is echoed as data",
        ["strict-single", "brave\nrm -rf /", "1mb"],
        "zero",
        "rm -rf",
    ),
    (
        "shell metacharacters in the rate are refused as a rate",
        ["strict-single", "brave", "1mb;$(id)"],
        "nonzero",
        "rate",
    ),
    (
        "shell chain in the rate is refused as a rate",
        ["strict-single", "brave", "1mb && rm -rf /"],
        "nonzero",
        "rate",
    ),
    (
        "injection inside the interval is refused as a duration",
        ["eagle-eyes", "--interval", "1s;reboot"],
        "nonzero",
        None,
    ),
    (
        "injection inside --color-mode is refused",
        ["--color-mode", "16;rm -rf /"],
        "nonzero",
        "color-mode",
    ),
    (
        "a 5000-char target is a graceful no-op, not a hang",
        ["strict-single", "a" * 5000, "1mb"],
        "zero",
        "no cgroup found",
    ),
    (
        "cgroup id beyond u32 range is a graceful no-op",
        ["strict-single", "99999999999999999999", "1mb"],
        "zero",
        "no cgroup found",
    ),
    # ── fatal usage shapes (exit 2: clap) ─────────────────────────────
    ("strict-single with no target is a usage error", ["strict-single"], "nonzero", "error"),
    (
        "colon target in strict-single tips strict-multi",
        ["strict-single", ":", "1mb"],
        "zero",
        "strict-multi",
    ),
    ("unstrict-single with no target is a usage error", ["unstrict-single"], "nonzero", "error"),
    ("unstrict-multi with no targets is a usage error", ["unstrict-multi"], "nonzero", "error"),
    ("block-single with no target is a usage error", ["block-single"], "nonzero", "error"),
    ("block-multi with no targets is a usage error", ["block-multi"], "nonzero", "error"),
    ("stray positional after status is refused", ["status", "extra"], "nonzero", "unexpected"),
    ("stray positional after recover is refused", ["recover", "extra"], "nonzero", "unexpected"),
    ("stray positional after doctor is refused", ["doctor", "extra"], "nonzero", "unexpected"),
    (
        "stray positional after list-apps is refused",
        ["list-apps", "extra"],
        "nonzero",
        "unexpected",
    ),
    (
        "stray positional after unstrict-all is refused",
        ["unstrict-all", "extra"],
        "nonzero",
        "unexpected",
    ),
    # ── every alias: the short forms resolve (and refuse safely) ──────
    ("ss alias resolves (missing target refuses)", ["ss"], "nonzero", "error"),
    ("strict alias resolves (missing target refuses)", ["strict"], "nonzero", "error"),
    ("sm alias resolves (missing targets refuse)", ["sm"], "nonzero", "error"),
    ("sa alias resolves (missing rate refuses)", ["sa"], "nonzero", "no rate specified"),
    ("bs alias resolves (missing target refuses)", ["bs"], "nonzero", "error"),
    ("bm alias resolves (missing targets refuse)", ["bm"], "nonzero", "error"),
    ("block-all typo refuses before any block", ["block-all", "--forse"], "nonzero", "--force"),
    ("ba alias typo refuses before any block", ["ba", "--forse"], "nonzero", "--force"),
    # NOTE: the --forse needles still say "--force" because the
    # suggestion is now "--force-this" (NIGHT-improve-30) and the
    # old needle remains a substring of it.
    ("us alias resolves (missing target refuses)", ["us"], "nonzero", "error"),
    ("unstrict alias resolves (missing target refuses)", ["unstrict"], "nonzero", "error"),
    ("um alias resolves (missing targets refuse)", ["um"], "nonzero", "error"),
    ("ua alias refuses a stray positional", ["ua", "extra"], "nonzero", "unexpected"),
    ("ee alias resolves (bad interval refuses)", ["ee", "--interval", "0s"], "nonzero", "interval"),
]

# The flag-and-command surface this table is CONTRACTED to touch: every
# documented command, alias, and flag string must appear in at least one
# case argv. The self-test pins this rootlessly — a flag added to the
# CLI without a stresstest case shows up as a FAILING PIN on the next
# push, not as an untested surface discovered by an attacker.
CLI_DOCUMENTED_SURFACE = [
    # commands
    "strict-single",
    "strict-multi",
    "strict-all",
    "block-single",
    "block-multi",
    "block-all",
    "unstrict-single",
    "unstrict-multi",
    "unstrict-all",
    "recover",
    "status",
    "list-apps",
    "eagle-eyes",
    "doctor",
    # aliases
    "strict",
    "ss",
    "sm",
    "sa",
    "bs",
    "bm",
    "ba",
    "us",
    "um",
    "ua",
    "ee",
    "unstrict",
    # flags
    "--help",
    "-h",
    "--version",
    "-V",
    "-v",
    "--verbose",
    "--print-json",
    "--color-mode",
    "--check-update",
    "--check-updated",
    "--force-this",
    "--interval",
    "-d",
    "-u",
    "--download",
    "--upload",
]


def _run_cli_case(argv):
    """Run one stresstest case against the real binary.

    stdin is /dev/null and the env carries NO_COLOR=1, so output is
    plain-text deterministic regardless of the harness's own terminal.
    Returns (returncode, combined-output); returncode None means the
    case never answered inside the timeout — a hang, the loudest
    failure a CLI can produce.
    """
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    try:
        p = subprocess.run(
            [lib.BINARY] + argv,
            capture_output=True,
            text=True,
            timeout=CLI_CASE_TIMEOUT,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, ""
    return p.returncode, f"{p.stdout}\n{p.stderr}"


# ── NIGHT-blade-4: the server depth phase (the survival family's half) ─────
#
# The 83-case CLI depth stresstest runs the guards under the
# INHERITED environment; a production server carries none of it (no
# DISPLAY, no DBUS session bus, no XDG desktop variables, TERM=dumb
# at best), so a representative guard subset re-runs under the
# stripped headless environment from v1's engine (one env definition,
# both harnesses). The invariants — every case answers, exits with
# the right class, carries its expected wording, never leaks a panic
# — must hold identically when the desktop is absent: a guard that
# only behaves on a desktop session is a server outage waiting for
# its first SSH session.


def _run_cli_case_headless(argv):
    """_run_cli_case's twin under the stripped server environment
    (NIGHT-blade-4): PATH + TERM=dumb + NO_COLOR, nothing else. stdin
    is /dev/null and every fd is a pipe — the exact stdio shape an
    SSH session with a dead terminal, a cron job, or a container
    entrypoint presents. Returns (returncode, combined-output);
    returncode None means the case never answered (a hang)."""
    env = sm1.server_headless_env()
    env["NO_COLOR"] = "1"
    try:
        p = subprocess.run(
            [lib.BINARY] + argv,
            capture_output=True,
            text=True,
            timeout=CLI_CASE_TIMEOUT,
            stdin=subprocess.DEVNULL,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None, ""
    return p.returncode, f"{p.stdout}\n{p.stderr}"


# (label, argv, exit class, needle) — the same tuple shape
# CLI_DEPTH_CASES speaks, so the runner loop below is the depth
# sweep's own verification logic, reused verbatim.
SERVER_DEPTH_CASES = [
    ("--help answers headless", ["--help"], "zero", "strict-single"),
    ("-V banner headless", ["-V"], "zero", "Architecture: Cosmic Dragon"),
    ("doctor --print-json parses headless", ["doctor", "--print-json"], "zero", '"system"'),
    (
        "retired --info tips --depth headless (NIGHT-blade-4)",
        ["eagle-eyes", "--info"],
        "nonzero",
        "--depth",
    ),
    ("removed eagle-eye redirects headless", ["eagle-eye"], "nonzero", "eagle-eyes"),
    (
        "--check-update refuses root headless",
        ["--check-update"],
        "nonzero",
        "root refused",
    ),
    (
        "live TUI refuses piped stdio headless",
        ["eagle-eyes"],
        "nonzero",
        "interactive monitor",
    ),
    (
        "ee --depth missing-target error headless",
        ["ee", "--depth"],
        "nonzero",
        "--depth needs a TARGET",
    ),
]


def run_server_phase():
    """NIGHT-blade-4: the server depth phase — the guard family under
    the stripped headless environment a production server carries.
    Every case must answer (never hang), exit with the right class,
    carry its expected wording, and leak no panic marker — identical
    contracts to the inherited-env sweep, proven where the desktop is
    absent. Returns True when no case failed."""
    out()
    out("━━━ phase 1/5: server depth (guards under the headless environment) ━━━")
    ok = True
    for label, argv, exit_class, needle in SERVER_DEPTH_CASES:
        rc, text = _run_cli_case_headless(argv)
        problems = []
        if rc is None:
            problems.append(f"no answer within {CLI_CASE_TIMEOUT:.0f}s — a hang")
        else:
            if exit_class == "zero" and rc != 0:
                problems.append(f"exit {rc}, want 0")
            if exit_class == "nonzero" and rc == 0:
                problems.append("exit 0, want non-zero")
            if needle and needle.lower() not in text.lower():
                problems.append(f"expected wording '{needle}' missing")
        low = text.lower()
        for marker in PANIC_MARKERS:
            if marker.lower() in low:
                problems.append(f"panic marker '{marker}' in the output")
        ok = (
            record(
                f"server: {label}",
                "PASS" if not problems else "FAIL",
                f"exit {rc}: {text.strip()[:120]}" if problems else f"exit {rc}",
            )
            == "PASS"
            and ok
        )
    if not ok:
        out()
        out("  server phase FAILED — the survival battery's four phases are skipped.")
    else:
        out()
        out("  server phase green — continuing to the survival battery.")
    return ok


def test_cli_depth():
    """The NIGHT-ultimate-3 depth sweep: every flag surface end to end
    against typo / wrong / ambiguous / injection / fatal input.

    Per-case verdicts plus the two global invariants this stage exists
    to enforce: (1) NO case may hang — fatal usage must answer within
    the timeout; (2) NO case may leak a panic marker — the binary is
    expected to refuse hostile input like a product, not crash like a
    prototype.
    """
    fails = 0
    for label, argv, exit_class, needle in CLI_DEPTH_CASES:
        rc, text = _run_cli_case(argv)
        problems = []
        if rc is None:
            problems.append(f"no answer within {CLI_CASE_TIMEOUT:.0f}s — a hang")
        else:
            if exit_class == "zero" and rc != 0:
                problems.append(f"exit {rc}, want 0")
            if exit_class == "nonzero" and rc == 0:
                problems.append("exit 0, want non-zero")
            if needle and needle.lower() not in text.lower():
                problems.append(f"expected wording '{needle}' missing")
        low = text.lower()
        for marker in PANIC_MARKERS:
            if marker.lower() in low:
                problems.append(f"panic marker '{marker}' in the output")
                break
        verdict = record(
            f"cli depth: {label}",
            "PASS" if not problems else "FAIL",
            "; ".join(problems)
            if problems
            else f"exit {rc}"
            + (f": {(text.strip().splitlines() or [''])[0][:90]}" if text.strip() else ""),
        )
        if verdict != "PASS":
            fails += 1
    total = len(CLI_DEPTH_CASES)
    record(
        f"cli depth: full-sweep invariant ({total} cases, zero hangs, zero panics)",
        "PASS" if fails == 0 else "FAIL",
        f"{total - fails}/{total} cases answered, exited right, and stayed panic-free",
    )
    return fails == 0


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

# NIGHT-hunt-31: the violent-death guard's restore bytes — the exact
# ALT_EXIT contract (src/terminal/screen.rs) the forked guard child
# writes to the pty the instant the SIGKILLed parent's pipe write-end
# closes. The kill battery now proves the TERMINAL restore too, not
# just enforcement survival: every signal-9 death must be followed by
# these bytes on the pty. The leading ESC[0m is the SGR pen reset the
# same night added — the pen state survives the alt-screen switch and
# a mid-frame death would otherwise leave the shell prompt wearing
# the dead monitor's last color.
KILL_TUI_RESTORE_BYTES = b"\x1b[0m\x1b[?1006l\x1b[?1002l\x1b[?1000l\x1b[?1049l\x1b[?25h"
# The settle window for the guard child's post-mortem write: the
# child fires on the pipe EOF within microseconds of the parent's
# death, but a loaded runner deserves a generous margin.
KILL_TUI_GUARD_SETTLE_S = 1.5


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
    guard_ok = 0
    # E2E-workflow hunt (run six): the 5.15 runner reaped 0/5 as -9
    # while the render proof passed — the TUI exited on its own before
    # the SIGKILL landed, and the row said nothing about HOW it exited.
    # Per-cycle evidence (exit code + the pty tail) now rides the
    # failure message: an attach failure shows its branded error line,
    # a quiet death shows the last frame, and the exit code names the
    # path (0 = sink-death, 1 = load/attach error, -N = another
    # signal). The next run convicts, this one only suspects.
    exit_codes = []
    pty_tails = []
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
            pty_bytes = _drain_pty(master, KILL_TUI_RENDER_S)
            proc.kill()  # SIGKILL: the violent death under test
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass  # unreapable child: surfaced by the killed_ok row
            # NIGHT-hunt-31: the restore proof — the forked guard child
            # sees the pipe EOF the instant the parent died and writes
            # the ALT_EXIT contract to the pty. This closes the coverage
            # gap the owner's "still breaks screen" report lived in:
            # the battery proved the enforcement rows survived every
            # kill but never asserted the terminal itself was restored.
            post_kill = _drain_pty(master, KILL_TUI_GUARD_SETTLE_S)
        finally:
            os.close(master)
        exit_codes.append(proc.returncode)
        # The last 2400 bytes decode-safe: the tail is where an attach
        # error prints its branded line (the alt screen restores
        # before the error lands on the main screen). 240, the old
        # window, cropped the BPF verifier log to its last footer
        # line when the 6.8-azure load failed (NIGHT-boost-34's
        # hunt: 'total_states 3 peak_states 3 mark_read 2' with the
        # actual rejection line cut off) — a verdict row that
        # suspects but cannot convict. The full error chain, from
        # branded line through every 'caused by:', now rides whole.
        pty_tails.append(pty_bytes[-2400:].decode("utf-8", "replace").replace("\x1b", "ESC"))
        if pty_bytes:
            rendered_ok += 1
        if proc.returncode == -signal.SIGKILL:
            killed_ok += 1
            # The guard proof rides only the true violent deaths — a
            # cycle where the TUI died on its own (convicted by the
            # killed_ok row with its pty tail) may never have taken
            # the terminal at all, and "no restore bytes" there is
            # correct behavior, not a guard failure.
            if KILL_TUI_RESTORE_BYTES in post_kill:
                guard_ok += 1
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
        + ("" if completed == KILL_TUI_CYCLES else f" (only {completed} cycles ran)")
        + (
            ""
            if killed_ok == completed
            else " — exits: "
            + ", ".join(
                f"c{i + 1}={code} tail='{tail[-800:]}'"
                for i, (code, tail) in enumerate(zip(exit_codes, pty_tails))
                if code != -signal.SIGKILL
            )
        ),
    )
    record(
        "kill tui: terminal restored after every kill (guard bytes)",
        "PASS" if guard_ok == killed_ok and killed_ok == KILL_TUI_CYCLES else "FAIL",
        f"{guard_ok}/{killed_ok} signal-9 deaths received the ALT_EXIT restore bytes"
        + (
            ""
            if killed_ok == KILL_TUI_CYCLES
            else " (not every cycle died by SIGKILL — see the signal-9 row)"
        ),
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
        and guard_ok == killed_ok
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
            "regression: dangerous name still refused without --force-this (systemd)",
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
    # NIGHT-blade-4 pin: the server phase's case list speaks the same
    # 4-tuple shape CLI_DEPTH_CASES speaks (label, argv, exit class,
    # needle), every exit class is one of the two the runner knows,
    # and v1's headless env helper is reachable — a malformed case
    # would crash the runner mid-phase on a root run, so the shape is
    # pinned rootless here.
    cases_ok = all(
        len(case) == 4 and case[2] in ("zero", "nonzero") and case[1] for case in SERVER_DEPTH_CASES
    ) and callable(sm1.server_headless_env)
    ok = (
        record(
            "engine: server depth case list shape (NIGHT-blade-4)",
            "PASS" if cases_ok else "FAIL",
            f"{len(SERVER_DEPTH_CASES)} headless cases, 4-tuple contract",
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
    # NIGHT-ultimate-3 pins: the depth table's own machinery, verified
    # rootlessly with no binary. (1) Well-formedness: every case is a
    # 4-tuple with a legal exit class and a unique label — a malformed
    # row would crash the battery mid-run on a distro. (2) Surface
    # completeness: every documented command, alias, and flag token
    # appears in at least one case argv — a flag added to the CLI
    # without a stresstest case fails this pin on the next push, not in
    # the field. (3) The timeout and panic-marker bounds stay sane.
    well_formed = all(
        isinstance(case, tuple)
        and len(case) == 4
        and case[2] in ("zero", "nonzero", None)
        and isinstance(case[0], str)
        and isinstance(case[1], list)
        for case in CLI_DEPTH_CASES
    )
    labels = [case[0] for case in CLI_DEPTH_CASES]
    well_formed = well_formed and len(labels) == len(set(labels))
    record(
        "engine: cli depth table well-formed (4-tuples, unique labels)",
        "PASS" if well_formed else "FAIL",
        f"{len(CLI_DEPTH_CASES)} cases",
    )
    touched = {tok for _, argv, _, _ in CLI_DEPTH_CASES for tok in argv}
    missing = [entry for entry in CLI_DOCUMENTED_SURFACE if entry not in touched]
    record(
        "engine: cli depth table covers the documented surface",
        "PASS" if not missing else "FAIL",
        f"{len(CLI_DOCUMENTED_SURFACE)} commands/aliases/flags touched"
        if not missing
        else f"never exercised: {', '.join(missing)}",
    )
    bounds_ok = 5.0 <= CLI_CASE_TIMEOUT <= 30.0 and len(PANIC_MARKERS) >= 3
    record(
        "engine: cli depth invariants configured (timeout bound, panic markers)",
        "PASS" if bounds_ok else "FAIL",
        f"timeout {CLI_CASE_TIMEOUT:.0f}s, {len(PANIC_MARKERS)} panic markers",
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


def run_survival(phases):
    """The abuse family in escalation order: server depth first
    (NIGHT-blade-4, the headless guard subset — the owner's phase
    order; a FAIL gates the rest off), then guards (does bad input
    behave?), kills (does violence break anything?), regression (is
    everything that passed before still passing?), teardown (is the
    machine returned clean?). v1's stages carry the preflight; the
    batteries below are v2's own."""
    out("zelynic supermassive test v2 (NIGHT-refactor-2 + NIGHT-blade-4, survival mode)")
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

    # NIGHT-blade-4: the phase pair — server depth first (the owner's
    # order), the four survival phases second; a server-phase FAIL
    # skips them. --desktop-only drops the server phase (the
    # pre-blade-4 battery), --server-only runs it alone.
    total = 5 if "server" in phases else 4
    base = 2 if "server" in phases else 1
    server_ok = True
    if "server" in phases:
        server_ok = run_server_phase()
    if "server" in phases and not server_ok:
        # A server-phase FAIL gates the survival battery off — the
        # owner's phase order cuts both ways.
        return False
    if "desktop" not in phases:
        # --server-only: the server phase green is the verdict (the
        # final report still computes from every recorded row).
        return True

    # phase base/total: the CLI input guards
    out()
    out(f"━━━ phase {base}/{total}: guards (bad input must be refused, never fatal) ━━━")
    test_cli_depth()
    test_rate_guard()

    # phase base+1/total: the brutal battery
    out()
    out(f"━━━ phase {base + 1}/{total}: kills (SIGKILL the TUI and the mid-flight writers) ━━━")
    test_kill_tui()
    test_kill_midflight()

    # phase base+2/total: the regression re-proof
    out()
    out(f"━━━ phase {base + 2}/{total}: regression (nothing broken stays broken) ━━━")
    test_regression_battery()

    # phase base+3/total: the crash-family teardown
    out()
    out(f"━━━ phase {base + 3}/{total}: teardown (recover, cleanup, kernel log) ━━━")
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
    ap.add_argument(
        "--server-only",
        action="store_true",
        help="run only the NIGHT-blade-4 server depth phase (the guard "
        "family under the stripped headless environment)",
    )
    ap.add_argument(
        "--desktop-only",
        action="store_true",
        help="skip the server phase — run only the four survival phases (the pre-blade-4 battery)",
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
    if args.server_only and args.desktop_only:
        out("--server-only and --desktop-only are mutually exclusive — pick a phase pair leg.")
        return 2

    if os.geteuid() != 0:
        out("This test programs the kernel datapath — run with sudo.")
        return 2
    if not lib.resolve_binary(args.binary, "sudo ./scripts/supermassive/supermassive-test-v2.sh"):
        return 2

    start = time.perf_counter()
    sm1.CG = sm1.CgroupSet()
    # NIGHT-blade-4: the phase pair — server depth first (the owner's
    # order), the four survival phases second. The JSON "mode" field
    # stays "survival" for tooling compatibility; the new "phases"
    # list names what actually ran.
    if args.desktop_only:
        phases = ["desktop"]
    elif args.server_only:
        phases = ["server"]
    else:
        phases = ["server", "desktop"]
    exit_code = 1
    try:
        MODE = sm1.CG.setup()
        sm1.MODE = MODE
        sm1.SERVER = sm1.HttpServer()
        ran = run_survival(phases)
        sm1.report_worker_faults()
        ok = (
            lib.final_report(
                start,
                "survival",
                "survival battery green: server depth, CLI guards, SIGKILL "
                "batteries, regression re-proof, teardown — all proven",
            )
            if ran
            else False
        )
        exit_code = 0 if ok else 1
    finally:
        sm1.clear_all()
        if sm1.FLEET is not None:
            sm1.FLEET.teardown()
            sm1.FLEET = None
        if sm1.SERVER:
            sm1.SERVER.stop()
        sm1.CG.cleanup()
    if args.json:
        print(
            json.dumps(
                {
                    "binary": lib.BINARY,
                    "mode": "survival",
                    "phases": phases,
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
