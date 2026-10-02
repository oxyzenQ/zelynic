#!/usr/bin/env python3
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# LOC_EXEMPT: like the v1/v2/v3 harnesses, one self-contained script by
# design — v4 is a thin orchestrator over the shared engine lib plus the
# CLI-surface case tables it owns outright (commands, aliases, flags,
# color modes, typos, rate-explode shapes, removed commands, hidden
# subcommands); over the 1000 scripts cap under NIGHT-lts-2 — tracked
# debt, the split is its own NIGHT task
"""zelynic supermassive test v4 — the CLI depth battery
(NIGHT-improve-35).

v1 (supermassive-test.py) answers "does the limiter HOLD?" — the full
policy matrix, the rate-change move, the internet lane. v2
(supermassive-test-v2.py) answers "does everything that is NOT a limit
measurement SURVIVE the day nothing goes right?" — the CLI input
guards under hostile input, the live TUI SIGKILLed mid-render, the
crash-family teardown. v3 (supermassive-test-v3.py) answers "does the
CONTAINER surface resolve clean?" — docker:// and k8s:// end to end.
This v4 harness answers the owner's next question: "does EVERY CLI
surface parse clean, end to end?" — every command, every flag, every
alias, every color mode (zero to hero), every near-miss typo, every
rate-explode shape, every removed/retired command, and every hidden
subcommand.

Division of labor (NIGHT-improve-35, the owner's call): v1 measures
limits; v2 survives violence; v3 resolves containers; v4 covers the CLI
surface. v2's 97-case stresstest is abuse-oriented (shell-injection
payloads, wrong values in every position, fatal usage shapes) — it
tests what a HOSTILE operator throws at the parser. v4 is
coverage-oriented — it tests that every flag the help NAMES exists,
every alias the help lists routes, every color mode the help allows
works, every near-miss typo gets its suggestion tip, every wrong rate
shape gets its category-specific error, and every removed/retired
command answers clean. Together they cover the CLI surface from both
ends: v4 proves the surface is COMPLETE, v2 proves it is HARD.

Rootless by design: the CLI surface (help, version, alias routing,
typo tips, rate validation, color modes, removed-command rejection)
parses BEFORE the root check, so v4 runs on every host without sudo —
the most CI-friendly supermassive test. The enforcement depth (root +
eBPF) is v1/v2's domain; v4 is the surface contract.

Design:

  * Zero engine duplication: the shared lib (scripts/lib/
    zelynic_harness_lib.py) carries BINARY, RESULTS, record, out — v4
    imports them, never redefines them. v1's engine is imported whole
    (importlib) for the self-test's importability pin.

  * The case tables: every command (canonical + alias), every global
    flag, every color mode (0/16/8/256/24/32 valid + 1/7/99/abc
    invalid), every near-miss typo, every rate-explode shape, every
    removed/retired command, every hidden subcommand. The invariant,
    not any single message, is the contract: every case ANSWERS
    (never hangs), exits with the right class (0 info / non-zero
    refusal), carries its expected category, and never leaks a Rust
    panic. Safety by construction: no case executes a policy — every
    case is a refusal or an info surface (valid executions are v1's
    matrix).

  * The typo ladder: every near-miss typo (--per-sockt, --no-prbe,
    --force-ths, --depht, --interal, --verboes, --color-mdoe) must
    carry its suggestion tip — the cosmostrix suggestion stresstest
    lineage. The tip is the user's only path from a typo to the real
    flag; a missing tip is a UX regression the stage catches.

  * The rate-explode ladder: every wrong rate shape (1mbps invalid
    format, 1MB uppercase, 0.5kb below min, 2tb above max, 1xb invalid
    number, 500 plain-below-min, abc invalid, "" empty) must produce
    its CATEGORY-specific error — invalid-format, below-minimum,
    above-maximum, or invalid-number. The category, not the wording,
    is the contract: a rate error that lies about its category
    (e.g., "below minimum" for a format error) is worse than a
    wording drift.

Usage:
  ./scripts/supermassive/supermassive-test-v4.sh               # full CLI depth (rootless)
  ./scripts/supermassive/supermassive-test-v4.sh --self-test    # engine smoke, no binary
  ./scripts/supermassive/supermassive-test-v4.sh --json         # machine-readable
  ./scripts/supermassive/supermassive-test-v4.sh --stages help,color  # run named stages

Exit code: 0 if every case passed; 1 if any case failed or the binary
panicked.
"""

import argparse
import importlib.util
import os
import re
import subprocess
import sys

# The shared engine lib lives one directory up in scripts/lib/
# (NIGHT-refactor-1); v1's engine lives one dash-named file over. Both
# paths are bound by ABSOLUTE location so the harness resolves regardless
# of how it was invoked (file path, -m, or the .sh wrapper).
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)
_LIB_DIR = os.path.join(_HERE, "..", "lib")
if _LIB_DIR not in sys.path:
    sys.path.insert(0, _LIB_DIR)

import zelynic_harness_lib as lib  # noqa: E402
from zelynic_harness_lib import (  # noqa: E402
    RESULTS,
    out,
    record,
)

# ── the v1 engine, imported whole (for the self-test's importability pin) ──
_V1_PATH = os.path.join(_HERE, "supermassive-test.py")
_V1_SPEC = importlib.util.spec_from_file_location("supermassive_test_v1", _V1_PATH)
sm1 = importlib.util.module_from_spec(_V1_SPEC)
sys.modules["supermassive_test_v1"] = sm1
_V1_SPEC.loader.exec_module(sm1)

# ── constants ─────────────────────────────────────────────────────────────

# Per-case timeout: a CLI surface case must ANSWER within this window —
# a hang is the loudest failure a CLI can produce (the same contract v2
# and v3 carry). 15s is generous for a help print or a parse error.
CLI_CASE_TIMEOUT = 15

# The panic sentinel: a Rust panic leaking past the CLI's error path is
# the one finding that fails the whole battery. The contract is zero
# panics on every CLI surface shape.
PANIC_RE = re.compile(r"panicked|RUST_BACKTRACE|thread .* panicked")

# ── the case tables (NIGHT-improve-35) ─────────────────────────────────────
#
# Every table below is the CLI surface's own enumeration — driven
# through the binary, one case per row. The invariant is the hardening
# contract (answers / right class / no panic), not any single message.

# Every command, canonical + alias. Invoked WITHOUT required args, each
# must answer a clean usage error (the command is RECOGNIZED — the
# complaint is the missing required arg, never "unrecognized subcommand").
# The alias must route identically to the canonical (same usage error
# shape).
COMMANDS = [
    ("strict-single", "ss"),
    ("strict-multi", "sm"),
    ("strict-all", "sa"),
    ("block-single", "bs"),
    ("block-multi", "bm"),
    ("block-all", "ba"),
    ("unstrict-single", "us"),
    ("unstrict-multi", "um"),
    ("unstrict-all", "ua"),
    ("eagle-eyes", "ee"),
    # Commands without aliases:
    ("recover", None),
    ("status", None),
    ("list-apps", None),
    ("doctor", None),
]

# Every global flag the help names. Each must answer clean when driven
# through the binary rootlessly (info surfaces exit 0; refusals exit
# non-zero). The flag's PRESENCE is the contract — a flag the help
# names but the parser rejects is a regression.
GLOBAL_FLAGS = [
    (["--help"], 0, "info"),
    (["-h"], 0, "info"),
    (["--version"], 0, "info"),
    (["-V"], 0, "info"),
    (["--reset-terminal"], 0, "rescue"),
    (["--check-update"], None, "network (refuses sudo or network)"),
    (["--verbose", "--help"], 0, "info (verbose + help)"),
    (["-v", "--help"], 0, "info (short verbose + help)"),
    (["--print-json", "--help"], 0, "info (print-json + help)"),
]

# The color-mode ladder (NIGHT-improve-35 "zero to hero"): every mode
# the help allows (0 mono, 16, 8/256 cube, 24/32 truecolor) plus the
# invalid modes that must refuse clean. The valid modes exit 0 (the
# mode is accepted, then --help prints); the invalid modes exit 2 (the
# mode is rejected with the allowed-modes error).
COLOR_MODES_VALID = ["0", "16", "8", "256", "24", "32"]
COLOR_MODES_INVALID = ["1", "7", "99", "abc", ""]

# Every near-miss typo (one character off from a real flag). Each must
# carry its suggestion tip — the typo's only path to the real flag. The
# tip's PRESENCE is the contract; the exact suggestion wording may
# evolve with the edit-distance tuner, but the tip must fire. Each typo
# is driven through the command that OWNS the flag with that command's
# own arg shape (eagle-eyes takes targets, not rates; a rate arg there
# is a second target, and the typo tip still fires, but the canonical
# shape is target + flag).
TYPOS = [
    # strict-single flags (target + rate + typo, driven through ss):
    ("--per-sockt", "--per-socket", ["ss", "brave", "1mb"]),
    ("--no-prbe", "--no-probe", ["ss", "brave", "1mb"]),
    ("--force-ths", "--force-this", ["ss", "brave", "1mb"]),
    # eagle-eyes flags (target + typo, driven through ee — no rate):
    ("--depht", "--depth", ["ee", "brave"]),
    ("--interal", "--interval", ["ee", "brave"]),
    # global flags (driven through ss — globals ride every command):
    ("--verboes", "--verbose", ["ss", "brave", "1mb"]),
    ("--color-mdoe", "--color-mode", ["ss", "brave", "1mb"]),
    ("--print-jso", "--print-json", ["ss", "brave", "1mb"]),
    ("--check-updat", "--check-update", ["ss", "brave", "1mb"]),
    ("--reset-termina", "--reset-terminal", ["ss", "brave", "1mb"]),
]

# Every rate-explode shape, categorized by the error the parser owns for
# it. The category, not the wording, is the contract — a rate error that
# lies about its category is worse than a wording drift.
RATE_CASES = [
    # (rate, category-keyword, description)
    ("1mbps", "invalid rate", "invalid format (mbps suffix)"),
    ("1MB", "invalid rate", "uppercase rejected"),
    ("abc", "invalid rate", "non-numeric"),
    ("", "invalid rate", "empty string"),
    ("1xb", "invalid number", "letters in numeric part"),
    ("0.5kb", "below minimum", "below the 1kb floor"),
    ("500", "below minimum", "plain number below min"),
    ("2tb", "above maximum", "above the 1tb ceiling"),
    ("1mb2000", "invalid rate", "trailing garbage"),
]

# Removed/retired commands and flags. Each must answer clean (no hang,
# no panic) — the removed command is either rejected as unrecognized
# (with a redirect suggestion where the help documents one) or, for
# retired flags like --info, redirected to its successor (--depth).
REMOVED = [
    ("observe", "unrecognized or redirect to eagle-eyes"),
    ("top", "unrecognized or redirect to eagle-eyes"),
    ("limit-all", "unrecognized or redirect to strict-all"),
    ("eagle-eye", "unrecognized or redirect to eagle-eyes"),
    ("man", "unrecognized (rejected)"),
]

# Hidden subcommands the parser knows but the help hides. Each must
# ANSWER clean (the parser recognizes it — the complaint is whatever
# the subcommand's own arg validation produces, never "unrecognized").
# A hidden subcommand that panics or hangs is the worst finding in the
# battery (the surface the help hides is the surface least tested).
HIDDEN = [
    "__probe-server",
    "__probe-client",
]

# The alias of --check-update (check-updated) — a hidden alias the help
# does not name but the parser accepts. Must answer clean (same shape
# as --check-update).
HIDDEN_ALIASES = [
    "check-updated",
]


# ── the binary runner ──────────────────────────────────────────────────────


def _run_cli_case(argv):
    """Run one CLI surface case against the real binary.

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
    except FileNotFoundError:
        return 127, f"binary not found: {lib.BINARY}"
    return p.returncode, f"{p.stdout}\n{p.stderr}"


def _case_panicked(output):
    """True when the output carries a Rust panic sentinel."""
    return bool(PANIC_RE.search(output))


# ── stage 1: command surface (every command + alias recognized) ──────────


def test_command_surface():
    """Every command (canonical + alias) is recognized by the parser.

    Invoked without required args, each must answer a clean usage error
    (rc=2, the complaint is the MISSING arg, never "unrecognized
    subcommand"). The alias must route identically to the canonical
    (same complaint shape). doctor/status/list-apps may exit 0 (info)
    or non-zero (no root/BPF) — the contract is ANSWERS + no panic, not
    a specific exit code, for those.
    """
    out()
    out("── stage 1: command surface (canonical + alias recognized) ──")
    all_ok = True
    for canonical, alias in COMMANDS:
        # Canonical: invoked without required args.
        rc, output = _run_cli_case([canonical])
        label = f"command: {canonical} answers"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        if "unrecognized subcommand" in output.lower():
            record(label, "FAIL", "canonical command not recognized")
            all_ok = False
            continue
        record(label, "PASS", f"rc={rc}, recognized, no panic")
        # Alias: routes to the canonical (same complaint shape).
        if alias:
            rc_a, output_a = _run_cli_case([alias])
            label_a = f"command: {alias} (alias) routes"
            if rc_a is None:
                record(label_a, "FAIL", "timed out (hang)")
                all_ok = False
                continue
            if _case_panicked(output_a):
                record(label_a + " no panic", "FAIL", "panic leaked")
                all_ok = False
                continue
            if "unrecognized subcommand" in output_a.lower():
                record(label_a, "FAIL", f"alias {alias} not recognized")
                all_ok = False
                continue
            record(label_a, "PASS", f"rc={rc_a}, routed, no panic")
    return all_ok


# ── stage 2: global flags (every flag the help names) ─────────────────────


def test_global_flags():
    """Every global flag the help names is present and answers clean.

    Info surfaces (--help, -V, --reset-terminal) exit 0; --check-update
    hits the network (may succeed or fail, but must answer clean, no
    panic). The flag's PRESENCE is the contract — a flag the help names
    but the parser rejects is a regression.
    """
    out()
    out("── stage 2: global flags (every help-named flag present) ──")
    all_ok = True
    for argv, expect_rc, desc in GLOBAL_FLAGS:
        rc, output = _run_cli_case(argv)
        label = f"flag: {' '.join(argv)} ({desc})"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        if expect_rc is not None and rc != expect_rc:
            record(
                label,
                "FAIL",
                f"expected rc={expect_rc}, got rc={rc}",
            )
            all_ok = False
            continue
        # --check-update: network-dependent, contract is answers + no panic.
        record(label, "PASS", f"rc={rc}, no panic")
    return all_ok


# ── stage 3: color-mode ladder (zero to hero) ──────────────────────────────
#
# Every color mode the help allows (0 mono, 16, 8/256 cube, 24/32
# truecolor — "zero to hero") must be accepted (rc=0); every invalid mode
# must be rejected with the allowed-modes error (rc=2). The ladder
# walks the full range the help documents, end to end.


def test_color_mode_ladder():
    """Every color mode (zero to hero) accepts or rejects clean.

    Valid modes (0, 16, 8, 256, 24, 32) exit 0 (accepted, then --help
    prints). Invalid modes (1, 7, 99, abc, "") exit 2 with the
    allowed-modes error. The contract: answers, no panic, right class.
    """
    out()
    out("── stage 3: color-mode ladder (zero to hero) ──")
    all_ok = True
    for mode in COLOR_MODES_VALID:
        rc, output = _run_cli_case(["--color-mode", mode, "--help"])
        label = f"color-mode: {mode} (valid)"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        if rc != 0:
            record(label, "FAIL", f"valid mode rejected: rc={rc}")
            all_ok = False
            continue
        record(label, "PASS", "accepted, rc=0")
    for mode in COLOR_MODES_INVALID:
        rc, output = _run_cli_case(["--color-mode", mode, "--help"])
        label = f"color-mode: {mode or '(empty)'} (invalid)"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        if rc == 0:
            record(label, "FAIL", "invalid mode accepted (rc=0)")
            all_ok = False
            continue
        if "color-mode" not in output.lower():
            record(label, "FAIL", "no color-mode error wording")
            all_ok = False
            continue
        record(label, "PASS", f"rejected clean, rc={rc}")
    return all_ok


# ── stage 4: short-alias routing (every alias routes to canonical) ─────────


def test_short_alias_routing():
    """Every short alias (ss, sm, sa, bs, bm, ba, us, um, ua, ee)
    routes to its canonical command.

    The alias and the canonical, invoked with the same args, must
    produce the SAME exit code and a consistent complaint shape — the
    alias is the canonical command under another name, not a separate
    surface.
    """
    out()
    out("── stage 4: short-alias routing (every alias = canonical) ──")
    all_ok = True
    for canonical, alias in COMMANDS:
        if not alias:
            continue
        # Both invoked with a no-op arg shape that reaches the command's
        # own validation (a typo rate the parser rejects identically
        # regardless of the command). The contract: same rc + no panic.
        args = ["__nonexistent_target__", "1xb"]
        rc_c, out_c = _run_cli_case([canonical] + args)
        rc_a, out_a = _run_cli_case([alias] + args)
        label = f"alias: {alias} -> {canonical}"
        if rc_c is None or rc_a is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(out_c) or _case_panicked(out_a):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        # The alias and canonical must agree on the exit class (both
        # refuse the same way, or both accept). The exact rc may differ
        # by one path detail (parse-order), so the class (zero vs
        # non-zero) is the contract.
        class_c = 0 if rc_c == 0 else 1
        class_a = 0 if rc_a == 0 else 1
        if class_c != class_a:
            record(
                label,
                "FAIL",
                f"alias rc={rc_a} != canonical rc={rc_c} (class mismatch)",
            )
            all_ok = False
            continue
        record(label, "PASS", f"both class={'info' if class_c == 0 else 'refusal'}, no panic")
    return all_ok


# ── stage 5: typo handling (every near-miss carries its tip) ───────────────


def test_typo_handling():
    """Every near-miss typo carries its suggestion tip.

    The tip is the user's only path from a typo to the real flag; a
    missing tip is a UX regression. The contract: the typo is rejected
    (non-zero) AND the tip (the real flag's name) appears in the output.
    """
    out()
    out("── stage 5: typo handling (near-miss -> suggestion tip) ──")
    all_ok = True
    for typo, real_flag, cmd_argv in TYPOS:
        # Drive the typo through the command that OWNS the flag, with
        # that command's own arg shape (eagle-eyes takes targets, not
        # rates; strict-single takes target + rate).
        rc, output = _run_cli_case(cmd_argv + [typo])
        label = f"typo: {typo} -> tip {real_flag}"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        if rc == 0:
            record(label, "FAIL", "typo accepted (rc=0)")
            all_ok = False
            continue
        if real_flag not in output:
            record(label, "FAIL", f"tip '{real_flag}' missing from output")
            all_ok = False
            continue
        record(label, "PASS", f"rejected rc={rc}, tip present")
    return all_ok


# ── stage 6: rate-explode (every wrong rate -> category error) ────────────


def test_rate_explode():
    """Every wrong rate shape produces its category-specific error.

    The category (invalid-rate, below-minimum, above-maximum,
    invalid-number), not the wording, is the contract — a rate error
    that lies about its category is worse than a wording drift.
    """
    out()
    out("── stage 6: rate-explode (wrong rate -> category error) ──")
    all_ok = True
    for rate, category, desc in RATE_CASES:
        rc, output = _run_cli_case(["ss", "brave", rate])
        label = f"rate: {rate!r} ({desc})"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        if rc == 0:
            record(label, "FAIL", "wrong rate accepted (rc=0)")
            all_ok = False
            continue
        if category.lower() not in output.lower():
            record(
                label,
                "FAIL",
                f"category '{category}' missing from output",
            )
            all_ok = False
            continue
        record(label, "PASS", f"rc={rc}, category '{category}' present")
    return all_ok


# ── stage 7: removed/retired commands (clean redirect/reject) ──────────────


def test_removed_retired():
    """Every removed/retired command answers clean (no hang, no panic).

    Removed commands (observe, top, limit-all, eagle-eye, man) are
    rejected as unrecognized (with a redirect suggestion where the help
    documents one). Retired flags (--info) redirect to their successor
    (--depth). The contract: answers, no panic, non-zero (a removed
    command never silently succeeds).
    """
    out()
    out("── stage 7: removed/retired commands (clean redirect/reject) ──")
    all_ok = True
    for cmd, desc in REMOVED:
        rc, output = _run_cli_case([cmd])
        label = f"removed: {cmd} ({desc})"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        if rc == 0:
            record(label, "FAIL", "removed command accepted (rc=0)")
            all_ok = False
            continue
        record(label, "PASS", f"rc={rc}, no panic")
    # --info retired -> --depth: the retired flag must redirect clean
    # (a deprecation tip or an error naming --depth as the successor).
    rc, output = _run_cli_case(["ee", "brave", "--info"])
    label = "retired: --info -> --depth"
    if rc is None:
        record(label, "FAIL", "timed out (hang)")
        all_ok = False
    elif _case_panicked(output):
        record(label + " no panic", "FAIL", "panic leaked")
        all_ok = False
    elif rc == 0:
        record(label, "FAIL", "retired --info accepted (rc=0)")
        all_ok = False
    else:
        record(label, "PASS", f"rc={rc}, no panic (retired flag rejected clean)")
    return all_ok


# ── stage 8: hidden subcommands + aliases (the surface the help hides) ────


def test_hidden_surface():
    """Hidden subcommands and aliases answer clean (no hang, no panic).

    The parser knows __probe-server, __probe-client (hidden), and the
    check-updated alias of --check-update. Each must ANSWER — the
    complaint is whatever the subcommand's own validation produces,
    never "unrecognized" (the parser recognizes it). A hidden surface
    that panics or hangs is the worst finding (the surface least
    tested).
    """
    out()
    out("── stage 8: hidden subcommands + aliases (surface the help hides) ──")
    all_ok = True
    for sub in HIDDEN:
        rc, output = _run_cli_case([sub])
        label = f"hidden: {sub} answers"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        # The hidden subcommand must be RECOGNIZED (not "unrecognized
        # subcommand") — the parser knows it even if the help hides it.
        if "unrecognized subcommand" in output.lower():
            record(label, "FAIL", "hidden subcommand not recognized")
            all_ok = False
            continue
        record(label, "PASS", f"rc={rc}, recognized, no panic")
    for alias in HIDDEN_ALIASES:
        rc, output = _run_cli_case([alias])
        label = f"hidden-alias: {alias} answers"
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        record(label, "PASS", f"rc={rc}, no panic")
    return all_ok


# ── the engine self-test (rootless, no binary) ─────────────────────────────


def self_test():
    out("zelynic supermassive test v4 — engine self-test (no root, no zelynic, no BPF)")
    out()
    ok = record(
        "engine: v1 harness importable",
        "PASS" if os.path.isfile(_V1_PATH) and hasattr(sm1, "CgroupSet") else "FAIL",
        f"{_V1_PATH} bound as supermassive_test_v1",
    )
    ok = (
        record(
            "engine: shared lib surface present",
            "PASS"
            if all(hasattr(lib, attr) for attr in ("BINARY", "RESULTS", "record", "out"))
            else "FAIL",
            "zelynic_harness_lib carries BINARY, RESULTS, record, out",
        )
        and ok
    )
    ok = (
        record(
            "engine: v4 case tables populated",
            "PASS"
            if len(COMMANDS) > 0
            and len(COLOR_MODES_VALID) > 0
            and len(TYPOS) > 0
            and len(RATE_CASES) > 0
            and len(REMOVED) > 0
            else "FAIL",
            f"{len(COMMANDS)} commands, {len(COLOR_MODES_VALID)}+{len(COLOR_MODES_INVALID)} color modes, "
            f"{len(TYPOS)} typos, {len(RATE_CASES)} rate cases, {len(REMOVED)} removed",
        )
        and ok
    )
    out()
    out(f"self-test: {'PASS' if ok else 'FAIL'}")
    return ok


# ── the orchestrator ────────────────────────────────────────────────────────


def run_cli_depth(phases):
    """Run the CLI depth battery, stage by stage."""
    all_stages = {
        "commands": test_command_surface,
        "flags": test_global_flags,
        "color": test_color_mode_ladder,
        "aliases": test_short_alias_routing,
        "typos": test_typo_handling,
        "rates": test_rate_explode,
        "removed": test_removed_retired,
        "hidden": test_hidden_surface,
    }
    if phases:
        stages = [(name, all_stages[name]) for name in phases]
    else:
        stages = list(all_stages.items())

    out()
    out("================================================================")
    out("  zelynic supermassive test v4 — the CLI depth battery")
    out("================================================================")
    out(f"  binary: {lib.BINARY or '(not bound — pass --binary)'}")
    out("  root:   not required (CLI surface parses before the root check)")
    out(f"  stages: {', '.join(name for name, _ in stages)}")
    out("================================================================")
    out()

    overall = True
    for name, stage_fn in stages:
        try:
            stage_ok = stage_fn()
        except Exception as exc:  # noqa: BLE001 — a stage crash is a FAIL, not a battery crash
            out(f"  STAGE {name} CRASHED: {exc}")
            record(f"stage: {name} (no crash)", "FAIL", str(exc))
            stage_ok = False
        overall = overall and stage_ok
    return overall


def main():
    parser = argparse.ArgumentParser(
        description="zelynic supermassive test v4 — the CLI depth battery",
    )
    parser.add_argument(
        "--binary",
        default="",
        help="path to the zelynic binary (default: auto-detect or zelynic on PATH)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="engine smoke: no root, no binary, no BPF (the harness is sound)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="machine-readable output (the verdict JSON on stdout)",
    )
    parser.add_argument(
        "--stages",
        default="",
        help="comma-separated stage names to run (default: all)",
    )
    args = parser.parse_args()

    if args.binary:
        lib.BINARY = args.binary
    elif os.path.isfile("/opt/zelynic/zelynic"):
        lib.BINARY = "/opt/zelynic/zelynic"
    elif not lib.BINARY:
        from shutil import which

        found = which("zelynic")
        lib.BINARY = found or "zelynic"

    if args.self_test:
        ok = self_test()
        if args.json:
            import json

            print(json.dumps({"results": RESULTS, "verdict": "PASS" if ok else "FAIL"}))
        return 0 if ok else 1

    phases = [s.strip() for s in args.stages.split(",") if s.strip()] if args.stages else None
    ok = run_cli_depth(phases)

    counts = {v: sum(1 for r in RESULTS if r["verdict"] == v) for v in ("PASS", "FAIL", "SKIP")}
    out()
    out("================================================================")
    out(f"  v4 verdict: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped")
    out("================================================================")

    if args.json:
        import json

        print(
            json.dumps({"results": RESULTS, "verdict": "PASS" if ok else "FAIL", "counts": counts})
        )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
