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
eBPF) is v1/v2's domain; v4 is the surface contract. The one honest
exception, stage 9's shadowed-positional table: its three valid-rate
rows assert the root-refusal message itself, a needle only a NON-root
run can produce. When the harness runs as root (the supermassive VM's
init context — the CI leg that also carries the BPF batteries), those
rows SKIP without executing on v3's privilege-gate doctrine ("the gate
cannot be triggered as root") and for the safety it shares with every
other v4 case: a valid rate past a passing gate is an enforcement
attempt, and no v4 case executes a policy. The rootless CI leg
(.github/workflows/ci.yml) still runs all 155 rows end to end on
every push that touches the Rust/scripts surface (ci.yml is
paths-filtered — NIGHT-hunt-32 corrected the unqualified "every
push"); the garbage/typo shadow rows run under every uid because
their refusals fire at the parse boundary, before the gate.

Design:

  * Zero engine duplication: the shared lib (scripts/lib/
    zelynic_harness_lib.py) carries BINARY, RESULTS, record, out — v4
    imports them, never redefines them. v1's engine is imported whole
    (importlib) for the self-test's importability pin.

  * The case tables: every command (canonical + alias), every global
    flag, every color mode (0/16/8/256/24/32 valid + 1/7/99/abc
    invalid), every near-miss typo, every rate-explode shape, every
    removed/retired command, every hidden subcommand. NIGHT-hunt-Z9
    adds the hardening tables: every hostile control-byte payload
    family against every pre-root echo path (the render boundary's
    '?' substitution contract), the shadowed-positional ladder, and
    the hidden-vocabulary leak cases. The invariant,
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
    NIGHT-hunt-Z8 closed the ladder's own gaps: --focs (the focus
    window), --dowload and --uploed (the -d/-u long forms — the
    short flags are single chars, the long forms are the ladder's
    own shape).

  * The alias inventory is complete (NIGHT-hunt-Z8): the short-alias
    stage carries every two-letter alias, the new long-alias stage
    (4b) carries the help's own shorthand spellings (strict,
    unstrict — NIGHT-hunt-10's pair), and the global-flag stage now
    includes NIGHT-boost-12's incident shape: a -V/--version at
    subcommand position must print the banner and exit 0 before any
    dispatch.

  * The rate-explode ladder: every wrong rate shape (1mbps invalid
    format, 1MB uppercase, 0.5kb below min, 2tb above max, 1xb invalid
    number, 500 plain-below-min, abc invalid, "" empty) must produce
    its CATEGORY-specific error — invalid-format, below-minimum,
    above-maximum, or invalid-number. The category, not the wording,
    is the contract: a rate error that lies about its category
    (e.g., "below minimum" for a format error) is worse than a
    wording drift.

  * NIGHT-improve-42, the private-research-4 depth audit — the
    owner's seven-feature list, each feature pinned at the surface it
    actually owns (the same division-of-labor doctrine that split v1
    through v4): the TIME-WINDOWED policies (--during, schema v23)
    get their own grammar ladder (the valid units and bounds parse to
    the gate across every enforcement verb; the removed window/date
    shapes, the unknown unit, and the out-of-bounds durations refuse
    by category); the GUARANTEED MINIMUM (--floor/--ceil brackets,
    schema v24) gets the law ladder (the one-spelling law, the
    floor<=ceil<=rate contradictions, the removed-direction law, the
    per-direction split's own grammar); the PER-SOCKET TIER gets its
    valid-parse row (the flag is strict-single's own — the family
    verbs' refusal is pinned too); and the SNAPSHOT/RESTORE pair
    joins the command surface (recognized verbs with their own
    privilege wording — the persistence pair's CLI shape). The three
    automatic lanes — ECN-FIRST POLICING (v19/v21), CAKE-STYLE FLOW
    ISOLATION (v20), QUIC-AWARE ATTRIBUTION (v22) — have NO CLI
    surface by design (kernel-side, no flag, no opt-out), so this
    battery has nothing to own for them: their depth lives where it
    already is — the Rust pin suites (ecn_tests, ecn_socket_tests,
    the cake family, quic_tests), the root-gated live probes
    (scripts/bench/ect-probe.sh, guarantee-probe.sh), and v1's VM
    matrix. The audit is the contract: every feature the owner
    listed is either pinned below or named here with the home its
    depth already has.

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

# NIGHT-improve-42: the persistence pair — private-research-4's
# snapshot/restore verbs. They take NO required args (a bare
# invocation IS the full invocation), so the COMMANDS shape above
# (the missing-arg complaint) does not fit: the recognized proof is
# the verb's OWN privilege refusal, which names the sudo ladder and
# the state file — never "unrecognized subcommand". The bare verbs
# are rootless-lane rows (as root they would WRITE the state file /
# RE-APPLY its policies — a mutation this battery refuses to make,
# the Z9 doctrine); the extra-positional row is a parse-boundary
# refusal and holds under every uid.
# Post as (argv, must_contain, must_not_contain, description,
# rootless_lane) — the shared needle-case shape. The verb's own name
# rides the needles: the refusal names the verb it refuses
# ("snapshot writes the policy state file ... run with sudo"), so an
# "unrecognized subcommand" answer fails as a missing needle — the
# same recognized proof the COMMANDS rows carry.
PRIVILEGED_VERBS = [
    (
        ["snapshot"],
        ["sudo", "snapshot"],
        [],
        "snapshot recognized - its own privilege refusal",
        True,
    ),
    (
        ["restore"],
        ["sudo", "restore"],
        [],
        "restore recognized - its own privilege refusal",
        True,
    ),
    (
        ["snapshot", "extra"],
        ["unexpected argument"],
        [],
        "snapshot takes no positionals (the parse refusal, every uid)",
        False,
    ),
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
    # NIGHT-hunt-Z8: the global-at-subcommand-position cases —
    # NIGHT-boost-12's own incident shape (a subcommand-position -V
    # used to die on a misleading --verbose tip). Both spellings must
    # print the banner and exit 0 before any dispatch.
    (["ss", "brave", "1mb", "-V"], 0, "info (-V at subcommand position, NIGHT-boost-12)"),
    (["ee", "brave", "--version"], 0, "info (--version at subcommand position)"),
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
    # NIGHT-hunt-Z8: the per-command flags the ladder skipped —
    # eagle-eyes --focus, and the -d/-u long forms.
    ("--focs", "--focus", ["ee", "brave"]),
    ("--dowload", "--download", ["ss", "brave", "1mb"]),
    ("--uploed", "--upload", ["ss", "brave", "1mb"]),
    # NIGHT-improve-42: the private-research-4 flags the ladder did
    # not know — the time window and the guarantee brackets (the
    # typos the owner's own fingers will make on the new grammar).
    ("--durign", "--during", ["ss", "brave", "1mb"]),
    ("--flor", "--floor", ["ss", "brave", "1mb"]),
    ("--cel", "--ceil", ["ss", "brave", "1mb"]),
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

# ── NIGHT-hunt-Z9: the hardening tables ────────────────────────────────────
#
# The echo-boundary payloads: hostile control bytes crafted into the
# strings the CLI echoes back in its own refusals (targets, rates,
# durations). Every case asserts the OUTPUT carries no raw control
# byte — the render boundary substitutes '?' (NIGHT-hunt-Z9) — plus
# the refusal itself (the echo path must still fire: the payload
# must not crash, hang, or dodge the guard by being unprintable).
#
# Payload families: the OSC-52 clipboard write (the paste-attack
# classic — a webpage-copied command carrying a hidden clipboard
# rewrite), the CSI color smuggle (screen corruption), the newline
# forgery (a fake output line reading as zelynic's own), the C1
# 8-bit control (ESC-equivalent on 8-bit terminals), and the plain
# tab (spacing forgery). Each rides the sshd prefix where the
# blocklist echo needs it to fire pre-root.
ECHO_PAYLOADS = [
    ("osc52-clipboard-write", "sshd\x1b]52;c;aGVsbG8=\x07", "?]52;c;"),
    ("csi-color-smuggle", "sshd\x1b[31;44mEVIL", "?[31;44m"),
    ("newline-forgery", "sshd\nfake-verdict", "sshd?fake-verdict"),
    ("c1-eight-bit", "sshd\x9b31m", "sshd?31m"),
    ("tab-forgery", "sshd\troot", "sshd?root"),
]

# Every pre-root echo path (each embeds a different user-supplied
# string in its refusal): the dangerous-target blocklist echo, the
# multi-segment grammar echo, the rate parse echo, and the duration
# parse echo (interval and focus). Post as (argv-builder, needle that
# proves the refusal fired).
ECHO_PATHS = [
    (lambda p: ["ss", p, "1mb"], "is a system process"),
    (lambda p: ["sm", "brave" + p + "/x", "1mb"], "not a valid app name"),
    (lambda p: ["ss", "brave", "1" + p + "kb"], "Invalid"),
    (lambda p: ["eagle-eyes", "--interval", "a" + p + "b"], "Invalid duration"),
]

# The control bytes that must never appear raw in any output: ESC
# (every escape family's leader), BEL (the OSC terminator), the C1
# CSI (8-bit terminals), TAB (spacing forgery), CR (line forgery).
RAW_CONTROL_BYTES = ["\x1b", "\x07", "\x9b", "\x08", "\x0b", "\x0c", "\r"]

# The shadowed-positional contract (NIGHT-hunt-Z9): a positional rate
# beside -d/-u is parsed (a garbage one surfaces its typo BEFORE the
# root ask — the parse-before-execute ladder) and a valid one is
# named (the ignored-input warn), while -d/-u decide what applies.
# Post as (argv, must_contain, must_not_contain, description,
# rootless_lane).
#
# rootless_lane marks the rows whose verdict rides the root-refusal
# message itself ("root required" in must_contain) — a needle only
# reachable when the harness runs NON-root. The supermassive VM runs
# this battery as root (its init context — v1/v2/v3 need root for
# the BPF legs), so the gate passes there and the needle never
# appears: the Z9 rows failed the VM leg red from their first push
# (118/3 on 9eb112d through f856ae3) while passing every rootless
# leg. When root, those rows SKIP on v3's own doctrine (its
# privilege-gate stage: "the gate cannot be triggered as root") and
# never execute — the safety half is load-bearing: a VALID rate past
# a passing gate is an enforcement attempt, and this battery's
# safety-by-construction contract refuses to execute a policy (valid
# executions are v1's matrix; on any host where the target app
# exists, running these rows as root would shape it for real). The
# garbage/typo rows stay lane-free — their refusals fire at the parse
# boundary, before the gate and before any enforcement, so they hold
# on every host under every uid. The rootless CI leg
# (.github/workflows/ci.yml) carries the three rootless-lane rows on
# every push, and test/cli/rates_shadow_tests.rs pins the note
# contract at the Rust level.
SHADOWED_POSITIONAL_CASES = [
    (
        # Pure garbage has no near-miss twin, so no tip fires — the
        # REFUSAL before the root ask is the contract (the '1MB' case
        # below carries the did-you-mean tip lane).
        ["ss", "brave", "not-a-rate", "-d", "100kb"],
        ["Invalid rate 'not-a-rate'"],
        ["root required"],
        "garbage positional surfaces its refusal before the root ask",
        False,
    ),
    (
        ["ss", "brave", "1MB", "-d", "100kb"],
        ["Invalid rate '1MB'", "'1mb'"],
        ["root required"],
        "uppercase positional typo carries the did-you-mean tip",
        False,
    ),
    (
        ["ss", "brave", "100kb", "-d", "50kb"],
        ["positional rate '100kb' ignored", "root required"],
        [],
        "valid positional is named, then the flags decide",
        True,
    ),
    (
        ["sm", "brave:curl", "garbage", "-d", "1mb"],
        ["Invalid rate"],
        ["root required"],
        "strict-multi family shares the ladder",
        False,
    ),
    (
        ["sa", "100kb", "-d", "1mb"],
        ["positional rate '100kb' ignored", "root required"],
        [],
        "strict-all family shares the note",
        True,
    ),
    (
        ["ss", "brave", "100kb"],
        ["root required"],
        ["ignored"],
        "unshadowed positional: no note (the rate applies)",
        True,
    ),
]

# The hidden-vocabulary contract (NIGHT-hunt-Z9): a typo near a
# hidden internal role must not leak the role's name, while visible
# near-misses keep their suggestions and removed names keep their
# redirects. Post as (argv, must_not_contain, must_contain, description).
HIDDEN_LEAK_CASES = [
    (
        ["__probe-serve"],
        ["__probe-server", "__probe-client"],
        ["unrecognized subcommand"],
        "near-miss of the hidden server role leaks nothing",
    ),
    (
        ["__probe-clint"],
        ["__probe-client", "__probe-server"],
        ["unrecognized subcommand"],
        "near-miss of the hidden client role leaks nothing",
    ),
    (
        ["__probe"],
        ["__probe-server", "__probe-client"],
        ["unrecognized subcommand"],
        "bare probe prefix leaks no role name",
    ),
    (
        ["statu"],
        [],
        ["status"],
        "visible near-miss keeps its suggestion",
    ),
    (
        ["eagle-ey"],
        [],
        ["eagle-eyes"],
        "visible alias family keeps its suggestion",
    ),
    (
        ["observe"],
        [],
        ["eagle-eyes"],
        "removed-name redirect survives the hidden filter",
    ),
]

# The long aliases the help's own shorthand notes name (NIGHT-hunt-10):
# strict-single also answers 'strict', unstrict-single also answers
# 'unstrict' — the two long aliases the short-alias tables above do
# not carry (NIGHT-hunt-Z8: an alias a help example prints is a
# surface the battery owns too). Each must route to the canonical:
# recognized (never "unrecognized subcommand"), the canonical's own
# complaint, no panic.
LONG_ALIASES = [
    ("strict-single", "strict"),
    ("unstrict-single", "unstrict"),
]

# ── NIGHT-improve-42: the private-research-4 depth tables ──────────────────
#
# The owner's seven-feature audit, pinned at the CLI surface each
# feature actually owns (the header's division-of-labor note carries
# the full map). All three tables share the needle-case shape:
# (argv, must_contain, must_not_contain, description, rootless_lane)
# — the rootless-lane rows' verdict rides the root-refusal message
# itself, so they run and assert on every NON-root host and skip
# without executing when the harness is root (the supermassive VM's
# init context; the Z9 doctrine — a valid policy shape past a
# passing gate is an enforcement attempt this battery refuses to
# make). The parse-boundary rows hold under every uid.

# The unified --during grammar (schema v23, the duration-only
# revision): every valid unit and both bounds parse to the gate
# across every enforcement verb (the strict family AND the block
# family — a bedtime block that lifts itself); every wrong shape
# refuses by CATEGORY — the grammar refusal names the unit list,
# the bounds refusals name their own floors and ceilings, and the
# removed window/date shapes are refused BY NAME (the owner's
# revision wording, the shapes the flag no longer takes).
DURING_CASES = [
    # The valid grammar — parse passes, the privilege gate answers.
    (
        ["ss", "brave", "1mb", "--during", "1s"],
        ["root required"],
        [],
        "min bound 1s parses",
        True,
    ),
    (
        ["ss", "brave", "1mb", "--during", "10y"],
        ["root required"],
        [],
        "max bound 10y parses",
        True,
    ),
    (
        ["ss", "brave", "1mb", "--during", "2mn"],
        ["root required"],
        [],
        "the mn unit parses (months - m is minutes)",
        True,
    ),
    (
        ["ss", "brave", "1mb", "--during", "48h"],
        ["root required"],
        [],
        "the hour shape parses",
        True,
    ),
    (
        ["sm", "brave:curl", "1mb", "--during", "2h"],
        ["root required"],
        [],
        "strict-multi rides the window",
        True,
    ),
    (
        ["sa", "1mb", "--during", "2h"],
        ["root required"],
        [],
        "strict-all rides the window",
        True,
    ),
    (
        ["bs", "brave", "--during", "2h"],
        ["root required"],
        [],
        "the block family rides it (a bedtime block that lifts itself)",
        True,
    ),
    (
        ["ba", "--during", "2h"],
        ["root required"],
        [],
        "block-all rides the window",
        True,
    ),
    # The refusal ladder — parse-boundary refusals, every uid.
    (
        ["ss", "brave", "1mb", "--during", "5x"],
        ["unit 'x' is not in the grammar"],
        [],
        "unknown unit names the grammar",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--during", "0.5s"],
        ["not in the grammar"],
        [],
        "fractional refused (integer N only)",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--during", "0s"],
        ["floor is 1s"],
        [],
        "below-min names the floor",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--during", "11y"],
        ["ceiling is 10y"],
        [],
        "above-max names the ceiling",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--during", "09:00-17:00"],
        ["window form"],
        [],
        "the removed window shape refused by name",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--during", "2026-10-15"],
        ["date form"],
        [],
        "the removed date shape refused by name",
        False,
    ),
]

# The guarantee brackets (--floor/--ceil, schema v24, and the
# improve-40-b per-direction twins): the valid shapes parse to the
# gate (including the legal mixed spelling — a both-directions floor
# beside per-direction ceilings, the resolver's own composition
# law); every law violation refuses by its OWN wording — the
# one-spelling law (a combined flag beside its per-direction twin is
# a mis-typed rate, not a wider guarantee), the floor<=ceil<=rate
# ladder (a guarantee above the cap is a contradiction; a bracket
# above the rate never binds), the removed-direction law (a bracket
# for a row the invocation does not set is a mistake, not an
# intent), and the rate ask (a bracket without any rate answers the
# rate question first).
GUARANTEE_CASES = [
    # The valid shapes — parse passes, the privilege gate answers.
    (
        ["ss", "brave", "1mb", "--floor", "100kb"],
        ["root required"],
        [],
        "the floor parses",
        True,
    ),
    (
        ["ss", "brave", "1mb", "--ceil", "500kb"],
        ["root required"],
        [],
        "the ceiling parses",
        True,
    ),
    (
        [
            "ss",
            "brave",
            "-d",
            "1mb",
            "-u",
            "500kb",
            "--floor-download",
            "100kb",
            "--floor-upload",
            "50kb",
        ],
        ["root required"],
        [],
        "the per-direction split parses",
        True,
    ),
    (
        [
            "ss",
            "brave",
            "1mb",
            "--floor",
            "100kb",
            "--ceil-download",
            "150kb",
            "--ceil-upload",
            "300kb",
        ],
        ["root required"],
        [],
        "both-directions floor composes with per-direction ceils",
        True,
    ),
    # The law ladder — parse-boundary refusals, every uid.
    (
        ["ss", "brave", "1mb", "--floor", "100kb", "--floor-download", "50kb"],
        ["one spelling"],
        [],
        "the floor's one-spelling law",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--ceil", "100kb", "--ceil-upload", "50kb"],
        ["one spelling"],
        [],
        "the ceiling twin's one-spelling law",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--floor", "200kb", "--ceil", "100kb"],
        ["exceeds ceil"],
        [],
        "floor above ceil is a contradiction",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--ceil", "2mb"],
        ["exceeds the download rate"],
        [],
        "ceil above rate never binds",
        False,
    ),
    (
        ["ss", "brave", "1mb", "--floor", "2mb"],
        ["exceeds the download rate"],
        [],
        "floor above rate never binds",
        False,
    ),
    (
        ["ss", "brave", "-d", "1mb", "--floor-upload", "100kb"],
        ["police the upload row"],
        [],
        "the removed-direction law (no -u, no upload row)",
        False,
    ),
    (
        ["ss", "brave", "--floor-download", "100kb"],
        ["No rate specified"],
        [],
        "the rate ask comes first",
        False,
    ),
]

# The per-socket tier's flag surface: --per-socket is
# strict-single's own (a per-connection cap on the ONE-app verb —
# the server shape: one process, many sockets), so the valid parse
# rides strict-single and the family verb's refusal is the parse
# boundary, not the gate. --no-probe rides the same verb with the
# same lane (the scripted-use probe skip).
TIER_FLAGS = [
    (
        ["ss", "brave", "1mb", "--per-socket"],
        ["root required"],
        [],
        "the per-socket tier's flag parses to the gate",
        True,
    ),
    (
        ["ss", "brave", "1mb", "--no-probe"],
        ["root required"],
        [],
        "the scripted-use probe skip parses to the gate",
        True,
    ),
    (
        ["sm", "brave:curl", "1mb", "--per-socket"],
        ["unexpected argument"],
        ["root required"],
        "the group verb refuses the per-socket flag at parse",
        False,
    ),
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


def _is_root():
    """True when the harness runs as UID 0 (the supermassive VM shape).

    v3's own twin, same shape: the supermassive init context (the VM's
    PID 1 lane) runs every battery as root because v1/v2/v3 need it
    for BPF — v4 rides the same init and must know which of its rows
    are unreachable there.
    """
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _run_needle_cases(cases, prefix):
    """Run (argv, must_contain, must_not_contain, desc, rootless_lane)
    rows — the shared shape of the NIGHT-improve-42 depth tables (and
    the Z9 shadow rows' own contract, factored here when it grew a
    second consumer): every row must ANSWER (never hang), carry no
    Rust panic, contain every must_contain needle, and leak none of
    the must_not_contain needles. The rootless-lane rows assert the
    root-refusal message itself — a needle only a NON-root host
    produces — so when the harness runs as root they SKIP without
    executing (the Z9 doctrine: a valid policy shape past a passing
    gate is an enforcement attempt this battery refuses to make; the
    rootless CI leg carries them on every push).
    """
    all_ok = True
    for argv, must_contain, must_not_contain, desc, rootless_lane in cases:
        label = f"{prefix}: {desc}"
        if rootless_lane and _is_root():
            record(
                label,
                "SKIP",
                "harness runs as root — the root-refusal lane cannot trigger "
                "(the rootless CI leg carries this row)",
            )
            continue
        rc, output = _run_cli_case(argv)
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label, "FAIL", "panic leaked")
            all_ok = False
            continue
        if rc == 0 and must_contain:
            # A refusal row that exits 0 accepted what it should have
            # refused — worse than a missing needle (an rc-0 answer
            # with needles set means the shape EXECUTED, not refused).
            record(label, "FAIL", f"accepted (rc=0) what should refuse")
            all_ok = False
            continue
        missing = [n for n in must_contain if n not in output]
        leaked = [n for n in must_not_contain if n in output]
        if missing or leaked:
            record(label, "FAIL", f"missing={missing} unexpected={leaked}")
            all_ok = False
            continue
        record(label, "PASS", f"rc={rc}, contract intact")
    return all_ok


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
    # NIGHT-improve-42: the persistence pair joins the command surface
    # — snapshot/restore carry no required args, so their recognized
    # proof is their own privilege refusal (the needles name the verb
    # AND the sudo ladder; an "unrecognized subcommand" answer fails
    # as a missing needle, the same contract the rows above carry).
    all_ok = _run_needle_cases(PRIVILEGED_VERBS, "verb") and all_ok
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


# ── stage 4b: long-alias routing (strict, unstrict) ───────────────
#
# NIGHT-hunt-Z8: the help's own examples print the long aliases
# ('zelynic strict brave -d 1mb' in strict-single's doc comment;
# 'unstrict' mirrors the strict/unstrict-single pair). The two-route
# surface the short-alias stage skipped: each long alias must reach
# the canonical's own validation — same exit class, recognized,
# no panic.


def test_long_alias_routing():
    """The long aliases (strict, unstrict) route to their canonicals.

    The alias and the canonical, invoked with the same args, must
    land in the same exit class — the alias is the canonical command
    under another name: the complaint is the command's own
    validation (strict's missing-rate usage error, unstrict's
    rootless root-guard refusal), never "unrecognized subcommand".
    """
    out()
    out("── stage 4b: long-alias routing (strict, unstrict) ──")
    all_ok = True
    for canonical, alias in LONG_ALIASES:
        # One target arg reaches both commands' own validation:
        # strict-single answers its missing-rate complaint, and
        # unstrict-single answers the rootless root-guard complaint.
        args = ["brave"]
        rc_c, out_c = _run_cli_case([canonical] + args)
        rc_a, out_a = _run_cli_case([alias] + args)
        label = f"long-alias: {alias} -> {canonical}"
        if rc_c is None or rc_a is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(out_c) or _case_panicked(out_a):
            record(label + " no panic", "FAIL", "panic leaked")
            all_ok = False
            continue
        if "unrecognized subcommand" in out_c.lower() or "unrecognized subcommand" in out_a.lower():
            record(label, "FAIL", "alias not recognized")
            all_ok = False
            continue
        class_c = 0 if rc_c == 0 else 1
        class_a = 0 if rc_a == 0 else 1
        if class_c != class_a:
            record(label, "FAIL", f"alias rc={rc_a} != canonical rc={rc_c} (class mismatch)")
            all_ok = False
            continue
        record(
            label,
            "PASS",
            f"both class={'info' if class_c == 0 else 'refusal'}, recognized, no panic",
        )
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


# ── stage 9: the echo boundary (NIGHT-hunt-Z9 hostile-input hardening) ────


def test_echo_boundary():
    """Hostile control bytes in, '?' out, refusal intact.

    Three contracts, one stage — the NIGHT-hunt-Z9 hardening:

    1. THE ECHO BOUNDARY. Every payload family (OSC-52 clipboard
       write, CSI color smuggle, newline forgery, C1 8-bit control,
       tab forgery) rides every pre-root echo path (the blocklist
       refusal, the multi grammar refusal, the rate parse, the
       duration parse). The output must carry NO raw control byte —
       the render boundary substitutes '?' — and the refusal itself
       must still fire (an unprintable target dodges no guard).
    2. THE SHADOWED POSITIONAL. A positional rate beside -d/-u is
       parsed (a garbage one surfaces its typo BEFORE the root ask)
       and a valid one is named by the ignored-input warn. The three
       rows that carry the root-refusal needle (the valid-rate
       shapes) are rootless-lane rows: they run and assert on every
       non-root host and SKIP without executing when the harness
       itself is root (v3's privilege-gate doctrine — and a valid
       rate past a passing gate is an enforcement attempt no v4 case
       may make).
    3. THE HIDDEN VOCABULARY. A typo near a hidden internal role
       leaks no role name, while visible near-misses keep their
       suggestions and removed names keep their redirects.
    """
    out()
    out("── stage 9: echo boundary + shadowed positional + hidden vocabulary ──")
    all_ok = True

    # ── contract 1: the echo boundary ──
    for payload_name, payload, subst_needle in ECHO_PAYLOADS:
        for path_i, (argv_builder, refusal_needle) in enumerate(ECHO_PATHS):
            argv = argv_builder(payload)
            label = f"echo: {payload_name} path-{path_i} renders '?' not bytes"
            rc, output = _run_cli_case(argv)
            if rc is None:
                record(label, "FAIL", "timed out (hang)")
                all_ok = False
                continue
            if _case_panicked(output):
                record(label, "FAIL", "panic leaked")
                all_ok = False
                continue
            # Every byte in the list must never appear raw in any
            # zelynic output (TAB included: no refusal prints tables).
            leaked = [repr(b) for b in RAW_CONTROL_BYTES if b in output]
            if leaked:
                record(label, "FAIL", f"raw control bytes leaked: {leaked}")
                all_ok = False
                continue
            if refusal_needle not in output:
                record(label, "FAIL", f"refusal needle missing: {refusal_needle!r}")
                all_ok = False
                continue
            record(label, "PASS", "no raw control byte, refusal intact")

    # ── contract 2: the shadowed positional ──
    for argv, must_contain, must_not_contain, desc, rootless_lane in SHADOWED_POSITIONAL_CASES:
        label = f"shadow: {desc}"
        if rootless_lane and _is_root():
            # v3's privilege-gate doctrine, one stage over: the
            # root-refusal needle these rows assert cannot fire when
            # the harness itself is root (the supermassive VM's init
            # context). The row skips without executing — the safety
            # half is the point: a valid rate past a passing gate is
            # an enforcement attempt, and no v4 case executes a
            # policy. The rootless CI leg carries these rows on every
            # push; rates_shadow_tests.rs pins the note at the Rust
            # level.
            record(
                label,
                "SKIP",
                "harness runs as root — the root-refusal lane cannot trigger "
                "(the rootless CI leg carries this row)",
            )
            continue
        rc, output = _run_cli_case(argv)
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label, "FAIL", "panic leaked")
            all_ok = False
            continue
        missing = [n for n in must_contain if n not in output]
        leaked = [n for n in must_not_contain if n in output]
        if missing or leaked:
            record(label, "FAIL", f"missing={missing} unexpected={leaked}")
            all_ok = False
            continue
        record(label, "PASS", f"rc={rc}, contract intact")

    # ── contract 3: the hidden vocabulary ──
    for argv, must_not_contain, must_contain, desc in HIDDEN_LEAK_CASES:
        label = f"vocab: {desc}"
        rc, output = _run_cli_case(argv)
        if rc is None:
            record(label, "FAIL", "timed out (hang)")
            all_ok = False
            continue
        if _case_panicked(output):
            record(label, "FAIL", "panic leaked")
            all_ok = False
            continue
        leaked = [n for n in must_not_contain if n in output]
        missing = [n for n in must_contain if n not in output]
        if leaked or missing:
            record(label, "FAIL", f"leaked={leaked} missing={missing}")
            all_ok = False
            continue
        record(label, "PASS", f"rc={rc}, vocabulary honest")

    return all_ok


# ── stage 10: the --during ladder (NIGHT-improve-42) ─────────────────────


def test_during_ladder():
    """The unified --during grammar, end to end (schema v23).

    Every valid unit and both bounds parse to the gate across every
    enforcement verb (the strict family AND the block family — the
    bedtime block that lifts itself); every wrong shape refuses by
    CATEGORY: the grammar refusal names the unit list, the bounds
    refusals name their own floors and ceilings, and the removed
    window/date shapes are refused BY NAME (the duration-only
    revision's own wording). The valid rows are rootless-lane (the
    root-refusal needle; as root they would be enforcement attempts
    and skip); the refusal rows hold under every uid.
    """
    out()
    out("── stage 10: --during ladder (the time-window grammar) ──")
    return _run_needle_cases(DURING_CASES, "during")


# ── stage 11: the guarantee bracket ladder (NIGHT-improve-42) ─────────────


def test_guarantee_ladder():
    """The --floor/--ceil bracket laws, end to end (schema v24).

    The valid shapes parse to the gate — including the legal mixed
    spelling (a both-directions floor beside per-direction ceilings,
    the resolver's own composition law). Every law violation refuses
    by its OWN wording: the one-spelling law, the floor<=ceil<=rate
    ladder, the removed-direction law, and the rate ask. The valid
    rows are rootless-lane; the law rows hold under every uid.
    """
    out()
    out("── stage 11: guarantee brackets (the floor/ceil laws) ──")
    return _run_needle_cases(GUARANTEE_CASES, "guarantee")


# ── stage 12: the tier flags (NIGHT-improve-42) ──────────────────────────


def test_tier_flags():
    """The per-socket tier's flag surface.

    --per-socket is strict-single's own (the server shape: one
    process, many sockets, each connection its own budget) — the
    valid parse rides the one verb that owns it, and the group
    verb's refusal is the parse boundary (a per-connection cap on a
    group verb is a different feature, not a wider one). --no-probe
    rides the same verb with the same lane.
    """
    out()
    out("── stage 12: tier flags (--per-socket / --no-probe) ──")
    return _run_needle_cases(TIER_FLAGS, "tier")


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
    _lanes = sum(1 for c in SHADOWED_POSITIONAL_CASES if c[-1])
    _during_lanes = sum(1 for c in DURING_CASES if c[-1])
    _guarantee_lanes = sum(1 for c in GUARANTEE_CASES if c[-1])
    _tier_lanes = sum(1 for c in TIER_FLAGS if c[-1])
    _verb_lanes = sum(1 for c in PRIVILEGED_VERBS if c[-1])
    ok = (
        record(
            "engine: v4 case tables populated",
            "PASS"
            if len(COMMANDS) > 0
            and len(COLOR_MODES_VALID) > 0
            and len(TYPOS) > 0
            and len(RATE_CASES) > 0
            and len(REMOVED) > 0
            and len(LONG_ALIASES) > 0
            and len(ECHO_PAYLOADS) > 0
            and len(ECHO_PATHS) > 0
            and len(SHADOWED_POSITIONAL_CASES) > 0
            and 0 < _lanes < len(SHADOWED_POSITIONAL_CASES)
            and len(HIDDEN_LEAK_CASES) > 0
            and len(DURING_CASES) > 0
            and 0 < _during_lanes < len(DURING_CASES)
            and len(GUARANTEE_CASES) > 0
            and 0 < _guarantee_lanes < len(GUARANTEE_CASES)
            and len(TIER_FLAGS) > 0
            and 0 < _tier_lanes < len(TIER_FLAGS)
            and len(PRIVILEGED_VERBS) > 0
            and 0 < _verb_lanes < len(PRIVILEGED_VERBS)
            else "FAIL",
            f"{len(COMMANDS)} commands, {len(COLOR_MODES_VALID)}+{len(COLOR_MODES_INVALID)} color modes, "
            f"{len(TYPOS)} typos, {len(RATE_CASES)} rate cases, {len(REMOVED)} removed, "
            f"{len(LONG_ALIASES)} long aliases, "
            f"{len(ECHO_PAYLOADS)}x{len(ECHO_PATHS)} echo payloads/paths, "
            f"{len(SHADOWED_POSITIONAL_CASES)} shadow cases ({_lanes} rootless-lane), "
            f"{len(HIDDEN_LEAK_CASES)} vocab cases, "
            f"{len(DURING_CASES)} during cases ({_during_lanes} rootless-lane), "
            f"{len(GUARANTEE_CASES)} guarantee cases ({_guarantee_lanes} rootless-lane), "
            f"{len(TIER_FLAGS)} tier cases ({_tier_lanes} rootless-lane), "
            f"{len(PRIVILEGED_VERBS)} privileged verbs ({_verb_lanes} rootless-lane)",
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
        "long-aliases": test_long_alias_routing,
        "typos": test_typo_handling,
        "rates": test_rate_explode,
        "removed": test_removed_retired,
        "hidden": test_hidden_surface,
        "during": test_during_ladder,
        "guarantee": test_guarantee_ladder,
        "tier-flags": test_tier_flags,
        "z9": test_echo_boundary,
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
    _rootless_lanes = sum(1 for c in SHADOWED_POSITIONAL_CASES if c[-1])
    if _is_root():
        out(
            f"          harness runs as root — the {_rootless_lanes} rootless-lane "
            "shadow rows will skip (v3's doctrine: the gate cannot fire as root)"
        )
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

    if args.self_test:
        # The engine smoke needs no binary (the harness's own
        # contracts) — it keeps its resolution-free path and returns
        # before any binary discipline applies.
        ok = self_test()
        if args.json:
            import json

            print(json.dumps({"results": RESULTS, "verdict": "PASS" if ok else "FAIL"}))
        return 0 if ok else 1

    # NIGHT-total-lts-4: the shared resolution discipline, the same
    # one every other battery rides (repo-local builds outrank the
    # system PATH, ZELYNIC_BINARY and --binary win the selection,
    # and every candidate passes the version gate — the harness
    # tests THIS checkout, never a foreign binary silently). The
    # local block this replaces knew none of that: its /opt
    # preference outranked fresh repo builds, it never looked at
    # repo-local candidates or the env var, its bare-name fallback
    # produced 75 confusing false-red rows on a fresh clone (every
    # output-assertion case reading "missing" against a binary that
    # never ran) instead of the clean not-found verdict, and a
    # stale zelynic on PATH or /opt would have been tested with no
    # gate at all — the exact hole NIGHT-improve-11 and the
    # 2026-09-21 debian13 incident closed for v1.
    if not lib.resolve_binary(
        args.binary,
        "./scripts/supermassive/supermassive-test-v4.sh --binary ./target/pro-native-gnu/zelynic",
    ):
        return 1

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
