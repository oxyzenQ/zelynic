#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# night-dragon-fly-1: the end-to-end CLI UX capture battery.
#
# Every command, flag, alias, retired spelling, error lane, and JSON
# contract the `zelynic --help` reference names, run against the real
# binary with stdout, stderr, and the exit code captured separately.
# The log this battery produces is the audit input: send the WHOLE
# file back, the analyzer diffs reality against the source-code
# contract (docs/audits/NIGHT_DRAGON_FLY_1_CLI_UX_E2E_MANUAL_*.md,
# the case catalog with the expected verdict per case ID).
#
# Usage:
#   bash scripts/labs-exp/capture-cli-ux-e2e.sh > zelynic-ndf1-e2e.log 2>&1
#
# Root lane (full enforcement smoke: doctor, sig, status, list-apps,
# recover, a self-contained strict/status/eagle-eyes/unstrict cycle
# against a spawned `sleep` process — nothing else is touched):
#   RUN_ROOT=1 bash scripts/labs-exp/capture-cli-ux-e2e.sh > zelynic-ndf1-e2e.log 2>&1
#
# Binary under test defaults to `zelynic` on PATH; override it:
#   ZELYNIC_BIN=/path/to/zelynic bash scripts/labs-exp/capture-cli-ux-e2e.sh
#
# Safety contract (default run): zero privilege, zero enforcement
# state touched, zero network except the one `--check-update` case
# (safe to run offline — its error chain is itself audit material).
# The guard below enforces it: run under sudo without RUN_ROOT=1 and
# the battery refuses, because the apply lanes (C09/D55/D59/D62/D64/
# D79) assume the binary's root gate closes them — under euid=0 they
# enforce for real and nothing tears the state down (the 2026-11-27
# owner run measured a whole-fleet 500kb limit that outlived the
# battery). The BYHAND block at the end lists the cases the battery
# refuses to automate (the terminal reset that clears the screen,
# the fleet sweeps, the live TUI frames) with the exact commands to
# run by hand.
#
# Exit 0 when the battery ran to completion (case verdicts are the
# analyzer's job, not the battery's), 1 on a broken setup.

# shellcheck disable=SC2016,SC2317 # the eval lane's own contract:
# run_sh receives the command as ONE single-quoted string (the case
# ID and the command are the log's two axes) and eval expands it
# later, so single-quote expansion notes and the reachability walk's
# "unreachable" verdicts on eval-called helpers and the EXIT trap are
# the design, not defects.
set -u
export PYTHONDONTWRITEBYTECODE=1

BIN="${ZELYNIC_BIN:-zelynic}"
RUN_ROOT="${RUN_ROOT:-0}"

if ! command -v "$BIN" >/dev/null 2>&1; then
	echo "battery: binary '$BIN' not found on PATH; set ZELYNIC_BIN=/path/to/zelynic"
	exit 1
fi
BIN_ABS="$(command -v "$BIN")"

# The privilege guard (night-dragon-fly-1, the owner's own sudo run
# find): the non-root battery's safety contract — zero enforcement
# state touched — leans on the binary's root gate to keep the apply
# cases inert. Under sudo the gate stands open, so C09/D55/D59/D62/
# D64/D79 enforce for real and the battery exits leaving the state
# behind (measured: a 45-cgroup fleet limit at 500kb that outlived
# the run, cleanup rides RUN_ROOT=1's trap alone). euid=0 without
# RUN_ROOT=1 is therefore never a supported shape: refuse, and say
# which lane owns which cleanup.
if [ "$(id -u)" = "0" ] && [ "$RUN_ROOT" != "1" ]; then
	echo "battery: euid=0 without RUN_ROOT=1 — refusing to run."
	echo "  The non-root lanes assume the root gate closes them; under sudo the"
	echo "  apply cases (C09/D55/D59/D62/D64/D79) enforce for real and nothing in"
	echo "  this battery tears the state down afterwards."
	echo "  Re-run without sudo, or set RUN_ROOT=1 for the root lane, which owns"
	echo "  its own unstrict --all cleanup at exit."
	exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

sleep_pid=""
cleanup_root() {
	if [ -n "$sleep_pid" ]; then
		kill "$sleep_pid" 2>/dev/null || true
	fi
	if [ "${ROOT_ARMED:-0}" = "1" ]; then
		sudo "$BIN_ABS" unstrict --all >/dev/null 2>&1 || true
	fi
}
trap cleanup_root EXIT

CASES=0

banner() {
	printf '\n###############################################################################\n'
	printf '## %s\n' "$1"
	printf '###############################################################################\n'
}

emit_header() {
	printf '\n===== [%s] %s =====\n' "$1" "$2"
}

emit_body() {
	local rc="$1"
	CASES=$((CASES + 1))
	printf -- '---- exit: %d ----\n' "$rc"
	printf -- '---- stdout ----\n'
	if [ -s "$WORK/out" ]; then cat "$WORK/out"; else echo "(empty)"; fi
	printf -- '---- stderr ----\n'
	if [ -s "$WORK/err" ]; then cat "$WORK/err"; else echo "(empty)"; fi
}

run_case() {
	local id="$1"
	shift
	emit_header "$id" "$*"
	"$@" >"$WORK/out" 2>"$WORK/err"
	local rc=$?
	emit_body "$rc"
}

run_sh() {
	local id="$1"
	local cmd="$2"
	emit_header "$id" "$cmd"
	eval "$cmd" >"$WORK/out" 2>"$WORK/err"
	local rc=$?
	emit_body "$rc"
}

byhand() {
	printf '\n----- BYHAND (run by hand, never automated) -----\n'
	printf '%s\n' "$1"
}

cat >"$WORK/json_shape.py" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1], "rb") as f:
        raw = f.read()
    doc = json.loads(raw.decode("utf-8"))
    if isinstance(doc, dict):
        print("JSON-VALID top-level keys: %s" % list(doc.keys()))
    elif isinstance(doc, list):
        print("JSON-VALID array of %d items" % len(doc))
    else:
        print("JSON-VALID scalar: %r" % doc)
except Exception as exc:
    print("JSON-BROKEN: %s" % exc)
PYEOF

json_shape() {
	# $1 = file holding captured stdout; verdict appended to the case output.
	if command -v python3 >/dev/null 2>&1; then
		python3 "$WORK/json_shape.py" "$1"
	else
		echo "JSON-UNCHECKED (python3 not present on this machine)"
	fi
}

banner "SECTION E — environment and identity"

run_sh E01 'command -v "$BIN"; "$BIN" -V'
run_case E02 "$BIN" --version
run_sh E03 'uname -a; printf "TERM=%s COLORTERM=%s COLUMNS=%s LINES=%s\n" "${TERM:-unset}" "${COLORTERM:-unset}" "${COLUMNS:-unset}" "${LINES:-unset}"; stty size 2>/dev/null || echo "stty: n/a"; printf "LANG=%s LC_ALL=%s NO_COLOR=%s\n" "${LANG:-unset}" "${LC_ALL:-unset}" "${NO_COLOR:-unset}"; printf "euid=%s sudo=%s\n" "$(id -u)" "$(command -v sudo || echo none)"'
run_sh E04 'for t in python3 jq sha256sum tput script stty curl; do command -v "$t" >/dev/null 2>&1 && echo "$t: present" || echo "$t: MISSING"; done'

banner "SECTION A — help and metadata surfaces"

run_case A01 "$BIN" --help
run_case A02 "$BIN" -h
run_case A03 "$BIN"
run_case A04 "$BIN" help
run_sh A05 '"$BIN" --help | head -3; printf "zelynic exit through the pipe: %s (broken-pipe law: no panic, no SIGPIPE kill)\n" "${PIPESTATUS[0]}"'
run_case A06 "$BIN" --print-json --help
run_case A07 "$BIN" --print-json -h
run_case A08 "$BIN" --print-json -V
run_case A09 "$BIN" --print-json
run_case A10 "$BIN" s -V
run_case A11 "$BIN" doctor -V
byhand 'A12: zelynic --reset-terminal — the emergency terminal rescue is silent by design and clears the screen; run it by hand only when you actually want the reset.'

banner "SECTION B — the per-verb help doors (clap local help, exit 0)"

run_case B01 "$BIN" strict -h
run_case B02 "$BIN" strict --help
run_case B03 "$BIN" s -h
run_case B04 "$BIN" block -h
run_case B05 "$BIN" unstrict -h
run_case B06 "$BIN" eagle-eyes -h
run_case B07 "$BIN" eagle-eyes --help
run_case B08 "$BIN" status -h
run_case B09 "$BIN" list-apps -h
run_case B10 "$BIN" doctor -h
run_case B11 "$BIN" sig -h
run_case B12 "$BIN" recover -h
run_case B13 "$BIN" strict -h --print-json

banner "SECTION C — the --print-json contract (non-root rungs)"

# The audit's own find: the captured exit code must be the BINARY's, not
# the validator's — bin_rc is recorded immediately after the binary and
# printed before json_shape runs (the old shape reported json_shape's 0
# for every case here, so the JSON error contract's exit-1 clause was
# never actually measured).
run_sh C01 '"$BIN" doctor --print-json > "$WORK/c01"; bin_rc=$?; cat "$WORK/c01"; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/c01"'
run_sh C02 '"$BIN" status --print-json > "$WORK/c02"; bin_rc=$?; cat "$WORK/c02"; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/c02"'
run_sh C03 '"$BIN" list-apps --print-json > "$WORK/c03"; bin_rc=$?; cat "$WORK/c03"; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/c03"'
run_sh C04 '"$BIN" eagle-eyes --depth --print-json > "$WORK/c04"; bin_rc=$?; cat "$WORK/c04"; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/c04"'
run_case C05 "$BIN" --print-json strictt
run_case C06 "$BIN" --print-json snapshot
run_case C07 "$BIN" --print-json __probe-serve
run_case C08 "$BIN" --print-json --verbos
run_case C09 "$BIN" --print-json s brave 1kb
run_case C10 "$BIN" --print-json sig
run_case C11 "$BIN" --print-json --color-mode 99

banner "SECTION D — rescue, suggestion and wording lanes (no privileges)"

run_case D01 "$BIN" strictt
run_case D02 "$BIN" sttict
run_case D03 "$BIN" statuss
run_case D04 "$BIN" observe
run_case D05 "$BIN" top
run_case D06 "$BIN" eagle-eye
run_case D07 "$BIN" limit-all
run_case D08 "$BIN" la
run_case D09 "$BIN" strict-single
run_case D10 "$BIN" strict-multi
run_case D11 "$BIN" ss
run_case D12 "$BIN" sm
run_case D13 "$BIN" block-single
run_case D14 "$BIN" block-multi
run_case D15 "$BIN" bs
run_case D16 "$BIN" bm
run_case D17 "$BIN" unstrict-single
run_case D18 "$BIN" unstrict-multi
run_case D19 "$BIN" us
run_case D20 "$BIN" um
run_case D21 "$BIN" strict-all
run_case D22 "$BIN" sa
run_case D23 "$BIN" block-all
run_case D24 "$BIN" ba
run_case D25 "$BIN" unstrict-all
run_case D26 "$BIN" ua
run_case D27 "$BIN" snapshot
run_case D28 "$BIN" restore
run_case D29 "$BIN" --verbos
run_case D30 "$BIN" --VERBOS
run_case D31 "$BIN" --json
run_case D32 "$BIN" s brave 1kb --json
run_case D33 "$BIN" s brave 1kb --check-updat
run_case D34 "$BIN" s brave 1kb --check-updated
run_case D35 "$BIN" s brave 1kb --no-probe
run_case D36 "$BIN" ee brave --info
run_case D37 "$BIN" s brave 1mb --allow-dangerous
run_case D38 "$BIN" s brave 550kb -- -V
run_case D39 "$BIN" s brave 550kb -- -i
run_case D40 "$BIN" ee brave electron
run_case D41 "$BIN" ee brave/electron
run_case D42 "$BIN" --color-mode
run_case D43 "$BIN" --color-mode 99 doctor
run_case D44 "$BIN" --color-mode 0 doctor
run_case D45 "$BIN" --color-mode 16 --verbos
run_sh D46 'c=$("$BIN" --color-mode 0 --verbos 2>&1 | tr -cd "\033" | wc -c); printf "ESC bytes on the mono error lane: %s (color law expects 0)\n" "$c"'
run_sh D47 'c=$("$BIN" --color-mode 16 --verbos 2>&1 | tr -cd "\033" | wc -c); printf "ESC bytes on the 16-rung error lane: %s (color law expects > 0)\n" "$c"; r=$("$BIN" --color-mode 16 --verbos 2>&1 | tr -cd "\033" | grep -c "38;2;" || true); printf "truecolor RGB escapes (38;2;) on the 16-rung: %s (remap law expects 0)\n" "$r"'
run_case D48 "$BIN" s brave 1kib
run_case D49 "$BIN" s brave 10mbps
run_case D50 "$BIN" s brave 1MB
run_case D51 "$BIN" s brave 5.5xb
run_case D52 "$BIN" s brave 500b
run_case D53 "$BIN" s brave 0.9kb
run_case D54 "$BIN" s brave 2tb
run_case D55 "$BIN" s brave 1000b
run_case D56 "$BIN" s brave 1kb --during 3min
run_case D57 "$BIN" s brave 1kb --during 0s
run_case D58 "$BIN" s brave 1kb --during 6y
run_case D59 "$BIN" s brave 1kb --during 30mn
run_case D60 "$BIN" s
run_case D61 "$BIN" s brave
run_case D62 "$BIN" s brave 1mb -d 2mb
run_case D63 "$BIN" s brave 1mb --floor 100kb --floor-download 50kb
run_case D64 "$BIN" s --all 500kb --per-socket
run_case D65 "$BIN" s brave::steam::curl 1mb --per-socket
run_case D66 "$BIN" s "" 1kb
run_case D67 "$BIN" s cg: 1kb
run_case D68 "$BIN" s cg:abc 1kb
run_case D69 "$BIN" s docker:// 1kb
run_case D70 "$BIN" ee ""
run_case D71 "$BIN" ee --interval 0s
run_case D72 "$BIN" ee --interval 61s
run_case D73 "$BIN" ee --focus 0s
run_case D74 "$BIN" ee --focus 31s
run_sh D75 '"$BIN" ee --focus 5s </dev/null'
run_case D76 "$BIN" --check-update
run_case D77 "$BIN" status
run_case D78 "$BIN" list-apps
run_case D79 "$BIN" s brave 1kb

banner "SECTION F — the color, wrap and environment law"

run_sh F01 'NO_COLOR=1 "$BIN" --help | head -12'
run_sh F02 'COLUMNS=40 "$BIN" --help | head -24'
run_sh F03 'COLUMNS=200 "$BIN" --help | head -6'
run_sh F04 'TERM=dumb "$BIN" doctor | head -12'
run_sh F05 'NO_COLOR=1 "$BIN" s brave 1kb 2>&1 | head -6'
run_sh F06 'COLUMNS=40 "$BIN" --print-json doctor > "$WORK/f06"; bin_rc=$?; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/f06"; printf "JSON line count under COLUMNS=40: %s (contract expects 1)\n" "$(wc -l < "$WORK/f06")"'
run_sh F07 'LC_ALL=C "$BIN" --help | head -6'

banner "SECTION G — determinism and the byte law"

run_sh G01 'a=$("$BIN" --help | sha256sum | cut -d" " -f1); b=$("$BIN" --help | sha256sum | cut -d" " -f1); printf "help run 1: %s\nhelp run 2: %s\n" "$a" "$b"; [ "$a" = "$b" ] && echo "HELP-DETERMINISTIC" || echo "HELP-NONDETERMINISTIC"'
run_sh G02 '"$BIN" doctor --print-json > "$WORK/g02a" 2>/dev/null; a_rc=$?; sleep 1; "$BIN" doctor --print-json > "$WORK/g02b" 2>/dev/null; b_rc=$?; if diff -q "$WORK/g02a" "$WORK/g02b" >/dev/null 2>&1; then echo "DOCTOR-JSON-DETERMINISTIC (byte-identical across runs)"; else echo "DOCTOR-JSON-DIFFERS (expected if the report embeds timestamps or counters — paste both bodies)"; diff "$WORK/g02a" "$WORK/g02b" | head -20; fi; printf "doctor exit run1: %s; run2: %s\n" "$a_rc" "$b_rc"'

banner "SECTION R — the root lane (RUN_ROOT=1 only)"

if [ "$RUN_ROOT" != "1" ]; then
	printf 'RUN_ROOT=0 — the root lane is SKIPPED. Re-run with RUN_ROOT=1 for the\n'
	printf 'enforcement smoke (doctor, sig, status, list-apps, recover, and one\n'
	printf 'strict/status/eagle-eyes/unstrict cycle against a spawned sleep).\n'
else
	if sudo -v 2>/dev/null; then
		ROOT_ARMED=1
		run_case R01 sudo "$BIN_ABS" --check-update
		run_case R02 sudo "$BIN_ABS" doctor
		run_case R03 sudo "$BIN_ABS" sig
		run_case R04 sudo "$BIN_ABS" status
		run_sh R05 'sudo "$BIN_ABS" status --print-json > "$WORK/r05"; bin_rc=$?; cat "$WORK/r05"; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/r05"'
		run_case R06 sudo "$BIN_ABS" list-apps
		run_sh R07 'sudo "$BIN_ABS" list-apps --print-json > "$WORK/r07"; bin_rc=$?; cat "$WORK/r07"; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/r07"'
		run_case R08 sudo "$BIN_ABS" recover
		run_case R09 sudo "$BIN_ABS" -v status
		# printf -- : the audit's second find — the bare "---- ... ----"
		# format died with "printf: --: invalid option" and the stderr
		# header vanished from the log (the helper at the top of this
		# script already guards the same strings with --).
		run_sh R10 'sudo "$BIN_ABS" -v status --print-json > "$WORK/r10out" 2> "$WORK/r10err"; bin_rc=$?; printf -- "---- stdout ----\n"; cat "$WORK/r10out"; printf -- "---- stderr ----\n"; cat "$WORK/r10err"; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/r10out"'
		printf '\n----- enforcement smoke: spawned target "sleep", full cleanup at exit -----\n'
		sleep 300 &
		sleep_pid=$!
		run_case R11 sudo "$BIN_ABS" strict sleep 1mb
		run_case R12 sudo "$BIN_ABS" status
		run_case R13 sudo "$BIN_ABS" ee sleep --depth
		run_sh R14 'sudo "$BIN_ABS" ee sleep --depth --print-json > "$WORK/r14"; bin_rc=$?; cat "$WORK/r14"; printf "binary exit: %s\n" "$bin_rc"; json_shape "$WORK/r14"'
		run_case R15 sudo "$BIN_ABS" s sleep 1mb --per-socket
		run_case R16 sudo "$BIN_ABS" u sleep
		run_case R17 sudo "$BIN_ABS" s sleep 500kb --during 30s
		run_case R18 sudo "$BIN_ABS" u sleep
		run_case R19 sudo "$BIN_ABS" u sleep
		run_sh R20 'sudo "$BIN_ABS" ee --focus 5s </dev/null'
		byhand 'R21: sudo zelynic ee cg:<ID> --depth --focus 5s — pick <ID> from R06 output; the battery stays static, IDs move.'
		byhand 'R22: sudo zelynic s --all 500kb then sudo zelynic u --all — the fleet sweep is destructive by definition; run only when you accept it.'
	else
		printf 'RUN_ROOT=1 but sudo could not authenticate — the root lane is SKIPPED.\n'
	fi
fi

banner "BATTERY COMPLETE"
printf 'cases captured: %d\n' "$CASES"
printf 'binary under test: %s (%s)\n' "$BIN" "$BIN_ABS"
printf 'send this whole log back for the night-dragon-fly-1 audit diff.\n'
exit 0
