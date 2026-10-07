#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Non-root end-to-end CLI depth test (NIGHT-hunt-13).
#
# Runs the FULL command surface as an unprivileged user and verifies the
# unprivileged contract end to end:
#   - informational surfaces exit 0 and produce output
#   - enforcement surfaces refuse cleanly (exit 1, root-required wording
#     with the sudo tip, never a panic)
#   - input validation precedes the root guard (fail-fast ladder: a typo
#     reports the typo, not the privilege)
#   - removed surfaces fail as usage errors (exit 2)
#   - edge-case inputs never panic (no exit 101, no backtrace)
#
# Safe to run anywhere: needs NO root, NO eBPF state, NO network (the
# --check-update probe is time-boxed and degrades to a clean network
# error). Refuses to run as root — this suite pins what an unprivileged
# user sees, so euid 0 would invalidate every assertion.
#
# Usage: ./scripts/depth/nonroot-depth-test.sh [--binary PATH | path-to-zelynic]
#
# Output: PASS/FAIL per case with a summary; exit 0 only when all pass.
#
# NON_LATIN_FIXTURE: the Cyrillic rate string in the "unicode rate"
# case below is intentional input data (invalid-rate rejection
# coverage), not prose (scripts/gates/check-language.sh exemption).

set -euo pipefail

# ━━ Setup ━━

if [[ "$(id -u)" -eq 0 ]]; then
	echo "refusing to run as root: this suite pins the unprivileged contract."
	echo "re-run without sudo."
	exit 1
fi

# Binary resolution rides the shared bash twin (NIGHT-hunt-33): the
# positional path and --binary PATH both work, ZELYNIC_BINARY wins
# over the scan, and among the repo's build outputs (pro-native,
# pro-linux, plain release — .cargo/config.toml) the NEWEST mtime is
# the test payload — the same ladder every supermassive engine
# resolves with, version gate included. The old private ladder
# (debug > release > PATH) was CWD-relative and decoy-prone: a
# target/debug build is the ebpf-less dev shell carrying THIS
# checkout's version, so neither the candidate family nor the version
# gate could catch it.
# shellcheck source=scripts/lib/harness_lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/harness_lib.sh"

if [[ -z "${BINARY:-}" ]]; then
	echo "no zelynic binary found (build first or pass a path)"
	exit 1
fi
check_binary

PASS=0
FAIL=0
RESULTS=()

pass() {
	echo "  OK   $1"
	PASS=$((PASS + 1))
	RESULTS+=("PASS|$1")
}

fail() {
	echo "  X    $1"
	FAIL=$((FAIL + 1))
	RESULTS+=("FAIL|$1")
}

# Run the binary, capture exit code + stderr, and enforce the
# no-panic contract on every single case (NIGHT-hunt-13): a Rust panic
# means exit 101 and a backtrace — neither may ever reach a user.
run_case() {
	local desc="$1"
	shift
	local out code
	# The "&& code=0 || code=$?" idiom keeps set -e alive while
	# capturing the real exit status of a deliberately failing
	# command (a plain capture would kill the script).
	out="$("$@" 2>&1)" && code=0 || code=$?
	if [[ "$code" -eq 101 ]]; then
		fail "$desc (panicked: exit 101)"
		echo "$out" | head -3 | sed 's/^/       /'
		return 1
	fi
	if echo "$out" | grep -q 'panicked at'; then
		fail "$desc (panicked: backtrace in output)"
		echo "$out" | grep -m1 'panicked at' | sed 's/^/       /'
		return 1
	fi
	pass "$desc (no panic)"
	return 0
}

# expect <desc> <exit-code> <must-contain...> -- <argv...>
# Verifies exit code, that stderr+stdout contains every must-contain
# fragment, and the no-panic contract. The fragments after the exit code
# up to "--" are the required substrings.
expect() {
	local desc="$1" want_code="$2"
	shift 2
	local must=()
	while [[ "$1" != "--" ]]; do
		must+=("$1")
		shift
	done
	shift # consume "--"

	local out code
	# The "&& code=0 || code=$?" idiom keeps set -e alive while
	# capturing the real exit status of a deliberately failing
	# command (a plain capture would kill the script).
	out="$("$@" 2>&1)" && code=0 || code=$?

	if [[ "$code" -ne "$want_code" ]]; then
		fail "$desc (want exit $want_code, got $code)"
		echo "$out" | head -3 | sed 's/^/       /'
		return 1
	fi
	if echo "$out" | grep -q 'panicked at' || [[ "$code" -eq 101 ]]; then
		fail "$desc (panicked)"
		return 1
	fi
	local frag
	for frag in "${must[@]}"; do
		if ! echo "$out" | grep -qF -- "$frag"; then
			fail "$desc (missing '$frag' in output)"
			echo "$out" | head -3 | sed 's/^/       /'
			return 1
		fi
	done
	pass "$desc"
}

# refute <desc> <must-NOT-contain> -- <argv...>  (any exit code accepted)
refute() {
	local desc="$1" absent="$2"
	shift 2
	[[ "$1" == "--" ]] && shift
	local out
	out="$("$@" 2>&1 || true)"
	if echo "$out" | grep -qF -- "$absent"; then
		fail "$desc (forbidden '$absent' present)"
		echo "$out" | head -3 | sed 's/^/       /'
	else
		pass "$desc"
	fi
}

echo "━━━ zelynic non-root depth test (NIGHT-hunt-13) ━━━"
echo "  binary: $BINARY (uid $(id -u))"
echo

# ━━ 1. Informational surfaces: exit 0, real output ━━

echo "── informational surfaces ──"

expect "bare invocation prints reference" 0 "Commands:" -- "$BINARY"
expect "--help exits 0 with reference" 0 "Commands:" "Global flags:" -- "$BINARY" --help
expect "-h short form matches --help" 0 "Commands:" -- "$BINARY" -h
expect "--version report" 0 "Signature: Pure eBPF builtin" "License: GPL-3.0-only" -- "$BINARY" --version
expect "-V short form" 0 "Signature: Pure eBPF builtin" -- "$BINARY" -V

expect "doctor runs without root" 0 -- "$BINARY" doctor
refute "doctor never mentions root" "root required" -- "$BINARY" doctor

expect "list-apps runs without root" 0 -- "$BINARY" list-apps
refute "list-apps never mentions root" "root required" -- "$BINARY" list-apps

# JSON surfaces: valid, parseable JSON for scripting.
if command -v python3 >/dev/null 2>&1; then
	if "$BINARY" doctor --print-json | python3 -m json.tool >/dev/null 2>&1; then
		pass "doctor --print-json emits valid JSON"
	else
		fail "doctor --print-json emits valid JSON"
	fi
	if "$BINARY" list-apps --print-json | python3 -m json.tool >/dev/null 2>&1; then
		pass "list-apps --print-json emits valid JSON"
	else
		fail "list-apps --print-json emits valid JSON"
	fi
else
	echo "  --   python3 absent: JSON validity checks skipped"
fi

# NO_COLOR degrades cleanly (env-only color control, no flag).
if NO_COLOR=1 "$BINARY" --help >/dev/null 2>&1; then
	pass "NO_COLOR=1 --help exits 0"
else
	fail "NO_COLOR=1 --help exits 0"
fi

# Broken pipe: short reader must truncate, not panic (exit 101).
if "$BINARY" --help 2>/dev/null | head -2 >/dev/null; then
	pass "--help | head -2 truncates without panic"
else
	fail "--help | head -2 truncates without panic"
fi

# ━━ 2. Enforcement surfaces: clean root refusal, exit 1 ━━

echo "── enforcement surfaces (root refusal) ──"

ROOT_ARGS=(
	"strict brave 100kb"
	"s brave::curl 1mb"
	"s cg:48181 100kb"
	"strict-all 500kb"
	"block brave"
	"block brave::curl"
	"b brave"
	"block-all"
	"unstrict brave"
	"u brave::curl"
	"unstrict-all"
	"recover"
	"status"
	"eagle-eyes"
	"eagle-eyes --interval 5s"
	"eagle-eyes brave/firefox"
)

for arg_str in "${ROOT_ARGS[@]}"; do
	# shellcheck disable=SC2086 # intentional word splitting of the case table
	expect "root refusal: $arg_str" 1 "root required" "tip: re-run with sudo" -- "$BINARY" $arg_str
done

# The JSON flag must not change the refusal contract.
expect "status --print-json refuses root identically" 1 "root required" -- "$BINARY" status --print-json

# ━━ 3. Parse-before-privilege ladder ━━

echo "── fail-fast ladder (validation before root guard) ──"

expect "rate typo surfaces before root guard" 1 "Invalid rate '1MB'" "tip:" -- "$BINARY" strict brave 1MB
refute "rate typo must not mention root" "root required" -- "$BINARY" strict brave 1MB
expect "missing rate surfaces before root guard" 1 "No rate specified" -- "$BINARY" strict brave
refute "missing rate must not mention root" "root required" -- "$BINARY" strict brave
expect "dangerous target guard precedes root guard" 1 "system process" -- "$BINARY" strict root 100kb
expect "interval bounds precede root guard" 1 "between 1s and 60s" -- "$BINARY" eagle-eyes --interval 61s
refute "interval error must not mention root" "root required" -- "$BINARY" eagle-eyes --interval 61s
expect "interval typo carries did-you-mean tip" 1 "Invalid duration '3min'" "tip: a similar value exists: '3m'" -- "$BINARY" eagle-eyes --interval 3min
expect "empty target spec precedes root guard" 1 "No targets in" -- "$BINARY" eagle-eyes /
# NIGHT-improve-53: the single ':' is the prefix grammar's byte
# now, so 'brave:curl' is ONE (unmatchable) name on the single lane —
# and the single lane root-gates before its /proc walk, so non-root
# users correctly see the root guard first. The '::' tip is post-apply
# advice there (the walk that proves the no-match needs privileges).
expect "old-grammar colon list in single slot still root-gated" 1 "root required" -- "$BINARY" strict brave:curl 100kb

# NIGHT-blade-18 grammar + NIGHT-improve-53 (the '::' separator):
# pinned rootless — every refusal fires BEFORE the root guard, and
# the fine list passes the grammar through to it. The separator
# doubled when the verbs merged: single ':' belongs to the cg:
# prefix and the container URIs.
expect "multi grammar: path member precedes root guard" 1 "not a valid app name" -- "$BINARY" strict "a::a/;/::1" 1mb
refute "multi grammar: path error must not mention root" "root required" -- "$BINARY" strict "a::a/;/::1" 1mb
expect "multi grammar: empty member precedes root guard" 1 "empty target" -- "$BINARY" strict a::::b 1mb
expect "multi grammar: trailing separator drops a member the same way" 1 "empty target" -- "$BINARY" strict a:: 1mb
expect "multi grammar: punctuation-only member is refused" 1 "not a valid app name" -- "$BINARY" strict "x::;;::y" 1mb
expect "multi grammar: single-colon member is the old grammar refused" 1 "members separate with '::'" -- "$BINARY" strict "brave:curl::steam" 1mb
expect "multi grammar: container URI in a list is the named refusal" 1 "do not ride lists" -- "$BINARY" strict "docker://nginx::brave" 1mb
expect "multi grammar: one distinct member needs no separator" 1 "needs no separator" -- "$BINARY" strict brave::brave 1mb
expect "multi grammar: block path member is refused" 1 "not a valid app name" -- "$BINARY" block "a::a/"
expect "multi grammar: unstrict path member is refused" 1 "not a valid app name" -- "$BINARY" unstrict "a::a/"
expect "multi grammar: unstrict empty member is refused" 1 "empty target" -- "$BINARY" unstrict a::
expect "multi grammar: separator-only keeps the no-targets error" 1 "No targets specified" -- "$BINARY" strict "::" 1mb
expect "multi grammar: fine list passes the grammar to the root guard" 1 "root required" -- "$BINARY" strict a::b::c 1mb
# NIGHT-hunt-Z3: the unresolvable-id example is a DEAD id now, not
# cg:1 — the old example only "flowed to the root guard" in container
# views where the host root has no visible members; on the host itself
# cg:1 is the live root cgroup, and the Z3 root catch-all arm refuses
# it by POSITION (before the privilege ask) exactly as designed. A
# near-u32-max id is unresolvable on every machine, so the contract
# this row pins — a dead id stays allowed and reaches the root ask —
# is now environment-independent.
expect "numeric target: cg form flows to the root guard when unresolvable" 1 "root required" -- "$BINARY" strict cg:4294967290 100kb
# The Z3 root catch-all arm itself, pinned rootlessly in both
# directions: the root POSITION refuses before the privilege ask,
# and --force-this lifts it back onto the root ask's runway.
expect "numeric target: the cgroupfs root refuses by position (Z3)" 1 "is the root cgroup" -- "$BINARY" strict cg:1 100kb
expect "numeric target: --force-this lifts the root position (Z3)" 1 "root required" -- "$BINARY" strict cg:1 100kb --force-this

# ━━ 4. Usage errors: exit 2 with canonical shape ━━

echo "── usage errors (exit 2) ──"

expect "strict without target" 2 "required arguments were not provided" -- "$BINARY" strict
expect "s without target" 2 "required arguments were not provided" -- "$BINARY" s
expect "block without target" 2 "required arguments were not provided" -- "$BINARY" block
expect "unstrict without target" 2 "required arguments were not provided" -- "$BINARY" unstrict
expect "typo subcommand suggests fix" 2 "tip:" "strict" -- "$BINARY" strict-singl
expect "case-variant flag rescued" 2 "--verbose" -- "$BINARY" --VERBOS doctor

# Removed surfaces (NIGHT-hunt-12 plus earlier removals):
# every one must be a usage error, never a silent success.
for gone in man unblock completions info; do
	expect "removed subcommand '$gone' rejected" 2 "unrecognized subcommand" -- "$BINARY" "$gone"
done
# NIGHT-boost-1: observe and top merged into eagle-eyes — both fail
# as unrecognized subcommands whose tip names the successor.
for gone in observe top; do
	expect "removed subcommand '$gone' redirects to eagle-eyes" 2 "unrecognized subcommand" "eagle-eyes" -- "$BINARY" "$gone"
done
# NIGHT-improve-53 (the masterclass unification): strict-single +
# strict-multi, block-single + block-multi, unstrict-single +
# unstrict-multi merged into one verb per family — all twelve retired
# spellings land on the family successor's redirect tip at exit 2.
for gone in strict-single strict-multi ss sm; do
	expect "removed spelling '$gone' redirects to strict" 2 "unrecognized subcommand" "strict" -- "$BINARY" "$gone"
done
for gone in block-single block-multi bs bm; do
	expect "removed spelling '$gone' redirects to block" 2 "unrecognized subcommand" "block" -- "$BINARY" "$gone"
done
for gone in unstrict-single unstrict-multi us um; do
	expect "removed spelling '$gone' redirects to unstrict" 2 "unrecognized subcommand" "unstrict" -- "$BINARY" "$gone"
done
# NIGHT-blade-7 (hunt find): the singular 'eagle-eye' alias was removed
# with the same merge (one canonical name, one short form) — typing it
# lands on the redirect tip at exit 2, NOT the root guard. This pin
# used to expect the pre-removal root refusal (exit 1) and failed on
# every post-removal main.
expect "removed alias 'eagle-eye' redirects to eagle-eyes" 2 "unrecognized subcommand" "eagle-eyes" -- "$BINARY" eagle-eye brave
expect "removed flag -i rejected" 2 "unexpected argument" -- "$BINARY" -i
expect "removed --live rejected" 2 "unexpected argument" -- "$BINARY" eagle-eyes --live 3m
expect "removed --duration rejected" 2 "unexpected argument" -- "$BINARY" eagle-eyes --duration 30s
expect "removed --cgroup rejected" 2 "unexpected argument" -- "$BINARY" eagle-eyes --cgroup 8066
expect "removed --limit rejected" 2 "unexpected argument" -- "$BINARY" eagle-eyes --limit 20
expect "removed --help-all rejected" 2 "unexpected argument" -- "$BINARY" --help-all
expect "removed --no-color rejected" 2 "unexpected argument" -- "$BINARY" --no-color doctor

# ━━ 5. Edge inputs: graceful, never a panic ━━

echo "── edge inputs ──"

run_case "empty target name" "$BINARY" strict "" 100kb
# NIGHT-hunt-Z3 find (stale row, pre-existing on main): dinner-16 moved
# the empty-target boundary to the INPUT rung — validate_single_target
# refuses `strict ""` before the root ask with its own wording
# (the unit pin empty_single_target_is_refused_at_the_input_boundary
# carries the same contract) — but this row still expected the
# pre-dinner-16 "root required" shape and failed on pristine main.
expect "empty target refused at the input boundary (dinner-16 wording)" 1 "target is empty" -- "$BINARY" strict "" 100kb
run_case "u64-overflow numeric target" "$BINARY" strict 99999999999999999999 100kb
expect "overflow numeric target treated as name" 1 "root required" -- "$BINARY" strict 99999999999999999999 100kb
run_case "path-shaped target" "$BINARY" strict "../../etc" 100kb
expect "path-shaped target refused as root-first" 1 "root required" -- "$BINARY" strict "../../etc" 100kb
run_case "space target" "$BINARY" strict "two words" 100kb
expect "space target refused as root-first" 1 "root required" -- "$BINARY" strict "two words" 100kb
run_case "negative numeric target" "$BINARY" strict -- "-5" 100kb
expect "negative numeric target refused as root-first" 1 "root required" -- "$BINARY" strict -- "-5" 100kb
run_case "unicode rate" "$BINARY" strict brave "100кб"
expect "unicode rate gets invalid-rate error" 1 "Invalid rate" -- "$BINARY" strict brave "100кб"
# NOTE: 0b is deliberately legal (0 = block, the strict path
# into block semantics); the real below-minimum case is 1b.
expect "rate 1b rejected below minimum" 1 "below minimum" -- "$BINARY" strict brave 1b
expect "rate 0b is legal block-shorthand (root-gated)" 1 "root required" -- "$BINARY" strict brave 0b
# NIGHT-blade-7 (hunt find): the rate ceiling is 1 TB/s (MAX_RATE =
# 1e12, the TB tier the parser accepts), so the over-max case must
# sit ABOVE it — the old 101gb pin predates the ceiling raise and
# parsed as a legal 0.101 TB/s, landing on the root guard instead.
expect "rate above maximum rejected" 1 "above maximum" -- "$BINARY" strict brave 1001gb
expect "verbose flag parses globally" 0 -- "$BINARY" -v doctor

# --check-update as non-root passes the privilege guard; the network
# probe itself is time-boxed (curl --max-time 15 inside the binary,
# timeout 25 here) and EITHER outcome is acceptable: exit 0 with the
# branded report, or exit 1 with a clean mapped network error. A hang
# or a panic is the only failure mode that matters.
check_probe="$(timeout 25 "$BINARY" --check-update 2>&1)" && check_code=0 || check_code=$?
if [[ "$check_code" -eq 101 ]] || echo "$check_probe" | grep -q 'panicked at'; then
	fail "--check-update non-root probe (panic/hang)"
elif [[ "$check_code" -eq 124 ]]; then
	fail "--check-update non-root probe (hung past 25s)"
elif [[ "$check_code" -eq 0 ]]; then
	pass "--check-update non-root probe (report rendered)"
elif echo "$check_probe" | grep -qE 'network|DNS|connection|timed out|curl|rate-limited|forbidden|not valid UTF-8|malformed'; then
	pass "--check-update non-root probe (clean mapped error, exit $check_code)"
else
	fail "--check-update non-root probe (exit $check_code, unmapped error)"
	echo "$check_probe" | head -3 | sed 's/^/       /'
fi

# ━━ comm-spoof terminal-injection guard (NIGHT-cybersecurity-1) ━━

echo "── comm-spoof display guard (NIGHT-cybersecurity-1) ──"

# prctl(PR_SET_NAME) lets any unprivileged process set a 15-byte comm
# containing ANSI/OSC escapes and newlines. A kernel quirk gives a
# pure-shell spoofer the same power WITHOUT prctl: comm defaults to the
# executable's basename, so a copied binary with a hostile filename
# carries that name into /proc/<pid>/comm. The invariant under test is
# environment-independent: list-apps output (text AND JSON) must never
# carry a raw ESC byte. On systems where the identity walk resolves
# cgroups, the spoofed labels surface sanitized ('?' substitution); on
# cgroup-namespaced sandboxes where the walk resolves nothing, the
# invariant still holds vacuously — and the sanitize behavior itself is
# pinned by the identity unit tests.
SPOOF_DIR="$(mktemp -d)"
SLEEP_BIN="$(command -v sleep || echo /bin/sleep)"
spoof_pids=()
cleanup_spoof() {
	kill "${spoof_pids[@]}" 2>/dev/null || true
	wait "${spoof_pids[@]}" 2>/dev/null || true
	rm -rf "$SPOOF_DIR"
}
trap cleanup_spoof EXIT

# Spoofer 1: OSC 52 clipboard-write attempt (ESC ] 5 2 ; p ; EVIL= BEL).
cp "$SLEEP_BIN" "$SPOOF_DIR/$(printf '\033]52;p;EVIL=\007')"
# shellcheck disable=SC2289 # the hostile name IS the point: a newline in a command name is legal on Linux
"$SPOOF_DIR/$(printf '\033]52;p;EVIL=\007')" 30 &
spoof_pids+=($!)

# Spoofer 2: newline row-forgery (a fake "8066" cgroup-id row).
cp "$SLEEP_BIN" "$SPOOF_DIR/evil
8066"
# shellcheck disable=SC2289 # the hostile name IS the point: a newline in a command name is legal on Linux
"$SPOOF_DIR/evil
8066" 30 &
spoof_pids+=($!)

# Give both processes a moment to appear in /proc before the walk.
sleep 0.3

if "$BINARY" list-apps 2>&1 | LC_ALL=C grep -qF "$(printf '\033')"; then
	fail "list-apps output must never carry a raw ESC byte (comm-spoof guard)"
else
	pass "list-apps output carries no raw ESC byte (comm-spoof guard)"
fi
if "$BINARY" list-apps --print-json 2>&1 | LC_ALL=C grep -qF "$(printf '\033')"; then
	fail "list-apps --print-json must never carry a raw ESC byte (comm-spoof guard)"
else
	pass "list-apps --print-json carries no raw ESC byte (comm-spoof guard)"
fi

cleanup_spoof
trap - EXIT

# ━━ Summary ━━

echo
echo "━━━ results ━━━"
echo "  passed: $PASS"
echo "  failed: $FAIL"
if [[ "$FAIL" -gt 0 ]]; then
	echo
	printf '  %s\n' "${RESULTS[@]}" | grep '^FAIL' || true
	exit 1
fi
exit 0
