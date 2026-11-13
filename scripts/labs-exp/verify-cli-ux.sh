#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# The non-root CLI UX verification battery for the
# night-total-hardening-1 fixes (night-total-hardening-1's local
# re-verification record, docs/audits/
# NIGHT_TOTAL_HARDENING_1_CRITICAL_FORENSIC_2026-11-13.md).
#
# Seventeen operator-visible cases pinned against the BINARY ITSELF,
# no privileges required: the 32-bit numeric-boundary refusal (both
# spellings, both lanes), the u32::MAX edge, the empty-target rung,
# the danger guard's pre-privilege rung, the JSON door's valueless
# verdict plus the genuine value error and the exit-code contract,
# and the help tiers. The root-lane shapes (the dead-id liveness
# gate, the once-per-process warning, the '::' separator tip, the
# unstrict honest tail) live post-privilege by design — their exact
# commands and expected verdicts ride the sibling guide,
# VERIFY_LOCAL_HARDENING_1.md.
#
# The battery targets the vendored fixed CLI in this directory by
# default; ZELYNIC_BIN overrides the binary under test (any build of
# the same tree answers the same verdicts).
#
# Usage:
#   ./scripts/labs-exp/verify-cli-ux.sh
#   ZELYNIC_BIN=./my-build ./scripts/labs-exp/verify-cli-ux.sh
#
# Exit 0 when every case passes, 1 on any failure. Pure English, no
# emoji — the repository is English-only (NIGHT-hunt-19).

set -u

# Root-owned __pycache__ wall (night-cafe-1): the JSON-door parses ride
# python3 -c, and the export keeps any interpreter this battery spawns
# from writing repo-local bytecode (docs/MAINTENANCE.md, the pycache
# class).
export PYTHONDONTWRITEBYTECODE=1

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=${ZELYNIC_BIN:-"$DIR/zelynic-fixed-cli-hardening-1"}
PASS=0
FAIL=0

if [ ! -x "$BIN" ]; then
	echo "FAIL  binary under test not executable: $BIN"
	echo "      ZELYNIC_BIN=<path> names another build, or build from source:"
	echo "      ./scripts/dev/bootstrap-ebpf.sh"
	exit 1
fi

check() {
	local name="$1"
	shift
	local expect="$1"
	shift
	local out
	out=$("$BIN" "$@" 2>&1)
	if echo "$out" | grep -qF "$expect"; then
		echo "PASS  $name"
		PASS=$((PASS + 1))
	else
		echo "FAIL  $name"
		echo "      expected grep: $expect"
		echo "      got: $(echo "$out" | head -4 | tr '\n' '|')"
		FAIL=$((FAIL + 1))
	fi
}

# The danger guard's pre-privilege rung: a live dangerous name is
# refused with the same wording and the --force-this tip before any
# privilege ask.
check "danger guard: sshd refused, force tip" \
	"is a system process" s sshd 1mb
check "danger guard: tip line present" \
	"re-run with --force-this" s sshd 1mb

# The 32-bit numeric-boundary refusal (the owner's safety call), the
# bare spelling: refuses at the input boundary with the bound named.
check "boundary: huge bare digits single" \
	"too large for a cgroup id" s 100000000000000000 1mb
check "boundary: bound named (32 bits)" \
	"inside 32 bits" s 100000000000000000 1mb
check "boundary: list-apps tip rides" \
	"list-apps" s 100000000000000000 1mb

# The cg: display spelling, same refusal.
check "boundary: cg: spelling refused" \
	"too large for a cgroup id" s cg:99999999999 1mb

# The list lane (validate_multi_targets), the bound named per member.
check "boundary: huge member in :: list" \
	"too large for a cgroup id" s 5000000000::brave 1mb
check "boundary: list lane names the member" \
	"list member '5000000000'" s 5000000000::brave 1mb

# u32 edge: 4294967295 is INSIDE the id space and must NOT refuse at
# the boundary (it flows to the privilege ladder as an id).
out=$("$BIN" s 4294967295 1mb 2>&1)
if echo "$out" | grep -q "too large for a cgroup id"; then
	echo "FAIL  boundary: u32::MAX wrongly refused"
	FAIL=$((FAIL + 1))
else
	echo "PASS  boundary: u32::MAX not refused (flows to privilege ladder)"
	PASS=$((PASS + 1))
fi

# The empty-target boundary (NIGHT-dinner-16, the same door).
check "boundary: empty target refused" \
	"target is empty" s "" 1mb

# The JSON door (the owner's "leaks bug"): a value-taking flag with
# NO value renders the prose verdict byte-for-clap, never
# "invalid value ''".
out=$("$BIN" ee --depth --print-json --focus 2>&1)
if echo "$out" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d['error'] == \"a value is required for '--focus <SECONDS>' but none was supplied\", d
assert d['tip'] == '', d
" 2>/dev/null; then
	echo "PASS  json door: valueless --focus renders prose verdict"
	PASS=$((PASS + 1))
else
	echo "FAIL  json door: valueless --focus"
	echo "      got: $out"
	FAIL=$((FAIL + 1))
fi

# A GENUINE non-empty value error keeps its own verdict on the JSON
# lane. The target rides first: --depth without one refuses at the
# target door before the value door (the parse-before-execute
# ladder), so the genuine value error needs a resolvable shape to
# reach its rung. The focus door is the command's own validator (the
# runtime chain), so the honest verdict is the bounded-window
# sentence, tip empty.
out=$("$BIN" ee 123 --depth --print-json --focus 0 2>&1)
if echo "$out" | grep -qF "Invalid focus window '0': must be between 1s and 30s"; then
	echo "PASS  json door: genuine value error kept (runtime verdict)"
	PASS=$((PASS + 1))
else
	echo "FAIL  json door: genuine value error kept"
	echo "      got: $out"
	FAIL=$((FAIL + 1))
fi

# The JSON lane's exit-code contract.
"$BIN" ee --depth --print-json --focus >/dev/null 2>&1
if [ $? -eq 1 ]; then
	echo "PASS  json door: exit 1"
	PASS=$((PASS + 1))
else
	echo "FAIL  json door: exit 1"
	FAIL=$((FAIL + 1))
fi

# The help rewrite: ee -h is the short tier — the lineage
# archaeology must stay OUT of the terminal help.
out=$("$BIN" ee -h 2>&1)
if echo "$out" | grep -q "NIGHT-"; then
	echo "FAIL  help: ee -h still carries lineage"
	FAIL=$((FAIL + 1))
else
	echo "PASS  help: ee -h clean of lineage"
	PASS=$((PASS + 1))
fi
lines=$(echo "$out" | wc -l)
if [ "$lines" -le 40 ]; then
	echo "PASS  help: ee -h compact ($lines lines)"
	PASS=$((PASS + 1))
else
	echo "FAIL  help: ee -h wall ($lines lines)"
	FAIL=$((FAIL + 1))
fi

# --help is the detail tier: the full contract stays reachable.
out=$("$BIN" ee --help 2>&1)
if echo "$out" | grep -q "USAGE.md"; then
	echo "PASS  help: --help points to the lineage home (USAGE.md)"
	PASS=$((PASS + 1))
else
	echo "FAIL  help: --help lineage pointer"
	FAIL=$((FAIL + 1))
fi

# The launcher's own help stays the curated reference.
out=$("$BIN" -h 2>&1)
if echo "$out" | grep -q "eagle-eyes"; then
	echo "PASS  help: root -h curated reference alive"
	PASS=$((PASS + 1))
else
	echo "FAIL  help: root -h reference"
	FAIL=$((FAIL + 1))
fi

echo "----"
echo "battery: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
