#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Crash recovery test suite — verifies zelynic survives crash scenarios.
#
# Tests:
#   1. Clean state baseline
#   2. Apply limit, verify active
#   3. Simulate crash (remove program pins → stale state)
#   4. Run 'recover' → verify cleanup
#   5. Apply limit, simulate partial pin state
#   6. Run 'strict' → verify auto-recovery
#   7. Apply limit, kill -9 (if zelynic were running), verify 'recover' cleans
#   8. Multiple crash-recover cycles
#   9. Final state verification
#
# NIGHT-hunt-32 (the suite's resurrection): $PIN_DIR was referenced
# eight times with nothing defining it — under this suite's own
# `set -euo pipefail` every run died at Test 1 ("PIN_DIR: unbound
# variable"), so 8 of 9 tests never executed anywhere since the
# NIGHT-hunt-21 dedup. The pin constant now lives in harness_lib.sh.
# Two more diseases from the same family died here: the "enforcing"/
# "Stale" greps matched strings the status surface never prints (the
# live verdict lines are "no active limits" and "stale bpf pin files
# detected", display.rs), and every apply targeted the comm "curl"
# with no curl process running — dinner-11's no-match hard error meant
# each apply failed silently (2>/dev/null) and the verdicts failed for
# the wrong reason. A long-lived sleep target now carries the applies,
# and the greps ride the display contract.

set -euo pipefail

# Shared colored-harness helpers (NIGHT-hunt-21): log_* / check_* /
# counters / BINARY resolution live in one sourced place (scripts/lib/
# since NIGHT-refactor-1 — one directory up from this category dir).
# shellcheck source=scripts/lib/harness_lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/harness_lib.sh"

cleanup() {
	"$BINARY" u --all 2>/dev/null || true
}

# A long-lived target for every apply in this suite (NIGHT-hunt-32 —
# see the header): the sleep twin is the pattern race-condition-
# test.sh's Test 5 and reload-test.sh already use.
sleep 600 &
TARGET_PID=$!
TARGET_COMM="$(cat /proc/$TARGET_PID/comm 2>/dev/null || echo "sleep")"
trap 'kill "${TARGET_PID:-0}" 2>/dev/null || true; cleanup' EXIT

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

echo "━━━ zelynic Crash Recovery Test Suite ━━━"
echo "Binary: $BINARY"
echo ""

check_root
check_binary
cleanup

# Test 1: Clean state baseline
log_test "Clean state baseline — no pins should exist"
if [ ! -d "$PIN_DIR" ] || [ -z "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
	log_pass "Pin directory is clean"
else
	log_fail "Pin directory has files (run 'zelynic u --all' first)"
fi

# Test 2: Apply limit, verify active
log_test "Apply limit, verify BPF is active"
"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || true
sleep 1
# The display contract: "no active limits" is the empty VERDICT line
# (display.rs) — anything else that is non-empty means live rows.
out="$("$BINARY" status 2>/dev/null || true)"
if [ -n "$out" ] && ! grep -q "no active limits" <<<"$out"; then
	log_pass "BPF is active after strict"
else
	log_fail "BPF not active after strict"
fi

# Test 3: Simulate crash — remove program pins (stale state)
log_test "Simulate crash — remove program pins (stale state)"
rm -f "$PIN_DIR/enforce_dl" "$PIN_DIR/enforce_ul" 2>/dev/null || true
out="$("$BINARY" status 2>/dev/null || true)"
if grep -q "stale bpf pin files" <<<"$out"; then
	log_pass "Status detects stale state"
else
	log_fail "Status does not detect stale state"
fi

# Test 4: Run recover → verify cleanup
log_test "Run 'recover' → verify cleanup"
"$BINARY" recover 2>/dev/null
if [ ! -d "$PIN_DIR" ] || [ -z "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
	log_pass "Recover cleaned up stale pins"
else
	log_fail "Recover did not clean up pins"
fi

# Test 5: Apply limit, simulate partial pin state (remove one program pin)
log_test "Apply limit, simulate partial state (remove enforce_dl only)"
"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || true
sleep 1
rm -f "$PIN_DIR/enforce_dl" 2>/dev/null || true
out="$("$BINARY" status 2>/dev/null || true)"
if grep -q "stale bpf pin files" <<<"$out"; then
	log_pass "Status detects partial state"
else
	log_fail "Status does not detect partial state"
fi

# Test 6: Run strict → verify auto-recovery
log_test "strict auto-recovers from stale state"
"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || true
sleep 1
out="$("$BINARY" status 2>/dev/null || true)"
if [ -n "$out" ] && ! grep -q "no active limits" <<<"$out"; then
	log_pass "strict auto-recovered"
else
	log_fail "strict did not auto-recover"
fi

# Test 7: Doctor reports pin state
log_test "Doctor reports pin state correctly"
cleanup
"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || true
sleep 1
if "$BINARY" doctor 2>/dev/null | grep -q "Pins:"; then
	log_pass "Doctor shows pin state"
else
	log_fail "Doctor does not show pin state"
fi

# Test 8: Multiple crash-recover cycles
log_test "Multiple crash-recover cycles (3x)"
cleanup
for i in 1 2 3; do
	"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || true
	sleep 0.5
	# Simulate crash — remove program pins
	rm -f "$PIN_DIR/enforce_dl" "$PIN_DIR/enforce_ul" 2>/dev/null
	"$BINARY" recover 2>/dev/null
	if [ -d "$PIN_DIR" ] && [ -n "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
		log_fail "Cycle $i: pins remain after recover"
		break
	fi
done
if [ "$FAIL" -eq 0 ]; then
	log_pass "All 3 crash-recover cycles succeeded"
fi

# Test 9: Final state verification
log_test "Final state — should be clean after u --all"
"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || true
"$BINARY" u --all 2>/dev/null
if [ ! -d "$PIN_DIR" ] || [ -z "$(ls -A "$PIN_DIR" 2>/dev/null)" ]; then
	log_pass "Final state is clean"
else
	log_fail "Final state has residual pins"
fi

# Summary
echo ""
echo "━━━ Results ━━━"
echo "  Total: $TOTAL"
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"

if [ "$FAIL" -gt 0 ]; then
	exit 1
fi
exit 0
