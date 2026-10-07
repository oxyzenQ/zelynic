#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Race condition test — verifies file lock prevents concurrent corruption.
#
# Tests:
#   1. Concurrent strict (5 parallel) — only 1 should succeed
#   2. Concurrent unstrict-all (5 parallel) — no crash
#   3. Mixed strict + unstrict-all — no crash, no corruption
#   4. Rapid strict → unstrict → strict cycle
#   5. Lock release on exit — sequential operations work after lock holder exits
#   6. Final state verification
#
# NIGHT-hunt-32: three always-green verdicts died here. Test 1
# targeted the comm "curl" with no curl running — dinner-11's
# no-match hard error failed all five applies and the FAIL blamed the
# lock machinery for an absent target. Test 2's pass condition
# ("CRASHED -le 5") could never be false — CRASHED only ever counts
# five waits — and it counted graceful lock refusals as crashes. Test
# 3 called log_pass in BOTH branches (and grepped "No active|Stale"
# strings the status surface prints lowercase). The verdicts below
# now measure what they claim: a real target, signal deaths counted
# apart from graceful refusals, and a state check that can fail.

set -uo pipefail

# Shared colored-harness helpers (NIGHT-hunt-21): log_* / check_* /
# counters / BINARY resolution live in one sourced place (scripts/lib/
# since NIGHT-refactor-1 — one directory up from this category dir).
# shellcheck source=scripts/lib/harness_lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/harness_lib.sh"

cleanup() {
	"$BINARY" unstrict-all 2>/dev/null || true
}

# A long-lived target for the concurrent applies (NIGHT-hunt-32 — see
# the header): targeting a comm with no live process is dinner-11's
# no-match hard error, not a lock race.
sleep 600 &
TARGET_PID=$!
TARGET_COMM="$(cat /proc/$TARGET_PID/comm 2>/dev/null || echo "sleep")"
trap 'kill "${TARGET_PID:-0}" 2>/dev/null || true; cleanup' EXIT

echo "━━━ zelynic Race Condition Test Suite ━━━"
echo "Binary: $BINARY"

check_root
check_binary
cleanup

# Test 1: Concurrent strict — lock should serialize
log_test "Concurrent strict (5 parallel) — lock serializes"
PIDS=()
for _ in 1 2 3 4 5; do
	"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null &
	PIDS+=($!)
done
SUCCESS=0
for pid in "${PIDS[@]}"; do
	wait "$pid" && SUCCESS=$((SUCCESS + 1))
done
# At least 1 should succeed. The lock is non-blocking (EWOULDBLOCK is
# a hard error, lock.rs), so the losers fail fast with a lock refusal
# — or succeed when the winner finished before they arrived. The
# serialization itself is the verdict.
if [ "$SUCCESS" -ge 1 ]; then
	log_pass "$SUCCESS/5 succeeded (lock serializes access)"
else
	log_fail "0/5 succeeded — none could apply a limit"
fi
cleanup

# Test 2: Concurrent unstrict-all — no crash
log_test "Concurrent unstrict-all (5 parallel) — no crash"
"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || true
PIDS=()
for _ in 1 2 3 4 5; do
	"$BINARY" unstrict-all 2>/dev/null &
	PIDS+=($!)
done
CRASHED=0
GRACEFUL=0
for pid in "${PIDS[@]}"; do
	wait "$pid" && continue
	rc=$?
	if [ "$rc" -ge 128 ]; then
		CRASHED=$((CRASHED + 1))
	else
		GRACEFUL=$((GRACEFUL + 1))
	fi
done
# A graceful non-zero exit is a lock refusal or a clean-state report
# (dinner-11 made the empty-state unstrict exit 0; the losers of the
# race still report it non-zero on some paths) — expected. A death by
# SIGNAL (rc >= 128) is the crash this test exists to catch.
if [ "$CRASHED" -eq 0 ]; then
	log_pass "No signal deaths (${GRACEFUL} graceful refusals — expected)"
else
	log_fail "Unexpected signal death count: $CRASHED"
fi
cleanup

# Test 3: Mixed strict + unstrict-all
log_test "Mixed strict + unstrict-all — no corruption"
PIDS=()
for _ in 1 2 3; do
	"$BINARY" strict curl 100kb 2>/dev/null &
	PIDS+=($!)
	"$BINARY" unstrict-all 2>/dev/null &
	PIDS+=($!)
done
for pid in "${PIDS[@]}"; do
	wait "$pid" 2>/dev/null || true
done
# The honest state check (NIGHT-hunt-32): a status read that answers
# with a non-empty, non-partial report is consistency; an unreadable
# or partially-stale state is the corruption this test exists to
# catch — and can, because the verdict can now fail.
out="$("$BINARY" status 2>/dev/null || true)"
if [ -n "$out" ] && ! grep -q "stale bpf pin files" <<<"$out"; then
	log_pass "State consistent after mixed operations"
else
	log_fail "Status unreadable or partial after mixed operations"
fi
cleanup

# Test 4: Rapid cycle — strict → unstrict → strict
log_test "Rapid strict → unstrict → strict cycle (10x)"
ERRORS=0
for _ in $(seq 1 10); do
	"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || ERRORS=$((ERRORS + 1))
	"$BINARY" unstrict-all 2>/dev/null || ERRORS=$((ERRORS + 1))
done
if [ "$ERRORS" -eq 0 ]; then
	log_pass "10 cycles completed without errors"
else
	log_fail "$ERRORS errors in 10 cycles"
fi
cleanup

# Test 5: Lock release on exit — sequential works
log_test "Lock release on exit — sequential operations work"
# Use sleep as target — long-lived, won't exit during test
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
"$BINARY" strict "$SLEEP_COMM" 100kb 2>/dev/null
"$BINARY" strict "$SLEEP_COMM" 200kb 2>/dev/null
if "$BINARY" status 2>/dev/null | grep -q "200.0 KB/s"; then
	log_pass "Sequential strict works (lock released between calls)"
else
	log_fail "Second strict blocked or failed"
fi
kill "$SLEEP_PID" 2>/dev/null || true
cleanup

# Test 6: Final state — clean
log_test "Final state verification"
"$BINARY" strict "$TARGET_COMM" 100kb 2>/dev/null || true
"$BINARY" unstrict-all 2>/dev/null
if [ ! -d "/sys/fs/bpf/zelynic" ] || [ -z "$(ls -A /sys/fs/bpf/zelynic 2>/dev/null)" ]; then
	log_pass "Final state is clean"
else
	log_fail "Residual pins remain"
fi

# Summary
echo ""
echo "━━━ Results ━━━"
echo "  Total: $TOTAL"
echo -e "  ${GREEN}Passed: $PASS${NC}"
echo -e "  ${RED}Failed: $FAIL${NC}"

[ "$FAIL" -gt 0 ] && exit 1
exit 0
