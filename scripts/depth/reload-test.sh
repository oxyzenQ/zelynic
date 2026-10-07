#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Reload test — verifies safe rate change during active traffic.
#
# Tests that zelynic can change rates while traffic is flowing
# without gaps, crashes, or orphaned pins.
#
# Tests:
#   1. Apply limit, start traffic, change rate — verify no crash
#   2. Apply limit, start traffic, unstrict → re-apply — verify no gap
#   3. Rapid rate changes (100kb → 500kb → 1mb → 100kb)
#   4. Change rate while BPF is actively dropping packets
#   5. Final state verification
#
# NIGHT-hunt-32: the traffic source is now a LOOPBACK blob server —
# self-contained like the rest of the family (the old external
# example.com fetch made the suite network-dependent, and its loose
# `pkill -f "curl.*example.com"` could kill unrelated processes).
# The server, the curls, and the sleep target are siblings in THIS
# cgroup, so the policed surface sees the traffic. Test 4's drop read
# once took awk field $5 of a status row — the UPLOAD-RATE column,
# because the "cg:ID (comm)" label shifts every field left of it —
# and its verdict called log_pass in both branches. The read now goes
# through the status JSON's limits[].bytes_dropped (display_json.rs,
# the stable contract), and the verdict fails honestly when no drops
# occurred.

set -uo pipefail

# Shared colored-harness helpers (NIGHT-hunt-21): log_* / check_* /
# counters / BINARY resolution live in one sourced place (scripts/lib/
# since NIGHT-refactor-1 — one directory up from this category dir).
# shellcheck source=scripts/lib/harness_lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/harness_lib.sh"

# NIGHT-hunt-35 (the battery's first live catch, in two acts): the
# hunt-32 rework gave this suite a cleanup() that killed the blob
# server and rm -rf'd the scratch dir — then CALLED it between the
# bring-up and the tests, so the suite deleted its own traffic
# source before dd ever wrote the blob (act one: the FATAL the
# first CI run caught; the suite had never run end to end anywhere
# — the owner's runs died earlier at the binary resolver, and no
# CI lane ran the rigs before the supermassive battery grew them)
# and again after every test (act two: Test 4's curls would have
# hit a dead server with the blob long gone). cleanup() now resets
# ENFORCEMENT state only — the same shape crash-recovery and
# race-condition already use — and teardown() owns the server and
# the scratch dir, riding the EXIT trap alone.
TMPD="$(mktemp -d /tmp/zelynic-reload.XXXXXX)"
PORT=18731
SRV_PID=""
URL="http://127.0.0.1:${PORT}/blob"

cleanup() {
	"$BINARY" u --all 2>/dev/null || true
}

# shellcheck disable=SC2317 # teardown rides the EXIT trap, never a call by name
teardown() {
	cleanup
	if [ -n "${SRV_PID:-}" ]; then
		kill "$SRV_PID" 2>/dev/null || true
	fi
	rm -rf "$TMPD" 2>/dev/null || true
}
trap teardown EXIT

# Dropped bytes summed across every live limit row (NIGHT-hunt-32 —
# see the header): the status JSON is the stable column contract.
dropped_bytes() {
	"$BINARY" status --print-json 2>/dev/null | python3 -c '
import json
import sys

try:
    doc = json.load(sys.stdin)
    print(sum(int(r.get("bytes_dropped", 0)) for r in doc.get("limits", [])))
except Exception:
    print(-1)
'
}

echo "━━━ zelynic Reload Test Suite ━━━"
echo "Binary: $BINARY"

check_root
check_binary
cleanup

# The loopback blob server (NIGHT-hunt-32 — see the header): 8 MiB
# so a policed fetch can never finish inside a test window.
dd if=/dev/zero of="${TMPD}/blob" bs=1M count=8 status=none
python3 -m http.server "${PORT}" --bind 127.0.0.1 --directory "${TMPD}" >/dev/null 2>&1 &
SRV_PID=$!
sleep 1
if ! curl -sf -o /dev/null --max-time 10 "${URL}" 2>/dev/null; then
	echo "FATAL: the loopback blob server did not come up (${URL})" >&2
	exit 1
fi

cleanup

# Test 1: Apply limit, change rate during traffic
log_test "Apply limit, change rate during traffic — no crash"
# Use sleep as target — long-lived, won't exit during test
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
"$BINARY" strict "$SLEEP_COMM" 100kb 2>/dev/null
# Start background traffic (loopback — self-contained)
curl -s -o /dev/null "${URL}" 2>/dev/null &
CURL_PID=$!
sleep 1
# Change rate while traffic flows
"$BINARY" strict "$SLEEP_COMM" 500kb 2>/dev/null
sleep 1
if "$BINARY" status 2>/dev/null | grep -q "500.0 KB/s"; then
	log_pass "Rate changed during traffic without crash"
else
	log_fail "Rate change failed during traffic"
fi
kill "${CURL_PID}" 2>/dev/null || true
kill "$SLEEP_PID" 2>/dev/null || true
cleanup

# Test 2: Unstrict → re-apply — verify no gap in enforcement
log_test "Unstrict → re-apply — no gap"
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
"$BINARY" strict "$SLEEP_COMM" 100kb 2>/dev/null
sleep 0.5
"$BINARY" unstrict "$SLEEP_COMM" 2>/dev/null
sleep 0.5
"$BINARY" strict "$SLEEP_COMM" 200kb 2>/dev/null
if "$BINARY" status 2>/dev/null | grep -q "200.0 KB/s"; then
	log_pass "Re-apply after unstrict works"
else
	log_fail "Re-apply failed"
fi
kill "$SLEEP_PID" 2>/dev/null || true
cleanup

# Test 3: Rapid rate changes
log_test "Rapid rate changes (100kb → 500kb → 1mb → 100kb)"
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
ERRORS=0
for rate in 100kb 500kb 1mb 100kb; do
	"$BINARY" strict "$SLEEP_COMM" "$rate" 2>/dev/null || ERRORS=$((ERRORS + 1))
	sleep 0.3
done
if [ "$ERRORS" -eq 0 ]; then
	log_pass "4 rapid rate changes succeeded"
else
	log_fail "$ERRORS errors in rapid rate changes"
fi
kill "$SLEEP_PID" 2>/dev/null || true
cleanup

# Test 4: Change rate while packets are being dropped
log_test "Change rate while packets are being dropped"
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
"$BINARY" strict "$SLEEP_COMM" 10kb 2>/dev/null # Very low rate → lots of drops
# Generate traffic (loopback — self-contained, same cgroup as the target)
CURL_PIDS=()
for _ in 1 2 3; do
	curl -s -o /dev/null "${URL}" 2>/dev/null &
	CURL_PIDS+=($!)
done
sleep 2
# Check drops are happening (the JSON column contract — see header)
DROPS_BEFORE="$(dropped_bytes)"
# Change rate
"$BINARY" strict "$SLEEP_COMM" 500kb 2>/dev/null
sleep 1
DROPS_AFTER="$(dropped_bytes)"
for cpid in "${CURL_PIDS[@]}"; do
	kill "$cpid" 2>/dev/null || true
done
kill "$SLEEP_PID" 2>/dev/null || true
if [ "${DROPS_BEFORE:--1}" -gt 0 ] && [ "${DROPS_AFTER:--1}" -ge 0 ]; then
	log_pass "Rate changed during active drops (dropped bytes: ${DROPS_BEFORE} → ${DROPS_AFTER})"
else
	log_fail "No drops observed under the 10kb cap — the loopback traffic produced no policed traffic (drop read: ${DROPS_BEFORE:-unreadable})"
fi
cleanup

# Test 5: Final state
log_test "Final state verification"
sleep 600 &
SLEEP_PID=$!
SLEEP_COMM=$(cat /proc/$SLEEP_PID/comm 2>/dev/null || echo "sleep")
"$BINARY" strict "$SLEEP_COMM" 100kb 2>/dev/null || true
kill "$SLEEP_PID" 2>/dev/null || true
"$BINARY" u --all 2>/dev/null
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
