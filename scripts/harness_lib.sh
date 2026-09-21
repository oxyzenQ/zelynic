# shellcheck shell=bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Shared helpers for the colored root-run harnesses (NIGHT-hunt-21
# dedup): crash-recovery-test.sh, race-condition-test.sh, and
# reload-test.sh carried three drifting copies of this block — the
# counters and log functions were byte-identical, but check_root's
# and check_binary's error wording had already diverged between the
# copies, and every color variable was truncated to a bare ESC
# ('\033' with the CSI parameters lost), so each "colored" line ever
# printed carried a stray escape byte and no color at all. One place
# now — the bash twin of scripts/zelynic_harness_lib.py (the
# NIGHT-improve-11 precedent for the python harnesses).
#
# No shebang on purpose: this file is sourced, never executed, so
# the 644 permission rule applies (same discipline as
# zelynic_harness_lib.py).
#
# Contract with the sourcing harness:
#   - source it AFTER the harness's own `set` flags are chosen
#     (each harness keeps its own -e/-u policy)
#   - BINARY is resolved here only if the harness has not set it
#     (argv[1] override, else ./target/release/zelynic)
#   - counters PASS / FAIL / TOTAL start at 0; log_* bump them
#   - cleanup() stays harness-owned — teardown is script-specific

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

BINARY="${BINARY:-${1:-./target/release/zelynic}}"

log_pass() {
	echo -e "  ${GREEN}OK PASS${NC}: $1"
	PASS=$((PASS + 1))
}

log_fail() {
	echo -e "  ${RED}X FAIL${NC}: $1"
	FAIL=$((FAIL + 1))
}

log_test() {
	echo ""
	echo -e "  ${YELLOW}TEST${NC}: $1"
	TOTAL=$((TOTAL + 1))
}

check_root() {
	if [ "$(id -u)" -ne 0 ]; then
		echo -e "${RED}ERROR: This test requires root. Run with sudo.${NC}"
		exit 1
	fi
}

check_binary() {
	if [ ! -f "$BINARY" ]; then
		echo -e "${RED}ERROR: Binary not found: $BINARY${NC}"
		echo "Build first: cargo build --release --features ebpf"
		exit 1
	fi
}
