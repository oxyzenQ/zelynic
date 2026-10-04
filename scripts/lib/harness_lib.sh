# shellcheck shell=bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# Shared helpers for the colored root-run harnesses (NIGHT-hunt-21
# dedup): crash-recovery-test.sh, race-condition-test.sh, and
# reload-test.sh carried three drifting copies of this block — the
# counters and log functions were byte-identical, but check_root's
# and check_binary's error wording had already diverged between the
# copies, and every color variable was truncated to a bare ESC
# ('\033' with the CSI parameters lost), so each "colored" line ever
# printed carried a stray escape byte and no color at all. One place
# now — the bash twin of scripts/lib/zelynic_harness_lib.py (the
# NIGHT-improve-11 precedent for the python harnesses).
#
# No shebang on purpose: this file is sourced, never executed, so
# the 644 permission rule applies (same discipline as
# zelynic_harness_lib.py).
#
# NIGHT-hunt-32 heals carried here (the dedup's own unfinished edge):
#   - PIN_DIR is defined — the bash twin of the python lib's constant
#     and pin.rs's PIN_DIR. crash-recovery-test.sh referenced it eight
#     times while nothing defined it: under that suite's own
#     `set -euo pipefail` it died at Test 1 on every machine since the
#     NIGHT-hunt-21 dedup moved the helpers here without the constant.
#   - the default binary is REPO-ANCHORED (never CWD-relative) and
#     version-GATED against Cargo.toml — the python twin's
#     NIGHT-improve-16 discipline, bash form: a stale decoy build must
#     never be tested silently (the 2026-09-21 debian13 lesson).
#   - the build remedy names the living flow: bootstrap-ebpf.sh
#     (NIGHT-cleanup-3 retired the plain `cargo build --release`
#     path the old remedy told people to run).
#
# NIGHT-hunt-33 (the resolver twin lag — the owner's nightpc run made
# it visible): benchmarking.py found target/pro-linux-amd64-v3-gnu/
# zelynic while reload/crash/race died at "Binary not found:
# target/release/zelynic" — the python twin scans every alias output
# (REPO_BINARY_CANDIDATES), the bash twin still had a single hardcoded
# release default. The ladder below is the python twin's
# resolve_binary, verbatim: explicit argv (--binary PATH or the
# positional path), then ZELYNIC_BINARY, then the NEWEST-mtime repo
# build ("test what was just built" — a fresh pro-linux build
# outranks a stale release binary of older code), PATH last. The pick
# note carries the mtimes so mixed release/alias trees stay easy to
# tell apart, and check_binary's version gate refuses decoys
# whichever way the pick happened.
#
# Contract with the sourcing harness:
#   - source it AFTER the harness's own `set` flags are chosen
#     (each harness keeps its own -e/-u policy)
#   - BINARY is resolved here only if the harness has not set it:
#     --binary PATH or the positional path, then ZELYNIC_BINARY, then
#     the newest repo build, then PATH (resolve_binary's ladder)
#   - counters PASS / FAIL / TOTAL start at 0; log_* bump them
#   - cleanup() stays harness-owned — teardown is script-specific

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0
TOTAL=0

# Repo anchor (the python twin's REPO_ROOT discipline): the default
# binary must never depend on the caller's CWD.
HARNESS_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HARNESS_LIB_DIR}/../.." && pwd)"

# The product's pin directory (pin.rs:13, the python lib's PIN_DIR) —
# sourced harnesses read pins through this constant, never a literal.
# shellcheck disable=SC2034 # consumed by the sourcing harnesses, not this file
PIN_DIR="/sys/fs/bpf/zelynic"

# Repo-local build outputs of the canonical build commands — the
# bash twin of the python lib's REPO_BINARY_CANDIDATES
# (.cargo/config.toml is the source of truth for where each command
# lands): the legacy root copy, pro-native-gnu/musl, the four
# pro-linux release shapes, and the plain release build. Among the
# candidates that exist, the NEWEST mtime wins — test what was just
# built, not what was built longest ago.
HARNESS_BINARY_CANDIDATES=(
	"${REPO_ROOT}/zelynic"
	"${REPO_ROOT}/target/pro-native-gnu/zelynic"
	"${REPO_ROOT}/target/x86_64-unknown-linux-musl/pro-native-musl/zelynic"
	"${REPO_ROOT}/target/pro-linux-amd64-v3-gnu/zelynic"
	"${REPO_ROOT}/target/pro-linux-amd64-v4-gnu/zelynic"
	"${REPO_ROOT}/target/x86_64-unknown-linux-musl/pro-linux-amd64-v3-musl/zelynic"
	"${REPO_ROOT}/target/x86_64-unknown-linux-musl/pro-linux-amd64-v4-musl/zelynic"
	"${REPO_ROOT}/target/release/zelynic"
)

# binary_label <path> — the alias that built a candidate
# (pro-linux-amd64-v3-gnu), not its whole path: the pick note stays
# one readable line even for the musl triple's nested directory.
binary_label() {
	local label="${1#"${REPO_ROOT}"/}"
	label="${label#target/}"
	label="${label#x86_64-unknown-linux-musl/}"
	label="${label%/zelynic}"
	if [ "${label}" = "zelynic" ]; then
		echo "repo-root copy"
	else
		echo "${label}"
	fi
}

# resolve_binary — the python twin's ladder, bash form. Sets BINARY
# and returns; check_binary owns the failure exit and report. Prints
# a pick note only when the scan had a real choice to name (two or
# more repo builds — the owner's tell-them-apart ask) or when PATH is
# the reason a binary was found at all.
resolve_binary() {
	local explicit="" cand m="" newest="" newest_m=0 existing=0 rest="" found
	if [ "${1:-}" = "--binary" ]; then
		if [ -z "${2:-}" ]; then
			echo "ERROR: --binary needs a path (e.g. --binary ./target/release/zelynic)" >&2
			exit 2
		fi
		explicit="${2}"
	elif [ -n "${1:-}" ]; then
		explicit="${1}"
	fi
	# The argv pick outranks the env pick (the python twin's order).
	explicit="${explicit:-${ZELYNIC_BINARY:-}}"
	if [ -n "${explicit}" ]; then
		BINARY="${explicit}"
		return 0
	fi
	for cand in "${HARNESS_BINARY_CANDIDATES[@]}"; do
		[ -x "${cand}" ] || continue
		existing=$((existing + 1))
		m="$(stat -c '%Y' "${cand}" 2>/dev/null || echo 0)"
		if [ "${m:-0}" -gt "${newest_m}" ]; then
			newest="${cand}"
			newest_m="${m:-0}"
		fi
	done
	if [ -n "${newest}" ]; then
		BINARY="${newest}"
		if [ "${existing}" -ge 2 ]; then
			for cand in "${HARNESS_BINARY_CANDIDATES[@]}"; do
				if [ -x "${cand}" ] && [ "${cand}" != "${newest}" ]; then
					rest="${rest:+${rest}, }$(binary_label "${cand}") ($(date -r "${cand}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?'))"
				fi
			done
			echo "  resolver: newest of ${existing} repo builds — $(binary_label "${newest}") ($(date -r "${newest}" '+%Y-%m-%d %H:%M' 2>/dev/null || echo '?')) over ${rest}"
		fi
		return 0
	fi
	found="$(command -v zelynic 2>/dev/null || true)"
	if [ -n "${found}" ]; then
		BINARY="${found}"
		echo "  resolver: no repo build — using the PATH zelynic (${found})"
		return 0
	fi
	# Nothing anywhere: leave BINARY empty and record the sweep for
	# check_binary's report (the python twin prints the same list).
	BINARY=""
	BINARY_TRIED="$(printf '%s, ' "${HARNESS_BINARY_CANDIDATES[@]}")PATH"
	return 0
}

# The rig-suite contract: resolve at source time unless the harness
# already chose (a pre-set BINARY is the harness's own pick — a
# sandbox-lane suite like install-flow-test.sh uses that hook).
if [ -z "${BINARY:-}" ]; then
	resolve_binary "$@"
fi

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
	if [ -z "${BINARY:-}" ]; then
		echo -e "${RED}ERROR: zelynic binary not found — no repo build and nothing on PATH.${NC}"
		echo "  Tried (repo builds first): ${BINARY_TRIED:-the shared candidate list}"
		echo "Build first: ./scripts/dev/bootstrap-ebpf.sh (eBPF toolchain pair + flagship binary)"
		echo "Or point at one: $(basename "${BASH_SOURCE[1]:-this-suite}") --binary ./target/pro-linux-amd64-v3-gnu/zelynic"
		exit 1
	fi
	if [ ! -f "${BINARY}" ]; then
		echo -e "${RED}ERROR: Binary not found: ${BINARY}${NC}"
		echo "Build first: ./scripts/dev/bootstrap-ebpf.sh (eBPF toolchain pair + flagship binary)"
		echo "Or point at a real one: $(basename "${BASH_SOURCE[1]:-this-suite}") --binary ./target/release/zelynic"
		exit 1
	fi
	# Version gate (NIGHT-improve-16, bash form): the harness tests THIS
	# checkout, never a decoy. Explicit overrides pass the same gate — a
	# wrong version means a wrong CLI surface and a wrong status schema:
	# every verdict would be decoy noise.
	local want got
	want="$(sed -n 's/^version = "\(.*\)"/\1/p' "${REPO_ROOT}/Cargo.toml" 2>/dev/null | head -1 || true)"
	got="$($BINARY -V 2>/dev/null | head -1 | sed -n 's/^zelynic: v//p' || true)"
	if [ -z "$want" ]; then
		echo -e "${YELLOW}WARN: version gate unavailable — no parsable version in ${REPO_ROOT}/Cargo.toml${NC}"
		return 0
	fi
	if [ "$got" != "$want" ]; then
		echo -e "${RED}ERROR: BINARY GATE — refusing to test a zelynic that is not this checkout's build.${NC}"
		echo "  ${BINARY} reports: ${got:-'(no version line)'}"
		echo "  this checkout is: v${want} (Cargo.toml) — a wrong version means a wrong"
		echo "  CLI surface and a wrong status schema: every verdict would be decoy noise."
		echo "Build first: ./scripts/dev/bootstrap-ebpf.sh"
		exit 1
	fi
}
