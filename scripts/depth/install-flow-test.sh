#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Install/uninstall flow depth test (NIGHT-blade-8).
#
# Runs the REAL scripts/install.sh and scripts/uninstall.sh end to
# end as root — the exact privilege shape of a fresh server, a
# container, or the zelynic sandbox micro-VM (where NO sudo binary
# exists on PATH; the escalation fix is part of what this pins) —
# and verifies the whole artifact lifecycle:
#
#   1. pre-built --user install: ~/.local/bin/zelynic lands, -V
#      answers, the PATH-visible command runs
#   2. pre-built --system install AS ROOT WITHOUT SUDO: the
#      root-without-sudo contract (NIGHT-blade-8) — /usr/bin/zelynic
#      lands, doctor answers from PATH
#   3. enforcement before uninstall: a live strict policy leaves
#      pins in /sys/fs/bpf/zelynic
#   4. uninstall --user with enforcement live: warns, does NOT
#      clear kernel state (the no-escalation contract)
#   5. uninstall (default --all) as root: clears enforcement FIRST
#      (pins gone), removes every artifact, postconditions verified
#   6. idempotent re-run: "nothing found to remove", exit 0
#
# Safe to run in the sandbox (--run) or on any root eBPF-capable
# box; it creates and removes only its own staging directory, one
# throwaway cgroup with a sleeper process, and zelynic artifacts.
#
# Usage: ./scripts/depth/install-flow-test.sh [path-to-zelynic]
#
# Output: OK/X rows with a summary; exit 0 only when all pass.

set -uo pipefail

# ━━ Setup ━━

if [[ "$(id -u)" -ne 0 ]]; then
	echo "this suite needs root: it installs to /usr/bin and clears kernel"
	echo "enforcement. Run it in the zelynic sandbox (--run) or with privileges."
	exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../.." && pwd)"

BINARY="${1:-}"
if [[ -z "${BINARY}" ]]; then
	if [[ -x "/opt/zelynic/zelynic" ]]; then
		BINARY="/opt/zelynic/zelynic"
	elif [[ -x "${REPO_ROOT}/target/pro-native-gnu/zelynic" ]]; then
		BINARY="${REPO_ROOT}/target/pro-native-gnu/zelynic"
	else
		echo "no zelynic binary found (pass a path or run in the sandbox)"
		exit 1
	fi
fi

PASS=0
FAIL=0

pass() {
	echo "  OK   $1"
	PASS=$((PASS + 1))
}

fail() {
	echo "  X    $1"
	FAIL=$((FAIL + 1))
}

expect_gone() {
	# expect_gone <label> <path>
	if [[ ! -e "$2" ]]; then
		pass "$1"
	else
		fail "$1 (still present: $2)"
	fi
}

pins_present() {
	[[ -d /sys/fs/bpf/zelynic ]] || return 1
	local count
	count="$(find /sys/fs/bpf/zelynic -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
	[[ "${count}" -gt 0 ]]
}

STAGE="$(mktemp -d /tmp/zelynic-install-flow.XXXXXX)"
CG="/sys/fs/cgroup/zelynic-install-flow"
cleanup() {
	"${STAGE}/uninstall.sh" --all >/dev/null 2>&1 || true
	if [[ -d "${CG}" ]]; then
		local pid
		for pid in $(<"${CG}/cgroup.procs"); do
			kill "${pid}" 2>/dev/null || true
		done
		sleep 0.3
		rmdir "${CG}" 2>/dev/null || true
	fi
	rm -rf "${STAGE}"
}
trap cleanup EXIT

# Stage the release-payload shape: install.sh + uninstall.sh + the
# binary beside them (the pre-built mode's contract).
cp "${REPO_ROOT}/scripts/install.sh" "${REPO_ROOT}/scripts/uninstall.sh" "${STAGE}/"
cp "${BINARY}" "${STAGE}/zelynic"

echo "── install/uninstall flow depth test (root, $(uname -r)) ──"

# ━━ 1. pre-built --user install ━━

if "${STAGE}/install.sh" --user >/dev/null 2>&1 &&
	[[ -x "${HOME}/.local/bin/zelynic" ]] &&
	"${HOME}/.local/bin/zelynic" -V 2>/dev/null | head -n 1 | grep -q "^zelynic: v"; then
	pass "install.sh --user (pre-built): ~/.local/bin/zelynic answers -V"
else
	fail "install.sh --user (pre-built): ~/.local/bin/zelynic answers -V"
fi
USER_PATH="${HOME}/.local/bin:${PATH}"
if PATH="${USER_PATH}" zelynic -V >/dev/null 2>&1; then
	pass "the user-installed command is PATH-runnable"
else
	fail "the user-installed command is PATH-runnable"
fi

# ━━ 2. pre-built --system install, as root, NO sudo guarantee ━━
# The sandbox VM (and most containers) ship no sudo binary at all —
# this is the NIGHT-blade-8 contract: root without sudo succeeds.

if "${STAGE}/install.sh" --system >/dev/null 2>&1 &&
	[[ -x /usr/bin/zelynic ]] &&
	/usr/bin/zelynic -V 2>/dev/null | head -n 1 | grep -q "^zelynic: v"; then
	pass "install.sh --system as root without sudo: /usr/bin/zelynic answers -V"
else
	fail "install.sh --system as root without sudo: /usr/bin/zelynic answers -V"
fi
if /usr/bin/zelynic doctor >/dev/null 2>&1; then
	pass "doctor answers from the system path"
else
	fail "doctor answers from the system path"
fi

# ━━ 3. live enforcement before uninstall ━━

mkdir -p "${CG}" 2>/dev/null || true
bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"' worker "${CG}" sleep 300 &
sleep 0.5
CG_ID="$(stat -c %i "${CG}")"
if /usr/bin/zelynic strict-single "cg:${CG_ID}" 500kb >/dev/null 2>&1 && pins_present; then
	pass "a live strict policy leaves pins in /sys/fs/bpf/zelynic"
else
	fail "a live strict policy leaves pins in /sys/fs/bpf/zelynic"
fi

# ━━ 4. uninstall --user with enforcement live: no escalation ━━

if "${STAGE}/uninstall.sh" --user >"${STAGE}/user-uninstall.log" 2>&1 &&
	[[ ! -e "${HOME}/.local/bin/zelynic" ]] && pins_present; then
	pass "uninstall.sh --user: removes the user binary, leaves kernel state (no escalation)"
else
	fail "uninstall.sh --user: removes the user binary, leaves kernel state (no escalation)"
fi
if grep -qi "unstrict-all\|does not escalate" "${STAGE}/user-uninstall.log"; then
	pass "uninstall.sh --user names the still-active kernel state"
else
	fail "uninstall.sh --user names the still-active kernel state"
fi

# ━━ 5. uninstall (default) as root: enforcement first, then files ━━

if "${STAGE}/uninstall.sh" >"${STAGE}/all-uninstall.log" 2>&1; then
	pass "uninstall.sh (default, root) exits 0"
else
	fail "uninstall.sh (default, root) exits 0"
fi
if ! pins_present; then
	pass "kernel enforcement cleared BEFORE file removal (pins gone)"
else
	fail "kernel enforcement cleared BEFORE file removal (pins gone)"
	echo "── uninstall.sh output (the failing run) ──"
	sed -n '1,40p' "${STAGE}/all-uninstall.log"
	echo "── pin dir state ──"
	find /sys/fs/bpf -mindepth 1 -maxdepth 2 2>/dev/null | head -10
fi
expect_gone "the system binary is gone" /usr/bin/zelynic
expect_gone "the user binary is gone" "${HOME}/.local/bin/zelynic"
expect_gone "the legacy object dir is gone" "/usr/lib/zelynic"
if /usr/bin/zelynic -V >/dev/null 2>&1; then
	fail "no zombie command answers from /usr/bin"
else
	pass "no zombie command answers from /usr/bin"
fi

# ━━ 6. idempotent re-run ━━

if "${STAGE}/uninstall.sh" >"${STAGE}/idempotent.log" 2>&1 &&
	grep -q "nothing found to remove" "${STAGE}/idempotent.log"; then
	pass "idempotent re-run: nothing found, exit 0"
else
	fail "idempotent re-run: nothing found, exit 0"
fi

# ━━ Summary ━━

echo "── summary: ${PASS} passed, ${FAIL} failed ──"
if [[ "${FAIL}" -gt 0 ]]; then
	exit 1
fi
