#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Uninstall zelynic: kernel enforcement first, then every on-disk artifact.
#
# The order is the contract (NIGHT-improve-15): removing the binary while
# limits are live leaves BPF programs pinned in /sys/fs/bpf/zelynic —
# enforcement keeps running with NO tool left to remove it. So before any
# file is deleted, the script checks the pin directory; when pins exist
# and a zelynic binary is still available, it runs `zelynic unstrict-all`
# (escalating only in the sudo-sanctioned modes) and verifies the pins
# are gone. When no binary is available, it says exactly what is still
# enforcing and how to clear it by hand. Never silent, never a trap.
#
# Auto-detects and removes from:
#   binary:       /usr/bin/, ~/.local/bin/
#   legacy BPF object dirs (pre-phase-3 installs shipped loose
#   .o files): /usr/lib/zelynic/, ~/.local/lib/zelynic/ — still
#   removed so upgrades from old installs leave nothing behind.
#   The phase-3 binary is self-contained (objects embedded).
#   legacy pid file: /tmp/zelynic.pid (old installations only).
#
# Postconditions are verified (NIGHT-improve-15): every path this script
# removed is checked to be gone afterwards, and any failed removal is
# reported and reflected in the exit status — a green run means clean.
# Bootstrap host tools are NOT touched: bpf-linker in ~/.local/bin and
# the dated nightly toolchain pin serve any future from-source build;
# the final note names them and their manual removal commands.
#
# Usage:
#   ./uninstall.sh [--system|--user|--all]
#
# Sudo is used only for system paths and, in --system/--all modes, to
# clear still-active kernel enforcement. Run WITHOUT sudo.

set -uo pipefail

PROJECT_NAME="zelynic"
REPO_URL="https://github.com/oxyzenQ/zelynic"
PIN_DIR="/sys/fs/bpf/${PROJECT_NAME}"
LEGACY_PID_FILE="/tmp/${PROJECT_NAME}.pid"
SUDO_MODES="--system --all"

usage() {
	cat <<EOF
Usage: $0 [--system|--user|--all]

  (default)  Auto-detect: clear kernel enforcement if active, then
	     scan /usr/bin, ~/.local/bin and remove every
	     ${PROJECT_NAME} artifact found. Sudo for system paths
	     and enforcement clearing.
  --system   Remove only from /usr/bin and /usr/lib/${PROJECT_NAME} (uses sudo).
  --user     Remove only from ~/.local/bin and ~/.local/lib/${PROJECT_NAME} (no sudo;
	     active kernel limits are reported, not cleared — re-run
	     with --system or see the printed manual steps).
  --all      Same as default.

Sudo is used only for system paths and enforcement clearing
(--system/--all). Run WITHOUT sudo.
EOF
}

MODE="--all"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--system)
		MODE="--system"
		shift
		;;
	--user)
		MODE="--user"
		shift
		;;
	--all)
		MODE="--all"
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown argument: $1" >&2
		usage
		exit 2
		;;
	esac
done

sudo_capable() {
	[[ "${SUDO_MODES}" == *"${MODE}"* ]]
}

# Escalation prefix (NIGHT-blade-8): a root shell without a sudo
# binary on PATH — containers, minimal VMs, the zelynic sandbox,
# hardened servers — already IS the privilege the removal needs;
# asking for sudo there failed uninstalls that had every right to
# succeed. Non-root without sudo keeps the plain command (and the
# postcondition check below reports the failure honestly).
SUDO_CMD=()
if [[ "$(id -u)" -ne 0 ]]; then
	SUDO_CMD=(sudo)
fi

esc() {
	# $1: yes -> the escalation prefix (when this mode may
	# escalate), else nothing
	if [[ "$1" == "yes" ]]; then
		printf '%s\n' "${SUDO_CMD[*]}"
	else
		printf '%s\n' ""
	fi
}

SYSTEM_BIN="/usr/bin"
SYSTEM_BPF="/usr/lib/${PROJECT_NAME}"
USER_BIN="${HOME}/.local/bin"
USER_BPF="${HOME}/.local/lib/${PROJECT_NAME}"
removed=0
failures=0

pins_present() {
	[[ -d "${PIN_DIR}" ]] || return 1
	# Any entry at all (including hidden) means enforcement state exists.
	local count
	count="$(find "${PIN_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
	[[ "${count}" -gt 0 ]]
}

remove_at() {
	local target="$1"
	local need_sudo="$2"
	local pre
	pre="$(esc "${need_sudo}")"
	if [[ -e "${target}" ]]; then
		if [[ -n "${pre}" && "$(id -u)" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
			echo "   FAILED: ${target} needs root and sudo is not on PATH" >&2
			failures=$((failures + 1))
			return 1
		fi
		if ! ${pre} rm -rf "${target}"; then
			echo "   FAILED to remove: ${target} (see the error above)" >&2
			failures=$((failures + 1))
			return 1
		fi
		if [[ -e "${target}" ]]; then
			echo "   FAILED: ${target} is still present after removal" >&2
			failures=$((failures + 1))
			return 1
		fi
		echo "   removed: ${target}"
		removed=$((removed + 1))
	fi
	return 0
}

# ── 1. Kernel enforcement guard — BEFORE any file removal ──────────────────
# Pins under /sys/fs/bpf/zelynic mean limits (or block policies) are live in
# the kernel. Deleting the binary first would strand them: enforcement
# continues with no command left to remove it. The guard clears them while a
# zelynic binary still exists on this machine, and says exactly what to do
# when it cannot.
clear_enforcement() {
	local bin bin_candidates candidate version_line
	if ! pins_present; then
		return 0
	fi
	echo ">> Active kernel state found (${PIN_DIR} has pins)"
	# Prefer the binary this run is about to remove; fall back to PATH.
	bin_candidates="${SYSTEM_BIN}/${PROJECT_NAME} ${USER_BIN}/${PROJECT_NAME}"
	bin=""
	for candidate in ${bin_candidates}; do
		if [[ -x "${candidate}" ]]; then
			bin="${candidate}"
			break
		fi
	done
	if [[ -z "${bin}" ]] && command -v "${PROJECT_NAME}" >/dev/null 2>&1; then
		bin="$(command -v "${PROJECT_NAME}")"
	fi
	if [[ -z "${bin}" ]]; then
		echo "   WARNING: no ${PROJECT_NAME} binary left on this machine to clear enforcement." >&2
		echo "   Limits stay active in the kernel. Manual cleanup (as root):" >&2
		echo "     sudo rm -rf ${PIN_DIR}" >&2
		echo "   (removing the link pins detaches the programs; removing the whole" >&2
		echo "    directory unpins maps and programs — this is what 'unstrict-all' does.)" >&2
		return 0
	fi
	version_line="$("${bin}" -V 2>/dev/null | head -n 1 || true)"
	if [[ "${version_line}" != "${PROJECT_NAME}: v"* ]]; then
		echo "   WARNING: ${bin} does not answer -V ('${version_line}') — not using it." >&2
		echo "   Manual cleanup (as root): sudo rm -rf ${PIN_DIR}" >&2
		return 0
	fi
	if ! sudo_capable; then
		echo "   WARNING: kernel state is machine-wide; --user mode does not escalate." >&2
		echo "   Clear it with: sudo ${bin} unstrict-all" >&2
		return 0
	fi
	echo ">> Clearing kernel enforcement: ${bin} unstrict-all"
	if ! "${SUDO_CMD[@]}" "${bin}" unstrict-all; then
		echo "   WARNING: 'unstrict-all' failed — kernel state may still be active." >&2
	fi
	if pins_present; then
		echo "   WARNING: pins still present in ${PIN_DIR}." >&2
		echo "   Manual cleanup (as root): sudo rm -rf ${PIN_DIR}" >&2
	else
		echo "   kernel state cleared (pin directory is empty)."
	fi
	return 0
}

running_instances() {
	# A running zelynic (eagle-eyes) survives binary deletion — the
	# process keeps its deleted inode. Informational only: it exits when
	# its terminal closes; enforcement never depended on it.
	local comm_path pid
	for comm_path in /proc/[0-9]*/comm; do
		[[ -r "${comm_path}" ]] || continue
		if [[ "$(head -n 1 "${comm_path}" 2>/dev/null)" == "${PROJECT_NAME}" ]]; then
			pid="${comm_path#/proc/}"
			echo "   running instance: pid ${pid%%/*} (survives removal; exits on its own)"
		fi
	done
	return 0
}

echo ">> Uninstalling ${PROJECT_NAME}"

clear_enforcement
running_instances

case "${MODE}" in
--system)
	remove_at "${SYSTEM_BIN}/${PROJECT_NAME}" yes
	remove_at "${SYSTEM_BPF}" yes
	;;
--user)
	remove_at "${USER_BIN}/${PROJECT_NAME}" no
	remove_at "${USER_BPF}" no
	;;
--all)
	remove_at "${SYSTEM_BIN}/${PROJECT_NAME}" yes
	remove_at "${SYSTEM_BPF}" yes
	remove_at "${USER_BIN}/${PROJECT_NAME}" no
	remove_at "${USER_BPF}" no
	;;
esac

# Legacy pid file from old installations (modern zelynic writes none).
if [[ -e "${LEGACY_PID_FILE}" ]]; then
	if rm -f "${LEGACY_PID_FILE}" 2>/dev/null; then
		echo "   removed: ${LEGACY_PID_FILE} (legacy pid file)"
		removed=$((removed + 1))
	else
		echo "   note: ${LEGACY_PID_FILE} needs root: sudo rm -f ${LEGACY_PID_FILE}" >&2
	fi
fi

if [[ ${removed} -eq 0 && ${failures} -eq 0 ]]; then
	echo "   (nothing found to remove)"
fi

if [[ ${failures} -gt 0 ]]; then
	echo ">> Done with ${failures} FAILURE(S). Removed ${removed} artifact(s);"
	echo "   the failed paths above are still present — inspect and remove them."
	exit 1
fi

echo ">> Done. Removed ${removed} artifact(s)."
echo "  - Docs: ${REPO_URL}#readme"
echo "  - Bootstrap host tools are intentionally left in place: bpf-linker"
echo "    (~/.local/bin/bpf-linker) and the dated nightly toolchain pin."
echo "    No longer building from source? Remove them manually:"
echo "      rm -f ~/.local/bin/bpf-linker"
echo "      rustup toolchain uninstall nightly-2026-09-18"
