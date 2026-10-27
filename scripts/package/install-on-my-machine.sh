#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# scripts/package/install-on-my-machine.sh — install zelynic on THIS
# machine: the install twin of uninstall.sh (the sibling zejtron
# package shape).
#
# The payload is ONE file: the static musl flagship binary built by
# scripts/dev/bootstrap-ebpf.sh (phase-3, eBPF objects embedded —
# no /usr/lib payload, no service, no man page; night-dragon-
# maintenance-6 made musl the only libc shape and the release payload
# one file per platform). This script lands that file on PATH, so the
# manual `cp` the README and the setup.sh menu used to prescribe has
# a tool: found binary in hand it installs and verifies; flagship
# missing it runs the canonical bootstrap first (idempotent, ends
# ready) — "install on my machine" must end with a working binary on
# PATH, not a build lecture.
#
# Auto-detect is uninstall.sh's scan reversed: where an older zelynic
# lives is where this upgrade lands — /usr/bin refreshed with sudo,
# ~/.local/bin without; both found, both refreshed so an upgrade never
# leaves a stale copy behind the newer one; nothing found, the fresh
# install defaults to ~/.local/bin (the rootless shape setup.sh's
# menu suggests first). --system/--user force one target.
#
# Sudo is used only for system paths. Run WITHOUT sudo (the uninstall
# contract): a root shell already IS the privilege the system path
# needs; non-root gets the sudo prefix on system paths only.
#
# Postconditions are verified (the uninstall law, install side):
# every destination must exist, be executable, and answer `-V` with
# "zelynic: v*" before this script claims success — a wrong-arch or
# truncated binary cannot pass silently (the flagship alias is
# x86_64-only; .cargo/config.toml carries the aarch64 note).
#
# Kernel state is never touched: an upgrade while limits are live is
# safe (the kernel enforces from the pinned maps, and the new binary
# manages them — `zelynic u --all` clears on demand); the dangerous
# direction (removing the binary under live pins) is uninstall.sh's
# guard, and this script only says what it sees.
#
# Usage:
#   ./install-on-my-machine.sh [--system|--user]
#
# Sudo is used only for system paths. Run WITHOUT sudo.

set -uo pipefail

PROJECT_NAME="zelynic"
REPO_URL="https://github.com/oxyzenQ/zelynic"
PIN_DIR="/sys/fs/bpf/${PROJECT_NAME}"
FLAGSHIP_REL="target/x86_64-unknown-linux-musl/pro-native-musl/${PROJECT_NAME}"
SYSTEM_BIN="/usr/bin"
USER_BIN="${HOME}/.local/bin"

usage() {
	cat <<EOF
Usage: $0 [--system|--user]

  (default)  Auto-detect: refresh the installation(s) found on this
             machine — /usr/bin with sudo, ~/.local/bin without; both
             found, both refreshed; none found, install to
             ~/.local/bin (no sudo). Builds the flagship first when
             this checkout has none.
  --system   Install to /usr/bin only (uses sudo).
  --user     Install to ~/.local/bin only (no sudo).

The binary is built from THIS checkout (scripts/dev/bootstrap-ebpf.sh
runs when the flagship is missing). Sudo is used only for system
paths. Run WITHOUT sudo.
EOF
}

MODE="auto"
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

# Root already holds the privilege; asking for sudo inside a root
# shell (containers, minimal VMs, hardened servers) fails installs
# that had every right to succeed (the uninstall escalation law).
SUDO_CMD=()
if [[ "$(id -u)" -ne 0 ]]; then
	SUDO_CMD=(sudo)
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FLAGSHIP="${REPO_ROOT}/${FLAGSHIP_REL}"

installed=0
failures=0

# The -V verdict contract uninstall.sh checks before using a binary:
# first line must answer "zelynic: v*". Anything else (a cross-built
# binary this host cannot exec, a truncated copy) reads as a failure
# here, with the arch explanation named once.
binary_verdict() {
	local bin="$1" line
	line="$("${bin}" -V 2>/dev/null | head -n 1 || true)"
	[[ "${line}" == "${PROJECT_NAME}: v"* ]] || return 1
	echo "   verdict: ${line}"
	return 0
}

# The flagship must exist, run, and identify itself. Missing -> the
# canonical bootstrap builds it (idempotent: re-running is cheap;
# prerequisites ship themselves). A binary that will not run is a
# hard stop with the reason, never a silent install of a file this
# machine cannot execute.
ensure_flagship() {
	if [[ ! -x "${FLAGSHIP}" ]]; then
		echo ">> flagship binary not found (${FLAGSHIP_REL})"
		echo "   building it first — ./scripts/dev/bootstrap-ebpf.sh (idempotent; first build ~1-3 min)"
		if ! "${REPO_ROOT}/scripts/dev/bootstrap-ebpf.sh"; then
			echo "   FAILED: the bootstrap above did not finish — read its output; fix and re-run this script." >&2
			failures=$((failures + 1))
			return 1
		fi
	fi
	if [[ ! -x "${FLAGSHIP}" ]]; then
		echo "   FAILED: ${FLAGSHIP_REL} is still missing after the bootstrap." >&2
		failures=$((failures + 1))
		return 1
	fi
	if ! binary_verdict "${FLAGSHIP}" >/dev/null; then
		echo "   FAILED: the flagship binary exists but does not run on this host ('${FLAGSHIP}' answered no zelynic -V verdict)." >&2
		echo "   The flagship alias builds x86_64 only (night-dragon-maintenance-6; .cargo/config.toml carries the aarch64 note) —" >&2
		echo "   on this arch the artifact is a cross product. A static aarch64 native build needs the alias mirrored for the aarch64 triple." >&2
		failures=$((failures + 1))
		return 1
	fi
	return 0
}

# Informational only (the mirror of uninstall.sh's guard, install
# side): pins under /sys/fs/bpf/zelynic mean limits are live in the
# kernel right now. Installing/overwriting the binary changes
# nothing about them — enforcement continues from the pinned maps,
# and the freshly installed binary manages them (or clears them with
# 'u --all'). An unreadable pin dir leans present, same as uninstall.
kernel_state_note() {
	local listing
	if [[ ! -d "${PIN_DIR}" ]]; then
		return 0
	fi
	if ! listing="$(find "${PIN_DIR}" -mindepth 1 -maxdepth 1 2>/dev/null)"; then
		echo ">> NOTE: ${PIN_DIR} could not be read — kernel state unknown; treat limits as live." >&2
		return 0
	fi
	if [[ -n "${listing}" ]]; then
		echo ">> NOTE: active kernel state found (${PIN_DIR} has pins) — upgrading the binary leaves enforcement intact;"
		echo "   the new binary manages it (clear on demand: sudo ${PROJECT_NAME} u --all). Teardown order lives in uninstall.sh."
	fi
	return 0
}

install_at() {
	local dest="$1"
	local escalate="$2"
	local pre=()
	if [[ "${escalate}" == "yes" && "$(id -u)" -ne 0 ]]; then
		pre=("${SUDO_CMD[@]}")
	fi
	echo ">> installing: ${dest}"
	if ! "${pre[@]}" install -Dm755 "${FLAGSHIP}" "${dest}"; then
		echo "   FAILED: install to ${dest} (see the error above)" >&2
		failures=$((failures + 1))
		return 1
	fi
	if [[ ! -x "${dest}" ]]; then
		echo "   FAILED: ${dest} is not executable after install" >&2
		failures=$((failures + 1))
		return 1
	fi
	if ! binary_verdict "${dest}"; then
		echo "   FAILED: ${dest} does not answer -V with a zelynic verdict" >&2
		failures=$((failures + 1))
		return 1
	fi
	installed=$((installed + 1))
	return 0
}

if [[ ! -f "${REPO_ROOT}/Cargo.toml" ]]; then
	echo "error: this script installs from a checkout — run it inside the zelynic repo (${SCRIPT_DIR} moved?)" >&2
	exit 2
fi

echo ">> Installing ${PROJECT_NAME} on this machine (from this checkout)"

ensure_flagship || true
if [[ ${failures} -gt 0 ]]; then
	echo ">> Done with ${failures} FAILURE(S). Nothing was installed — fix the cause above and re-run." >&2
	exit 1
fi
binary_verdict "${FLAGSHIP}"

kernel_state_note

# Target resolution (the uninstall scan, install side). A forced mode
# skips detection entirely; auto refreshes what exists and defaults
# to the rootless user shape when the machine is fresh.
declare -a TARGETS=()
case "${MODE}" in
--system)
	TARGETS=("${SYSTEM_BIN}/${PROJECT_NAME}:yes")
	;;
--user)
	TARGETS=("${USER_BIN}/${PROJECT_NAME}:no")
	;;
*)
	[[ -x "${SYSTEM_BIN}/${PROJECT_NAME}" ]] && TARGETS+=("${SYSTEM_BIN}/${PROJECT_NAME}:yes")
	[[ -x "${USER_BIN}/${PROJECT_NAME}" ]] && TARGETS+=("${USER_BIN}/${PROJECT_NAME}:no")
	if [[ ${#TARGETS[@]} -eq 0 ]]; then
		TARGETS=("${USER_BIN}/${PROJECT_NAME}:no")
	fi
	;;
esac

for target in "${TARGETS[@]}"; do
	install_at "${target%%:*}" "${target##*:}"
done

if [[ ${failures} -gt 0 ]]; then
	echo ">> Done with ${failures} FAILURE(S). Installed ${installed} destination(s);"
	echo "   the failed destinations above are NOT on PATH — inspect and re-run." >&2
	exit 1
fi

if [[ ${installed} -eq 0 ]]; then
	echo ">> nothing was installed (no target resolved) — pass --user or --system explicitly." >&2
	exit 1
fi

# The debian13 lesson (NIGHT-improve-16): a user install is only "on
# PATH" if ~/.local/bin IS on PATH. The exact export line, plus the
# one command that persists it for future shells.
if [[ "${MODE}" != "--system" && ":${PATH}:" != *":${USER_BIN}:"* ]]; then
	echo ">> NOTE: ${USER_BIN} is not on this shell's PATH — the binary is installed but not yet resolvable by name."
	echo "   this session:  export PATH=\"${USER_BIN}:\$PATH\""
	echo "   future shells: ./scripts/dev/bootstrap-ebpf.sh persists the export to ~/.profile (idempotent)."
fi

echo ">> Done. ${PROJECT_NAME} installed at ${installed} destination(s)."
echo "  - try it:        ${PROJECT_NAME} doctor   (kernel support, root or not)"
echo "  - limit for fun: sudo ${PROJECT_NAME} strict curl 1mb"
echo "  - uninstall:     ${REPO_ROOT}/scripts/package/uninstall.sh (clears kernel enforcement first)"
echo "  - docs:          ${REPO_URL}#readme"
