#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# scripts/package/install-on-my-machine.sh — install zelynic on THIS
# machine: the install twin of uninstall.sh (the sibling zejtron
# package shape), now carrying the zejtron install-path law
# (night-dragon-maintenance-7): /usr/bin is the ONE install path, by
# default, with no flags — the old auto-detect/--system/--user surface
# is retired. A stale ~/.local/bin/zelynic is removed first so nothing
# shadows /usr/bin (the zylaxion rule; the shadow class the owner hit
# in the wild).
#
# The contract:
#   1. Linux only, amd64 only (the only shapes zelynic ships).
#   2. CPU detect: x86-64-v4 if the core carries the AVX-512 baseline,
#      else x86-64-v3 if it carries the AVX2 baseline, else refuse —
#      v3/v4 are the only shapes the release matrix builds
#      (night-dragon-maintenance-6 made musl the only libc shape), and
#      a v1/v2 core gets the honest pointer to the native dev tier.
#   3. Build: cargo pro-linux-amd64-v{3,4}-musl — the arch-baseline
#      alias whose rustflags check-release-parity.sh pins equal to the
#      release matrix, so what lands on this machine is the shipped
#      optimization tier, bit-for-bit, eBPF objects embedded (the ebpf
#      feature is the default). The build is fully static musl and
#      runs as the current user (a root build corrupts target/
#      ownership). Prerequisites ship themselves: the musl rust-std
#      target is added on demand, and a missing pinned bpf-linker is
#      installed by scripts/dev/install-bpf-linker.sh (the same
#      one-shot the release lane runs).
#   4. Install: /usr/bin/zelynic. ONE path, the default, no
#      --system/--user option to choose — the script escalates sudo
#      for the install step ONLY. Postconditions are verified (the
#      uninstall law, install side): the destination must exist, be
#      executable, and answer -V with "zelynic: v*" before this
#      script claims success — a wrong-arch or truncated binary
#      cannot pass silently.
#   5. Kernel state is never touched: an upgrade while limits are live
#      is safe (enforcement continues from the pinned maps; the new
#      binary manages them, `zelynic u --all` clears on demand); the
#      dangerous direction is uninstall.sh's guard, and this script
#      only says what it sees.
#
# Run WITHOUT sudo (a root build corrupts target/ ownership); sudo is
# escalated internally for the /usr/bin install step only.

set -euo pipefail

PROJECT_NAME="zelynic"
REPO_URL="https://github.com/oxyzenQ/zelynic"
PIN_DIR="/sys/fs/bpf/${PROJECT_NAME}"
USER_BIN="${HOME}/.local/bin"

usage() {
	cat <<EOF
Usage: $0

  Fast setup for this machine: detect the CPU's x86-64 level (v3/v4),
  build the release-tier binary, install to /usr/bin/${PROJECT_NAME}.

  Takes no options - the install path is /usr/bin by law, not a flag.
  Run as your normal user; sudo is escalated internally for the
  /usr/bin install step only.

  Requires: rust (the pinned toolchain via rust-toolchain.toml), the
  musl rust-std target (added automatically), and a Linux on x86-64
  (the build is fully static musl).
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-h | --help)
		usage
		exit 0
		;;
	*)
		echo "error: unknown argument: $1 - this script takes no options" >&2
		usage
		exit 2
		;;
	esac
done

# 1. Platform gates: Linux, x86-64, repo root.
if [[ "$(uname -s)" != "Linux" ]]; then
	echo "error: $(uname -s) is not Linux - zelynic is a Linux tool." >&2
	exit 1
fi
if [[ "$(uname -m)" != "x86_64" ]]; then
	echo "error: $(uname -m) is not amd64 - the release shapes are x86-64-v3/v4 only." >&2
	exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
if [[ ! -f "${REPO_ROOT}/Cargo.toml" || ! -f "${REPO_ROOT}/.cargo/config.toml" ]]; then
	echo "error: run this script from the zelynic repo root (${SCRIPT_DIR} moved?)." >&2
	exit 1
fi

# Refuse to run as root - the build step must run as the current user
# (a root build creates root-owned files in target/, breaking every
# future cargo clean/build for the normal user). sudo is escalated
# internally for the /usr/bin install step only.
if [[ $EUID -eq 0 ]]; then
	echo "error: do not run this script with sudo." >&2
	echo "  the build step would run as root, corrupting target/ ownership." >&2
	echo "  Run: $0   (sudo is used internally only for /usr/bin)" >&2
	exit 1
fi

# 2. CPU detect: the x86-64 microarch level from /proc/cpuinfo flags.
flags="$(grep -m1 '^flags' /proc/cpuinfo)"
detect_level() {
	# v4 baseline: AVX-512 Foundation + BW + CD + DQ + VL.
	if [[ "$flags" =~ avx512f ]] && [[ "$flags" =~ avx512bw ]] &&
		[[ "$flags" =~ avx512cd ]] && [[ "$flags" =~ avx512dq ]] &&
		[[ "$flags" =~ avx512vl ]]; then
		echo "v4"
		return 0
	fi
	# v3 baseline: AVX2 + BMI2 + FMA (the load-bearing trio), plus
	# the rest of the level's required surface where present.
	if [[ "$flags" =~ avx2 ]] && [[ "$flags" =~ bmi2 ]] &&
		[[ "$flags" =~ fma ]] && [[ "$flags" =~ sse4_2 ]] &&
		[[ "$flags" =~ ssse3 ]] && [[ "$flags" =~ avx ]] &&
		[[ "$flags" =~ bmi1 ]] && [[ "$flags" =~ movbe ]]; then
		echo "v3"
		return 0
	fi
	return 1
}
LEVEL="$(detect_level)" || {
	echo "error: this core is below the x86-64-v3 baseline." >&2
	echo "  the release shapes are v3/v4 only - on a v1/v2 machine build" >&2
	echo "  the native dev tier instead: ./scripts/dev/bootstrap-ebpf.sh" >&2
	exit 1
}
echo ">> [1/4] CPU level detected: x86-64-${LEVEL}"

ALIAS="pro-linux-amd64-${LEVEL}-musl"

# The alias builds for the musl triple: its rust-std target must be
# installed (idempotent; the alias links through rust-lld, so the
# target is the only rustup prerequisite - see .cargo/config.toml).
if ! rustup target list --installed 2>/dev/null | grep -q '^x86_64-unknown-linux-musl$'; then
	echo ">> Adding the musl rust-std target (rustup target add)"
	rustup target add x86_64-unknown-linux-musl
fi

# The eBPF nested build links through the pinned bpf-linker: missing
# here means the same one-shot the release lane runs ships it (the
# pinned version resolves from install-bpf-linker.sh's single source).
if ! command -v bpf-linker >/dev/null 2>&1 &&
	[[ ! -x "${HOME}/.cargo/bin/bpf-linker" ]]; then
	echo ">> Installing the pinned bpf-linker (scripts/dev/install-bpf-linker.sh)"
	bash "${REPO_ROOT}/scripts/dev/install-bpf-linker.sh"
fi

# 3. Build: the release-tier alias (parity-gated against the matrix).
echo ">> [2/4] Building the release tier: cargo ${ALIAS}"
cargo "${ALIAS}"
BINARY="target/x86_64-unknown-linux-musl/${ALIAS}/${PROJECT_NAME}"
if [[ ! -f "${BINARY}" ]]; then
	# The musl alias builds into target/x86_64-unknown-linux-musl/<profile>/;
	# fall back to a find so a profile rename upstream cannot strand
	# the installer.
	BINARY="$(find target -maxdepth 3 -type f -name "${PROJECT_NAME}" -perm -u+x | head -1 || true)"
fi
if [[ -z "${BINARY}" || ! -f "${BINARY}" ]]; then
	echo "error: build produced no ${PROJECT_NAME} binary under target/." >&2
	exit 1
fi
echo "   built: ${BINARY}"

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

# The stale user-local shadow, removed before /usr/bin lands (the
# zylaxion rule): a ~/.local/bin/zelynic left behind by the retired
# auto-detect law would shadow /usr/bin on every PATH where
# ~/.local/bin comes first — the exact state `zejtron path zelynic`
# reported in the field.
if [[ -e "${USER_BIN}/${PROJECT_NAME}" ]]; then
	echo ">> Removing the stale user-local binary: ${USER_BIN}/${PROJECT_NAME} (nothing shadows /usr/bin)"
	rm -f "${USER_BIN}/${PROJECT_NAME}"
fi

# 4. Install: /usr/bin - the one path, by default, no flag.
echo ">> [3/4] Installing to /usr/bin/${PROJECT_NAME} (sudo for this step only)"
sudo install -Dm755 "${BINARY}" "/usr/bin/${PROJECT_NAME}"
echo "   installed: /usr/bin/${PROJECT_NAME}"

# 5. Verify: the -V verdict from the installed path (the uninstall
# law, install side — a binary that will not answer is a hard stop).
echo ">> [4/4] Verify"
if ! binary_verdict "/usr/bin/${PROJECT_NAME}"; then
	echo "error: /usr/bin/${PROJECT_NAME} is installed but does not answer -V with a zelynic verdict." >&2
	exit 1
fi
if ! command -v "${PROJECT_NAME}" >/dev/null 2>&1; then
	echo "note: /usr/bin is not on this shell's PATH yet - open a new shell." >&2
fi
kernel_state_note

echo
echo "Next: ${PROJECT_NAME} --help   |   Docs: ${REPO_URL}#readme"
echo "  - try it:    ${PROJECT_NAME} doctor   (kernel support, root or not)"
echo "  - uninstall: ${REPO_ROOT}/scripts/package/uninstall.sh (clears kernel enforcement first)"
