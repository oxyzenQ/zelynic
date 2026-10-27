#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# scripts/setup.sh — the lazy one-command pipeline (NIGHT-improve-18).
#
# For the owner who does not want to remember the order: this runs
# the WHOLE bring-up — toolchain bootstrap, the flagship build, the
# rootless engine self-test, and the full supermassive matrix —
# then hands back a menu of next steps. Every phase is idempotent:
# re-running skips satisfied work (bootstrap re-checks in seconds,
# cargo rebuilds incrementally, tests just run again).
#
# The pipeline (each phase must pass before the next starts):
#   1. bootstrap-ebpf.sh  — dated nightly pin + bpf-linker 0.11.1 +
#                           the static pro-native-musl flagship build
#                           (night-dragon-maintenance-6: musl is the
#                           only libc shape — the old gnu flagship and
#                           the opt-in --musl twin phase retired with
#                           the gnu packaging)
#   2. self-test          — supermassive engine smoke, rootless
#   3. supermassive matrix — the 5+ min full command-surface sweep,
#                           run under sudo (setup asks once)
#
# Usage:
#   ./scripts/setup.sh              # everything
#   ./scripts/setup.sh --skip-heavy # bootstrap + build + self-test only
#
# Run as your NORMAL user (not root): phases 1-2 install into $HOME
# and the script elevates itself with sudo for phase 3 only.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok() { echo -e "${GREEN}[setup]${NC} $1"; }
warn() { echo -e "${YELLOW}[setup]${NC} $1"; }
die() {
	echo -e "${RED}[setup]${NC} $1" >&2
	exit 1
}

SKIP_HEAVY=false

usage() {
	cat <<'EOF'
Usage: ./scripts/setup.sh [--skip-heavy]

  --skip-heavy  Stop after bootstrap + build + self-test
                (skip the 5+ min root supermassive matrix)
  -h, --help    Show this help
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--skip-heavy)
		SKIP_HEAVY=true
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage
		die "unknown option: $1"
		;;
	esac
done

if [ "$(id -u)" -eq 0 ]; then
	die "run as your normal user, not root — phases 1-2 install into \$HOME, and this script calls sudo itself for the matrix."
fi

cd "${REPO_ROOT}"

# bootstrap fixes ~/.profile PATH persistence for FUTURE shells; the
# current shell still needs the two cargo/local entries for any cargo
# re-invocation.
PATH="${HOME}/.cargo/bin:${HOME}/.local/bin:${PATH}"

SECONDS=0

ok "phase 1/3: bootstrap (toolchain + bpf-linker + static musl flagship build)"
if ! "${SCRIPT_DIR}/dev/bootstrap-ebpf.sh"; then
	die "bootstrap failed — read its output above; fix and re-run ./scripts/setup.sh (idempotent)."
fi
ok "phase 1/3: bootstrap done (${SECONDS}s)"

ok "phase 2/3: supermassive engine self-test (rootless)"
if ! "${SCRIPT_DIR}/supermassive/supermassive-test.sh" --self-test; then
	die "self-test failed — the harness engine itself is broken; run scripts/supermassive/supermassive-test.py --self-test for the failing rows."
fi
ok "phase 2/3: self-test green"

if [ "${SKIP_HEAVY}" = true ]; then
	ok "phase 3/3: matrix skipped (--skip-heavy)"
else
	ok "phase 3/3: the supermassive matrix (5+ min, sudo)"
	if ! sudo "${SCRIPT_DIR}/supermassive/supermassive-test.sh"; then
		warn "the matrix reported FAILURES — read the marked rows above (they are the verdict, not this script)."
		warn "re-run just the matrix: sudo ./scripts/supermassive/supermassive-test.sh"
	fi
fi

# The commit-time prebuilt gate self-install (the same arm
# gate-keepers.sh carries, now on the bring-up path too): a fresh
# clone that never ran gate-keepers still gets the auto-heal law -
# any commit touching ebpf/ regenerates the lane and stages it
# (night-dragon-maintenance-3: the unkillable ebpf law's commit
# trigger must not depend on remembering a second script).
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	hook_path="$(git config --local core.hooksPath || true)"
	if [ "${hook_path}" != ".githooks" ]; then
		git config --local core.hooksPath .githooks
		ok "pre-commit gate wired (core.hooksPath=.githooks — commit-time auto-heal live)"
	else
		ok "pre-commit gate already wired (core.hooksPath=.githooks)"
	fi
fi

BUILT="${REPO_ROOT}/target/x86_64-unknown-linux-musl/pro-native-musl/zelynic"
echo ""
ok "setup finished in ${SECONDS}s — binary: ${BUILT}"
echo ""
echo "next steps — the menu:"
echo "  want it on PATH?                 cp target/x86_64-unknown-linux-musl/pro-native-musl/zelynic ~/.local/bin/ (or /usr/local/bin)"
echo "  want it gone again?              ./scripts/package/uninstall.sh"
echo "  explore the CLI:                 ${BUILT} --help"
echo "  check kernel support:            sudo ${BUILT} doctor"
echo "  see live traffic:                sudo ${BUILT} top"
echo "  limit something for fun:         sudo ${BUILT} strict curl 1mb"
echo "  docs:                            README.md + docs/USAGE.md"
