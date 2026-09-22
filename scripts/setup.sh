#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# scripts/setup.sh — the lazy one-command pipeline (NIGHT-improve-18).
#
# For the owner who does not want to remember the order: this runs
# the WHOLE bring-up — toolchain bootstrap, the pro-native build,
# the rootless engine self-test, and the full supermassive matrix —
# then hands back a menu of next steps. Every phase is idempotent:
# re-running skips satisfied work (bootstrap re-checks in seconds,
# cargo rebuilds incrementally, tests just run again).
#
# The pipeline (each phase must pass before the next starts):
#   1. bootstrap-ebpf.sh  — dated nightly pin + bpf-linker 0.11.1 +
#                           the flagship pro-native-gnu build
#   2. (opt-in --musl)    — the static pro-native-musl twin build
#   3. self-test          — supermassive engine smoke, rootless
#   4. supermassive matrix — the 5+ min full command-surface sweep,
#                           run under sudo (setup asks once)
#
# Usage:
#   ./scripts/setup.sh              # everything, gnu build
#   ./scripts/setup.sh --musl      # also build the static musl twin
#   ./scripts/setup.sh --skip-heavy # bootstrap + build + self-test only
#
# Run as your NORMAL user (not root): phases 1-3 install into $HOME
# and the script elevates itself with sudo for phase 4 only.

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

BUILD_MUSL=false
SKIP_HEAVY=false

usage() {
	cat <<'EOF'
Usage: ./scripts/setup.sh [--musl] [--skip-heavy]

  --musl        Also build the static pro-native-musl twin
                (x86_64 hosts only; lands in
                target/x86_64-unknown-linux-musl/pro-native-musl/)
  --skip-heavy  Stop after bootstrap + build + self-test
                (skip the 5+ min root supermassive matrix)
  -h, --help    Show this help
EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--musl)
		BUILD_MUSL=true
		shift
		;;
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
	die "run as your normal user, not root — phases 1-3 install into \$HOME, and this script calls sudo itself for the matrix."
fi

cd "${REPO_ROOT}"

# bootstrap fixes ~/.profile PATH persistence for FUTURE shells; the
# current shell still needs the two cargo/local entries for the musl
# phase and any cargo re-invocation.
PATH="${HOME}/.cargo/bin:${HOME}/.local/bin:${PATH}"

SECONDS=0

ok "phase 1/4: bootstrap (toolchain + bpf-linker + pro-native-gnu flagship build)"
if ! "${SCRIPT_DIR}/bootstrap-ebpf.sh"; then
	die "bootstrap failed — read its output above; fix and re-run ./scripts/setup.sh (idempotent)."
fi
ok "phase 1/4: bootstrap done (${SECONDS}s)"

if [ "${BUILD_MUSL}" = true ]; then
	ok "phase 2/4 (--musl): static pro-native-musl build"
	if [ "$(uname -m)" != "x86_64" ]; then
		die "--musl is x86_64-only (the alias pins x86_64-unknown-linux-musl; see .cargo/config.toml)."
	fi
	if ! cargo pro-native-musl --locked; then
		die "pro-native-musl build failed — read the compiler output above (is the musl target installed? see .cargo/config.toml)."
	fi
	ok "phase 2/4: musl twin ready at target/x86_64-unknown-linux-musl/pro-native-musl/zelynic"
else
	ok "phase 2/4: musl twin skipped (opt in with --musl)"
fi

ok "phase 3/4: supermassive engine self-test (rootless)"
if ! "${SCRIPT_DIR}/supermassive-test.sh" --self-test; then
	die "self-test failed — the harness engine itself is broken; run scripts/supermassive-test.py --self-test for the failing rows."
fi
ok "phase 3/4: self-test green"

if [ "${SKIP_HEAVY}" = true ]; then
	ok "phase 4/4: matrix skipped (--skip-heavy)"
else
	ok "phase 4/4: the supermassive matrix (5+ min, sudo)"
	if ! sudo "${SCRIPT_DIR}/supermassive-test.sh"; then
		warn "the matrix reported FAILURES — read the marked rows above (they are the verdict, not this script)."
		warn "re-run just the matrix: sudo ./scripts/supermassive-test.sh"
	fi
fi

BUILT="${REPO_ROOT}/target/pro-native-gnu/zelynic"
echo ""
ok "setup finished in ${SECONDS}s — binary: ${BUILT}"
if [ "${BUILD_MUSL}" = true ]; then
	ok "static twin: target/x86_64-unknown-linux-musl/pro-native-musl/zelynic"
fi
echo ""
echo "next steps — the menu:"
echo "  want it installed system-wide?   sudo ./scripts/install.sh"
echo "  want it gone again?              sudo ./scripts/uninstall.sh"
echo "  explore the CLI:                 ${BUILT} --help"
echo "  check kernel support:            sudo ${BUILT} doctor"
echo "  see live traffic:                sudo ${BUILT} top"
echo "  limit something for fun:         sudo ${BUILT} strict-single curl 1mb"
echo "  docs:                            README.md + docs/USAGE.md"
