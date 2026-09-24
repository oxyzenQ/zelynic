#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Install zelynic system-wide or user-local.
#
# Works in two modes:
#   1. Pre-built: a zelynic binary already sits beside this script
#      (a release-payload drop, or a build copied into the repo root).
#      The eBPF objects are embedded inside it (NIGHT-improve-1
#      phase 3), so no toolchain is needed — install the one file.
#      The mode announces itself so a stale drop is never mistaken
#      for a fresh build (NIGHT-improve-15).
#   2. From source repo: build the flagship binary with the canonical
#      native alias — cargo pro-native-gnu (default, same profile
#      bootstrap-ebpf.sh builds and the supermassive harness tests),
#      or cargo pro-native-musl with --musl (static, x86_64 only).
#      NOT the plain `cargo build --release` shape: the owner
#      contract is that anything this script installs carries the
#      pro-native lineage and its build label. The eBPF objects are
#      built pure-Rust by build.rs's nested nightly build and
#      embedded automatically; the prerequisites are rustup's dated
#      nightly pin and bpf-linker (pre-checked below with install
#      pointers, verified again after the build).
#
# Usage:
#   ./install.sh --user     → install to ~/.local/bin (default)
#   ./install.sh --system   → install to /usr/bin (script uses sudo internally)
#   ./install.sh --musl     → static pro-native-musl build (x86_64 hosts only)
#
# Run WITHOUT sudo: the script escalates via sudo ONLY for --system install steps.

set -euo pipefail

PROJECT_NAME="zelynic"
EBPF_TOOLCHAIN="nightly-2026-09-18"
INSTALL_MODE="--user"
BUILD_FLAVOR="gnu"

# Parse args
for arg in "$@"; do
	case "$arg" in
	--system) INSTALL_MODE="--system" ;;
	--user) INSTALL_MODE="--user" ;;
	--musl) BUILD_FLAVOR="musl" ;;
	--help | -h)
		echo "Usage: $0 [--system|--user] [--musl]"
		echo "  --user    Install to ~/.local/bin (default)"
		echo "  --system  Install to /usr/bin (script uses sudo internally)"
		echo "  --musl    Build static via cargo pro-native-musl (x86_64 only;"
		echo "            default is cargo pro-native-gnu, dynamic glibc)"
		exit 0
		;;
	*)
		echo "Unknown option: $arg"
		echo "Usage: $0 [--system|--user] [--musl]"
		exit 1
		;;
	esac
done

# Detect mode: pre-built binary exists beside this script, or source repo (Cargo.toml exists)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/${PROJECT_NAME}"

if [[ ! -f "${BINARY}" ]]; then
	# Source mode — need to build

	# Refuse to run as root — cargo build must run as the current user.
	# If run with sudo, cargo build would create root-owned files in target/,
	# breaking future `cargo clean` / `cargo build` for the normal user.
	if [[ $EUID -eq 0 ]]; then
		echo "error: do not run this script with sudo (source build mode)." >&2
		echo "  cargo build would run as root, corrupting target/ ownership." >&2
		echo "  Run: $0 --system" >&2
		echo "  The script will use sudo internally only for the install step." >&2
		exit 1
	fi

	if [[ -f "${SCRIPT_DIR}/Cargo.toml" ]]; then
		REPO_ROOT="${SCRIPT_DIR}"
	elif [[ -f "${SCRIPT_DIR}/../Cargo.toml" ]]; then
		REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
	else
		echo "ERROR: No pre-compiled binary found and no Cargo.toml."
		echo "  Run from release tarball directory or repo root."
		exit 1
	fi

	cd "${REPO_ROOT}"

	# The pro-native-musl alias targets x86_64-unknown-linux-musl (see
	# .cargo/config.toml: cargo aliases cannot detect the host arch, so
	# the static native build is x86_64-only by construction). Refuse
	# loudly on other hosts instead of letting cargo cross-compile a
	# binary the install step would then place on the wrong machine.
	if [[ "${BUILD_FLAVOR}" == "musl" && "$(uname -m)" != "x86_64" ]]; then
		echo "ERROR: --musl is x86_64-only (the alias pins x86_64-unknown-linux-musl)." >&2
		echo "  This host is $(uname -m). Use the default pro-native-gnu build," >&2
		echo "  or mirror the aarch64 target block in .cargo/config.toml first." >&2
		exit 1
	fi

	# Both flavors land the binary under a profile-specific directory
	# (.cargo/config.toml pro-native contract) — a native build never
	# clobbers target/release/zelynic.
	if [[ "${BUILD_FLAVOR}" == "musl" ]]; then
		BINARY="target/x86_64-unknown-linux-musl/pro-native-musl/${PROJECT_NAME}"
	else
		BINARY="target/pro-native-gnu/${PROJECT_NAME}"
	fi

	# Prerequisites for the pure-Rust eBPF build (NIGHT-improve-1
	# phase 3): the dated nightly pin and bpf-linker. build.rs
	# fails with the same pointers if these are missing; this
	# pre-check gives the friendly version before any compile
	# time is spent (NIGHT-host-1: scripts/dev/bootstrap-ebpf.sh is
	# the one-command fix for both).
	if ! command -v rustup >/dev/null 2>&1; then
		echo "ERROR: rustup is required to build zelynic (the eBPF objects"
		echo "  build with the pinned nightly toolchain ${EBPF_TOOLCHAIN})."
		echo "  Install rustup: https://rustup.rs"
		exit 1
	fi
	if ! rustup toolchain list 2>/dev/null | grep -q "${EBPF_TOOLCHAIN}"; then
		echo "ERROR: the pinned nightly toolchain is not installed."
		echo "  One-command fix: ./scripts/dev/bootstrap-ebpf.sh"
		echo "  (manual: rustup toolchain install ${EBPF_TOOLCHAIN} --component rust-src --component rustfmt)"
		exit 1
	fi
	if ! command -v bpf-linker >/dev/null 2>&1; then
		echo "ERROR: bpf-linker not found on PATH (the eBPF link step)."
		echo "  One-command fix: ./scripts/dev/bootstrap-ebpf.sh"
		echo "  (manual: https://github.com/aya-rs/bpf-linker/releases — v0.11.1 prebuilt)"
		exit 1
	fi

	# Build the self-contained flagship binary through the canonical
	# native alias: the pure-Rust eBPF objects are cross-built by
	# build.rs's nested nightly build and embedded, the host binary is
	# tuned for THIS machine's CPU, and the result carries its build
	# label in `zelynic -V` (local-native-gnu / local-native-musl).
	# --locked keeps the release discipline the old plain-release
	# build had: the committed Cargo.lock is the dependency set.
	echo "Building ${PROJECT_NAME} (cargo pro-native-${BUILD_FLAVOR}, pure-Rust eBPF objects embedded)..."
	if ! cargo "pro-native-${BUILD_FLAVOR}" --locked; then
		echo "ERROR: the pro-native-${BUILD_FLAVOR} build failed — read the compiler output above."
		exit 1
	fi

	# Post-build verification (NIGHT-improve-15: "built" must MEAN
	# built): the alias reports success, the binary must exist at the
	# profile's contract path and answer -V. A missing binary after a
	# green build is a real inconsistency, not something to install
	# around; a -V failure means the artifact is not a working zelynic.
	if [[ ! -x "${BINARY}" ]]; then
		echo "ERROR: cargo reported success but ${BINARY} is missing or not executable."
		echo "  Inspect the cargo output above and the target/ tree."
		exit 1
	fi
	VERSION_LINE="$("${BINARY}" -V 2>/dev/null | head -n 1 || true)"
	if [[ "${VERSION_LINE}" != "${PROJECT_NAME}: v"* ]]; then
		echo "ERROR: built binary failed the -V sanity check (got: '${VERSION_LINE}')."
		echo "  Refusing to install an artifact that does not identify itself as ${PROJECT_NAME}."
		exit 1
	fi
	echo "Built and verified: ${VERSION_LINE}"
else
	echo "Installing the pre-built binary beside this script (no build performed):"
	echo "  ${BINARY}"
	# Same -V sanity gate for the pre-built path: a truncated or
	# foreign drop must fail HERE, not on the user's first command.
	VERSION_LINE="$("${BINARY}" -V 2>/dev/null | head -n 1 || true)"
	if [[ "${VERSION_LINE}" != "${PROJECT_NAME}: v"* ]]; then
		echo "ERROR: ${BINARY} failed the -V sanity check (got: '${VERSION_LINE}')."
		echo "  The file is damaged or not a ${PROJECT_NAME} binary."
		exit 1
	fi
	echo "Verified: ${VERSION_LINE}"
fi

# Install — sudo used ONLY for --system mode install steps.
# The BPF objects ride inside the binary (NIGHT-improve-1 phase 3):
# nothing else to install, no /usr/lib/zelynic/ object directory.
if [[ "${INSTALL_MODE}" == "--system" ]]; then
	sudo install -Dm755 "${BINARY}" "/usr/bin/${PROJECT_NAME}"
	echo "${PROJECT_NAME} installed to /usr/bin/${PROJECT_NAME}"
	echo "Run: ${PROJECT_NAME} doctor  (to verify eBPF support)"
else
	# User install — no sudo
	BINDIR="${HOME}/.local/bin"
	mkdir -p "${BINDIR}"
	install -Dm755 "${BINARY}" "${BINDIR}/${PROJECT_NAME}"
	echo "${PROJECT_NAME} installed to ${BINDIR}/${PROJECT_NAME}"
	echo "Make sure ${BINDIR} is in your PATH."
fi
