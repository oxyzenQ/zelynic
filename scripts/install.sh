#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
#
# Install zelynic system-wide or user-local.
#
# Works in two modes:
#   1. From release tarball: the self-contained binary (eBPF objects
#      embedded inside it — NIGHT-improve-1 phase 3). No toolchain
#      needed, just install the one file.
#   2. From source repo: build the pure-Rust binary. The eBPF objects
#      are built from the aya-ebpf crate and embedded automatically by
#      build.rs; the prerequisites are rustup's dated nightly pin and
#      bpf-linker (checked below with install pointers).
#
# Usage:
#   ./install.sh --user     → install to ~/.local/bin (default)
#   ./install.sh --system   → install to /usr/bin (script uses sudo internally)
#
# Run WITHOUT sudo: the script escalates via sudo ONLY for --system install steps.

set -euo pipefail

PROJECT_NAME="zelynic"
EBPF_TOOLCHAIN="nightly-2026-09-18"
INSTALL_MODE="--user"

# Parse args
for arg in "$@"; do
	case "$arg" in
	--system) INSTALL_MODE="--system" ;;
	--user) INSTALL_MODE="--user" ;;
	--help | -h)
		echo "Usage: $0 [--system|--user]"
		echo "  --user    Install to ~/.local/bin (default)"
		echo "  --system  Install to /usr/bin (script uses sudo internally)"
		exit 0
		;;
	*)
		echo "Unknown option: $arg"
		echo "Usage: $0 [--system|--user]"
		exit 1
		;;
	esac
done

# Detect mode: release tarball (binary exists) or source repo (Cargo.toml exists)
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
	BINARY="target/release/${PROJECT_NAME}"

	# Prerequisites for the pure-Rust eBPF build (NIGHT-improve-1
	# phase 3): the dated nightly pin and bpf-linker. build.rs
	# fails with the same pointers if these are missing; this
	# pre-check gives the friendly version before any compile
	# time is spent (NIGHT-host-1: scripts/bootstrap-ebpf.sh is
	# the one-command fix for both).
	if ! command -v rustup >/dev/null 2>&1; then
		echo "ERROR: rustup is required to build zelynic (the eBPF objects"
		echo "  build with the pinned nightly toolchain ${EBPF_TOOLCHAIN})."
		echo "  Install rustup: https://rustup.rs"
		exit 1
	fi
	if ! rustup toolchain list 2>/dev/null | grep -q "${EBPF_TOOLCHAIN}"; then
		echo "ERROR: the pinned nightly toolchain is not installed."
		echo "  One-command fix: ./scripts/bootstrap-ebpf.sh"
		echo "  (manual: rustup toolchain install ${EBPF_TOOLCHAIN} --component rust-src --component rustfmt)"
		exit 1
	fi
	if ! command -v bpf-linker >/dev/null 2>&1; then
		echo "ERROR: bpf-linker not found on PATH (the eBPF link step)."
		echo "  One-command fix: ./scripts/bootstrap-ebpf.sh"
		echo "  (manual: https://github.com/aya-rs/bpf-linker/releases — v0.11.1 prebuilt)"
		exit 1
	fi

	# Build the self-contained binary: the pure-Rust eBPF objects are
	# cross-built by build.rs's nested nightly build and embedded.
	echo "Building ${PROJECT_NAME} (pure-Rust eBPF objects embedded)..."
	cargo build --release --locked --features ebpf
fi

# Verify binary exists
if [[ ! -f "${BINARY}" ]]; then
	echo "ERROR: Binary not found at ${BINARY}"
	exit 1
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
