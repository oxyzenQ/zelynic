#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# Install the pinned bpf-linker binary (NIGHT-improve-11).
#
# The four CI jobs (ci.yml check + ebpf-build, release.yml build,
# maintenance.yml validate) each carried a byte-identical copy of
# this block — the pin now lives in exactly one place. Local
# non-root installs belong to scripts/bootstrap-ebpf.sh
# (~/.local/bin, no sudo, richer UX); that one-click flow is NOT
# changed. This script is the CI/root-context twin.
#
# Usage:
#   bash scripts/install-bpf-linker.sh            # /usr/local/bin
#   bash scripts/install-bpf-linker.sh <prefix>   # custom directory
#
# Version pin: must mirror scripts/bootstrap-ebpf.sh, the toolchain
# pairing in docs/PURE_RUST_EVALUATION.md, and the bpf-linker row in
# docs/KERNEL_COMPATIBILITY.md.

set -euo pipefail

VERSION="0.11.1"
PREFIX="${1:-/usr/local/bin}"
ASSET="bpf-linker-x86_64-unknown-linux-musl.tar.zst"
URL="https://github.com/aya-rs/bpf-linker/releases/download/v${VERSION}/${ASSET}"

if ! command -v zstd >/dev/null 2>&1; then
	if command -v apt-get >/dev/null 2>&1; then
		if [ "$(id -u)" = "0" ]; then
			apt-get update -q && apt-get install -y -q zstd
		else
			sudo apt-get update -q && sudo apt-get install -y -q zstd
		fi
	else
		echo "FAIL: zstd is required to unpack ${ASSET} but is neither installed nor apt-installable here." >&2
		exit 1
	fi
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

curl -sL -o "${TMP_DIR}/bpf-linker.tar.zst" "${URL}"
tar --zstd -xf "${TMP_DIR}/bpf-linker.tar.zst" -C "${TMP_DIR}"

# install(1) never creates directories; a custom prefix may not
# exist yet (the CI default always does).
if [ ! -d "${PREFIX}" ]; then
	if [ -w "$(dirname "${PREFIX}")" ]; then
		mkdir -p "${PREFIX}"
	else
		sudo mkdir -p "${PREFIX}"
	fi
fi

# sudo only when the destination is not writable as-is (CI runners
# are non-root; a local root shell never needs it).
if [ -w "${PREFIX}" ]; then
	install -m755 "${TMP_DIR}/bpf-linker" "${PREFIX}/bpf-linker"
else
	sudo install -m755 "${TMP_DIR}/bpf-linker" "${PREFIX}/bpf-linker"
fi

# A custom prefix may not be on PATH yet; make the verification below
# resolve the binary we just placed.
if ! command -v bpf-linker >/dev/null 2>&1; then
	PATH="${PREFIX}:${PATH}"
	export PATH
fi

bpf-linker --version
echo "OK: bpf-linker ${VERSION} installed to ${PREFIX}"
