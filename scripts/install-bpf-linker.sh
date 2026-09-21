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
# Version pin: THIS file is the single source of truth —
# scripts/bootstrap-ebpf.sh reads the pin from here (NIGHT-hunt-21,
# the twin-constant drift class is gone). The toolchain pairing
# rationale lives in docs/PURE_RUST_EVALUATION.md, the bpf-linker
# row in docs/KERNEL_COMPATIBILITY.md.

set -euo pipefail

VERSION="0.11.1"
PREFIX="${1:-/usr/local/bin}"
ASSET="bpf-linker-x86_64-unknown-linux-musl.tar.zst"
URL="https://github.com/aya-rs/bpf-linker/releases/download/v${VERSION}/${ASSET}"

# zstd preference: a real zstd binary is the fast path, and apt
# installs it on CI runners — but it is NOT a hard requirement
# (NIGHT-hunt-21): hosts without zstd and without apt (Arch, Fedora,
# Nix, this-exact-case sandboxes) fall through to the python
# zstandard ladder below instead of dying. The extraction ladder
# mirrors scripts/bootstrap-ebpf.sh's extract_tar_zst — the two
# scripts are siblings; the ladder must not drift between them.
if ! command -v zstd >/dev/null 2>&1; then
	if command -v apt-get >/dev/null 2>&1; then
		if [ "$(id -u)" = "0" ]; then
			{ apt-get update -q && apt-get install -y -q zstd; } ||
				echo "WARN: apt zstd install failed — the python zstandard ladder below takes over." >&2
		else
			{ sudo apt-get update -q && sudo apt-get install -y -q zstd; } ||
				echo "WARN: apt zstd install failed — the python zstandard ladder below takes over." >&2
		fi
	fi
fi

# tar.zst extraction with host-available decompressors (the
# bootstrap-ebpf.sh ladder): (1) GNU tar with zstd support (needs
# the zstd binary — the probe tests the actual round trip), (2)
# python3 with the zstandard module decompressing to .tar, then
# plain tar, (3) explicit failure.
extract_tar_zst() {
	local archive="$1" dest="$2"
	if command -v zstd >/dev/null 2>&1 && tar --zstd -tf "$archive" >/dev/null 2>&1; then
		tar --zstd -xf "$archive" -C "$dest"
		return 0
	fi
	if command -v python3 >/dev/null 2>&1 && python3 -c 'import zstandard' >/dev/null 2>&1; then
		local tarfile="${archive%.tar.zst}.tar"
		python3 - "$archive" "$tarfile" <<'PYEOF'
import sys

import zstandard

with open(sys.argv[1], "rb") as src, open(sys.argv[2], "wb") as dst:
    zstandard.ZstdDecompressor().copy_stream(src, dst)
PYEOF
		tar -xf "$tarfile" -C "$dest"
		return 0
	fi
	return 1
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

curl -sL -o "${TMP_DIR}/bpf-linker.tar.zst" "${URL}"
if ! extract_tar_zst "${TMP_DIR}/bpf-linker.tar.zst" "${TMP_DIR}"; then
	echo "FAIL: no zstd-capable extractor on this host (GNU tar with zstd, the zstd binary, or python3 with the zstandard module) — unpack ${URL} by hand into ${PREFIX}." >&2
	exit 1
fi

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
