#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ZELYNIC PREBUILT eBPF OBJECT REFRESH (NIGHT-ask-2)
#
# Regenerates ebpf-prebuilt/ — the two maintainer-built eBPF objects
# that ride the crates.io tarball so `cargo install zelynic` lands the
# FULL-FEATURED binary (monitor + limiter) on a plain stable
# toolchain. Why the lane exists: cargo's package walk auto-excludes
# nested packages, so the detached ebpf/ workspace (its own
# Cargo.toml) cannot ride a registry tarball — verified live twice on
# this manifest (NIGHT-ask-1), and `include` does not override the
# rule. The registry lane therefore stages the SAME objects the GitHub
# Release binaries embed: identical bytes, identical CO-RE kernel
# compatibility, provenance pinned in ebpf-prebuilt/manifest.toml.
#
# The generation path deliberately reuses the repo's own validated
# build as the single source of build truth: `cargo build --release
# --locked --features ebpf` at the ROOT drives build.rs's full
# pipeline — the NIGHT-host-1 prerequisite preflight, the nested
# nightly cross-compile, and the NIGHT-hunt-29 structural validation
# (every object is read + ELF-law-checked before it may be staged).
# This script only copies the artifacts that pipeline just validated
# out of ebpf/target/ and records their provenance. A forced rebuild
# on 2026-09-27 (touch + rebuild) produced byte-identical objects —
# bpf-linker 0.11.1 output is reproducible under the dated pin — but
# the parity gate deliberately does NOT rely on that: it pins the
# ebpf/ SOURCE TREE hash, which is deterministic everywhere.
#
# The manifest's ebpf_tree_sha256 is the sha256 over the sorted
# git-tracked ebpf/ file hashes (content + path stream). The gate
# (scripts/gates/check-prebuilt-parity.sh) recomputes it with its own
# implementation and this script ends by RUNNING that gate — the two
# implementations must agree on every generation, so a drift between
# them fails at the source instead of silently passing.
#
# When to run: after ANY change under ebpf/ (sources, Cargo.toml,
# Cargo.lock, rust-toolchain.toml, .cargo/config.toml, target spec).
# The parity gate fails CI until the refresh lands, so a stale
# prebuilt lane can never ride a release.
#
# Usage (from the repo root, with the eBPF toolchain bootstrapped):
#   ./scripts/release/refresh-prebuilt.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PREBUILT_DIR="ebpf-prebuilt"
NESTED_OUT="ebpf/target/bpfel-unknown-none/release"
MANIFEST="${PREBUILT_DIR}/manifest.toml"
OBJECTS=("zelynic-observer" "zelynic-limiter")

log() { echo "[refresh-prebuilt] $*"; }

# sha256 over the sorted git-tracked ebpf/ file hashes. Kept in
# lockstep with scripts/gates/check-prebuilt-parity.sh (that gate's
# header documents the same algorithm; this script's final step runs
# the gate, so the two can never drift apart silently).
ebpf_tree_sha() {
	git ls-files -z -- ebpf/ |
		sort -z |
		xargs -0 -r sha256sum |
		sha256sum |
		awk '{print $1}'
}

# The maintainer-built objects only ever come out of the repo's own
# validated build pipeline — never a bare nested cargo call whose
# flags could drift from build.rs's invocation.
log "building the eBPF objects through the repo's validated pipeline"
log "(cargo build --release --locked --features ebpf — build.rs runs"
log " the preflight, the nested nightly cross-compile, and the"
log " NIGHT-hunt-29 structural validation)"
cargo build --release --locked --features ebpf

mkdir -p "$PREBUILT_DIR"

TOOLCHAIN="$(awk -F'"' '/^channel = /{print $2}' ebpf/rust-toolchain.toml)"
BPF_LINKER="$(bpf-linker --version | awk '{print $2}')"
TREE_SHA="$(ebpf_tree_sha)"
GENERATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log "toolchain pin: ${TOOLCHAIN}"
log "bpf-linker:    ${BPF_LINKER}"
log "ebpf tree sha: ${TREE_SHA}"

# Copy + sanity: the objects were already structurally validated by
# build.rs moments ago; the magic/size re-check here guards the copy
# itself (a truncated copy would fail the gate one step later anyway).
for name in "${OBJECTS[@]}"; do
	src="${NESTED_OUT}/${name}"
	dst="${PREBUILT_DIR}/${name}"
	[ -f "$src" ] || {
		echo "FAIL: ${src} missing after a successful build" >&2
		exit 1
	}
	magic="$(head -c 4 "$src" | od -An -tx1 | tr -d ' \n')"
	[ "$magic" = "7f454c46" ] || {
		echo "FAIL: ${src} is not an ELF file (magic ${magic})" >&2
		exit 1
	}
	size="$(stat -c%s "$src")"
	[ "$size" -ge 64 ] || {
		echo "FAIL: ${src} is only ${size} bytes" >&2
		exit 1
	}
	cp "$src" "$dst"
	log "staged ${name} ($(stat -c%s "$dst") bytes)"
done

# Provenance manifest. Generator-controlled format: flat keys first,
# then one [[object]] block per object (name/sha256/size). The parity
# gate parses exactly this shape and its header says so.
{
	echo "# Copyright (C) 2026 rezky_nightky"
	echo "# SPDX-License-Identifier: GPL-3.0-only"
	echo "#"
	echo "# ZELYNIC prebuilt eBPF object manifest (NIGHT-ask-2)."
	echo "# Generated by scripts/release/refresh-prebuilt.sh — regenerate"
	echo "# after any change under ebpf/ (the parity gate fails until the"
	echo "# refresh lands). ebpf_tree_sha256 pins the exact ebpf/ source"
	echo "# tree the objects were built from: the sha256 over the sorted"
	echo "# git-tracked ebpf/ file hashes. These are the same bytes the"
	echo "# GitHub Release binaries embed."
	echo ""
	echo "schema = 1"
	echo "generated = \"${GENERATED}\""
	echo "toolchain = \"${TOOLCHAIN}\""
	echo "bpf_linker = \"${BPF_LINKER}\""
	echo "ebpf_tree_sha256 = \"${TREE_SHA}\""
	echo ""
	for name in "${OBJECTS[@]}"; do
		sha="$(sha256sum "${PREBUILT_DIR}/${name}" | awk '{print $1}')"
		size="$(stat -c%s "${PREBUILT_DIR}/${name}")"
		echo "[[object]]"
		echo "name = \"${name}\""
		echo "sha256 = \"${sha}\""
		echo "size = ${size}"
		echo ""
	done
} >"$MANIFEST"
log "wrote ${MANIFEST}"

# Self-verification: the gate recomputes everything with its own
# implementation and must agree with what was just written.
log "running the parity gate (scripts/gates/check-prebuilt-parity.sh)"
bash scripts/gates/check-prebuilt-parity.sh

log "done — review and commit ebpf-prebuilt/ (git add ebpf-prebuilt)"
