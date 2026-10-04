#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
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
# The manifest's ebpf_tree_sha256 is the sha256 over the
# byte-order-sorted (LC_ALL=C) git-tracked ebpf/ file hashes
# (content + path stream). The gate
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
# The phantom-pin guard (NIGHT-repair-1): the tree pin hashes
# ON-DISK content over the tracked list, so this script REFUSES to
# generate while any tracked file under ebpf/ hides behind an
# assume-unchanged/skip-worktree flag — the one shape whose churn
# git status cannot see and git add -A cannot stage, which the
# 2523b7d incident pinned into the manifest and only CI's clean
# checkout could name. Uncommitted-but-visible ebpf/ changes are
# the NORMAL refresh shape (the lane and its sources land in one
# commit); the advisory names them so that commit cannot forget.
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

# sha256 over the byte-order-sorted git-tracked ebpf/ file hashes.
# LC_ALL=C is load-bearing (the NIGHT-hunt-Z6 find, the 779907d
# shape): a bare `sort -z` follows the invoking shell's collation,
# and a UTF-8 desktop locale reorders the very list a C locale
# sorts by raw bytes — one identical ebpf/ tree, two hashes, a
# lane that passes every local gate and fails CI's clean checkout.
# Kept in lockstep with scripts/gates/check-prebuilt-parity.sh
# (that gate's header documents the same algorithm; this script's
# final step runs the gate, so the two can never drift apart
# silently).
ebpf_tree_sha() {
	git ls-files -z -- ebpf/ |
		LC_ALL=C sort -z |
		xargs -0 -r sha256sum |
		sha256sum |
		awk '{print $1}'
}

# The phantom-pin guard (NIGHT-repair-1): refuse BEFORE the build
# (fail fast — the build is 45s the refusal does not need to pay)
# while any tracked file under ebpf/ hides behind assume-unchanged
# (h) or skip-worktree (S). Those flags make local churn invisible
# to git status and unreachable by git add -A, so the pin this
# script writes would describe a tree the commit cannot carry —
# exactly the 2523b7d phantom (manifest 481d777d vs the committed
# tree 0a43a812, a two-file commit riding a clean status).
hidden_churn="$(git ls-files -v -- ebpf/ | awk '$1 ~ /^[hS]$/ {sub(/^[hS] /, ""); print}')"
if [ -n "$hidden_churn" ]; then
	echo "FAIL: tracked ebpf/ file(s) hide behind assume-unchanged/skip-worktree flags —" >&2
	echo "      the tree pin would describe churn the commit cannot carry:" >&2
	while IFS= read -r f; do
		echo "      ${f}" >&2
	done <<<"$hidden_churn"
	echo "Fix: unhide each file, then either restore the committed bytes or stage the change on purpose:" >&2
	echo "      git update-index --no-assume-unchanged --no-skip-worktree <file>" >&2
	echo "      git checkout -- <file>   # to drop the local churn" >&2
	echo "Then re-run this refresh — a pin over hidden churn ships a phantom tree (the 2523b7d shape)." >&2
	exit 1
fi

# The same-commit advisory: uncommitted-but-VISIBLE ebpf/ changes
# are the normal refresh flow (new sources + the regenerated lane
# land together), but only if they actually land — the pin covers
# them, so the commit that carries the lane must carry them too.
uncommitted="$(git status --porcelain -- ebpf/)"
if [ -n "$uncommitted" ]; then
	log "ebpf/ carries uncommitted changes — they MUST ride the same commit as the lane:"
	while IFS= read -r line; do
		log "    ${line}"
	done <<<"$uncommitted"
	log "(one commit: git add ebpf/ ebpf-prebuilt/ — a lane without its sources fails CI's parity gate)"
fi

# The maintainer-built objects only ever come out of the repo's own
# validated build pipeline — never a bare nested cargo call whose
# flags could drift from build.rs's invocation.
log "building the eBPF objects through the repo's validated pipeline"
log "(cargo build --release --locked --features ebpf — build.rs runs"
log " the preflight, the nested nightly cross-compile, and the"
log " NIGHT-hunt-29 structural validation)"
cargo build --release --locked --features ebpf

mkdir -p "$PREBUILT_DIR"

# NIGHT-hunt-32: the tolerant channel anchor (bootstrap-ebpf.sh's
# twin) plus a die on empty — the old column-0-only pattern could
# silently write toolchain = "" into the manifest's provenance field
# if the line ever gains indentation.
TOOLCHAIN="$(awk -F'"' '/^[[:space:]]*channel = /{print $2}' ebpf/rust-toolchain.toml)"
if [ -z "${TOOLCHAIN}" ]; then
	echo "FAIL: could not read the toolchain channel from ebpf/rust-toolchain.toml — the manifest's provenance field refuses to ship empty." >&2
	exit 1
fi
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
	echo "# zelynic prebuilt eBPF object manifest (NIGHT-ask-2)."
	echo "# Generated by scripts/release/refresh-prebuilt.sh — regenerate"
	echo "# after any change under ebpf/ (the parity gate fails until the"
	echo "# refresh lands). ebpf_tree_sha256 pins the exact ebpf/ source"
	echo "# tree the objects were built from: the sha256 over the"
	echo "# byte-order-sorted (LC_ALL=C) git-tracked ebpf/ file hashes."
	echo "# These are the same bytes the GitHub Release binaries embed."
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

log "done — review and commit the lane WITH its ebpf/ changes (git add ebpf/ ebpf-prebuilt/)"
