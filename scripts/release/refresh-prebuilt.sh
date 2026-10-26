#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC PREBUILT eBPF OBJECT REFRESH (NIGHT-ask-2, refreshed by
# night-dragon-maintenance-0)
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
# This script is the ONE WRITER of the prebuilt lane (the
# night-dragon-maintenance-0 shape, the sibling zejtron
# regenerate-ebpf-prebuilt.sh law): build.rs's registry lane stages
# only what this script wrote — and since the same maintenance pass it
# verifies the manifest's object blake3 against the staged bytes
# before embedding them — and scripts/gates/check-commit-gate.sh
# enforces the pins at commit time through this script's read-only
# --check verdict. One writer, one reader-shaped gate, no second
# implementation of the recipe.
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
# The manifest's ebpf_tree_blake3 (night-dragon-maintenance-0 — the
# digest upgraded from the sha256 the lane shipped with until now) is
# the blake3 over the byte-order-sorted (LC_ALL=C) git-tracked ebpf/
# file hashes (content + path stream):
#
#   git ls-files -z -- ebpf/ | LC_ALL=C sort -z | xargs -0 -r b3sum | b3sum
#
# The digest tool is the reference b3sum binary (crates.io b3sum,
# installed at the pinned version by scripts/dev/bootstrap-ebpf.sh),
# and build/blake3.rs is the reader-side one — the standalone build
# suite pins the two to the same vectors. The gate
# (scripts/gates/check-prebuilt-parity.sh) recomputes the pins with
# the same recipe and this script ends by RUNNING that gate — the
# implementations must agree on every generation, so a drift between
# them fails at the source instead of silently passing.
#
# When to run: after ANY change under ebpf/ (sources, Cargo.toml,
# Cargo.lock, rust-toolchain.toml, .cargo/config.toml, target spec).
# The parity gate fails CI until the refresh lands, so a stale
# prebuilt lane can never ride a release. The commit-time arm
# (check-commit-gate.sh) auto-heals a stale lane through this script
# and stages the refresh into the commit, so the normal flow is
# simply "edit ebpf/, commit" — the refresh rides along.
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
#   ./scripts/release/refresh-prebuilt.sh          # rebuild + rewrite
#   ./scripts/release/refresh-prebuilt.sh --check  # read-only verdict
#
# Exit codes: 0 in sync (or the rewrite succeeded); 1 stale/drift
# (or the build/prerequisite step failed); 2 usage error.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# The install locations are not on PATH in every invocation context
# (the pre-commit hook and cron run non-login shells): the bootstrap
# installs b3sum into ~/.cargo/bin (cargo install) and bpf-linker
# into ~/.local/bin, so prepend both before any probe — the same
# contract bootstrap-ebpf.sh applies to its own invocations.
for bin_dir in "${HOME}/.cargo/bin" "${HOME}/.local/bin"; do
	[ -d "${bin_dir}" ] && PATH="${bin_dir}:${PATH}"
done
export PATH

PREBUILT_DIR="ebpf-prebuilt"
NESTED_OUT="ebpf/target/bpfel-unknown-none/release"
MANIFEST="${PREBUILT_DIR}/manifest.toml"
OBJECTS=("zelynic-observer" "zelynic-limiter")

# The digest tool, needed by BOTH modes (the --check verdict
# recomputes the same pins the rewrite writes, so both need the
# pinned digest tool). The reference b3sum binary, pinned — the
# bootstrap installs it beside the build pair.
B3SUM_VERSION="1.8.7"

log() { echo "[refresh-prebuilt] $*"; }

# blake3 over the byte-order-sorted git-tracked ebpf/ file hashes.
# LC_ALL=C is load-bearing (the NIGHT-hunt-Z6 find, the 779907d
# shape): a bare `sort -z` follows the invoking shell's collation,
# and a UTF-8 desktop locale reorders the very list a C locale
# sorts by raw bytes — one identical ebpf/ tree, two hashes, a
# lane that passes every local gate and fails CI's clean checkout.
# The hashed listing carries each file's path, so a
# content-preserving rename under ebpf/ still stales the pin (the
# pin describes the tree, not just its content multiset), and the
# NUL-separated -z pipeline is locale-proof and newline-proof by
# construction. Kept in lockstep with
# scripts/gates/check-prebuilt-parity.sh (that gate recomputes the
# same recipe; this script's final step runs the gate, so the two
# can never drift apart silently).
ebpf_tree_blake3() {
	git ls-files -z -- ebpf/ |
		LC_ALL=C sort -z |
		xargs -0 -r b3sum |
		b3sum |
		awk '{print $1}'
}

toolchain_pin() {
	awk -F'"' '/^[[:space:]]*channel = /{print $2; exit}' ebpf/rust-toolchain.toml
}

# The b3sum gate runs before ANY mode: the --check verdict recomputes
# the same pins the rewrite writes, so both need the pinned digest
# tool. The fix message names the bootstrap, the one-command install.
b3sum_report="$(b3sum --version 2>/dev/null || true)"
if ! printf '%s' "$b3sum_report" | grep -q "$B3SUM_VERSION"; then
	echo "FAIL: the prebuilt lane's digest tool is b3sum ${B3SUM_VERSION} and it is not on PATH ('${b3sum_report:-no answer}')." >&2
	echo "      One command: ./scripts/dev/bootstrap-ebpf.sh (installs the toolchain pair plus the pinned b3sum)" >&2
	exit 1
fi

# ── The read-only verdict: --check ────────────────────────────────────
# Recomputes every pin the rewrite would write and compares it with
# the manifest on disk, without building anything: the tree pin, each
# [[object]] row's blake3 + size, and the toolchain pin. The commit
# gate (scripts/gates/check-commit-gate.sh) drives this mode — a
# stale verdict there auto-heals through the full rewrite below.
if [ "${1:-}" = "--check" ]; then
	[ "$#" -eq 1 ] || {
		echo "usage: $0 [--check]" >&2
		exit 2
	}
	STALE=0
	[ -f "$MANIFEST" ] || {
		echo "stale: $MANIFEST is missing entirely — run $0 (one writer, one rewrite)"
		exit 1
	}
	for name in "${OBJECTS[@]}"; do
		[ -f "${PREBUILT_DIR}/${name}" ] || {
			echo "stale: the staged ${PREBUILT_DIR}/${name} is missing"
			STALE=1
		}
	done
	[ "$STALE" -eq 0 ] || exit 1

	TREE_NOW="$(ebpf_tree_blake3)"
	PIN_TREE="$(awk -F'"' '/^ebpf_tree_blake3 = /{print $2}' "$MANIFEST")"
	PIN_TOOLCHAIN="$(awk -F'"' '/^toolchain = /{print $2; exit}' "$MANIFEST")"
	[ "$TREE_NOW" = "$PIN_TREE" ] || {
		echo "stale: manifest ebpf_tree_blake3 lags the ebpf/ tree (${PIN_TREE:-none} -> ${TREE_NOW})"
		STALE=1
	}
	[ "$(toolchain_pin)" = "$PIN_TOOLCHAIN" ] || {
		echo "stale: manifest toolchain lags ebpf/rust-toolchain.toml (${PIN_TOOLCHAIN:-none} -> $(toolchain_pin))"
		STALE=1
	}
	# Each [[object]] row: name/blake3/size must match the staged
	# bytes — the lane-integrity surface (the tree pin is the
	# staleness surface; the staged copy's pins are its own).
	while read -r name want_sha want_size; do
		[ -n "$name" ] || continue
		file="${PREBUILT_DIR}/${name}"
		if [ ! -f "$file" ]; then
			echo "stale: manifest names ${name} but the file is absent"
			STALE=1
			continue
		fi
		got_sha="$(b3sum "$file" | awk '{print $1}')"
		got_size="$(stat -c%s "$file")"
		if [ "$got_sha" != "$want_sha" ]; then
			echo "stale: ${name} blake3 drift (manifest ${want_sha}, disk ${got_sha})"
			STALE=1
		elif [ "$got_size" != "$want_size" ]; then
			echo "stale: ${name} size drift (manifest ${want_size}, disk ${got_size})"
			STALE=1
		fi
	done < <(
		awk '
                        /^\[\[object\]\]/ {
                                if (name != "") print name, sha, size
                                name = ""; sha = ""; size = ""
                        }
                        /^name = / { gsub(/"/, "", $3); name = $3 }
                        /^blake3 = / { gsub(/"/, "", $3); sha = $3 }
                        /^size = / { size = $3 }
                        END { if (name != "") print name, sha, size }
                ' "$MANIFEST"
	)

	[ "$STALE" -eq 0 ] && {
		log "in sync: manifest pins match the ebpf/ tree, the staged objects, and the toolchain pin"
		exit 0
	}
	exit 1
fi

[ "$#" -eq 0 ] || {
	echo "usage: $0 [--check]" >&2
	exit 2
}

# sha256 retired with the schema-1 manifest: the lane's one digest is
# blake3 (night-dragon-maintenance-0), every pin the same algorithm.

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

# NIGHT-hunt-32: the tolerant channel anchor plus a die on empty —
# a silently empty provenance field would ship a manifest that
# describes nothing.
TOOLCHAIN="$(toolchain_pin)"
if [ -z "${TOOLCHAIN}" ]; then
	echo "FAIL: could not read the toolchain channel from ebpf/rust-toolchain.toml — the manifest's provenance field refuses to ship empty." >&2
	exit 1
fi
BPF_LINKER="$(bpf-linker --version | awk '{print $2}')"
TREE_B3="$(ebpf_tree_blake3)"
GENERATED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
BUILT_BY="$(git config user.name >/dev/null 2>&1 && git config user.email >/dev/null 2>&1 &&
	printf '%s <%s>' "$(git config user.name)" "$(git config user.email)" ||
	printf 'oxyzenQ <130107241+oxyzenQ@users.noreply.github.com>')"

log "toolchain pin: ${TOOLCHAIN}"
log "bpf-linker:    ${BPF_LINKER}"
log "ebpf tree b3:  ${TREE_B3}"

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

# Provenance manifest (schema 2 since night-dragon-maintenance-0 —
# the digest algorithm is blake3, upgraded from sha256). The
# built_by line records the machine-side identity that drove the
# validated pipeline; git config is the source, the owner's identity
# the fallback. Generator-controlled format: flat keys first, then
# one [[object]] block per object (name/blake3/size). The parity
# gate parses exactly this shape and its header says so.
{
	echo "# Copyright (C) 2026 rezky_nightky"
	echo "# SPDX-License-Identifier: GPL-3.0-only"
	echo "#"
	echo "# zelynic prebuilt eBPF object manifest (NIGHT-ask-2;"
	echo "# schema 2 since night-dragon-maintenance-0 — the digest"
	echo "# algorithm is blake3, upgraded from sha256). Generated by"
	echo "# scripts/release/refresh-prebuilt.sh — the ONE WRITER of the"
	echo "# lane; regenerate after any change under ebpf/ (the parity"
	echo "# gate fails until the refresh lands, and the commit gate"
	echo "# auto-heals a stale lane through this script)."
	echo "# ebpf_tree_blake3 pins the exact ebpf/ source tree the"
	echo "# objects were built from: the blake3 over the byte-order-sorted"
	echo "# (LC_ALL=C) git-tracked ebpf/ file hashes (content + path"
	echo "# stream). built_by records the identity that drove the"
	echo "# validated build. These are the same bytes the GitHub Release"
	echo "# binaries embed."
	echo ""
	echo "schema = 2"
	echo "generated = \"${GENERATED}\""
	echo "toolchain = \"${TOOLCHAIN}\""
	echo "bpf_linker = \"${BPF_LINKER}\""
	echo "ebpf_tree_blake3 = \"${TREE_B3}\""
	echo "built_by = \"${BUILT_BY}\""
	echo ""
	for name in "${OBJECTS[@]}"; do
		sha="$(b3sum "${PREBUILT_DIR}/${name}" | awk '{print $1}')"
		size="$(stat -c%s "${PREBUILT_DIR}/${name}")"
		echo "[[object]]"
		echo "name = \"${name}\""
		echo "blake3 = \"${sha}\""
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
