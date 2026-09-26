#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ZELYNIC PREBUILT eBPF PARITY CHECK (NIGHT-ask-2)
#
# Guards the ebpf-prebuilt/ lane — the two maintainer-built objects
# that make `cargo install zelynic` land the full-featured binary on
# a plain stable toolchain (cargo's package walk cannot carry the
# detached ebpf/ workspace, so the registry tarball ships these
# objects instead; provenance: ebpf-prebuilt/manifest.toml).
#
# What is checked, and why each row is load-bearing:
#   1. Both objects exist and are structurally sane ELFs (magic +
#      minimum size). A missing or truncated object would make the
#      registry lane's build.rs panic on every `cargo install`.
#   2. Every manifest [[object]] row matches the file on disk
#      (sha256 + size). A tampered or partially refreshed directory
#      fails here instead of shipping an unaccounted artifact.
#   3. The manifest's ebpf_tree_sha256 equals the sha256 over the
#      sorted git-tracked ebpf/ file hashes — the STALENESS killer:
#      any change under ebpf/ (sources, locks, pins, target spec)
#      changes the tree hash, and the gate fails until
#      scripts/release/refresh-prebuilt.sh regenerates the lane. The
#      shipped objects can never silently fall behind the sources
#      they claim to carry.
#
# Deliberately NOT checked: a rebuild-and-byte-compare of the
# objects. bpf-linker 0.11.1 under the dated pin reproduced both
# objects byte-identically on 2026-09-27 (forced-rebuild evidence in
# refresh-prebuilt.sh's header), but byte reproducibility is a host
# property, not a contract — the tree-hash pin is deterministic on
# every Linux and is the enforcement surface. The same discipline as
# check-release-parity.sh: pin what is deterministic, document what
# is not.
#
# The manifest is generator-controlled (refresh-prebuilt.sh writes a
# flat-key header plus one [[object]] block per object), so parsing is
# deliberately simple awk over that exact shape.
#
# Usage: bash scripts/gates/check-prebuilt-parity.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

PREBUILT_DIR="ebpf-prebuilt"
MANIFEST="${PREBUILT_DIR}/manifest.toml"
FAILED=0

fail() {
	echo "FAIL: $*"
	FAILED=$((FAILED + 1))
}

pass() {
	echo "PASS: $*"
}

# sha256 over the sorted git-tracked ebpf/ file hashes. Kept in
# lockstep with scripts/gates/../release/refresh-prebuilt.sh (which
# ends every generation by running THIS gate, so the two
# implementations cannot drift apart silently).
ebpf_tree_sha() {
	git ls-files -z -- ebpf/ |
		sort -z |
		xargs -0 -r sha256sum |
		sha256sum |
		awk '{print $1}'
}

# ── 1. the lane exists and its objects are structurally sane ──────
if [ ! -d "$PREBUILT_DIR" ]; then
	fail "ebpf-prebuilt/ is missing — the registry lane cannot ship. Run ./scripts/release/refresh-prebuilt.sh"
	echo "FAIL: 1 of 3 checks (lane missing)"
	exit 1
fi
if [ ! -f "$MANIFEST" ]; then
	fail "ebpf-prebuilt/manifest.toml is missing — regenerate with ./scripts/release/refresh-prebuilt.sh"
	FAILED=$((FAILED + 1))
else
	pass "manifest present (${MANIFEST})"
fi

for name in zelynic-observer zelynic-limiter; do
	file="${PREBUILT_DIR}/${name}"
	if [ ! -f "$file" ]; then
		fail "${file} is missing — regenerate with ./scripts/release/refresh-prebuilt.sh"
		continue
	fi
	magic="$(head -c 4 "$file" | od -An -tx1 | tr -d ' \n')"
	if [ "$magic" != "7f454c46" ]; then
		fail "${file} is not an ELF file (magic ${magic})"
		continue
	fi
	size="$(stat -c%s "$file")"
	if [ "$size" -lt 64 ]; then
		fail "${file} is only ${size} bytes — too short for an ELF64 header"
		continue
	fi
	pass "${name} is a structurally sane ELF (${size} bytes)"
done

# ── 2. every manifest row matches the file on disk ───────────────
if [ -f "$MANIFEST" ]; then
	# One line per [[object]] block: "name sha256 size"
	while read -r name want_sha want_size; do
		[ -n "$name" ] || continue
		file="${PREBUILT_DIR}/${name}"
		if [ ! -f "$file" ]; then
			fail "manifest names ${name} but the file is absent"
			continue
		fi
		got_sha="$(sha256sum "$file" | awk '{print $1}')"
		got_size="$(stat -c%s "$file")"
		if [ "$got_sha" != "$want_sha" ]; then
			fail "${name} sha256 drift: manifest ${want_sha}, disk ${got_sha}"
		elif [ "$got_size" != "$want_size" ]; then
			fail "${name} size drift: manifest ${want_size}, disk ${got_size}"
		else
			pass "${name} matches its manifest row (sha256 + size)"
		fi
	done < <(
		awk '
			/^\[\[object\]\]/ {
				if (name != "") print name, sha, size
				name = ""; sha = ""; size = ""
			}
			/^name = / { gsub(/"/, "", $3); name = $3 }
			/^sha256 = / { gsub(/"/, "", $3); sha = $3 }
			/^size = / { size = $3 }
			END { if (name != "") print name, sha, size }
		' "$MANIFEST"
	)

	# ── 3. the manifest's tree pin equals the live ebpf/ tree ──────
	want_tree="$(awk -F'"' '/^ebpf_tree_sha256 = /{print $2}' "$MANIFEST")"
	got_tree="$(ebpf_tree_sha)"
	if [ -z "$want_tree" ]; then
		fail "manifest carries no ebpf_tree_sha256 — regenerate with ./scripts/release/refresh-prebuilt.sh"
	elif [ "$want_tree" != "$got_tree" ]; then
		fail "ebpf/ changed after the prebuilt lane was generated (tree ${got_tree} vs manifest ${want_tree}) — run ./scripts/release/refresh-prebuilt.sh and commit ebpf-prebuilt/"
	else
		pass "prebuilt objects pin the live ebpf/ tree (${got_tree:0:12}...)"
	fi
fi

if [ "$FAILED" -eq 0 ]; then
	echo "OK: ebpf-prebuilt lane in parity (objects + manifest + ebpf/ tree pin)"
	exit 0
else
	echo "FAIL: ${FAILED} prebuilt-parity failure(s) — the registry lane is not shippable"
	exit 1
fi
