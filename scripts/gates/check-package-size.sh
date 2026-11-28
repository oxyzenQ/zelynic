#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
# PLATFORM: needs cargo, git, awk, wc — the packaging machinery, not the
#   full build (no rustc invocation: --no-verify).
#
# ZELYNIC PACKAGE-SIZE CAP CHECK (night-cafe-mclaren-5; the cosmostrix
# NIGHT-CAFE-MCLAREN-5 lineage, ported after that port was itself
# third-party verified end to end)
#
# The registry upload size is a hard external contract: crates.io
# refuses an oversized .crate with HTTP 413 Payload Too Large (max
# upload 10485760 bytes). The sibling estate's v100.1.3-dragon.2
# publish died on exactly that answer in 1m36s — a 9.2 MB showcase
# webp rode the tarball while every gate measured everything except
# the package itself. zelynic's exposure is real: the crate is LIVE
# on the registry (23 versions at port time) and its ship set is
# include-mode curated, but include-mode is not a size contract —
# the heaviest members only ever grow (the shipped CHANGELOG is
# ~316 KB, docs/USAGE.md ~198 KB, docs/INNOVATIONS.md ~139 KB, the
# two ebpf-prebuilt objects ~1 MB, and every release adds to them),
# and one include-line mistake would have ridden silently past the
# wholesale gate suite into an irreversible registry upload. No
# gate measured the tarball. This one does — the 20th gate.
#
# This gate builds the real .crate (metadata + packaging only, no
# verify build) and asserts its byte count against the documented
# server cap, so the refusal class fails in the CI package gate in
# about a minute instead of in the publish job.
#
# Equality with the cap fails too: the server's exact boundary
# behaviour at 10485760 bytes is not part of this contract, headroom
# is. The measured tarball must be the publish candidate, so the
# gate refuses to run over a dirty tree — untracked or modified
# files change the bytes the gate measures, and a size verdict over
# a tree that will never publish is a lie. (The reference mapped
# cargo's failure to a dirty-tree message; this port asserts the
# dirtiness explicitly instead — a real git check, not an inferred
# one.)
#
# Usage: bash scripts/gates/check-package-size.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

# crates.io's documented max upload size (the 413 answer quotes it).
CAP=10485760

if ! command -v cargo >/dev/null 2>&1; then
	echo "FAIL: cargo not found on PATH - the gate measures the real"
	echo ".crate bytes, which requires the packaging machinery."
	exit 1
fi

NAME=$(grep -m1 '^name = ' Cargo.toml | sed 's/^name = "\(.*\)".*/\1/')
VERSION=$(grep -m1 '^version = ' Cargo.toml | sed 's/^version = "\(.*\)".*/\1/')
if [ -z "$NAME" ] || [ -z "$VERSION" ]; then
	echo "FAIL: no package name/version line found in Cargo.toml"
	exit 1
fi

# The dirty-tree refusal runs BEFORE packaging: git is the truth
# about the tree the tarball would be cut from (tracked changes,
# staged changes, and untracked files all change what a stranger
# would receive).
if [ -n "$(git status --porcelain)" ]; then
	echo "FAIL: the working tree is dirty - the gate refuses to put a"
	echo "size verdict on a tree that will never publish (untracked or"
	echo "modified files change the measured bytes). Commit or restore"
	echo "the working tree, then re-run this gate."
	exit 1
fi

CRATE="target/package/${NAME}-${VERSION}.crate"
rm -f "$CRATE"

if ! cargo package --locked --no-verify >/dev/null 2>&1; then
	echo "FAIL: cargo package --locked --no-verify refused the tree."
	echo "Fix the manifest error the command prints when run directly,"
	echo "then re-run this gate."
	exit 1
fi

if [ ! -f "$CRATE" ]; then
	echo "FAIL: expected $CRATE was not produced by cargo package"
	exit 1
fi

BYTES=$(wc -c <"$CRATE" | tr -d ' ')
MIB=$(awk -v b="$BYTES" 'BEGIN { printf "%.2f", b / 1048576 }')

if [ "$BYTES" -ge "$CAP" ]; then
	OVER=$(awk -v b="$BYTES" -v c="$CAP" 'BEGIN { printf "%.2f", (b - c) / 1048576 }')
	echo "FAIL: ${NAME}-${VERSION}.crate is ${BYTES} bytes (${MIB} MiB)"
	echo "- at or over the crates.io hard upload cap of ${CAP} bytes"
	echo "(10 MiB), over by ${OVER} MiB. The registry answers such an"
	echo "upload with HTTP 413 Payload Too Large. Find the heavyweight"
	echo "that entered the package (cargo package --list) and drop it"
	echo "from Cargo.toml [package] include."
	exit 1
fi

HEADROOM=$(awk -v b="$BYTES" -v c="$CAP" 'BEGIN { printf "%.2f", (c - b) / 1048576 }')
echo "OK: ${NAME}-${VERSION}.crate is ${BYTES} bytes (${MIB} MiB),"
echo "under the crates.io hard upload cap of ${CAP} bytes (10 MiB) with"
echo "${HEADROOM} MiB headroom."
