#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC RUST SOURCE FILE LOC CHECK
#
# Ensures every Rust source file in the tree stays under the hard LOC
# cap. Owner rule (NIGHT-improve-44, the no-mercy era): the cap is
# 600 lines, it applies to EVERY tracked *.rs file ANYWHERE in the
# tree — the checker autodetects the file type and walks the whole
# git index, not a hand-listed directory set (src/ and test/ and
# build.rs were the 500-era scope; the 600-era scope is the tree:
# ebpf/src/**, build/**, and any future .rs home are covered the day
# they land). NO file is exempt: the // LOC_EXEMPT: marker that the
# 500-era honored as tracked debt is retired for Rust — over the cap
# means SPLIT, the same hour, no marker, no mercy (the owner's
# wording), with precision kept (the split is a pure move, gates
# green in between).
#
# NIGHT-blade-15 additionally enforces the src/ root single-file
# policy here (the cosmostrix Single-File Policy convention):
# src/ root holds exactly ONE .rs file, main.rs. Every other module
# lives in its subsystem directory as dir/mod.rs. Same scope, same
# walk, one more invariant.
#
# Usage: scripts/gates/check-loc.sh [MAX_LINES]
#   MAX_LINES: override the default limit (default: 600)
#
# Platform: UNIX-only (uses `git`, `wc -l`). Not for Windows cmd.exe.

set -euo pipefail

MAX_LINES="${1:-600}"
FAILED=0
FOUND=0

# ── src/ root single-file policy (NIGHT-blade-15) ──────────────────────────
# Checked FIRST: a stray root module is a layout failure, not a size
# one — it fails before any line is counted. src/RULES.md (the doc
# standing in the tree) and docs/RULES.md (the canonical policy)
# carry the full text.
ROOT_STRAYS=$(find src -maxdepth 1 -name '*.rs' ! -name 'main.rs' 2>/dev/null || true)
if [ -n "$ROOT_STRAYS" ]; then
	echo "FAIL: src/ root must contain only main.rs (single-file policy)."
	echo "Stray root module(s) found:"
	while IFS= read -r stray; do
		echo "    ${stray}"
	done <<<"$ROOT_STRAYS"
	echo ""
	echo "Move each into its subsystem directory (dir/mod.rs style):"
	echo "    git mv src/<module>.rs src/<module>/mod.rs"
	echo "(a moved module's relative #[path] wirings gain one ../ level)"
	exit 1
fi

echo "Rust source file line counts, tree-wide by type (max ${MAX_LINES}):"
echo ""

# NIGHT-improve-44: autodetect by FILE TYPE, not by directory. Every
# git-tracked *.rs file anywhere in the repo (plus untracked-but-
# present, respecting .gitignore, so a new over-cap file fails BEFORE
# the commit — the pre-commit proxy parity discipline
# check-headers.sh set). Cargo build dirs are excluded by .gitignore
# already; the guard below is defensive.
FILES=$(git ls-files --cached --others --exclude-standard -- '*.rs' 2>/dev/null |
	grep -v -E '^(target|ebpf/target)/' | sort)

if [ -z "$FILES" ]; then
	echo "No .rs files found in the tree"
	exit 0
fi

# Compute and display line counts sorted descending
while IFS= read -r f; do
	LINES=$(wc -l <"$f")
	printf "  %5d  %s\n" "$LINES" "$f"
	if [ "$LINES" -gt "$MAX_LINES" ]; then
		FAILED=$((FAILED + 1))
		echo "    ^^^ VIOLATES ${MAX_LINES} limit (NIGHT-improve-44: no marker,"
		echo "           no mercy — over the cap means SPLIT, precision kept)"
	fi
	FOUND=$((FOUND + 1))
done <<<"$FILES"

echo ""
echo "Total files: ${FOUND}"
echo "Files over ${MAX_LINES}: ${FAILED} (the 600-era law: zero allowed)"

if [ "$FAILED" -gt 0 ]; then
	echo ""
	echo "FAIL: ${FAILED} file(s) exceed ${MAX_LINES} lines."
	echo "The NIGHT-improve-44 rule: no exemptions, no markers — split the"
	echo "file into modules (a pure move, gates green in between)."
	exit 1
fi

echo ""
echo "OK: all ${FOUND} .rs files are within the ${MAX_LINES}-line cap."
exit 0
