#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ZELYNIC SCRIPTS FILE LOC CHECK (NIGHT-lts-2)
#
# Ensures every script under scripts/ (shell AND python, recursive)
# stays under the hard LOC cap. Owner rule: the cap is 1000 lines
# (see docs/RULES.md "File size caps" — the scripts twin of the 500
# Rust cap owned by check-loc.sh; scripts get the doubled budget
# because a one-shot harness legitimately bundles its constants,
# its stage table, and its verdict plumbing in one self-contained
# file, but NO script gets to grow unbounded).
#
# Exemption mechanism: NO hardcoded file list. Instead, each file
# that legitimately exceeds 1000 LOC self-declares with a marker
# comment (hash syntax — the sh/py comment convention):
#
#   # LOC_EXEMPT: <one-line justification>
#
# The marker is tracked migration debt, exactly like the Rust
# contract: the exemption lives WITH the file it exempts, removing
# it means deleting the comment, and the justification is visible
# at the top of the exempt file. The three flagship harnesses
# (supermassive v1/v2, proof-claims) carried their markers BEFORE
# this checker existed — this gate is what turned those
# declarations from prose into a live, every-push audit.
#
# Usage: scripts/gates/check-scripts-loc.sh [MAX_LINES]
#   MAX_LINES: override the default limit (default: 1000)
#
# Platform: UNIX-only (uses `find`, `wc -l`, `grep`). Not for
# Windows cmd.exe.

set -euo pipefail

MAX_LINES="${1:-1000}"
FAILED=0
FOUND=0
EXEMPT_VIOLATIONS=0

# Marker that a file uses to self-declare an LOC exemption.
# Must be followed by a justification (one line, free-form text).
EXEMPT_MARKER='# LOC_EXEMPT:'

echo "Scripts file line counts (max ${MAX_LINES}):"
echo ""

# Dynamically collect all .sh and .py files under scripts/
# (recursive). No hardcoding — new directories are covered the day
# they land. The */target/* exclusion is defensive only (a cargo
# invocation from a script never runs with cwd inside scripts/).
FILES=$(find scripts -type f \( -name '*.sh' -o -name '*.py' \) \
	-not -path '*/target/*' 2>/dev/null | sort)

if [ -z "$FILES" ]; then
	echo "No .sh/.py files found under scripts/"
	exit 0
fi

# Compute and display line counts sorted descending
while IFS= read -r f; do
	LINES=$(wc -l <"$f")
	printf "  %5d  %s\n" "$LINES" "$f"
	if [ "$LINES" -gt "$MAX_LINES" ]; then
		# Dynamically check if the file self-declares an exemption
		# via the marker comment (no hardcoded list lookup).
		if grep -qF "$EXEMPT_MARKER" "$f"; then
			EXEMPT_VIOLATIONS=$((EXEMPT_VIOLATIONS + 1))
			echo "    ^^^ over ${MAX_LINES} (exempt via # LOC_EXEMPT: marker — tracked debt)"
		else
			FAILED=$((FAILED + 1))
			echo "    ^^^ VIOLATES ${MAX_LINES} limit (no # LOC_EXEMPT: marker found)"
			echo "           Either refactor below ${MAX_LINES}, or add a marker comment:"
			echo "               # LOC_EXEMPT: <one-line justification>"
		fi
	fi
	FOUND=$((FOUND + 1))
done <<<"$FILES"

echo ""
echo "Total files: ${FOUND}"
echo "Files over ${MAX_LINES} (exempt via # LOC_EXEMPT: marker): ${EXEMPT_VIOLATIONS}"
echo "Files over ${MAX_LINES} (NOT exempt — BUILD FAIL): ${FAILED}"

if [ "$FAILED" -gt 0 ]; then
	echo ""
	echo "FAIL: ${FAILED} script file(s) exceed ${MAX_LINES} lines without a"
	echo "# LOC_EXEMPT: marker. Either refactor them below ${MAX_LINES}, or"
	echo "add the marker with a justification:"
	echo "    # LOC_EXEMPT: <reason this file cannot be split>"
	exit 1
fi

if [ "$EXEMPT_VIOLATIONS" -gt 0 ]; then
	echo ""
	echo "OK (with migration debt): ${EXEMPT_VIOLATIONS} file(s) exceed ${MAX_LINES}"
	echo "but self-declare exemption via # LOC_EXEMPT: marker."
	echo "Refactor incrementally — see docs/RULES.md 'File size caps'."
	exit 0
fi

echo "OK: all script files at or below ${MAX_LINES} lines (no exemptions needed)"
exit 0
