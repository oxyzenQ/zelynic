#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ZELYNIC DISCLAIMER INJECTOR
#
# Auto-injects a "documentation disclaimer" note at the BOTTOM of every
# git-tracked *.md file in the repo. The disclaimer warns readers that
# docs may contain stale data, hardcoded counts, or outdated references
# because maintainers update source code but may forget to sync docs.
# Source code is the single source of truth — cross-check before relying
# on any specific number, file path, or symbol name.
#
# The disclaimer is idempotent: re-running this script will not add a
# second copy if the marker is already present.
#
# Usage:
#   bash scripts/inject-disclaimer.sh          # inject into all .md files
#   bash scripts/inject-disclaimer.sh --check  # verify all .md files have it
#
# Exit codes:
#   0 = all .md files have the disclaimer (or were just injected)
#   1 = one or more .md files are missing the disclaimer (in --check mode)
#
# Why this exists:
#   Owner observed that AI agents (and human maintainers) frequently
#   update source code (e.g. changing a rate bound or a file layout)
#   but forget to update every doc that references that number or path.
#   Chasing perfect sync across every .md file is a maintenance burden
#   with diminishing returns. Instead, the project ships a uniform
#   disclaimer that asks readers to cross-check source code before
#   believing any specific data point.
#
# Excluded: CHANGELOG.md and CHANGELOG-V11-ERA.md — frozen
#   historical records, never rewritten (the same exclusion policy as
#   every other gate). The era file joined the exclusion when the
#   NIGHT-docs-1 split moved the NIGHT campaign history out of
#   CHANGELOG.md.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK_MODE=false

if [[ "${1:-}" == "--check" ]]; then
	CHECK_MODE=true
fi

# The disclaimer marker — must match exactly for idempotency.
# If this string appears anywhere in the file, the file is considered
# already-injected and will be skipped.
MARKER="<!-- ZELYNIC-DISCLAIMER -->"

# The full disclaimer block. Injected at the BOTTOM of the file.
read -r -d '' DISCLAIMER <<'EOF' || true

<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
EOF

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

INJECTED=0
SKIPPED=0
MISSING=0
CHECKED=0

# Process every git-tracked OR untracked-but-present .md file in the
# repo (git ls-files --cached --others --exclude-standard returns
# tracked files PLUS new files not yet staged — respecting .gitignore —
# so a freshly written .md fails the check BEFORE it can be committed).
while IFS= read -r -d '' file; do
	CHECKED=$((CHECKED + 1))

	if grep -q "$MARKER" "$file"; then
		SKIPPED=$((SKIPPED + 1))
		continue
	fi

	if $CHECK_MODE; then
		echo -e "${RED}MISSING disclaimer: ${file}${NC}"
		MISSING=$((MISSING + 1))
		continue
	fi

	# Inject the disclaimer at the end of the file.
	# Preserve a blank line separator if the file doesn't end with one.
	if [[ -n "$(tail -c1 "$file" 2>/dev/null)" ]]; then
		printf '\n' >>"$file"
	fi
	printf '%s\n' "$DISCLAIMER" >>"$file"
	INJECTED=$((INJECTED + 1))
	echo "Injected: $file"
done < <(
	git ls-files --cached --others --exclude-standard 2>/dev/null |
		grep -E '\.md$' |
		grep -v -E '^CHANGELOG(-V11-ERA)?\.md$' |
		while IFS= read -r line; do
			printf '%s\0' "${REPO_ROOT}/${line}"
		done
)

if $CHECK_MODE; then
	if [[ "$MISSING" -eq 0 ]]; then
		echo -e "${GREEN}OK: $CHECKED .md files checked, all have the disclaimer${NC}"
		exit 0
	else
		echo -e "${RED}FAIL: $MISSING of $CHECKED .md files missing the disclaimer${NC}"
		echo "Run: bash scripts/inject-disclaimer.sh"
		exit 1
	fi
else
	echo ""
	echo -e "${GREEN}Injected: ${INJECTED}  Skipped (already had it): ${SKIPPED}  Total checked: ${CHECKED}${NC}"
	exit 0
fi
