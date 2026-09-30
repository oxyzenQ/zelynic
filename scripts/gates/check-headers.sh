#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC SPDX HEADER CHECK
#
# Scans all core/code/config/script/doc files for the required license
# header. Fails if any included file is missing the header or carries
# the wrong license identifier.
#
# Required (both lines, within the first 10 lines of the file):
#   Copyright (C) 2026 rezky_nightky
#   SPDX-License-Identifier: GPL-3.0-only
# Rejected: any other SPDX-License-Identifier value (project is
# GPL-3.0-only licensed).
#
# dinner-28: every *.sh ADDITIONALLY requires the OS line within the
# first 10 lines — '# OS: Linux only' — the owner's rule, enforced as
# a failure (never a warning): a .sh without it never reaches CI. The
# pre-dinner-28 'PLATFORM: UNIX-only' wording is gone; the OS line is
# the one convention.
#
# Included file types: *.rs, *.c, *.h, *.py, *.sh, *.toml, *.yml, *.yaml, *.md
# Scope: git-tracked files PLUS untracked-but-present files (respecting
#   .gitignore), so a new source file missing its header fails the check
#   BEFORE it can be committed (pre-commit proxy parity).
# Excluded: CHANGELOG.md — a frozen historical record, never
#   rewritten (the same exclusion policy as every other gate). The
#   former CHANGELOG-V11-ERA.md root duplicate was removed in
#   NIGHT-dinner-19 (its frozen content lives in git history);
#   the regex below keeps the era-file arm so an old checkout
#   running this gate still excludes it.
#
# Usage: bash scripts/gates/check-headers.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Colors
RED='\033[0;31m'
NC='\033[0m'

MISSING=0
WRONG=0
CHECKED=0

EXPECTED_COPYRIGHT="Copyright (C) 2026 rezky_nightky"
EXPECTED_LICENSE_NAME="GPL-3.0-only"

while IFS= read -r -d '' file; do
	CHECKED=$((CHECKED + 1))

	# Check if the file has any SPDX-License-Identifier at all
	if ! head -10 "$file" | grep -q "SPDX-License-Identifier"; then
		echo -e "${RED}MISSING SPDX header: ${file}${NC}"
		MISSING=$((MISSING + 1))
		continue
	fi

	# Check for a non-GPL license identifier
	if ! head -10 "$file" | grep -q "SPDX-License-Identifier: ${EXPECTED_LICENSE_NAME}"; then
		echo -e "${RED}WRONG LICENSE (expected ${EXPECTED_LICENSE_NAME}): ${file}${NC}"
		WRONG=$((WRONG + 1))
		continue
	fi

	# Check for the copyright line
	if ! head -10 "$file" | grep -q "${EXPECTED_COPYRIGHT}"; then
		echo -e "${RED}MISSING copyright line: ${file}${NC}"
		MISSING=$((MISSING + 1))
	fi

	# dinner-28: the OS line is a *.sh-only requirement — the
	# owner's header rule. A .sh without it fails here, never a
	# warning (all CI warnings are failures; none are ignored).
	if [[ "$file" == *.sh ]]; then
		if ! head -10 "$file" | grep -q '^# OS: Linux only'; then
			echo -e "${RED}MISSING OS line (os linux only): ${file}${NC}"
			MISSING=$((MISSING + 1))
		fi
	fi
done < <(
	# Only check git-tracked files plus untracked-but-present files —
	# the pre-commit proxy parity scan (a new file fails BEFORE the
	# commit, not after CI picks it up).
	git ls-files --cached --others --exclude-standard 2>/dev/null |
		grep -E '\.(rs|c|h|py|sh|toml|yml|yaml|md)$' |
		grep -v -E '^CHANGELOG(-V11-ERA)?\.md$' |
		while IFS= read -r line; do
			printf '%s\0' "${REPO_ROOT}/${line}"
		done
)

TOTAL_FAIL=$((MISSING + WRONG))

if [[ "$TOTAL_FAIL" -eq 0 ]]; then
	echo "OK: $CHECKED files checked, all carry the license header"
	exit 0
else
	echo -e "${RED}FAIL: $MISSING missing, $WRONG wrong license (of $CHECKED checked)${NC}"
	exit 1
fi
