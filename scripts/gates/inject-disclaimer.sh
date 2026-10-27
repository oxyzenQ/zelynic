#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# ZELYNIC DISCLAIMER INJECTOR (night-dragon-maintenance-3: the
# placement law, the sibling's mature shape)
#
# Guarantees the "documentation disclaimer" note sits at the BOTTOM
# of every living git-tracked *.md file in the repo - the last
# content block, never mid-file and never under a header. The
# disclaimer warns readers that docs may contain stale data,
# hardcoded counts, or outdated references, because maintainers
# update source code but may forget to sync every doc. Source code
# is the single source of truth - cross-check before relying on any
# specific number, file path, or symbol name.
#
# The injector this port replaces read MARKER PRESENCE as the done
# verdict, so a block hand-pasted mid-file (or left behind when a
# footer was appended after it) stayed there forever - the exact
# defect the owner flagged (docs/PERFORMANCE.md and an audit record
# carried the block hundreds of lines above EOF; README.md carried
# it above the built-with-curiosity footer). This port reads
# PLACEMENT as the verdict: any disclaimer block found anywhere
# other than the bottom is stripped from its position and
# re-appended as the file's final block, so one run normalizes every
# file and a second run changes no bytes.
#
# Placement law:
#   - the marker line is `<!-- ZELYNIC-DISCLAIMER -->`, followed by
#     the single HTML comment that closes on the next `-->` line;
#   - between the closing `-->` and EOF nothing but blank lines may
#     remain;
#   - one blank line separates the block from the body above it.
#
# Excluded (the frozen-record class the gate must not demand edits
# in): CHANGELOG.md and the CHANGELOG-V*-ERA.md family - the frozen
# release ledgers - and everything under docs/archive/ - the frozen
# era records. The root-era regex arms stay as the old-checkout
# shield (the era files moved into docs/archive/ long ago).
#
# Usage:
#   bash scripts/gates/inject-disclaimer.sh          # normalize (inject/relocate)
#   bash scripts/gates/inject-disclaimer.sh --check  # verify placement only
#
# Exit codes:
#   0 = every living .md carries the bottom block (or was normalized)
#   1 = --check mode found at least one file missing or misplaced

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECK_MODE=false

if [[ "${1:-}" == "--check" ]]; then
	CHECK_MODE=true
elif [[ $# -gt 0 ]]; then
	echo "usage: bash scripts/gates/inject-disclaimer.sh [--check]" >&2
	exit 2
fi

# The house marker - the marker line AND the block's first line.
MARKER="<!-- ZELYNIC-DISCLAIMER -->"

# The canonical block. The leading separator blank line is added at
# append time, so the heredoc carries the block proper only.
read -r -d '' BLOCK_TEXT <<'EOF' || true
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
mapfile -t BLOCK_LINES <<<"${BLOCK_TEXT}"

RED='\033'
GREEN='\033'
YELLOW='\033'
NC='\033'

CHECKED=0
OK_BOTTOM=0
INJECTED=0
RELOCATED=0
NOT_BOTTOM=0

TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/zelynic-discl.XXXXXX")"
trap 'rm -rf "${TMPDIR}"' EXIT

# normalize <file>: strip every disclaimer block from wherever it
# sits, then append the canonical block as the file's final block.
# Emits the candidate path; the caller cmps it against the original.
normalize() {
	local file="$1"
	local -a lines=()
	mapfile -t lines <"${file}"

	local -a kept=()
	local i=0
	local n=${#lines[@]}
	while [ "${i}" -lt "${n}" ]; do
		local line="${lines[${i}]}"
		if [ "${line}" = "${MARKER}" ]; then
			# swallow the one separator blank above the block
			local top=$((${#kept[@]} - 1))
			if [ "${top}" -ge 0 ] && [ -z "${kept[${top}]}" ]; then
				kept=("${kept[@]:0:${top}}")
			fi
			# skip the block proper: to the closing --> line
			local j=$((i + 1))
			while [ "${j}" -lt "${n}" ] && [ "${lines[${j}]}" != "-->" ]; do
				j=$((j + 1))
			done
			i=$((j + 1))
			continue
		fi
		kept+=("${line}")
		i=$((i + 1))
	done

	# strip the trailing blank runs the block left behind
	local last=$((${#kept[@]} - 1))
	while [ "${last}" -ge 0 ] && [ -z "${kept[${last}]}" ]; do
		last=$((last - 1))
	done
	kept=("${kept[@]:0:$((last + 1))}")

	local -a out=()
	if [ "${#kept[@]}" -gt 0 ]; then
		out=("${kept[@]}" "")
	fi
	out=("${out[@]}" "${BLOCK_LINES[@]}")

	local candidate="${TMPDIR}/normalized.md"
	printf '%s\n' "${out[@]}" >"${candidate}"
	printf '%s' "${candidate}"
}

process_file() {
	local rel="$1"
	local file="${REPO_ROOT}/${rel}"
	CHECKED=$((CHECKED + 1))

	local had_house=0
	if grep -Fq -- "${MARKER}" "${file}"; then
		had_house=1
	fi

	local candidate
	candidate="$(normalize "${file}")"
	local changed=1
	if cmp -s "${candidate}" "${file}"; then
		changed=0
	fi

	if [ "${CHECK_MODE}" = true ]; then
		if [ "${changed}" -eq 0 ]; then
			OK_BOTTOM=$((OK_BOTTOM + 1))
		elif [ "${had_house}" -eq 1 ]; then
			echo -e "${RED}MISPLACED block (not the bottom block): ${rel}${NC}"
			NOT_BOTTOM=$((NOT_BOTTOM + 1))
		else
			echo -e "${RED}MISSING disclaimer: ${rel}${NC}"
			NOT_BOTTOM=$((NOT_BOTTOM + 1))
		fi
		return 0
	fi

	if [ "${changed}" -eq 0 ]; then
		OK_BOTTOM=$((OK_BOTTOM + 1))
		return 0
	fi
	cp "${candidate}" "${file}"
	if [ "${had_house}" -eq 1 ]; then
		echo "Relocated: ${rel} (block moved to the bottom)"
		RELOCATED=$((RELOCATED + 1))
	else
		echo "Injected: ${rel}"
		INJECTED=$((INJECTED + 1))
	fi
}

# Every tracked OR untracked-but-present .md (git ls-files
# --cached --others --exclude-standard respects .gitignore, so a
# freshly written .md fails the check BEFORE it can be committed).
# The filter is awk (a zero-match filter is not a failed pipeline
# under pipefail); the NUL shim is bash printf - awk cannot emit
# NUL bytes on mawk (the Ubuntu default), and read -d '' starved on
# a NUL-less stream (the sibling's bash-printf shim is
# load-bearing, kept verbatim).
while IFS= read -r -d '' rel; do
	process_file "${rel}"
done < <(
	cd "${REPO_ROOT}" &&
		git ls-files --cached --others --exclude-standard 2>/dev/null |
		awk '/\.md$/ && $0 !~ /^CHANGELOG\.md$/ && $0 !~ /CHANGELOG-V[0-9]+-ERA\.md$/ && $0 !~ /^docs\/archive\//' |
			while IFS= read -r rel; do
				printf '%s\0' "${rel}"
			done
)

if [ "${CHECK_MODE}" = true ]; then
	if [ "${NOT_BOTTOM}" -eq 0 ]; then
		echo -e "${GREEN}OK: ${CHECKED} .md files checked, every disclaimer sits at the bottom${NC}"
		exit 0
	fi
	echo -e "${RED}FAIL: ${NOT_BOTTOM} of ${CHECKED} .md files missing or misplaced${NC}"
	echo "Run: bash scripts/gates/inject-disclaimer.sh"
	exit 1
fi

echo ""
echo -e "${GREEN}Injected: ${INJECTED}  Relocated: ${RELOCATED}  Already-at-bottom: ${OK_BOTTOM}  Total: ${CHECKED}${NC}"
if [ "$((INJECTED + RELOCATED))" -gt 0 ]; then
	echo -e "${YELLOW}Review the git diff before staging.${NC}"
fi
exit 0
