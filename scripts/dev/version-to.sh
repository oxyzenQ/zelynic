#!/bin/bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
# =============================================================================
# ZELYNIC VERSION MANAGER
# =============================================================================
# Centralized version management — update ALL files from a single command.
#
# Usage:
#   ./scripts/dev/version-to.sh v11.1.0        # Update to v11.1.0
#   ./scripts/dev/version-to.sh v11.0.1 --commit # Update and auto-commit
#   ./scripts/dev/version-to.sh v11.0.1 --force  # Record a deliberate
#                                                # release-line reset
#   ./scripts/dev/version-to.sh                # Show current version
#
# Single source of truth: Cargo.toml
# Files updated: EVERY tracked Cargo.toml that belongs to the zelynic
# crate family, plus every tracked Cargo.lock that carries one of
# those crates' [[package]] entries (NIGHT-bump-2: the bump set is
# DETECTED, never listed — git enumerates the manifests, the [package]
# blocks are parsed, and the graph falls out. The pre-autodetect
# script carried the pairs it knew about as literals, and the owner's
# v80.5.0-dragon.1 run proved the disease: zelynic-proofs rode 0.1.0
# and zelynic-fuzz rode 0.0.0 beside a dragon.1 root — the exact
# provenance-hole shape NIGHT-improve-67 closed for the ebpf crate,
# reopened by every workspace the literal list never learned about.
# The law now: the root crate rides by definition; every OTHER crate
# named zelynic-* rides too, and a drifted one is healed, not
# skipped; a manifest outside the family is reported at its own
# version — never silently swept, never silently lost. The lock pass
# rewrites every matching [[package]] entry in every tracked lock
# (a future path dependency's cross-entry heals the same way), and
# every rewrite is re-read and verified — a write this script cannot
# verify is a write it does not keep. A fifth workspace joins the
# bump with zero edits here.)
# NIGHT-improve-70: the version change touches the ebpf/ tree, so the
# prebuilt lane's tree pin notices it — when THIS script's own rewrite
# stales the lane, the refresh runs in the same invocation
# (./scripts/release/refresh-prebuilt.sh through the repo's validated
# build pipeline — one command leaves a committable tree; a refresh
# that cannot complete fails closed with the bootstrap recipe).
# NIGHT-bump-2 (the reconcile law): "already at" no longer exits when
# the match is partial — the early exit fires only when EVERY detected
# surface carries the target. A re-run at an already-bumped root
# still reaches the surfaces the old literal list never knew about
# (the owner's exact recovery path), and the git-add recipe at the
# bottom is DERIVED from what the run actually touched — the old
# literal recipe was itself a stale literal: it named README.md on
# runs that never rewrote it and never named the workspaces it did
# not know about.
# A lane already stale BEFORE the bump keeps the honest manual
# verdict: this script auto-refreshes only the churn it created,
# never a WIP it found. README.md is probed
# for a version surface and reported honestly either way —
# NIGHT-hunt-32: the README lane once printed an unconditional
# "OK README.md -> vN" while the README carried no badge, no release
# URL, and no Version line for any pattern to match —
# a claimed rewrite that never happened)
# CHANGELOG.md earns its release line (NIGHT-improve-76: a bump is a
# release event — the ledger records it the same way the Cargo files
# do: the owner's shape, a "## [Released]" heading with the bare
# version line under it, newest first, pre-release and stable alike,
# above "## [Unreleased]". Probed honestly, the README lane's rule:
# a missing file, a missing anchor, or a non-standard Released shape
# warns and writes nothing — never claim a write that did not happen)
# NIGHT-bump-1 (the fatal class the owner hit on the v80.0.x line:
# the bump's version line landed BELOW the unreleased section because
# nothing ever verified where a write landed): the ledger work now
# runs as a PRE-FLIGHT before any file is mutated, under four laws —
#   1. Shape law: exactly one "## [Released]" and one
#      "## [Unreleased]" heading, Released FIRST, the owner's pure
#      shape (blank spacers + bare version lines) inside Released.
#      The two repairable shapes heal in place, loudly: a Released
#      block sitting below Unreleased relocates above it; a version
#      line stranded outside Released is deleted and re-spliced.
#      Foreign content inside Released refuses — a ledger this script
#      did not create is not one it rewrites.
#   2. Semver law: a bump that is NOT a step up from the ledger's top
#      refuses (the stale-tree downgrade) unless --force records the
#      deliberate release-line reset, named as such in the output.
#   3. Verification law: after any splice the file is re-parsed and
#      the version line must sit inside "## [Released]" exactly once
#      with Released above Unreleased — any other outcome restores
#      the backup and fails the run. A write this script cannot
#      verify is a write it does not keep.
#   4. History law: after a verified write the release's git history
#      prints — the commits since the previous "release: vPREV"
#      commit — so the ledger line's association with the work it
#      releases is verifiable in the same breath, not by a manual
#      git archaeology session afterwards.
# Files auto-derived: scripts/build.sh (reads from Cargo.toml), binary (env!("CARGO_PKG_VERSION"))
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${SCRIPT_DIR}"

# night-cafe-1: the tiers come from the shared brand palette — the
# bash twin of src/output/color.rs — so this surface renders the exact
# values the CLI renders (mono when piped; the legacy RED/GREEN/
# YELLOW/NC names map onto the tiers inside the palette).
# shellcheck source=scripts/lib/ux_palette.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/ux_palette.sh"

# The [package] block parsers (NIGHT-bump-2): the version surface is
# located by structure, not by file order — the first name/version
# pair inside [package] is the crate's own, whatever the file's
# layout. An empty result means the manifest carries no versioned
# package (a virtual workspace root — no surface, no opinion).
manifest_version_of() {
	awk '
		/^\[package\][[:space:]]*$/ { pkg=1; next }
		/^\[/ { pkg=0 }
		pkg && /^version = "[^"]+"/ {
			sub(/^version = "/, ""); sub(/".*$/, ""); print; exit
		}
	' "$1"
}

manifest_name_of() {
	awk '
		/^\[package\][[:space:]]*$/ { pkg=1; next }
		/^\[/ { pkg=0 }
		pkg && /^name = "[^"]+"/ {
			sub(/^name = "/, ""); sub(/".*$/, ""); print; exit
		}
	' "$1"
}

# The crate graph, detected every run (NIGHT-bump-2): one
# <path><TAB><name><TAB><version> row per versioned tracked manifest.
# git ls-files enumerates — untracked trees, target/ output and
# vendored junk can never enter the walk.
manifest_rows() {
	local f
	while IFS= read -r f; do
		printf '%s\t%s\t%s\n' "${f}" "$(manifest_name_of "${f}")" "$(manifest_version_of "${f}")"
	done < <(git ls-files | grep -E '(^|/)Cargo\.toml$' | sort)
}

# Read current version from Cargo.toml (the [package] block — the
# source of truth).
current_version() {
	manifest_version_of Cargo.toml
}

# The bump set, decided once per run (NIGHT-bump-2). Fills:
#   BUMP_PATHS[i] / BUMP_NAMES[i] / BUMP_OLDS[i] — the surfaces that
#   ride the root version: the root crate itself by definition, and
#   every other crate whose name starts with "zelynic" (the
#   provenance law NIGHT-improve-67 put on the ebpf crate, now
#   repo-wide; a drifted one is healed, not skipped);
#   SKIP_REPORTS[@] — the honest report lines for manifests left at
#   their own version (a crate that is not a zelynic crate is never
#   silently swept, and never silently lost).
BUMP_PATHS=()
BUMP_NAMES=()
BUMP_OLDS=()
SKIP_REPORTS=()
build_bump_sets() {
	local path name ver
	while IFS=$'\t' read -r path name ver; do
		if [ "${path}" = "Cargo.toml" ] || [[ "${name}" == zelynic* ]]; then
			BUMP_PATHS+=("${path}")
			BUMP_NAMES+=("${name}")
			BUMP_OLDS+=("${ver}")
		else
			SKIP_REPORTS+=("$(printf '%-21s' "${path}") ${name} ${ver} — left at its own version (not a zelynic-* crate)")
		fi
	done < <(manifest_rows)
	if [ "${#BUMP_PATHS[@]}" -eq 0 ]; then
		echo -e "${RED}FAIL:${NC} no versioned Cargo.toml found in the tracked tree — the bump has no anchor." >&2
		exit 1
	fi
}

# One manifest lane: rewrite the [package] version inside its own
# section (dependency version lines live in other sections and never
# move), verify the WRITE TARGET before it lands (the ledger's
# verification law, generalized: a write this script cannot verify
# is a write it does not keep), and only then commit the file.
# Returns 0 when the file changed, 1 when it already carried the
# target.
bump_manifest() {
	local path="$1" name="$2" old="$3" label tmp now
	label="$(printf '%-21s' "${path}")"
	if [ "${old}" = "${NEW_VERSION}" ]; then
		echo -e "  ${YELLOW}!${NC} ${label} ${name} already at v${NEW_VERSION}"
		return 1
	fi
	tmp="$(mktemp)"
	awk -v new="${NEW_VERSION}" '
		/^\[package\][[:space:]]*$/ { pkg=1; print; next }
		/^\[/ { pkg=0; print; next }
		pkg && !done && /^version = "[^"]*"/ { sub(/"[^"]*"/, "\"" new "\""); done=1 }
		{ print }
	' "${path}" >"${tmp}"
	now="$(manifest_version_of "${tmp}")"
	if [ "${now}" != "${NEW_VERSION}" ]; then
		rm -f "${tmp}"
		echo -e "${RED}FAIL:${NC} ${label} the rewrite did not verify (expected ${NEW_VERSION}, read ${now:-nothing}) — the file was left as found, nothing kept." >&2
		exit 1
	fi
	mv "${tmp}" "${path}"
	echo -e "  ${GREEN}OK${NC} ${label} ${name} ${old} → ${NEW_VERSION}"
	return 0
}

# The name<TAB>version rows a Cargo.lock carries for an ERE of
# package names (the lock's own top-level version line sits outside
# any [[package]] block and is never touched).
lock_entry_versions() {
	awk -v re="^(${1})$" '
		/^\[\[package\]\]/ { inb=1; hit=0; next }
		inb && /^name = "[^"]*"/ {
			sub(/^name = "/, ""); sub(/".*$/, "")
			name=$0
			hit=(name ~ re) ? 1 : 0
			next
		}
		inb && hit && /^version = "[^"]*"/ {
			sub(/^version = "/, ""); sub(/".*$/, "")
			print name "\t" $0
		}
	' "$2"
}

# One lock lane (NIGHT-bump-2): rewrite EVERY [[package]] entry whose
# name rides the bump set — the crate's own workspace entry today, a
# path dependency's cross-entry the day one appears — verify the
# WRITE TARGET first (the entry set must survive and every entry must
# read the target), and only then commit the file. Returns 0 when the
# lock changed, 1 when it did not.
bump_lock() {
	local lockf="$1" names_regex="$2" label tmp before after moved already
	label="$(printf '%-21s' "${lockf}")"
	before="$(lock_entry_versions "${names_regex}" "${lockf}")"
	if [ -z "${before}" ]; then
		echo -e "  ${YELLOW}!${NC} ${label} no [[package]] entry rides the bump set here — nothing to rewrite"
		return 1
	fi
	tmp="$(mktemp)"
	awk -v re="^(${names_regex})$" -v new="${NEW_VERSION}" '
		/^\[\[package\]\]/ { inb=1; hit=0; print; next }
		inb && /^name = "[^"]*"/ {
			print
			sub(/^name = "/, ""); sub(/".*$/, "")
			hit=($0 ~ re) ? 1 : 0
			next
		}
		inb && hit && /^version = "[^"]*"/ {
			sub(/"[^"]*"/, "\"" new "\"")
			print; next
		}
		{ print }
	' "${lockf}" >"${tmp}"
	after="$(lock_entry_versions "${names_regex}" "${tmp}")"
	if [ "$(sort <<<"${before}" | cut -f1)" != "$(sort <<<"${after}" | cut -f1)" ] \
		|| [ -n "$(awk -F'\t' -v want="${NEW_VERSION}" '$2 != want' <<<"${after}")" ]; then
		rm -f "${tmp}"
		echo -e "${RED}FAIL:${NC} ${label} the lock rewrite did not verify — the file was left as found, nothing kept." >&2
		exit 1
	fi
	mv "${tmp}" "${lockf}"
	moved="$(awk -F'\t' 'NR==FNR { b[$1]=$2; next } { if ($1 in b && b[$1] != $2) printf "%s ", $1 }' \
		<(printf '%s\n' "${before}") <(printf '%s\n' "${after}"))"
	already="$(awk -F'\t' 'NR==FNR { b[$1]=$2; next } { if ($1 in b && b[$1] == $2) printf "%s ", $1 }' \
		<(printf '%s\n' "${before}") <(printf '%s\n' "${after}"))"
	if [ -n "${moved}" ]; then
		echo -e "  ${GREEN}OK${NC} ${label} ${moved% } → ${NEW_VERSION}"
		return 0
	fi
	if [ -n "${already}" ]; then
		echo -e "  ${YELLOW}!${NC} ${label} ${already% } already at v${NEW_VERSION}"
	fi
	return 1
}

# Validate semver format
validate_version() {
	local ver="$1"
	if ! echo "${ver}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
		echo -e "${RED}Error: Invalid version '${ver}'. Expected format: X.Y.Z or X.Y.Z-label${NC}" >&2
		exit 1
	fi
}

# The ## [Released] section's bare version lines, in file order
# (NIGHT-bump-1: the ledger is parsed, never assumed).
ledger_versions() {
	awk '/^## \[Released\]$/{f=1;next} /^## \[Unreleased\]$/{f=0} f&&/^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$/' CHANGELOG.md
}

# ver_lt A B — true when A sorts before B in version order (A < B).
# sort -V is the one comparator: pre-release labels, patch and minor
# resets all order exactly as semver says.
ver_lt() {
	local first
	first="$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)"
	[ "${first}" = "$1" ] && [ "$1" != "$2" ]
}

# Relocate a ## [Released] block that sits BELOW ## [Unreleased]
# (NIGHT-bump-1 law 1, the shape the owner hit on the v80.0.x line):
# only the owner's pure shape relocates — heading, blank spacers,
# bare version lines, nothing else. The block moves above Unreleased
# and the result is re-verified; anything less honest refuses.
ledger_relocate_released_block() {
	local rline="$1" block bad tmp rest
	block="$(sed -n "${rline},\$p" CHANGELOG.md)"
	bad="$(printf '%s\n' "${block}" | grep -vE '^(## \[Released\]|v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?)$' | head -3 || true)"
	if [ -n "${bad}" ]; then
		echo -e "${RED}FAIL:${NC} CHANGELOG.md      → ## [Released] sits below ## [Unreleased] AND carries foreign content:" >&2
		printf '%s\n' "${bad}" >&2
		echo -e "  a ledger this script did not create is not one it rewrites — repair the shape by hand, then re-run." >&2
		exit 1
	fi
	rest="$(sed -n "1,$((rline - 1))p" CHANGELOG.md)"
	tmp="$(mktemp)"
	awk -v blk="${block}" '
		/^## \[Unreleased\]$/ && !done {
			printf "%s\n\n", blk
			done = 1
		}
		{ print }
	' <<<"${rest}" >"${tmp}"
	mv "${tmp}" CHANGELOG.md
	local rnew uline
	rnew="$(grep -n '^## \[Released\]$' CHANGELOG.md | cut -d: -f1)"
	uline="$(grep -n '^## \[Unreleased\]$' CHANGELOG.md | cut -d: -f1)"
	if [ "${rnew}" -gt "${uline}" ]; then
		echo -e "${RED}FAIL:${NC} CHANGELOG.md      → the relocation did not verify (## [Released] still below ## [Unreleased]) — the file was left as found." >&2
		exit 1
	fi
	LEDGER_MUTATED=true
	echo -e "  ${GREEN}OK${NC} CHANGELOG.md        → ## [Released] relocated above ## [Unreleased] (the owner shape restored)"
}

# The release's git history (NIGHT-bump-1 law 4): the commits since
# the previous release commit, printed at bump time — the association
# between the ledger line and the work it releases is verifiable in
# the same breath, not by manual git archaeology afterwards.
git_release_history() {
	local ver="$1" prev prev_esc rel_commit count
	prev="$(ledger_versions | sed -n '2p')"
	if [ -z "${prev}" ]; then
		echo -e "  ${YELLOW}!${NC} release history     → no previous release line under ## [Released] — nothing to diff against"
		return 0
	fi
	prev_esc="${prev//./\\.}"
	rel_commit="$(git log -E --grep "^release: ${prev_esc}( |$)" --format=%H -n 1 2>/dev/null || true)"
	if [ -z "${rel_commit}" ]; then
		echo -e "  ${YELLOW}!${NC} release history     → no 'release: ${prev}' commit found in git history — showing the last 10 commits instead:"
		git log --oneline -10 | sed 's/^/    /' || true
		return 0
	fi
	count="$(git log --oneline "${rel_commit}..HEAD" | wc -l)"
	echo -e "  ${GREEN}OK${NC} release history     → ${count} commit(s) since ${prev} (${rel_commit:0:8}):"
	git log --oneline "${rel_commit}..HEAD" | head -15 | sed 's/^/    /' || true
	if [ "${count}" -gt 15 ]; then
		echo -e "    ... and $((count - 15)) more"
	fi
	return 0
}

# The whole ledger work, run as a PRE-FLIGHT before any file is
# mutated (NIGHT-bump-1): shape checks, the two healable repairs, the
# semver gate, the verified splice, and the history summary. Sets
# LEDGER_DONE=true when the version line is already properly recorded,
# so re-runs stay idempotent and the early-exit path still heals.
ledger_preflight() {
	local ver="v$1"
	LEDGER_DONE=false
	if [ ! -f CHANGELOG.md ]; then
		echo -e "  ${YELLOW}!${NC} CHANGELOG.md        → file absent, nothing to write"
		return 0
	fi

	# Law 1a: exactly one of each heading. More than one is a shape this
	# script cannot parse and will not edit.
	local rcount ucount
	rcount="$(grep -c '^## \[Released\]$' CHANGELOG.md || true)"
	ucount="$(grep -c '^## \[Unreleased\]$' CHANGELOG.md || true)"
	if [ "${rcount}" -gt 1 ] || [ "${ucount}" -gt 1 ]; then
		echo -e "${RED}FAIL:${NC} CHANGELOG.md      → ${rcount} '## [Released]' heading(s) and ${ucount} '## [Unreleased]' heading(s); expected exactly one of each. Repair the headings by hand, then re-run." >&2
		exit 1
	fi

	# Law 1b: Released must PRECEDE Unreleased. The pure-block shape
	# below-Unreleased relocates; anything richer refuses.
	if [ "${rcount}" -eq 1 ] && [ "${ucount}" -eq 1 ]; then
		local rline uline
		rline="$(grep -n '^## \[Released\]$' CHANGELOG.md | cut -d: -f1)"
		uline="$(grep -n '^## \[Unreleased\]$' CHANGELOG.md | cut -d: -f1)"
		if [ "${rline}" -gt "${uline}" ]; then
			ledger_relocate_released_block "${rline}"
		fi
	fi

	# Law 1c: the owner's pure shape inside Released — blank spacers and
	# bare version lines, nothing else.
	if [ "${rcount}" -eq 1 ]; then
		local junk
		junk="$(awk '/^## \[Released\]$/{f=1;next} /^## \[Unreleased\]$/{f=0} f&&!/^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$/&&!/^$/' CHANGELOG.md | head -3 || true)"
		if [ -n "${junk}" ]; then
			echo -e "${RED}FAIL:${NC} CHANGELOG.md      → foreign content inside ## [Released] (the owner's shape is blank spacers + bare version lines):" >&2
			printf '%s\n' "${junk}" >&2
			echo -e "  a ledger this script did not create is not one it rewrites — repair the shape by hand, then re-run." >&2
			exit 1
		fi
		# The spacer law: one blank line under the heading, the shape
		# this script's own splice relies on. Its absence is hand-edit
		# drift — refused, never guessed around.
		if [ -n "$(sed -n '/^## \[Released\]$/{n;p;}' CHANGELOG.md)" ]; then
			echo -e "${RED}FAIL:${NC} CHANGELOG.md      → the blank spacer under ## [Released] is gone (the owner shape is heading, blank line, version lines). Restore the blank line, then re-run." >&2
			exit 1
		fi
	fi

	# The version line never repeats — and a line stranded OUTSIDE
	# Released (the owner's broken state) heals in place: delete the
	# strays now, the splice below writes the line where it belongs.
	local total inside
	total="$(grep -cxF "${ver}" CHANGELOG.md || true)"
	inside="$(sed -n '/^## \[Released\]$/,/^## \[Unreleased\]$/p' CHANGELOG.md | grep -cxF "${ver}" || true)"
	if [ "${total}" -gt 0 ] && [ "${inside}" -eq "${total}" ]; then
		LEDGER_DONE=true
		echo -e "  ${GREEN}OK${NC} CHANGELOG.md        → ${ver} already recorded in ## [Released]"
		return 0
	fi
	if [ "${total}" -gt 0 ]; then
		local tmp
		tmp="$(mktemp)"
		grep -vxF "${ver}" CHANGELOG.md >"${tmp}"
		mv "${tmp}" CHANGELOG.md
		LEDGER_MUTATED=true
		echo -e "  ${YELLOW}!${NC} CHANGELOG.md        → ${ver} recorded OUTSIDE ## [Released] (${total} line(s), ${inside} inside) — deleted; the verified splice below records it properly"
	fi

	# Law 2: the semver gate — a bump below the ledger's top is the
	# stale-tree downgrade; --force records a deliberate line reset.
	if [ "${LEDGER_DONE}" != true ]; then
		local top
		top="$(ledger_versions | head -1)"
		if [ -n "${top}" ] && ver_lt "${ver}" "${top}" && [ "${FORCE}" != true ]; then
			echo -e "${RED}FAIL:${NC} ${ver} is not a step up from the ledger's top (${top}) — a stale-tree downgrade, refused. A deliberate release-line reset is recorded with: ./scripts/dev/version-to.sh ${ver#v} --force" >&2
			exit 1
		fi
		if [ -n "${top}" ] && ver_lt "${ver}" "${top}" && [ "${FORCE}" = true ]; then
			echo -e "  ${YELLOW}!${NC} CHANGELOG.md        → release-line reset recorded (--force): ${ver} takes the ledger's top position while sorting below ${top}"
		fi
	fi

	# Law 3 (the splice): write, then VERIFY — the version line must sit
	# inside ## [Released] exactly once with Released above Unreleased;
	# any other outcome restores the backup and fails the run. A write
	# this script cannot verify is a write it does not keep.
	local tmp backup
	tmp="$(mktemp)"
	backup="$(mktemp)"
	cp CHANGELOG.md "${backup}"
	if [ "${rcount}" -eq 1 ]; then
		# The section exists with its verified spacer — splice the new
		# version in under it, above the current top line.
		awk -v ver="${ver}" '
			/^## \[Released\]$/ && !done {
				print
				getline spacer
				print spacer
				print ver
				done = 1
				next
			}
			{ print }
		' CHANGELOG.md >"${tmp}"
		mv "${tmp}" CHANGELOG.md
	elif [ "${ucount}" -eq 1 ]; then
		# No section yet — create it above "## [Unreleased]" (the
		# unreleased work keeps its own section below the ledger).
		awk -v ver="${ver}" '
			/^## \[Unreleased\]$/ && !done {
				print "## [Released]"
				print ""
				print ver
				print ""
				done = 1
			}
			{ print }
		' CHANGELOG.md >"${tmp}"
		mv "${tmp}" CHANGELOG.md
	else
		rm -f "${tmp}" "${backup}"
		echo -e "  ${YELLOW}!${NC} CHANGELOG.md        → no ## [Unreleased] anchor found — nothing to write"
		return 0
	fi
	LEDGER_MUTATED=true
	total="$(grep -cxF "${ver}" CHANGELOG.md || true)"
	inside="$(sed -n '/^## \[Released\]$/,/^## \[Unreleased\]$/p' CHANGELOG.md | grep -cxF "${ver}" || true)"
	local order_ok=true
	if [ "$(grep -c '^## \[Released\]$' CHANGELOG.md || true)" -eq 1 ] && [ "$(grep -c '^## \[Unreleased\]$' CHANGELOG.md || true)" -eq 1 ]; then
		local rnow unow
		rnow="$(grep -n '^## \[Released\]$' CHANGELOG.md | cut -d: -f1)"
		unow="$(grep -n '^## \[Unreleased\]$' CHANGELOG.md | cut -d: -f1)"
		[ "${rnow}" -lt "${unow}" ] || order_ok=false
	else
		order_ok=false
	fi
	if [ "${total}" -ne 1 ] || [ "${inside}" -ne 1 ] || [ "${order_ok}" != true ]; then
		mv "${backup}" CHANGELOG.md
		echo -e "${RED}FAIL:${NC} CHANGELOG.md      → the ledger write did not verify (the version line must sit inside ## [Released] exactly once, with Released above Unreleased) — the file was restored, nothing kept." >&2
		exit 1
	fi
	rm -f "${tmp}" "${backup}"
	if [ "${rcount}" -eq 1 ]; then
		echo -e "  ${GREEN}OK${NC} CHANGELOG.md        → ${ver} (## [Released], verified in place)"
	else
		echo -e "  ${GREEN}OK${NC} CHANGELOG.md        → ${ver} (section created above ## [Unreleased], verified in place)"
	fi

	# Law 4: the release's git history, printed while it is being made.
	git_release_history "${ver}"
	return 0
}

# Show current version and exit
if [ $# -eq 0 ]; then
	echo -e "Current version: ${GREEN}v$(current_version)${NC}"
	echo ""
	echo "Usage: ./scripts/dev/version-to.sh v<VERSION> [--commit] [--force]"
	echo ""
	echo "Detected version surfaces (NIGHT-bump-2: the crate graph, not a literal list):"
	build_bump_sets
	for i in "${!BUMP_PATHS[@]}"; do
		echo "  ${BUMP_PATHS[$i]}  ${BUMP_NAMES[$i]}  v${BUMP_OLDS[$i]}"
	done
	exit 0
fi

NEW_VERSION="${1#v}"
shift

COMMIT=false
FORCE=false
for arg in "$@"; do
	case "${arg}" in
	--commit | -c) COMMIT=true ;;
	--force | -f) FORCE=true ;;
	*)
		echo -e "${RED}Unknown option: ${arg}${NC}" >&2
		exit 1
		;;
	esac
done

validate_version "${NEW_VERSION}"

# NIGHT-bump-2: detect the crate graph BEFORE anything mutates — the
# bump set, the drift verdict and the stranger reports all come from
# this pass.
TOUCHED=()
build_bump_sets
CURRENT=$(current_version)
# The bump set as one ERE of crate names — the lock graph walks it.
names_regex="$(IFS='|'; echo "${BUMP_NAMES[*]}")"

# NIGHT-bump-1: the ledger pre-flight runs BEFORE the early exit and
# BEFORE any file is mutated — a re-run at an already-bumped version
# still repairs a broken ledger (the owner's v80.0.6 heal path), and
# a downgrade refusal fires before Cargo.toml moves.
LEDGER_MUTATED=false
ledger_preflight "${NEW_VERSION}"
if [ "${LEDGER_MUTATED}" = true ]; then
	TOUCHED+=("CHANGELOG.md")
fi

# The stranger report (NIGHT-bump-2): a manifest outside the family
# is visible on every run — never silently swept, never silently lost.
if [ "${#SKIP_REPORTS[@]}" -gt 0 ]; then
	echo -e "  ${YELLOW}!${NC} version surfaces outside the zelynic family (left alone, reported):"
	for line in "${SKIP_REPORTS[@]}"; do
		echo "      ${line}"
	done
	echo ""
fi

# The reconcile gate (NIGHT-bump-2): the early exit fires only when
# EVERY detected surface already carries the target — a partial
# match proceeds and the drifted surfaces heal below. A re-run at an
# already-bumped root must still reach the workspaces the old
# literal list never knew about.
ALL_AT_TARGET=true
for old in "${BUMP_OLDS[@]}"; do
	if [ "${old}" != "${NEW_VERSION}" ]; then
		ALL_AT_TARGET=false
		break
	fi
done
# The lock entries ride the same gate (NIGHT-bump-2): a lock whose
# [[package]] entry drifted below the target reopens the run even
# when every manifest already carries the version — the reconcile
# law covers the lock graph, not just the manifests.
if [ "${ALL_AT_TARGET}" = true ]; then
	while IFS= read -r lockf; do
		if [ -n "$(lock_entry_versions "${names_regex}" "${lockf}" | awk -F'\t' -v want="${NEW_VERSION}" '$2 != want')" ]; then
			ALL_AT_TARGET=false
			break
		fi
	done < <(git ls-files | grep -E '(^|/)Cargo\.lock$' | sort)
fi
if [ "${ALL_AT_TARGET}" = true ]; then
	if [ "${LEDGER_MUTATED}" = true ]; then
		echo -e "${YELLOW}Already at v${NEW_VERSION} across ${#BUMP_PATHS[@]} detected surface(s); the ledger was repaired — commit it:${NC}"
		echo "next: git add CHANGELOG.md && git commit"
	else
		echo -e "${YELLOW}Already at v${NEW_VERSION} across ${#BUMP_PATHS[@]} detected surface(s) — nothing to change.${NC}"
	fi
	exit 0
fi

echo -e "Version surfaces riding → ${GREEN}v${NEW_VERSION}${NC}"
for i in "${!BUMP_PATHS[@]}"; do
	if [ "${BUMP_OLDS[$i]}" != "${NEW_VERSION}" ]; then
		echo -e "  ${BUMP_PATHS[$i]} (${BUMP_NAMES[$i]}): ${YELLOW}v${BUMP_OLDS[$i]}${NC} → ${GREEN}v${NEW_VERSION}${NC}"
	fi
done
echo ""

# --- The manifest lanes (NIGHT-bump-2) ---
# Every detected surface rides; each rewrite is verified by reading
# the write target back before it lands. Dependency version lines
# live in their own sections and never move (those are the job of
# `cargo update`, not a version bump). The ebpf/ churn THIS run
# creates is what the prebuilt lane below answers for
# (NIGHT-improve-70) — churn found before the run keeps the honest
# manual verdict.
EBPF_CHANGED=false
for i in "${!BUMP_PATHS[@]}"; do
	if bump_manifest "${BUMP_PATHS[$i]}" "${BUMP_NAMES[$i]}" "${BUMP_OLDS[$i]}"; then
		TOUCHED+=("${BUMP_PATHS[$i]}")
		if [[ "${BUMP_PATHS[$i]}" == ebpf/* ]]; then
			EBPF_CHANGED=true
		fi
	fi
done

# --- The lock lanes (NIGHT-bump-2) ---
# Every tracked Cargo.lock, every [[package]] entry whose name rides
# the bump set: the crate's own workspace entry today, a path
# dependency's cross-entry the day one appears. Dependency versions
# (the whole rest of the lock) are the job of `cargo update`, not a
# version bump.
echo ""
while IFS= read -r lockf; do
	if bump_lock "${lockf}" "${names_regex}"; then
		TOUCHED+=("${lockf}")
	fi
done < <(git ls-files | grep -E '(^|/)Cargo\.lock$' | sort)

# --- Update README.md (probed first — NIGHT-hunt-32: the lane once ---
# --- printed an unconditional OK while the README carried no badge, ---
# --- no release URL, and no Version line for any pattern to match) ---
# The badge lane died with the badge (NIGHT-dinner-32: the owner
# dropped the static release badge from the README header — one
# less surface to keep honest on every bump). What remains rewrites
# the surfaces that carry a real version: release/download URLs,
# versioned tarball names, and Version lines.
README_HITS="$(grep -cE 'releases/download/v[0-9]|zelynic-v[0-9]+\.[0-9]+|^Version: v[0-9]' README.md 2>/dev/null || true)"
if [ "${README_HITS:-0}" -gt 0 ]; then
	sed -i -E "s|releases/download/v[0-9]+\.[0-9]+\.[0-9]+|releases/download/v${NEW_VERSION}|g" README.md
	sed -i -E "s|zelynic-v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?-x86_64|zelynic-v${NEW_VERSION}-x86_64|g" README.md
	sed -i "s|Version: v.*|Version: v${NEW_VERSION}|" README.md
	echo -e "  ${GREEN}OK${NC} README.md           → v${NEW_VERSION} (release URLs + versioned examples)"
	TOUCHED+=("README.md")
else
	echo -e "  ${YELLOW}!${NC} README.md           → no version surface found (no release URL / versioned example / Version line) — nothing to rewrite"
fi

# --- CHANGELOG.md ledger (NIGHT-bump-1) ---
# The ledger work ran as the pre-flight above: the shape was checked,
# the repairable shapes healed, the semver gate fired before any file
# moved, the splice was verified in place, and the release's git
# history printed. Nothing re-runs here — a bump whose ledger write
# could not be verified never reached this line.
echo -e "  ${GREEN}OK${NC} CHANGELOG.md        → verified pre-flight (see the ledger lines above)"

# --- scripts/build.sh reads dynamically from Cargo.toml, no update needed ---
echo -e "  ${GREEN}OK${NC} scripts/build.sh    → auto (reads from Cargo.toml)"

# --- Binary reads from Cargo.toml via env!("CARGO_PKG_VERSION"), no update needed ---
echo -e "  ${GREEN}OK${NC} Binary (zelynic)    → auto (reads from Cargo.toml)"

# --- Prebuilt-lane refresh + parity verdict (NIGHT-improve-70) ---
# The gate is the one implementation of the tree pin (refresh-
# prebuilt.sh ends by running it; this script only READS its verdict —
# the anti-drift discipline the gate's header documents). When THIS
# script's own rewrite staled the lane, the refresh runs in the same
# invocation so one command leaves a committable tree — the manual
# two-step (bump, failed commit, refresh, re-commit) was the exact
# friction the owner refused to keep typing. A lane stale for
# reasons this script did not create keeps the honest manual verdict.
echo ""
if [ "${EBPF_CHANGED}" = true ] && ! bash scripts/gates/check-prebuilt-parity.sh >/dev/null 2>&1; then
	echo -e "  ${YELLOW}..${NC} ebpf-prebuilt/     → the version rewrite staled the lane's tree pin — auto-refreshing through the validated build pipeline"
	if bash scripts/release/refresh-prebuilt.sh; then
		echo -e "  ${GREEN}OK${NC} ebpf-prebuilt/     → lane regenerated in parity (commit ebpf/ + ebpf-prebuilt/ together)"
		TOUCHED+=("ebpf-prebuilt/")
	else
		echo -e "${RED}FAIL:${NC} the prebuilt refresh did not complete — the tree is NOT committable in this state."
		echo -e "  the refresh drives the eBPF build; its once-per-machine prerequisites:"
		echo -e "    ./scripts/dev/bootstrap-ebpf.sh"
		echo -e "  then finish the bump manually and commit the lane with its sources:"
		echo -e "    ./scripts/release/refresh-prebuilt.sh"
		echo -e "    git add ${TOUCHED[*]} ebpf-prebuilt/"
		exit 1
	fi
elif bash scripts/gates/check-prebuilt-parity.sh >/dev/null 2>&1; then
	echo -e "  ${GREEN}OK${NC} ebpf-prebuilt/     → parity green (the lane pins the live ebpf/ tree)"
else
	echo -e "  ${YELLOW}!${NC} ebpf-prebuilt/     → STALE: ebpf/ changed after the lane was generated (not by this run)"
	echo -e "     run ./scripts/release/refresh-prebuilt.sh and commit ebpf/ + ebpf-prebuilt/ together (the parity gate fails CI until the refresh lands)"
fi

echo ""
echo -e "${GREEN}Version updated to v${NEW_VERSION}${NC}"
if [ "${#TOUCHED[@]}" -gt 0 ]; then
	echo "next: git add ${TOUCHED[*]} && git commit"
else
	echo -e "${YELLOW}Nothing changed — every detected surface already carries v${NEW_VERSION}.${NC}"
fi

if [ "${COMMIT}" = true ]; then
	# Fail closed (NIGHT-improve-67): a commit that stages the ebpf
	# version bump WITHOUT the refreshed lane would ride a stale
	# tree pin straight into CI's parity gate — refuse, name the
	# refresh, and hand over the one-commit recipe. With the
	# NIGHT-improve-70 auto-refresh this refusal is reachable only
	# when the lane was stale for reasons this run did not create
	# (the refresh above already failed closed for its own shape).
	# Re-running version-to.sh after a manual refresh hits the early
	# "already at" exit, so the recipe commits manually by design.
	if ! bash scripts/gates/check-prebuilt-parity.sh >/dev/null 2>&1; then
		echo -e "${RED}FAIL:${NC} refusing to commit — the prebuilt lane is stale (ebpf/ changed, ebpf-prebuilt/ has not)."
		echo -e "  1. ./scripts/release/refresh-prebuilt.sh"
		echo -e "  2. git add ${TOUCHED[*]} ebpf-prebuilt/"
		echo -e "  3. git commit -m \"release: v${NEW_VERSION}\""
		exit 1
	fi
	if [ "${#TOUCHED[@]}" -eq 0 ]; then
		echo -e "${YELLOW}Nothing to commit — every detected surface already carries v${NEW_VERSION}.${NC}"
		exit 0
	fi
	git add "${TOUCHED[@]}"
	git commit -m "release: v${NEW_VERSION}"
	echo -e "${GREEN}OK Committed: release: v${NEW_VERSION}${NC}"
fi
