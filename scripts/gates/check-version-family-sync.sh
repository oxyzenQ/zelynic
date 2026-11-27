#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
# SPDX-License-Identifier: AGPL-3.0-only OR Commercial
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
# =============================================================================
# ZELYNIC VERSION FAMILY SYNC GUARD (night-cafe-mclaren-1)
# =============================================================================
# Fails when any crate named after the root crate carries a version
# the root does not — in its manifest, or in any [[package]] entry a
# tracked-or-uncommitted Cargo.lock holds for it.
#
# The release lane's own parity tripwire (release.yml) validates the
# ROOT Cargo.toml against the tag before any compile time is spent;
# nothing held the SIBLINGS to the same number. The provenance hole
# NIGHT-bump-2 closed at bump time (zelynic-proofs once rode 0.1.0
# beside a dragon.1 root) stays closed here at every push: a drifted
# sibling fails this gate with the heal recipe, instead of shipping a
# provenance disagreement into a release.
#
# Discovery law (the same one scripts/dev/version-to.sh rides): git
# enumerates the manifests and the locks — tracked files plus
# authored-but-uncommitted files (a new workspace joins the family
# the moment it exists on disk); gitignored trees (target/ output,
# vendored junk) never enter. The family is DETECTED, never listed —
# the prefix is the root [package] name, so a renamed root or a fifth
# workspace joins with zero edits here.
#
# A manifest outside the family is left at its own version and
# reported informationally — never silently swept, never silently
# lost (the NIGHT-bump-2 stranger law).
#
# Usage: bash scripts/gates/check-version-family-sync.sh
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${REPO_ROOT}"

# night-cafe-1: the tiers come from the shared brand palette — the
# bash twin of src/output/color.rs.
# shellcheck source=scripts/lib/ux_palette.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/ux_palette.sh"

# The [package] parsers (NIGHT-bump-2's structural law: the name and
# version surfaces live inside [package], whatever the file layout).
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

# The version walk (night-cafe-mclaren-1): tracked plus
# authored-but-uncommitted, deduplicated, sorted — the walk
# version-to.sh rides. The [.] form keeps the dot literal with no
# backslash-quoting dance.
version_walk() {
	{
		git ls-files | grep -E "(^|/)${1//./[.]}$" || true
		git ls-files --others --exclude-standard | grep -E "(^|/)${1//./[.]}$" || true
	} | sort -u
}

# The name<TAB>version rows a lock carries for an ERE of names (the
# lock's own top-level version line sits outside any [[package]]
# block and is never read).
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

ROOT_NAME="$(manifest_name_of Cargo.toml)"
ROOT_VERSION="$(manifest_version_of Cargo.toml)"
if [ -z "${ROOT_NAME}" ] || [ -z "${ROOT_VERSION}" ]; then
	echo -e "${RED}FAIL:${NC} the root Cargo.toml carries no [package] name/version — the family law has no anchor"
	exit 1
fi

DRIFT=0
FAMILY=0
ENTRIES=0

# Manifest lane: every family manifest must carry the root version.
# The root rides by definition; a sibling rides when its name starts
# with the root's own name.
while IFS= read -r f; do
	name="$(manifest_name_of "${f}")"
	ver="$(manifest_version_of "${f}")"
	if [ "${f}" != "Cargo.toml" ] && [[ "${name}" != "${ROOT_NAME}"* ]]; then
		continue
	fi
	FAMILY=$((FAMILY + 1))
	if [ "${ver}" != "${ROOT_VERSION}" ]; then
		echo -e "${RED}DRIFT:${NC} ${f} (${name:-no name}) carries v${ver:-nothing}; the root carries v${ROOT_VERSION}"
		DRIFT=$((DRIFT + 1))
	fi
done < <(version_walk Cargo.toml)

# The family ERE, from the detected family manifests — the same
# names_regex shape the lock lanes ride in version-to.sh.
names_regex=""
while IFS= read -r f; do
	name="$(manifest_name_of "${f}")"
	if [ -n "${name}" ] && { [ "${f}" = "Cargo.toml" ] || [[ "${name}" == "${ROOT_NAME}"* ]]; }; then
		names_regex="${names_regex}${name}|"
	fi
done < <(version_walk Cargo.toml)
names_regex="${names_regex%|}"

# Lock lane: every family [[package]] entry must carry the root
# version (the crate's own workspace entry today, a path dependency's
# cross-entry the day one appears).
while IFS= read -r lockf; do
	while IFS=$'\t' read -r lname lver; do
		ENTRIES=$((ENTRIES + 1))
		if [ "${lver}" != "${ROOT_VERSION}" ]; then
			echo -e "${RED}DRIFT:${NC} ${lockf} [[package]] ${lname} carries v${lver}; the root carries v${ROOT_VERSION}"
			DRIFT=$((DRIFT + 1))
		fi
	done < <(lock_entry_versions "${names_regex}" "${lockf}")
done < <(version_walk Cargo.lock)

# The stranger report: a manifest outside the family is visible on
# every run — informational, never a failure, never swept silently.
while IFS= read -r f; do
	name="$(manifest_name_of "${f}")"
	if [ -n "${name}" ] && [ "${f}" != "Cargo.toml" ] && [[ "${name}" != "${ROOT_NAME}"* ]]; then
		echo -e "${YELLOW}!${NC} ${f} ${name} v$(manifest_version_of "${f}") — outside the ${ROOT_NAME} family (left at its own version)"
	fi
done < <(version_walk Cargo.toml)

if [ "${DRIFT}" -ne 0 ]; then
	echo ""
	echo -e "${RED}FAIL: ${DRIFT} version drift(s) inside the ${ROOT_NAME} family${NC}"
	echo ""
	echo "Fix: one command heals every detected surface (it detects, never lists):"
	echo "  ./scripts/dev/version-to.sh v${ROOT_VERSION}"
	exit 1
fi
echo -e "${GREEN}OK:${NC} family sync — manifests: ${FAMILY}, lock [[package]] entries: ${ENTRIES}, all at v${ROOT_VERSION}, zero drift"
