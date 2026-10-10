#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
# =============================================================================
# ZELYNIC VERSION MANAGER
# =============================================================================
# Centralized version management — update ALL files from a single command.
#
# Usage:
#   ./scripts/dev/version-to.sh v11.1.0        # Update to v11.1.0
#   ./scripts/dev/version-to.sh v11.0.1 --commit # Update and auto-commit
#   ./scripts/dev/version-to.sh                 # Show current version
#
# Single source of truth: Cargo.toml
# Files updated: Cargo.toml, Cargo.lock, ebpf/Cargo.toml,
# ebpf/Cargo.lock (NIGHT-improve-67: the eBPF crate's version follows
# the root crate's — its objects ship inside the binary, so a drifting
# 0.1.0 label riding a v50 binary was a provenance hole. The version
# change touches the ebpf/ tree, so the prebuilt lane's tree pin
# notices it: NIGHT-improve-70 — when THIS script's own rewrite stales
# the lane, the refresh runs in the same invocation
# (./scripts/release/refresh-prebuilt.sh through the repo's validated
# build pipeline — one command leaves a committable tree; a refresh
# that cannot complete fails closed with the bootstrap recipe).
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
# Files auto-derived: scripts/build.sh (reads from Cargo.toml), binary (env!("CARGO_PKG_VERSION"))
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${SCRIPT_DIR}"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# Read current version from Cargo.toml
current_version() {
	grep '^version = ' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/'
}

# Read current version from ebpf/Cargo.toml (NIGHT-improve-67: the
# eBPF crate rides the root's version; read its OWN current value
# instead of assuming it matches the root — a drifted lane is exactly
# the state this script exists to heal).
ebpf_current_version() {
	grep '^version = ' ebpf/Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/'
}

# Validate semver format
validate_version() {
	local ver="$1"
	if ! echo "${ver}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
		echo -e "${RED}Error: Invalid version '${ver}'. Expected format: X.Y.Z or X.Y.Z-label${NC}" >&2
		exit 1
	fi
}

# Write the release line to CHANGELOG.md (NIGHT-improve-76). The
# ledger shape is the owner's: a "## [Released]" heading with the
# bare version line under it — newest first, created above
# "## [Unreleased]" when absent. Pre-release (X.Y.Z-rc.1) and stable
# (X.Y.Z) write the same shape. Honest probes (the README lane's
# NIGHT-hunt-32 rule): a missing file, a missing "## [Unreleased]"
# anchor, or a "## [Released]" section without this tool's own shape
# (heading, blank spacer, version lines) warns and writes nothing —
# a ledger this script did not create is not one it rewrites.
changelog_release() {
	local ver="v$1"
	if [ ! -f CHANGELOG.md ]; then
		echo -e "  ${YELLOW}!${NC} CHANGELOG.md        → file absent, nothing to write"
		return 0
	fi
	# A version line never repeats: the re-run at a version the ledger
	# already carries (the usual stale-tree re-entry) writes nothing.
	if grep -qxF "${ver}" CHANGELOG.md; then
		echo -e "  ${YELLOW}!${NC} CHANGELOG.md        → ${ver} already recorded, nothing to write"
		return 0
	fi
	local tmp
	tmp="$(mktemp)"
	if grep -q '^## \[Released\]$' CHANGELOG.md; then
		# The section exists. This tool's own shape puts one blank
		# spacer between the heading and the version lines — the new
		# version splices in under it, above the current top line.
		if [ -z "$(sed -n '/^## \[Released\]$/{n;p;}' CHANGELOG.md)" ]; then
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
			echo -e "  ${GREEN}OK${NC} CHANGELOG.md        → ${ver} (## [Released], newest first)"
		else
			rm -f "${tmp}"
			echo -e "  ${YELLOW}!${NC} CHANGELOG.md        → unexpected ## [Released] shape (no blank spacer under the heading) — nothing to write"
		fi
	else
		# No section yet — create it above "## [Unreleased]" (the
		# unreleased work keeps its own section below the ledger).
		if grep -q '^## \[Unreleased\]$' CHANGELOG.md; then
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
			echo -e "  ${GREEN}OK${NC} CHANGELOG.md        → ${ver} (section created above ## [Unreleased])"
		else
			rm -f "${tmp}"
			echo -e "  ${YELLOW}!${NC} CHANGELOG.md        → no ## [Unreleased] anchor found — nothing to write"
		fi
	fi
}

# Show current version and exit
if [ $# -eq 0 ]; then
	echo -e "Current version: ${GREEN}v$(current_version)${NC}"
	echo ""
	echo "Usage: ./scripts/dev/version-to.sh v<VERSION> [--commit]"
	exit 0
fi

NEW_VERSION="${1#v}"
shift

COMMIT=false
for arg in "$@"; do
	case "${arg}" in
	--commit | -c) COMMIT=true ;;
	*)
		echo -e "${RED}Unknown option: ${arg}${NC}" >&2
		exit 1
		;;
	esac
done

validate_version "${NEW_VERSION}"
CURRENT=$(current_version)
EBPF_CURRENT=$(ebpf_current_version)

if [ "${CURRENT}" = "${NEW_VERSION}" ] && [ "${EBPF_CURRENT}" = "${NEW_VERSION}" ]; then
	echo -e "${YELLOW}Already at v${NEW_VERSION} (root + ebpf), nothing to change.${NC}"
	exit 0
fi

echo -e "Updating version: ${YELLOW}v${CURRENT}${NC} → ${GREEN}v${NEW_VERSION}${NC}"
echo ""

# --- Update Cargo.toml (source of truth) ---
# Only update the [package] version (line 1-10 of file), not dependency versions
if [ "${CURRENT}" = "${NEW_VERSION}" ]; then
	echo -e "  ${YELLOW}!${NC} Cargo.toml          → already at v${NEW_VERSION} (the ebpf lane alone drifted)"
else
	sed -i "0,/^version = \".*\"/s//version = \"${NEW_VERSION}\"/" Cargo.toml
	echo -e "  ${GREEN}OK${NC} Cargo.toml          → ${NEW_VERSION}"
fi

# --- Update Cargo.lock (zelynic package entry only) ---
# Cargo.lock has the form:
#   [[package]]
#   name = "zelynic"
#   version = "OLD"
# We update only the zelynic package version, NOT dependency versions
# (those are the job of `cargo update`, not a version bump).
if [ -f Cargo.lock ] && [ "${CURRENT}" != "${NEW_VERSION}" ]; then
	sed -i -E "/^name = \"zelynic\"$/{n;s|^version = \"${CURRENT}\"|version = \"${NEW_VERSION}\"|;}" Cargo.lock
	LOCK_VER="$(grep -A1 '^name = "zelynic"' Cargo.lock | grep '^version = "' | head -1 | sed -E 's/^version = "(.+)"/\1/')"
	if [ "${LOCK_VER}" = "${NEW_VERSION}" ]; then
		echo -e "  ${GREEN}OK${NC} Cargo.lock          → zelynic version = ${NEW_VERSION}"
	else
		echo -e "  ${YELLOW}!${NC} Cargo.lock          → expected ${NEW_VERSION}, got ${LOCK_VER} (run 'cargo update -p zelynic' to fix)"
	fi
fi

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
	sed -i -E "s|releases/download/v[0-9]+\\.[0-9]+\\.[0-9]+|releases/download/v${NEW_VERSION}|g" README.md
	sed -i -E "s|zelynic-v[0-9]+\\.[0-9]+\\.[0-9]+(-[A-Za-z0-9.]+)?-x86_64|zelynic-v${NEW_VERSION}-x86_64|g" README.md
	sed -i "s|Version: v.*|Version: v${NEW_VERSION}|" README.md
	echo -e "  ${GREEN}OK${NC} README.md           → v${NEW_VERSION} (release URLs + versioned examples)"
else
	echo -e "  ${YELLOW}!${NC} README.md           → no version surface found (no release URL / versioned example / Version line) — nothing to rewrite"
fi

# --- Update CHANGELOG.md (NIGHT-improve-76: the release ledger line) ---
changelog_release "${NEW_VERSION}"

# --- scripts/build.sh reads dynamically from Cargo.toml, no update needed ---
echo -e "  ${GREEN}OK${NC} scripts/build.sh    → auto (reads from Cargo.toml)"

# --- Binary reads from Cargo.toml via env!("CARGO_PKG_VERSION"), no update needed ---
echo -e "  ${GREEN}OK${NC} Binary (zelynic)    → auto (reads from Cargo.toml)"

# --- Update ebpf/Cargo.toml + ebpf/Cargo.lock (NIGHT-improve-67: the ---
# --- eBPF crate rides the root's version) ---
# The eBPF tree is pinned by ebpf-prebuilt/manifest.toml's tree hash,
# so ANY version change here stales the prebuilt lane — the parity
# verdict below reports it honestly and --commit refuses until
# ./scripts/release/refresh-prebuilt.sh regenerates the lane. The
# lock edit mirrors the root pair's shape: the name-anchored
# zelynic-ebpf entry moves, dependency versions never do.
EBPF_CHANGED=false
if [ "${EBPF_CURRENT}" != "${NEW_VERSION}" ]; then
	sed -i "0,/^version = \".*\"/s//version = \"${NEW_VERSION}\"/" ebpf/Cargo.toml
	echo -e "  ${GREEN}OK${NC} ebpf/Cargo.toml     → ${NEW_VERSION}"
	EBPF_CHANGED=true
	if [ -f ebpf/Cargo.lock ]; then
		sed -i -E "/^name = \"zelynic-ebpf\"$/{n;s|^version = \"${EBPF_CURRENT}\"|version = \"${NEW_VERSION}\"|;}" ebpf/Cargo.lock
		EBPF_LOCK_VER="$(grep -A1 '^name = "zelynic-ebpf"' ebpf/Cargo.lock | grep '^version = "' | head -1 | sed -E 's/^version = "(.+)"/\1/')"
		if [ "${EBPF_LOCK_VER}" = "${NEW_VERSION}" ]; then
			echo -e "  ${GREEN}OK${NC} ebpf/Cargo.lock     → zelynic-ebpf version = ${NEW_VERSION}"
		else
			echo -e "  ${YELLOW}!${NC} ebpf/Cargo.lock     → expected ${NEW_VERSION}, got ${EBPF_LOCK_VER} (run 'cargo update --manifest-path ebpf/Cargo.toml -p zelynic-ebpf' inside ebpf/ to fix)"
		fi
	fi
else
	echo -e "  ${YELLOW}!${NC} ebpf/Cargo.toml     → already at v${NEW_VERSION}"
fi

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
	else
		echo -e "${RED}FAIL:${NC} the prebuilt refresh did not complete — the tree is NOT committable in this state."
		echo -e "  the refresh drives the eBPF build; its once-per-machine prerequisites:"
		echo -e "    ./scripts/dev/bootstrap-ebpf.sh"
		echo -e "  then finish the bump manually and commit the lane with its sources:"
		echo -e "    ./scripts/release/refresh-prebuilt.sh"
		echo -e "    git add Cargo.toml Cargo.lock README.md CHANGELOG.md ebpf/ ebpf-prebuilt/"
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
if [ "${EBPF_CHANGED}" = true ]; then
	echo "next: git add Cargo.toml Cargo.lock README.md CHANGELOG.md ebpf/ ebpf-prebuilt/ && git commit"
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
		echo -e "  2. git add Cargo.toml Cargo.lock README.md CHANGELOG.md ebpf/Cargo.toml ebpf/Cargo.lock ebpf-prebuilt/"
		echo -e "  3. git commit -m \"release: v${NEW_VERSION}\""
		exit 1
	fi
	git add Cargo.toml Cargo.lock README.md CHANGELOG.md ebpf/Cargo.toml ebpf/Cargo.lock ebpf-prebuilt/
	git commit -m "release: v${NEW_VERSION}"
	echo -e "${GREEN}OK Committed: release: v${NEW_VERSION}${NC}"
fi
