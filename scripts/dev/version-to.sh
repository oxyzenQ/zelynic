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
# notices it: the script ends by reporting the lane's parity verdict
# honestly, and --commit REFUSES while the lane is stale — run
# ./scripts/release/refresh-prebuilt.sh first. README.md is probed
# for a version surface and reported honestly either way —
# NIGHT-hunt-32: the README lane once printed an unconditional
# "OK README.md -> vN" while the README carried no badge, no release
# URL, and no Version line for any of the four patterns to match —
# a claimed rewrite that never happened)
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
README_HITS="$(grep -cE 'version-v[0-9]|releases/download/v[0-9]|zelynic-v[0-9]+\.[0-9]+|^Version: v[0-9]' README.md 2>/dev/null || true)"
if [ "${README_HITS:-0}" -gt 0 ]; then
	sed -i -E "s|version-v[^?]*\\?|version-v${NEW_VERSION}-7C3AED?|" README.md
	sed -i -E "s|releases/download/v[0-9]+\\.[0-9]+\\.[0-9]+|releases/download/v${NEW_VERSION}|g" README.md
	sed -i -E "s|zelynic-v[0-9]+\\.[0-9]+\\.[0-9]+(-[A-Za-z0-9.]+)?-x86_64|zelynic-v${NEW_VERSION}-x86_64|g" README.md
	sed -i "s|Version: v.*|Version: v${NEW_VERSION}|" README.md
	echo -e "  ${GREEN}OK${NC} README.md           → v${NEW_VERSION} (badge + example)"
else
	echo -e "  ${YELLOW}!${NC} README.md           → no version surface found (no badge / release URL / Version line) — nothing to rewrite"
fi

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
if [ "${EBPF_CURRENT}" != "${NEW_VERSION}" ]; then
	sed -i "0,/^version = \".*\"/s//version = \"${NEW_VERSION}\"/" ebpf/Cargo.toml
	echo -e "  ${GREEN}OK${NC} ebpf/Cargo.toml     → ${NEW_VERSION}"
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

# --- Prebuilt-lane parity verdict (always reported, never guessed) ---
# The gate is the one implementation of the tree pin (refresh-
# prebuilt.sh ends by running it; this script only READS its verdict —
# the anti-drift discipline the gate's header documents). Quiet by
# design: the version report prints one line, the gate's own PASS/
# FAIL detail belongs to its dedicated invocation.
echo ""
if bash scripts/gates/check-prebuilt-parity.sh >/dev/null 2>&1; then
	echo -e "  ${GREEN}OK${NC} ebpf-prebuilt/     → parity green (the lane pins the live ebpf/ tree)"
else
	echo -e "  ${YELLOW}!${NC} ebpf-prebuilt/     → STALE: ebpf/ changed after the lane was generated"
	echo -e "     run ./scripts/release/refresh-prebuilt.sh and commit ebpf/ + ebpf-prebuilt/ together (the parity gate fails CI until the refresh lands)"
fi

echo ""
echo -e "${GREEN}Version updated to v${NEW_VERSION}${NC}"

if [ "${COMMIT}" = true ]; then
	# Fail closed (NIGHT-improve-67): a commit that stages the ebpf
	# version bump WITHOUT the refreshed lane would ride a stale
	# tree pin straight into CI's parity gate — refuse, name the
	# refresh, and hand over the one-commit recipe. Re-running
	# version-to.sh after the refresh hits the early "already at"
	# exit, so the recipe commits manually by design.
	if ! bash scripts/gates/check-prebuilt-parity.sh >/dev/null 2>&1; then
		echo -e "${RED}FAIL:${NC} refusing to commit — the prebuilt lane is stale (ebpf/ changed, ebpf-prebuilt/ has not)."
		echo -e "  1. ./scripts/release/refresh-prebuilt.sh"
		echo -e "  2. git add Cargo.toml Cargo.lock README.md ebpf/Cargo.toml ebpf/Cargo.lock ebpf-prebuilt/"
		echo -e "  3. git commit -m \"release: v${NEW_VERSION}\""
		exit 1
	fi
	git add Cargo.toml Cargo.lock README.md ebpf/Cargo.toml ebpf/Cargo.lock
	git commit -m "release: v${NEW_VERSION}"
	echo -e "${GREEN}OK Committed: release: v${NEW_VERSION}${NC}"
fi
