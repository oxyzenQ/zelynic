#!/bin/bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# =============================================================================
# ZELYNIC VERSION MANAGER
# =============================================================================
# Centralized version management — update ALL files from a single command.
#
# Usage:
#   ./scripts/version-to.sh v3.0.0          # Update to v3.0.0
#   ./scripts/version-to.sh v2.1.0 --commit # Update and auto-commit
#   ./scripts/version-to.sh                 # Show current version
#
# Single source of truth: Cargo.toml
# Files updated: Cargo.toml, Cargo.lock, README.md
# Files auto-derived: scripts/build.sh (reads from Cargo.toml), binary (env!("CARGO_PKG_VERSION"))
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
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
    echo "Usage: ./scripts/version-to.sh v<VERSION> [--commit]"
    exit 0
fi

NEW_VERSION="${1#v}"
shift

COMMIT=false
for arg in "$@"; do
    case "${arg}" in
        --commit|-c) COMMIT=true ;;
        *) echo -e "${RED}Unknown option: ${arg}${NC}" >&2; exit 1 ;;
    esac
done

validate_version "${NEW_VERSION}"
CURRENT=$(current_version)

if [ "${CURRENT}" = "${NEW_VERSION}" ]; then
    echo -e "${YELLOW}Already at v${NEW_VERSION}, nothing to change.${NC}"
    exit 0
fi

echo -e "Updating version: ${YELLOW}v${CURRENT}${NC} → ${GREEN}v${NEW_VERSION}${NC}"
echo ""

# --- Update Cargo.toml (source of truth) ---
# Only update the [package] version (line 1-10 of file), not dependency versions
sed -i "0,/^version = \".*\"/s//version = \"${NEW_VERSION}\"/" Cargo.toml
echo -e "  ${GREEN}✓${NC} Cargo.toml          → ${NEW_VERSION}"

# --- Update Cargo.lock (zelynic package entry only) ---
# Cargo.lock has the form:
#   [[package]]
#   name = "zelynic"
#   version = "OLD"
# We update only the zelynic package version, NOT dependency versions
# (those are the job of `cargo update`, not a version bump).
if [ -f Cargo.lock ]; then
    sed -i -E "/^name = \"zelynic\"$/{n;s|^version = \"${CURRENT}\"|version = \"${NEW_VERSION}\"|;}" Cargo.lock
    LOCK_VER="$(grep -A1 '^name = "zelynic"' Cargo.lock | grep '^version = "' | head -1 | sed -E 's/^version = "(.+)"/\1/')"
    if [ "${LOCK_VER}" = "${NEW_VERSION}" ]; then
        echo -e "  ${GREEN}✓${NC} Cargo.lock          → zelynic version = ${NEW_VERSION}"
    else
        echo -e "  ${YELLOW}⚠${NC} Cargo.lock          → expected ${NEW_VERSION}, got ${LOCK_VER} (run 'cargo update -p zelynic' to fix)"
    fi
fi

# --- Update README.md ---
sed -i -E "s|version-v[^?]*\\?|version-v${NEW_VERSION}-7C3AED?|" README.md
sed -i -E "s|releases/download/v[0-9]+\\.[0-9]+\\.[0-9]+|releases/download/v${NEW_VERSION}|g" README.md
sed -i -E "s|zelynic-v[0-9]+\\.[0-9]+\\.[0-9]+(-[A-Za-z0-9.]+)?-x86_64|zelynic-v${NEW_VERSION}-x86_64|g" README.md
sed -i "s|Version: v.*|Version: v${NEW_VERSION}|" README.md
echo -e "  ${GREEN}✓${NC} README.md           → v${NEW_VERSION} (badge + example)"

# --- scripts/build.sh reads dynamically from Cargo.toml, no update needed ---
echo -e "  ${GREEN}✓${NC} scripts/build.sh    → auto (reads from Cargo.toml)"

# --- Binary reads from Cargo.toml via env!("CARGO_PKG_VERSION"), no update needed ---
echo -e "  ${GREEN}✓${NC} Binary (zelynic)    → auto (reads from Cargo.toml)"

echo ""
echo -e "${GREEN}Version updated to v${NEW_VERSION}${NC}"

if [ "${COMMIT}" = true ]; then
    git add Cargo.toml Cargo.lock README.md
    git commit -m "release: v${NEW_VERSION}"
    echo -e "${GREEN}✓ Committed: release: v${NEW_VERSION}${NC}"
fi
