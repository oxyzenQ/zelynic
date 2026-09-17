#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# ZELYNIC RUST VERSION SYNC CHECK
#
# Verifies the Rust toolchain version is consistent across all sources:
#   1. rust-toolchain.toml  (channel = "X.Y.Z" — authoritative source)
#   2. Cargo.toml           (rust-version = "X.Y" — MSRV)
#   3. .github/workflows/*.yml (RUST_VERSION: "X.Y.Z" — CI install pin)
#
# Fails if any source disagrees with the others. The write counterpart is
# `scripts/rust-version-to.sh` (the owner-facing bumper).
#
# Workflows without a RUST_VERSION declaration are out of scope by policy:
#   audit.yml — security scanning only, builds nothing, any recent
#     toolchain works (same skip policy cosmostrix applies to miri/docs-ci).
#
# Usage: bash scripts/check-rust-version-sync.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ── 1. rust-toolchain.toml (authoritative) ──
TOOLCHAIN_FILE="rust-toolchain.toml"
if [ ! -f "$TOOLCHAIN_FILE" ]; then
	echo "FAIL: $TOOLCHAIN_FILE not found"
	exit 1
fi
FULL_VERSION=$(grep '^channel = ' "$TOOLCHAIN_FILE" | sed 's/channel = "\(.*\)".*/\1/')
if [ -z "$FULL_VERSION" ]; then
	echo "FAIL: could not parse channel from $TOOLCHAIN_FILE"
	exit 1
fi

# A channel alias means the dormant-mode pin is broken (a future stable
# release could silently change the toolchain). Reject it loudly.
if [[ "$FULL_VERSION" == "stable" || "$FULL_VERSION" == "beta" || "$FULL_VERSION" == nightly* ]]; then
	echo "FAIL: rust-toolchain.toml channel = \"$FULL_VERSION\" is a channel alias."
	echo "      Dormant-mode policy requires a concrete X.Y.Z pin."
	exit 1
fi

# Extract major.minor (strip patch) for MSRV comparison
MSRV_EXPECTED="${FULL_VERSION%.*}"
if [ -z "$MSRV_EXPECTED" ]; then
	echo "FAIL: could not derive MSRV from full version '$FULL_VERSION'"
	exit 1
fi

echo "Authoritative source: rust-toolchain.toml channel = \"$FULL_VERSION\""
echo "Expected MSRV (major.minor): $MSRV_EXPECTED"
echo ""

FAILED=0

# ── 2. Cargo.toml ──
CARGO_MSRV=$(grep '^rust-version = ' Cargo.toml | sed 's/rust-version = "\(.*\)".*/\1/')
if [ "$CARGO_MSRV" != "$MSRV_EXPECTED" ]; then
	echo "FAIL: Cargo.toml rust-version = \"$CARGO_MSRV\" — expected \"$MSRV_EXPECTED\""
	FAILED=$((FAILED + 1))
else
	echo "OK: Cargo.toml rust-version = \"$CARGO_MSRV\""
fi

# ── 3. .github/workflows/*.yml ──
for wf in .github/workflows/*.yml; do
	[ -f "$wf" ] || continue
	# Skip audit.yml (security scanner, no build, no pinned toolchain).
	[ "$(basename "$wf")" = "audit.yml" ] && continue

	if grep -q 'RUST_VERSION:' "$wf"; then
		WF_VERSION=$(grep 'RUST_VERSION:' "$wf" | head -1 | sed 's/.*RUST_VERSION: *"\(.*\)".*/\1/')
		if [ "$WF_VERSION" != "$FULL_VERSION" ]; then
			echo "FAIL: $wf RUST_VERSION = \"$WF_VERSION\" — expected \"$FULL_VERSION\""
			FAILED=$((FAILED + 1))
		else
			echo "OK: $wf RUST_VERSION = \"$WF_VERSION\""
		fi
	fi
done

echo ""
if [ "$FAILED" -gt 0 ]; then
	echo "FAIL: $FAILED source(s) out of sync with rust-toolchain.toml"
	echo ""
	echo "To fix: ./scripts/rust-version-to.sh <X.Y.Z>"
	exit 1
else
	echo "OK: all Rust version sources in sync"
	exit 0
fi
