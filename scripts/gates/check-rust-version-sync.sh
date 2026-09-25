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
# NIGHT-lts-9 added the SECOND pin family — the eBPF nightly toolchain,
# whose dated pin is duplicated across nine sites with no sync check
# until now (a half-bumped pin means CI installs one nightly while
# build.rs invokes another — the nested eBPF build silently downloads
# an unverified toolchain at compile time, or fails on a runner without
# network):
#   4. ebpf/rust-toolchain.toml (channel = "nightly-YYYY-MM-DD" — the
#      eBPF crate's own pin, authoritative for the nightly family)
#      == every `toolchain: nightly-*` install in the workflows
#      == build.rs's EBPF_TOOLCHAIN const (what build.rs actually
#         invokes for the nested build)
#      == scripts/install.sh's EBPF_TOOLCHAIN (the from-source path)
#      == scripts/uninstall.sh's uninstall hint (the cleanup path)
#
# Fails if any source disagrees with the others. The write counterpart is
# `scripts/dev/rust-version-to.sh` (the owner-facing bumper, stable family).
#
# Workflows without a RUST_VERSION declaration are out of scope by policy:
#   audit.yml — security scanning only, builds nothing, any recent
#     toolchain works (same skip policy cosmostrix applies to miri/docs-ci).
#
# Usage: bash scripts/gates/check-rust-version-sync.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
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

# ── 4. The eBPF nightly pin family (NIGHT-lts-9) ──────────────────
# ebpf/rust-toolchain.toml is authoritative for the dated nightly; the
# pin is duplicated at every site that installs or names it, and every
# duplicate must agree. A bare "nightly" alias is rejected for the same
# reason the stable gate rejects channel aliases: an alias silently
# moves, a dated pin is a verdict.
EBPF_TOOLCHAIN_FILE="ebpf/rust-toolchain.toml"
if [ -f "$EBPF_TOOLCHAIN_FILE" ]; then
	EBPF_NIGHTLY=$(grep '^channel = ' "$EBPF_TOOLCHAIN_FILE" | sed 's/channel = "\(.*\)".*/\1/')
	if [ -z "$EBPF_NIGHTLY" ]; then
		echo "FAIL: could not parse channel from $EBPF_TOOLCHAIN_FILE"
		FAILED=$((FAILED + 1))
	elif [[ "$EBPF_NIGHTLY" != nightly-[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] ]]; then
		echo "FAIL: ebpf/rust-toolchain.toml channel = \"$EBPF_NIGHTLY\" is not a dated nightly pin"
		echo "      (nightly-YYYY-MM-DD required — an alias drifts, a date is a verdict)"
		FAILED=$((FAILED + 1))
	else
		echo ""
		echo "Authoritative eBPF nightly: $EBPF_NIGHTLY"
		echo ""

		# 4a. Every nightly toolchain install in the workflows.
		NIGHTLY_REFS=0
		NIGHTLY_MATCHED=0
		for wf in .github/workflows/*.yml; do
			[ -f "$wf" ] || continue
			while IFS= read -r ref; do
				NIGHTLY_REFS=$((NIGHTLY_REFS + 1))
				if [ "$ref" != "$EBPF_NIGHTLY" ]; then
					echo "FAIL: $wf installs nightly \"$ref\" — expected \"$EBPF_NIGHTLY\""
					FAILED=$((FAILED + 1))
				else
					NIGHTLY_MATCHED=$((NIGHTLY_MATCHED + 1))
				fi
			done < <(grep -o 'toolchain: nightly-[^[:space:]]*' "$wf" | sed 's/toolchain: //' || true)
		done
		if [ "$NIGHTLY_REFS" -eq 0 ]; then
			echo "FAIL: no nightly toolchain installs found in .github/workflows/ — the eBPF build prerequisites disappeared"
			FAILED=$((FAILED + 1))
		elif [ "$NIGHTLY_MATCHED" -eq "$NIGHTLY_REFS" ]; then
			echo "OK: $NIGHTLY_REFS workflow nightly install(s) match $EBPF_NIGHTLY"
		fi

		# 4b. build.rs — the toolchain the nested build invokes.
		if grep -q 'EBPF_TOOLCHAIN: &str' build.rs; then
			BUILD_RS_TOOLCHAIN=$(grep 'EBPF_TOOLCHAIN: &str' build.rs | sed 's/.*= *"\(.*\)".*/\1/')
			if [ "$BUILD_RS_TOOLCHAIN" != "$EBPF_NIGHTLY" ]; then
				echo "FAIL: build.rs EBPF_TOOLCHAIN = \"$BUILD_RS_TOOLCHAIN\" — expected \"$EBPF_NIGHTLY\""
				FAILED=$((FAILED + 1))
			else
				echo "OK: build.rs EBPF_TOOLCHAIN = \"$BUILD_RS_TOOLCHAIN\""
			fi
		else
			echo "FAIL: build.rs EBPF_TOOLCHAIN const not found (renamed?)"
			FAILED=$((FAILED + 1))
		fi

		# 4c. scripts/install.sh — the from-source install path.
		if grep -q '^EBPF_TOOLCHAIN=' scripts/install.sh; then
			INSTALL_TOOLCHAIN=$(grep '^EBPF_TOOLCHAIN=' scripts/install.sh | sed 's/EBPF_TOOLCHAIN= *"\(.*\)".*/\1/')
			if [ "$INSTALL_TOOLCHAIN" != "$EBPF_NIGHTLY" ]; then
				echo "FAIL: scripts/install.sh EBPF_TOOLCHAIN = \"$INSTALL_TOOLCHAIN\" — expected \"$EBPF_NIGHTLY\""
				FAILED=$((FAILED + 1))
			else
				echo "OK: scripts/install.sh EBPF_TOOLCHAIN = \"$INSTALL_TOOLCHAIN\""
			fi
		else
			echo "FAIL: scripts/install.sh EBPF_TOOLCHAIN not found (renamed?)"
			FAILED=$((FAILED + 1))
		fi

		# 4d. scripts/uninstall.sh — the cleanup hint names the pin.
		if grep -q "rustup toolchain uninstall $EBPF_NIGHTLY" scripts/uninstall.sh; then
			echo "OK: scripts/uninstall.sh hints the pinned nightly"
		else
			echo "FAIL: scripts/uninstall.sh does not name $EBPF_NIGHTLY in its uninstall hint"
			FAILED=$((FAILED + 1))
		fi
	fi
else
	echo "FAIL: $EBPF_TOOLCHAIN_FILE not found"
	FAILED=$((FAILED + 1))
fi

echo ""
if [ "$FAILED" -gt 0 ]; then
	echo "FAIL: $FAILED source(s) out of sync"
	echo ""
	echo "To fix (stable family): ./scripts/dev/rust-version-to.sh <X.Y.Z>"
	echo "To fix (eBPF nightly family): bump ebpf/rust-toolchain.toml AND every"
	echo "duplicate site together — the workflows' toolchain: pins, build.rs's"
	echo "EBPF_TOOLCHAIN const, scripts/install.sh, scripts/uninstall.sh."
	exit 1
else
	echo "OK: all Rust version sources in sync (stable family + eBPF nightly family)"
	exit 0
fi
