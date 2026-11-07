#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# RESEARCH TOOL — measures the saver-lane delta (latest zelynic vs
# legacy zelynic at the SAME rate). NOT the buyer-facing proof.
# The buyer-facing proof is scripts/bench/quota-saver-ab.sh
# (zelynic vs unlimited). Keep this script for the honest peak
# declaration; never demo it to a buyer.
#
# Measured 2026-11-07 (night-spark-10 host run): v80.1.0 vs v80.0.0
# at 100kb, same link, same workload: overrun download 87.58% vs
# 87.33% (delta +0.25pp — within noise), bounded upload 16.44% vs
# 16.86% (delta -0.42pp — within noise). The saver lanes (RECWN/
# ECN/EDT) are neutral at 100kb on this workload. Keep measuring
# at other rates before any rate-specific claim.
#
# The quota saver's vs-legacy proof (night-spark-9): run the A/B
# harness TWICE — first with the working tree's latest zelynic, then
# with the LEGACY release binary (default v80.0.0, the pre-saver
# edition limiter) at the SAME rate. The owner's origin brief priced
# the counterfactual as EITHER "no zelynic" OR "an old zelynic"; the
# harness alone answers the first (the trivial "rate limiting works").
# The saver edition's real claim is against the old drop-based
# limiter — the same rate on both sides of the version line is what
# prices the saver lanes themselves.
#
# Between the two runs the LATEST binary tears every limit down
# (`u --all`, the fleet sweep) and again after the legacy run — no
# kernel state crosses the version boundary, and the harness's own
# clean-slate preflight re-verifies the slate before each run's
# scenario A anyway (night-netrunner-5, measured, not assumed).
#
# The legacy binary lands in <repo>/legacy/zelynic — gitignored, a
# test artifact, never committed. Auto-downloaded from the GitHub
# release page ONLY when absent: the flat tarball plus its .sha512sum
# sidecar, checksum-verified before install. Override the pin via
# LEGACY_VERSION / LEGACY_PLATFORM.
#
# Legacy compatibility was verified against the v80.0.0 release
# binary before this script landed: bare-integer cgroup targets
# (parse_target_id's strip_prefix rule), --no-test, -u, unstrict
# --all, status --print-json with bytes_allowed, doctor --print-json.
# Its status JSON carries no bytes_saved_total, so a legacy leg books
# 0.00% honestly — the baseline is zero by construction, not by
# suppression. If some other LEGACY_VERSION cannot answer a call, the
# harness refuses with the reason and the run stops there.
#
# Each run's full output is kept: /tmp/quota-ab-latest.log and
# /tmp/quota-ab-legacy.log. The closing comparison lifts the two
# runs' contract verdict lines and labels them what they are — the
# ledger's counterfactual bookings; each run's per-leg wire ground
# truth stays in its log.
#
# The bounded legs ride inside the harness's 60 s curl --max-time: at
# the 100 kb default (decimal SI, 1000 bit/s — 12.5 KB/s) a 500 KB
# leg takes ~40 s. The harness's own 2 MB defaults at 100 kb would
# outlive the wall clock and the rung would honestly refuse — size
# the legs against the rate, or override the env knobs.
#
# Usage:
#   sudo ./scripts/bench/quota-saver-ab-vs-legacy.sh
#   sudo LEGACY_VERSION=v80.0.2 ./scripts/bench/quota-saver-ab-vs-legacy.sh
#   sudo DL_RATE=50kb DL_BYTES=300000 OVERRUN_SECONDS=60 \
#       ./scripts/bench/quota-saver-ab-vs-legacy.sh
#
# Env overrides: LATEST_BIN, LEGACY_VERSION, LEGACY_PLATFORM,
#   DL_RATE, UL_RATE, DL_BYTES, UL_BYTES, OVERRUN_SECONDS, LOG_DIR.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
LEGACY_DIR="$REPO_ROOT/legacy"
LEGACY_BIN="$LEGACY_DIR/zelynic"

LEGACY_VERSION="${LEGACY_VERSION:-v80.0.0}"
LEGACY_PLATFORM="${LEGACY_PLATFORM:-linux-amd64-v3-musl}"
ASSET="zelynic-${LEGACY_VERSION}-${LEGACY_PLATFORM}.tar.gz"
BASE_URL="https://github.com/oxyzenQ/zelynic/releases/download/${LEGACY_VERSION}"

HARNESS_ARGS=(
	--download-rate "${DL_RATE:-100kb}"
	--upload-rate "${UL_RATE:-100kb}"
	--download-bytes "${DL_BYTES:-500000}"
	--upload-bytes "${UL_BYTES:-500000}"
	--overrun-seconds "${OVERRUN_SECONDS:-30}"
)

LATEST_LOG="${LOG_DIR:-/tmp}/quota-ab-latest.log"
LEGACY_LOG="${LOG_DIR:-/tmp}/quota-ab-legacy.log"

die() {
	echo "quota-saver-ab-vs-legacy: cannot run — $*" >&2
	exit 2
}

resolve_latest() {
	# The harness's own ladder, plus the LATEST_BIN override: an
	# explicit path outranks the repo-local builds, which outrank the
	# PATH install.
	if [ -n "${LATEST_BIN:-}" ] && [ -x "$LATEST_BIN" ]; then
		echo "$LATEST_BIN"
		return 0
	fi
	local candidate
	for candidate in \
		"$REPO_ROOT/target/x86_64-unknown-linux-musl/pro-native-musl/zelynic" \
		"$REPO_ROOT/target/x86_64-unknown-linux-musl/release/zelynic" \
		"$REPO_ROOT/target/release/zelynic"; do
		if [ -x "$candidate" ]; then
			echo "$candidate"
			return 0
		fi
	done
	command -v zelynic || die "no latest zelynic binary found — build one (./scripts/build.sh release) or pass LATEST_BIN"
}

download_and_install() {
	# Runs in a subshell so the temp dir always dies with the flow,
	# and so a mid-download failure never leaves a half-installed
	# legacy binary behind.
	local tmp
	tmp="$(mktemp -d)" || return 1
	(
		set -euo pipefail
		curl -fsSL "$BASE_URL/$ASSET" -o "$tmp/$ASSET" ||
			{
				echo "the release asset 404'd or the lane died: $BASE_URL/$ASSET" >&2
				exit 1
			}
		curl -fsSL "$BASE_URL/$ASSET.sha512sum" -o "$tmp/$ASSET.sha512sum" ||
			{
				echo "the sha512sum sidecar 404'd: $BASE_URL/$ASSET.sha512sum" >&2
				exit 1
			}
		(cd "$tmp" && sha512sum -c "$ASSET.sha512sum") ||
			{
				echo "sha512 mismatch — the download is not the release artifact" >&2
				exit 1
			}
		tar -xzf "$tmp/$ASSET" -C "$tmp" ||
			{
				echo "the tarball would not unpack" >&2
				exit 1
			}
		[ -f "$tmp/zelynic" ] ||
			{
				echo "the tarball layout changed — no zelynic at its root" >&2
				exit 1
			}
		install -m 755 "$tmp/zelynic" "$LEGACY_BIN" ||
			{
				echo "could not install into $LEGACY_DIR" >&2
				exit 1
			}
	)
	local rc=$?
	rm -rf "$tmp"
	return "$rc"
}

ensure_legacy() {
	if [ -x "$LEGACY_BIN" ]; then
		echo ">> legacy already at $LEGACY_BIN ($("$LEGACY_BIN" -V 2>/dev/null | head -1))"
		return 0
	fi
	command -v curl >/dev/null 2>&1 || die "curl not found — the legacy download is a real transfer"
	command -v sha512sum >/dev/null 2>&1 || die "sha512sum not found — the checksum IS the trust"
	command -v tar >/dev/null 2>&1 || die "tar not found"
	mkdir -p "$LEGACY_DIR"
	echo ">> legacy $LEGACY_VERSION not at $LEGACY_BIN — downloading from the release page ..."
	download_and_install || die "the legacy download failed — see the reason above"
	echo ">> legacy installed: $LEGACY_BIN ($("$LEGACY_BIN" -V 2>/dev/null | head -1))"
}

run_leg() {
	local label="$1" bin="$2" log="$3"
	echo ""
	echo "━━━ $label ━━━"
	echo "    binary:  $bin"
	echo "    version: $("$bin" -V 2>/dev/null | head -1 || echo unknown)"
	echo "    args:    ${HARNESS_ARGS[*]}"
	echo ""
	"$SCRIPT_DIR/quota-saver-ab.sh" --binary "$bin" "${HARNESS_ARGS[@]}" | tee "$log"
}

pct_of() {
	# The run's contract verdict line -> its booked percentage, or
	# n/a when the run refused before the verdict (never a guess).
	local value=""
	value="$(grep -m1 "^test $2 results the internet kuota save total is " "$1" 2>/dev/null |
		grep -oE '[0-9]+\.[0-9]+' | tail -1)" || true
	echo "${value:-n/a}"
}

compare() {
	local dl_latest dl_legacy ul_latest ul_legacy
	dl_latest="$(pct_of "$LATEST_LOG" download)"
	dl_legacy="$(pct_of "$LEGACY_LOG" download)"
	ul_latest="$(pct_of "$LATEST_LOG" upload)"
	ul_legacy="$(pct_of "$LEGACY_LOG" upload)"
	echo ""
	echo "━━━ the comparison — latest vs legacy, same rate ━━━"
	echo "  the four numbers are the two runs' ledger bookings (the harness's"
	echo "  own contract verdict lines — counterfactual, not wire); each run's"
	echo "  per-leg wire ground truth lives in its log:"
	echo "    $LATEST_LOG"
	echo "    $LEGACY_LOG"
	echo "  download: latest ${dl_latest}% vs legacy ${dl_legacy}%"
	echo "  upload:   latest ${ul_latest}% vs legacy ${ul_legacy}%"
	if [[ "$dl_latest" =~ ^[0-9.]+$ ]] && [[ "$dl_legacy" =~ ^[0-9.]+$ ]]; then
		awk -v a="$dl_latest" -v b="$dl_legacy" \
			'BEGIN { printf "  the saver edition books %.2f percentage points more on download\n", a - b }'
	fi
	if [[ "$ul_latest" =~ ^[0-9.]+$ ]] && [[ "$ul_legacy" =~ ^[0-9.]+$ ]]; then
		awk -v a="$ul_latest" -v b="$ul_legacy" \
			'BEGIN { printf "  the saver edition books %.2f percentage points more on upload\n", a - b }'
	fi
	echo "  the booked delta is the claim to defend on the wire — the overrun"
	echo "  leg's block in each log is where an eager sender prices it."
}

main() {
	[ "$(id -u)" -eq 0 ] || die "this proof programs the kernel datapath — run with sudo"
	local latest
	latest="$(resolve_latest)"
	ensure_legacy

	run_leg "run 1 of 2 — the latest zelynic (the saver edition)" "$latest" "$LATEST_LOG"
	echo ""
	echo ">> cleanup between runs: $latest u --all (the LATEST binary owns the teardown)"
	"$latest" u --all || die "the between-runs cleanup failed — refusing to start the legacy run against a dirty kernel"

	run_leg "run 2 of 2 — the legacy release (the pre-saver edition)" "$LEGACY_BIN" "$LEGACY_LOG"
	echo ""
	echo ">> final cleanup: $latest u --all"
	"$latest" u --all || die "the final cleanup failed — check zelynic status before anything else"

	compare
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi
