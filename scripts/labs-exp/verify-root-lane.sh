#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# The root-lane verification battery for the night-total-hardening-1
# fixes — the seven post-privilege shapes the sibling guide,
# VERIFY_LOCAL_HARDENING_1.md (Step 2), documents, pinned against the
# BINARY ITSELF on a machine that meets the floor: root, kernel
# >= 5.15, cgroup v2 at /sys/fs/cgroup.
#
# Isolation law: the default battery writes NOTHING to the machine's
# enforcement state. Every row ends in a refusal, a hard error, or a
# read-only verdict — that IS the fix being pinned. The three rows
# that need a resolvable target ride a battery-owned probe cgroup
# (/sys/fs/cgroup/zelynic-root-lane-battery): created empty, never
# hosting a process, torn down by the EXIT trap even on Ctrl-C. The
# once-per-process warning's full demonstration — the apply at the
# root catch-all the forensic rig pins (scripts/sandbox/
# forensic-critical-sim.sh) — writes a real machine-wide policy for
# about a second, so it runs ONLY behind --apply-row and the same
# trap lifts it immediately.
#
# The root cgroup id is DISCOVERED per machine (the cgroupfs mount's
# own inode, `stat -c %i /sys/fs/cgroup` — often 1, never assumed),
# and the dead-id row rides 4294967200, just under u32::MAX: no real
# kernfs inode truncates to it, so the death is machine-independent
# proven and the row doubles as the boundary's other edge (the value
# flows past the 32-bit refusal the non-root battery pins).
#
# Usage:
#   sudo ./scripts/labs-exp/verify-root-lane.sh
#   sudo ./scripts/labs-exp/verify-root-lane.sh --apply-row
#   ZELYNIC_BIN=/usr/bin/zelynic sudo ./scripts/labs-exp/verify-root-lane.sh
#
# Exit 0 when every row passed, 1 on any failure. Pure English, no
# emoji — the repository is English-only (NIGHT-hunt-19).

set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=${ZELYNIC_BIN:-"$DIR/zelynic-fixed-cli-hardening-1"}
PASS=0
FAIL=0
SKIP=0
APPLY_ROW=0
PROBE_DIR="/sys/fs/cgroup/zelynic-root-lane-battery"
PROBE_MADE=0
PROBE_ID=""
ROOT_INO=""
ROOT_APPLIED=0
CAP="$(mktemp)"
RC=0
CLEANED=0
EXTRACTED_BIN=""

for arg in "$@"; do
	case "$arg" in
	--apply-row) APPLY_ROW=1 ;;
	*)
		echo "FAIL  unknown argument: $arg (the only flag is --apply-row)"
		exit 1
		;;
	esac
done

cleanup() {
	[ "$CLEANED" -eq 1 ] && return
	CLEANED=1
	if [ "$ROOT_APPLIED" -eq 1 ] && [ -n "$ROOT_INO" ]; then
		"$BIN" u "$ROOT_INO" >/dev/null 2>&1 && ROOT_APPLIED=0
		if [ "$ROOT_APPLIED" -eq 1 ]; then
			echo "NOTE  the root catch-all policy may still stand — lift it: sudo zelynic u $ROOT_INO" >&2
		fi
	fi
	if [ "$PROBE_MADE" -eq 1 ] && [ -n "$PROBE_ID" ]; then
		"$BIN" u "cg:$PROBE_ID" >/dev/null 2>&1
		rmdir "$PROBE_DIR" >/dev/null 2>&1
	fi
	rm -f "$CAP"
	if [ -n "$EXTRACTED_BIN" ]; then
		rm -rf -- "$(dirname "$EXTRACTED_BIN")"
	fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT TERM

# night-cafe-1 binary hygiene: the vendored fixed CLI ships as a gz
# package with checksum sidecars (the legacy-for-test vendoring
# precedent — raw binaries are never tracked), so a default-target run
# extracts the package into a private temp dir, verifies the pinned
# sha256, and tests the extracted copy; the EXIT trap removes the temp
# dir. An explicit ZELYNIC_BIN is never touched.
VENDORED_SHA256="7556c6272eb114709afc3059820c434302708c7033ce2e88d041b7b4d9b2fc66"
if [ ! -x "$BIN" ]; then
	if [ "${ZELYNIC_BIN:-}" = "" ] && [ -f "$DIR/zelynic-fixed-cli-hardening-1.gz" ]; then
		TMPBIN="$(mktemp -d)" || {
			echo "FAIL  vendored package staging failed (mktemp -d)"
			exit 1
		}
		gunzip -c "$DIR/zelynic-fixed-cli-hardening-1.gz" > "$TMPBIN/zelynic-fixed-cli-hardening-1" || {
			echo "FAIL  vendored package extraction failed: $DIR/zelynic-fixed-cli-hardening-1.gz"
			exit 1
		}
		got="$(sha256sum "$TMPBIN/zelynic-fixed-cli-hardening-1" | awk '{print $1}')"
		if [ "$got" != "$VENDORED_SHA256" ]; then
			echo "FAIL  vendored package sha256 mismatch: $got"
			echo "      expected: $VENDORED_SHA256 — refuse to test unverified bytes"
			exit 1
		fi
		chmod 755 "$TMPBIN/zelynic-fixed-cli-hardening-1"
		EXTRACTED_BIN="$TMPBIN/zelynic-fixed-cli-hardening-1"
		BIN="$EXTRACTED_BIN"
	else
		echo "FAIL  binary under test not executable: $BIN"
		echo "      ZELYNIC_BIN=<path> names another build, or build from source:"
		echo "      ./scripts/dev/bootstrap-ebpf.sh"
		exit 1
	fi
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "FAIL  the root-lane battery needs root — run: sudo $0"
	echo "      the non-root shapes ride the sibling battery: ./scripts/labs-exp/verify-cli-ux.sh"
	exit 1
fi

if [ "$(stat -f -c %T /sys/fs/cgroup 2>/dev/null)" != "cgroup2fs" ]; then
	echo "FAIL  /sys/fs/cgroup is not cgroup v2 — the root-lane floor (kernel >= 5.15, unified hierarchy)"
	exit 1
fi

ROOT_INO=$(stat -c %i /sys/fs/cgroup 2>/dev/null)
case "$ROOT_INO" in
'' | *[!0-9]*)
	echo "FAIL  cgroupfs root inode unreadable"
	exit 1
	;;
esac

echo "prep  binary under test: $("$BIN" -V 2>&1 | head -1)"
echo "prep  root cgroup id: $ROOT_INO (discovered, never assumed)"

rmdir "$PROBE_DIR" >/dev/null 2>&1
if mkdir "$PROBE_DIR" 2>/dev/null; then
	PROBE_MADE=1
	PROBE_ID=$(stat -c %i "$PROBE_DIR")
	echo "prep  probe cgroup: $PROBE_DIR (id $PROBE_ID, battery-owned, empty, never hosting a process)"
else
	echo "prep  probe cgroup could not be created — the three probe rows SKIP (the forensic rig owns them on a throwaway VM)"
fi

# Row 1 — the apply-side liveness gate (the audit's dead-id find): an
# id inside the u32 space flows past the boundary, the gate proves it
# against the cgroupfs census, and the no-match hard error names the
# dead target — exit 1, nothing limited, the blind OK gone.
"$BIN" s 4294967200 100kb >"$CAP" 2>&1
RC=$?
if [ "$RC" -eq 1 ] &&
	grep -qF "No cgroup found for '4294967200'" "$CAP" &&
	grep -qF "nothing was limited" "$CAP"; then
	echo "PASS  liveness gate: dead id named, nothing limited"
	PASS=$((PASS + 1))
else
	echo "FAIL  liveness gate: dead id named, nothing limited"
	echo "      rc: $RC"
	echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
	FAIL=$((FAIL + 1))
fi

# Row 2 — the block family's atomic list apply (the audit's 1011::11
# find, on a machine-independent spelling): one dead member beside one
# resolvable one (the probe) must refuse the WHOLE list, naming the
# miss beside the untouched remainder — nothing blocked.
if [ "$PROBE_MADE" -eq 1 ]; then
	"$BIN" b "4294967200::cg:$PROBE_ID" >"$CAP" 2>&1
	RC=$?
	if [ "$RC" -eq 1 ] &&
		grep -qF "resolved to no cgroup" "$CAP" &&
		grep -qF "the list apply is atomic, nothing was blocked" "$CAP" &&
		grep -qF "(1 of 2 targets were resolvable, 0 applied)" "$CAP"; then
		echo "PASS  atomic block refusal: miss named beside the resolvable remainder"
		PASS=$((PASS + 1))
	else
		echo "FAIL  atomic block refusal: miss named beside the resolvable remainder"
		echo "      rc: $RC"
		echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
		FAIL=$((FAIL + 1))
	fi
else
	echo "SKIP  atomic block refusal (no probe cgroup)"
	SKIP=$((SKIP + 1))
fi

# Row 3 — the strict family's atomic list apply with the honest MISS
# count (the audit's zylaxion::brave::noexist find): the dead segment
# is NAMED, the resolvable one (the probe) stays untouched, and the
# verdict reports the whole transaction — nothing limited.
if [ "$PROBE_MADE" -eq 1 ]; then
	"$BIN" s "cg:$PROBE_ID::zylaxion-ghost" 1mb >"$CAP" 2>&1
	RC=$?
	if [ "$RC" -eq 1 ] &&
		grep -qF "zylaxion-ghost" "$CAP" &&
		grep -qF "the list apply is atomic, nothing was limited" "$CAP" &&
		grep -qF "(1 of 2 targets were resolvable, 0 applied)" "$CAP"; then
		echo "PASS  atomic strict refusal: honest MISS, resolvable half untouched"
		PASS=$((PASS + 1))
	else
		echo "FAIL  atomic strict refusal: honest MISS, resolvable half untouched"
		echo "      rc: $RC"
		echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
		FAIL=$((FAIL + 1))
	fi
else
	echo "SKIP  atomic strict refusal (no probe cgroup)"
	SKIP=$((SKIP + 1))
fi

# Row 4 — the honest removal tail (the owner's u zylaxion::... find):
# the setup applies a real limit to the battery-owned probe cgroup
# (nothing else on the machine), then the mixed removal must count
# only the target that actually had limits ("across 1 target") and
# name the ghost member in the grey tail — the old shape claimed the
# whole list while members that matched nothing vanished silently.
if [ "$PROBE_MADE" -eq 1 ]; then
	"$BIN" s "cg:$PROBE_ID" 1mb --no-test >"$CAP" 2>&1
	RC=$?
	if [ "$RC" -eq 0 ]; then
		"$BIN" u "cg:$PROBE_ID::zylaxion-ghost" >"$CAP" 2>&1
		RC=$?
		if [ "$RC" -eq 0 ] &&
			grep -qF "across 1 target from" "$CAP" &&
			grep -qF "no active limits for 'zylaxion-ghost'" "$CAP"; then
			echo "PASS  honest removal tail: count names the real match, ghost named"
			PASS=$((PASS + 1))
		else
			echo "FAIL  honest removal tail: count names the real match, ghost named"
			echo "      rc: $RC"
			echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
			FAIL=$((FAIL + 1))
		fi
	else
		echo "FAIL  honest removal tail: the probe setup apply did not land"
		echo "      rc: $RC"
		echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
		FAIL=$((FAIL + 1))
	fi
else
	echo "SKIP  honest removal tail (no probe cgroup)"
	SKIP=$((SKIP + 1))
fi

# Row 5 — the root catch-all's refusal arm (NIGHT-hunt-Z3): a target
# that IS the cgroupfs root answers with the blast-radius wording and
# the --force-this tip, exit 1, nothing written. The forced arm (the
# once-per-process warning the forensic rig pins) rides --apply-row.
"$BIN" s "$ROOT_INO" 1mb >"$CAP" 2>&1
RC=$?
if [ "$RC" -eq 1 ] &&
	grep -qF "is the root cgroup (cg:$ROOT_INO)" "$CAP" &&
	grep -qF "tip: re-run with --force-this" "$CAP"; then
	echo "PASS  root catch-all: blast-radius refusal, force tip, nothing written"
	PASS=$((PASS + 1))
else
	echo "FAIL  root catch-all: blast-radius refusal, force tip, nothing written"
	echo "      rc: $RC"
	echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
	FAIL=$((FAIL + 1))
fi

# Row 5b — the once-per-process gate, the forensic rig's own row
# (forensic-critical-sim.sh): the forced apply at the root catch-all
# runs BOTH guards that answer the root, and the fix makes the second
# rung silent — the warning prints exactly once while the apply lands.
# OPT-IN because it writes a real machine-wide 1mb policy; the EXIT
# trap lifts it immediately (about a one-second window).
if [ "$APPLY_ROW" -eq 1 ]; then
	echo "NOTE  --apply-row: writing the 1mb catch-all at the root cgroup ($ROOT_INO), lifting it immediately — about a one-second machine-wide window, the forensic rig's own row"
	ROOT_APPLIED=1
	"$BIN" s "$ROOT_INO" 1mb --no-test --force-this >"$CAP" 2>&1
	RC=$?
	WARNS=$(grep -cF "is the root cgroup" "$CAP")
	if [ "$RC" -eq 0 ] && [ "$WARNS" -eq 1 ]; then
		echo "PASS  root catch-all: forced warning prints once, apply lands (the once-per-process gate)"
		PASS=$((PASS + 1))
	else
		echo "FAIL  root catch-all: forced warning prints once, apply lands"
		echo "      rc: $RC, warning count: $WARNS"
		echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
		FAIL=$((FAIL + 1))
		# A failed apply is all-or-nothing (the rollback law): nothing
		# landed, so the trap must not hunt for a standing policy.
		[ "$RC" -eq 0 ] || ROOT_APPLIED=0
	fi
	"$BIN" u "$ROOT_INO" >"$CAP" 2>&1
	RC=$?
	if [ "$RC" -eq 0 ] && grep -qF "Removed" "$CAP"; then
		ROOT_APPLIED=0
		echo "PASS  root catch-all: teardown lifted the policy clean"
		PASS=$((PASS + 1))
	else
		echo "FAIL  root catch-all: teardown — lift it by hand: sudo zelynic u $ROOT_INO"
		echo "      rc: $RC"
		echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
		FAIL=$((FAIL + 1))
	fi
fi

# Row 6 — the eagle-eyes separator tip (the audit's no-match guess):
# a '::' spec on the depth lane is the WRONG separator grammar, and
# the tip now names the right one instead of leaving the operator
# guessing. Read-only.
"$BIN" ee "zylaxion::brave" >"$CAP" 2>&1
RC=$?
if [ "$RC" -eq 1 ] &&
	grep -qF "separate with '/'" "$CAP" &&
	grep -qF "nothing to watch" "$CAP"; then
	echo "PASS  ee '::' spec: the '/' separator tip names the fix"
	PASS=$((PASS + 1))
else
	echo "FAIL  ee '::' spec: the '/' separator tip names the fix"
	echo "      rc: $RC"
	echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
	FAIL=$((FAIL + 1))
fi

# Row 7 — the verb carries the family (the block family joining the
# atomic contract): a block-family abort says "nothing was BLOCKED",
# never the strict family's "limited" — the old line claimed the
# wrong action.
"$BIN" b "zylaxion::noexist" >"$CAP" 2>&1
RC=$?
if [ "$RC" -eq 1 ] &&
	grep -qF "nothing was blocked" "$CAP" &&
	! grep -qF "nothing was limited" "$CAP"; then
	echo "PASS  block family carries its verb: nothing was blocked, never limited"
	PASS=$((PASS + 1))
else
	echo "FAIL  block family carries its verb: nothing was blocked, never limited"
	echo "      rc: $RC"
	echo "      got: $(head -4 "$CAP" | tr '\n' '|')"
	FAIL=$((FAIL + 1))
fi

echo "----"
echo "battery: $PASS passed, $FAIL failed, $SKIP skipped"
[ "$FAIL" -eq 0 ]
