#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: AGPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# The E2E depth-stresstest's HOST-NATIVE twin (the arm64 rung of
# night-dragon-maintenance-2's lane): the driver of the arm64 variant
# in .github/workflows/supermassive-e2e.yml, running the IDENTICAL
# five-suite depth contract directly on the runner host — no
# micro-VM. e2e-init.sh stays the guest side of the x86 legs; this
# twin exists because the platform gives arm CI no guest to boot.
#
# Why the arm64 leg cannot ride the micro-VM contract: GitHub's
# arm64 hosted fleet exposes no /dev/kvm at any tier
# (actions/runner-images#14062, maintainer answer: the underlying
# Azure Arm SKU surfaces no nested KVM device, and the only path to
# a KVM arm64 guest is a bare-metal self-hosted runner). The
# remaining "VM" option is TCG software emulation — rejected on
# contract grounds, not convenience: a 10-20x slowdown under
# emulated clocks is garbage in, garbage out for a realtime depth
# suite whose subject IS the pacer's hrtimer fidelity. The honest
# arm64 variant is the runner itself: a real arm64 Linux host
# (kernel >= 6.8, cgroup v2, root), exactly the owner-local mode
# the five depth suites were built for before the lane wired them
# into CI.
#
# The payload contract mirrors the lane's from-source law on the
# arm64 shape: the workflow builds the pro-native-arm64-musl alias
# (the arm64 twin of the flagship local build) FRESH IN-JOB and
# passes the absolute artifact path via --binary. Fresh-in-job is
# load-bearing: the artifact carries -C target-cpu=native, so a
# target tree restored from a cache built on a different arm
# silicon generation is the SIGILL lottery ci.yml's arm rung
# retired — and this leg EXECUTES the binary. The leg's cache
# therefore stops at the registry (arch-neutral sources), never
# the target tree; within one job the build and the execution
# share the same silicon, so the native artifact is always safe.
#
# Deltas from the guest init (each deliberate, each the host's
# jurisdiction, never the suite's):
#   - surfaces: the host owns the mounts (proc, sysfs, cgroup2,
#     bpffs, devpts) and the egress; this twin VERIFY-fails-loudly
#     on the surfaces the suites need instead of mounting them —
#     a CI runner is a shared host, never a PID-1 sandbox.
#   - relay: the same E2E-RESULT / E2E-VERDICT sentinel lines keep
#     every leg's log grep-uniform, and the twin adds the one
#     honesty a qemu guest cannot carry — a real exit code
#     (0 = PASS, 1 = any red row), which the workflow's step gates.
#   - envelope: no SMP/RAM split (the suites get the whole host,
#     the shape the best-spec leg's dynamic envelope lands on a
#     4-vCPU runner); the wedge-guard outer bound rides the
#     workflow's timeout around this script, as the VM legs' bound
#     rides the qemu process.
set -u

FAILURES=0
note() {
	echo "E2E-RESULT: $1 — $2"
	if [ "$2" != "PASS" ]; then
		FAILURES=$((FAILURES + 1))
	fi
}

usage() {
	echo "usage: $0 --binary PATH [--suite fast|surface|endurance|all]" >&2
	exit 2
}

BINARY=""
SUITE="all"
while [ $# -gt 0 ]; do
	case "$1" in
	--binary)
		[ $# -ge 2 ] || usage
		BINARY=$2
		shift 2
		;;
	--suite)
		# The shard selector (night-T-1): the workflow's stage job
		# builds the payload once; each arm64 shard boots nothing and
		# names its slice here. "all" keeps the pre-split behavior
		# (the canonical five, in order). An unknown value fails
		# LOUDLY — a selector typo can never silently shallow a leg.
		[ $# -ge 2 ] || usage
		SUITE=$2
		shift 2
		;;
	*)
		usage
		;;
	esac
done
[ -n "$BINARY" ] || usage
case "$SUITE" in
fast | surface | endurance | all) ;;
*)
	echo "E2E: --suite '$SUITE' is not one of fast|surface|endurance|all" >&2
	exit 2
	;;
esac
[ -x "$BINARY" ] || {
	echo "E2E: --binary $BINARY is not an executable" >&2
	exit 2
}

# The repo root (the rigs' cwd law: every suite runs from the
# checkout root — the guest's $Z equivalent).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || {
	echo "E2E: cannot locate the script directory" >&2
	exit 2
}
Z="$(cd "$SCRIPT_DIR/../.." && pwd)" || {
	echo "E2E: cannot locate the repo root" >&2
	exit 2
}
cd "$Z" || exit 2

echo "E2E: native host run on $(uname -r) ($(uname -m))"

# ── the floor itself, verbatim law ─────────────────────────────────────
# Numeric (the guest init's shape): uname -r's major.minor must sit
# at or above 5.15, the verified matrix's floor since
# night-netrunner-1 (docs/KERNEL_COMPATIBILITY.md).
kver=$(uname -r)
major=${kver%%.*}
minor=$(echo "$kver" | cut -d. -f2 | grep -oE '^[0-9]+' || echo 0)
if [ "${major:-0}" -gt 5 ] || { [ "${major:-0}" -eq 5 ] && [ "${minor:-0}" -ge 15 ]; }; then
	note "kernel $kver (the 5.15+ verified floor)" PASS
else
	note "kernel (uname -r = $kver, wanted >= 5.15)" FAIL
fi

# ── the kernel surfaces, verified (never mounted — the host owns them) ─
# cgroup v2 unified (the rigs' own cgroup mkdirs), bpffs (the pin
# surface), loopback (the traffic lanes), devpts (the monitor pty
# soak). The workflow's prepare step ensures bpffs idempotently; a
# red row here means the HOST is not a zelynic host — loud, never
# silently shallow.
if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" ] &&
	mountpoint -q /sys/fs/bpf &&
	ip -o link show lo | grep -qE '<[^>]*\bUP\b' &&
	test -d /dev/pts; then
	note "kernel surfaces (cgroup2, bpffs, loopback, devpts — verified, host-owned)" PASS
else
	note "kernel surfaces" FAIL
fi

# ── the lean prelude: the binary is the one the workflow built ─────────
# The payload shape names itself (the -V line's Build: token — the
# pro-native-arm64-musl alias the workflow's own label gate already
# pinned; "unknown" means a foreign binary was handed in, visible
# in the log, never silent).
SHAPE=$("$BINARY" -V 2>/dev/null | sed -n 's/.*Build: \([^ ]*\).*/\1/p' | head -1)
echo "E2E: payload shape: ${SHAPE:-unknown}"
# The BINARY GATE (the harness law, USAGE's stale-binary incident):
# the binary's -V must carry the checkout's own version, so a stale
# artifact can never masquerade as the build under test.
WANT=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$Z/Cargo.toml" | head -1)
GOT=$("$BINARY" -V 2>/dev/null | head -1 || true)
if [ -n "$WANT" ] && printf '%s' "$GOT" | grep -qF "$WANT"; then
	note "binary gate (-V carries the checkout's $WANT)" PASS
else
	note "binary gate (-V '$GOT' vs checkout $WANT)" FAIL
fi
if "$BINARY" doctor >/dev/null 2>&1; then
	note "doctor (bpf syscall answers on this kernel)" PASS
else
	note "doctor (bpf syscall answers on this kernel)" FAIL
fi

echo "E2E: suite selector: $SUITE (fast = nonroot + limiter, surface = smoke + quota, endurance = the LTS clocks)"

# ── the suite: the identical five canonical invocations, USER leg first
# 1. The USER-mode leg (the unprivileged contract): the full command
#    surface as an unprivileged user — setpriv into nobody's uid/gid
#    from a writable cwd. The rig REFUSES euid 0 by design (it pins
#    what an unprivileged user sees), so the setpriv drop is the
#    contract, not a workaround.
case "$SUITE" in
fast | all)
	if (cd /tmp && setpriv --reuid=65534 --regid=65534 --clear-groups \
		"$Z/scripts/depth/nonroot-depth-test.sh" --binary "$BINARY"); then
		note "USER leg - nonroot depth suite (the unprivileged contract)" PASS
	else
		note "USER leg - nonroot depth suite (the unprivileged contract)" FAIL
	fi
	# 2. The realtime depth stresstest (the owner's words), FULL depth —
	#    the budget buys headroom, never depth.
	if "$Z/scripts/depth/limiter-depth-test.sh" --binary "$BINARY"; then
		note "ROOT leg - limiter depth stresstest (full, measured + cross-checked)" PASS
	else
		note "ROOT leg - limiter depth stresstest (full, measured + cross-checked)" FAIL
	fi
	;;
esac
# 3. The LTS clocks, FULL depth: the map-slot churn amplification
#    (any group-slot leak exhausts the 256 cap and fails loudly) plus
#    the monitor's pty soak (no unbounded collection, no fd leak).
#    The 300-cycle campaign exists to cross the 256-slot boundary —
#    it runs WHOLE or not at all (night-T-1: the nightly schedule's
#    own shard), never sharded, never shortened.
case "$SUITE" in
endurance | all)
	if "$Z/scripts/depth/endurance-test.sh" --binary "$BINARY"; then
		note "ROOT leg - endurance clocks (full churn + monitor soak)" PASS
	else
		note "ROOT leg - endurance clocks (full churn + monitor soak)" FAIL
	fi
	;;
esac
# 4. The whole CLI surface as root: every verb, every guard, real
#    policing against the unlimited baseline, leak postconditions,
#    the unprivileged refusal row.
case "$SUITE" in
surface | all)
	if "$Z/scripts/sandbox/smoke-cli.sh" --binary "$BINARY"; then
		note "ROOT leg - CLI surface smoke (every verb, every guard)" PASS
	else
		note "ROOT leg - CLI surface smoke (every verb, every guard)" FAIL
	fi
	;;
esac

# 5. The quota saver's A/B proof (night-netrunner-4): scenario A
#    (zelynic) against the legacy drop-based counterfactual — the
#    same real download and upload twice over one virtual 100 MB
#    ledger, the two exact contract lines. The runner's real egress
#    plays the SLIRP lane's role here; a mirror hiccup or an honest
#    refusal is a SKIP row (it never reddens the verdict); a run
#    that claims success without both lines is a contract breach
#    and FAILs.
case "$SUITE" in
surface | all)
	QUOTA_LOG=/tmp/quota-ab.log
	if "$Z/scripts/bench/quota-saver-ab.sh" --binary "$BINARY" >"$QUOTA_LOG" 2>&1; then
		cat "$QUOTA_LOG"
		if grep -q '^test download results the internet kuota save total is ' "$QUOTA_LOG" &&
			grep -q '^test upload results the internet kuota save total is ' "$QUOTA_LOG"; then
			note "ROOT leg - quota saver A/B (the two exact contract lines)" PASS
		else
			note "ROOT leg - quota saver A/B (run claimed but the lines are missing)" FAIL
		fi
	else
		cat "$QUOTA_LOG" >&2 || true
		echo "E2E-RESULT: ROOT leg - quota saver A/B — SKIP (the internet lane never reddens the kernel-floor legs)"
	fi
	rm -f "$QUOTA_LOG"
	;;
esac

# ── the verdict relay ──────────────────────────────────────────────────
# The same sentinel contract every leg carries, plus the native
# exit code (the guest cannot pass exit codes through qemu; the
# host can, and the workflow's step gates on it).
if [ "$FAILURES" -eq 0 ]; then
	echo "E2E-VERDICT: PASS"
	exit 0
fi
echo "E2E-VERDICT: FAIL ($FAILURES row(s) red)"
exit 1
