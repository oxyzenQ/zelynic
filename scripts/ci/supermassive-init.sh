#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# The supermassive init (NIGHT-improve-31, the CI half; the kernel
# span + dynamic envelopes are NIGHT-improve-33): PID 1 inside the
# micro-VM booted by .github/workflows/supermassive.yml — the
# consolidation of the whole E2E estate. The retired pair — e2e.yml
# (the hosted-runner pipeline whose images no longer boot a 5.x
# kernel) and e2e-kernel-floor.yml (the probe-only micro-VM) — both
# live on here: the bring-up half of the pipeline runs on the runner
# (scripts/setup.sh --skip-heavy --musl, the exact owner-facing
# phase one, outside the VM because a low-specs guest cannot
# host a Rust toolchain build), and THIS script is the other half —
# the stresstest, from the lean prelude to the supermassive v1
# limiter matrix and the v2 survival battery, inside the resource
# envelope the job's profile DERIVES from the runner at boot time
# (NIGHT-improve-33, the owner's "cpu core, ram, etc don't set fixed
# let dynamic"; the minimum name itself is retired — NIGHT-blade-3
# renames the small envelope low): low specs = a quarter of the
# cores floored at 1 + an eighth of the RAM floored at 1024 MB;
# best specs = every core + three quarters of the RAM — the two
# ends of the machines zelynic promises to run on, scaling
# with the runner era instead of pinning one). The kernel is the
# pair's other variable: the low leg boots the TRUE documented
# floor (impish 5.13, docs/KERNEL_COMPATIBILITY.md), the best leg
# boots the archive's latest (resolved dynamically at run time),
# and the same userland (the ubuntu:22.04 container) serves both.
#
# NIGHT-blade-12: the envelope pair crossed with the payload's
# libc — the matrix is now {low, best} x {gnu, musl} and this init
# runs once per leg with ITS payload at /opt/zelynic/zelynic. The
# rootfs assembly writes /opt/zelynic/PAYLOAD-FLAVOR ("gnu" or
# "musl") beside the binary, and the probe rows below name it, so
# a four-leg matrix's serial log always says which libc it proved
# (the gnu legs ride a ubuntu:24.04 rootfs — same-distro as the
# runner that built the dynamic flagship; the musl legs keep the
# frozen ubuntu:22.04 userland). A missing marker is a rootfs
# assembly bug and shows as "unknown" — visible in the verdict
# lines, never silent.
#
# Contract: one MASS-RESULT line per probe plus a final
# MASS-VERDICT line, all on the serial console (the workflow's
# Verdict step greps these sentinels; the VM cannot relay exit
# codes through qemu, the sentinel lines ARE the relay — the
# kernel-floor contract, kept verbatim). The battery inventory is
# canonical invocations only (the e2e house rule): the binary's -V
# + doctor, the engine self-test, then BOTH full engines with
# --binary pinned — never a bespoke assertion that could drift
# from the harness the owner runs locally. The realnet lane
# self-skips (no network in the micro-VM — loopback only, the
# documented SKIP row), so the loopback matrix carries the limiter
# proof on the floor kernel.
#
# PID-1 rules (the kernel-floor lessons, kept): no systemd here —
# this script owns every mount; it must NEVER exit without ending
# the VM, and the exit rides qemu's isa-debug-exit port device
# (reboot(2) poweroff silently no-ops in a direct-boot guest) —
# see guest_exit.

set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

FAILURES=0

note() {
	echo "MASS-RESULT: $1 — $2"
	if [ "$2" != "PASS" ]; then
		FAILURES=$((FAILURES + 1))
	fi
}

guest_exit() {
	# The deterministic VM exit (the kernel-floor run-4 lesson):
	# qemu's isa-debug-exit device ends the VM the moment one
	# byte lands on port 0xf4; /dev/port is the root-writable
	# port-I/O window (seek = the port number), and the written
	# value 0 makes qemu exit with status 1 — the rc the
	# workflow's boot step accepts as the guest's deliberate
	# exit, the MASS-* sentinel lines being the verdict.
	printf '\x00' | dd of=/dev/port bs=1 seek=244 count=1 2>/dev/null || true
	# Belts, in order: the raw poweroff syscall (if this guest
	# ever grows an ACPI S5 path), then the sleep loop (never
	# spin the runner's budget — the outer timeout owns the
	# last resort).
	python3 -c 'import os; os.sync(); os.reboot(os.LINUX_REBOOT_CMD_POWER_OFF)' 2>/dev/null || true
	while true; do sleep 60; done
}

Z=/opt/zelynic
if ! cd "$Z"; then
	# A PID 1 must never plain-exit (the guest would panic-wedge):
	# exit through the port device with the verdict already naming
	# the failure.
	echo "MASS-VERDICT: FAIL (cannot cd $Z — rootfs assembly bug)"
	guest_exit
fi

# ── the kernel surfaces, before anything that needs them ──────────────
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs dev /dev
exec >/dev/console 2>&1
echo "MASS: init on $(uname -r)"

# The floor itself — the whole reason this VM exists. Numeric since
# NIGHT-improve-33: the low leg boots the TRUE documented floor
# (impish 5.13.0-52) and the best leg boots the archive's latest
# (whatever the dynamic resolver found), so one check serves both
# ends of the span: uname -r's major.minor must sit at or above
# 5.13, the verified matrix's floor (docs/KERNEL_COMPATIBILITY.md).
kver=$(uname -r)
major=${kver%%.*}
minor=$(echo "$kver" | cut -d. -f2 | grep -oE '^[0-9]+' || echo 0)
if [ "${major:-0}" -gt 5 ] || { [ "${major:-0}" -eq 5 ] && [ "${minor:-0}" -ge 13 ]; }; then
	note "kernel $kver (the 5.13+ verified floor)" PASS
else
	note "kernel (uname -r = $kver, wanted >= 5.13)" FAIL
fi

# Everything the batteries need (PID 1 owns them all): tmpfs scratch
# (the engines' work dirs AND the /run/zelynic lock), cgroup v2 (the
# limiter's cgroup mkdirs need no controllers), bpffs (the pin
# surface), devpts (the v2 pty batteries), loopback (the v1 traffic
# lane — the realnet lane self-skips, the documented row).
if mount -t tmpfs tmp /tmp &&
	mount -t tmpfs run /run &&
	mkdir -p /sys/fs/cgroup /sys/fs/bpf /dev/pts &&
	mount -t cgroup2 none /sys/fs/cgroup &&
	mount -t bpf bpf /sys/fs/bpf &&
	mount -t devpts devpts /dev/pts &&
	ip link set lo up; then
	note "kernel surfaces (proc, sysfs, devtmpfs, cgroup2, bpffs, devpts, loopback)" PASS
else
	note "kernel surfaces" FAIL
fi

# ── the lean prelude: the binary runs, the bpf syscall answers ───────
# The payload flavor names itself in the probe rows (NIGHT-blade-12):
# the rootfs assembly wrote /opt/zelynic/PAYLOAD-FLAVOR beside the
# binary this init is about to exercise. "unknown" means the marker
# never landed — a rootfs assembly bug, visible in the log, never
# silent; the probe's PASS/FAIL verdict rides the binary, not the
# marker.
FLAVOR="unknown"
if [ -r "$Z/PAYLOAD-FLAVOR" ]; then
	FLAVOR=$(tr -d '[:space:]' <"$Z/PAYLOAD-FLAVOR")
fi
echo "MASS: payload flavor: $FLAVOR"
if ./zelynic -V >/dev/null 2>&1; then
	note "zelynic -V ($FLAVOR payload + CPU match)" PASS
else
	note "zelynic -V ($FLAVOR payload + CPU match)" FAIL
fi
if ./zelynic doctor; then
	note "doctor (bpf syscall on the floor)" PASS
else
	note "doctor (bpf syscall on the floor)" FAIL
fi

# The engine smoke (rootless, canonical) — the harness itself is
# sound inside this userland before either full battery runs.
if python3 scripts/supermassive/supermassive-test.py --self-test; then
	note "supermassive engine self-test" PASS
else
	note "supermassive engine self-test" FAIL
fi

# The emergency rescue smoke (NIGHT-improve-31's terminal half): the
# rescue runs clean on the floor kernel and exits 0 — as PID 1 there
# is no interposer and no parent, so this proves the classic path's
# exit shape, not the sudo lane (whose proof is the pin family plus
# the live harness, recorded in SAFETY_ANALYSIS).
if ./zelynic --reset-terminal; then
	note "zelynic --reset-terminal (exit 0 on the floor)" PASS
else
	note "zelynic --reset-terminal (exit 0 on the floor)" FAIL
fi

# ── the stresstest: BOTH full engines, canonical invocations ─────────
# v1, the limiter matrix (the e2e pipeline's phase two): the
# NIGHT-blade-4 server phase FIRST (headless report surfaces under
# PATH + TERM=dumb, the dense 64-cgroup fleet censused and policed
# by one strict-multi write, daemonized traffic, concurrent report
# readers) gating the desktop matrix — every policy shape on the
# loopback lane (the realnet lane self-skips without an endpoint),
# the rate ladder, reload, sustain — attach, policy writes, MEASURED
# rates, accounting. A green row here is the "holds everywhere it
# claims" verdict, server shape included, on the leg's kernel,
# inside the profile's derived resource envelope.
if python3 scripts/supermassive/supermassive-test.py \
	--binary /opt/zelynic/zelynic; then
	note "supermassive v1 - limiter matrix (full, server-first)" PASS
else
	note "supermassive v1 - limiter matrix (full, server-first)" FAIL
fi

# v2, the survival battery (the e2e pipeline's phase three, LAST per
# the qualification order): the NIGHT-blade-4 server phase FIRST
# (the guard family under the stripped headless environment — the
# exact stdio shape this PID-1 guest itself presents), then the
# 83-case CLI depth stresstest, the input guards, the SIGKILL
# batteries (live TUI mid-render on a pty, one-shot writers inside
# the attach/pin/write window), the post-kill regression re-proof,
# and the crash-family teardown (recover, cleanup, dmesg). A green
# row here is the "works under fire" verdict — the observer AND the
# violent-death guard on the leg's kernel (the floor or the latest
# head), the old kernel-floor probe's surface and more.
if python3 scripts/supermassive/supermassive-test-v2.py \
	--binary /opt/zelynic/zelynic; then
	note "supermassive v2 - survival battery (full, server-first)" PASS
else
	note "supermassive v2 - survival battery (full, server-first)" FAIL
fi

# ── the claims proof, LIVE on this leg's kernel (NIGHT-lts-6) ─────────
# The four-plus-one headline claims proven with root on the exact
# kernel this leg booted (canonical invocation, --quick windows):
# no-daemon, pure-eBPF, per-app, precision 0.00%, and the footprint
# claim — the CLI's own RAM/CPU/IO plus the attached programs'
# kernel run time. Every push's supermassive run is now also a
# live claims audit; the full owner-facing flow stays
# `sudo ./scripts/bench/proof-claims.sh` on the host.
if python3 scripts/bench/proof-claims.py \
	--quick --binary /opt/zelynic/zelynic; then
	note "claims proof (live, quick)" PASS
else
	note "claims proof (live, quick)" FAIL
fi

# ── the verdict ───────────────────────────────────────────────────────
if [ "$FAILURES" -eq 0 ]; then
	echo "MASS-VERDICT: PASS"
else
	echo "MASS-VERDICT: FAIL ($FAILURES probe(s) failed)"
fi
guest_exit
