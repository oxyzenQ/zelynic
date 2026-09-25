#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# The kernel-floor probe init (NIGHT-improve-29): PID 1 inside the
# 5.15 micro-VM booted by .github/workflows/e2e-kernel-floor.yml —
# the KVM answer to "how do we keep proving the 5.15 floor without a
# self-hosted runner" (containers share the host kernel, so the
# ubuntu:22.04 container supplies the USERLAND and QEMU+KVM supplies
# the KERNEL; this script is what runs on that kernel).
#
# Contract: one FLOOR-RESULT line per probe plus a final
# FLOOR-VERDICT line, all on the serial console (qemu -nographic
# relays every byte to the CI log — the workflow's Verdict step
# greps these sentinels; the VM cannot relay exit codes through
# qemu, the sentinel lines ARE the relay). The probe inventory is
# canonical invocations only (the e2e house rule): uname -r, the
# binary's -V + doctor, the supermassive engine self-test, the
# limiter depth battery --quick, and the v2 kill-tui pattern on a
# pty for the observer + the violent-death guard.
#
# PID-1 rules: no systemd here — this script owns every mount; it
# must NEVER exit without powering off (a PID 1 that exits wedges
# the guest into a panic), and the poweroff uses python's os.reboot
# because a container-derived rootfs carries no init-system
# poweroff binary by definition (python3 is guaranteed: the VM
# assembly installs it).

set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

FAILURES=0

note() {
	echo "FLOOR-RESULT: $1 — $2"
	if [ "$2" != "PASS" ]; then
		FAILURES=$((FAILURES + 1))
	fi
}

halt_now() {
	# PID 1 powers off via the raw syscall (see the header): python3
	# is guaranteed in this rootfs, init-system poweroff binaries are
	# not. sync first — discipline, not need (everything is tmpfs).
	python3 -c 'import os; os.sync(); os.reboot(os.LINUX_REBOOT_CMD_POWER_OFF)'
	# Unreachable when the syscall works; a belt for a python that
	# refuses (never spin the 25-minute CI budget).
	while true; do sleep 60; done
}

Z=/opt/zelynic
if ! cd "$Z"; then
	# A PID 1 must never plain-exit (the guest would panic-wedge):
	# power off through the raw syscall with the verdict already
	# naming the failure.
	echo "FLOOR-VERDICT: FAIL (cannot cd $Z — rootfs assembly bug)"
	halt_now
fi

# ── the kernel surfaces, before anything that needs them ──────────────
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs dev /dev
exec >/dev/console 2>&1
echo "FLOOR: init on $(uname -r)"

# The floor itself — the whole reason this VM exists.
case "$(uname -r)" in
5.15.*) note "kernel $(uname -r) (the 5.15 floor)" PASS ;;
*) note "kernel (uname -r = $(uname -r), wanted 5.15.*)" FAIL ;;
esac

# Everything the batteries need (PID 1 owns them all): tmpfs scratch,
# cgroup v2 (the limiter's cgroup mkdirs need no controllers), bpffs
# (the pin surface), devpts (the eagle-eyes pty probe), loopback (the
# depth battery's traffic lane).
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

# ── the binary: runs at all, then the capability probe ───────────────
if ./zelynic -V >/dev/null 2>&1; then
	note "zelynic -V (glibc + CPU match)" PASS
else
	note "zelynic -V (glibc + CPU match)" FAIL
fi
if ./zelynic doctor; then
	note "doctor (bpf syscall on 5.15)" PASS
else
	note "doctor (bpf syscall on 5.15)" FAIL
fi

# ── the harness engine smoke (rootless, canonical) ───────────────────
if python3 scripts/supermassive/supermassive-test.py --self-test; then
	note "supermassive engine self-test" PASS
else
	note "supermassive engine self-test" FAIL
fi

# ── the flagship depth battery (root, real BPF enforcement) ──────────
# --quick: the same cross-distro instrument CROSS_DISTRO results ride
# — attach, policy writes, MEASURED rates, accounting, reload. The
# strongest single proof of the floor.
if python3 scripts/depth/limiter-depth-test.py --quick \
	--binary /opt/zelynic/zelynic; then
	note "limiter depth battery (--quick)" PASS
else
	note "limiter depth battery (--quick)" FAIL
fi

# ── the observer + the violent-death guard, the v2 kill-tui way ──────
# Spawn eagle-eyes on a pty (supermassive-test-v2's _spawn_tui_on_pty
# pattern), prove frames render under a live session, SIGKILL
# mid-render, then require the guard child's ALT_EXIT restore bytes on
# the pty — both the observer's 5.15 load AND boost-33's guard in one
# probe. The restore constant is the screen.rs contract (NIGHT-hunt-31
# carries the leading SGR reset).
if python3 /opt/zelynic/scripts/ci/kernel-floor-observer-probe.py \
	/opt/zelynic/zelynic; then
	note "observer attach + guard restore (pty)" PASS
else
	note "observer attach + guard restore (pty)" FAIL
fi

# ── the verdict ───────────────────────────────────────────────────────
if [ "$FAILURES" -eq 0 ]; then
	echo "FLOOR-VERDICT: PASS"
else
	echo "FLOOR-VERDICT: FAIL ($FAILURES probe(s) failed)"
fi
halt_now
