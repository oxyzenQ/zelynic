#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# PLATFORM: UNIX-only (Linux). zelynic is a Linux-only tool.
#
# The zelynic sandbox init (NIGHT-think-1) — PID 1 inside the local
# micro-VM booted by scripts/sandbox/zelynic-sandbox.sh. Modeled on
# the CI twin scripts/ci/supermassive-init.sh (the kernel-floor
# lessons kept: no systemd, this script owns every mount, it must
# NEVER exit without ending the VM, and the exit rides qemu's
# isa-debug-exit port device — reboot(2) poweroff silently no-ops in
# a direct-boot guest). The differences are the point: the CI twin
# runs ONE fixed battery and relays MASS-* verdict rows; this init
# runs whatever payload the entrypoint packed into
# /opt/zelynic/.sandbox/payload.sh (a root shell, an arbitrary
# root-requiring script, or the supermassive batteries) and relays
# the exit code through the SANDBOX-VERDICT sentinel line.
#
# Contract: SANDBOX-RESULT lines for the bring-up probes plus one
# final SANDBOX-VERDICT line (PASS, or FAIL with the payload's exit
# code), all on the serial console — the entrypoint greps these
# sentinels; the VM cannot relay exit codes through qemu, the
# sentinel lines ARE the relay.

set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TERM="${TERM:-dumb}"

FAILURES=0

note() {
	echo "SANDBOX-RESULT: $1 — $2"
	if [ "$2" != "PASS" ]; then
		FAILURES=$((FAILURES + 1))
	fi
}

guest_exit() {
	# The deterministic VM exit (the kernel-floor run-4 lesson):
	# qemu's isa-debug-exit device ends the VM the moment one byte
	# lands on port 0xf4; /dev/port is the root-writable port-I/O
	# window (seek = the port number), and the written value 0
	# makes qemu exit with status 1 — the rc the entrypoint's boot
	# step accepts as the guest's deliberate exit.
	printf '\x00' | dd of=/dev/port bs=1 seek=244 count=1 2>/dev/null || true
	# Belts, in order: the raw poweroff syscall (if this guest ever
	# grows an ACPI S5 path), then the sleep loop (never spin the
	# host's budget — the outer timeout owns the last resort).
	python3 -c 'import os; os.sync(); os.reboot(os.LINUX_REBOOT_CMD_POWER_OFF)' 2>/dev/null || true
	while true; do sleep 60; done
}

Z=/opt/zelynic
if ! cd "$Z"; then
	# A PID 1 must never plain-exit (the guest would panic-wedge):
	# exit through the port device with the verdict already naming
	# the failure.
	echo "SANDBOX-VERDICT: FAIL (cannot cd $Z — initrd assembly bug)"
	guest_exit
fi

# ── the kernel surfaces, before anything that needs them ──────────────
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs dev /dev
exec >/dev/console 2>&1
echo "SANDBOX: init on $(uname -r)"

# Everything a zelynic battery needs (PID 1 owns it all): tmpfs
# scratch (the engines' work dirs AND the /run/zelynic lock),
# cgroup v2 (the limiter's cgroup mkdirs need no controllers),
# bpffs (the pin surface), devpts (the v2 pty batteries), loopback
# (the v1 traffic lane).
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

# The lean prelude (the CI twin's shape): the binary runs and the
# bpf syscall answers, before any payload spends its budget.
if ./zelynic -V >/dev/null 2>&1; then
	note "zelynic -V (binary runs on this kernel)" PASS
else
	note "zelynic -V (binary runs on this kernel)" FAIL
fi
if ./zelynic doctor; then
	note "doctor (bpf syscall answers)" PASS
else
	note "doctor (bpf syscall answers)" FAIL
fi

# ── the payload ────────────────────────────────────────────────────────
# Whatever the entrypoint packed: --shell drops into an interactive
# root bash on this console, --run executes an arbitrary root-
# requiring script, --battery runs both supermassive engines. The
# payload's exit code IS the verdict; bring-up FAILURES above fail
# the run too (a machine that cannot host zelynic has no payload
# verdict worth reporting).
PAYLOAD="$Z/.sandbox/payload.sh"
if [ "$FAILURES" -ne 0 ]; then
	echo "SANDBOX-VERDICT: FAIL (bring-up probes failed — payload never ran)"
	guest_exit
fi
if [ -x "$PAYLOAD" ]; then
	echo "SANDBOX: running the packed payload..."
	bash "$PAYLOAD"
	rc=$?
else
	echo "SANDBOX: no payload packed — the root shell is the console."
	bash
	rc=$?
fi
if [ "$rc" -eq 0 ]; then
	echo "SANDBOX-VERDICT: PASS"
else
	echo "SANDBOX-VERDICT: FAIL (payload exit $rc)"
fi
guest_exit
