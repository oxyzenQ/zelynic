#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# The E2E depth-stresstest init (night-dragon-maintenance-2): the
# guest side of .github/workflows/supermassive-e2e.yml, the sibling's
# supermassive-e2e contract sized to zelynic's own physics.
#
# The contract: every surface, every guard, every error path,
# exercised against the REAL alias-built release binary, on two
# KVM micro-VM legs (the workflow owns them): the low-spec leg
# boots the TRUE documented floor kernel (impish 5.13, the oldest
# kernel in the verified matrix) and the best-spec leg boots the
# archive's dynamically resolved latest. Both legs run the
# IDENTICAL suite and the IDENTICAL check depth here — the budget
# buys headroom, never depth — and both run it in the modes the
# owner named: the unprivileged USER leg first (the honest refusal
# contract), then the ROOT legs (zelynic is a root tool —
# README's "Linux kernel 5.13+, cgroup v2, root"; the enforcement
# depth belongs to root by design, never to sudo-of-convenience).
#
# The suite is canonical invocations only (the e2e house rule, the
# same law supermassive-init.sh carries): the five depth suites the
# owner runs locally, each with --binary pinned, each its own
# E2E-RESULT row:
#   1. scripts/depth/nonroot-depth-test.sh   - the USER-mode leg
#      (the full command surface as an unprivileged user: refusal
#      ladder, fail-fast validation, no-panic edges)
#   2. scripts/depth/limiter-depth-test.sh   - the realtime depth
#      stresstest (measured rates, BPF-counter cross-checks, the
#      kernel-span verdict family) — full depth, both legs
#   3. scripts/depth/endurance-test.sh       - the LTS clocks
#      (map-slot churn amplification + the monitor soak) — full
#      depth, both legs
#   4. scripts/sandbox/smoke-cli.sh          - the whole CLI surface
#      battery as root (every verb, every guard, real policing,
#      leak postconditions, the unprivileged refusal row)
#   5. scripts/depth/install-flow-test.sh    - the install/uninstall
#      lifecycle as root (last: it owns /usr/bin and clears kernel
#      state by design)
#
# Verdict relay: the VM cannot pass exit codes through qemu — the
# E2E-RESULT / E2E-VERDICT sentinel lines ARE the relay (the
# kernel-floor contract supermassive-init.sh keeps, one namespace
# over so the two lanes' log greps can never cross-contaminate).
#
# PID-1 rules (the kernel-floor lessons, kept verbatim): no systemd
# here — this script owns every mount; it must NEVER exit without
# ending the VM, and the exit rides qemu's isa-debug-exit port
# device (reboot(2) poweroff silently no-ops in a direct-boot
# guest) — see guest_exit.
set -u
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
FAILURES=0
note() {
	echo "E2E-RESULT: $1 — $2"
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
	# exit, the E2E-* sentinel lines being the verdict.
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
	echo "E2E-VERDICT: FAIL (cannot cd $Z — rootfs assembly bug)"
	guest_exit
fi
# ── the kernel surfaces, before anything that needs them ──────────────
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs dev /dev
exec >/dev/console 2>&1
echo "E2E: init on $(uname -r)"
# The floor itself — the whole reason these legs exist. Numeric
# (supermassive-init's shape): the low leg boots the TRUE documented
# floor (impish 5.13) and the best leg boots the archive's latest,
# so one check serves both ends of the span: uname -r's major.minor
# must sit at or above 5.13, the verified matrix's floor
# (docs/KERNEL_COMPATIBILITY.md).
kver=$(uname -r)
major=${kver%%.*}
minor=$(echo "$kver" | cut -d. -f2 | grep -oE '^[0-9]+' || echo 0)
if [ "${major:-0}" -gt 5 ] || { [ "${major:-0}" -eq 5 ] && [ "${minor:-0}" -ge 13 ]; }; then
	note "kernel $kver (the 5.13+ verified floor)" PASS
else
	note "kernel (uname -r = $kver, wanted >= 5.13)" FAIL
fi
# Everything the five suites need (PID 1 owns them all): tmpfs
# scratch, /run state, cgroup v2 (the rigs' own cgroup mkdirs),
# bpffs (the pin surface), devpts (the monitor pty soak), loopback
# (the traffic lanes).
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
# ── the egress (NIGHT-approved-1's contract, the same shape the ───────
# supermassive battery carries): qemu's user-mode networking
# attaches a virtio-net NIC with a deterministic static shape —
# guest 10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3. The bus layer
# is built into every kernel this guest boots; the 5.13 floor's
# virtio_net is a MODULE staged by the rootfs assembly (the
# three-module insmod chain: failover, net_failover, virtio_net —
# run 37520041688's lesson). The depth suites themselves run on
# loopback; the egress keeps the informational probes (the update
# check's time-boxed network row) honest instead of hanging.
KVER=$(uname -r)
KMOD="/lib/modules/$KVER/kernel"
if [ -f "$KMOD/net/core/failover.ko" ]; then
	insmod "$KMOD/net/core/failover.ko" 2>/dev/null || true
fi
if [ -f "$KMOD/drivers/net/net_failover.ko" ]; then
	insmod "$KMOD/drivers/net/net_failover.ko" 2>/dev/null || true
fi
if [ -f "$KMOD/drivers/net/virtio_net.ko" ]; then
	insmod "$KMOD/drivers/net/virtio_net.ko" 2>/dev/null || true
fi
if [ -e /sys/class/net/eth0 ] &&
	ip link set eth0 up &&
	ip addr add 10.0.2.15/24 dev eth0 &&
	ip route add default via 10.0.2.2 &&
	printf 'nameserver 10.0.2.3\n' >/etc/resolv.conf; then
	note "egress (SLIRP user-net, virtio-net 10.0.2.15 via 10.0.2.2)" PASS
else
	note "egress (virtio-net eth0 bring-up)" FAIL
fi
# ── the lean prelude: the binary is the one the workflow built ────────
# The payload shape names itself (the rootfs assembly wrote
# /opt/zelynic/PAYLOAD-SHAPE beside the binary — the release-tier
# alias the from-source law mandates, never a bare cargo release
# shape). "unknown" means the marker never landed — a rootfs
# assembly bug, visible in the log, never silent.
SHAPE="unknown"
if [ -r "$Z/PAYLOAD-SHAPE" ]; then
	SHAPE=$(tr -d '[:space:]' <"$Z/PAYLOAD-SHAPE")
fi
echo "E2E: payload shape: $SHAPE"
# The BINARY GATE (the harness law, USAGE's stale-binary incident):
# the binary's -V must carry the checkout's own version, so a stale
# artifact can never masquerade as the build under test.
WANT=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$Z/Cargo.toml" | head -1)
GOT=$(./zelynic -V 2>/dev/null | head -1 || true)
if [ -n "$WANT" ] && printf '%s' "$GOT" | grep -qF "$WANT"; then
	note "binary gate (-V carries the checkout's $WANT)" PASS
else
	note "binary gate (-V '$GOT' vs checkout $WANT)" FAIL
fi
if ./zelynic doctor >/dev/null 2>&1; then
	note "doctor (bpf syscall answers on this kernel)" PASS
else
	note "doctor (bpf syscall answers on this kernel)" FAIL
fi
# ── the suite: five canonical invocations, USER leg first ─────────────
# 1. The USER-mode leg (night-dragon-maintenance-2's "real user"):
#    the full command surface as an unprivileged user — setpriv into
#    nobody's uid/gid from a writable cwd. The rig REFUSES euid 0 by
#    design (it pins what an unprivileged user sees), so the setpriv
#    drop is the contract, not a workaround.
if (cd /tmp && setpriv --reuid=65534 --regid=65534 --clear-groups \
	"$Z/scripts/depth/nonroot-depth-test.sh" --binary "$Z/zelynic"); then
	note "USER leg - nonroot depth suite (the unprivileged contract)" PASS
else
	note "USER leg - nonroot depth suite (the unprivileged contract)" FAIL
fi
# 2. The realtime depth stresstest (the owner's words), FULL depth on
#    both legs — the budget buys headroom, never depth.
if ./scripts/depth/limiter-depth-test.sh --binary "$Z/zelynic"; then
	note "ROOT leg - limiter depth stresstest (full, measured + cross-checked)" PASS
else
	note "ROOT leg - limiter depth stresstest (full, measured + cross-checked)" FAIL
fi
# 3. The LTS clocks, FULL depth on both legs: the map-slot churn
#    amplification (any group-slot leak exhausts the 256 cap and
#    fails loudly) plus the monitor's pty soak (no unbounded
#    collection, no fd leak).
if ./scripts/depth/endurance-test.sh --binary "$Z/zelynic"; then
	note "ROOT leg - endurance clocks (full churn + monitor soak)" PASS
else
	note "ROOT leg - endurance clocks (full churn + monitor soak)" FAIL
fi
# 4. The whole CLI surface as root: every verb, every guard, real
#    policing against the unlimited baseline, leak postconditions,
#    the unprivileged refusal row — the smoke battery the sandbox
#    lane runs, on both kernel ends of the span.
if ./scripts/sandbox/smoke-cli.sh --binary "$Z/zelynic"; then
	note "ROOT leg - CLI surface smoke (every verb, every guard)" PASS
else
	note "ROOT leg - CLI surface smoke (every verb, every guard)" FAIL
fi
# 5. The install/uninstall lifecycle as root, LAST: it installs to
#    /usr/bin, enforces, and clears kernel state by design — it owns
#    its own teardown, and nothing after it needs the binary.
if ./scripts/depth/install-flow-test.sh --binary "$Z/zelynic"; then
	note "ROOT leg - install flow lifecycle (install, enforce, uninstall)" PASS
else
	note "ROOT leg - install flow lifecycle (install, enforce, uninstall)" FAIL
fi
# ── the verdict relay ──────────────────────────────────────────────────
if [ "$FAILURES" -eq 0 ]; then
	echo "E2E-VERDICT: PASS"
else
	echo "E2E-VERDICT: FAIL ($FAILURES row(s) red)"
fi
guest_exit
