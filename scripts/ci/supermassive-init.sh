#!/usr/bin/env bash
# Copyright (C) 2026 rezky_nightky
# SPDX-License-Identifier: GPL-3.0-only
# OS: Linux only — zelynic is a Linux eBPF tool; no other OS is supported.
#
# NIGHT-hunt-35 (the owner's approved CI-budget call, the hunt-33 open
# item): the three root rig suites — reload-test.sh, crash-recovery-
# test.sh, race-condition-test.sh — join the battery on every leg.
# hunt-33 made every bash harness speak the engines' binary contract;
# this closes the other half of that integration: the rigs the owner
# runs with sudo on nightpc now prove the same things inside the
# guest, on the floor kernel and the archive's latest, per leg, per
# libc. The one VM detail that shape needs: everything in this guest
# is a child of PID 1, which sits in the cgroupfs ROOT — and the
# resolver rightly refuses a root-catch-all target — so each rig
# moves itself into a dedicated zelynic-rig-suite child cgroup first
# (the engines' own worker-move shape, verbatim), which is also
# exactly the sibling-cgroup contract those suites were designed
# around (NIGHT-hunt-32's loopback blob-server heal).
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
# + doctor, the engine self-test, then the full engines with
# --binary pinned — never a bespoke assertion that could drift
# from the harness the owner runs locally. NIGHT-hunt-35 adds the
# three root rig suites (reload, crash recovery, race condition)
# under the same rule — the local sudo battery and the CI battery
# are one battery now. Since NIGHT-approved-1 the micro-VM carries
# REAL EGRESS (qemu user-mode networking — the owner's
# architectural call), so v1's realnet lane RUNS: its own
# reachability probe and its honest SKIPs own the endpoint-down
# days, and the loopback matrix keeps carrying the limiter proof
# on the floor kernel beside it.
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
# surface), devpts (the v2 pty batteries), loopback (the v1 loopback
# traffic lane — the realnet lane rides the egress block below).
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

# ── the realnet lane's egress (NIGHT-approved-1, the owner's ──────
# architectural call) ────────────────────────────────────────────
# qemu's user-mode networking (SLIRP) attaches a virtio-net NIC
# with a deterministic static shape: guest 10.0.2.15/24, gateway
# 10.0.2.2, DNS 10.0.2.3 — no DHCP, no bridge, the runner's own
# egress NAT'd behind it. The bus layer (virtio, virtio_pci) is
# built into every kernel this guest boots; the 5.13 floor's
# virtio_net is a MODULE, staged by the rootfs assembly from the
# kernel's own modules deb (vermagic exact by construction) as a
# THREE-module chain — failover.ko under net/core owns the very
# symbols net_failover.ko imports (run 37520041688's lesson: the
# pair without the core leaf fails every insmod with Unknown
# symbol), so the insmods walk bottom-up: failover, net_failover,
# virtio_net — and tolerate the built-in heads, where no files
# exist and eth0 is born attached. The bring-up is outcome-judged:
# eth0 exists, is up, carries the default route, and the resolver
# points at SLIRP's DNS — everything past this row (the endpoint
# chain, the bands, the honest SKIPs) belongs to v1's own
# reachability probe, which waited for exactly this day.
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

# v3's engine smoke (NIGHT-improve-34): the container depth harness is
# sound — v1 importable, the shared lib surface present, v3's grammar
# tables populated. Runs before the full container depth battery.
if python3 scripts/supermassive/supermassive-test-v3.py --self-test; then
	note "supermassive v3 engine self-test" PASS
else
	note "supermassive v3 engine self-test" FAIL
fi

# v4's engine smoke (NIGHT-improve-35): the CLI depth harness is sound
# — v1 importable, the shared lib surface present, v4's case tables
# populated. Runs before the full CLI depth battery.
if python3 scripts/supermassive/supermassive-test-v4.py --self-test; then
	note "supermassive v4 engine self-test" PASS
else
	note "supermassive v4 engine self-test" FAIL
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
# by one strict write, daemonized traffic, concurrent report
# readers) gating the desktop matrix — every policy shape on the
# loopback lane (the realnet lane rides the egress block above,
# honest SKIPs on the endpoint-down days), the rate ladder, reload,
# sustain — attach, policy writes, MEASURED
# rates, accounting. A green row here is the "holds everywhere it
# claims" verdict, server shape included, on the leg's kernel,
# inside the profile's derived resource envelope.
if python3 scripts/supermassive/supermassive-test.py \
	--binary /opt/zelynic/zelynic; then
	note "supermassive v1 - limiter matrix (full, server-first)" PASS
else
	note "supermassive v1 - limiter matrix (full, server-first)" FAIL
fi

# ── the AMMSP-vs-legacy DELTA (NIGHT-perf-1, the owner's ask: "verify
# and proof the AMMSP works 99% or not"): the identical subtree battery
# against THIS build and the pre-AMMSP v11.0.0 stable the rootfs
# assembly staged at /opt/zelynic/legacy — seven child leaves (a depth
# chain, siblings, a late-born child), a pre-poisoned memo, the shared
# budget, and the nested root, per side, with the >= 99% child-coverage
# DELTA as the verdict. The counterfactual — what the same machine,
# same fleet, same traffic leaked on the old stable — is the one thing
# only a two-binary run can prove, measured live on this leg's kernel
# inside this profile's derived envelope. The staged legacy binary is
# absent only when the assembly could not run (the manual/local shape);
# the CI rootfs step FAILS the leg instead, so a skip here never hides
# on the supermassive lanes.
if [ -x /opt/zelynic/legacy/zelynic ]; then
	if python3 scripts/supermassive/ammsp-vs-legacy-test.py \
		--binary /opt/zelynic/zelynic \
		--legacy-binary /opt/zelynic/legacy/zelynic; then
		note "AMMSP vs legacy v11.0.0 - subtree coverage delta (>= 99%)" PASS
	else
		note "AMMSP vs legacy v11.0.0 - subtree coverage delta (>= 99%)" FAIL
	fi
else
	note "AMMSP vs legacy v11.0.0 - subtree coverage delta (>= 99%)" SKIP
fi

# v2, the survival battery (the e2e pipeline's phase three, LAST per
# the qualification order): the NIGHT-blade-4 server phase FIRST
# (the guard family under the stripped headless environment — the
# exact stdio shape this PID-1 guest itself presents), then the
# 104-case CLI depth stresstest, the input guards, the SIGKILL
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

# v3, the container depth battery (NIGHT-improve-34, the e2e
# pipeline's phase four): the docker:// and k8s:// target surface
# end to end — the URI grammar depth (every malformed shape the
# parse_container pure core rejects), the resolution error paths
# (no docker socket, no /var/log/pods, no container named X), the
# resolve-only contract (container targets ride the same strict-
# single machinery), and the docker E2E lane (self-skips when no
# daemon — the CI micro-VM ships no docker, the same shape v1's
# realnet lane self-skips when every endpoint is down). A green row here is
# the "names a workload by its container and enforces on the cgroup
# the name resolves to, clean on every error path" verdict. The
# rootless stages (help + privilege gate) run on every host; the
# root stages (grammar + resolution) run on this leg's root (the
# floor or the latest head). NIGHT-improve-49: this leg runs as
# root (the init context), so the privilege-gate stage's refusal
# rows re-execute through the real-user drop lane (setpriv to uid
# 65534) instead of skipping — the gate refuses the dropped user
# exactly as it refuses a real one, the refusal needle asserts for
# real on every leg.
if python3 scripts/supermassive/supermassive-test-v3.py \
	--binary /opt/zelynic/zelynic; then
	note "supermassive v3 - container depth battery (full, user rows via the real-user drop)" PASS
else
	note "supermassive v3 - container depth battery (full, user rows via the real-user drop)" FAIL
fi

# v4, the CLI depth battery (NIGHT-improve-35, the e2e pipeline's phase
# five): every CLI surface end to end — every command (canonical +
# alias), every global flag, every color mode (zero to hero), every
# near-miss typo's suggestion tip, every rate-explode shape's category
# error, every removed/retired command's clean redirect, and every
# hidden subcommand. Rootless by design (the CLI surface parses
# before the root check), so v4 is the most CI-friendly supermassive
# test — it runs on every host without sudo. A green row here is the
# "the surface is COMPLETE" verdict — v4 proves coverage, v2 proves
# hardness (the same surface from both ends). NIGHT-hunt-Z9 adds
# stage 9, the hardening seat: hostile control-byte payloads against
# every pre-root echo path (the render boundary's '?' contract), the
# shadowed-positional ladder, and the hidden-vocabulary leak cases.
# This leg runs the battery as root (the init context), so the
# rootless-lane rows — the ones asserting the root-refusal message a
# real user sees — re-execute through the real-user drop lane
# (NIGHT-improve-49: setpriv to uid 65534) instead of skipping: the
# gate refuses the dropped user exactly as it refuses a real one,
# and a dropped uid cannot pass the root gate, so no v4 case ever
# makes an enforcement attempt (only a host without setpriv keeps
# the honest SKIP — this rootfs ships util-linux, so the drop runs).
# The rootless Dragon Guard - CI leg still runs all rows on every
# push that touches the Rust/scripts surface (ci.yml is
# paths-filtered — NIGHT-hunt-32 corrected the unqualified "every
# push").
if python3 scripts/supermassive/supermassive-test-v4.py \
	--binary /opt/zelynic/zelynic; then
	note "supermassive v4 - CLI depth battery (full, user rows via the real-user drop)" PASS
else
	note "supermassive v4 - CLI depth battery (full, user rows via the real-user drop)" FAIL
fi

# ── the rig suites (NIGHT-hunt-35): the root bash rigs, canonical ────
# The three suites the owner runs with sudo on nightpc — reload
# (rate changes under live loopback traffic), crash recovery (pin
# death and the recover/auto-heal machinery), race condition (the
# file lock under concurrency) — each its own MASS-RESULT row,
# --binary pinned like every engine row. The lane: a rig's sleeps,
# curls, and blob server must be siblings in ONE policed cgroup
# (hunt-32's contract), and they must NOT sit in the cgroupfs root
# (the resolver's catch-all guard). The move below is the engines'
# own worker shape (`echo $$ > cgroup.procs; exec`, verbatim from
# supermassive-test.py): the wrapper bash lands in the child cgroup,
# exec replaces it with the rig, and every process the rig spawns
# inherits the lane — the same sibling shape a systemd session
# slice gives the owner's local runs.
RIG_MOVE='echo $$ > "/sys/fs/cgroup/zelynic-rig-suite/cgroup.procs"; exec "$@"'
mkdir -p /sys/fs/cgroup/zelynic-rig-suite
if bash -c "$RIG_MOVE" rig \
	./scripts/depth/reload-test.sh --binary /opt/zelynic/zelynic; then
	note "rig suite - reload (rate changes under live traffic)" PASS
else
	note "rig suite - reload (rate changes under live traffic)" FAIL
fi
if bash -c "$RIG_MOVE" rig \
	./scripts/depth/crash-recovery-test.sh --binary /opt/zelynic/zelynic; then
	note "rig suite - crash recovery (pin death, recover, auto-heal)" PASS
else
	note "rig suite - crash recovery (pin death, recover, auto-heal)" FAIL
fi
if bash -c "$RIG_MOVE" rig \
	./scripts/depth/race-condition-test.sh --binary /opt/zelynic/zelynic; then
	note "rig suite - race condition (the lock under concurrency)" PASS
else
	note "rig suite - race condition (the lock under concurrency)" FAIL
fi
# The lane empties itself (each rig kills its own sleeps and curls in
# cleanup; a straggler zombie can hold the directory a moment) — the
# removal is best-effort hygiene, never a verdict.
rmdir /sys/fs/cgroup/zelynic-rig-suite 2>/dev/null || true

# ── the claims proof, LIVE on this leg's kernel (NIGHT-lts-6) ─────────
# The four-plus-one headline claims proven with root on the exact
# kernel this leg booted (canonical invocation, --quick windows):
# no-daemon, pure-eBPF, per-app, precision 0.00%, and the footprint
# claim — the CLI's own RAM/CPU/IO plus the attached programs'
# kernel run time. Every push's supermassive run is now also a
# live claims audit; the full owner-facing flow stays
# `sudo ./scripts/bench/proof-claims.sh` on the host.
# NIGHT-improve-48: the rootfs now ships nft and bpftool (the
# rootfs assembly's tools closure), so the pure-eBPF ruleset
# snapshot, the bpftool visibility row, and the footprint's
# kernel run-time numbers run for real on every leg — the three
# tool-absent SKIP rows the VM carried since lts-6 are closed,
# and the quick-mode verdict should read 29 passed, 0 skipped
# on this shape.
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
