<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# The zelynic Sandbox — a Local KVM Micro-VM for Root Testing

> A throwaway kernel of your own: root inside a VM, no host changes,
> no docker, no CI queue (NIGHT-think-1).

zelynic needs root. Its batteries — the supermassive engines, the
depth harnesses, anything that programs the kernel datapath — cannot
run honestly from a sandbox without privileges, and waiting for CI
(or asking the owner to run things by hand) is slow feedback. The
sandbox closes that gap: it boots the SAME shape of micro-VM the CI
runs (`.github/workflows/supermassive.yml`), but locally, from a
cache, in seconds.

```bash
scripts/sandbox/zelynic-sandbox.sh --smoke     # ONE CLICK: the full CLI depth battery, as root, in the VM
scripts/sandbox/zelynic-sandbox.sh --endurance # ONE CLICK: the map-cap exhaustion + monitor soak, in the VM
scripts/sandbox/zelynic-sandbox.sh --limiter   # ONE CLICK: the flagship limiter depth stress, in the VM
scripts/sandbox/zelynic-sandbox.sh --battery   # both supermassive engines, as root, in the VM
scripts/sandbox/zelynic-sandbox.sh --run <cmd> # any root-requiring command, in the VM
scripts/sandbox/zelynic-sandbox.sh --shell     # interactive root bash on the VM console
scripts/sandbox/zelynic-sandbox.sh --self-test # rootless preflight, no VM boot
```

The `--smoke` battery (NIGHT-blade-10) is the one-command depth
audit: every surface verb, the strict/block/unstrict matrix, the
guards, the JSON documents, real policing on loopback (a 500kb cap
vs the unlimited baseline), the leak probes (zero pins, zero
`/run/zelynic` state, zero lingering processes after teardown) and
the security probes (an unprivileged uid-65534 invocation must be
refused cleanly, with zero partial application). One `SANDBOX-RESULT`
row per surface, one verdict.

The `--endurance` and `--limiter` lanes (NIGHT-harness-1) give the
two flagship depth harnesses the same one-click shape: the map-cap
exhaustion proof (300 apply/unstrict cycles churning ~2100 slots
against the 1024/256 caps — any per-cycle slot leak exhausts a cap
and the next apply fails loudly) plus the monitor pty soak sampled
at 1 Hz, and the cross-distro limiter stress (enforced rates
cross-checked against the BPF counters, kernel drops, steady-state
sustain, reload churn, overhead, cleanup). Both harnesses had no
local execution lane until the sandbox could boot on agent boxes —
their first VM runs caught the endurance pin drift the same day.

## What it is

- **A direct-boot micro-VM**: `qemu-system-x86_64 -kernel … -initrd …`,
  no disk, serial console, `panic=-1 -no-reboot`, the
  `isa-debug-exit` device for deterministic shutdown — the CI VM's
  exact boot contract.
- **The kernel lane** (NIGHT-blade-10): `--kernel lts` (the default)
  resolves the newest **Ubuntu LTS suite**'s kernel across its
  `main` / `-updates` / `-security` pockets straight off the
  archive's own `Version:` field (YY.04 with an even YY — the LTS
  cadence, no hardcoded codename list to rot); `--kernel floor`
  boots impish 5.13.0-* — the documented minimum, the same lane as
  CI's low-specs leg, resolved live from the frozen old-releases
  archive; `--kernel latest` resolves the archive's newest generic
  kernel across the two newest suites by REAL release date (the
  former string sort ranked "Thu, 23 Apr" above "Sat, 26 Sep", and
  the former codename-based fetch 404'd on the devel suite — both
  fixed); `--kernel PATH` boots your own vmlinuz. A cached
  `vmlinuz-*` wins until the cache is cleared — delete
  `~/.cache/zelynic-sandbox` to re-resolve a lane.
- **The userland**: the ubuntu:22.04 base tarball (glibc 2.35 boots
  on any kernel >= 3.2 — the CI VM holds it constant on purpose so
  the kernel is the only variable), plus `python3` / `iproute2` /
  `curl` provisioned by REAL dependency resolution against the jammy
  `Packages` index: every closure `.deb` downloaded once into the
  cache and `data.tar` extracted rootless. No docker, no chroot, no
  host root — the whole rootfs is built by
  `scripts/sandbox/rootfs-pack.py` with python3 stdlib.
- **The payload**: the repo checkout (`git archive HEAD`, tracked
  files only) lands at `/opt/zelynic`, the static musl `zelynic`
  binary beside it, `scripts/sandbox/sandbox-init.sh` becomes `/init`
  (PID 1: mounts `proc` / `sysfs` / `devtmpfs` / `cgroup2` / `bpffs`
  / `devpts`, brings up loopback, runs the packed payload, relays
  the verdict). `--smoke` packs a one-liner payload that invokes the
  tracked battery `scripts/sandbox/smoke-cli.sh`; `--run` packs the
  rest of argv as ONE command line and refuses an empty one
  (NIGHT-blade-10: the old empty `--run` packed a payload that ran
  nothing and still reported PASS).
- **The verdict contract**: `SANDBOX-RESULT` rows for the bring-up
  probes plus one final `SANDBOX-VERDICT: PASS|FAIL` line on the
  serial console — the exit code cannot cross qemu, the sentinel
  lines ARE the relay (the CI `MASS-*` contract, same discipline).

## Why no host root is needed

A non-root process cannot `mknod`, so a plain `tar` extraction can
never produce `/dev/console`. The packer therefore writes the newc
cpio stream itself: the device nodes a direct-boot guest needs
(`console` 5:1, `null` 1:3, `tty` 5:0, `ttyS0` 4:64) are
synthesized directly into the archive — a pure-python cpio writer
with a rootless self-test (round-trip parse of every field, mode
discipline, rdev numbers). The 644/755 permission rule is enforced
at pack time: every regular file lands 0644 unless executable, every
directory 0755 — the image inherits the repo's own contract.

Ubuntu ships some `.deb`s (kernels notably) with `data.tar.zst`; the
packer decompresses them through python 3.14+ stdlib
(`compression.zstd`), the `zstandard` pip module, or the `zstd` CLI —
whichever is present, with a clear error naming the fix when none is.

## Requirements and performance

- `qemu-system-x86_64`, `python3`, `curl`, `git` on the host — and
  even the qemu can be portable: a rootless extraction of the
  distro archive's dependency closure works (NIGHT-harness-1 proved
  the recipe: the Debian trixie closure — 97 .debs — extracted
  under `~/.local/lib/qemu-vm` with a loader + data-dir wrapper in
  `~/.local/bin`; TCG, no `/dev/kvm` required).
- `/dev/kvm` is OPTIONAL: without it the VM boots under TCG software
  emulation (`-cpu max`) — slower, and arch-baseline v3/v4 binaries
  may SIGILL under emulation, which is why the default binary probe
  prefers the plain (v1-baseline) static musl build. With KVM,
  `-cpu host` passthrough makes "native" honest, exactly as CI does.
- First run downloads ~100 MiB (kernel, base tarball, deb closure)
  into `~/.cache/zelynic-sandbox/` (override with
  `ZELYNIC_SANDBOX_CACHE`); every later run rebuilds the initramfs
  from the cache in ~20 seconds.
- The envelope is derived from the host at boot time (the CI dynamic
  math): `--envelope low` (default) = a quarter of the cores floored
  at 1 and an eighth of the RAM floored at 1024 MB; `--envelope
  best` = every core and three quarters of the RAM.
- `--net` adds user-mode networking for interactive debugging; the
  default is OFF — the batteries are loopback-only (the CI VM
  contract; the realnet lane self-skips, its documented row).

## Relationship to CI

The CI supermassive workflow remains the authority: it runs the same
batteries on hosted runners with docker-built rootfs, on both the
5.13 floor and the latest kernel, low and best envelopes, on every
qualifying push. The sandbox is the LOCAL instrument — same kernel
lanes, same userland, same sentinel discipline — for the tight loop:
agent boxes, laptops, any machine with qemu. Anything the sandbox
proves green is what CI will confirm; anything it finds red is found
in seconds instead of a CI round-trip.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `ebpf/src/**/*.rs`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
