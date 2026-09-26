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
scripts/sandbox/zelynic-sandbox.sh --battery   # both supermassive engines, as root, in the VM
scripts/sandbox/zelynic-sandbox.sh --run <cmd> # any root-requiring command, in the VM
scripts/sandbox/zelynic-sandbox.sh --shell     # interactive root bash on the VM console
scripts/sandbox/zelynic-sandbox.sh --self-test # rootless preflight, no VM boot
```

## What it is

- **A direct-boot micro-VM**: `qemu-system-x86_64 -kernel … -initrd …`,
  no disk, serial console, `panic=-1 -no-reboot`, the
  `isa-debug-exit` device for deterministic shutdown — the CI VM's
  exact boot contract.
- **The kernel lane**: `--kernel floor` (default) boots impish
  5.13.0-52 — the documented minimum, the same lane as CI's
  low-specs leg, resolved live from the frozen old-releases archive;
  `--kernel latest` resolves the archive's newest generic kernel
  (two newest suites, `-updates` included, `-proposed` excluded);
  `--kernel PATH` boots your own vmlinuz.
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
  the verdict).
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

- `qemu-system-x86_64`, `python3`, `curl`, `git` on the host.
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
