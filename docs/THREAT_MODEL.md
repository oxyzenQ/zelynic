<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Threat Model

This is the honest boundary of what zelynic defends. No marketing
fluff: each claim below names the mechanism that carries it, and each
limitation names the adversary it concedes to. Read this before
trusting zelynic with anything that matters.

## The one-paragraph verdict

Zelynic provides application-layer bypass resistance, not host-level
security. It assumes root is trustworthy. Everything zelynic enforces
lives in the kernel's eBPF layer (cgroup skb/sock hooks, no tc, no
nftables, no daemon), so it holds against every attempt to evade it
from userspace — and falls to anyone who can touch the kernel or the
root account.

## What zelynic CAN defend against

- **Application-level bypass.** A limited app changing its own
  socket options, using raw syscalls instead of a library, or
  shipping its own userspace throttling logic cannot escape: the
  verdict is made in the kernel on the cgroup path (`bpf` programs
  attached to the cgroup's skb/sock hooks), below every libc, LD_PRELOAD
  shim, or socket hook the app controls. The rate the kernel polices
  is the rate the wire carries.
- **Per-process rename and spoofing.** An app renaming its `comm`,
  forking a worker with an innocent name, or rewriting its argv is
  still limited: enforcement keys on the cgroup the process actually
  lives in, resolved by the kernel on the packet path
  (`bpf_skb_cgroup_id`) and carried to the socket layer through
  cookie-keyed hints — never on a name the process can change. A
  renamed process inside the limited cgroup is a limited process.
- **Connection-level escape.** Opening more connections, rotating
  ports, or moving between interfaces stays inside the same cgroup
  bucket — the policy follows the cgroup, and per-socket enforcement
  (`--per-socket`) narrows it further. A blocked cgroup cannot
  smuggle traffic out through a new socket.
- **Resource-exhaustion races from unprivileged users.** A non-root
  process cannot remove, weaken, or detach the enforcement: the
  maps, links, and pins are root-owned kernel state, and the
  userspace surfaces that mutate policy require euid 0 (fail fast,
  no silent downgrade).

## What zelynic CANNOT defend against

- **Root access.** Root disables everything zelynic enforces —
  `unstrict --all` is one command, the pinned objects and links are
  root-removable kernel state, and root can unload the loader's
  programs outright. This is by design and unavoidable: on Linux,
  CAP_SYS_ADMIN (or CAP_BPF + CAP_NET_ADMIN, depending on the
  kernel) outranks any eBPF control plane. Zelynic assumes root is
  trustworthy; if it is not, nothing in this document holds.
- **Kernel compromise.** If the kernel is compromised, eBPF is
  compromised: the attacker owns the verifier, the helpers, and the
  hooks zelynic's verdicts ride. There is no layer below the kernel
  for an eBPF product to stand on. A kernel-level rootkit can
  report the numbers zelynic's ledger expects while the wire carries
  whatever it wants.
- **Hardware-level attacks.** DMA attacks, malicious firmware,
  SMM/UEFI implants, and physical taps sit below the kernel entirely.
  zelynic's accounting reads kernel counters; a NIC or bus that lies
  is invisible to every surface this repo ships.
- **The host's own userspace after compromise.** A full userspace
  compromise (malicious root-owned process, tampered binary) can
  rewrite zelynic itself — this repo ships a binary, not a
  hypervisor. Verify the artifact (docs/VERIFY_RELEASE.md) and run
  it on a host you actually control.

## The honest threat summary

- **Defends:** userspace evasion of rate limits and blocks — any
  app, any language, any library, below the syscall surface.
- **Does not defend:** anyone with root, a compromised kernel, or
  hardware access. Zelynic provides application-layer bypass
  resistance, not host-level security. It assumes root is
  trustworthy.
- **Failure mode:** loud, not silent — a missing pin, an unload, or
  a cgroup teardown removes the enforcement and the status surface
  stops reporting a limit row for it. Absence of a row is visible;
  the tool never claims enforcement it did not attach. What it
  cannot see is a kernel that lies — that boundary is the one above.

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
