<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Stability, LTS, and the nightly eBPF toolchain

> **The one-paragraph answer.** zelynic's eBPF build toolchain — the
> `aya-ebpf` crate family compiled by a pinned nightly rustc and linked
> by bpf-linker — is experimental software by any honest measure. The
> product quarantines that experiment at BUILD time: the eBPF objects
> are cross-compiled, structurally validated, and embedded inside the
> one release binary. At RUN time a zelynic deployment needs only a
> Linux kernel, root, and the single file — no rustup, no nightly, no
> bpf-linker, no LLVM, no clang. Production stability therefore does
> not depend on the experimental half; it depends on the kernel
> interface, which is the most stable ABI Linux maintains. This page
> documents that layering, and then — because a stability page that
> only markets is a lie — the residual limits, exactly what they cost,
> and what to do when one of them bites.

## The layering contract

| Layer | What it needs | Stability source |
|---|---|---|
| **Runtime (every install)** | kernel 5.13+, cgroup v2 unified hierarchy, BPF filesystem, root. One self-contained binary. | The kernel's eBPF UAPI — stable ABI, verified matrix in [KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md) |
| **Release artifacts** | Nothing else. Each tarball is `zelynic` + `LICENSE` + `README.md`; the eBPF objects ride inside the binary (`include_bytes!`, aligned + structurally validated at build time). | Built by CI on ephemeral runners; consumer machines never see any toolchain |
| **Build from source** | rustup with the stable `1.98.1` pin (userspace), the dated `nightly-2026-09-18` pin (eBPF objects only, nested build in `build.rs`), bpf-linker `0.11.1` prebuilt. | All three installed by one command: `scripts/bootstrap-ebpf.sh` |

The split is deliberate. The userspace binary — the CLI, output
rendering, rate parsing, all 15 commands' plumbing — builds on the
pinned STABLE toolchain and would keep building on any future stable.
The nightly exists for exactly one reason: the `aya-ebpf` crates
require `#![feature()]` gates that stable rustc rejects, so the BPF
object side cannot leave nightly today. That is the experimental
dependency, and it is fenced into `build.rs`'s nested cross-build.

## Why the nightly is DATED, not floating

`ebpf/rust-toolchain.toml` pins `nightly-2026-09-18`, not `nightly`.
A floating nightly is a moving target: any upstream regression would
break every from-source build at once, and no two machines could
produce identical objects. The dated pin makes the eBPF build
reproducible and reviewable — the rustc that compiles the BPF objects
is a specific, inspectable artifact. The pin and bpf-linker `0.11.1`
are a validated pair (the selection rationale lives in
[PURE_RUST_EVALUATION.md](PURE_RUST_EVALUATION.md)); bumping either is
an owner-controlled, deliberate act, not something the ecosystem does
to the project overnight.

## The LTS isolation contract

A release binary already shipped does not depend on any toolchain
component continuing to exist:

- Rust could delete the nightly archive, bpf-linker could vanish from
  GitHub, aya could rewrite its API — **every already-downloaded
  zelynic binary keeps working**, because its BPF programs were
  compiled, embedded, and verified at build time. The binary's
  lifetime is bounded by the kernels it runs on, not by the Rust
  release train.
- The inverse coupling is equally fenced: build.rs strips host-CPU
  and host-linker rustflags from the nested eBPF build
  (NIGHT-hunt-28), so the embedded objects are identical no matter
  which profile or host compiled them. A native-tune build can never
  produce objects a plain build would not.
- Recovery state is versioned, not toolchain-bound: the pinned map
  carries a schema version, and `zelynic recover` repairs or clears
  state left by older binaries (see [USAGE.md](USAGE.md)).

This is the sense in which zelynic is production-stable while its eBPF
dependencies are not: **stability is a property of what ships, and
only reviewed, embedded, kernel-verified artifacts ship.**

## Honest limits (the 99% section)

None of the above makes the system perfect. These are the real
residual risks, ranked by how likely they are to matter:

1. **Kernel verifier drift.** The BPF verifier is tightened release
   over release; a program the 6.18 kernel accepts can, in principle,
   be rejected by a future kernel's stricter checks. Mitigation: the
   cross-distro matrix ([CROSS_DISTRO_RESULTS.md](CROSS_DISTRO_RESULTS.md))
   covers the kernels real users run, `zelynic doctor` preflights
   load capability before any policy work, and a load failure is a
   loud, branded error with its full cause chain — never a silent
   no-op. Residual cost: on an exotic kernel/config outside the
   matrix, zelynic may refuse to start. It will not misbehave.
2. **Dated-nightly aging.** The pin receives no fixes; if a future
   rustup or glibc change breaks the archived toolchain, from-source
   builds stall until the owner re-pins (a deliberate, tested bump).
   Release binaries are unaffected — this limit only bites people
   building new binaries from source, and it bites loudly: build.rs's
   preflight names the exact broken prerequisite with its one-command
   repair (`scripts/bootstrap-ebpf.sh`, which also detects and
   reinstalls a DAMAGED pin).
3. **aya upstream evolution.** The `aya`/`aya-ebpf` APIs move fast;
   a re-pin (limit 2) may require code changes on the zelynic side.
   The dependency set is minimal and every direct dependency has a
   recorded call-site justification
   ([DEPENDENCY_AUDIT.md](DEPENDENCY_AUDIT.md)), so the surface that
   upstream churn can reach is deliberately small.
4. **Measurement physics, not toolchain.** Loopback GSO granularity
   bounds sub-skb rates, the min-RTO cushion shapes near-capacity
   aggregates, and a policer drops rather than queues — these are
   documented model limits of rate enforcement on Linux
   ([PERFORMANCE.md](PERFORMANCE.md)), not bugs, and no toolchain
   change can remove them.

The honest summary the owner stands behind: **99% production-useful,
and the missing 1% fails closed and says so.**

## When something breaks

| Symptom | First command | Why |
|---|---|---|
| A strict/limit command errors at BPF load | `zelynic doctor` | Preflights kernel eBPF support, cgroup v2, and BPF fs; names the missing piece |
| Limits behave oddly after a crash / old binary | `zelynic recover` | Repairs or clears pinned state via the schema version |
| Machine-wide sweep misbehaving | `sudo zelynic unstrict-all` | Full unpin: every limit, link, and map removed in one shot |
| A from-source build dies on toolchain errors | `./scripts/bootstrap-ebpf.sh` | Installs/repairs the dated nightly + bpf-linker pair, then builds |
| Uninstalling while limits are live | `./scripts/uninstall.sh` | Clears kernel enforcement BEFORE removing the binary (NIGHT-improve-15) |

Every runtime error prints its full cause chain (`caused by:` lines
naming map, syscall, and errno), and every failure mode above is
covered by the supermassive test suite — the command surface is
verified end-to-end on real kernels, not asserted.
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
