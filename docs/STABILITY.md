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
| **Build from source** | rustup with the stable `1.98.1` pin (userspace), the dated `nightly-2026-09-18` pin (eBPF objects only, nested build in `build.rs`), bpf-linker `0.11.1` prebuilt. | All three installed by one command: `scripts/dev/bootstrap-ebpf.sh` |

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
   repair (`scripts/dev/bootstrap-ebpf.sh`, which also detects and
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
5. **Long-uptime monitor endurance (bounded by design, audited
   2026-09).** An eagle-eyes session that runs for months accumulates
   per-cgroup totals in u64; at the 18.4 EB-per-direction ceiling the
   accumulator the user SEES — the session ledger in userspace —
   SATURATES (never wraps, never panics — every arithmetic surface in
   the session path is saturating since the NIGHT-boost-16 audit).
   The kernel maps' own lifetime counters keep the C twin's plain
   adds (NIGHT-ultimate-1 precision: their wrap horizon is the same
   18.4 EB, but it would take years of saturated line-rate traffic
   through one cgroup inside one session-scoped map — the maps are
   recreated at every eagle-eyes start — and a wrap there could never
   reach the display: the session ledger, not the map counter, is
   what renders). The leaderboard's entry count mirrors
   the kernel's own 1024-slot counter-map ceiling
   (`MAX_TRACKED_CGROUPS`), so cgroup churn cannot grow the monitor's
   memory. The counter maps themselves are recreated at every
   `eagle-eyes` start — the session horizon resets on restart, which
   is the documented cadence for a trunk that could genuinely move
   exabytes per cgroup. Full detail:
   [SAFETY_ANALYSIS.md](SAFETY_ANALYSIS.md), the
   accumulate-explosion audit.

The honest summary the owner stands behind: **99% production-useful,
and the missing 1% fails closed and says so.**

## The silent-killer inventory (NIGHT-ultimate-2, 2026-09-24)

The owner's question: "is zelynic already for LTS long usage?
strong, killers but silent?" The audit walked every class of failure
that could END or DRAIN a months-long deployment quietly, and the
inventory below is the answer — one killer found and fixed, every
other class already fenced:

- **Memory growth — fenced.** Every long-lived structure is bounded
  by construction: the session leaderboard mirrors the kernel's own
  1024-slot map ceiling (`MAX_TRACKED_CGROUPS`), the two cookie maps
  are LRU (self-evicting, session-scoped), both `/proc` caches are
  rebuilt in place behind their TTLs (identity 10s, connections 3s),
  the diff engine's shadow and buffers scale with terminal size, and
  the per-frame join map is replaced, never appended.
- **FD leaks — fenced.** The pidfd join opens one pidfd per PID,
  marks failure sticky, and closes explicitly per scan (the Copy
  redesign makes re-entrant drop recursion structurally impossible —
  the boost-26 incident and its regression pin); the pidfd_getfd
  local copies close on every path including the failure path.
- **Arithmetic endurance — fenced.** Every userspace accumulator
  saturates (boost-16); the kernel counters' plain adds sit behind a
  physically-unreachable wrap horizon (see honest limit 5, corrected
  at ultimate-1); the limiter clamps every stored value it consumes
  (security-3/depthbore-1).
- **Kernel resource leaks — fenced.** Observer maps are
  session-scoped and freed at detach; the limiter's pinned state is
  reclaimed by `unstrict`/`unstrict-all`/`recover` with bucket-slot
  return (improve-10), and a reboot clears bpffs by design (the
  documented no-residue contract).
- **Time — fenced.** Uptime rides `Instant` (CLOCK_MONOTONIC: no
  wall-clock jumps, no NTP step, no wrap inside any realistic
  session horizon); every rate divides by the configured interval,
  never by measured wall time.
- **The forever-monitor — FOUND AND FIXED (this audit).** The one
  genuine silent killer: Rust ignores SIGPIPE, and the diff engine
  discarded emission errors with no consequence, so a piped
  `zelynic eagle-eyes | head -3` left a root process running forever
  — eBPF attached, `/proc` walks on cadence, every write discarded —
  until reboot, invisible except in `ps`. The diff engine's own
  comment claimed "a short-reader kills the monitor quietly"; the
  code never implemented it. Now it does: a failed emission (EPIPE
  from a closed reader, ENOSPC from a filled sink) sets a sticky
  sink-death flag, the monitor loop checks it after every beat, and
  the session leaves quietly — alt screen restored, observer
  detached, exit 0. A slow-but-open reader can never trip it (a
  full pipe blocks, it does not error); std's `write_all` retries
  `Interrupted`, so only real deaths count. Five pins hold the
  mechanism (test/terminal/sink_death_tests.rs); the live re-proof
  is the owner-host battery's lane.
- **The garbled-terminal pipe entry — PREVENTED (NIGHT-boost-28).**
  The sink-death exit fenced the pipe monitor's RUN; the entry was
  still open and worse: `sudo zelynic ee | grep` keeps stdin on the
  real terminal while stdout is the pipe, so the enter path
  raw-moded the REAL terminal (echo off, ISIG off — Ctrl+C dead)
  while every alt-screen byte and frame painted into the pipe, and
  the loop spun forever holding root — a garbled terminal plus a
  hidden root process. eagle-eyes now refuses any non-interactive
  stdio BEFORE root work, terminal state, or BPF load: the gate
  (`terminal::require_interactive`) sits in the handler (teaching
  `status --print-json` for scripts) and again inside
  `AltScreen::enter` as the structural backstop; the stdin twin
  covers redirected input (`ee < /dev/null`) whose frames used to
  paint on the MAIN screen with keys that could never arrive; and
  `Monitor::open` returns `Result` so no enter failure can degrade
  into the old silent pipe session. Prevention at the door, the
  sink-death containment still armed behind it (a pty can die
  mid-run); unit pins (test/terminal/interactive_guard_tests.rs)
  and the piped-subprocess integration pin
  (test/integration/monitor_guard.rs) hold both layers.
- **The violent-death terminal wreck — MITIGATED (NIGHT-boost-33).**
  Every clean exit path restores the terminal (AltScreen's Drop),
  but `kill -9` and `pkill zelynic` run no user code: the process
  vanished, the terminal stayed raw (echo off, ISIG off, alt screen
  holding the frame) — for a root-held monitor the worst residual
  shape after boost-28: the machine fine, enforcement fine (the
  pinned maps survive by design), the USER blind. The monitor now
  arms a forked guard child BEFORE the alt screen takes the
  terminal: the child parks in one blocking `read(2)` on a pipe —
  zero CPU, zero wakeups, no polling — and the kernel's own fd
  teardown (the one thing no signal can skip) closes the parent's
  write end the instant the parent dies, any way it dies. EOF wakes
  the child: it restores the shell's termios, writes the exact
  ALT_EXIT bytes, exits. A clean exit sends a stand-down byte first
  (the parent's own restore is the authoritative one — the two can
  never race), and the open-failure path leaves the guard in
  restore mode. The child survives the killing itself: its name
  (`zny-tguard`) does not match `pkill zelynic`, and it leaves the
  process group (setsid) so a group kill cannot reach it either.
  It touches no BPF state, no pins — enforcement continuity is the
  architecture's contract, never the guard's. The pure pins
  (restore-bytes lockstep, the name shape) live in
  test/terminal/termguard_tests.rs; the fork/EOF mechanics are the
  CI kill-tui battery's lane (it SIGKILLs a real monitor on a real
  pty five times per run).

**Verdict: yes — LTS-ready for long usage.** Every silent-killer
class the audit could name is either bounded by construction,
self-healing, or (as of this audit) exits loudly-quietly on its own;
the residual risks are the five honest limits above, each documented
with its cost and its first command.

## When something breaks

| Symptom | First command | Why |
|---|---|---|
| A strict/limit command errors at BPF load | `zelynic doctor` | Preflights kernel eBPF support, cgroup v2, and BPF fs; names the missing piece |
| Limits behave oddly after a crash / old binary | `zelynic recover` | Repairs or clears pinned state via the schema version |
| Machine-wide sweep misbehaving | `sudo zelynic unstrict-all` | Full unpin: every limit, link, and map removed in one shot |
| A from-source build dies on toolchain errors | `./scripts/dev/bootstrap-ebpf.sh` | Installs/repairs the dated nightly + bpf-linker pair, then builds |
| Uninstalling while limits are live | `./scripts/uninstall.sh` | Clears kernel enforcement BEFORE removing the binary (NIGHT-improve-15) |

Every runtime error prints its full cause chain (`caused by:` lines
naming map, syscall, and errno), and every failure mode above is
covered by the supermassive test suites — v1 (the limiter-scope
matrix: every policy shape locally and against the real internet,
NIGHT-refactor-2) and v2 (the survival battery: the 83-case CLI
depth stresstest of NIGHT-ultimate-3, the CLI guards, the SIGKILL
batteries, the post-kill regression re-proof, and the crash-family
teardown) — so the command surface is verified end-to-end on real
kernels, not asserted.
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
