<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Zelynic Toolchain & Monitoring-Coverage Research

This document answers two owner research questions, asked as a
no-coding session ("docs for repo only research"). Every external
fact below was re-verified against live upstream sources on
**2026-09-23** (the rustc platform-support tables on the current
nightly docs, the local rustup target list, the aya-rs/bpf-linker
and rust-lang/rust trackers, and the aya repository state); the
zelynic-side facts were verified against the source tree at commit
`da58c7c` (aya 0.13.1 userspace, dated nightly pin 2026-09-18,
bpf-linker 0.11.1).

---

## Part 1 — Can the eBPF aya stack run on Rust stable instead of nightly?

**Short answer: the split already exists, and it is the best split
available today. The userspace half of aya has been stable-Rust for
zelynic's whole v11 life; the eBPF program half cannot move to
stable today, the blocker is upstream at the rustc target tier —
not in zelynic, not even in aya — and there is no visible upstream
roadmap that changes this. The correct strategy is exactly what the
repo already does: a dated nightly pin scoped to the eBPF sidecar
directory, and stable everywhere else.**

### 1.1 The two halves of "aya"

The question conflates two crates with opposite toolchain
requirements, and separating them is the whole answer:

| Half | Crate | Target | Toolchain today |
|---|---|---|---|
| Userspace loader/library | `aya` 0.13.1 (zelynic's root `Cargo.toml`) | `x86_64-unknown-linux-gnu` / `-musl` | **stable 1.98.1** — has been stable all along |
| eBPF programs | `aya-ebpf` (the `ebpf/` sidecar crate) | `bpfel-unknown-none` | **nightly, required** — see 1.2 |

Everything a user or operator runs — the CLI, the monitor, the
limiter, the map reads, the JSON output — is the userspace half and
compiles, tests, and ships on the root toolchain pin
(`rust-toolchain.toml`: `1.98.1`, stable). This is why the default
`cargo build` of zelynic never touches nightly and why the
featureless (dormant-mode) build is a stable-only contract.

### 1.2 The exact blocker chain for the eBPF half

The program side needs nightly for a chain of three hard facts, each
verified today:

1. **`bpfel-unknown-none` is a Tier 3 target.** The rustc
   platform-support table (current nightly docs) lists
   `bpfel-unknown-none` / `bpfeb-unknown-none` in the Tier 3 class
   with no prebuilt standard library — the same row family as
   `avr-none`, which the table itself annotates "requires
   `-Zbuild-std=core`". Confirmed locally: `rustup target list`
   does not offer the target at all, so `core` cannot be installed;
   it must be compiled from source as part of the build.
2. **`-Z build-std=core` is a nightly-only cargo flag.** Building
   `core` on demand for a tier-3 target rides the unstable build-std
   machinery; it is not stabilized, and it is not on any published
   stabilization roadmap. Without it, `cargo build --target
   bpfel-unknown-none` cannot link even an empty `no_std` program.
3. **bpf-linker must match rustc's LLVM.** The linker consumes the
   LLVM bitcode rustc emits; a nightly that bumps LLVM past what the
   pinned bpf-linker accepts breaks the link. This is why the pin
   must be a DATED nightly (zelynic: `nightly-2026-09-18` +
   bpf-linker 0.11.1) rather than a floating channel — the exact
   drift risk the ebpf toolchain comments document.

### 1.3 The upstream state (verified 2026-09-23)

- aya-rs/bpf-linker issue #6, "Become a Tier 2 Rust Target" —
  **open since 2021-10-05**, no movement toward the tier-2 policy
  checklist in the current tracker state. Tier 2 would mean a
  designated maintainer team shipping prebuilt std via rustup —
  which would dissolve both blocker 1 and blocker 2 at once.
- No `-Zbuild-std` stabilization RFC is tracking toward stable.
- The aya project's own guidance and examples still carry the
  nightly requirement for the eBPF program crate. The userspace
  crate carries none.

### 1.4 What zelynic already does right (no action needed)

The architecture already isolates the nightly dependency to the
smallest possible surface, and this is worth stating as the
contract rather than as debt:

- **The root pipeline is stable-only.** `rust-toolchain.toml` pins
  stable 1.98.1; every build outside `ebpf/` resolves it.
- **The nightly pin is dated and scoped.** `ebpf/rust-toolchain.toml`
  resolves only for cargo invocations with cwd inside `ebpf/` (the
  nested build the root `build.rs` drives). A floating nightly could
  break the LLVM match at any rustup update; the dated pin makes
  that drift impossible without an explicit, reviewed bump.
- **Release users never need nightly.** The shipped binaries carry
  the eBPF objects embedded at build time (`src/ebpf/embedded.rs`);
  a user installing a release artifact loads the embedded object and
  never compiles BPF code. Nightly is a developer/CI-time dependency
  only — and CI reproduces it exactly (the dated pin + the
  prebuilt-static bpf-linker install script).
- **The no-ebpf escape hatch is fully stable.** Dormant-mode builds
  (`--no-default-features`) compile and run without any BPF
  toolchain at all.

### 1.5 Verdict and recommendation

**Not adoptable today.** The only stable-Rust ways to load eBPF are
C-toolchain-shaped (libbpf skeletons with clang-compiled objects or
vendored prebuilt .o files), and both violate the pure-Rust
principle this repo is built on (`docs/PURE_RUST_EVALUATION.md`):
the first adds a C toolchain to the build surface; the second adds a
vendored binary blob that cannot be audited or rebuilt from source
— strictly worse than the dated nightly pin it would replace.

Recommendation: **hold the current discipline and re-evaluate on
upstream signal, not on a schedule.** The two signals to watch are
(1) aya-rs/bpf-linker #6 moving toward the tier-2 checklist (std
for `bpfel-unknown-none` via rustup would retire the nightly pin
outright), and (2) any build-std stabilization RFC landing. Until
one of those fires, engineering around it locally would be
over-engineering against the owner's rule.

---

## Part 2 — Is zelynic peak masterclass for network-consumption monitoring?

**Short answer: within its declared class — kernel-accurate
per-cgroup / per-process network CONSUMPTION attribution on Linux,
one-shot, no daemon — zelynic is at the front of the class today,
and most of what the class's other tools show is either already
done better here or deliberately out of scope. There is exactly ONE
genuine coverage gap left on the consumption frontier: per-socket
(per-endpoint) byte attribution. Everything else a reviewer might
name is either a quality-of-traffic metric (someone else's class),
an interface-level aggregate (a different question), or a
persistence feature (a violation of the one-shot architecture).**

### 2.1 The declared class

The class is "who is eating my bandwidth" tools: per-process /
per-entity network consumption attribution. The reference set:
nethogs (libpcap promiscuous sniffing, per-process),
bandwhich (eBPF + /proc, per-process and per-connection),
iftop / iptraf (per-connection, pcap), nload / bmon
(per-interface aggregates), btop / glances (aggregate columns), and
kyanos (per-connection with latency/retransmit analysis).

### 2.2 Coverage inventory (source-verified at da58c7c)

What the observer stack measures today, from the BPF layer up:

- **Hook scope:** `cgroup_skb` ingress AND egress attached at the
  cgroup v2 **root** (`/sys/fs/cgroup`) — the whole hierarchy, every
  cgroup, local/loopback paths included, both directions counted
  independently. This is kernel-side attribution: the kernel itself
  names the owning cgroup per packet (`bpf_skb_cgroup_id`); nothing
  is inferred in userspace from captures.
- **Per-cgroup accounting:** bytes and packets per direction, both
  per-frame deltas (the live rates) and lifetime totals (the
  since-attach accumulators) — four counters per cgroup per
  direction, saturating u64 with an honest EB display ceiling.
- **Session intelligence:** a session leaderboard that ranks by
  ACCUMULATED total (not last-interval twitches), rows persisting
  across quiet frames — the exact owner scenario (A downloads 10 GB,
  stops, keeps the crown until passed).
- **Process attribution:** per-cgroup socket-holder resolution from
  the kernel's own socket tables (`/proc/net/{tcp,tcp6,udp,udp6}`)
  joined with per-PID file descriptors — IPv4 and IPv6, TCP and
  UDP, with connection states, queued-socket flags, and refresh
  throttling that keeps the 1s frame cadence clean.
- **Endpoint detail:** per-process endpoint trees (the
  NIGHT-boost-21 two-level layout) in both the ranked view and the
  uncapped focus view.
- **Presentation:** responsive pinned-frame monitor, per-direction
  rates plus accumulated totals in one frame, focus deep-dive, JSON
  output mode for scripting.

### 2.3 Class comparison — where zelynic leads

| Capability | nethogs | bandwhich | iftop | **zelynic** |
|---|---|---|---|---|
| Attribution accuracy | pcap match, miss-prone at load | eBPF, per-process | pcap, per-connection | **eBPF kernel-named cgroup — exact** |
| Direction split | sent/recv | up/down | two columns | **ingress+egress independently, rates + lifetime** |
| Session accumulation | instantaneous | instantaneous | instantaneous | **accumulated leaderboard, rows persist** |
| Attribution unit | process | process + connection | connection | **cgroup + process (+ endpoints)** |
| Enforcement tie-in | none | none | none | **same observer feeds the limiter** |
| Daemon requirement | foreground process | foreground | foreground | **one-shot, no daemon, fail-safe detach** |

The last two rows are the class frontier zelynic already owns: no
other tool in the set can say "the counter that names the consumer
is the same counter that enforces the cap" (the observer IS the
limiter's data source — Cosmic Dragon principle 5), and none of
them carries a session-accumulated view that survives quiet
periods.

### 2.4 The one genuine gap: per-endpoint consumption — CLOSED at NIGHT-boost-26

The ranked table answers "which cgroup, which process, how much".
The endpoint trees answer "which sockets exist". **Nothing used to
answer "which ENDPOINT is consuming"** — the per-cgroup byte
counters were not broken down per socket, so a process holding five
connections showed five endpoint rows and one aggregate number, and
the eye could not tell which of the five was the eater. bandwhich and
iftop both answered this (their attribution unit IS the connection),
so on that single axis zelynic was behind the leaders, not ahead.

**How it closed (owner-approved at NIGHT-ask-1, 2026-09-24; shipped
as NIGHT-boost-26, same day):** the observer's two existing cgroup_skb
hooks now also bump per-socket LRU byte maps keyed by
`bpf_get_socket_cookie` — the sender's cookie on egress, the
RECEIVER's on ingress (the CGROUP_INET_INGRESS attach fires
per-socket from `sk_filter_trim_cap`, and
`__cgroup_bpf_run_filter_skb` assigns `skb->sk = sk` before the
program runs, so the cookie names the download's true owner —
verified against torvalds/linux net/core/filter.c and
kernel/bpf/cgroup.c, and the helper's legality in cgroup_skb via the
`cg_skb_func_proto` -> `sk_filter_func_proto` fallthrough). The
userspace join rides the identity plumbing that already existed, as
the design promised: the ConnectionMap's fd walk resolves each held
socket's cookie with `pidfd_getfd` + `SO_COOKIE` (kernel 5.6+, under
the 5.13 floor), the loader point-looks-up the cookie maps for
exactly the walked set (tens of syscalls per frame, never a map
iteration), and the endpoint rows render `[dl X | ul Y]` session
totals — with the focus view ranking each process's endpoints by
their bytes, the exact 2.4 promise. Zero new program types, zero new
privileges, map sizing bounded (two 4096-entry LRU hashes,
session-scoped, freed at detach); the honest bounds — cookie-less
rows on hosts that refuse pidfd_getfd, and LRU eviction under
4096+ warm-socket churn — are documented in USAGE.md. The gap is
closed: on every axis of the declared class, zelynic is now at or
ahead of the reference set.

### 2.5 Improvements considered and rejected (scope discipline)

- **Retransmits / RTT / per-connection latency** (kyanos's lane):
  quality-of-traffic metrics, not consumption. The owner's scope is
  "cakupan monitoring consume network saja" — adding these would
  widen the class, not master it. Rejected.
- **Interface-level totals** (nload/bmon's lane): "how full is the
  pipe" is a different question from "who ate it"; the cgroup
  observer deliberately does not answer it. Rejected.
- **Reverse-DNS / SNI enrichment of endpoints**: bandwhich makes
  this optional for a reason — resolution is slow, cached, and
  stale; IPs are honest. Rejected unless a future owner task asks.
- **History / persistence / daemon mode**: violates Cosmic Dragon
  principle 3 (one-shot, no daemons) and the fail-safe detach
  contract. Rejected structurally.
- **UID rollup**: the identity map already knows UIDs, so a
  `--by-uid` summary is a cheap userspace join — but it answers a
  multi-user-box question this single-user focus limiter does not
  have. Held as a known-cheap future, not a gap.
- **Session minimum speed ("total low", rejected at NIGHT-ask-1,
  2026-09-24)**: a minimum-speed statistic is structurally ~0 — any
  idle interval drives it to the floor, so the figure carries no
  information at rest and would render a permanent near-zero row.
  The session statistics that DO carry information are the pair
  already shipped (max and average per direction, NIGHT-engrave-6);
  a minimum would be the third wheel. Rejected.

### 2.6 Verdict

**Yes — peak masterclass in class, with the one named exception
now closed.** The cgroup-scoped, kernel-accurate, dual-direction,
session-accumulated consumption view is ahead of every tool in the
reference set on its own axes; the single axis where the class
leaders were ahead — per-endpoint byte attribution (2.4) — closed
at NIGHT-boost-26 with the cookie-map design above. Everything else
is either already superior here or correctly out of scope — and
building any of it anyway would be over-engineering against the
owner's rule.

**Owner decision (NIGHT-ask-1, 2026-09-24): the verdict is
accepted as the LTS scope statement.** The metric set is closed
(live rates, session totals, session max/avg speed statistics,
census, cgroup → process attribution — the rationale is documented
where users read it, USAGE.md "Honest limitations" entry 12), and
the 2.4 gap closed on its own task cycle (NIGHT-boost-26) exactly
as approved. The scope question is settled, not reopened: any
future widening needs a new owner task, by design.

---

## Sources (verified 2026-09-23)

- rustc platform-support tables (nightly docs):
  `bpfel-unknown-none` listed Tier 3, no prebuilt std —
  <https://doc.rust-lang.org/nightly/rustc/platform-support.html>
- Local `rustup target list` (1.98.1): no `bpfel`/`bpfeb` targets
  offered for install.
- rust-lang/rust `compiler/rustc_target/src/spec/mod.rs` (master):
  `bpfel-unknown-none` present as a built-in tier-3 target spec.
- aya-rs/bpf-linker issue #6 "Become a Tier 2 Rust Target":
  open since 2021-10-05, no tier-2 movement —
  <https://github.com/aya-rs/bpf-linker/issues/6>
- aya repository (aya-rs/aya, main): userspace crate carries no
  nightly requirement; nightly is an eBPF-program-crate concern.
- zelynic source tree at `da58c7c`: `ebpf/rust-toolchain.toml`
  (dated nightly pin + rationale), `build.rs` (nested sidecar
  build), `src/ebpf/loader.rs` (root-cgroup attach),
  `src/ebpf/connections.rs` (socket-table + fd-inode join),
  `ebpf/src/main.rs` (ingress+egress observers and maps).
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
