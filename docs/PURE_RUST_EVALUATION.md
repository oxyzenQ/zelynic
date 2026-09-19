<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Pure Rust eBPF Evaluation (NIGHT-improve-1, stage 1)

> Research artifact on the `pure-rust-prototype` branch. Nothing here
> ships on `main` unless the decision section (below) says so. The
> stage-1 goal is the owner-approved DeepSeek plan: rewrite ONE BPF
> program (the observer) with `aya-ebpf`, measure everything, and let
> the numbers decide whether a Phase 2 (limiter) or Phase 3 (full pure
> Rust) makes sense for zelynic.

## Why this document exists

zelynic's BPF side is C (`bpf/observer.bpf.c`, `bpf/limiter.bpf.c`)
compiled with `clang -target bpf`, while the userspace is already pure
Rust on `aya`. "Pure Rust" therefore means migrating the BPF programs
themselves to Rust via `aya-ebpf` — dropping the clang/libbpf C
toolchain dependency, keeping one language across the whole stack.

The evaluation criteria were fixed BEFORE any code was written (the
DeepSeek recommendation the owner adopted):

- **Stop condition**: if the Rust port costs more than 2x the LOC of
  the C twin AND the build hard-requires nightly, stop after stage 1
  and keep the branch as a research artifact.
- **Continue condition**: otherwise Phase 2 (limiter port behind a
  feature flag) and Phase 3 (drop C entirely) stay on the table.
- **Never** degrade the v11 line's contract: stable-toolchain builds,
  the 15 local gates, `build.sh check-all`, and the frozen
  userspace API stay intact on `main` regardless of the outcome.

## Naming note

The task label used throughout this branch is **NIGHT-improve-1**,
as briefed by the owner. A historical code comment in
`.cargo/config.toml` (the pro-native aliases) also carried an
"(NIGHT-improve-1)" tag; that label was never recorded in the
CHANGELOG ledger (which jumped from the pre-improve era straight to
NIGHT-improve-2). The stale comment is corrected in the final
docs-sync commit of this branch so the ledger has exactly one
NIGHT-improve-1. If the owner prefers a different number, every
reference lives on this branch only — renumbering is a one-commit
affair.

## The aya ecosystem as measured (2026-09-19)

All facts below were pulled from crates.io and the upstream repos on
2026-09-19 and then verified empirically in the research sandbox
(persisted under the session's `scripts/` area, outside this repo):

| Crate | Version | Notes |
|---|---|---|
| `aya` (userspace) | 0.14.0 (2026-06-24) | zelynic pins 0.13 — see compatibility section |
| `aya-ebpf` (BPF side) | 0.2.1 (2026-06-30) | edition 2024, MSRV 1.87 |
| `aya-obj` (ELF parser) | 0.2.1 | the parser inside aya 0.13.1 and 0.14 |
| `aya-build` | 0.2.0 | build.rs helper driving the nightly cross-build |
| `bpf-linker` | 0.11.1 (2026-09-07) | static musl prebuilts on GitHub releases |

Key upstream facts, verified against sources (not from memory):

1. **Nightly is still mandatory for the BPF side.** The official
   command remains `cargo +nightly build --target bpfel-unknown-none
   -Z build-std=core --release`. `bpf-linker`'s README documents no
   stable-toolchain alternative as of 0.11.1. The userspace side
   stays perfectly fine on stable.
2. **The `bpfel-unknown-none` target spec (tier 3) names bpf-linker
   as its default linker** (`linker-flavor: "bpf"`,
   `obj-is-bitcode: true`). rustc invokes `bpf-linker` from PATH
   automatically — hiding it produces `error: linker 'bpf-linker'
   not found`. This also means cargo's `-v` output never shows the
   linker step (it runs inside rustc), which confused the first
   sandbox measurements until it was tested directly.
3. **bpf-linker prebuilts make the "no system LLVM" story real.** A
   104 MB static musl binary from the GitHub release ran flawlessly
   in the research sandbox (a container with no sudo, no LLVM, no
   clang) and accepted rustc 1.100.0-nightly's LLVM 23 bitcode.
   Building bpf-linker from source is the path that needs system
   LLVM 21/22/23 — the prebuilt path does not.
4. **The aya-template restructured (2026-09)**: root workspace with
   `default-members` excluding the ebpf crate, a `*-common` shared
   types crate, and the userspace crate's build.rs (aya-build)
   driving the nightly cross-build. The old xtask layout is gone.
   zelynic's prototype deliberately does NOT adopt the workspace
   conversion (see the setup section for the blast-radius rationale).
5. **`#[cgroup_skb(egress)]` / `#[cgroup_skb(ingress)]` emit exactly
   the sections `cgroup_skb/egress` / `cgroup_skb/ingress`** —
   byte-for-byte the section names the C twin uses. Verified by
   reading the macro expansion in aya-ebpf-macros 0.2.0 and by
   parsing the built object.

## Compatibility with zelynic's pinned userspace (the critical question)

The make-or-break question for stage 1 was: **can zelynic's existing
aya 0.13.1 userspace load an object built with aya-ebpf 0.2.1?** The
upstream pairing is aya 0.14 + aya-ebpf 0.2, so this had to be
verified, not assumed.

Empirical answer (parse-level, via `aya-obj` 0.2.1 — the exact parser
compiled into aya 0.13.1; full harness protocol in the measurements
section):

- `observe_egress` classifies as `CgroupSkbEgress` and
  `observe_ingress` as `CgroupSkbIngress` — the section kinds
  `src/ebpf/loader.rs` attaches via `CgroupSkbAttachType::Egress` /
  `Ingress`.
- The map contract resolves by name: `cgroup_counters` and
  `cgroup_counters_ingress` (HASH, key 4, value 24, max 256) and
  `events` (RINGBUF, 2 MB) — identical to the C object's contract
  as coded in `bpf/observer.bpf.c`.
- The `license` section carries `GPL` exactly like the C object
  (required: `bpf_skb_cgroup_id` is a GPL-only helper).

So the Rust-built object is a **drop-in replacement at the ELF
contract level** for the loader zelynic ships today. One structural
divergence exists and is documented in the measurements section: the
`#[map]` macro emits legacy 28-byte `bpf_map_def` entries in a
`maps` section, while the C twin uses BTF-style `.maps` definitions.
aya 0.13.1 parses both formats; the loader never looks at the format,
only at the resulting map metadata.

Environmental limit discovered in the sandbox (not a defect): the
container runs unprivileged, where `BPF_MAP_CREATE` of HASH maps
succeeds but a 2 MB RINGBUF fails with EPERM (`RLIMIT_MEMLOCK` is
64 KB there), and after a failed ringbuf charge even subsequent hash
map creations EPERM. `Ebpf::load` in aya creates maps eagerly, so a
full syscall-level load of the three-map observer needs a privileged
host. The runtime A/B protocol for Phase 2 is written accordingly.

## The port contract (what "identical" means)

Every name, section, layout and helper the C object exposes, because
`src/ebpf/loader.rs` depends on each one:

| Contract element | C twin | Rust port |
|---|---|---|
| Program `observe_egress` | `SEC("cgroup_skb/egress")` | `#[cgroup_skb(egress)]` |
| Program `observe_ingress` | `SEC("cgroup_skb/ingress")` | `#[cgroup_skb(ingress)]` |
| Map `cgroup_counters` | HASH u32 -> cgroup_stats (24 B), 256 | identical |
| Map `cgroup_counters_ingress` | HASH u32 -> cgroup_stats (24 B), 256 | identical |
| Map `events` | RINGBUF 2 MB | identical |
| `struct event` layout | 52 B, `#[repr(C)]` mirror | compile-time size pin |
| `struct cgroup_stats` layout | 24 B | compile-time size pin |
| License | `GPL` | `GPL` |
| Counter semantics | in-place +=, init-then-relookup | line-for-line port |
| Event throttle | 1 event / 100 packets / cgroup | line-for-line port |
| IPv4/TCP/UDP parse | direct data/data_end access | `ctx.load` helper copies |

Two deliberate behavioral deltas, both documented for the decision
section:

1. The Rust port reads packet headers through `bpf_skb_load_bytes`
   (`ctx.load`) instead of direct `data`/`data_end` access. On
   non-linear skbs the C code silently skips the parse (ports stay
   0) while the helper-based read succeeds — the Rust port emits
   strictly more complete events in that corner. The port read
   bounds also differ (4 bytes needed vs the C check requiring the
   full 20-byte transport header).
2. The C ingress program ignores the `bpf_map_update_elem` return
   value; the port keeps that exact behavior with a comment saying
   so (a swallow-audit would flag it otherwise).

A hunt finding recorded while porting, independent of Rust vs C: the
`events` ringbuf is **written by the BPF side but never read by
zelynic's userspace** — `src/ebpf/loader.rs` reads only the two hash
maps. The C object has been paying one `bpf_ringbuf_reserve` per 100
packets per cgroup for output nobody consumes since the "no ring
buffer" simplification. Phase 2 should decide whether BOTH objects
drop the dead ringbuf or a consumer arrives; stage 1 keeps it for
exact parity.

## Stage 2: prototype setup (this branch)

The upstream aya-template converts the whole project to a cargo
workspace (root `Cargo.toml` with `default-members`, a `*-common`
crate, userspace `build.rs` driving the nightly cross-build). That
is the right shape for a NEW project — and the wrong shape for this
evaluation, because a workspace conversion touches the root
manifest, the gate scripts, CI, `deny.toml` and the release
toolchain in one move. Stage 1 needs the smallest possible blast
radius. So the prototype uses a **detached crate** instead:

```
ebpf/                     nightly-only, invisible to the default build
  Cargo.toml              empty [workspace] table = not in the root graph
  Cargo.lock              committed: the research artifact is reproducible
  .cargo/config.toml      bpfel-unknown-none target + build-std, so the
                          build is exactly `cd ebpf && cargo +nightly build --release`
  src/main.rs             the observer port (stage 3)
```

Why each choice is safe for the v11 line (all verified locally after
the crate landed):

- The empty `[workspace]` table keeps `ebpf/` out of every
  root-level cargo invocation: `build.sh check-all` (fmt, clippy
  `--all-targets --all-features`, tests) runs unchanged and green —
  measured, not assumed.
- `rust-toolchain.toml` at the root still pins 1.98.1 for the
  default build; the ebpf crate is only ever touched through an
  explicit `cargo +nightly`, which overrides the toolchain file.
- The LOC gate scans root `src/` + `test/` only; the version-sync
  gate reads the root manifest only; the header gate is satisfied by
  giving every new file the standard GPL header.
- One gate adaptation was required: `.codespellrc` now also skips
  `./ebpf/target` (build artifacts of the new crate; the entry
  follows the existing `./target` precedent). No other gate changed.
- `ebpf/target/` is covered by the existing root `.gitignore`
  `target/` rule (verified with `git check-ignore`).

The skeleton build (stage 2 commit) compiles a minimal
`#[cgroup_skb(egress)]` stub end to end — nightly 1.100.0, build-std
core, bpf-linker 0.11.1 from PATH — and the object passes the
verification harness: parse OK, license `GPL`, section classified as
`CgroupSkbEgress`. Cold build cost of the whole toolchain path
(build-std core + aya-ebpf + crate): ~22 s; warm rebuild: ~0.4 s.
The shipped zelynic binary and both C objects are untouched by this
stage, so no benchmark was run (docs-and-skeleton only).

## Stage 3: the observer port

`ebpf/src/main.rs` (269 lines including the contract comments and
compile-time pins) is the line-for-line port of
`bpf/observer.bpf.c` (172 lines). Both programs, all three maps,
the event and stats layouts, the throttle, and the license section
carry over exactly; the section names come from the
`#[cgroup_skb(egress)]` / `#[cgroup_skb(ingress)]` macros, which
emit precisely the sections the C `SEC(...)` annotations produce.

Verification output of the built object (3864 bytes lean; 128,136
bytes with `-Cdebuginfo=2 -Clink-arg=--btf`) through the harness
that uses aya-obj 0.2.1 + aya 0.13.1 — the exact userspace stack
zelynic pins:

```
PARSE OK
license: "GPL"
programs:
  observe_egress:   section=CgroupSkbEgress
  observe_ingress:  section=CgroupSkbIngress
maps:
  cgroup_counters:          HASH    key=4  value=24  max=256
  cgroup_counters_ingress:  HASH    key=4  value=24  max=256
  events:                   RINGBUF 2 MB
contract: all five names FOUND
LOAD env-limited: ringbuf EPERM under a 64 KB RLIMIT_MEMLOCK
                  (unprivileged sandbox; hash maps create fine)
```

The port adds four compile-time layout pins
(`size_of::<CgroupStats>() == 24`, `Event == 52`, `Ipv4Header == 20`,
`PortsHeader == 4`) — a class of guarantee the C file cannot express;
the C side relies on the kernel headers for the same invariants.

Build timings on this machine (see stage 4 for the full table):
warm rebuild 0.31 s lean / 14.1 s for the BTF+debuginfo variant
(that number includes rebuilding the crate and relinking with debug
data).

## Stage-1 task map (DeepSeek plan, one commit each)

1. Research (this document's ecosystem and compatibility sections).
2. Prototype setup: the `ebpf/` crate skeleton, toolchain wiring,
   zero blast radius on the default build.
3. The observer port: `bpf/observer.bpf.c` translated to aya-ebpf.
4. Measurements: LOC, build times, object layout, verification
   harness output.
5. Decision: apply the stop/continue criteria to the numbers.
6. Docs sync: CHANGELOG entry, stale-reference fixes, pointers from
   the main docs to this branch.
<!-- ZELYNIC-DISCLAIMER -->
<!--
  Documentation Disclaimer — read before relying on any data point.

  This document may contain stale data, hardcoded counts, or outdated
  file paths and symbol names. Maintainers update source code but may
  forget to sync every doc — perfect sync across every .md file is a
  known maintenance burden with diminishing returns.

  Source code (`src/**/*.rs`, `bpf/*.bpf.c`) is the single source of
  truth. Always cross-check against the actual source files before
  relying on any specific number (target count, LOC, rate bound),
  file path, function name, or config key.

  If you find a discrepancy, please open a PR — the doc is wrong, not
  the source.
-->
