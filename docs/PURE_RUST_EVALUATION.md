<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Pure Rust eBPF Evaluation (NIGHT-improve-1, stage 1 + phase 2 + phase 3)

> The full record of zelynic's C-to-Rust BPF migration. Stage 1
> (the observer port) and phase 2 (the limiter port) ran as research
> on the `pure-rust-prototype` branch, merged into `main` as a pure
> fast-forward (392ee80 -> ca74cdb). Phase 3 — the owner's explicit
> go-totally-pure-Rust directive — was then executed ON main as
> three stages: the promoted build path, the embedded loaders, and
> the deletion of `bpf/*.bpf.c` (see the Phase 3 section). The
> `ebpf/` crate is now the production BPF source and its objects
> ship INSIDE the binary; the default build (feature off) stays
> stable-toolchain-only. The stage-1 goal was the owner-approved
> DeepSeek plan: rewrite ONE BPF program (the observer) with
> `aya-ebpf`, measure everything, and let the numbers decide — they
> did, at every gate.

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

The task label used throughout this work is **NIGHT-improve-1**,
as briefed by the owner. A historical code comment in
`.cargo/config.toml` (the pro-native aliases) also carried an
"(NIGHT-improve-1)" tag; that label was never recorded in the
CHANGELOG ledger (which jumped from the pre-improve era straight to
NIGHT-improve-2). The stale comment is corrected in the final
docs-sync commit of stage 1 so the ledger has exactly one
NIGHT-improve-1. If the owner prefers a different number, every
reference lives on the research artifact surface (this document,
the CHANGELOG entries, the ebpf/ crate comments) — renumbering
stays a one-commit affair.

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

## Stage 2: prototype setup (the detached crate)

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

## Stage 4: measurements

All numbers measured on the research sandbox (same machine class as
the frame-bench baseline runs; 2026-09-19, nightly 1.100.0,
bpf-linker 0.11.1 prebuilt musl, aya-ebpf 0.2.1).

### Line counts

| File | total | blank | comment | code |
|---|---|---|---|---|
| `bpf/observer.bpf.c` | 172 | 21 | 16 | 135 |
| `ebpf/src/main.rs` | 269 | 29 | 69 | 171 |

Ratios: 1.56x total, **1.27x code-only**. The Rust side carries 53
more comment lines than the C twin because the port documents the
userspace contract, the parity decisions, and the swallow rationale
in place. The DeepSeek stop criterion (>2x LOC) is not met on either
count.

### Build cost

| Path | cold | warm | notes |
|---|---|---|---|
| Rust (lean) | 22.5 s | 0.31 s | cold = full pipeline: build-std core, aya-ebpf, crate, bpf-linker |
| Rust (BTF + debuginfo) | 14.1 s* | — | *incremental over the lean artifacts; adds .BTF/.BTF.ext and DWARF |
| C (`clang -O2 -target bpf`) | not measurable here | — | no clang in the sandbox; single-file C compile is sub-second by nature, but needs a clang + libbpf-headers toolchain present |

The honest comparison is not seconds but toolchain surface: the C
path needs clang and libbpf headers installed; the Rust path needs
`rustup toolchain install nightly --component rust-src` plus one
prebuilt bpf-linker binary (no system LLVM, no sudo, no clang). The
22.5 s cold cost is paid once per clean checkout; every subsequent
edit is the 0.31 s warm rebuild.

### Object properties

| Property | C twin | Rust port |
|---|---|---|
| Lean object size | not built here (no clang in sandbox) | 3864 B |
| BTF + debuginfo variant | default (`clang -g`) | 128,136 B |
| Map definition format | BTF-style `.maps` section | legacy 28-byte `bpf_map_def` in `maps` section |
| Program sections | `cgroup_skb/egress`, `cgroup_skb/ingress` | identical (macro-emitted) |
| License section | `GPL` | `GPL` |

The map-format divergence is cosmetic for zelynic: aya 0.13.1 parses
both formats into the same map metadata, and the loader only ever
sees names and geometry (verified in the stage-3 output).

### Render-path A/B (owner benchmark protocol)

10 s formal frame-bench at the pinned 80x40 harness geometry, A =
c7ed061 (pre-port) in a throwaway worktree, B = 1eef11e (the port
commit):

| metric | before | after | delta |
|---|---|---|---|
| density gini | 0.1812 | 0.1812 | 0.00% |
| frame entropy | 4.1913 | 4.1913 | 0.00% |
| dirty cells/frame | 755.42 | 755.39 | -0.00% |
| bytes/frame | 1437.54 | 1437.55 | +0.00% |
| emit bytes/frame | 1375.61 | 1375.61 | 0.00% |
| fps | 14627 | 14400 | -1.55% (machine noise) |

Every visual metric identical, as expected by construction: the
detached ebpf crate is not part of the shipped binary, so the
render path measured by the harness cannot change. The run exists to
prove that claim with data instead of assertion, per the owner rule
that code-changing commits get the benchmark.

### Verification harness (reproducibility)

The harness used for stage-3/4 verification is deliberately NOT
committed as a crate (blast-radius discipline). It is small enough
to reproduce verbatim — a throwaway cargo project depending on
`aya = "0.13"` and `aya-obj = "0.2"` with this main:

```rust
fn main() {
    let data = std::fs::read(std::env::args().nth(1).unwrap()).unwrap();
    let obj = aya_obj::Object::parse(&data).unwrap();   // parse-only
    for (name, p) in &obj.programs {
        println!("program {name}: {:?}", p.section);
    }
    for (name, m) in &obj.maps {
        println!("map {name}: type={} key={} value={} max={}",
            m.map_type(), m.key_size(), m.value_size(), m.max_entries());
    }
    match aya::Ebpf::load(&data) {                      // creates maps
        Ok(_) => println!("LOAD OK"),
        Err(e) => println!("LOAD env-limited: {e}"),    // needs privileges
    }
}
```

Run it against `ebpf/target/bpfel-unknown-none/release/zelynic-observer`.
On an unprivileged host the final line reports the ringbuf EPERM; on
a privileged host (root, or CAP_BPF + CAP_SYS_ADMIN) it prints LOAD
OK and Phase 2 can go one step further: run the real observe loop
against the Rust object by placing it at `bpf/observer.bpf.o` — the
loader reads the object from a path, so the swap needs no rebuild.

(Phase 2 note: the harness was later extended with per-map pinning
verification and a contract-table mode that hard-fails on geometry
mismatch or unexpected symbols — the same scratch-project protocol,
one profile per object. The Phase 2 section carries its output; this
stage-1 listing stays verbatim as the reproduction baseline.)

## Stage 5: the decision

The stop criterion was fixed before any code existed: **stop if the
port costs >2x the C LOC AND hard-requires nightly.** The
measurements say:

| Criterion | Threshold | Measured | Verdict |
|---|---|---|---|
| LOC ratio (total) | > 2x | 1.56x | pass |
| LOC ratio (code-only) | > 2x | 1.27x | pass |
| Nightly required for BPF builds | unavoidable blocker | still true (aya-ebpf 0.2.1, bpf-linker 0.11.1) | cost, not blocker |

The conjunction is false, so by the plan's own letter stage 1
**passes**. But the honest decision is broader than one criterion,
so here is the full picture.

### What worked better than expected

- **Drop-in compatibility with the pinned userspace.** The object
  loads and classifies through aya 0.13.1 — the version zelynic
  ships today — with identical names, sections, and map geometry.
  Phase 2/3 would need ZERO userspace changes for the observer.
- **The toolchain story.** No clang, no system LLVM, no sudo, no
  libbpf headers: rustup nightly + rust-src + one prebuilt static
  bpf-linker. This was the biggest pre-research fear (bpf-linker's
  source build needs specific LLVM versions) and the prebuilt path
  dissolves it.
- **Compile-time layout pins.** The Rust side asserts every shared
  struct size at compile time; the C side trusts kernel headers.
- **The detached-crate design.** The whole prototype lives beside
  the mainline without touching it — gates, CI, release toolchain,
  and the frozen v11 contract all stayed green through five commits.

### What did not

- **Nightly is still mandatory.** No stable-Rust BPF path exists in
  the aya ecosystem as of 2026-09-19. This is the single real cost.
- **The cold build is 22.5 s** (build-std core dominates) against a
  sub-second C compile — paid once per clean checkout, 0.31 s after.
- **Toolchain weight**: nightly toolchain + a 104 MB linker binary
  versus clang + libbpf-dev, which every distro packages.

### Phase 2 assessment (the limiter)

`bpf/limiter.bpf.c` (364 lines) uses a **strict subset** of the BPF
surface the observer port already proved: the same
`cgroup_skb/ingress|egress` sections, only four helpers
(`bpf_skb_cgroup_id`, `bpf_ktime_get_ns`, `bpf_map_lookup_elem`,
`bpf_map_update_elem` — three already in the observer port), and
only HASH and ARRAY maps (9 + 2). No spin locks, no timers, no
exotic program types. The port is mechanical: same crate, same
harness, the two ARRAY maps and `bpf_ktime_get_ns` are the only new
API surface. One semantic to port carefully: the limiter's maps are
pinned by name (LIBBPF_PIN_BY_NAME), which aya-ebpf supports via
`HashMap::pinned` / `Array::pinned`.

Phase 2 should also settle the dead-ringbuf question from the
research section: either both objects drop the unconsumed `events`
map or a consumer finally reads it.

> Phase 2 status: **DONE** — ported, verified, and measured. See the
> Phase 2 section below; the stop criteria pass with a wider margin
> than stage 1 (code-only ratio 0.93x — the Rust side is smaller
> than the C twin). The dead-ringbuf question is observer-scoped
> only (the limiter has never had a ringbuf) and stays open for
> Phase 3.

### Verdict

1. **Stage 1: SUCCESS.** The criteria pass, the port is verified
   drop-in at the ELF-contract level, and the prototype is a
   reproducible research artifact.
2. **Phase 2 (limiter port): GO.** Mechanical work,
   subset surface, high information value — it completes the
   pure-Rust picture before any mainline decision. **DONE** — see
   the Phase 2 section; every criterion passed with margin.
3. **Phase 3 (drop C from the mainline): was HOLD, then EXECUTED
   by owner directive.** The original HOLD rationale: a mainline
   nightly-dependency for BPF builds would contradict the repo's
   own dormant-mode toolchain pin. The owner reviewed the phase-2
   evidence and explicitly overrode it ("delete the C/legacy code,
   totally pure Rust") — accepting the nightly cost. Phase 3 ran
   as three stages on main; the design kept the HOLD's core
   concern intact: the DEFAULT build (feature off) never touches
   nightly, so the dormant-mode stable pin still governs every
   non-ebpf build. See the Phase 3 section for the execution
   record.
4. **Adoption note (historical, superseded by phase 3):** the
   DeepSeek plan's `--features ebpf-rust` flag turned out to be
   unnecessary even for adoption — both loaders read the object
   from a file path, so the integration point was the object file
   itself. Phase 3 replaced that mechanism entirely: the objects
   are now embedded via include_bytes! and the file-path contract
   is gone.

### Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| aya-ebpf 0.2.x API churn (crate is 3 months old) | medium | low (detached crate, locked file) | ebpf/Cargo.lock committed; ports are 269 + 396 lines across two binaries |
| bpf-linker prebuilt lag behind new nightly LLVM | medium | build break until new prebuilt | pin the working nightly in docs; prebuilts ship per release |
| aya 0.13 -> 0.14 userspace pairing changes | low | low | compatibility verified empirically, not assumed; re-verify per bump |
| Nightly-only stalls forever | unknown | Phase 3 never happens | superseded: the owner accepted the nightly cost and phase 3 shipped; the dated pin caps the drift risk |

## Phase 2: the limiter port (NIGHT-improve-1, phase 2)

The Phase 2 GO verdict above was executed as four
commits (task map at the bottom of this document). This section is
the stage-2 evidence: what was ported, the pinning contract that
made it non-trivial, the verification output, and the measurements.

### The port

`ebpf/src/bin/limiter.rs` (396 lines) is the line-for-line port of
`bpf/limiter.bpf.c` (364 lines), built as a second detached binary
(`zelynic-limiter`) in the same crate. Both programs carry over:
`enforce_dl` on `cgroup_skb/ingress` and `enforce_ul` on
`cgroup_skb/egress`. The token-bucket core ports verbatim — the
fractional remainder accumulation (schema v2) and the
overflow-safe fill-detect path (NIGHT-cybersecurity-1) including
its guard comments. The `get_stats` / `get_bucket`
init-then-relookup helpers keep their insert-result-ignored
behavior with the rationale commented in place.

One structural choice differs from the C twin, on purpose: the C
file duplicates the whole enforcement flow in both program bodies;
the port factors the shared tail into a single
`#[inline(always)] try_enforce` helper that receives the three
direction-specific maps. LLVM inlines it into both programs, so the
verifier sees the same instruction shape and the object stays a
faithful translation — measured, not assumed, via the harness below
(sections, map geometry, and pinning all verify identically for
both programs).

### The pinning contract (the real phase-2 question)

The stage-1 observer maps are anonymous (no pinning); the limiter's
nine maps are the opposite — every one declares
`LIBBPF_PIN_BY_NAME`, and the entire persistence design of zelynic
(policies surviving process exit) rests on that field. So phase 2's
make-or-break question was: does the pinning flag survive the round
trip through a `#[map]`-emitted legacy `bpf_map_def`, aya-obj's
parser, and aya 0.13.1's loader?

Verified from the pinned sources, not from memory:

1. `aya_ebpf`'s `HashMap::pinned` / `Array::pinned` constructors set
   `PinningType::ByName` in the emitted `bpf_map_def`.
2. `aya-obj` 0.2.1 (the exact parser inside aya 0.13.1) reads the
   `pinning` field of the legacy 28-byte `bpf_map_def` — the field
   is public in `maps.rs` and the harness reads it directly.
3. `aya` 0.13.1's `EbpfLoader` branches on `PinningType::ByName` at
   load and calls `MapData::create_pinned_by_name(path, ...)`,
   exactly the libbpf `PIN_BY_NAME` behavior the comment in
   `src/ebpf/limiter/mod.rs` documents.

A detail discovered while verifying point 3, recorded so nobody
trips on it later: with no `map_pin_path` configured, aya pins
ByName maps to `/sys/fs/bpf` (the libbpf default root), NOT to
`/sys/fs/bpf/zelynic`. The production loader always sets
`map_pin_path(PIN_DIR)`, so zelynic is unaffected — but anyone
hand-loading the object with `aya::Ebpf::load` on a privileged host
will scatter nine pins into the bpffs root. The harness therefore
treats the load step as environment-limited by default.

### The limiter port contract

| Contract element | C twin | Rust port |
|---|---|---|
| Program `enforce_dl` | `SEC("cgroup_skb/ingress")` | `#[cgroup_skb(ingress)]` |
| Program `enforce_ul` | `SEC("cgroup_skb/egress")` | `#[cgroup_skb(egress)]` |
| Maps `cgroup_{policy,bucket}_{dl,ul}` | HASH u32 -> policy/bucket (24 B), 1024, pinned | identical |
| Maps `group_bucket_{dl,ul}` | HASH u32 -> bucket (24 B), 256, pinned | identical |
| Map `watchdog_deadline` | ARRAY u32 -> u64, 1, pinned | identical |
| Map `schema_version` | ARRAY u32 -> u32, 1, pinned | identical |
| Map `cgroup_limiter_stats` | HASH u32 -> limiter_stats (32 B), 1024, pinned | identical |
| Map pinning | `__uint(pinning, LIBBPF_PIN_BY_NAME)` x9 | `HashMap::pinned` / `Array::pinned` x9 |
| `struct policy` layout | 24 B | compile-time size pin |
| `struct bucket` layout | 24 B (schema v2) | compile-time size pin |
| `struct limiter_stats` layout | 32 B | compile-time size pin |
| License | `GPL` | `GPL` |
| Refill math | frac_rem + fill-detect | line-for-line port |
| stats/bucket init | insert-result ignored, relookup | line-for-line port |

### Verification output (scratch harness, 2026-09-19)

The stage-1 harness was rebuilt for this phase with one extension:
per-map pinning verification (the parse-level field that phase 2's
contract depends on), plus a contract-table mode that fails on any
geometry mismatch or unexpected symbol. The observer object was
re-verified first as a regression baseline — its three maps still
report `pinned=false`, which proves the harness genuinely reads the
pinning field rather than defaulting to true.

```
PARSE OK (zelynic-limiter)
OK   program enforce_dl (section matches CgroupSkbIngress)
OK   program enforce_ul (section matches CgroupSkbEgress)
OK   map cgroup_policy_dl:      HASH  key=4 value=24 max=1024 pinned=true
OK   map cgroup_bucket_dl:      HASH  key=4 value=24 max=1024 pinned=true
OK   map group_bucket_dl:       HASH  key=4 value=24 max=256  pinned=true
OK   map cgroup_policy_ul:      HASH  key=4 value=24 max=1024 pinned=true
OK   map cgroup_bucket_ul:      HASH  key=4 value=24 max=1024 pinned=true
OK   map group_bucket_ul:       HASH  key=4 value=24 max=256  pinned=true
OK   map watchdog_deadline:     ARRAY key=4 value=8  max=1    pinned=true
OK   map schema_version:        ARRAY key=4 value=4  max=1    pinned=true
OK   map cgroup_limiter_stats:  HASH  key=4 value=32 max=1024 pinned=true
LOAD env-limited: map error: map `Some("schema_version")` requested pinning. pinning failed
CONTRACT: all names, sections, layouts, and pins verified
```

The load line is the expected unprivileged-sandbox result. The exact
failure point varies between runs with the loader's map iteration
order (a std HashMap), but always lands in the environment-limited
class: this sandbox's `/sys/fs/bpf` is a root-owned read-only
directory, so the first ByName pin write fails. The message itself
is the strongest parse-level evidence phase 2 has: the loader took
the `PinningType::ByName` branch and attempted the pin — the exact
code path the production loader exercises with
`map_pin_path(PIN_DIR)` on a real host. Nothing leaks (the pin
directory is unwritable and empty). The observer regression run
reports all `pinned=false` and the ringbuf EPERM, as in stage 1.

### Phase 2 measurements

Line counts (same methodology as the stage-4 table; the script
reproduces the stage-4 numbers on the observer pair exactly):

| File | total | blank | comment | code |
|---|---|---|---|---|
| `bpf/limiter.bpf.c` | 364 | 38 | 101 | 225 |
| `ebpf/src/bin/limiter.rs` | 396 | 44 | 143 | 209 |

Ratios: **1.09x total, 0.93x code-only.** This is the first port
where the Rust code lines are fewer than the C twin's — the C side
duplicates the enforcement flow in both program bodies, and the
factored Rust helper erases the duplication while the comment load
grows. The DeepSeek stop criterion (>2x) is not merely met; the
trend from observer (1.27x code) to limiter (0.93x code) shows the
ratio is a function of C-side duplication, not of Rust verbosity.

Build cost (same machine class as stage 4; both binaries):

| Path | cold | warm | notes |
|---|---|---|---|
| Rust (lean, both objects) | 22.6 s | 0.32 s | cold includes build-std core + aya-ebpf + both binaries; the limiter adds ~0.1 s over stage-1's 22.5 s |
| Rust (BTF + debuginfo) | 15.3 s* | — | *incremental over the lean artifacts; limiter object 144,392 B (observer: 128,136 B, matching stage 4) |

Object properties:

| Property | C twin | Rust port |
|---|---|---|
| Lean object size | not built here (no clang in sandbox) | 5,624 B |
| BTF + debuginfo variant | default (`clang -g`) | 144,392 B |
| Map definition format | BTF-style `.maps` section | legacy 28-byte `bpf_map_def` in `maps` section (pinning field set) |
| Program sections | `cgroup_skb/ingress`, `cgroup_skb/egress` | identical (macro-emitted) |
| License section | `GPL` | `GPL` |

### Render-path A/B (owner benchmark protocol)

10 s formal frame-bench at the pinned 80x40 harness geometry, A =
392ee80 (pre-port, in a throwaway worktree), B = 9562cf6 (the
branch tip after the three phase-2 commits; its src/ tree is
byte-identical to the port commit's):

| metric | before | after | delta |
|---|---|---|---|
| density gini | 0.1812 | 0.1812 | 0.00% |
| frame entropy | 4.1913 | 4.1912 | -0.00% |
| dirty cells/frame | 755.4 | 755.4 | -0.00% |
| bytes/frame | 1437.5 | 1437.6 | +0.00% |
| emit bytes/frame | 1375.6 | 1375.6 | -0.00% |
| fps | 14486 | 14322 | -1.1% (machine noise) |

Every visual metric identical, as expected by construction: none
of the phase-2 commits touch `src/**`, so the shipped render path
measured by the harness cannot change. The baseline run also
reproduced the stage-4 numbers exactly (gini 0.1812, entropy
4.1913, dirty 755.4) — the harness stays deterministic across
machines and sessions. The run exists to prove the claim with data
instead of assertion, per the owner rule that code-changing
commits get the benchmark (the same protocol stage 1 applied to
its port commit).

Adoption path: identical to the observer's — place the built object
at `bpf/limiter.bpf.o` and the existing loader reads it with zero
userspace changes (the integration point is the object file, not a
feature flag). On a privileged host the runtime A/B protocol from
stage 1 applies: swap the object, run the observe/limit loop, and
compare the enforcement behavior against the C twin.

### Phase 2 findings (hunt)

Beyond the port itself, the phase-2 hunt recorded three items:

1. **Stale CI comment (resolved on mainline, post-merge):**
   `.github/workflows/codeql.yml` said "shellcheck/codespell gates
   in ci.yml instead" — codespell is there, but ci.yml contains no
   shellcheck job at all (and no shfmt). The comment predates a
   workflow cleanup. Recorded for the owner during phase 2 and
   fixed in the mainline docs-sync commit that followed the merge:
   the comment now points Python tooling at the ci.yml codespell
   gate and shell coverage at the local gate-keepers shellcheck.
2. **The default-pin-path footgun** (documented in the pinning
   contract section above): plain `Ebpf::load` pins ByName maps to
   the bpffs root. Production code is unaffected; the hazard only
   exists for hand-loading experiments.
3. **The dead-ringbuf question is observer-scoped.** The limiter
   has never carried a ringbuf, so phase 2 has nothing to decide
   there. The question (drop the unconsumed `events` map from the
   observer or add a consumer) remains open and is now explicitly
   a Phase 3 decision item.

### Phase 2 verdict

Both stop criteria pass with room to spare (1.09x total, 0.93x
code-only, nightly unchanged as the accepted cost), the pinning
contract round-trips through the pinned userspace stack exactly,
and the mainline stayed green throughout (gate-keepers 15/15,
build.sh check-all, and the render-path A/B above is
metric-identical as expected — zero shipped-surface changes,
proven with data). Phase 3 (drop C from the mainline) remains HOLD
pending a stable-Rust aya-ebpf; the detached crate now covers BOTH
production objects, so the research artifact is complete and the
Phase 3 decision has everything it needs.

## Phase 3: executed on main (NIGHT-improve-1, phase 3)

The owner read the phase-2 record and gave the explicit directive:
delete the C/legacy code, make zelynic totally pure Rust — the
nightly cost accepted. The HOLD was overridden by its own owner;
the design below keeps the HOLD's real concern (the dormant-mode
stable pin) intact. Three stages, one commit each, all green:

### Stage 1 — the promoted build path (1fa542e)

The root `build.rs` now drives the eBPF build: with the `ebpf`
feature on it runs a NESTED `rustup run nightly-2026-09-18 cargo
build --release --locked --target bpfel-unknown-none -Z
build-std=core` with cwd inside `ebpf/`, stages both objects into
OUT_DIR (with an ELF-magic check), and the loaders embed them.
Two aya-build upstream lessons were reproduced and fixed locally
before the commit landed: the `CARGO` env var a build script
receives points at the RESOLVED root toolchain's cargo (stable —
silently dropping the toolchain file and the build-std flag), and
the parent cargo exports `RUSTC` pointing at the stable rustc,
which must be scrubbed from the child env or build-std core
compiles against the wrong sysroot. The dated nightly pin moved
from prose to a real file (`ebpf/rust-toolchain.toml`, with
rust-src + rustfmt) — the risk-register mitigation made
structural. CI followed: every build-carrying job installs the
pin and bpf-linker 0.11.1; the eBPF Build matrix dropped
clang/libbpf-dev and now gates the crate with rustfmt and builds
it directly.

### Stage 2 — the embedded loaders (76b9547)

`include_bytes!` replaced the entire on-disk object pipeline:
`OBSERVER_ELF` (loader.rs) and `LIMITER_ELF`
(limiter/types.rs) carry the objects inside the binary.
`find_bpf_object()` (both copies), the four-path candidate
search, and the "BPF object file not found. Compile with: clang
..." error strings are deleted — the error class is structurally
impossible, verified by an unprivileged runtime smoke test (the
binary proceeds straight to the root check). The pinning flow is
untouched; `Ebpf::load`/`EbpfLoader::load` receive the same
bytes aya would have read from disk. The formal 10 s render-path
A/B (A = 1fa542e, B = 76b9547) is metric-identical on every
visual metric — recorded in PERFORMANCE.md, because the owner
rule gives every shipped-surface commit the benchmark.

### Stage 3 — C deleted (f844038)

`bpf/observer.bpf.c` and `bpf/limiter.bpf.c` are gone (-1,061
lines against +504 of pure-Rust plumbing across the phase). No
clang, no libbpf-dev, no linux-libc-dev anywhere in the build
surface. install.sh ships one self-contained binary and
pre-checks the two pure-Rust prerequisites with install pointers;
package.sh and release.yml stop packaging loose objects (the
tarball is binary + docs + scripts); gate 12 became rustfmt on
the ebpf/ crate; the changes-job core pattern now watches `ebpf/`
(it never did during the research era — a blind spot closed);
codeql.yml drops the C datapath story; the live-contract comments
point at their in-tree counterparts.

### Toolchain contract after phase 3

| Build | Toolchain | Notes |
|---|---|---|
| Default (`cargo build` / check-all / tests) | stable 1.98.1 pin | the dormant-mode contract, unchanged |
| ebpf-feature builds (incl. clippy --all-features) | stable root + nested dated nightly | nightly entered only through build.rs, never the default path |
| Direct ebpf work (`cd ebpf && cargo build`) | dated nightly pin | resolves from ebpf/rust-toolchain.toml |
| Prerequisites | rustup + bpf-linker 0.11.1 prebuilt | host install: ./scripts/bootstrap-ebpf.sh (NIGHT-host-1); no clang, no system LLVM, no libbpf headers |

The runtime A/B on a privileged host (swap objects, run the
observe/limit loop against real traffic) is the owner's own next
step — the phase-2 sandbox was unprivileged by environment, and
the phase-3 build reproduces both documented object sizes exactly
(3,864 / 5,624 B), so the bytes that load on the host are the
bytes the harness verified at the ELF-contract level.

### NIGHT-host-1: the first host run demanded a one-command bootstrap

The owner's first host build after the merge spent the whole
dependency compile and then hit the generic prerequisite panic —
two manual installs (a rustup command plus a bpf-linker tar.zst
download/extract/place) with no automation. NIGHT-host-1 fixes the
path: scripts/bootstrap-ebpf.sh reads the dated pin straight from
ebpf/rust-toolchain.toml (bump the pin, the script follows — only
the bpf-linker version lives in the script, pin and linker being a
validated pair), installs the toolchain with the minimal profile +
rust-src + rustfmt, downloads the bpf-linker 0.11.1 prebuilt for
the host arch into ~/.local/bin (no sudo, no system LLVM), and
extracts the tar.zst with whichever decompressor the host actually
has — GNU tar --zstd, a zstd binary, or python3 with the zstandard
module (the last is not hypothetical: the dev sandbox itself has
no zstd binary and no tar --zstd support). The script is
idempotent, re-probes everything it changes, and --check reports
status without side effects. build.rs gained a matching preflight
that names the exact missing prerequisite in milliseconds, before
any compile time is spent — which also closed a measured blind
spot: a fully warm ebpf/target skips the link step, so a host with
bpf-linker invisible on PATH used to build "successfully" until
the next clean. The sandbox reproduced that silent pass before the
fix and rejects it after (reproduced, then closed). CI keeps its
own install (dtolnay/rust-toolchain + sudo to /usr/local/bin) —
the ephemeral privileged runner fit, documented in the script
header.


## Stage-1 task map (DeepSeek plan, one commit each)

1. Research (this document's ecosystem and compatibility sections).
2. Prototype setup: the `ebpf/` crate skeleton, toolchain wiring,
   zero blast radius on the default build.
3. The observer port: `bpf/observer.bpf.c` translated to aya-ebpf.
4. Measurements: LOC, build times, object layout, verification
   harness output.
5. Decision: apply the stop/continue criteria to the numbers.
6. Docs sync: CHANGELOG entry (the discoverable pointer to this
   branch), the stale gate-count references fixed (three files said
   14 checks; the real count has been 15 since the test-tree
   discipline gate landed), and the stale "(NIGHT-improve-1)" tag
   removed from the pro-native alias comment in .cargo/config.toml
   so this task owns the label cleanly.

## Phase-2 task map (one commit each)

1. The port: `ebpf/src/bin/limiter.rs` plus the `zelynic-limiter`
   binary declaration — both programs, all nine pinned maps, the
   token-bucket core, harness-verified before commit.
2. Measurements and decision: this document's Phase 2 section (LOC
   ratio 1.09x/0.93x, build cost, object properties, the pinning
   contract verification, and the hunt findings).
3. Docs sync: CHANGELOG entry for phase 2 and the stale-reference
   sweep across the repo's pointers to this branch.
4. Benchmark: the formal 10 s render-path A/B (A = 392ee80 in a
   throwaway worktree, B = the branch tip), recorded in the
   measurements section — every visual metric identical, proving
   the zero-shipped-surface claim with data instead of assertion.

## Phase-3 task map (one commit each)

1. The promoted build path: root build.rs nested nightly build +
   OUT_DIR staging with the ELF-magic check, the dated toolchain
   pin file, publish = false, and the CI toolchain installs
   (1fa542e).
2. The embedded loaders: include_bytes! switch, deletion of the
   object-discovery pipeline, embedded-object drift pins; the
   benchmark record commit followed (76b9547, 39c09e4).
3. C deleted: bpf/*.bpf.c removed, install/package/release
   reworked to the self-contained binary, gate 12 -> ebpf rustfmt,
   the changes-job pattern watching ebpf/, codeql cleanup
   (f844038).
4. Docs sync: this section, the toolchain contract table, and the
   repo-wide sweep (README, CONTRIBUTING, KERNEL_COMPATIBILITY,
   SAFETY_ANALYSIS, DRAGON_ARCHITECTURE, CROSS_DISTRO historical
   note, USAGE, the disclaimer source-of-truth paths).
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
