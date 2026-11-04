<!-- Copyright (C) 2026 rezky_nightky -->
<!-- SPDX-License-Identifier: AGPL-3.0-only -->

# Flow Mastery and Adaptive Intelligence Audit — 2026-11-05 (night-netrunner-2)

The pure depth audit the owner ordered: four phases over the flow
machinery — Flow Coherence ("Smoothbore"), Adaptive Capability
("Orchestra"), Future-Proofing (Type Seams), and Maintenance
Trajectory. No new features, no Layer 5, no AI-ML: the intelligence
this audit looks for is the deterministic kind — capability probes
and heuristic laws already in the tree. One friction find surfaced
and it is fixed in the same commit that carries this audit; the two
design-only surfaces (Orchestra, type alias) are recorded here as
designs, exactly the scope the task brief set.

## The audit table

| Phase | Verdict | Evidence (file:line) |
|-------|---------|----------------------|
| **1. Flow Coherence (Smoothbore)** | **SMOOTHBORE** (one friction find, fixed) | Authority: every layer owns its state alone — `recwn_socket_hint` has exactly one writer (`ebpf/src/recwn_flow.rs:229-248`, `recwn_prime`) and one reader (`recwn_flow.rs:170`); `pace_socket_hint` one writer (`ebpf/src/pace_flow.rs:250-268`) and one reader (`pace_flow.rs:184`); `pace_saved_stamp` one writer (`pace_flow.rs:298-324`); the ECN debt words move only through the charge/pay pair (`ebpf/src/ecn.rs:146-161`, `:202-231`) at the two call-site shapes the call-site law pins (`ebpf/src/enforce.rs:444-459`, `:520-537`). Dispatch: `try_enforce` is one linear chain — unlimited fast path first (`enforce.rs:64-123`), clock (`:134`), window gate (`:143`), watchdog (`:156`), rate-0 block (`:185`), then three EXCLUSIVE lanes (per-socket `:348`, group `:400`, DRR `:475+`); the one superlinear spot the tree ever had (the O(egress x ingress) merge) was already closed by the think-like-light-years-3 index (`src/ebpf/loader.rs:358-363`). Ordering: policy resolution → gate → block → prime → clamp (`:263`) → stats → accrue (`:317`) → lane → debt-pay on ALLOW only → ECN rescue on DROP only (`:454`, `:536`) → ring wrap — every stage's position carries its own rationale comment, and the cross-program order (prime at the packet hook, consume at the sock_ops callback) is documented per lane (`recwn_flow.rs:34-55`, `pace_flow.rs:31-51`). Friction: the policy map is read ONCE per packet on the direct-hit majority (`enforce.rs:100`); the memoized-subtree path adds one stale-detect read (`ebpf/src/mmspa_resolve.rs:173-178`) whose result CAN change the verdict (it retires a memo naming a dead root) — load-bearing belt, not friction, by the tree's own NIGHT-lts-2 definition. The one true friction — a second `bpf_get_socket_cookie` whose answer cannot differ within one invocation — is the fix below. |
| **2. Adaptive Capability (Orchestra)** | **FORCED** (probes real, scattered; Orchestra designed below) | The load-bearing gates ARE probed before any BPF syscall: the 5.15.0 floor (`src/ebpf/limiter/mod.rs:129`, `src/ebpf/loader.rs:93` — one law, `src/ebpf/kernel_floor.rs`), cgroup v2 (`mod.rs:130-133`, `loader.rs:94-97`), the pin filesystem (`mod.rs:210-219`, the hunt-28 preflight), and the pinned-state/schema reuse gate (`mod.rs:139-177`). But the detection surface is scattered across three compositions that do not share a struct: the doctor builds `SystemInfo` (`src/capabilities/mod.rs:22-33`) and `attach()` never consumes it; the observer and the limiter each re-derive floor + cgroup checks; root is probed only in the doctor (`capabilities/mod.rs:189`) while attach discovers it at syscall time. The brief's four questions: (a) **ECN helper probe before load** — none, deliberately: helper 97 is exposed to cgroup_skb under CONFIG_INET on the whole verified floor and above (`ebpf/src/enforce_helpers.rs:170-177` pins the source record), so a probe would be dead weight; the runtime refusal is graceful anyway (a refused mark lets the drop stand, `enforce_helpers.rs:241-270`). (b) **TCP-only host and `ce_marked_*` memory** — no waste: `ce_marked_packets/bytes` and `bytes_saved_by_*` are FIELDS inside `LimiterStats` (`src/ebpf/limiter/types.rs:241-257`), not a separate map; the cost is 32 B per policed cgroup row, bounded by the 1024 policy census (≤ 32 KiB worst case), booked zero on a host that never marks. (c) **BTF** — a non-dependency, neither refusal nor degradation: the objects use legacy map definitions and read fixed-layout binding structs, no CO-RE type relocations (`ebpf/.cargo/config.toml` records the lean default; `recwn_flow.rs:139-151` reads `bpf_sock` fields directly). (d) **Lockdown** — fail-loud at load, not silent: the integrity-mode EPERM surfaces through the verdict-first picker (`src/ebpf/bpf_syscall.rs:180-224`). |
| **3. Future-Proofing (Type Seams)** | **HARDCODED** (by the letter; the abstraction is designed below, doc-only) | No `type Rate = u64;`-family alias exists anywhere (`rg "^(pub )?type"` over `ebpf/src/` + `src/ebpf/` returns exactly one unrelated alias, `src/ebpf/render/sweep.rs:94`). The count: `u64` appears in 28 files under `ebpf/src/` and 46 under `src/ebpf/` — 74 files total, 33 of which declare u64 rates/bytes/timestamps/packets as struct fields. Against the Seam Law (a type upgrade must touch ≤ 5 files), the letter is violated. The honest decomposition, though: the width itself is ISA-pinned, not chosen — the enforcement core's correctness rides 64-bit BPF_ATOMIC fetch-adds and CASes (`ebpf/src/math_atomics.rs`, `ebpf/src/ecn.rs:105-126`), and the BPF ISA offers no wider atomic, so "upgrade the counter type" is not a software migration on the datapath at all. The seam that CAN migrate — the schema layout family — is already seamed and tight: v28's additive layout change touched exactly 5 type-surface files (`ebpf/src/math.rs` the kernel struct, `ebpf/src/enforce_helpers.rs:27-44` the init, `src/ebpf/limiter/types.rs:241-257` the Raw twin, `ebpf/src/schema.rs` and `src/ebpf/limiter/schema.rs` the two ledgers), inside the ≤ 5 law, with the drift pinned by the twin layout tests (`test/ebpf/limiter/types_tests.rs`). Verdict per the letter: HARDCODED; the alias design waits in the doc, adoption rides the next schema-breaking migration, not a standalone churn commit across 74 files for zero behavior. |
| **4. Maintenance Trajectory** | **DECREASING** | Layer dependencies: the seven pure cores (`recwn.rs`, `pace.rs`, `ecn.rs`, `drr.rs`, `mmspa.rs`, `during.rs`, `quic.rs`) import NOTHING from each other (`rg "^use "` over the family returns only `core::` — verified this audit); each depends only on Layer 0's `Policy`/`Bucket` vocabulary, and the one place a layer must touch another's state (the ECN pay into the DRR pool's tokens) goes through a raw field pointer the wiring hands over (`ebpf/src/ecn.rs:82-87` states the law verbatim: "pure cores never reference each other's types"). Composition lives in exactly one place (`ebpf/src/enforce.rs`). Magic numbers: every figure the brief names is a named constant already — 65536 = `GSO_ADMIT_FLOOR` (`ebpf/src/drr.rs:91`), `ECN_DEBT_CAP` (`ebpf/src/ecn.rs:103`), `BURST_FLOOR_BYTES` (`src/ebpf/limiter/types.rs:74`), cross-pinned in the test tree; 200 ms = `RECWN_DEFAULT_RTT_US` (`ebpf/src/recwn.rs:67`) with its userspace twin `RECWN_RTT_ESTIMATE_US` (`src/ebpf/display.rs:200`) pinned against drift by `recwn_tests.rs`; 131072 = `RECWN_SAVED_DEFAULT_WINDOW_BYTES` (`src/ebpf/display.rs:283`). The brief's 250 ms appears nowhere — no such constant exists in the tree. Test reuse: the newest layers' pins ride the same rootless `#[path]` discipline the depthbore-1 family set — `test/ebpf/limiter/pace_tests.rs` is the math_tests shape one layer up, as `recwn_tests.rs` and `ecn_tests.rs` were before it. Doc drift: `docs/COSMIC_DRAGON_ARC.md` is current through v28 (the fourteen-scale anatomy table, the quota-gap section, Layer 1-4 all recorded at `:48-70`, `:174-323`), and the night-netrunner-1 floor raise left no stale 5.13 claims (the README's remaining 5.13 rows carry the RETIRED caveat, `README.md:703,738`). The trajectory's own proof: each quota-saver layer explicitly rode the previous layer's verified kernel truths instead of re-deriving them (pace's header rides RECWN's two verified 5.15 finds verbatim, `ebpf/src/pace.rs:21-45`) — the per-layer verification cost is falling, not growing. |

## The Smoothbore proof — one packet, four layers, one path

A single policed EGRESS packet (the richest shape: rate > 0, no
group, per-socket flag clear, QUIC long header) walks exactly this
chain, in file:line order, with no branch it can re-enter:

1. **Layer 0, identity and policy.** `enforce_dl`/`enforce_ul` hand
   the skb to `try_enforce` with their direction's fifteen maps
   (`ebpf/src/bin/limiter.rs:324-365`). The leaf cgroup id comes
   from the kernel (`enforce.rs:92`), the policy resolves in ONE
   map read on the direct hit (`enforce.rs:100`) or through the
   memoized MMSPA walk (bounded at 32 levels, memoized forever
   after the first packet — `mmspa_resolve.rs:148-216`).
2. **The gates.** One monotonic clock fetch shared by everything
   below (`enforce.rs:134`); the window gate reads the resolved
   root's row (`enforce.rs:143`, `enforce_helpers.rs:283-304`);
   the watchdog answers its dormant belt (`enforce.rs:156-165`).
3. **The verdict spine, Layer 0.** Rate 0 books the drop and
   returns (`enforce.rs:185-195`); the burst clamp sanitizes
   before any consumer sees it (`enforce.rs:263-278`).
4. **Layer 1 + Layer 3, the hints (one fetch now).** The socket
   cookie is read ONCE (`enforce.rs:233`); the ingress hook primes
   the RECWN window hint (`enforce.rs:234-236`, `recwn_flow.rs:229`),
   the egress hook primes the pacing hint (`enforce.rs:253-255`,
   `pace_flow.rs:250`) — steady state one LRU lookup, no write.
   The sock_ops programs consume the hints at the connection
   callbacks (documented convergence: `recwn_flow.rs:34-55`,
   `pace_flow.rs:31-51`); a hint miss is the OS default, never a
   fabricated clamp.
5. **Layer 4, the telemetry accrual.** The egress lane accrues the
   pacing lane's saved headroom through the raw stats pointer,
   before the Option materializes (the v28.1 verifier lesson —
   `enforce.rs:313-328`, `pace_flow.rs:298-324`).
6. **The lane.** The DRR lane refills the pool (`drr_flow.rs:205`),
   belts the stale quantum (`drr_flow.rs:226-233`), draws the flow
   bucket (`drr_flow.rs:247+`), and books the verdict — the packet
   is policed, attributed, and ledgered.
7. **Layer 2, the ECN closure.** On an ALLOW, the leftover pays the
   outstanding marked-bytes debt out of the same stream that
   delivered (`enforce.rs:520-527`, `ecn.rs:202-231` — the
   call-site law); on a DROP, the kernel is asked for a CE mark
   FIRST and only a refusal lets the drop stand (`enforce.rs:536`,
   `enforce_helpers.rs:241-270`).
8. **The ring.** Every allow books into the one-second window
   (`enforce.rs:539`, `enforce_helpers.rs:121-138`) — a monitor,
   never a verdict input.

No layer's write is another layer's hidden read: every cross-layer
touch in the chain is a named function at a named call site with
its own contract comment. The path is one line, and the line is
linear. That is the smoothbore.

## The fix — one cookie, one fetch (friction close)

**The find.** The policed path fetched the socket cookie TWICE: the
direction's prime site fetched it (`enforce.rs` old `:219`/`:244`)
and then the per-socket or DRR lane fetched it again (old `:345`/
`:480`). The helper's answer cannot differ within one invocation —
the same skb, the same owning socket — so the second call was pure
per-packet overhead, the exact friction class NIGHT-lts-2 defined
when it reordered the unlimited fast path ("operations whose
results could not change the verdict"). The lane comments honestly
documented the cost as "one helper call more than before" — the
cost class the overhead row owns — which is how it survived three
audits: documented, deliberate, and still a second call.

**The close.** One fetch (`enforce.rs:233`), placed exactly where
the prime sites sat — after the rate-0 block verdict, so the
unlimited fast path, the inactive-window path, and the block path
still pay nothing — and reused by the prime sites (`:234`, `:253`),
the per-socket lane (`:348+`), and the DRR flow lane (`:486`). The
group lane, which keys no flow state, lets the value go unused.
Semantics are bit-identical: cookie 0 guards unchanged, QUIC key
unchanged, the prime maps' single-writer contract unchanged.

**The proof.** The pure-Rust eBPF objects build clean against the
pinned nightly (`cargo +nightly build --release` in `ebpf/`, both
ELFs emitted); the standing kernel clippy lane passes at `-D
warnings` (the lts-2d zero holds); the ebpf-prebuilt lane is
regenerated through its one writer (`scripts/release/refresh-prebuilt.sh`)
and pins the live tree; the workspace's 1,058 rootless tests pass
(988 + 70, zero failures); the frame bench measures 5,075 fps
through the real render path with the fix in the tree. The CI
battery's kernel lanes re-prove the object on the 5.15.0 floor and
the archive's latest kernel on every push, as they did for
night-netrunner-1.

## The Orchestra design — one probe, one struct, every attach decision (doc-only)

The verdict is FORCED: the probes exist but three surfaces compose
them independently. The design below consolidates without touching
a datapath byte. It is deliberately shaped like `SystemInfo` — the
doctor's struct IS the near-miss — so the consolidation is a move,
not a rewrite:

```rust
/// The one capability probe, taken once per process, riding the
/// pure kernel_floor law the attach paths already refuse on.
/// Every attach decision reads THIS struct — never a re-derived
/// check, never a syscall-time surprise.
pub struct HostCaps {
    // Layer 0 — the non-negotiables (attach refuses if any is false).
    pub kernel_floor_met: bool,      // 5.15.0 law (kernel_floor.rs)
    pub cgroup_v2: bool,             // unified mount at /sys/fs/cgroup
    pub bpffs_mounted: bool,         // pin filesystem (limiter only;
                                     // observer stays unpinned by design)
    pub is_root: bool,               // CAP_BPF/CAP_SYS_ADMIN proxy
    // Layer 1 — the shape facts (constants on the 5.15.0 floor,
    // recorded so a future floor drop re-opens the probe question
    // honestly instead of silently).
    pub bpf_link: true,              // 5.7+  — unconditional on the floor
    pub bpf_atomic_64: true,         // 5.12+ — unconditional on the floor
    pub ecn_set_ce: true,            // helper 97, cgroup_skb, CONFIG_INET
                                     // — unconditional on the floor; the
                                     // runtime refusal stays graceful
    pub needs_kernel_btf: false,     // no CO-RE relocations; aya loads
                                     // without /sys/kernel/btf/vmlinux
}
```

The attach decision tree — one probe, three consumers:

```
probe_host_caps()  ── called once, at the first attach-family entry
  │
  ├─ !kernel_floor_met ────────────────── refuse (the floor law's msg)
  ├─ !cgroup_v2 ───────────────────────── refuse (mount hint)
  ├─ !is_root ─────────────────────────── refuse (capability hint)
  │
  ├─ observer.attach():  bpffs NOT required (unpinned maps — the
  │                       documented diagnostic split: observe works
  │                       + strict fails = pin filesystem)
  └─ limiter.attach():
       ├─ !bpffs_mounted ──────────────── refuse (the hunt-28 tip)
       ├─ schema pin match ────────────── reuse (the v-N gate)
       └─ load; lockdown EPERM surfaces through the verdict-first
          picker (bpf_syscall.rs) — the belt behind the probe
```

Adoption sketch (for the follow-up that lands it, not this audit):
`detect_system()` builds `HostCaps` instead of `SystemInfo`; the
doctor renders it (the JSON contract keeps its field names);
`Observer::attach` and `Limiter::attach` take it as the single
argument and lose their private re-derivations; `kernel_floor`
stays the pure law it already is. Net effect: one probe, one
struct, three consumers, zero behavior change, and the ECN/BTF/ISA
rows become recorded facts instead of tribal knowledge.

## The type-seam design — named widths at the next schema break (doc-only)

The letter of the Seam Law is violated (74 files, no aliases), so
the design is recorded; the migration itself must NOT ride a
standalone churn commit. The ISA pins the datapath width (64-bit
BPF_ATOMIC only — the enforcement core's own proof shape), so the
alias family exists for the two seams that can actually move:

```rust
// ebpf/src/math.rs (the shared vocabulary the pure cores already
// ride — NOT a new module, the math.rs discipline):
pub type Rate = u64;        // bytes per second, the policy's rate family
pub type TimestampNs = u64; // bpf_ktime_get_ns monotonic domain
pub type ByteCount = u64;   // the counters the atomics book
```

Adoption law: the aliases land with the NEXT schema-breaking
migration (v29), file by file, exactly where that migration already
touches the structs it moves — the way v28 carried its two new
fields through five type-surface files. The layout twin family
(kernel struct ↔ `Raw` mirror ↔ two schema ledgers) is the seam
that matters, it measures 5 files today, and the ISA note above is
recorded so nobody pays 74-file churn for a migration the machine
cannot make.

## The honest conclusion

**MASTERCLASS on the flow, with two honest residuals.** The
single-packet path is a smoothbore in the strict sense: one linear
chain, single-writer state per layer, explicit composition order,
and every cross-layer touch at a named, documented call site. The
one friction find (the double cookie fetch) was small precisely
because the surface is otherwise clean — and it is fixed in this
commit with its proof. The residuals are not flow defects: the
capability surface is FORCED (probes real, composition scattered —
the Orchestra design above is the consolidation plan), and the
type-alias letter is HARDCODED while the seam that can migrate
measures five files (the alias design rides the next schema break).
Maintenance trajectory is DECREASING by measurement: later layers
reuse earlier layers' verified kernel truths, the pure cores never
import each other, the constants are named, the arc doc is current,
and the newest test pins are the oldest discipline one lane over.
The mixed-flow smell the brief warns about does not exist in this
tree — what exists is a flow already governed by its own laws, and
this audit found every law still holding.

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
