<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The NIGHT-perf-2 depth audit — AMMSP endurance and ultra scale, now and future

> Audit date: 2026-09-30 (NIGHT-perf-2, the perf-trilogy's endurance
> leg). Scope: the AMMSP resolution machinery (ebpf/src/ammsp.rs,
> ebpf/src/ammsp_resolve.rs, ebpf/src/bin/limiter.rs) and its
> userspace invalidation half (src/ebpf/limiter/ammsp.rs, lanes.rs,
> policy.rs, reclaim.rs) audited for the owner's directive: "depth
> audit for endurance and ability to handle ultra scale > trillion
> data/burst for now and future". The question decomposes into four
> measurable ones: what does one packet cost on each lane, what
> does one mutation cost, what scales with TIME instead of state,
> and what are the ceilings that a "trillions" deployment would hit
> first. Status: one fix landed from this trilogy's own hunt
> (NIGHT-perf-0, schema v12 — the generation stamp, committed
> 0b0a8f5), the A/B proof harness landed with it (NIGHT-perf-1,
> f1eb095), and every verdict below is re-verified against the
> source at HEAD, not against any earlier doc's claim.

## 1. The mandate

"Ultra scale > trillion data/burst" is not one number — it is
three different loads wearing one phrase, and each lands on a
different surface:

- **Trillions of PACKETS** (a host moving 10 Mpps for weeks): the
  per-packet fast path and everything that accumulates per packet.
- **Trillions of BYTES** (multi-TB transfers under enforcement):
  the token-bucket arithmetic and the ledgers.
- **Bursts** (many-CPU first-packet storms, apply storms, IRQ
  storms): the races the 2026-09-27 and think-like-light-years-3
  audits hunted, plus the mutation-vs-datapath races this trilogy
  hunted.

The method is the house method: compute the cost of every lane
from the source, name the term that scales with each load, and
check whether that term's failure mode is WRONG (a correctness
hole), SLOW (a bounded degradation), or LOUD (an error at the
boundary). The zelynic contract this audit holds the code to: at
any scale, never WRONG; degrade only in ways already documented.

## 2. What the hunt found — and landed

**Finding P1 (the insert race, landed as schema v12):** the
pre-perf-0 invalidation — every mutation sweeping the whole memo
LRU with one syscall per entry — held a TOCTOU no sweep could
close: a kernel walk whose tail an NMI/IRQ storm stretched past
the sweep landed a memo computed against PRE-mutation state AFTER
the flush finished. The flock serializes mutations against
mutations, never against walks; the stale verdict then lived
until the NEXT mutation — the one shape that violated "no
exception" under exactly the ultra-load endurance framing this
audit exists for. The close is the generation stamp: every memo
word packs `(generation << 32) | root`, the datapath reads the
counter before any policy read, every mutation bumps it after its
writes land — a stale insert is self-invalidating on the very next
packet, whatever the sweep missed. Full record: the perf-0
CHANGELOG entry and the design brief's rewritten userspace half.

**Finding P2 (the mutation storm, landed with P1):** the sweep
cost O(memo-cap) syscalls per mutation — up to 4096 removes per
apply, ~4-8 ms of syscall work at the full cap — which an
apply storm (fleet management, CI churn, scripted
re-configuration) paid per mutation while holding the flock. The
bump is one Array store: the mutation lane now costs writes + one
store, so the flock hold time no longer scales with memo
population at all. The sweep survives only as the bump's failure
fallback.

**Finding P3 (the proof gap, landed as NIGHT-perf-1):** the
subtree contract had no counterfactual proof — nothing measured
what the same machine would have leaked on the pre-AMMSP stable.
The ammsp-vs-legacy harness now runs the identical seven-leaf
battery against v11.0.0 and the current build on every
supermassive leg (low AND best, gnu AND musl), with the >= 99%
child-coverage DELTA as the verdict.

## 3. The per-packet cost budget, at HEAD

Three lanes, computed from the source (map ops are the only
per-packet cost — no allocation, no locks beyond the bucket's own
atomics):

| Lane | Who takes it | Map ops (pre-perf-0) | Map ops (HEAD) |
|------|-------------|----------------------|----------------|
| Leaf-policed | socket's own cgroup carries the policy | 1 (policy hit) | 1 (unchanged) |
| Unlimited majority | no root covers the socket | 2 (policy miss + memo hit) | 3 (policy miss + gen read + memo hit) |
| Root-policed steady | memoized subtree resolution | 3 (policy miss + memo + policy at root) | 3 (policy miss + gen + memo — the stale-detect's root read rides the gen match) |
| Fresh leaf, first packet | any of the above, once per leaf per generation | walk (<= 33 helper + policy queries) + insert | same + one Array read already counted |

The one added cost of the stamp is the generation Array read on
the policy-miss branch — a direct-index array lookup (the
cheapest map op the kernel offers, no hashing), taken once per
packet on the lanes that were already paying a memo lookup. In
absolute terms the resolution branch adds on the order of tens
of nanoseconds; at 10 Mpps that is a fraction of one core on a
many-core host, and it buys the property the sweep could not:
no memo verdict can outlive the state it summarized, at any
packet rate, under any IRQ storm.

The walk itself is bounded by construction: queries scale with the
socket's REAL depth (the zero-break), ~8 queries at systemd
depths, 32 at the hard ceiling. A depth-6 socket pays the walk
once per generation per leaf — after that, one memo hit.

## 4. The trillion-packet math

**What accumulates per packet: nothing in the fast path.** The
verdict lanes above touch only caches and the policy map; the
only per-packet writes land on the policed tail (the bucket's
atomic fields and the stats fetch_adds) and are bounded by the
rate arithmetic, not by packet count. There is no array the
limiter appends to, no list that grows, no timer that arms per
packet.

**The scale-sensitive term is the memo's hit rate.** The 4096-entry
LRU holds leaf -> root resolutions; the correctness invariant
(the memo is never an authority — the policy map is, and the stamp
plus stale-detect re-walk through it) holds at ANY hit rate. What
the hit rate buys is speed:

- Hit (leaf live and inside the cap): one lookup, forever.
- Cold leaf beyond the cap (more than 4096 distinct live leaves):
  re-walk per packet — the bounded ~depth+2 queries, correct every
  time, just not free. This is the honest degradation regime, and
  it takes a host with more than 4096 SIMULTANEOUSLY-live cgroups
  moving traffic to enter it: a k8s node at the common densities
  (500 pods x 2-3 cgroups) sits at ~1500; a systemd desktop sits
  in the dozens. The design doc's risk register already owns this
  row; this audit re-verified the bound and the LRU eviction path.

**Time-to-wrap, every counter that a "trillions" horizon meets:**

| Counter | Width | Wrap horizon | Failure mode at wrap |
|---------|-------|--------------|----------------------|
| Per-cgroup bytes allowed/dropped | u64 | 18.4 EB per cgroup — ~4,670 years at 1 Gbps line rate | wrap_coherent_delta (pinned) — the delta math is wrap-safe by design |
| Tokens / frac_rem | u64 per bucket | bounded by burst clamp (<= 100 MB) and the 1s elapsed cap per window | arithmetic cannot reach wrap; the v4/v6 clamp family pins it |
| ammsp_generation | u32 | 2^32 mutations — 136 years at one mutation per second | total ordering: the wrap-neighbor pin (a stamp one full u32 behind reads as stale, never as current) |
| kernfs cgroup ids (u32 keys) | u32 per boot | ~4 billion cgroup CREATIONS per boot | the pre-existing map contract; a fresh leaf aliasing a live leaf's key needs ~497 days of 100-cgroups/second churn in one boot (STABILITY's documented residual) |

**Mutation storms:** the apply lane now costs its policy writes
plus one Array store (P2) — the flock hold time no longer scales
with memo population. A thousand applies per second on a fleet
manager is syscall-bound on the writes themselves, which is the
floor any design pays; zelynic adds nothing proportional to
time or history above it.

**Memory:** the whole limiter state is bounded by construction —
policies 1024 x 2 directions x 24 B, buckets 1024 x 2 + 256 x 2
x 24 B, stats 1024 x 32 B, memo 4096 entries x ~64 B with LRU
overhead, one u32 generation word, the watchdog and schema
arrays. A few hundred kilobytes TOTAL, flat in packet count,
flat in bytes moved, proportional to live policy count and
nothing else. The reclaim family (improve-10 / lts-7 / dinner-6)
keeps the policy-keyed maps proportional to LIVE policies, not
to history.

## 5. The verdicts

### 5.1 Endurance under ultra loads and bursts — YES, and the layered story is now closed at every layer

The endurance question is the race question, and the answer is a
stack, each layer landed and pinned: v7 closed the per-field
lost-updates (SMP atomics), v8 the extreme-burst consume retry,
v9 the rate-0 booking, v11 the init-path wholesale reset
(BPF_NOEXIST), and v12 (this trilogy) the mutation-vs-walk
insert race (the generation stamp). Each was found by hunting the
layer BELOW the one before it; this audit's hunt found no layer
left standing in the mutation/datapath pair — the stamp's
ordering proof is airtight against any interleaving the kernel
can schedule (walks read the stamp before policies; mutations
write policies before the stamp; both visibility orders are the
kernel's own syscall-completion guarantees).

### 5.2 Ultra-scale > trillion data — bounded by design, honest at the ceiling

Trillions of BYTES and PACKETS traverse the fast path without
accumulating anything: no per-packet state, u64 ledgers with
wrap-safe deltas, bucket arithmetic bounded by window math. The
ceilings a "trillions" deployment hits are all in CARDINALITY,
not volume — distinct live leaves (4096 memo slots: beyond it,
bounded re-walks, never wrong verdicts), distinct policies
(1024 slots per direction, reclaimed, fail-open documented), and
distinct groups (256, dead-group sweep). Every one of those is a
documented constant with a one-line lift path and a schema-bump
cost the owner decides — none is reachable by volume of traffic.

### 5.3 Future — the lifts are ready and deliberately not taken

The two constants a future deployment might want raised are
`AMMSP_MAX_DEPTH` (32 levels — three times any real hierarchy;
raising it is one line plus one pin plus the USAGE.md paragraph)
and the memo's 4096-entry cap (one line in the map definition,
one schema bump, the LRU handles the rest). Neither is taken now:
raising them today would spend a schema bump (a one-time
re-apply for every pinned deployment) to buy headroom no real
host needs — the over-engineering the LTS rules refuse. When a
real deployment names the number, the lift is an afternoon.

### 5.4 High-gain investments — what was taken, what was declined

Taken: the generation stamp (correctness at any scale plus the
O(1) mutation), the A/B counterfactual harness (the proof that
outlives this audit), the lanes.rs split (the 500-LOC cap held
under the Array twin). Declined, with reasons on the record:
a larger LRU or per-CPU memo variants (no host needs them; the
degradation is bounded and documented), double-buffered memo
swaps (RCU-style — the stamp achieves the same invalidation for
one word), and any form of subtree enumeration at apply time
(the design brief rejected it before AMMSP landed; nothing this
audit found moves that verdict).

## 6. Verification

- The pure core is pinned rootlessly: the walk state machine,
  the verdict table WITH the generation row (mismatch walks
  regardless of root or aliveness; the wraparound neighbor does
  not alias), the pack/unpack roundtrips, and the
  only-current-generation-is-trusted sweep (ammsp_tests.rs).
- The wording surface is pinned (bump trace, fallback sweep
  trace, the two-cause failure line) in ammsp_flush_lines_tests.rs.
- The schema pin (types.rs) and the acquisition-lane architecture
  pin (architecture_pins.rs, now naming lanes.rs) hold the
  structural contracts.
- The live proof is permanent: supermassive's test_ammsp_subtree
  (functional) and the new ammsp-vs-legacy harness (the
  counterfactual DELTA, low AND best legs, gnu AND musl) — the
  >= 99% child-coverage question is answered by CI on every
  push that touches the limiter, on the kernel floor and the
  latest head.
- Local gates at HEAD: fmt + ebpf fmt clean, clippy -D warnings
  clean, 509 + 46 tests green, build.sh check-all green,
  gate-keepers 17/17.

## 7. Residuals (honest)

The bounds this audit confirms rather than closes — each one
documented where its users meet it:

1. **The memo cap** (4096 live leaves): beyond it, cold leaves
   re-walk per packet — bounded, correct, and the documented
   dense-host regime (USAGE.md, PERFORMANCE.md).
2. **The depth bound** (32 levels): a hierarchy deeper than 32
   from the cgroup root resolves unlimited — the one written
   exception, three times any real hierarchy.
3. **The u32 kernfs id space**: per-boot, ~4 billion creations —
   a hostile-churn horizon no real boot approaches; the pre-existing
   map contract (STABILITY.md's row).
4. **The generation wraparound**: 2^32 mutations, total ordering
   preserved (the wrap-neighbor pin); a stale stamp can only read
   stale, never current.
5. **The capacity ceilings** (1024 policies / 1024 buckets / 256
   groups): fail-open by design with the reclaim family keeping
   them proportional to live policies; the LTS budget rows in
   STABILITY.md own the churn evidence.
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
