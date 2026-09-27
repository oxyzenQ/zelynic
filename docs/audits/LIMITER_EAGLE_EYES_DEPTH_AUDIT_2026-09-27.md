<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The limiter and eagle-eyes depth audit (NIGHT-dinner-6 & depth-research-1, 2026-09-27)

The owner's question: is the limiter already peak — sharp and badass,
not to be touched again — and is eagle-eyes peak too? This audit
walks both surfaces dimension by dimension against the theoretical
eBPF ceiling on Linux, verifies every claim against the source
(byte-level, file:line below), and lands what the hunt found. The
verdicts first, the evidence after.

- **The limiter: PEAK for its class.** Every dimension is at the
  ceiling a cgroup-v2 token-bucket policer can reach: exact math,
  SMP-safe by construction, hostile-state hardened, overflow-proved,
  and — after this commit — leak-free across the whole removal
  family. What sits "beyond peak" is a different product class
  (shaping/queueing), which the architecture deliberately rejects.
- **Eagle-eyes: architecture-peak.** Counting truth, attribution,
  the per-socket join, and render cost are each at their ceiling.
  One real gap remains and it is kernel-side (counter-map eviction,
  finding E1 below) — deferred to the next prebuilt-refresh cycle
  with the design sketched there. Everything userspace is now at
  peak, including the top-consumer ranking this audit re-cut.

Method note: every number and claim below was re-verified against
the current tree (`git clone --depth=1`, HEAD = the NIGHT-dinner-5
era commit `cf3566d`), not taken from prior docs — several prior
doc claims failed that verification and are corrected in this
commit. The ebpf/ tree is byte-frozen (check-prebuilt-parity PASS);
everything landed here is userspace-only.

## Part 1 — The limiter, dimension by dimension

### 1.1 Rate math exactness — PEAK

The refill arithmetic (`ebpf/src/math.rs:465-500`, `refill_credits`)
is exact u64 nanosecond math: `elapsed_ns * rate_bps / NS_PER_SEC`
with the sub-byte fractional remainder carried in `frac_rem` and
folded back on the next window (the carry at
`math.rs:492-498`). Without the remainder, integer division
truncates up to ~1 byte per refill — a 0.5-1 percent rate error at
common rates; with it, the enforced rate is the asked rate. The
cross-era battery measured the same precision surviving a full
engine rewrite 0.006 percent apart (NIGHT_DINNER_5 research doc) —
the exactness is structural, not accidental. The kernel math is u64
end to end; u128 exists only in the userspace parse/render horizon
(the footer's session sums), which is the correct place for it.

### 1.2 SMP discipline — PEAK

Three separate races, three closures, all verified in the source:

- **Window ownership** (`math.rs:259-341`): exactly one CPU credits
  `[last, now]` — the CAS at `math.rs:294-296` makes the winner the
  sole creditor, the loser's window is a subset of the winner's
  (each nanosecond paid once, never twice), and the stale-sampler /
  hostile-excursion branches heal the stamp without re-credit.
- **Token consume** (`math.rs:395-418`): sufficiency-verified CAS,
  written out four times (no loop body for the verifier to bound).
  The probe-measured numbers: one attempt falsely dropped 1.35
  percent of affordable packets under an 8-thread burst; four took
  it 28x down, still erring to the safe verdict.
- **Stats booking** (`math.rs:430-444`): atomic `fetch_add` through
  the RMW view — the pre-boost-38 plain `+=` lost increments and is
  closed since v7/v9.

The access-primitive split (`math.rs:88-128`) is itself ceiling
work: volatile loads/stores where the BPF ISA has no atomic
load/store, `AtomicU64` RMW views only where the ISA has real
atomics (5.12+, under the verified 5.13 floor).

### 1.3 Trust-boundary hardening — PEAK

The maps are persistent kernel state any root process can write;
the enforcement boundary sanitizes for itself. The clamp family:
stored burst (`MAX_ENFORCABLE_BURST`, `math.rs:188-202` — the exact
mathematical ceiling under which every product `enforce` can form is
provably representable in u64), the security-3 seed clamp
(`math.rs:249-257`, one-shot CAS, converges across packets under
contention), the v4 burst/tokens clamps, and the v6 `frac_rem`
sanitize (`math.rs:472-473` — a healthy remainder is always
< NS_PER_SEC). Hostile or drifted state degrades to the healthy
value, never to a verdict change.

### 1.4 Overflow safety — PEAK

The fill-detect guard (`math.rs:482-488`) is the overflow proof, not
an optimization: once the true refill reaches 2x burst the exact
value is irrelevant (the cap lands at burst anyway), and the branch
only runs while `elapsed < fill_ns`, bounding the product by
construction. Layout pins (`math.rs:181-183`) keep the repr(C)
contract from drifting silently against the userspace mirrors.

### 1.5 The endurance budget — PEAK AFTER THIS COMMIT

The pinned maps (1024 policy slots, 256 group slots) hold hard
caps; the reclaim family keeps them proportional to LIVE state:
improve-10 returns per-cgroup bucket/stats slots, lts-7 returns
dead groups' shared-bucket slots on unstrict. **The gap this audit
found (L1): `recover` never called the lts-7 sweep** — the
commands-side orphan recovery (`src/commands/cleanup.rs`) captured
nothing and swept nothing, so a container-churn recovery leaked the
256-slot group maps while STABILITY.md claimed otherwise. Fixed in
this commit: the recover path now captures each orphan's group id
read-before-delete (the `read_policy_group` seam, `reclaim.rs:224`)
and runs the dead-group sweep after the removal loop — the result
line reports the returned slots. The endurance harness's 300-cycle
churn now exercises the recover lane too, via the same map caps.

### 1.6 What "beyond peak" would mean — DO NOT TOUCH

Above a token-bucket policer sits shaping/queueing (EDT, FQ,
`setsockopt(SO_MAX_PACING_RATE)`-class machinery): sub-burst pacing
instead of drop. That is a different product — it changes the
failure model (delay instead of drop), moves cost into the qdisc
layer, and abandons the single-hooking-layer architecture the
project is built on (COSMIC_DRAGON_ARCHITECTURE's first two laws).
The philosophy's over-engineering guard applies: the limiter is at
the ceiling of ITS design class, and the class is the product.

## Part 2 — Eagle-eyes, dimension by dimension

### 2.1 Counting truth — PEAK

The observer hooks the cgroup v2 datapath itself; every figure is
the kernel's own accounting taken at the point of truth. The
counter maps hold 4096 entries per direction
(`ebpf/src/main.rs:117`, `COUNTER_MAP_MAX_ENTRIES`) and the
allow-and-skip contract means a full map loses one packet's COUNT,
never the packet. No polling window for traffic to hide in.

### 2.2 Attribution — PEAK

Per-cgroup identity through the TTL-memoized /proc walk (3s), with
per-socket resolution via `pidfd_getfd` + `SO_COOKIE`
(`src/ebpf/connections.rs`, kernel 5.6+ under the 5.13 floor). The
ingress join names the download's true owner (the RECEIVER's
cookie — verified against torvalds/linux net/core/filter.c, the
boost-26 note). Hosts that refuse the syscall pair degrade to
figure-less rows, never fabricated zeros — the honest degradation.

### 2.3 The per-socket byte join — PEAK

Two 4096-entry LRU hashes keyed by socket cookie, session-scoped,
freed at detach (`ebpf/src/main.rs:146`). Never-reused keys mean no
cross-socket contamination; LRU means a new warm socket always finds
room. The userspace join point-looks-up exactly the walked cookies —
tens of syscalls per frame, never a map iteration.

### 2.4 Ranking honesty — PEAK AFTER THIS COMMIT

**The gap this audit found (E3): the footer's top-consumer pick.**
The line's contract says "busiest process INSIDE the champion
cgroup", but the pick was `socket_holders.first()`
(`src/ebpf/render/footer.rs`) — the /proc walk's order, sorted by
SOCKET COUNT (`src/ebpf/connections.rs` refresh): a three-socket
idle daemon out-ranked a one-socket download, exactly when the
headline matters most (the champion cgroup under a limit). Fixed in
this commit: the new rank module (`src/ebpf/render/rank.rs`) ranks
by the boost-26 byte join — dl+ul lifetime bytes summed per process,
saturating u128 — with the walk order standing whenever the join
carries no figures (cookie-less hosts, the pre-first-join frame:
the ranking degrades to the pre-dinner-6 behavior rather than going
dark, which is exactly the contract the footer's curl pin pins).
Ties break first-in-walk-order: deterministic, never
hash-flattered. Eight pins hold it
(`test/ebpf/render/rank_tests.rs`). The focus view's endpoint
ranking was already byte-true and is untouched.

### 2.5 Render cost — PEAK

The render loop is zero-alloc through the diff engine
(blade-16's audit closed the last two per-frame allocations), the
geometry probe is one TIOCGWINSZ per frame, and the walks are
TTL-memoized. The selection-guard beat is the documented
copy-protection product, not a regression to chase.

### 2.6 The remaining gap (deferred): counter-map eviction — E1

The counter maps are plain HASH maps, not LRU (unlike the cookie
maps): slots do not age out. On a host churning past 4096 distinct
cgroups inside one observe session, the FIRST 4096 pin their slots
for the session's life and later cgroups count nothing — the
limitation USAGE.md number 11 documents, now sharpened to say
exactly that (this commit). The fix is kernel-side — swap the two
maps to `BPF_MAP_TYPE_LRU_HASH` in `ebpf/src/main.rs`, the same lane
the cookie maps already ride; the accepted trade (an idle cgroup's
entry ages out, its row leaves the frame until traffic returns)
matches the socket maps' documented posture, and the 192 KiB
session footprint is unchanged. It is deferred because the ebpf/
tree is byte-frozen behind check-prebuilt-parity (rebuilding the
embedded objects takes the pinned nightly + bpf-linker lane, an
owner-run cycle) — the same cycle that owns the stale `zelynic
rates` comment inside the frozen tree. Until then the bound is
documented, bounded (one session), and costs counts, never packets.

## Part 3 — The findings ledger

What the audit found beyond the owner's question, each verified
against the source before it was flagged (trust but verify — the
byte rule):

| ID | Finding | Evidence | Status |
|----|---------|----------|--------|
| L1 | recover never swept dead groups — the lts-7 contract's recover half missing; STABILITY.md claimed it already held | cleanup.rs recover loop vs reclaim.rs:274 (pre-fix `pub(super)`, callers: policy.rs x2, unstrict only) | FIXED (this commit) |
| L2 | Rate math exactness (frac_rem carry, u64 end to end) | math.rs:465-500 | Verified PEAK |
| L3 | SMP discipline: window CAS, 4-attempt consume, atomic booking | math.rs:259-341, :395-418, :430-444 | Verified PEAK |
| L4 | Trust-boundary clamp family + MAX_ENFORCABLE_BURST proof | math.rs:188-202, :249-257, :472-473 | Verified PEAK |
| L5 | Stale doc truths: QA.md "exact u128", SAFETY_ANALYSIS pre-boost-38 "stats += NOT atomic" relic, STABILITY recover claim | QA.md Q3, SAFETY_ANALYSIS.md race section, STABILITY.md leak fence | FIXED (this commit) |
| E1 | Counter-map eviction: HASH not LRU, no aging, first-4096-wins | ebpf/src/main.rs:117 vs :146 | DEFERRED (kernel-side, prebuilt-refresh cycle) |
| E2 | Per-socket attribution join (receiver's cookie, LRU maps, honest degradation) | connections.rs, loader.rs SocketBytes | Verified PEAK |
| E3 | Footer top consumer ranked by socket count, not bytes | footer.rs gather (pre-fix) vs connections.rs sort | FIXED (this commit) |
| E4 | Stale doc truths: README half-life "monitoring works", PERFORMANCE 1024-era costs, USAGE limitation 11 under-sharpened | README.md doctor paragraph, PERFORMANCE.md held-design list, USAGE.md limitation 11 | FIXED (this commit) |
| E5 | Render cost: zero-alloc diff engine, one probe per frame | terminal/diff.rs lineage, render.rs geometry | Verified PEAK |

The half-life README truth in full: a `--no-default-features` build
compiles doctor and help only — every eBPF surface (limits AND the
live monitor) answers its honest refusal
(`src/commands/mod.rs` dispatch arms, `src/cli/mod.rs:151`). The
old "monitoring works, limits refuse" line overstated the build by
one whole surface.

## Part 4 — What landed in this commit

- `src/commands/cleanup.rs` — the recover dead-group sweep: capture
  read-before-delete, sweep after the loop, the result lines report
  the returned group-bucket slots.
- `src/ebpf/limiter/reclaim.rs` — `reclaim_dead_groups` and
  `read_policy_group` promoted `pub` for the commands-side caller
  (the third caller of the lts-7 seams), docs updated.
- `src/ebpf/render/rank.rs` (new) — the byte-ranked top consumer;
  `src/ebpf/render.rs` — module wiring + map line;
  `src/ebpf/render/footer.rs` — the pick swapped, line-count
  neutral (the file rides the LOC cap).
- `test/ebpf/render/rank_tests.rs` (new) — 8 pins: bytes outrank
  socket count, later-holder-wins, no-join fallback, all-zero
  fallback, both legs together, deterministic ties, empty->None,
  unknown-cgroup->None.
- Doc truths: STABILITY.md (recover claim, endurance row), USAGE.md
  (limitation 11), README.md (half-life), QA.md (u64 vs u128),
  PERFORMANCE.md (4096-era costs), SAFETY_ANALYSIS.md (boost-38
  atomics), format.rs header (sysfs relic).
- This audit doc, the CHANGELOG entry, and the docs/README index
  row.

## Part 5 — The benchmark decision

Skipped, with justification: the A/B harness owns frame-visible
deltas (density gini, frame entropy, fps, dirty cells), and this
commit changes none of them. The top-consumer re-rank changes WHICH
name a pinned line can carry, not the frame's composition or
geometry — the footer's line count, cells, and layout are pinned
unchanged, and the rank walk is O(holders) over an already-walked
set inside a 1s-cadence loop. The recover sweep is an error-path
bookkeeping operation. Both are correctness fixes the test battery
owns (8 new pins; 462 existing green), not render-path changes the
frame harness would measure.

## Part 6 — Context weight for AI coding agents

The owner asked: is this project heavy, medium, or light for an
agent's context? Honest answer: **medium**. The tree is ~60 source
files with a hard 500-line cap each and a comment culture that
documents intent at the seam (the agent reads the contract where
the code lives, not a wiki). What makes it feel heavy is the density
of cross-references (task lineages, pins, mirrored layouts) — an
agent that reads whole files burns context fast; an agent that
greps for the seam first (`rg 'fn name'`, then read the hit with
context) runs comfortably inside a session. The pin system is the
agent's safety net: behavior contracts are executable, so a change
is verifiable without re-deriving the design. The frozen ebpf/ tree
is the one place an agent must NOT work — parity is the wall.

## The verdict

The limiter is peak for its class: exact, SMP-safe, hardened,
overflow-proved, and — after this commit — leak-free across the
whole removal family. Do not touch it; the next real movement is a
product-class decision (shaping), not a code task. Eagle-eyes is
architecture-peak: every userspace dimension is at its ceiling
(including the two this audit closed), and the single remaining gap
(counter-map eviction) is kernel-side, designed, bounded, documented,
and scheduled for the prebuilt-refresh cycle where the ebpf/ tree
thaws.
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
