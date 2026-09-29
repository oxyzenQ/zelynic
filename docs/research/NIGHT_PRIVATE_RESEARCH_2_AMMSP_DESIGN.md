<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 rezky_nightky (oxyzenQ) -->

# The AMMSP design brief (NIGHT-private-research-2 & think-like-light-years-2, 2026-09-30)

The owner's directive, verbatim intent: give the limiter engine
(intergalaxion-engine) an adaptive ability — a limit set on a cgroup
must cover that cgroup AND every process that spawns beneath it, at
any depth, with no exceptions and no compromise, sharing ONE budget,
still with no daemon, no config, no manual intervention. The owner
found the hole himself, live, through eagle-eyes: a cgroup limited to
100kb showed a subprocess in a child cgroup downloading at more than
1mbps. This document records the verified root cause, the design
chosen, the designs rejected, and the risk register — then the
implementation carries it.

## 1. The problem, verified against the source

The 2026-09-27 depth audit called the limiter "peak for its class"
across every dimension it walked — rate math, SMP, hostile state,
leaks. The owner's observation exposed the dimension it never walked:
**semantic coverage of the cgroup subtree**.

The verified mechanics (ebpf/src/bin/limiter.rs, pre-AMMSP):

- Both hooks attach at the cgroup v2 ROOT and see every packet the
  machine moves.
- The datapath keys its policy lookup by `bpf_skb_cgroup_id(skb)` —
  the cgroup id of the SOCKET, which is the socket's own (leaf)
  cgroup, set at socket creation from the creating process's cgroup.
- `zelynic strict-single A 100kb` writes the policy at A's cgroup id
  — and at nothing else. No descendant is enumerated; nothing
  watches for new ones.
- A socket born in a child cgroup `A/sub/a` carries THAT cgroup's
  id, misses the policy map, and hits the fail-open: **unlimited**.

So the hole is worse than the "each child gets its own bucket"
theory that circulated with the directive: a child cgroup is not
separately budgeted — it is not budgeted AT ALL. One subprocess in
one fresh scope and the limit is simply gone for it. On systemd
distros this is not an edge case: transient scopes, sandboxed
browsers, container runtimes, and session slices all create fresh
child cgroups as a matter of course. The owner's "100 to billions"
framing on a critical server is the honest scale of it.

## 2. The four candidate designs

### Option A — fentry tracking (the plan that arrived with the directive)

A map `leaf -> root` populated at apply time, maintained by fentry
hooks on `cgroup_mkdir` / `cgroup_rmdir`. Rejected on four
verified grounds:

1. **fentry fires at function ENTRY** — the new cgroup does not
   exist yet when `cgroup_mkdir(parent_kn, name, mode)` is entered;
   its kernfs id is not an argument and not yet allocated. The hook
   that can see the new id is an fexit or a deeper attach
   (`cgroup_create`), walking kernfs internals by CO-RE — brittle
   against kernel refactors in exactly the way the repo's CO-RE
   policy exists to avoid.
2. **Reverse-index cleanup is not a BPF primitive.** `cgroup_rmdir`
   needs "every entry whose VALUE is the dying root" — a hash map
   cannot be scanned by value without `bpf_for_each_map_elem` in
   tracing context (5.17+), and the floor is 5.13.
3. **Runtime overflow cannot error loudly.** A full tracking map at
   cgroup-creation time can only bump a counter — the honest-error
   contract (error at apply, never a silent hole) has no kernel-side
   teeth, which is precisely the failure mode the owner's "no
   exception / no compromise" rule refuses.
4. **A third program object.** A tracing program running on every
   cgroup create/remove system-wide, resolved through
   /proc/kallsyms symbol names that are static functions — a new
   load-time failure surface for zero coverage the walk cannot give.

### Option B — the ancestor walk + LRU memo (CHOSEN)

Keep the policy map as the single authority. When a packet's leaf
misses it, walk UP the socket's cgroup chain with
`bpf_skb_ancestor_cgroup_id(skb, level)` — absolute levels from the
cgroup root, ascending, stop at the first 0 (past the leaf's depth)
— and keep the LAST level that carries a policy: the NEAREST root.
Memoize the resolution in a pinned LRU hash map
(`ammsp_leaf_cache`, 4096 entries) so every packet after the first
pays one lookup, not a walk.

Every kernel fact this rests on was verified against
torvalds/linux master AND v5.13 source (net/core/filter.c,
include/linux/cgroup.h) — not assumed:

- the helper is exposed to cgroup_skb programs via
  `cg_skb_func_proto` (it was built for exactly this program class);
- it is `gpl_only = false` (the object's GPL section stays anyway,
  for C-twin parity and the dual-license contract);
- `cgroup_ancestor(cgrp, level)` counts levels from the ROOT
  (`ancestors[0]`), returning NULL past the leaf's own level — the
  walk's ascending order and zero-break are the kernel's own
  semantics, not an approximation;
- v5.13 — the repo's verified floor — already carries it.

### Option C — re-attach per descendant

Userspace re-attaches programs to each new cgroup. Requires a
watching process = a daemon. Violates zelynic's no-daemon rule. Rejected
outright.

### Option D — cgroup local storage

`BPF_MAP_TYPE_CGROUP_STORAGE` would key the bucket at the ATTACH
cgroup — shared by construction, no resolution at all. The elegant
answer the kernel offers — and aya does not implement the map type,
so the pure-Rust constraint blocks it. Rejected for this codebase;
recorded here because a future aya that grows the type could
simplify the bucket half (the resolution half would still be needed
for the policy-map contract).

## 3. The chosen design, in full

**Datapath** (ebpf/src/bin/limiter.rs + ebpf/src/ammsp_resolve.rs +
ebpf/src/ammsp.rs):

1. The leaf's own policy lookup stays FIRST — a socket whose own
   cgroup carries the policy takes the exact pre-AMMSP path: one
   lookup, enforce at the leaf id. Every existing scenario is
   bit-identical.
2. On leaf miss: consult the memo. A cached 0 (resolved unlimited)
   allows — the unlimited majority pays ONE extra lookup per packet,
   the whole cost of AMMSP on the fast path. A cached root is
   trusted only while the policy map still holds it (stale-detect:
   delete the memo, re-walk). No memo: walk.
3. The walk: ascending absolute levels, zero-break, last-match-wins
   = nearest root. Bounded by `AMMSP_MAX_DEPTH = 32` — a ceiling,
   never a cost (the break makes a depth-6 socket pay ~8 queries).
   The walk result is memoized either way (root id or 0).
4. Enforcement keys the bucket AND the stats at the ROOT id: the
   subtree shares one token budget, and the ledger rolls up to the
   target's own status row — the aggregate-stats-per-root ability
   the think-like-light-years list wanted, arriving as a
   consequence of the design rather than a feature of its own.

**Userspace** (src/ebpf/limiter/ammsp.rs): every policy mutation —
apply_single, apply_group, unstrict — flushes the whole memo once
per invocation, inside the flock the mutation already holds. The
flush is the memo's only addition-side invalidation: a cached
negative (or a cached farther root) cannot see a policy that was
added after the walk ran, and the kernel-side stale-detect covers
only removals. Belt and suspenders, each covering exactly the half
the other cannot see. After a flush each live leaf re-walks ONCE.

**Nested roots arrive free**: a strict on A (100kb) and another on
B (50kb), B a descendant of A — a socket under B resolves to B (the
nearest match in ascending order), a socket under A-outside-B to A.
Each subtree shares its own root's budget. The directive's "flat
first, nested in v11.2" staging turned out unnecessary: the chosen
resolution makes nearest-root the ONLY natural semantics, so it
shipped correct rather than deferred.

**Schema v10**: new pinned map, new coverage, existing struct
layouts. The bump forces pinned v9 programs to reload into the
subtree-aware object — active limits are dropped once, re-applied
after upgrade, the same one-time contract as every bump before it.

## 4. The depth bound — the one compromise, stated plainly

A socket nested deeper than 32 levels from the cgroup root resolves
unlimited. Real hierarchies sit at a third of that or less
(systemd user sessions ~6, container runtimes ~4, Kubernetes pods
under 10); reaching 32 requires constructing it on purpose. The
walk's cost scales with the socket's REAL depth (the zero-break),
so raising the bound is free if a real deployment ever needs it —
the constant is one line, its pin is one test, the honest-limitation
entry is one paragraph. "No exception / no compromise" holds for
every hierarchy a kernel actually builds; the bound is the price of
the verifier's bounded loop, paid once, documented here and in
USAGE.md.

## 5. Risk register

| Risk | Shape | Answer |
|------|-------|--------|
| Memo staleness after policy ADD | cached negative outlives a new policy | the mutation-side flush (userspace) + flock serialization |
| Memo staleness after policy REMOVE | cached root outlives its policy | datapath stale-detect: delete + re-walk, per packet |
| Map growth from dead leaves | transient scopes fill the memo | LRU eviction is the map type; 4096 entries bound it |
| LRU insert failure | never expected on LRU | costs a re-walk next packet, never a wrong verdict |
| Walk cost on a new leaf | ~depth+2 helper calls once | memoized; the unlimited majority never walks twice |
| u32 truncation of u64 cgroup ids | kernfs ids are small sequential | the pre-existing map contract; both helpers truncate identically |
| Helper unavailable on some kernel | program fails to verify at attach | verified present in 5.13 (the floor) and every kernel above it; CI Supermassive proves it live on the matrix |
| Aya LRU map pinning | pin contract drift | same PIN_BY_NAME macro family as the other nine maps; parity gate owns the ELF |

## 6. The verification battery

- Rootless pins: test/ebpf/limiter/ammsp_tests.rs — the walk state
  machine (nearest-root, nested, zero-match, trailing-miss), the
  cache verdict table (exhaustive), the memo value contract, the
  depth bound and its cost curve. The pure core compiles from
  ebpf/src/ammsp.rs — the same file the BPF object builds.
- Wording pins: test/ebpf/limiter/ammsp_flush_lines_tests.rs — the
  flush trace and failure lines.
- The schema pin: types.rs's version constant test, moved to 10.
- Live proof (CI root lanes): the supermassive matrix gains
  `test_ammsp_subtree` — the child born after the apply, the
  poisoned-memo invalidation, the parent+child shared budget, the
  grandchild nearest-root resolution, and the aggregate-at-root
  stats row, each a measured band verdict plus the kernel-drop
  proof. This is the owner's eagle-eyes scenario, made permanent.
- Frame A/B: bytes/frame byte-identical (the render surface is
  untouched); the datapath overhead lives where it can be measured
  — the CI overhead stage and the depth battery's rate verdicts.

## 7. What this deliberately does NOT do

- No new CLI flag, no grammar change: AMMSP is the DEFAULT
  behavior of every strict/block verb (the v11 frozen grammar
  honored — an ability upgrade, not a surface change).
- No daemon, no watcher, no enumeration of children that do not
  exist yet — the walk resolves what IS, per packet, in kernel.
- No change to eagle-eyes: the monitor still shows per-leaf truth
  (a child downloading 1mbps will now SHOW as policed-and-dropped
  at the kernel, not escape it). A future per-root aggregate VIEW
  is a think-like-light-years item, not a v11.1.0 one.
- No per-leaf mode flag: the directive's "no exception" and the
  no-config rule together mean default-on is the only shape.
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
