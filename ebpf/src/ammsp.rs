// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The AMMSP resolution core, extracted pure (NIGHT-private-research-2
// & think-like-light-years-2): the walk state machine and the cache
// decision table that run inside the BPF program, with zero
// aya/eBPF dependencies so the SAME file compiles into the kernel
// object (ebpf/src/bin/limiter.rs wires it with #[path]) AND into
// the userspace test tree (src/ebpf/limiter/ammsp.rs wires it the
// same way), where test/ebpf/limiter/ammsp_tests.rs pins it
// rootlessly — the NIGHT-depthbore-1 math.rs discipline applied to
// the resolution logic.
//
// AMMSP (Aware Multi Micro Sub-Process) is the intergalaxion-engine
// skill patch that closes the subtree hole: a policy written for
// cgroup A must police A AND every descendant socket (A/**), sharing
// ONE token budget, with no daemon, no config, and no enumeration of
// children that do not exist yet. The owner found the hole live
// (eagle-eyes, 2026-09-30): a cgroup limited to 100kb showed a
// subprocess in a child cgroup downloading >1mbps. The datapath
// keyed its policy lookup by bpf_skb_cgroup_id — the SOCKET's leaf
// cgroup — so a socket born in a fresh child cgroup missed the map
// and was unlimited, not merely separately-bucketed.
//
// This module must stay `core`-only: no std, no alloc, no aya — any
// dependency added here reaches both trees at once.
//
// The two kernel facts the design rests on (verified against
// torvalds/linux master and v5.13, net/core/filter.c +
// include/linux/cgroup.h — not assumed):
//
//   1. bpf_skb_ancestor_cgroup_id(skb, level) is exposed to
//      cgroup_skb programs via cg_skb_func_proto, is gpl_only =
//      false, and present in the verified 5.13 floor (it predates
//      it by years).
//   2. cgroup_ancestor(cgrp, level) indexes by ABSOLUTE level
//      counted from the cgroup root (ancestors[0] = root; NULL when
//      level > cgrp->level), so ascending level queries walk the
//      socket's chain from the root downward and return 0 once past
//      the leaf's own depth — the walk's break condition.
//
// The generation stamp (NIGHT-perf-0): every memo carries the
// ammsp_generation counter value it was resolved under, and every
// policy mutation bumps that counter AFTER its writes land. The
// ordering proof that makes a stale memo self-invalidating:
//
//   * the walk reads the generation BEFORE it reads any policy, and
//     stamps its insert with that value;
//   * the mutation writes policies first, bumps the generation
//     second — so a walk that observed the post-bump generation
//     necessarily reads post-write policies (map updates are
//     visible to other CPUs once the writing syscall returns),
//     while a walk that read pre-write policies can only carry a
//     pre-bump stamp, which the very next packet sees mismatch and
//     re-walks.
//
// This closes the one hole the whole-map delete flush could not:
// a walk whose tail was stretched by an NMI/IRQ storm past the
// flush used to insert a memo computed against pre-mutation state
// AFTER the flush finished sweeping — a stale verdict that then
// lived until the NEXT mutation. A generation mismatch is detected
// per packet by the memo reader, so no insert can ever outlive the
// state it summarized.

/// How deep the ancestor walk reaches: the loop queries absolute
/// levels 0..AMMSP_MAX_DEPTH and stops early the moment the helper
/// returns 0 (past the socket's cgroup), so the bound is a ceiling,
/// not a cost — a depth-6 socket pays seven queries, not 32.
///
/// Real hierarchies sit far below this line (systemd user sessions
/// ~6, container runtimes ~4, Kubernetes pods under 10), so 32 is
/// three times generous. A socket nested deeper than 32 levels from
/// the cgroup root resolves as unlimited — the one documented,
/// explicit compromise of AMMSP (USAGE.md honest limitations); no
/// deployment reaches it without deliberately constructing it.
pub const AMMSP_MAX_DEPTH: u32 = 32;

/// The walk state machine: fed cgroup ids in ascending level order
/// (the socket's chain from the cgroup root downward), it tracks the
/// NEAREST level that carries a policy.
///
/// Ascending order is the correctness contract, not a convention:
/// a policy can live at several levels of one chain (nested roots —
/// a strict on A and another strict on B, B a descendant of A), and
/// the nearest root is the one with the highest absolute level, so
/// the LAST match an ascending feed notes is the one that must win.
/// The caller feeds levels 0, 1, 2, ... in order; feeding out of
/// order picks the wrong root by construction.
///
/// The leaf itself is deliberately NOT fed to the walk: the caller
/// checks the leaf's own policy first (a policy at the socket's own
/// cgroup is the nearest possible root — nothing below it can be
/// nearer), so by the time the walk runs the leaf is known
/// policy-free and only ancestors can match.
pub struct AmmspWalk {
    nearest: u32,
}

impl AmmspWalk {
    /// A fresh walk: nothing matched yet, root() would report 0
    /// (unlimited).
    #[inline(always)]
    pub const fn new() -> Self {
        AmmspWalk { nearest: 0 }
    }

    /// Note one chain member. `id` is the cgroup id the caller
    /// queried at the current ascending level; `has_policy` is
    /// whether the policy map contains it. A match overwrites the
    /// previous one — the ascending-order rule that makes the last
    /// match the nearest root.
    #[inline(always)]
    pub fn note(&mut self, id: u32, has_policy: bool) {
        if has_policy {
            self.nearest = id;
        }
    }

    /// The resolved root: the nearest matched id, or 0 when nothing
    /// on the chain carries a policy (unlimited). 0 is unreachable
    /// as a real cgroup id — kernfs ids start at 1 — so it is a safe
    /// sentinel for both the walk result and the cached negative.
    #[inline(always)]
    pub const fn root(&self) -> u32 {
        self.nearest
    }
}

impl Default for AmmspWalk {
    fn default() -> Self {
        Self::new()
    }
}

/// What the datapath does with the cached resolution for one leaf.
///
/// The cache is a memo, never an authority: a cached POSITIVE root
/// is only trusted while the policy map still agrees it is alive
/// (checked by the caller before enforcing), and only while the
/// generation it was stamped with is still the current one (checked
/// by the caller against ammsp_generation before anything else) —
/// and any disagreement, or an absent entry, sends the packet
/// through the walk, which re-reads the live policy map and
/// rewrites the memo with the current generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheVerdict {
    /// Cached resolution says no root covers this leaf: unlimited.
    /// (A cached negative stays valid across policy REMOVALS —
    /// removing coverage cannot create coverage — and its
    /// generation stamp was taken while that was already true: an
    /// ADDITION bumps the generation, so the stale-negative case is
    /// a generation mismatch, not this verdict.)
    Allow,
    /// Cached root, generation current and policy alive: enforce
    /// against this root.
    Enforce(u32),
    /// No usable memo: run the walk and rewrite the entry. Reached
    /// when the entry is absent (first packet from this leaf), when
    /// its generation stamp no longer matches (a mutation has
    /// occurred since it was written — the insert race the delete
    /// flush could not close, NIGHT-perf-0), or when the cached
    /// root's policy is gone (removed mid-flight — the belt the
    /// generation stamp makes near-impossible and the stale-detect
    /// keeps anyway).
    Walk,
}

/// The cache decision table. `cached` is the memoized packed value
/// for the leaf (None = absent, Some(v) = the packed
/// generation-and-root word); `current_gen` is the generation the
/// caller just read from ammsp_generation; `root_policy_alive` is
/// whether the policy map currently contains the cached root (only
/// meaningful for a generation-current memo with a nonzero root).
///
/// The generation row is the NIGHT-perf-0 close: a memo whose
/// stamp mismatches the current generation is a Walk no matter
/// what root it names — the memo may have been computed against
/// pre-mutation policy state (the insert-after-flush race), so its
/// content is untrusted even when it names a live root. The walk
/// then re-reads the only authority, the live policy map, and
/// rewrites the memo under the current generation.
#[inline(always)]
pub fn cache_verdict(
    cached: Option<u64>,
    current_gen: u32,
    root_policy_alive: bool,
) -> CacheVerdict {
    match cached {
        None => CacheVerdict::Walk,
        Some(v) if memo_gen(v) != current_gen => CacheVerdict::Walk,
        Some(v) => match memo_root(v) {
            0 => CacheVerdict::Allow,
            root => {
                if root_policy_alive {
                    CacheVerdict::Enforce(root)
                } else {
                    CacheVerdict::Walk
                }
            }
        },
    }
}

/// The value to memoize after a walk resolves `root` under
/// `generation`: the root id and the generation stamped into
/// one u64 word — `(generation << 32) | root` — so the memo lookup
/// that already runs per packet carries the staleness check with it
/// (a separate generation read would be a second map lookup on the
/// unlimited majority's fast path; packing keeps the memo at ONE
/// lookup plus the single Array read the resolver takes anyway).
/// `root` is the walk result verbatim: a root id when one matched,
/// 0 when none did — the negative memo that keeps unlimited
/// traffic at one cache lookup per packet forever after.
#[inline(always)]
pub const fn memo_value(generation: u32, root: u32) -> u64 {
    ((generation as u64) << 32) | (root as u64)
}

/// The generation stamp half of a packed memo value. The stamp is
/// the ammsp_generation counter the walk read BEFORE its policy
/// reads — the ordering that makes a mismatch provable staleness
/// (see the module header's proof).
#[inline(always)]
pub const fn memo_gen(value: u64) -> u32 {
    (value >> 32) as u32
}

/// The resolution half of a packed memo value: the root id the walk
/// resolved (0 = resolved unlimited) — exactly the word the
/// pre-generation design stored on its own.
#[inline(always)]
pub const fn memo_root(value: u64) -> u32 {
    (value & 0xFFFF_FFFF) as u32
}

/// Depth bound honesty helper (unit-pinned): the number of helper
/// queries a walk performs for a socket whose cgroup sits at
/// absolute level `leaf_level` — one query per ancestor level from
/// the root (0..leaf_level), plus the one past-the-depth query that
/// returns 0 and breaks the loop. Kernels disagree by one on whether
/// the leaf's own level returns the leaf itself or 0 (the ancestors
/// array's self-slot), so the exact count is leaf_level+1 or +2 —
/// the bound, never the exact integer, is the contract, and a socket
/// deeper than [`AMMSP_MAX_DEPTH`] resolves unlimited (the one
/// documented compromise).
///
/// Test-facing by design: the datapath needs no query budget, the
/// documentation and the pins do — cfg(test) keeps the ebpf release
/// build free of the dead symbol a clippy -D warnings run rejects
/// (the userspace test tree compiles this same file with the test
/// profile, so the pins see it).
#[cfg(test)]
#[inline(always)]
pub const fn walk_queries(leaf_level: u32) -> u32 {
    if leaf_level + 2 > AMMSP_MAX_DEPTH {
        AMMSP_MAX_DEPTH
    } else {
        leaf_level + 2
    }
}
