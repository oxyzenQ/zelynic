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
/// (checked by the caller before enforcing), and any disagreement —
/// or an absent entry — sends the packet through the walk, which
/// re-reads the live policy map and rewrites the memo.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheVerdict {
    /// Cached resolution says no root covers this leaf: unlimited.
    /// (A cached negative stays valid across policy REMOVALS —
    /// removing coverage cannot create coverage — and every policy
    /// ADDITION flushes the whole map, so it can never outlive the
    /// state it summarized.)
    Allow,
    /// Cached root, confirmed alive by the policy map: enforce
    /// against this root.
    Enforce(u32),
    /// No usable memo: run the walk and rewrite the entry. Reached
    /// when the entry is absent (first packet from this leaf) or
    /// when the cached root's policy is gone (removed mid-flight —
    /// the map flush missed it, or the pin was re-created empty).
    Walk,
}

/// The cache decision table. `cached` is the memoized value for the
/// leaf (None = absent, Some(0) = cached negative, Some(r) = cached
/// root); `root_policy_alive` is whether the policy map currently
/// contains the cached root (only meaningful for Some(r) != 0).
///
/// The stale-negative case — Some(0) while a policy was ADDED above
/// this leaf — is deliberately NOT a verdict here: it cannot be
/// detected from the cached value alone, which is exactly why every
/// policy write flushes the entire cache (userspace,
/// NIGHT-private-research-2) instead of trusting this table to
/// self-heal. The table covers what the kernel can see on its own;
/// the flush covers what only the mutation path knows.
#[inline(always)]
pub fn cache_verdict(cached: Option<u32>, root_policy_alive: bool) -> CacheVerdict {
    match cached {
        None => CacheVerdict::Walk,
        Some(0) => CacheVerdict::Allow,
        Some(root) => {
            if root_policy_alive {
                CacheVerdict::Enforce(root)
            } else {
                CacheVerdict::Walk
            }
        }
    }
}

/// The value to memoize after a walk resolves `root`: the root id
/// itself, or 0 when nothing matched — the negative memo that keeps
/// unlimited traffic at ONE cache lookup per packet forever after.
#[inline(always)]
pub const fn memo_value(root: u32) -> u32 {
    root
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
