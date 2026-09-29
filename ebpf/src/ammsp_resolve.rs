// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The AMMSP datapath resolution (NIGHT-private-research-2 &
// think-like-light-years-2): the BPF-side wiring that maps a
// packet's socket leaf cgroup to the policy ROOT covering it. Split
// from ebpf/src/bin/limiter.rs at the same task to hold the bin
// under the 500-LOC owner cap — the resolution block is one
// self-contained concern (the memo map + the walk driver), the same
// split discipline the userspace tree's policy_lines/parse splits
// set. The DECISION logic stays pure in ../ammsp.rs (core-only,
// dual-tree, rootlessly pinned); this file owns what only the
// kernel side can touch:
//
//   * the pinned ammsp_leaf_cache LRU map (leaf id -> resolved root,
//     0 = resolved unlimited),
//   * the bpf_skb_ancestor_cgroup_id helper calls (absolute levels,
//     ascending, break at 0),
//   * the policy-map lookups that feed the walk.
//
// Everything aya-ebpf-dependent about AMMSP lives here and nowhere
// else; everything decidable about it lives in ammsp.rs and is
// pinned by test/ebpf/limiter/ammsp_tests.rs.

use aya_ebpf::{
    helpers::bpf_skb_ancestor_cgroup_id,
    macros::map,
    maps::{HashMap, LruHashMap},
    programs::SkBuffContext,
};

// The pure resolution core (core-only, the same file the userspace
// test tree compiles) and the policy struct it queries against.
// Reused from the root's own inclusion — ONE copy per crate, the
// math.rs duplicate-mod discipline (clippy rightly rejects two).
use super::ammsp::{AMMSP_MAX_DEPTH, AmmspWalk, CacheVerdict, cache_verdict, memo_value};
use super::math::Policy;

/// AMMSP leaf cache: leaf cgroup id -> resolved policy-root id,
/// 0 = resolved unlimited. LRU so dead leaves (systemd scopes and
/// other transient cgroups) evict naturally instead of filling the
/// memo — a full plain hash map would degrade every new leaf to a
/// per-packet walk, while LRU keeps resolution at one lookup per
/// packet forever. The static name stays lowercase like every map
/// symbol in the limiter object — it IS the userspace pin contract
/// (/sys/fs/bpf/zelynic/ammsp_leaf_cache, PIN_MAP_AMMSP_CACHE in
/// src/ebpf/pin.rs).
///
/// The memo is written by the datapath ONLY; userspace never seeds
/// it, but every policy mutation flushes it whole (ammsp_cache_flush
/// in src/ebpf/limiter/ammsp.rs) — a cached negative or a cached
/// farther root would otherwise outlive the policy state it
/// summarized. The datapath's stale-detect (cache hit whose root
/// lost its policy -> delete + re-walk) is the belt for whatever the
/// flush misses; the flush is the belt for what stale-detect cannot
/// see (additions). Neither trusts the other; both re-walk through
/// the live policy map, which is the only authority.
#[allow(non_upper_case_globals)]
#[map]
static ammsp_leaf_cache: LruHashMap<u32, u32> = LruHashMap::pinned(4096, 0);

/// Resolve the policy root covering `leaf` (0 = unlimited). Called
/// only after the leaf's own policy lookup MISSED (a policy at the
/// socket's own cgroup is the nearest possible root, handled by the
/// caller without a walk), so the walk feeds ancestors only.
///
/// Fast path first: the LRU memo. A cached 0 is a resolved negative
/// (one lookup, unlimited); a cached root is trusted only while the
/// policy map still holds it (stale-detect: delete + re-walk — the
/// belt for flush misses). The walk itself queries absolute cgroup
/// levels 0..AMMSP_MAX_DEPTH ascending — root first, then downward —
/// breaks at the first 0 (past the socket's depth), and keeps the
/// LAST level whose id carries a policy: ascending order makes the
/// last match the NEAREST root, which is also the nested-root
/// verdict (a strict on A and a stricter strict on B, B under A: a
/// socket under B resolves to B, a socket under A-outside-B to A —
/// each subtree shares its own root's budget).
#[inline(always)]
pub(super) fn ammsp_resolve_root(
    ctx: &SkBuffContext,
    leaf: u32,
    policy_map: &HashMap<u32, Policy>,
) -> u32 {
    // get_ptr is the repo's map-lookup idiom (safe, raw-pointer); the
    // one unsafe read is the map-value deref every get_ptr caller in
    // the object performs the same way.
    let cached = ammsp_leaf_cache.get_ptr(&leaf).map(|p| unsafe { *p });
    match cached {
        Some(cached) => match cache_verdict(Some(cached), policy_map.get_ptr(&cached).is_some()) {
            CacheVerdict::Allow => return 0,
            CacheVerdict::Enforce(root) => return root,
            CacheVerdict::Walk => {
                // Stale memo (root's policy gone): drop it so the
                // rewrite below lands on a clean slot. Best-effort —
                // an LRU remove cannot fail loudly, and the rewrite
                // makes the entry correct either way.
                let _ = ammsp_leaf_cache.remove(&leaf);
            }
        },
        None => {}
    }

    let mut walk = AmmspWalk::new();
    for level in 0..AMMSP_MAX_DEPTH {
        let id = unsafe { bpf_skb_ancestor_cgroup_id(ctx.skb.skb, level as i32) } as u32;
        if id == 0 {
            // Past the socket's own depth: the chain is exhausted
            // (cgroup_ancestor returns NULL above the leaf's level,
            // and kernfs ids never truncate to 0 — see ammsp.rs).
            break;
        }
        walk.note(id, policy_map.get_ptr(&id).is_some());
    }
    let root = walk.root();
    // Memoize both outcomes — the negative memo is what keeps the
    // unlimited majority at ONE extra lookup per packet forever.
    // Insert failures (never expected on LRU) cost a re-walk next
    // packet, never a wrong verdict: the walk result is used this
    // packet regardless. memo_value names the stored shape: the root
    // id itself, or 0 when nothing matched.
    let _ = ammsp_leaf_cache.insert(&leaf, &memo_value(root), 0);
    root
}
