// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The MMSPA datapath resolution (NIGHT-private-research-2 &
// think-like-light-years-2): the BPF-side wiring that maps a
// packet's socket leaf cgroup to the policy ROOT covering it. Split
// from ebpf/src/bin/limiter.rs at the same task to hold the bin
// under the 500-LOC owner cap — the resolution block is one
// self-contained concern (the memo map + the walk driver), the same
// split discipline the userspace tree's policy_lines/parse splits
// set. The DECISION logic stays pure in ../mmspa.rs (core-only,
// dual-tree, rootlessly pinned); this file owns what only the
// kernel side can touch:
//
//   * the two pinned mmspa_leaf_cache LRU maps (leaf id -> resolved
//     root, 0 = resolved unlimited), ONE PER DIRECTION (v18, the
//     cross-direction poisoning close — see the map docs below);
//   * the bpf_skb_ancestor_cgroup_id helper calls (absolute levels,
//     ascending, break at 0),
//   * the policy-map lookups that feed the walk.
//
// Everything aya-ebpf-dependent about MMSPA lives here and nowhere
// else; everything decidable about it lives in mmspa.rs and is
// pinned by test/ebpf/limiter/mmspa_tests.rs.

use aya_ebpf::{
    helpers::bpf_skb_ancestor_cgroup_id,
    macros::map,
    maps::{Array, HashMap, LruHashMap},
    programs::SkBuffContext,
};

// The pure resolution core (core-only, the same file the userspace
// test tree compiles) and the policy struct it queries against.
// Reused from the root's own inclusion — ONE copy per crate, the
// math.rs duplicate-mod discipline (clippy rightly rejects two).
use super::math::Policy;
use super::mmspa::{
    CacheVerdict, MMSPA_MAX_DEPTH, MmspaWalk, cache_verdict, memo_gen, memo_root, memo_value,
};

/// MMSPA leaf cache, DOWNLOAD lane: leaf cgroup id -> the packed
/// u64 memo word (`(generation << 32) | root`, the packing pure core
/// in mmspa.rs owns; root 0 = resolved unlimited). LRU so dead
/// leaves (systemd scopes and other transient cgroups) evict
/// naturally instead of filling the memo — a full plain hash map
/// would degrade every new leaf to a per-packet walk, while LRU
/// keeps resolution at one lookup per packet forever. The static
/// name stays lowercase like every map symbol in the limiter object
/// — it IS the userspace pin contract (/sys/fs/bpf/zelynic/
/// mmspa_leaf_cache_dl, PIN_MAP_MMSPA_CACHE_DL in src/ebpf/pin.rs).
///
/// SCHEMA v18 (NIGHT-hunt-Z1): the memo is now DIRECTION-SCOPED —
/// one map per direction, never shared. The v10..v17 single
/// mmspa_leaf_cache was read by BOTH enforce_dl and enforce_ul, but
/// a memo's root is only valid for the direction whose walk produced
/// it: the walk resolves against THAT direction's policy map, and
/// the two maps legitimately disagree — the single-direction applies
/// (`strict -d`, `strict -u`) delete one leg's row, so the deleted
/// direction's nearest root is an ANCESTOR (the catch-all at the
/// root cgroup, or unlimited) while the written direction's is the
/// target. The shared memo let the first direction to walk a leaf
/// poison the other: the handshake/ACK packets (egress, upload map)
/// memoized the probe leaf to the root catch-all, and every download
/// data packet then hit that memo — the stale-detect could not catch
/// it, because the catch-all carries a row in the download map too —
/// so the flow enforced at the ANCESTOR's rate, not the target's
/// (measured 3.5-4.7x the target budget, ledger booked at the
/// ancestor, the verdict FAILED against a policy that never ran).
/// Two maps close the class: each direction memoizes only what its
/// own walk resolved.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static mmspa_leaf_cache_dl: LruHashMap<u32, u64> = LruHashMap::pinned(4096, 0);

/// MMSPA leaf cache, UPLOAD lane — the download twin's map and
/// posture, one direction's resolution never consulted by the other
/// (the v18 close; see mmspa_leaf_cache_dl's docs for the poisoning
/// shape the split ends). Pin contract: /sys/fs/bpf/zelynic/
/// mmspa_leaf_cache_ul, PIN_MAP_MMSPA_CACHE_UL in src/ebpf/pin.rs.
#[allow(non_upper_case_globals)]
#[map]
pub(super) static mmspa_leaf_cache_ul: LruHashMap<u32, u64> = LruHashMap::pinned(4096, 0);

/// The MMSPA memo generation (NIGHT-perf-0): a one-entry pinned
/// counter array, read by the datapath before every resolution and
/// bumped by userspace (mmspa_memo_invalidate in
/// src/ebpf/limiter/mmspa.rs) after every policy mutation's writes
/// land. The bump is the O(1) replacement for the O(memo-cap) delete
/// sweep: instead of walking the whole 4096-entry LRU with one
/// syscall per remove, the mutation advances the single word every
/// memo is stamped against, and the per-packet stamp check retires
/// the stale generation lazily — one re-walk per live leaf, the same
/// steady-state cost, a thousandth of the mutation-side syscall
/// work under a burst of applies. The static name is the pin
/// contract (/sys/fs/bpf/zelynic/mmspa_generation,
/// PIN_MAP_MMSPA_GEN in src/ebpf/pin.rs), lowercase like every map
/// symbol in the object.
#[allow(non_upper_case_globals)]
#[map]
static mmspa_generation: Array<u32> = Array::pinned(1, 0);

/// Read the current memo generation. The Array's single entry is
/// pre-created by the kernel, so a None is unreachable in practice;
/// the 0 fallback still keeps the datapath correct when one happens
/// (a broken read degrades to re-walks — every memo carries a real
/// generation stamp from its own insert, so a bogus 0 mismatches it
/// and forces the walk; a wrong verdict would require the map to
/// hold a state it never held, which no read failure can arrange).
/// Charger-core-1c: the generation the DRR stale-quantum belt
/// reads (one Array word, one lookup per DRR-enforced packet —
/// shared with the memo stamping above, the same counter).
#[inline(always)]
pub(super) fn current_generation() -> u32 {
    mmspa_generation
        .get_ptr(0)
        .map(|p| unsafe { *p })
        .unwrap_or(0)
}

/// Resolve the policy root covering `leaf` (0 = unlimited) through
/// THIS direction's own memo map. Called only after the leaf's own
/// policy lookup MISSED (a policy at the socket's own cgroup is the
/// nearest possible root, handled by the caller without a walk), so
/// the walk feeds ancestors only. `memo_map` is the calling
/// direction's leaf cache (v18: the resolution is direction-scoped —
/// a root valid for the upload map is not one for the download map,
/// and the memo never crosses lanes).
///
/// Fast path first: the LRU memo. A cached word whose generation
/// stamp is current and whose root is 0 is a resolved negative (one
/// lookup, unlimited); a cached current root is trusted only while
/// the policy map still holds it (stale-detect: delete + re-walk —
/// the belt behind the generation stamp). A stamp mismatch is the
/// NIGHT-perf-0 verdict: the memo was written against pre-mutation
/// state, so it is Walked regardless of what it names. The walk
/// itself queries absolute cgroup levels 0..MMSPA_MAX_DEPTH
/// ascending — root first, then downward — breaks at the first 0
/// (past the socket's depth), and keeps the LAST level whose id
/// carries a policy: ascending order makes the last match the
/// NEAREST root, which is also the nested-root verdict (a strict on
/// A and a stricter strict on B, B under A: a socket under B
/// resolves to B, a socket under A-outside-B to A — each subtree
/// shares its own root's budget).
#[inline(always)]
pub(super) fn mmspa_resolve_root(
    ctx: &SkBuffContext,
    leaf: u32,
    policy_map: &HashMap<u32, Policy>,
    memo_map: &LruHashMap<u32, u64>,
) -> u32 {
    // The generation is read BEFORE any policy read — the ordering
    // half of the staleness proof (module header of mmspa.rs): a
    // walk that carries this stamp either saw every policy write
    // that preceded its bump, or its stamp is already stale by the
    // time it is compared.
    let generation = current_generation();

    // get_ptr is the repo's map-lookup idiom (safe, raw-pointer); the
    // one unsafe read is the map-value deref every get_ptr caller in
    // the object performs the same way.
    let cached = memo_map.get_ptr(&leaf).map(|p| unsafe { *p });
    // The stale-detect's policy lookup runs only when it can change
    // the verdict: a generation-current memo with a nonzero root.
    // (A mismatched stamp never consults the policy map — the memo
    // is untrusted wholesale, which is the whole point of the row.)
    let root_policy_alive = match cached {
        Some(v) if memo_gen(v) == generation && memo_root(v) != 0 => {
            policy_map.get_ptr(&memo_root(v)).is_some()
        }
        _ => false,
    };
    match cache_verdict(cached, generation, root_policy_alive) {
        CacheVerdict::Allow => return 0,
        CacheVerdict::Enforce(root) => return root,
        CacheVerdict::Walk => {
            // Stale memo (stamp mismatch, or a root whose policy is
            // gone): drop it so the rewrite below lands on a clean
            // slot. Best-effort — an LRU remove cannot fail loudly,
            // and the rewrite makes the entry correct either way.
            let _ = memo_map.remove(&leaf);
        }
    }

    let mut walk = MmspaWalk::new();
    for level in 0..MMSPA_MAX_DEPTH {
        let id = unsafe { bpf_skb_ancestor_cgroup_id(ctx.skb.skb, level as i32) } as u32;
        if id == 0 {
            // Past the socket's own depth: the chain is exhausted
            // (cgroup_ancestor returns NULL above the leaf's level,
            // and kernfs ids never truncate to 0 — see mmspa.rs).
            break;
        }
        walk.note(id, policy_map.get_ptr(&id).is_some());
    }
    let root = walk.root();
    // Memoize both outcomes under the generation this walk read —
    // the negative memo is what keeps the unlimited majority at ONE
    // extra lookup per packet forever. Insert failures (never
    // expected on LRU) cost a re-walk next packet, never a wrong
    // verdict: the walk result is used this packet regardless.
    // memo_value names the stored shape: the packed stamp-and-root
    // word, root 0 when nothing matched.
    let _ = memo_map.insert(&leaf, &memo_value(generation, root), 0);
    root
}
