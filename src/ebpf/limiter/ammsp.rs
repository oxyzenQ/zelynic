// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The AMMSP userspace half (NIGHT-private-research-2 &
//! think-like-light-years-2, hardened by NIGHT-perf-0): memo
//! invalidation on policy mutation.
//!
//! The kernel half (ebpf/src/bin/limiter.rs + ebpf/src/ammsp.rs +
//! ebpf/src/ammsp_resolve.rs) resolves every packet's socket leaf
//! cgroup to the policy ROOT covering it — the subtree contract: a
//! strict on cgroup A polices every socket born under A/** with ONE
//! shared budget — and memoizes the resolution in the pinned LRU
//! `ammsp_leaf_cache` map so the unlimited majority pays one lookup,
//! not a walk, per packet.
//!
//! The memo's one blind spot is mutation: a cached NEGATIVE (leaf ->
//! 0, "no root covers this leaf") or a cached FARTHER root cannot see
//! a policy that was ADDED after the walk ran. The original answer
//! (NIGHT-private-research-2) was a whole-map delete flush on every
//! mutation; the perf-0 audit found the shape it could not cover: a
//! walk whose tail an NMI/IRQ storm stretched past the sweep inserted
//! a memo computed against PRE-mutation state AFTER the flush
//! finished sweeping — the flock serializes mutations against
//! mutations, never against kernel-side walks, so the stale verdict
//! then lived until the NEXT mutation. The perf-0 answer is the
//! generation stamp: every memo carries the `ammsp_generation`
//! counter value current when its walk ran (packed into the memo
//! word), and every mutation bumps that counter AFTER its writes
//! land. The per-packet stamp check then catches any insert that
//! outlived the state it summarized — a stale memo becomes a Walk on
//! the very next packet, whatever the sweep missed by construction.
//! The bump is also the endurance win: one Array store replaces up
//! to 4096 one-syscall removes per mutation, so a burst of applies
//! no longer pays O(memo-cap) syscall work each. The sweep survives
//! as the fallback for the (never-expected) failure of the bump, and
//! the datapath's stale-detect (a cached root whose policy is gone
//! triggers a delete + re-walk) stays as the belt behind the stamp.
//! After a bump, each live leaf re-walks ONCE on its next packet and
//! re-memoizes under the new generation — correct by re-reading the
//! only authority, the live policy map.

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array as BpfArray, HashMap as BpfHashMap, MapData};

use super::lanes::map_error_means_absent;
use crate::ebpf::pin::{self, PIN_MAP_AMMSP_GEN};

/// Advance the generation word in whatever array handle the
/// acquisition lane hands over: read, wrap-increment, write. Pure
/// plumbing kept in one place so the read-modify-write contract
/// (wrapping, never saturating, so a counter that outlives u32
/// keeps the scheme total) is written once.
fn bump_generation_word(map: &mut BpfArray<&mut MapData, u32>) -> Result<(u32, u32)> {
    let old = map.get(&0, 0).context("read ammsp_generation[0]")?;
    let new = old.wrapping_add(1);
    map.set(0, new, 0).context("write ammsp_generation[0]")?;
    Ok((old, new))
}

/// Verbose trace line for one generation bump (NIGHT-perf-0): pure
/// formatting so the wording is unit-pinned. Every memo stamped
/// before the bump retires on its leaf's next packet — one re-walk
/// each, through the live policy map.
pub(super) fn bump_trace_line(old: u32, new: u32) -> String {
    format!(
        "[limiter] ammsp memo generation {old} -> {new} — every leaf re-resolves \
         once on its next packet"
    )
}

/// Verbose trace line for one fallback sweep (the NIGHT-perf-0
/// fallback lane): pure formatting so the wording is unit-pinned.
/// The count is the number of memos dropped — the leaves that
/// re-walk once each.
pub(super) fn flush_trace_line(flushed: u32) -> String {
    if flushed == 0 {
        "[limiter] ammsp leaf cache: 0 memos — resolution state already clean".to_string()
    } else {
        format!(
            "[limiter] ammsp leaf cache: flushed {flushed} memo{} — each covered leaf \
             re-resolves once on its next packet",
            if flushed == 1 { "" } else { "s" }
        )
    }
}

/// The invalidation failure line: a mutation whose memo invalidation
/// cannot run at all is never silent (the unstrict precedent) but
/// never fails the mutation either — the datapath's stale-detect
/// re-walks whatever removals left behind, so the miss degrades
/// resolution to per-packet walks for REMOVALS, while a stale verdict
/// for an ADDITION can outlive this apply until the next mutation
/// (the exact half the stamp exists to cover — stated plainly, not
/// papered over). Pure formatting so the wording is unit-pinned.
pub(super) fn invalidate_failed_line(bump_cause: &str, sweep_cause: &str) -> String {
    format!(
        "ammsp memo invalidation failed (generation bump: {bump_cause}; sweep: \
         {sweep_cause}) — removals still self-heal per packet, but a stale verdict \
         can outlive this apply until the next mutation; run 'zelynic recover' if \
         this persists"
    )
}

impl super::Limiter {
    /// Bump the AMMSP memo generation (NIGHT-perf-0).
    ///
    /// The O(1) memo invalidation: one Array store advances the word
    /// every memo is stamped against, and the datapath's per-packet
    /// stamp check retires the old generation lazily — one re-walk
    /// per LIVE leaf (a dead leaf never re-walks at all, which the
    /// sweep could never offer). Runs once per policy-mutation
    /// invocation, after every write and delete that invocation made
    /// landed (including the rollback ledger's deletions), inside
    /// the flock the mutation already holds — the bump-after-write
    /// ordering is the staleness proof's other half (see the ebpf
    /// core's module header). The Array access rides the
    /// with_array_u32_map acquisition lane (lanes.rs — the
    /// architecture pin's ONE-path contract, the Array twin of
    /// with_u32_map). `Ok((old, new))` reports the counter before
    /// and after; `Err` names the acquisition problem without
    /// failing the caller's own verdict (the caller falls back to
    /// the sweep).
    pub fn ammsp_generation_bump(&mut self) -> Result<(u32, u32)> {
        self.with_array_u32_map("ammsp_generation", PIN_MAP_AMMSP_GEN, bump_generation_word)
    }

    /// Flush the AMMSP leaf cache whole (NIGHT-private-research-2;
    /// the NIGHT-perf-0 fallback lane).
    ///
    /// The pre-perf-0 invalidation, kept as the belt for a failed
    /// generation bump: iterate-then-remove every memo so the map
    /// starts clean regardless of stamps. Runs only when the O(1)
    /// bump could not (a missing pin, a corrupted array handle) —
    /// the sweep costs up to one syscall per memo the LRU holds,
    /// which is exactly why the bump replaced it on the common path.
    ///
    /// Deletion is iterate-then-remove, not remove-while-iterating:
    /// the key set is snapshotted first (bounded by the 4096-entry
    /// LRU cap) so a mid-iteration LRU eviction cannot walk the
    /// iterator off a moving map. ENOENT on a remove means the memo
    /// was already gone — the flush wants the map empty, so absent
    /// counts as done.
    pub fn ammsp_cache_flush(&mut self) -> Result<u32> {
        // NIGHT-hunt-Z1 (schema v18): the memo lane is TWO
        // direction-scoped maps — the sweep must empty BOTH or a
        // stale memo survives the fallback on the unswept side (the
        // exact half-life the bump's failure made this lane run for).
        // The pair list is the pin contract's own shape: static map
        // name + pin path, one row per direction.
        const MEMO_MAPS: [(&str, &str); 2] = [
            (
                "ammsp_leaf_cache_dl",
                crate::ebpf::pin::PIN_MAP_AMMSP_CACHE_DL,
            ),
            (
                "ammsp_leaf_cache_ul",
                crate::ebpf::pin::PIN_MAP_AMMSP_CACHE_UL,
            ),
        ];
        let mut flushed = 0u32;
        for (map_name, pin_path) in MEMO_MAPS {
            // Key snapshot under whichever mode is live — a READ, so
            // it opens the map directly the way every status reader
            // does (stats.rs precedent); mutations are the
            // with_u32_map lane's monopoly, and the delete phase
            // below rides the LRU twin of that lane in lanes.rs.
            let keys: Vec<u32> = if let Some(bpf) = self.bpf.as_ref() {
                let map_ref = bpf
                    .map(map_name)
                    .with_context(|| format!("{map_name} not found in loaded object"))?;
                let map: BpfHashMap<_, u32, u64> = BpfHashMap::try_from(map_ref)
                    .with_context(|| format!("Failed to access {map_name}"))?;
                map.keys().flatten().collect()
            } else {
                let map_obj = pin::open_pinned_lru_hash_map(pin_path)?;
                let map: BpfHashMap<_, u32, u64> = BpfHashMap::try_from(&map_obj)
                    .with_context(|| format!("Failed to open pinned {map_name}"))?;
                map.keys().flatten().collect()
            };

            // Delete phase: through the LRU acquisition lane (the
            // architecture pin's ONE-path contract, the LRU twin of
            // with_u32_map).
            self.with_lru_u32_map::<u64, ()>(map_name, pin_path, |map| {
                for key in keys {
                    match map.remove(&key) {
                        Ok(()) => flushed += 1,
                        Err(e) if map_error_means_absent(&e) => flushed += 1,
                        Err(e) => return Err(anyhow!("remove cg:{key} memo from {map_name}: {e}")),
                    }
                }
                Ok(())
            })?;
        }

        Ok(flushed)
    }

    /// The invalidation's never-fail wrapper (NIGHT-perf-0): bump the
    /// generation, trace it verbosely; if the bump cannot run, fall
    /// back to the whole-map sweep and trace that; if BOTH fail,
    /// print the honest degradation line (never silent, never failing
    /// the mutation's own verdict, which outranks the memo
    /// housekeeping — the datapath's stale-detect covers removals,
    /// and the next successful mutation re-covers additions).
    pub(super) fn ammsp_memo_invalidate_best_effort(&mut self) {
        match self.ammsp_generation_bump() {
            Ok((old, new)) => {
                if self.verbose {
                    eprintln_safe!("{}", bump_trace_line(old, new));
                }
            }
            Err(bump_cause) => match self.ammsp_cache_flush() {
                Ok(flushed) => {
                    if self.verbose {
                        eprintln_safe!("{}", flush_trace_line(flushed));
                    }
                }
                Err(sweep_cause) => {
                    eprintln_safe!(
                        "{}",
                        invalidate_failed_line(&bump_cause.to_string(), &sweep_cause.to_string())
                    );
                }
            },
        }
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/ammsp_flush_lines_tests.rs"]
mod ammsp_flush_lines_tests;
