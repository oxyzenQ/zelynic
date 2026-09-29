// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The AMMSP userspace half (NIGHT-private-research-2 &
//! think-like-light-years-2): cache invalidation on policy mutation.
//!
//! The kernel half (ebpf/src/bin/limiter.rs + ebpf/src/ammsp.rs)
//! resolves every packet's socket leaf cgroup to the policy ROOT
//! covering it — the subtree contract: a strict on cgroup A polices
//! every socket born under A/** with ONE shared budget — and memoizes
//! the resolution in the pinned LRU `ammsp_leaf_cache` map so the
//! unlimited majority pays one lookup, not a walk, per packet.
//!
//! The memo's one blind spot is mutation: a cached NEGATIVE (leaf ->
//! 0, "no root covers this leaf") or a cached FARTHER root cannot see
//! a policy that was ADDED after the walk ran — the kernel's
//! stale-detect (a cached root whose policy is gone triggers a
//! delete + re-walk) covers removals, but only the mutation path
//! knows an addition happened. So every policy write and delete
//! flushes the whole cache: entries are few (bounded by the number
//! of distinct leaf cgroups that moved a packet since the last
//! mutation, at most the 4096-entry LRU cap), mutations are
//! human-scale, and the flock every mutation already holds makes the
//! flush race-free by construction. After a flush, each live leaf
//! re-walks ONCE on its next packet and re-memoizes — correct by
//! re-reading the only authority, the live policy map.

use anyhow::{anyhow, Context, Result};
use aya::maps::HashMap as BpfHashMap;

use super::reclaim::map_remove_means_absent;
use crate::ebpf::pin::{self, PIN_MAP_AMMSP_CACHE};

/// Verbose trace line for one cache flush (NIGHT-private-research-2):
/// pure formatting so the wording is unit-pinned. The count is the
/// number of memos dropped — the leaves that re-walk once each.
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

/// The flush error line: a flush that cannot run is never silent (the
/// unstrict precedent) but never fails the mutation either — the
/// datapath's stale-detect re-walks whatever the flush missed, so the
/// miss degrades resolution to per-packet walks, never to a wrong
/// verdict. Pure formatting so the wording is unit-pinned.
pub(super) fn flush_failed_line(cause: &str) -> String {
    format!(
        "ammsp leaf cache flush failed ({cause}) — resolutions re-walk per \
         packet until the next mutation; run 'zelynic recover' if this persists"
    )
}

impl super::Limiter {
    /// Flush the AMMSP leaf cache whole (NIGHT-private-research-2).
    ///
    /// Runs once per policy-mutation invocation — the tail of
    /// `apply_single`, `apply_group`, and `unstrict` — after the
    /// policy writes/deletes landed (including the rollback ledger:
    /// a rolled-back apply still mutated, so the flush still runs on
    /// the error path before the error returns). `Ok(n)` reports the
    /// number of memos dropped; `Err` names the pin problem without
    /// failing the caller's own verdict (the callers print it, the
    /// datapath's stale-detect covers the miss).
    ///
    /// Deletion is iterate-then-remove, not remove-while-iterating:
    /// the key set is snapshotted first (bounded by the 4096-entry
    /// LRU cap) so a mid-iteration LRU eviction cannot walk the
    /// iterator off a moving map. ENOENT on a remove means the memo
    /// was already gone — the flush wants the map empty, so absent
    /// counts as done.
    pub fn ammsp_cache_flush(&mut self) -> Result<u32> {
        // Key snapshot under whichever mode is live — a READ, so it
        // opens the map directly the way every status reader does
        // (stats.rs precedent); mutations are the with_u32_map lane's
        // monopoly, and the delete phase below rides the LRU twin of
        // that lane in reclaim.rs.
        let keys: Vec<u32> = if let Some(bpf) = self.bpf.as_ref() {
            let map_ref = bpf
                .map("ammsp_leaf_cache")
                .context("ammsp_leaf_cache not found in loaded object")?;
            let map: BpfHashMap<_, u32, u32> =
                BpfHashMap::try_from(map_ref).context("Failed to access ammsp_leaf_cache")?;
            map.keys().flatten().collect()
        } else {
            let map_obj = pin::open_pinned_lru_hash_map(PIN_MAP_AMMSP_CACHE)?;
            let map: BpfHashMap<_, u32, u32> =
                BpfHashMap::try_from(&map_obj).context("Failed to open pinned ammsp_leaf_cache")?;
            map.keys().flatten().collect()
        };

        // Delete phase: through the LRU acquisition lane (the
        // architecture pin's ONE-path contract, the LRU twin of
        // with_u32_map).
        let mut flushed = 0u32;
        self.with_lru_u32_map::<u32, ()>("ammsp_leaf_cache", PIN_MAP_AMMSP_CACHE, |map| {
            for key in keys {
                match map.remove(&key) {
                    Ok(()) => flushed += 1,
                    Err(e) if map_remove_means_absent(&e) => flushed += 1,
                    Err(e) => return Err(anyhow!("remove cg:{key} memo: {e}")),
                }
            }
            Ok(())
        })?;

        Ok(flushed)
    }

    /// The flush's never-fail wrapper: runs the flush, traces it
    /// verbosely, and prints (never propagates) a failure — the
    /// mutation's own verdict outranks the memo housekeeping, and
    /// the datapath's stale-detect covers whatever the flush missed.
    pub(super) fn ammsp_cache_flush_best_effort(&mut self) {
        match self.ammsp_cache_flush() {
            Ok(flushed) => {
                if self.verbose {
                    eprintln_safe!("{}", flush_trace_line(flushed));
                }
            }
            Err(e) => {
                eprintln_safe!("{}", flush_failed_line(&e.to_string()));
            }
        }
    }
}

// NIGHT-hunt-17: pins live under the single test/ tree, #[path]-wired
// across trees (cosmostrix Pattern C).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/ammsp_flush_lines_tests.rs"]
mod ammsp_flush_lines_tests;
