// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The limiter's map-acquisition lanes — the ONE-path contract for
//! every map mutation the userspace tree makes (NIGHT-hunt-20's
//! architecture pin, enforced by
//! test/integration/architecture_pins.rs: the only sanctioned
//! `.map_mut(` sites in the limiter tree live here and in attach's
//! ephemeral schema_version stamp, mod.rs).
//!
//! Split from reclaim.rs at the NIGHT-perf-0 task (the Array twin
//! pushed the file past the 500-LOC owner cap): the lanes are
//! acquisition plumbing, self-contained with zero removal semantics,
//! while the removal family — delete, partial-failure honesty,
//! reclamation — stays in reclaim.rs. The same split discipline
//! policy_lines/parse set before it.
//!
//! Three twins, one shape: the loaded object's map when one is live,
//! the opened pin otherwise, acquisition errors keeping their
//! per-mode wording. The hash twin serves the policy, bucket, and
//! stats maps; the LRU twin serves the ammsp_leaf_cache memo (the
//! pin opens as `Map::LruHashMap` so aya's map-type reporting stays
//! honest); the Array twin serves the ammsp_generation counter
//! (NIGHT-perf-0) the memo invalidation bumps.

use anyhow::{anyhow, Context, Result};
use aya::maps::{Array as BpfArray, HashMap as BpfHashMap, MapData, MapError};

use crate::ebpf::pin;

/// NIGHT-hunt-20 (error-path audit): a failed map delete means
/// "key absent" ONLY for ENOENT — every other errno means the delete
/// did NOT happen and the entry is still live. Conflating the two is
/// how a remove path reports "nothing to remove" while state stays
/// behind. Pure so it is unit-pinned in the policy tests.
pub(super) fn map_remove_means_absent(err: &MapError) -> bool {
    matches!(
        err,
        MapError::SyscallError(e) if e.io_error.kind() == std::io::ErrorKind::NotFound
    )
}

impl super::Limiter {
    /// Generic u32-keyed limiter map access in whichever mode is live
    /// (NIGHT-improve-10). `op` runs against the ephemeral object's
    /// map when one is loaded, or the pinned map otherwise;
    /// acquisition errors keep their per-mode wording exactly like
    /// the former policy-only path. The ONE acquisition path for
    /// every u32-keyed limiter map: NIGHT-hunt-20 introduced it for
    /// policies, this widened it to the bucket and stats maps the
    /// reclaim path touches.
    pub(super) fn with_u32_map<V, R>(
        &mut self,
        map_name: &str,
        pin_path: &str,
        op: impl FnOnce(&mut BpfHashMap<&mut MapData, u32, V>) -> Result<R>,
    ) -> Result<R>
    where
        V: aya::Pod,
    {
        if let Some(bpf) = self.bpf.as_mut() {
            let map_ref = bpf
                .map_mut(map_name)
                .context(format!("{map_name} not found"))?;
            let mut map: BpfHashMap<&mut MapData, u32, V> =
                BpfHashMap::try_from(map_ref).context(format!("Failed to access {map_name}"))?;
            op(&mut map)
        } else {
            let mut map_obj = pin::open_pinned_hash_map(pin_path)?;
            let mut map: BpfHashMap<&mut MapData, u32, V> = BpfHashMap::try_from(&mut map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            op(&mut map)
        }
    }

    /// The LRU twin of [`Self::with_u32_map`]
    /// (NIGHT-private-research-2): the same ONE-acquisition-lane
    /// contract — every mutation of a u32-keyed limiter map flows
    /// through this file — extended to the map family whose pin opens
    /// as `Map::LruHashMap` so aya's map-type reporting stays honest
    /// (the ammsp_leaf_cache memo; the plain twin would work
    /// operationally, the variant is the honesty). Only the ammsp
    /// fallback sweep mutates an LRU map, so only it rides this lane.
    pub(super) fn with_lru_u32_map<V, R>(
        &mut self,
        map_name: &str,
        pin_path: &str,
        op: impl FnOnce(&mut BpfHashMap<&mut MapData, u32, V>) -> Result<R>,
    ) -> Result<R>
    where
        V: aya::Pod,
    {
        if let Some(bpf) = self.bpf.as_mut() {
            let map_ref = bpf
                .map_mut(map_name)
                .context(format!("{map_name} not found"))?;
            let mut map: BpfHashMap<&mut MapData, u32, V> =
                BpfHashMap::try_from(map_ref).context(format!("Failed to access {map_name}"))?;
            op(&mut map)
        } else {
            let mut map_obj = pin::open_pinned_lru_hash_map(pin_path)?;
            let mut map: BpfHashMap<&mut MapData, u32, V> = BpfHashMap::try_from(&mut map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            op(&mut map)
        }
    }

    /// The Array twin of [`Self::with_u32_map`] (NIGHT-perf-0):
    /// the one acquisition path for the limiter's u32-valued pinned
    /// array maps — the ammsp_generation counter the memo
    /// invalidation bumps. Same per-mode shape as the hash twins:
    /// the loaded object's map when one is live, the opened pin
    /// otherwise; acquisition errors keep their per-mode wording.
    /// The only sanctioned `.map_mut(` sites in the limiter tree
    /// remain this file and attach's schema_version stamp (mod.rs),
    /// exactly what the architecture pin holds.
    pub(super) fn with_array_u32_map<R>(
        &mut self,
        map_name: &str,
        pin_path: &str,
        op: impl FnOnce(&mut BpfArray<&mut MapData, u32>) -> Result<R>,
    ) -> Result<R> {
        if let Some(bpf) = self.bpf.as_mut() {
            let map_ref = bpf
                .map_mut(map_name)
                .context(format!("{map_name} not found"))?;
            let mut map: BpfArray<&mut MapData, u32> =
                BpfArray::try_from(map_ref).context(format!("Failed to access {map_name}"))?;
            op(&mut map)
        } else {
            let mut map_obj = pin::open_pinned_array_map(pin_path)?;
            let mut map: BpfArray<&mut MapData, u32> = BpfArray::try_from(&mut map_obj)
                .context(format!("Failed to open pinned map {pin_path}"))?;
            op(&mut map)
        }
    }

    /// Delete one u32 key from a limiter map in whichever mode is
    /// live. `Ok(true)` deleted, `Ok(false)` ENOENT (genuinely
    /// absent), `Err` when the delete could not be performed — the
    /// tri-state contract `delete_policy` exposes, factored once so
    /// the bucket/stats reclaim path shares it verbatim.
    pub(super) fn remove_map_entry<V: aya::Pod>(
        &mut self,
        map_name: &str,
        pin_path: &str,
        key: u32,
    ) -> Result<bool> {
        self.with_u32_map::<V, bool>(map_name, pin_path, |map| match map.remove(&key) {
            Ok(()) => Ok(true),
            Err(e) if map_remove_means_absent(&e) => Ok(false),
            Err(e) => Err(anyhow!("failed to delete key {key} from {map_name}: {e}")),
        })
    }
}
