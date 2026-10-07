// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Pin path constants + cleanup helpers.
//! Single source of truth for all BPF pin file paths.

use std::path::PathBuf;

use anyhow::{anyhow, Result};
use aya::maps::{Array as BpfArray, MapData};

/// Root pin directory on bpffs.
pub const PIN_DIR: &str = "/sys/fs/bpf/zelynic";

/// Program pins (BPF programs stay loaded after process exit).
pub const PIN_PROG_DL: &str = "/sys/fs/bpf/zelynic/enforce_dl";
pub const PIN_PROG_UL: &str = "/sys/fs/bpf/zelynic/enforce_ul";

/// Link pins (bpf_links stay attached after process exit).
pub const PIN_LINK_DL: &str = "/sys/fs/bpf/zelynic/enforce_dl_link";
pub const PIN_LINK_UL: &str = "/sys/fs/bpf/zelynic/enforce_ul_link";

/// Map pins opened directly by userspace (policy + stats + watchdog +
/// schema version) and the individual bucket maps the unstrict/recover
/// reclaim path deletes from (NIGHT-improve-10: bucket slots are the
/// 1024-entry LTS budget — a removed policy must return its bucket,
/// or eventually-full maps make new limits silently unenforced).
/// The group bucket maps (group_bucket_dl/ul) joined the reclaim
/// family in NIGHT-lts-7: the dead-group sweep deletes a group's
/// shared slots when the LAST policy referencing it is gone (the
/// improve-10 "no single removal may decide" rule now decides at
/// the last reference — 256 slots, one fresh quasi-random group id
/// per group-lane invocation, previously never reclaimed).
pub const PIN_MAP_POLICY_DL: &str = "/sys/fs/bpf/zelynic/cgroup_policy_dl";
pub const PIN_MAP_POLICY_UL: &str = "/sys/fs/bpf/zelynic/cgroup_policy_ul";
pub const PIN_MAP_BUCKET_DL: &str = "/sys/fs/bpf/zelynic/cgroup_bucket_dl";
pub const PIN_MAP_BUCKET_UL: &str = "/sys/fs/bpf/zelynic/cgroup_bucket_ul";
pub const PIN_MAP_GROUP_BUCKET_DL: &str = "/sys/fs/bpf/zelynic/group_bucket_dl";
pub const PIN_MAP_GROUP_BUCKET_UL: &str = "/sys/fs/bpf/zelynic/group_bucket_ul";
pub const PIN_MAP_WATCHDOG: &str = "/sys/fs/bpf/zelynic/watchdog_deadline";
pub const PIN_MAP_STATS: &str = "/sys/fs/bpf/zelynic/cgroup_limiter_stats";
pub const PIN_MAP_SCHEMA_VERSION: &str = "/sys/fs/bpf/zelynic/schema_version";

// The time-window lane (night-during, schema v23 — the unified
// --during): the side map the apply family writes beside the policy
// legs (one row per resolved policy root, both hooks sharing it)
// and the one-entry Array carrying the wall-minus-mono offset the
// bridge stamps at every attach and apply-family mutation (the
// watchdog/schema_version userspace-written contract; the daily
// comparator reads it per packet through the margin law).
pub const PIN_MAP_POLICY_WINDOW: &str = "/sys/fs/bpf/zelynic/policy_window";
pub const PIN_MAP_WALL_CLOCK_OFFSET: &str = "/sys/fs/bpf/zelynic/wall_clock_offset";

// The time-series rings (NIGHT-upgrade-charger-core-3a): one pinned
// map per direction, keyed by the policy-root cgroup id — the status
// reader's absent-lens surface (rate_ring.rs documents why a missing
// pin is None, not an error).
pub const PIN_MAP_RATE_RING_DL: &str = "/sys/fs/bpf/zelynic/rate_ring_dl";
pub const PIN_MAP_RATE_RING_UL: &str = "/sys/fs/bpf/zelynic/rate_ring_ul";

/// The AMMSP leaf caches (NIGHT-private-research-2; direction-scoped
/// since NIGHT-hunt-Z1, schema v18): leaf cgroup id -> the packed u64
/// memo word (`(generation << 32) | root`, 0 root = resolved
/// unlimited; the packing is the pure core's, ebpf/src/ammsp.rs).
/// ONE MAP PER DIRECTION — a memo's root is only valid for the
/// direction whose walk produced it (the walk reads THAT direction's
/// policy map, and the single-direction applies legitimately leave
/// the two disagreeing; the shared v10..v17 map let one direction's
/// resolution poison the other's enforcement). LRU hash maps,
/// written by the datapath only, retired generationally by every
/// policy mutation (ammsp_memo_invalidate in limiter/ammsp.rs — the
/// ammsp_generation bump, NIGHT-perf-0, one shared counter retiring
/// both lanes at once). The static map names in
/// ebpf/src/ammsp_resolve.rs and these pin paths are the same
/// contract every other map here follows.
pub const PIN_MAP_AMMSP_CACHE_DL: &str = "/sys/fs/bpf/zelynic/ammsp_leaf_cache_dl";
pub const PIN_MAP_AMMSP_CACHE_UL: &str = "/sys/fs/bpf/zelynic/ammsp_leaf_cache_ul";

/// The AMMSP memo generation counter (NIGHT-perf-0): a one-entry
/// pinned array, read by the datapath before every resolution and
/// bumped by userspace after every policy mutation's writes land
/// (ammsp_memo_invalidate in limiter/ammsp.rs). The stamp every memo
/// carries is compared against this word per packet — the O(1)
/// replacement for the whole-map delete sweep, and the close for the
/// insert-after-flush race no sweep could cover. The static map
/// name in ebpf/src/bin/limiter.rs and this pin path are the same
/// contract every other map here follows.
pub const PIN_MAP_AMMSP_GEN: &str = "/sys/fs/bpf/zelynic/ammsp_generation";

/// Open a pinned hash map in read mode (NIGHT-optimized-2).
/// Single source of the pin-open + error-mapping dance the status
/// readers and the reclaim path share — the error names the pin
/// path, so a missing pin reads as a diagnosis, not a generic
/// failure. Owned `Map` because every caller converts it through
/// `BpfHashMap::try_from(&map)` immediately.
pub(crate) fn open_pinned_hash_map(pin_path: &str) -> Result<aya::maps::Map> {
    let map_data =
        MapData::from_pin(pin_path).map_err(|e| anyhow!("pinned map {pin_path}: {e}"))?;
    Ok(aya::maps::Map::HashMap(map_data))
}

/// Open a pinned LRU hash map in read mode — the LRU twin of
/// [`open_pinned_hash_map`] (the AMMSP leaf cache). Wrapped in the
/// matching enum variant so aya's map-type reporting stays honest;
/// every syscall op (get / insert / remove / keys iteration) the
/// flush and the status readers need works identically on LRU hash
/// maps, and `BpfHashMap::try_from` accepts both variants.
pub(crate) fn open_pinned_lru_hash_map(pin_path: &str) -> Result<aya::maps::Map> {
    let map_data =
        MapData::from_pin(pin_path).map_err(|e| anyhow!("pinned map {pin_path}: {e}"))?;
    Ok(aya::maps::Map::LruHashMap(map_data))
}

/// Open a pinned array map in read mode — the Array twin of
/// [`open_pinned_hash_map`] (watchdog + schema-version readers).
pub(crate) fn open_pinned_array_map(pin_path: &str) -> Result<aya::maps::Map> {
    let map_data =
        MapData::from_pin(pin_path).map_err(|e| anyhow!("pinned map {pin_path}: {e}"))?;
    Ok(aya::maps::Map::Array(map_data))
}

/// Read the pinned schema version. Returns None if pin doesn't exist or read fails.
pub fn read_pinned_schema_version() -> Option<u32> {
    let map_obj = open_pinned_array_map(PIN_MAP_SCHEMA_VERSION).ok()?;
    let map: BpfArray<_, u32> = BpfArray::try_from(&map_obj).ok()?;
    let key: u32 = 0;
    map.get(&key, 0).ok()
}

/// Check if the pin directory has any files.
pub fn pin_dir_has_files() -> bool {
    let pin_dir = PathBuf::from(PIN_DIR);
    pin_dir.exists()
        && std::fs::read_dir(&pin_dir)
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
}

/// Remove ALL pin files + directory. Full cleanup.
///
/// NIGHT-master-4 (the honesty audit): the removal is VERIFIED, not
/// assumed. The former implementation discarded every `remove_file`
/// result and returned `Ok(())` unconditionally — so `u --all`
/// could print "All limits removed, no residue." and `recover`
/// "Result: recovered" while pin files were still on disk (a busy
/// pin, a read-only bpffs mount, or a foreign nested entry). The
/// verdict now comes from the filesystem's after-state: the function
/// returns the count of entries it actually unlinked, and any entry
/// that survives the removal pass is an error naming the leftover
/// count — the same never-fabricate contract the policy-map readers
/// hold (`unpin_if_no_policies`, NIGHT-hunt-20).
///
/// A missing directory is `Ok(0)` (idempotent — every teardown path
/// must be safe to re-run, which `recover` after `u --all`
/// exercises for real).
///
/// Returns the number of pin entries removed.
pub fn unpin_all() -> Result<usize> {
    unpin_dir(&PathBuf::from(PIN_DIR))
}

/// The verified removal core — split from [`unpin_all`] so the
/// unit pins can drive the full remove/verify/fail cycle against a
/// temp directory (the production path only ever runs as root
/// against `/sys/fs/bpf/zelynic`).
///
/// Discipline: unlink every entry (an entry that raced away mid-pass
/// counts as neither removed nor leftover), re-read the directory,
/// and require it EMPTY — then remove the directory itself, whose
/// failure is also residue. `remove_file` on a nested directory
/// fails `EISDIR` and the verification pass catches the survivor,
/// so a foreign nested entry cannot pass silently either.
pub(crate) fn unpin_dir(dir: &std::path::Path) -> Result<usize> {
    // Enumerate first: a missing directory is a clean Ok(0), an
    // unreadable one is an honest error (we cannot even attempt the
    // cleanup we are about to claim).
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(anyhow!("pin dir {}: {e}", dir.display()));
        }
    };

    let mut removed = 0usize;
    for entry in entries.flatten() {
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed += 1,
            // Raced away mid-pass (a concurrent teardown won): not
            // removed, not leftover — the verification pass below is
            // the arbiter.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            // A stubborn entry (busy pin, read-only fs, EISDIR on a
            // nested dir): keep sweeping the rest, report after —
            // a partial removal followed by an honest error beats a
            // half-cleaned directory reported as clean.
            Err(_) => {}
        }
    }

    // The verification pass: the directory must be EMPTY. This is
    // the verdict's source of truth, not the unlink return values.
    match std::fs::read_dir(dir) {
        Ok(mut survivors) => {
            if survivors.next().is_some() {
                let leftover = 1 + survivors.count();
                return Err(anyhow!(
                    "pin dir {} still holds {leftover} {} after cleanup — \
                     a pin is busy or the bpf fs refused the removal; \
                     the state is NOT clean",
                    dir.display(),
                    if leftover == 1 { "entry" } else { "entries" }
                ));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
        Err(e) => {
            return Err(anyhow!(
                "pin dir {} could not be re-read for verification: {e}",
                dir.display()
            ));
        }
    }

    // Empty and verified: drop the directory itself. Its failure is
    // residue too (a non-empty race would have been caught above; a
    // refused rmdir is an honest error).
    std::fs::remove_dir(dir)
        .map_err(|e| anyhow!("pin dir {} could not be removed: {e}", dir.display()))?;
    Ok(removed)
}

// NIGHT-master-4: the verified-unpin pins live under the single
// test/ tree (cosmostrix Pattern C), #[path]-wired exactly like the
// lock and limiter pins.
#[cfg(test)]
#[path = "../../test/ebpf/pin_tests.rs"]
mod tests;
