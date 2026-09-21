// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Identity mapping — resolve cgroup IDs to process names and users.
//!
//! Walks /proc and /sys/fs/cgroup to build a reverse map:
//! cgroup_id (u32) → ProcessIdentity.
//!
//! Refreshed periodically (default 10s TTL) to handle process churn without
//! paying the /proc walk cost on every observer poll.
//!
//! # Dragon Architecture — Layer 2: Identity Resolution
//!
//! BPF programs return raw cgroup IDs. To make output human-readable, we
//! reverse-resolve: walk /proc to find which PID lives in which cgroup, then
//! look up the cgroup's path and the process's name/uid.
//!
//! The representative name per cgroup is chosen by MAJORITY VOTE
//! (NIGHT-hunt-10): the comm hosting the most processes names the
//! cgroup. The previous first-pid-wins rule let a single
//! chrome_crashpad process label the cgroup whose other ~30 processes
//! were all brave — status then showed the browser's real traffic
//! carrier as "cg:18526 (chrome_crashpad)", and removing that
//! "helper" silently removed brave's enforcement.
//!
//! This layer is **userspace-only** and **best-effort**: if resolution fails,
//! we fall back to raw `cg:{id}` labels. The BPF program is unaffected.

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

mod tally;

// NIGHT-cybersecurity-2: sanitize_comm moved up to the always-compiled
// output layer (src/output/sanitize.rs) so the update check — which
// runs in BOTH feature graphs — reuses the one canonical terminal
// sanitizer instead of a copy.
use crate::output::sanitize_comm;
use tally::{pick_representative, CommStat};

/// Default refresh interval: rebuild the identity map every 10 seconds.
const DEFAULT_REFRESH_TTL_SECS: u64 = 10;

/// Process identity information.
#[derive(Debug, Clone, Default)]
pub struct ProcessIdentity {
    pub cgroup_id: u32,
    pub uid: u32,
    pub comm: String,
}

/// Cached identity mapping: cgroup_id (u32) → ProcessIdentity.
///
/// Refreshed periodically to handle process churn. Build cost is O(nproc),
/// paid once per TTL window.
#[derive(Debug)]
pub struct IdentityMap {
    cache: HashMap<u32, ProcessIdentity>,
    last_refresh: Option<Instant>,
    refresh_ttl: Duration,
}

impl Default for IdentityMap {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityMap {
    /// Create new empty identity map with default 10s refresh TTL.
    pub fn new() -> Self {
        IdentityMap {
            cache: HashMap::new(),
            last_refresh: None,
            refresh_ttl: Duration::from_secs(DEFAULT_REFRESH_TTL_SECS),
        }
    }

    /// Create with custom refresh TTL (test seam for TTL logic).
    #[cfg(test)]
    pub fn with_ttl(ttl: Duration) -> Self {
        IdentityMap {
            cache: HashMap::new(),
            last_refresh: None,
            refresh_ttl: ttl,
        }
    }

    /// Test seam: insert a synthetic identity directly.
    ///
    /// Cross-module harnesses (the frame benchmark in `render.rs`)
    /// need realistic label sets without walking /proc. In-module tests
    /// touch `cache` directly; this seam offers the same power to
    /// sibling modules under cfg(test).
    #[cfg(test)]
    pub fn insert(&mut self, id: ProcessIdentity) {
        self.cache.insert(id.cgroup_id, id);
    }

    /// Force a full refresh: walk /proc to rebuild the reverse map.
    ///
    /// For each live PID:
    /// 1. Read `/proc/<pid>/cgroup` → cgroup path (v2 format: `0::/path`)
    /// 2. `stat()` `/sys/fs/cgroup{path}` → the kernfs inode IS the
    ///    64-bit cgroup ID
    /// 3. Truncate to u32 to match BPF map key
    /// 4. Read `/proc/<pid>/comm` → process name (tallied per cgroup)
    /// 5. Read `/proc/<pid>/status` → uid
    ///
    /// The cgroup's representative identity is the MAJORITY comm
    /// (NIGHT-hunt-10, see [`pick_representative`]) — first-pid-wins
    /// let one chrome_crashpad speak for a cgroup of 30 brave
    /// processes. Unreadable comms never outvote real ones; a cgroup
    /// whose every comm read failed keeps an empty-comm identity (the
    /// `cg:{id}` label fallback) so crash-recovery still sees it alive.
    ///
    /// Returns the number of unique cgroups discovered.
    pub fn refresh(&mut self) -> usize {
        self.cache.clear();

        // cgroup_id → comm tally. Entries exist for every resolvable
        // cgroup even when no comm was readable (empty map), so the
        // alive-cgroup set stays complete for recover().
        let mut per_cgroup: HashMap<u32, HashMap<String, CommStat>> = HashMap::new();

        let proc_entries = match fs::read_dir("/proc") {
            Ok(e) => e,
            Err(_) => {
                self.last_refresh = Some(Instant::now());
                return 0;
            }
        };

        for entry in proc_entries.flatten() {
            let name = entry.file_name();
            let name_str = match name.to_str() {
                Some(s) => s,
                None => continue,
            };

            // Only numeric directories are PIDs.
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Shared /proc boundary helpers (NIGHT-optimized-1): the
            // pid-to-cgroup resolution and the sanitized comm read now
            // live once — this walk, the connection walk, and the
            // resolve_target match walk all call the same functions, so
            // boundary fixes (like the cybersecurity-1 sanitize) apply
            // in one place, not three.
            let Some(cgroup_id) = pid_cgroup_id(pid) else {
                continue;
            };

            // Read /proc/<pid>/comm for the tally. Sanitized at the
            // boundary (NIGHT-cybersecurity-1): the label is attacker
            // controllable via prctl, and it flows to every display
            // surface — list-apps, observe/top, detail lines — as well
            // as the majority-vote tally below.
            let comm = pid_comm(pid).unwrap_or_default();

            // Unreadable comm: count the cgroup as alive but never let a
            // blank name outvote real ones.
            let comm_stats = per_cgroup.entry(cgroup_id).or_default();
            if comm.is_empty() {
                continue;
            }

            // Read /proc/<pid>/status for uid (first field after "Uid:").
            let uid = fs::read_to_string(format!("/proc/{pid}/status"))
                .ok()
                .and_then(|s| {
                    s.lines()
                        .find(|l| l.starts_with("Uid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|u| u.parse().ok())
                })
                .unwrap_or(0);

            match comm_stats.get_mut(&comm) {
                Some(stat) => {
                    stat.count += 1;
                    if pid < stat.min_pid {
                        stat.min_pid = pid;
                        stat.min_pid_uid = uid;
                    }
                }
                None => {
                    comm_stats.insert(
                        comm,
                        CommStat {
                            count: 1,
                            min_pid: pid,
                            min_pid_uid: uid,
                        },
                    );
                }
            }
        }

        for (cgroup_id, comm_stats) in per_cgroup {
            let (comm, uid) = pick_representative(&comm_stats).unwrap_or_default();
            self.cache.insert(
                cgroup_id,
                ProcessIdentity {
                    cgroup_id,
                    uid,
                    comm,
                },
            );
        }

        self.last_refresh = Some(Instant::now());
        self.cache.len()
    }

    /// Refresh if the TTL has elapsed. Returns true if a refresh happened.
    pub fn maybe_refresh(&mut self) -> bool {
        let needs_refresh = match self.last_refresh {
            None => true,
            Some(last) => last.elapsed() >= self.refresh_ttl,
        };

        if needs_refresh {
            self.refresh();
            true
        } else {
            false
        }
    }

    /// Look up identity for a cgroup ID. Returns None if not in cache.
    pub fn get(&self, cgroup_id: u32) -> Option<&ProcessIdentity> {
        self.cache.get(&cgroup_id)
    }

    /// Get a short display label for a cgroup ID.
    ///
    /// Format: `cg:73386 (firefox)` if resolved, else `cg:73386`.
    pub fn label(&self, cgroup_id: u32) -> String {
        match self.get(cgroup_id) {
            Some(id) if !id.comm.is_empty() => {
                format!("cg:{cgroup_id} ({})", id.comm)
            }
            _ => format!("cg:{cgroup_id}"),
        }
    }

    /// Number of cached identities.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Is the cache empty?
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// All known identities (unspecified order).
    pub fn all(&self) -> Vec<&ProcessIdentity> {
        self.cache.values().collect()
    }
}

/// Resolve the cgroup ID (u32, BPF map key width) a PID lives in
/// (NIGHT-optimized-1: the ONE canonical pid-to-cgroup boundary —
/// the identity walk, the connection walk, and the resolve_target
/// match walk all route through here; the only public door to the
/// path-based resolver below, so no caller can skip the u32
/// truncation or the v2-format parsing this function owns).
///
/// Reads `/proc/<pid>/cgroup`, parses the cgroup v2 `0::/path`
/// single-line format, and resolves the ID via
/// [`cgroup_id_from_path`]. Truncates to u32 to match the
/// BPF map key type (cgroup IDs are well under 2^32 in practice —
/// see the SAFETY_ANALYSIS audit note on ID width).
pub fn pid_cgroup_id(pid: u32) -> Option<u32> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = content.lines().next()?.split("::").nth(1)?.trim();
    if path.is_empty() {
        return None;
    }
    let id64 = cgroup_id_from_path(&format!("/sys/fs/cgroup{path}"))?;
    Some(id64 as u32)
}

/// Read and sanitize a PID's comm (NIGHT-optimized-1: the ONE
/// canonical comm boundary; sanitize semantics per
/// [`sanitize_comm`]). Callers own the fallback: the identity tally
/// treats a failed read as an empty label, the connection walk shows
/// `pid {n}`, and the match walk lowercases for case-insensitive
/// comparison.
pub fn pid_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| sanitize_comm(s.trim()))
}

/// Resolve a 64-bit cgroup ID from a cgroup v2 path.
///
/// The kernfs inode number IS the cgroup ID: `bpf_skb_cgroup_id()`
/// returns `cgrp->kn->id`, and kernfs publishes that same node id as
/// the directory's `st_ino` — `stat(2)` is the whole resolution, and it
/// is the numbering every kernel in the verified cross-distro matrix
/// ran on. (NIGHT-hunt-31: the "cgroup.id file" this resolver once
/// tried first never existed in any mainline kernel — the stat path
/// below was the one that always worked, so the phantom file read is
/// gone.)
fn cgroup_id_from_path(path: &str) -> Option<u64> {
    fs::metadata(path).ok().map(|meta| meta.ino())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_identity_map_new_is_empty() {
        let map = IdentityMap::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn test_label_for_unknown_cgroup() {
        let map = IdentityMap::new();
        // No refresh — cache is empty.
        assert_eq!(map.label(99999), "cg:99999");
    }

    #[test]
    fn test_get_returns_none_when_empty() {
        let map = IdentityMap::new();
        assert!(map.get(1).is_none());
    }

    #[test]
    fn test_with_ttl_constructor() {
        let map = IdentityMap::with_ttl(Duration::from_millis(1));
        assert!(map.is_empty());
        assert_eq!(map.refresh_ttl, Duration::from_millis(1));
    }

    #[test]
    fn test_maybe_refresh_when_no_last_refresh() {
        // When last_refresh is None, maybe_refresh should trigger.
        // We can't easily test the actual refresh without /proc access,
        // but we can verify the contract: maybe_refresh returns true and
        // sets last_refresh.
        let mut map = IdentityMap::with_ttl(Duration::from_secs(60));
        let refreshed = map.maybe_refresh();
        assert!(refreshed);
        assert!(map.last_refresh.is_some());
    }

    #[test]
    fn test_maybe_refresh_skips_when_within_ttl() {
        let mut map = IdentityMap::with_ttl(Duration::from_secs(60));
        // Prime the cache.
        let _ = map.maybe_refresh();
        let first_refresh = map.last_refresh.unwrap();

        // Second call should NOT refresh (within TTL).
        let refreshed = map.maybe_refresh();
        assert!(!refreshed);
        assert_eq!(map.last_refresh.unwrap(), first_refresh);
    }

    #[test]
    fn test_label_with_manually_inserted_identity() {
        // Test the label() formatting directly by inserting a fake entry.
        let mut map = IdentityMap::new();
        map.cache.insert(
            12345,
            ProcessIdentity {
                cgroup_id: 12345,
                uid: 1000,
                comm: "firefox".to_string(),
            },
        );

        assert_eq!(map.label(12345), "cg:12345 (firefox)");
    }

    #[test]
    fn test_label_with_empty_comm_falls_back() {
        let mut map = IdentityMap::new();
        map.cache.insert(
            12345,
            ProcessIdentity {
                cgroup_id: 12345,
                uid: 1000,
                comm: String::new(),
            },
        );

        // Empty comm → fall back to raw label.
        assert_eq!(map.label(12345), "cg:12345");
    }

    #[test]
    fn test_refresh_runs_without_panic() {
        // Refresh should always succeed (even if /proc has 0 entries or
        // permissions block some reads). Must not panic.
        let mut map = IdentityMap::new();
        let _count = map.refresh();
        // last_refresh must be set after a refresh.
        assert!(map.last_refresh.is_some());
    }

    #[test]
    fn test_all_returns_cached_values() {
        let mut map = IdentityMap::new();
        map.cache.insert(
            1,
            ProcessIdentity {
                cgroup_id: 1,
                uid: 0,
                comm: "init".to_string(),
            },
        );
        map.cache.insert(
            2,
            ProcessIdentity {
                cgroup_id: 2,
                uid: 1000,
                comm: "shell".to_string(),
            },
        );

        let all = map.all();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn test_cgroup_id_from_path_is_the_inode() {
        // NIGHT-hunt-31: the resolver is stat(2), nothing else.
        let dir = std::env::temp_dir().join("zelynic-h31-inode");
        fs::create_dir_all(&dir).unwrap();
        let ino = fs::metadata(&dir).unwrap().ino();
        assert_eq!(cgroup_id_from_path(dir.to_str().unwrap()), Some(ino));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cgroup_id_from_path_ignores_decoy_cgroup_id_file() {
        // NIGHT-hunt-31 pin: a decoy cgroup.id file must never override
        // the kernel's numbering — the file does not exist in mainline.
        let dir = std::env::temp_dir().join("zelynic-h31-decoy");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("cgroup.id"), "999999999\n").unwrap();
        let ino = fs::metadata(&dir).unwrap().ino();
        assert_eq!(cgroup_id_from_path(dir.to_str().unwrap()), Some(ino));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_cgroup_id_from_path_missing_dir_is_none() {
        assert_eq!(cgroup_id_from_path("/nonexistent-zelynic-h31"), None);
    }
}
