// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Identity mapping — resolve cgroup IDs to process names and users.
//!
//! Reads /proc and /sys/fs/cgroup to map BPF cgroup IDs to
//! human-readable process information.

use std::collections::HashMap;
use std::fs;

/// Cached identity mapping: cgroup_id → ProcessIdentity.
#[derive(Debug, Clone, Default)]
pub struct IdentityMap {
    cache: HashMap<u32, ProcessIdentity>,
}

/// Process identity information.
#[derive(Debug, Clone, Default)]
pub struct ProcessIdentity {
    pub cgroup_id: u32,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub cgroup_path: Option<String>,
}

impl IdentityMap {
    /// Create new empty identity map.
    pub fn new() -> Self {
        IdentityMap {
            cache: HashMap::new(),
        }
    }

    /// Look up or create identity for a cgroup ID.
    /// Falls back to the provided pid/comm if lookup fails.
    pub fn resolve(
        &mut self,
        cgroup_id: u32,
        fallback_pid: u32,
        fallback_comm: &str,
    ) -> &ProcessIdentity {
        self.cache
            .entry(cgroup_id)
            .or_insert_with(|| ProcessIdentity {
                cgroup_id,
                pid: fallback_pid,
                uid: 0,
                comm: fallback_comm.to_string(),
                cgroup_path: resolve_cgroup_path(cgroup_id),
            })
    }

    /// Get all known identities.
    pub fn all(&self) -> Vec<&ProcessIdentity> {
        self.cache.values().collect()
    }

    /// Clear cache.
    pub fn clear(&mut self) {
        self.cache.clear();
    }
}

/// Try to resolve cgroup path from cgroup ID.
/// Reads /sys/fs/cgroup and looks for matching cgroup.id file.
fn resolve_cgroup_path(cgroup_id: u32) -> Option<String> {
    // Walk /sys/fs/cgroup looking for cgroup.id files
    let root = "/sys/fs/cgroup";
    walk_cgroup_dir(root, cgroup_id)
}

fn walk_cgroup_dir(dir: &str, target_id: u32) -> Option<String> {
    let entries = fs::read_dir(dir).ok()?;

    for entry in entries.flatten() {
        let path = entry.path();

        // Check cgroup.id file
        let id_file = path.join("cgroup.id");
        if id_file.exists() {
            if let Ok(id_str) = fs::read_to_string(&id_file) {
                if let Ok(id) = id_str.trim().parse::<u32>() {
                    if id == target_id {
                        return Some(path.to_string_lossy().to_string());
                    }
                }
            }
        }

        // Recurse into subdirectories
        if path.is_dir() {
            if let Some(found) = walk_cgroup_dir(&path.to_string_lossy(), target_id) {
                return Some(found);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_map_new() {
        let map = IdentityMap::new();
        assert!(map.cache.is_empty());
    }

    #[test]
    fn test_identity_map_resolve() {
        let mut map = IdentityMap::new();
        let id = map.resolve(12345, 1000, "brave");
        assert_eq!(id.cgroup_id, 12345);
        assert_eq!(id.pid, 1000);
        assert_eq!(id.comm, "brave");
    }

    #[test]
    fn test_identity_map_cache() {
        let mut map = IdentityMap::new();
        map.resolve(12345, 1000, "brave");
        map.resolve(12345, 2000, "firefox"); // should return cached
        let id = map.resolve(12345, 9999, "test");
        assert_eq!(id.pid, 1000); // cached value
        assert_eq!(id.comm, "brave"); // cached value
    }

    #[test]
    fn test_identity_map_clear() {
        let mut map = IdentityMap::new();
        map.resolve(12345, 1000, "brave");
        assert!(!map.cache.is_empty());
        map.clear();
        assert!(map.cache.is_empty());
    }
}
