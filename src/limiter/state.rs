// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

use super::{STATE_DIR, STATE_FILE};

// ---------------------------------------------------------------------------
// State persistence
// ---------------------------------------------------------------------------

/// Persistent record of an active bandwidth limit for a process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitRecord {
    pub target: String,
    pub pid: u32,
    pub download_bytes_per_sec: Option<u64>,
    pub upload_bytes_per_sec: Option<u64>,
    pub download_display: Option<String>,
    pub upload_display: Option<String>,
    pub interface: String,
    pub class_id: u32,
    pub applied_at: String,
    /// Handle for the ingress (download) tc fw filter.
    /// No longer used (download limiting is handled by nftables input hook).
    /// Kept for state file backward compatibility; always None for new limits.
    #[serde(default)]
    pub ingress_handle: Option<u32>,
    /// Cgroup v2 ID for the per-target cgroup.  This is the kernfs inode
    /// number of the cgroup directory (64-bit on 64-bit kernels).
    /// Used by nftables `socket cgroupv2 level <depth>` (output hook,
    /// egress marking) and `ct mark` (input hook, download policing).
    /// NOTE: `meta cgroup` is NOT used — it only returns cgroup v1
    /// `net_cls.classid`.  `socket cgroupv2` was added in kernel 5.7.
    #[serde(default)]
    pub cgroup_id: Option<u64>,
    /// Path to the per-target cgroup (e.g., `/sys/fs/cgroup/zelynic/target_helium`).
    /// New for per-target isolation; None for legacy state files.
    #[serde(default)]
    pub target_cgroup_path: Option<String>,
    /// Original cgroup v2 path recorded before strict moved the PID.
    /// Used by unstrict to restore the process safely when the destination
    /// still exists. None for older state files and cgroup v1 fallback state.
    #[serde(default)]
    pub original_cgroup_path: Option<String>,
    /// UID of the target process.  Kept for backward compatibility with
    /// legacy state files; always None for new limits (meta skuid fallback
    /// was removed to prevent per-UID cross-process leaks).
    #[serde(default)]
    pub uid: Option<u32>,
}

/// Full state file structure containing all active limits.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ZelynicState {
    pub limits: Vec<LimitRecord>,
}

impl ZelynicState {
    pub fn load() -> Result<Self> {
        if !Path::new(STATE_FILE).exists() {
            return Ok(Self::default());
        }

        let content =
            fs::read_to_string(STATE_FILE).context("failed to read zelynic state file")?;
        let state: ZelynicState =
            serde_json::from_str(&content).context("failed to parse zelynic state file")?;
        Ok(state)
    }

    pub fn save(&self) -> Result<()> {
        fs::create_dir_all(STATE_DIR).context("failed to create zelynic state directory")?;

        let content =
            serde_json::to_string_pretty(self).context("failed to serialize zelynic state")?;
        fs::write(STATE_FILE, content).context("failed to write zelynic state file")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_file_path_uses_zelynic_namespace() {
        assert_eq!(super::super::STATE_FILE, "/run/zelynic/state.json");
    }

    #[test]
    fn old_state_without_original_cgroup_path_still_parses() {
        let json = r#"
        {
          "limits": [
            {
              "target": "brave",
              "pid": 1234,
              "download_bytes_per_sec": 62500,
              "upload_bytes_per_sec": 62500,
              "download_display": "500 Kbit/s",
              "upload_display": "500 Kbit/s",
              "interface": "wlp1s0",
              "class_id": 100,
              "applied_at": "test",
              "ingress_handle": null,
              "cgroup_id": 42,
              "target_cgroup_path": "/sys/fs/cgroup/zelynic/target_brave",
              "uid": null
            }
          ]
        }
        "#;

        let state: ZelynicState = serde_json::from_str(json).unwrap();

        assert_eq!(state.limits.len(), 1);
        assert_eq!(state.limits[0].original_cgroup_path, None);
    }

    #[test]
    fn new_state_with_original_cgroup_path_parses() {
        let json = r#"
        {
          "limits": [
            {
              "target": "brave",
              "pid": 1234,
              "download_bytes_per_sec": 62500,
              "upload_bytes_per_sec": 62500,
              "download_display": "500 Kbit/s",
              "upload_display": "500 Kbit/s",
              "interface": "wlp1s0",
              "class_id": 100,
              "applied_at": "test",
              "ingress_handle": null,
              "cgroup_id": 42,
              "target_cgroup_path": "/sys/fs/cgroup/zelynic/target_brave",
              "original_cgroup_path": "/sys/fs/cgroup/user.slice/user-1000.slice/session.scope",
              "uid": null
            }
          ]
        }
        "#;

        let state: ZelynicState = serde_json::from_str(json).unwrap();

        assert_eq!(
            state.limits[0].original_cgroup_path.as_deref(),
            Some("/sys/fs/cgroup/user.slice/user-1000.slice/session.scope")
        );
    }
}
