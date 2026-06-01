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
    /// Path to the per-target cgroup (e.g., `/sys/fs/cgroup/oxy/target_helium`).
    /// New for per-target isolation; None for legacy state files.
    #[serde(default)]
    pub target_cgroup_path: Option<String>,
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
