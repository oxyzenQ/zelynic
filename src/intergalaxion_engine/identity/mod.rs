// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Process and cgroup identity model for the Intergalaxion Engine.
//!
//! In I-0 this module provides only compile-safe identity structs.
//! No live PID inspection or cgroup mutation is performed.

/// Identity anchor for a process or cgroup.
///
/// In the stable v3.1.0 line, identity is used only for ledger
/// attribution. In the intergalaxion branch, this struct becomes the
/// anchor for future eBPF-based per-process telemetry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcessIdentity {
    /// Process ID (PID). `None` when operating in cgroup-only mode.
    pub pid: Option<u32>,
    /// Cgroup path, used as an identity anchor when PID is unavailable.
    pub cgroup_path: Option<String>,
    /// Human-readable label assigned by the user or auto-detected.
    pub label: Option<String>,
}

impl ProcessIdentity {
    /// Create a new identity with a PID.
    pub fn with_pid(pid: u32) -> Self {
        Self {
            pid: Some(pid),
            ..Default::default()
        }
    }

    /// Create a new identity with a cgroup path anchor.
    pub fn with_cgroup(path: String) -> Self {
        Self {
            cgroup_path: Some(path),
            ..Default::default()
        }
    }
}
