// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CapabilityStatus {
    Yes,
    Likely,
    Unknown,
    RequiresRoot,
    No,
}

impl fmt::Display for CapabilityStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yes => f.write_str("yes"),
            Self::Likely => f.write_str("likely"),
            Self::Unknown => f.write_str("unknown"),
            Self::RequiresRoot => f.write_str("requires root"),
            Self::No => f.write_str("no"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CgroupMode {
    PureV2,
    Hybrid,
    V1Legacy,
    Unknown,
}

impl fmt::Display for CgroupMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PureV2 => f.write_str("pure cgroup v2"),
            Self::Hybrid => f.write_str("hybrid"),
            Self::V1Legacy => f.write_str("cgroup v1/legacy"),
            Self::Unknown => f.write_str("unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendCandidateStatus {
    Supported,
    Partial,
    Unavailable,
    Future,
}

impl fmt::Display for BackendCandidateStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Supported => f.write_str("supported"),
            Self::Partial => f.write_str("partial"),
            Self::Unavailable => f.write_str("unavailable"),
            Self::Future => f.write_str("future"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ToolInfo {
    pub available: bool,
    pub version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemInfo {
    pub kernel: String,
    pub cgroup_mode: CgroupMode,
    pub cgroup2_mount_path: Option<String>,
    pub cgroup2_mount_flags: Vec<String>,
    pub nftables: ToolInfo,
    pub tc: ToolInfo,
    pub systemd: ToolInfo,
    pub systemd_run: ToolInfo,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityMatrix {
    pub cgroup_v2: CapabilityStatus,
    pub nft_socket_cgroupv2: CapabilityStatus,
    pub tc_htb: CapabilityStatus,
    pub fw_filter: CapabilityStatus,
    pub conntrack_mark: CapabilityStatus,
    pub bpf_fs_mounted: CapabilityStatus,
    pub ebpf: CapabilityStatus,
    pub transient_scope_wrapper: CapabilityStatus,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendCandidate {
    pub name: String,
    pub status: BackendCandidateStatus,
    pub confidence: u8,
    pub missing_requirements: Vec<String>,
    pub risk_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendDoctorReport {
    pub system: SystemInfo,
    pub capabilities: CapabilityMatrix,
    pub backend_candidates: Vec<BackendCandidate>,
    pub recommended_backend: Option<String>,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_mode_labels_are_stable() {
        assert_eq!(CgroupMode::PureV2.to_string(), "pure cgroup v2");
        assert_eq!(CgroupMode::Hybrid.to_string(), "hybrid");
        assert_eq!(CgroupMode::V1Legacy.to_string(), "cgroup v1/legacy");
        assert_eq!(CgroupMode::Unknown.to_string(), "unknown");
    }

    #[test]
    fn capability_status_labels_are_stable() {
        assert_eq!(CapabilityStatus::Yes.to_string(), "yes");
        assert_eq!(CapabilityStatus::Likely.to_string(), "likely");
        assert_eq!(CapabilityStatus::Unknown.to_string(), "unknown");
        assert_eq!(CapabilityStatus::RequiresRoot.to_string(), "requires root");
        assert_eq!(CapabilityStatus::No.to_string(), "no");
    }
}
