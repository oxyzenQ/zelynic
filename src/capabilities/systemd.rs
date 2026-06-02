// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use std::path::Path;

use super::detect::command_version;
use super::types::{CapabilityStatus, CgroupMode, SystemInfo, ToolInfo};

pub(super) fn detect_systemd() -> ToolInfo {
    let mut info = command_version("systemctl", &["--version"]);
    if !info.available && Path::new("/run/systemd/system").exists() {
        info.available = true;
        info.version = "available".to_string();
    }
    info
}

pub(super) fn transient_scope_wrapper_readiness(system: &SystemInfo) -> CapabilityStatus {
    if system.systemd.available
        && system.systemd_run.available
        && matches!(system.cgroup_mode, CgroupMode::PureV2 | CgroupMode::Hybrid)
    {
        CapabilityStatus::Likely
    } else if !system.systemd.available || !system.systemd_run.available {
        CapabilityStatus::No
    } else {
        CapabilityStatus::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(available: bool) -> ToolInfo {
        ToolInfo {
            available,
            version: if available { "available" } else { "not found" }.to_string(),
        }
    }

    fn system(cgroup_mode: CgroupMode, systemd: bool) -> SystemInfo {
        SystemInfo {
            kernel: "6.18.33-1-cachyos-lts".to_string(),
            cgroup_mode,
            cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
            cgroup2_mount_flags: vec!["rw".to_string(), "nosuid".to_string()],
            nftables: tool(true),
            tc: tool(true),
            systemd: tool(systemd),
            systemd_run: tool(systemd),
        }
    }

    #[test]
    fn transient_scope_wrapper_readiness_requires_systemd_run_and_cgroup_v2() {
        let ready = system(CgroupMode::PureV2, true);
        assert_eq!(
            transient_scope_wrapper_readiness(&ready),
            CapabilityStatus::Likely
        );

        let no_systemd = system(CgroupMode::PureV2, false);
        assert_eq!(
            transient_scope_wrapper_readiness(&no_systemd),
            CapabilityStatus::No
        );

        let legacy = system(CgroupMode::V1Legacy, true);
        assert_eq!(
            transient_scope_wrapper_readiness(&legacy),
            CapabilityStatus::Unknown
        );
    }
}
