// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::ebpf;

use super::systemd::{detect_systemd, transient_scope_wrapper_readiness};
use super::types::{CapabilityMatrix, CapabilityStatus, CgroupMode, SystemInfo, ToolInfo};

pub(super) fn detect_system_info() -> SystemInfo {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| command_version("uname", &["-r"]).version);
    let mount = cgroup2_mount();
    let cgroup_mode = detect_cgroup_mode(mount.as_ref().map(|m| m.0.as_str()));

    SystemInfo {
        kernel,
        cgroup_mode,
        cgroup2_mount_path: mount.as_ref().map(|m| m.0.clone()),
        cgroup2_mount_flags: mount.map(|m| m.1).unwrap_or_default(),
        nftables: command_version("nft", &["--version"]),
        tc: command_version("tc", &["-V"]),
        systemd: detect_systemd(),
        systemd_run: command_version("systemd-run", &["--version"]),
    }
}

pub(super) fn detect_capabilities(system: &SystemInfo) -> CapabilityMatrix {
    let ebpf_support = ebpf::check_ebpf_support();
    let kernel_supports_socket_cgroupv2 = kernel_meets(&system.kernel, 5, 7);

    CapabilityMatrix {
        cgroup_v2: match system.cgroup_mode {
            CgroupMode::PureV2 | CgroupMode::Hybrid => CapabilityStatus::Yes,
            CgroupMode::V1Legacy => CapabilityStatus::No,
            CgroupMode::Unknown => CapabilityStatus::Unknown,
        },
        nft_socket_cgroupv2: if system.nftables.available
            && kernel_supports_socket_cgroupv2
            && matches!(system.cgroup_mode, CgroupMode::PureV2 | CgroupMode::Hybrid)
        {
            CapabilityStatus::Likely
        } else if !system.nftables.available {
            CapabilityStatus::No
        } else {
            CapabilityStatus::Unknown
        },
        tc_htb: if system.tc.available {
            CapabilityStatus::Likely
        } else {
            CapabilityStatus::No
        },
        fw_filter: if system.tc.available {
            CapabilityStatus::Likely
        } else {
            CapabilityStatus::No
        },
        conntrack_mark: detect_conntrack_mark(),
        bpf_fs_mounted: if is_bpf_fs_mounted() {
            CapabilityStatus::Yes
        } else {
            CapabilityStatus::No
        },
        ebpf: if ebpf_support.supported {
            CapabilityStatus::Yes
        } else if ebpf_support.kernel_ok && ebpf_support.bpf_fs_ok && ebpf_support.config_ok {
            CapabilityStatus::RequiresRoot
        } else {
            CapabilityStatus::No
        },
        transient_scope_wrapper: transient_scope_wrapper_readiness(system),
    }
}

pub(super) fn command_version(program: &str, args: &[&str]) -> ToolInfo {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let first_line = stdout
                .lines()
                .chain(stderr.lines())
                .find(|line| !line.trim().is_empty())
                .map(str::trim)
                .unwrap_or("available");

            ToolInfo {
                available: true,
                version: first_line.to_string(),
            }
        }
        Ok(_) | Err(_) => ToolInfo {
            available: false,
            version: "not found".to_string(),
        },
    }
}

fn cgroup2_mount() -> Option<(String, Vec<String>)> {
    let mountinfo = fs::read_to_string("/proc/self/mountinfo").ok()?;
    for line in mountinfo.lines() {
        let separator = line.find(" - ")?;
        let before = &line[..separator];
        let after = &line[separator + 3..];
        let mut after_fields = after.split_whitespace();
        if after_fields.next() != Some("cgroup2") {
            continue;
        }

        let before_fields: Vec<&str> = before.split_whitespace().collect();
        let mount_point = before_fields.get(4)?.replace("\\040", " ");
        let flags = before_fields
            .get(5)
            .map(|raw| raw.split(',').map(str::to_string).collect())
            .unwrap_or_default();
        return Some((mount_point, flags));
    }
    None
}

fn detect_cgroup_mode(cgroup2_mount_path: Option<&str>) -> CgroupMode {
    let has_v2 =
        cgroup2_mount_path.is_some() || Path::new("/sys/fs/cgroup/cgroup.controllers").exists();
    let has_v1 = Path::new("/sys/fs/cgroup/net_cls").exists()
        || Path::new("/sys/fs/cgroup/memory").exists()
        || Path::new("/sys/fs/cgroup/cpu").exists();

    match (has_v2, has_v1) {
        (true, false) => CgroupMode::PureV2,
        (true, true) => CgroupMode::Hybrid,
        (false, true) => CgroupMode::V1Legacy,
        (false, false) => CgroupMode::Unknown,
    }
}

fn detect_conntrack_mark() -> CapabilityStatus {
    if Path::new("/proc/sys/net/netfilter").exists() {
        return CapabilityStatus::Likely;
    }

    if let Ok(modules) = fs::read_to_string("/proc/modules") {
        if modules
            .lines()
            .any(|line| line.starts_with("nf_conntrack "))
        {
            return CapabilityStatus::Likely;
        }
    }

    CapabilityStatus::Unknown
}

fn is_bpf_fs_mounted() -> bool {
    if let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") {
        if mountinfo.lines().any(|line| {
            line.contains(" - bpf ") && line.split_whitespace().nth(4) == Some("/sys/fs/bpf")
        }) {
            return true;
        }
    }
    Path::new("/sys/fs/bpf").exists()
}

fn kernel_meets(release: &str, major: u32, minor: u32) -> bool {
    let Some((found_major, found_minor)) = parse_kernel_major_minor(release) else {
        return false;
    };

    found_major > major || (found_major == major && found_minor >= minor)
}

fn parse_kernel_major_minor(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(['.', '-']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}
