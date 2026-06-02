// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
/// Read-only host capability detection and backend scoring.
///
/// Backend Doctor intentionally avoids commands that mutate tc, nftables,
/// cgroups, or kernel module state. Results are best-effort and are meant to
/// guide the user toward the safest backend to validate with `strict --diagnose`.
use anyhow::Result;

mod detect;
mod render;
mod scoring;
mod systemd;
mod types;

use detect::{detect_capabilities, detect_system_info};
use render::print_backend_doctor_report;
use scoring::{recommend_backend, score_backend_candidates};

pub use types::*;

pub fn run_backend_doctor(json: bool) -> Result<()> {
    let report = detect_backend_doctor_report();
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_backend_doctor_report(&report);
    }
    Ok(())
}

pub fn detect_backend_doctor_report() -> BackendDoctorReport {
    let system = detect_system_info();
    let capabilities = detect_capabilities(&system);
    let backend_candidates = score_backend_candidates(&system, &capabilities);
    let recommended_backend = recommend_backend(&backend_candidates).map(str::to_string);
    let notes = vec![
        "Backend Doctor does not modify nftables, tc, or cgroups.".to_string(),
        "Status meanings: supported = host likely has requirements; partial = requirements or implementation work remain; future = not implemented as an active strict backend.".to_string(),
        "Strict mode is only truly validated after a real zelynic strict --diagnose test.".to_string(),
        "Systemd scope wrapper/run mode is experimental groundwork and dry-run only.".to_string(),
    ];
    let mut warnings = Vec::new();

    if system.cgroup_mode != CgroupMode::PureV2 {
        warnings
            .push("Host is not pure cgroup v2; strict backend behavior may differ.".to_string());
    }
    if capabilities.nft_socket_cgroupv2 != CapabilityStatus::Likely
        && capabilities.nft_socket_cgroupv2 != CapabilityStatus::Yes
    {
        warnings.push("nft socket cgroupv2 support could not be proven safely.".to_string());
    }
    if recommended_backend.is_none() {
        warnings
            .push("No supported or partial backend candidate detected on this host.".to_string());
    }

    BackendDoctorReport {
        system,
        capabilities,
        backend_candidates,
        recommended_backend,
        notes,
        warnings,
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

    fn system(cgroup_mode: CgroupMode, nft: bool, tc: bool, systemd: bool) -> SystemInfo {
        SystemInfo {
            kernel: "6.18.33-1-cachyos-lts".to_string(),
            cgroup_mode,
            cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
            cgroup2_mount_flags: vec!["rw".to_string(), "nosuid".to_string()],
            nftables: tool(nft),
            tc: tool(tc),
            systemd: tool(systemd),
            systemd_run: tool(systemd),
        }
    }

    #[test]
    fn doctor_report_serializes_to_json() {
        let report = BackendDoctorReport {
            system: system(CgroupMode::PureV2, true, true, true),
            capabilities: CapabilityMatrix {
                cgroup_v2: CapabilityStatus::Yes,
                nft_socket_cgroupv2: CapabilityStatus::Likely,
                tc_htb: CapabilityStatus::Likely,
                fw_filter: CapabilityStatus::Likely,
                conntrack_mark: CapabilityStatus::Likely,
                bpf_fs_mounted: CapabilityStatus::Yes,
                ebpf: CapabilityStatus::RequiresRoot,
                transient_scope_wrapper: CapabilityStatus::Likely,
            },
            backend_candidates: vec![BackendCandidate {
                name: "modern-cgroupv2-nft-tc".to_string(),
                status: BackendCandidateStatus::Supported,
                confidence: 94,
                missing_requirements: Vec::new(),
                risk_notes: Vec::new(),
            }],
            recommended_backend: Some("modern-cgroupv2-nft-tc".to_string()),
            notes: vec!["read-only".to_string()],
            warnings: Vec::new(),
        };

        let json = serde_json::to_string(&report).unwrap();

        assert!(json.contains("modern-cgroupv2-nft-tc"));
        assert!(json.contains("pure-v2"));
    }

    #[test]
    fn doctor_report_serializes_no_recommendation_as_json_null() {
        let report = BackendDoctorReport {
            system: system(CgroupMode::Unknown, false, false, false),
            capabilities: CapabilityMatrix {
                cgroup_v2: CapabilityStatus::Unknown,
                nft_socket_cgroupv2: CapabilityStatus::No,
                tc_htb: CapabilityStatus::No,
                fw_filter: CapabilityStatus::No,
                conntrack_mark: CapabilityStatus::Unknown,
                bpf_fs_mounted: CapabilityStatus::No,
                ebpf: CapabilityStatus::No,
                transient_scope_wrapper: CapabilityStatus::No,
            },
            backend_candidates: vec![BackendCandidate {
                name: "unavailable".to_string(),
                status: BackendCandidateStatus::Unavailable,
                confidence: 99,
                missing_requirements: vec!["tc".to_string()],
                risk_notes: Vec::new(),
            }],
            recommended_backend: None,
            notes: Vec::new(),
            warnings: vec![
                "No supported or partial backend candidate detected on this host.".to_string(),
            ],
        };

        let json = serde_json::to_string(&report).unwrap();

        assert!(json.contains(r#""recommended_backend":null"#));
        assert!(json.contains("No supported or partial backend candidate detected"));
    }
}
