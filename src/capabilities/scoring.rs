// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use super::types::{
    BackendCandidate, BackendCandidateStatus, CapabilityMatrix, CapabilityStatus, CgroupMode,
    SystemInfo,
};

pub(super) fn score_backend_candidates(
    system: &SystemInfo,
    caps: &CapabilityMatrix,
) -> Vec<BackendCandidate> {
    vec![
        score_modern_cgroupv2_nft_tc(system, caps),
        score_systemd_scope_wrapper(system),
        score_legacy_cgroup_v1(system),
        score_interface_global_fallback(system),
        score_ebpf_future(caps),
    ]
}

pub(super) fn recommend_backend(candidates: &[BackendCandidate]) -> Option<&str> {
    candidates
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.status,
                BackendCandidateStatus::Supported | BackendCandidateStatus::Partial
            )
        })
        .max_by_key(|candidate| match candidate.status {
            BackendCandidateStatus::Supported => (3u8, candidate.confidence),
            BackendCandidateStatus::Partial => (2u8, candidate.confidence),
            BackendCandidateStatus::Unavailable => (1u8, candidate.confidence),
            BackendCandidateStatus::Future => (0u8, candidate.confidence),
        })
        .map(|candidate| candidate.name.as_str())
}

fn score_modern_cgroupv2_nft_tc(system: &SystemInfo, caps: &CapabilityMatrix) -> BackendCandidate {
    let mut missing = Vec::new();
    let mut risk_notes = Vec::new();
    let mut score = 40u8;

    if system.cgroup_mode == CgroupMode::PureV2 {
        score += 22;
    } else {
        missing.push("pure cgroup v2".to_string());
        if system.cgroup_mode == CgroupMode::Hybrid {
            risk_notes
                .push("hybrid cgroup layout may require host-specific validation".to_string());
            score += 10;
        }
    }

    add_likely_score(
        caps.nft_socket_cgroupv2,
        18,
        "nft socket cgroupv2",
        &mut score,
        &mut missing,
    );
    add_likely_score(caps.tc_htb, 10, "tc HTB", &mut score, &mut missing);
    add_likely_score(caps.fw_filter, 6, "tc fw filter", &mut score, &mut missing);
    add_likely_score(
        caps.conntrack_mark,
        4,
        "conntrack mark support",
        &mut score,
        &mut missing,
    );

    if caps.nft_socket_cgroupv2 == CapabilityStatus::Likely {
        risk_notes.push(
            "nft socket cgroupv2 support is inferred, not proven without a strict diagnostic run"
                .to_string(),
        );
    }
    if caps.tc_htb == CapabilityStatus::Likely || caps.fw_filter == CapabilityStatus::Likely {
        risk_notes.push("tc HTB/fw support is inferred from tc availability".to_string());
    }

    let status = if missing.is_empty() && system.cgroup_mode == CgroupMode::PureV2 {
        BackendCandidateStatus::Supported
    } else if score >= 60 {
        BackendCandidateStatus::Partial
    } else {
        BackendCandidateStatus::Unavailable
    };

    BackendCandidate {
        name: "modern-cgroupv2-nft-tc".to_string(),
        status,
        confidence: score.min(98),
        missing_requirements: missing,
        risk_notes,
    }
}

fn score_systemd_scope_wrapper(system: &SystemInfo) -> BackendCandidate {
    let mut missing = Vec::new();
    let mut risk_notes = Vec::new();
    let mut score = 30u8;

    if system.systemd.available {
        score += 15;
    } else {
        missing.push("systemd".to_string());
    }
    if system.systemd_run.available {
        score += 15;
    } else {
        missing.push("systemd-run".to_string());
    }
    if matches!(system.cgroup_mode, CgroupMode::PureV2 | CgroupMode::Hybrid) {
        score += 8;
    } else {
        missing.push("cgroup v2 hierarchy".to_string());
    }

    risk_notes.push("wrapper backend is planned and not used by strict today".to_string());
    risk_notes.push("already-running GUI applications may still need manual targeting".to_string());

    BackendCandidate {
        name: "systemd-scope-wrapper".to_string(),
        status: if missing.is_empty() || score >= 50 {
            BackendCandidateStatus::Partial
        } else {
            BackendCandidateStatus::Unavailable
        },
        confidence: score.min(68),
        missing_requirements: missing,
        risk_notes,
    }
}

fn score_legacy_cgroup_v1(system: &SystemInfo) -> BackendCandidate {
    let mut risk_notes = Vec::new();
    let (status, score, missing) = if system.cgroup_mode == CgroupMode::V1Legacy {
        risk_notes.push("legacy net_cls systems are not the v2.0 validated path".to_string());
        (BackendCandidateStatus::Partial, 60, Vec::new())
    } else {
        (
            BackendCandidateStatus::Unavailable,
            10,
            vec!["cgroup v1 net_cls hierarchy".to_string()],
        )
    };

    BackendCandidate {
        name: "legacy-cgroup-v1-net-cls".to_string(),
        status,
        confidence: score,
        missing_requirements: missing,
        risk_notes,
    }
}

fn score_interface_global_fallback(system: &SystemInfo) -> BackendCandidate {
    let mut missing = Vec::new();
    let mut score = 30u8;

    if system.tc.available {
        score += 20;
    } else {
        missing.push("tc".to_string());
    }

    BackendCandidate {
        name: "interface-global-fallback".to_string(),
        status: if system.tc.available {
            BackendCandidateStatus::Partial
        } else {
            BackendCandidateStatus::Unavailable
        },
        confidence: score,
        missing_requirements: missing,
        risk_notes: vec![
            "fallback is coarse and may affect traffic beyond the requested process".to_string(),
            "kept as a conceptual fallback, not preferred for strict per-process limiting"
                .to_string(),
        ],
    }
}

fn score_ebpf_future(caps: &CapabilityMatrix) -> BackendCandidate {
    let confidence = match caps.ebpf {
        CapabilityStatus::Yes => 50,
        CapabilityStatus::RequiresRoot | CapabilityStatus::Likely => 45,
        CapabilityStatus::Unknown => 40,
        CapabilityStatus::No => 20,
    };

    BackendCandidate {
        name: "ebpf-future".to_string(),
        status: BackendCandidateStatus::Future,
        confidence,
        missing_requirements: vec!["implemented eBPF limiter".to_string()],
        risk_notes: vec![
            "eBPF detection is informational; strict currently uses tc/cgroup".to_string(),
        ],
    }
}

fn add_likely_score(
    status: CapabilityStatus,
    points: u8,
    requirement: &str,
    score: &mut u8,
    missing: &mut Vec<String>,
) {
    match status {
        CapabilityStatus::Yes => *score += points,
        CapabilityStatus::Likely => *score += points.saturating_sub(2),
        CapabilityStatus::RequiresRoot | CapabilityStatus::Unknown => {
            *score += points / 2;
            missing.push(format!("{} not proven", requirement));
        }
        CapabilityStatus::No => missing.push(requirement.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::ToolInfo;
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
    fn modern_backend_scores_supported_on_pure_v2_host() {
        let system = system(CgroupMode::PureV2, true, true, true);
        let caps = CapabilityMatrix {
            cgroup_v2: CapabilityStatus::Yes,
            nft_socket_cgroupv2: CapabilityStatus::Likely,
            tc_htb: CapabilityStatus::Likely,
            fw_filter: CapabilityStatus::Likely,
            conntrack_mark: CapabilityStatus::Likely,
            bpf_fs_mounted: CapabilityStatus::Yes,
            ebpf: CapabilityStatus::RequiresRoot,
            transient_scope_wrapper: CapabilityStatus::Likely,
        };

        let candidates = score_backend_candidates(&system, &caps);
        let modern = candidates
            .iter()
            .find(|candidate| candidate.name == "modern-cgroupv2-nft-tc")
            .unwrap();

        assert_eq!(modern.status, BackendCandidateStatus::Supported);
        assert!(modern.confidence >= 90);
        assert_eq!(
            recommend_backend(&candidates),
            Some("modern-cgroupv2-nft-tc")
        );
    }

    #[test]
    fn non_active_backends_use_partial_or_future_readiness() {
        let system = system(CgroupMode::PureV2, true, true, true);
        let caps = CapabilityMatrix {
            cgroup_v2: CapabilityStatus::Yes,
            nft_socket_cgroupv2: CapabilityStatus::Likely,
            tc_htb: CapabilityStatus::Likely,
            fw_filter: CapabilityStatus::Likely,
            conntrack_mark: CapabilityStatus::Likely,
            bpf_fs_mounted: CapabilityStatus::Yes,
            ebpf: CapabilityStatus::RequiresRoot,
            transient_scope_wrapper: CapabilityStatus::Likely,
        };

        let candidates = score_backend_candidates(&system, &caps);
        let systemd = candidates
            .iter()
            .find(|candidate| candidate.name == "systemd-scope-wrapper")
            .unwrap();
        let interface = candidates
            .iter()
            .find(|candidate| candidate.name == "interface-global-fallback")
            .unwrap();
        let ebpf = candidates
            .iter()
            .find(|candidate| candidate.name == "ebpf-future")
            .unwrap();

        assert_eq!(systemd.status, BackendCandidateStatus::Partial);
        assert!((65..=70).contains(&systemd.confidence));
        assert_eq!(interface.status, BackendCandidateStatus::Partial);
        assert_eq!(interface.confidence, 50);
        assert_eq!(ebpf.status, BackendCandidateStatus::Future);
        assert!((40..=50).contains(&ebpf.confidence));
    }

    #[test]
    fn missing_nft_makes_modern_backend_unavailable_or_partial() {
        let system = system(CgroupMode::PureV2, false, true, true);
        let caps = CapabilityMatrix {
            cgroup_v2: CapabilityStatus::Yes,
            nft_socket_cgroupv2: CapabilityStatus::No,
            tc_htb: CapabilityStatus::Likely,
            fw_filter: CapabilityStatus::Likely,
            conntrack_mark: CapabilityStatus::Likely,
            bpf_fs_mounted: CapabilityStatus::Yes,
            ebpf: CapabilityStatus::No,
            transient_scope_wrapper: CapabilityStatus::Likely,
        };

        let candidates = score_backend_candidates(&system, &caps);
        let modern = candidates
            .iter()
            .find(|candidate| candidate.name == "modern-cgroupv2-nft-tc")
            .unwrap();

        assert!(modern
            .missing_requirements
            .contains(&"nft socket cgroupv2".to_string()));
        assert_ne!(modern.status, BackendCandidateStatus::Supported);
    }

    #[test]
    fn recommendation_prefers_legacy_v1_over_conceptual_interface_fallback() {
        let system = system(CgroupMode::V1Legacy, false, true, false);
        let caps = CapabilityMatrix {
            cgroup_v2: CapabilityStatus::No,
            nft_socket_cgroupv2: CapabilityStatus::No,
            tc_htb: CapabilityStatus::Likely,
            fw_filter: CapabilityStatus::Likely,
            conntrack_mark: CapabilityStatus::Unknown,
            bpf_fs_mounted: CapabilityStatus::No,
            ebpf: CapabilityStatus::No,
            transient_scope_wrapper: CapabilityStatus::No,
        };

        let candidates = score_backend_candidates(&system, &caps);

        assert_eq!(
            recommend_backend(&candidates),
            Some("legacy-cgroup-v1-net-cls")
        );
    }

    #[test]
    fn all_unavailable_or_future_candidates_have_no_recommendation() {
        let candidates = vec![
            BackendCandidate {
                name: "unavailable-high-confidence".to_string(),
                status: BackendCandidateStatus::Unavailable,
                confidence: 99,
                missing_requirements: vec!["everything".to_string()],
                risk_notes: Vec::new(),
            },
            BackendCandidate {
                name: "future-high-confidence".to_string(),
                status: BackendCandidateStatus::Future,
                confidence: 99,
                missing_requirements: vec!["implementation".to_string()],
                risk_notes: Vec::new(),
            },
        ];

        assert_eq!(recommend_backend(&candidates), None);
    }

    #[test]
    fn unavailable_candidate_cannot_beat_partial_candidate() {
        let candidates = vec![
            BackendCandidate {
                name: "unavailable-high-confidence".to_string(),
                status: BackendCandidateStatus::Unavailable,
                confidence: 99,
                missing_requirements: vec!["critical requirement".to_string()],
                risk_notes: Vec::new(),
            },
            BackendCandidate {
                name: "partial-low-confidence".to_string(),
                status: BackendCandidateStatus::Partial,
                confidence: 10,
                missing_requirements: vec!["some implementation work".to_string()],
                risk_notes: Vec::new(),
            },
        ];

        assert_eq!(
            recommend_backend(&candidates),
            Some("partial-low-confidence")
        );
    }

    #[test]
    fn supported_candidate_beats_partial_candidate() {
        let candidates = vec![
            BackendCandidate {
                name: "partial-high-confidence".to_string(),
                status: BackendCandidateStatus::Partial,
                confidence: 99,
                missing_requirements: Vec::new(),
                risk_notes: Vec::new(),
            },
            BackendCandidate {
                name: "supported-low-confidence".to_string(),
                status: BackendCandidateStatus::Supported,
                confidence: 1,
                missing_requirements: Vec::new(),
                risk_notes: Vec::new(),
            },
        ];

        assert_eq!(
            recommend_backend(&candidates),
            Some("supported-low-confidence")
        );
    }
}
