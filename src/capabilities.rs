// SPDX-License-Identifier: GPL-3.0-only
/// Read-only host capability detection and backend scoring.
///
/// Backend Doctor intentionally avoids commands that mutate tc, nftables,
/// cgroups, or kernel module state. Results are best-effort and are meant to
/// guide the user toward the safest backend to validate with `strict --diagnose`.
use anyhow::Result;
use colored::Colorize;
use serde::Serialize;
use std::fmt;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::ebpf;

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
    pub recommended_backend: String,
    pub notes: Vec<String>,
    pub warnings: Vec<String>,
}

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
    let recommended_backend = recommend_backend(&backend_candidates).to_string();
    let notes = vec![
        "Backend Doctor does not modify nftables, tc, or cgroups.".to_string(),
        "Strict mode is only truly validated after a real strict --diagnose test.".to_string(),
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

    BackendDoctorReport {
        system,
        capabilities,
        backend_candidates,
        recommended_backend,
        notes,
        warnings,
    }
}

pub fn detect_system_info() -> SystemInfo {
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

fn detect_capabilities(system: &SystemInfo) -> CapabilityMatrix {
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
    }
}

pub fn score_backend_candidates(
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

pub fn recommend_backend(candidates: &[BackendCandidate]) -> &str {
    candidates
        .iter()
        .filter(|candidate| candidate.status != BackendCandidateStatus::Future)
        .max_by_key(|candidate| match candidate.status {
            BackendCandidateStatus::Supported => (3u8, candidate.confidence),
            BackendCandidateStatus::Partial => (2u8, candidate.confidence),
            BackendCandidateStatus::Unavailable => (1u8, candidate.confidence),
            BackendCandidateStatus::Future => (0u8, candidate.confidence),
        })
        .map(|candidate| candidate.name.as_str())
        .unwrap_or("modern-cgroupv2-nft-tc")
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
    let mut score = 35u8;

    if system.systemd.available {
        score += 18;
    } else {
        missing.push("systemd".to_string());
    }
    if system.systemd_run.available {
        score += 17;
    } else {
        missing.push("systemd-run".to_string());
    }
    if matches!(system.cgroup_mode, CgroupMode::PureV2 | CgroupMode::Hybrid) {
        score += 10;
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
        confidence: score.min(80),
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
            BackendCandidateStatus::Supported
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
        CapabilityStatus::Yes => 75,
        CapabilityStatus::RequiresRoot | CapabilityStatus::Likely => 65,
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

fn print_backend_doctor_report(report: &BackendDoctorReport) {
    println!("{}", "Zelynic Backend Doctor".bold());
    println!();

    println!("{}", "System:".bold());
    println!("Kernel: {}", report.system.kernel);
    println!("cgroup: {}", report.system.cgroup_mode);
    println!(
        "cgroup2 mount: {}",
        report
            .system
            .cgroup2_mount_path
            .as_deref()
            .unwrap_or("not found")
    );
    println!(
        "cgroup2 flags: {}",
        if report.system.cgroup2_mount_flags.is_empty() {
            "unknown".to_string()
        } else {
            report.system.cgroup2_mount_flags.join(",")
        }
    );
    println!("nftables: {}", tool_display(&report.system.nftables));
    println!("tc/iproute2: {}", tool_display(&report.system.tc));
    println!("systemd: {}", tool_display(&report.system.systemd));
    println!("systemd-run: {}", tool_display(&report.system.systemd_run));
    println!();

    println!("{}", "Capabilities:".bold());
    println!("cgroup v2: {}", report.capabilities.cgroup_v2);
    println!(
        "nft socket cgroupv2: {}",
        report.capabilities.nft_socket_cgroupv2
    );
    println!("tc HTB: {}", report.capabilities.tc_htb);
    println!("fw filter: {}", report.capabilities.fw_filter);
    println!("conntrack mark: {}", report.capabilities.conntrack_mark);
    println!("BPF filesystem: {}", report.capabilities.bpf_fs_mounted);
    println!("eBPF: {}", ebpf_display(report.capabilities.ebpf));
    println!();

    println!("{}", "Backend candidates:".bold());
    for candidate in &report.backend_candidates {
        println!(
            "{}: {}, confidence {}%",
            candidate.name, candidate.status, candidate.confidence
        );
        if !candidate.missing_requirements.is_empty() {
            println!("  missing: {}", candidate.missing_requirements.join(", "));
        }
        if !candidate.risk_notes.is_empty() {
            println!("  risks: {}", candidate.risk_notes.join("; "));
        }
    }
    println!();

    println!("{}", "Recommended:".bold());
    println!("{}", report.recommended_backend);
    println!();

    println!("{}", "Notes:".bold());
    for note in &report.notes {
        println!("- {}", note);
    }
    for warning in &report.warnings {
        println!("- {}", warning);
    }
}

fn tool_display(tool: &ToolInfo) -> String {
    if tool.available {
        tool.version.clone()
    } else {
        "not found".to_string()
    }
}

fn ebpf_display(status: CapabilityStatus) -> String {
    match status {
        CapabilityStatus::Yes => "supported but not implemented".to_string(),
        CapabilityStatus::RequiresRoot => {
            "likely supported; requires root to verify capability".to_string()
        }
        other => format!("{}; not implemented", other),
    }
}

fn command_version(program: &str, args: &[&str]) -> ToolInfo {
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

fn detect_systemd() -> ToolInfo {
    let mut info = command_version("systemctl", &["--version"]);
    if !info.available && Path::new("/run/systemd/system").exists() {
        info.available = true;
        info.version = "available".to_string();
    }
    info
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

pub fn detect_cgroup_mode(cgroup2_mount_path: Option<&str>) -> CgroupMode {
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
        };

        let candidates = score_backend_candidates(&system, &caps);
        let modern = candidates
            .iter()
            .find(|candidate| candidate.name == "modern-cgroupv2-nft-tc")
            .unwrap();

        assert_eq!(modern.status, BackendCandidateStatus::Supported);
        assert!(modern.confidence >= 90);
        assert_eq!(recommend_backend(&candidates), "modern-cgroupv2-nft-tc");
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
    fn recommendation_falls_back_when_modern_is_unavailable() {
        let system = system(CgroupMode::V1Legacy, false, true, false);
        let caps = CapabilityMatrix {
            cgroup_v2: CapabilityStatus::No,
            nft_socket_cgroupv2: CapabilityStatus::No,
            tc_htb: CapabilityStatus::Likely,
            fw_filter: CapabilityStatus::Likely,
            conntrack_mark: CapabilityStatus::Unknown,
            bpf_fs_mounted: CapabilityStatus::No,
            ebpf: CapabilityStatus::No,
        };

        let candidates = score_backend_candidates(&system, &caps);

        assert_eq!(recommend_backend(&candidates), "interface-global-fallback");
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
            },
            backend_candidates: vec![BackendCandidate {
                name: "modern-cgroupv2-nft-tc".to_string(),
                status: BackendCandidateStatus::Supported,
                confidence: 94,
                missing_requirements: Vec::new(),
                risk_notes: Vec::new(),
            }],
            recommended_backend: "modern-cgroupv2-nft-tc".to_string(),
            notes: vec!["read-only".to_string()],
            warnings: Vec::new(),
        };

        let json = serde_json::to_string(&report).unwrap();

        assert!(json.contains("modern-cgroupv2-nft-tc"));
        assert!(json.contains("pure-v2"));
    }
}
