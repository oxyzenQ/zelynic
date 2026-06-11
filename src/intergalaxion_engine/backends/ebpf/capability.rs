// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Pure eBPF capability model for the Intergalaxion Engine.

/// Injected host facts used by the pure evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfCapabilitySnapshot {
    /// Kernel release string, informational in I-1.
    pub kernel_release: Option<String>,
    /// Whether bpffs is visible at the expected path.
    pub bpf_fs_mounted: Option<bool>,
    /// Whether `/sys/kernel/btf/vmlinux` is visible.
    pub btf_vmlinux_available: Option<bool>,
    /// Whether CAP_BPF is effective for this process.
    pub cap_bpf_effective: Option<bool>,
    /// Whether CAP_SYS_ADMIN is effective for this process.
    pub cap_sys_admin_effective: Option<bool>,
    /// Raw `/proc/sys/kernel/unprivileged_bpf_disabled` value.
    pub unprivileged_bpf_disabled: Option<u8>,
    /// Whether the optional aya dependency was enabled at compile time.
    pub aya_available_at_compile_time: bool,
}

impl Default for EbpfCapabilitySnapshot {
    fn default() -> Self {
        Self {
            kernel_release: None,
            bpf_fs_mounted: None,
            btf_vmlinux_available: None,
            cap_bpf_effective: None,
            cap_sys_admin_effective: None,
            unprivileged_bpf_disabled: None,
            aya_available_at_compile_time: cfg!(feature = "ebpf"),
        }
    }
}

/// A single capability finding from evaluating a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfCapabilityFinding {
    /// Stable machine key for the finding.
    pub key: &'static str,
    /// Whether this capability is present.
    pub available: bool,
    /// Whether this fact was known in the injected snapshot.
    pub checked: bool,
    /// Short human-readable explanation.
    pub reason: String,
}

impl EbpfCapabilityFinding {
    fn new(key: &'static str, available: bool, checked: bool, reason: impl Into<String>) -> Self {
        Self {
            key,
            available,
            checked,
            reason: reason.into(),
        }
    }
}

/// Conservative readiness label for future observer work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfReadinessLevel {
    /// Required facts are missing or negative.
    #[default]
    Unavailable,
    /// Some host facts are promising, but the minimum observer facts are absent.
    Partial,
    /// Minimum observer facts are present.
    ObserverReady,
    /// The host model also has a capability suitable for future program use.
    AttachCandidate,
}

impl EbpfReadinessLevel {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Partial => "partial",
            Self::ObserverReady => "observer_ready",
            Self::AttachCandidate => "attach_candidate",
        }
    }
}

/// Pure report produced by evaluating an injected snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfCapabilityReport {
    /// Original injected facts.
    pub snapshot: EbpfCapabilitySnapshot,
    /// Per-fact findings in stable order.
    pub findings: Vec<EbpfCapabilityFinding>,
    /// Conservative overall readiness label.
    pub readiness: EbpfReadinessLevel,
    /// True only when minimum observer facts are present.
    pub observer_ready: bool,
    /// True only when all explicit future program-use facts pass.
    pub attach_candidate: bool,
}

impl Default for EbpfCapabilityReport {
    fn default() -> Self {
        evaluate_ebpf_capability(&EbpfCapabilitySnapshot::default())
    }
}

/// Evaluate a snapshot without reading host state.
pub fn evaluate_ebpf_capability(snapshot: &EbpfCapabilitySnapshot) -> EbpfCapabilityReport {
    let bpf_fs_ready = snapshot.bpf_fs_mounted == Some(true);
    let btf_ready = snapshot.btf_vmlinux_available == Some(true);
    let has_future_program_cap =
        snapshot.cap_bpf_effective == Some(true) || snapshot.cap_sys_admin_effective == Some(true);

    let observer_ready = bpf_fs_ready && btf_ready;
    let attach_candidate = observer_ready && has_future_program_cap;

    let readiness = if attach_candidate {
        EbpfReadinessLevel::AttachCandidate
    } else if observer_ready {
        EbpfReadinessLevel::ObserverReady
    } else if bpf_fs_ready {
        EbpfReadinessLevel::Partial
    } else {
        EbpfReadinessLevel::Unavailable
    };

    let findings = vec![
        finding_from_bool(
            "bpf_fs_mounted",
            snapshot.bpf_fs_mounted,
            "bpffs visible",
            "bpffs missing",
            "bpffs state unknown",
        ),
        finding_from_bool(
            "btf_vmlinux_available",
            snapshot.btf_vmlinux_available,
            "vmlinux BTF visible",
            "vmlinux BTF missing",
            "vmlinux BTF state unknown",
        ),
        EbpfCapabilityFinding::new(
            "future_program_capability",
            has_future_program_cap,
            snapshot.cap_bpf_effective.is_some() || snapshot.cap_sys_admin_effective.is_some(),
            if has_future_program_cap {
                "CAP_BPF or CAP_SYS_ADMIN effective"
            } else if snapshot.cap_bpf_effective.is_some()
                || snapshot.cap_sys_admin_effective.is_some()
            {
                "CAP_BPF and CAP_SYS_ADMIN not effective"
            } else {
                "effective capability state unknown"
            },
        ),
        EbpfCapabilityFinding::new(
            "unprivileged_bpf_disabled",
            snapshot.unprivileged_bpf_disabled == Some(0),
            snapshot.unprivileged_bpf_disabled.is_some(),
            match snapshot.unprivileged_bpf_disabled {
                Some(value) => format!("kernel value recorded as {value}"),
                None => "kernel value unknown".to_string(),
            },
        ),
        EbpfCapabilityFinding::new(
            "kernel_release",
            snapshot.kernel_release.is_some(),
            snapshot.kernel_release.is_some(),
            snapshot
                .kernel_release
                .clone()
                .unwrap_or_else(|| "kernel release unknown".to_string()),
        ),
        EbpfCapabilityFinding::new(
            "aya_available_at_compile_time",
            snapshot.aya_available_at_compile_time,
            true,
            if snapshot.aya_available_at_compile_time {
                "aya feature enabled"
            } else {
                "aya feature disabled"
            },
        ),
    ];

    EbpfCapabilityReport {
        snapshot: snapshot.clone(),
        findings,
        readiness,
        observer_ready,
        attach_candidate,
    }
}

fn finding_from_bool(
    key: &'static str,
    value: Option<bool>,
    yes: &'static str,
    no: &'static str,
    unknown: &'static str,
) -> EbpfCapabilityFinding {
    match value {
        Some(true) => EbpfCapabilityFinding::new(key, true, true, yes),
        Some(false) => EbpfCapabilityFinding::new(key, false, true, no),
        None => EbpfCapabilityFinding::new(key, false, false, unknown),
    }
}
