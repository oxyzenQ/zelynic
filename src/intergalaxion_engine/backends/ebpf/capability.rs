// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF capability detection model.

/// Whether a specific eBPF capability is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfCapabilityStatus {
    /// Capability is proven available.
    Available,
    /// Capability is likely available but not proven.
    Likely,
    /// Capability is not available on this system.
    Unavailable,
}

/// Summary report of eBPF capabilities detected on the host.
#[derive(Debug, Clone)]
pub struct EbpfCapabilityReport {
    /// Overall status of the eBPF backend.
    pub backend_status: EbpfCapabilityStatus,
    /// Whether the kernel version meets the minimum requirement.
    pub kernel_supported: bool,
    /// Whether the process has CAP_BPF or is root.
    pub has_bpf_caps: bool,
    /// Whether /sys/fs/bpf is mounted.
    pub bpf_fs_mounted: bool,
    /// Whether required kernel config options are present.
    pub kernel_config_ok: bool,
}

impl Default for EbpfCapabilityReport {
    fn default() -> Self {
        // Safe default: everything is unavailable unless explicitly detected.
        Self {
            backend_status: EbpfCapabilityStatus::Unavailable,
            kernel_supported: false,
            has_bpf_caps: false,
            bpf_fs_mounted: false,
            kernel_config_ok: false,
        }
    }
}
