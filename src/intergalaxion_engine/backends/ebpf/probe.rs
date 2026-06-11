// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF probe model for the Intergalaxion Engine.
//!
//! In future phases the probe is responsible for loading and managing
//! eBPF programs. In I-0 no probes are created and no programs are loaded.

/// A probe descriptor that identifies a planned eBPF program attachment point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProbeDescriptor {
    /// Program type (e.g., cgroup_skb, tc, tracepoint).
    pub program_type: String,
    /// Attachment target (e.g., cgroup path, interface name).
    pub attach_target: String,
    /// Whether this probe is allowed to activate in the current phase.
    pub gated: bool,
}

impl Default for EbpfProbeDescriptor {
    fn default() -> Self {
        Self {
            program_type: String::from("cgroup_skb"),
            attach_target: String::new(),
            gated: true, // Always gated in I-0.
        }
    }
}
