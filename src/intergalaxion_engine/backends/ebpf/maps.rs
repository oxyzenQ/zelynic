// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF map model for the Intergalaxion Engine.
//!
//! In a live eBPF backend, BPF maps are shared data structures between
//! kernel programs and userspace. In I-0 this module only defines the
//! planned map layout.

/// Planned BPF map type for the Intergalaxion Engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfMapType {
    /// Hash map: PID -> byte counters.
    HashMap,
    /// Per-CPU array for fast counter accumulation.
    PerCpuArray,
    /// Ring buffer for streaming events to userspace.
    RingBuf,
}

/// A planned BPF map entry describing the map's purpose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfMapEntry {
    /// Human-readable name of the map.
    pub name: String,
    /// The type of BPF map.
    pub map_type: EbpfMapType,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
}

/// Planned set of BPF maps for the Intergalaxion Engine.
#[derive(Debug, Clone, Default)]
pub struct EbpfMapPlan {
    /// List of planned map entries.
    pub maps: Vec<EbpfMapEntry>,
}
