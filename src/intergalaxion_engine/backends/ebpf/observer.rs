// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF observer state model for the Intergalaxion Engine.
//!
//! The observer is the read-only data collection component. In I-0
//! the observer is always inactive and never attaches to anything.

/// Whether the eBPF observer is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfObserverState {
    /// Observer is actively collecting telemetry.
    Active,
    /// Observer is inactive (default for I-0).
    #[default]
    Inactive,
}

/// Whether an eBPF program is attached to a kernel hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfAttachState {
    /// An eBPF program is attached.
    Attached,
    /// No eBPF program is attached (default for I-0).
    #[default]
    NotAttached,
}

/// Overall status of the eBPF backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfBackendStatus {
    /// Backend is detected and available for use.
    Available,
    /// Backend is not available on this system (default for I-0).
    #[default]
    Unavailable,
}
