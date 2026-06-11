// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF event model for the Intergalaxion Engine observer.

/// Kinds of events that the eBPF observer may produce.
///
/// In I-0 no real events are generated; this enum exists as a
/// compile-safe model for future phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfEventKind {
    /// A telemetry sample was collected (byte counters).
    TelemetrySample,
    /// A process was seen attaching to a cgroup.
    CgroupAttach,
    /// A process was seen detaching from a cgroup.
    CgroupDetach,
    /// An error was reported by the eBPF program.
    Error,
    /// The observer loop cycled without producing a meaningful event.
    #[default]
    Noop,
}
