// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Telemetry data model for the Intergalaxion Engine.
//!
//! In I-0 this is a pure data-model skeleton. No live data collection
//! or kernel interaction occurs.

/// A single telemetry sample collected (future) from an eBPF program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetrySample {
    /// Monotonic counter identifying the sample sequence.
    pub sequence: u64,
    /// Timestamp when the sample was recorded (epoch millis).
    pub timestamp_ms: u64,
    /// Number of bytes received since the previous sample.
    pub rx_bytes: u64,
    /// Number of bytes transmitted since the previous sample.
    pub tx_bytes: u64,
}

/// Accumulated telemetry summary for a single identity target.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TelemetrySummary {
    /// Total bytes received.
    pub total_rx_bytes: u64,
    /// Total bytes transmitted.
    pub total_tx_bytes: u64,
    /// Number of samples that contributed to this summary.
    pub sample_count: u64,
}
