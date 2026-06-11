// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! eBPF observer event schema model for the Intergalaxion Engine.
//!
//! Phase I-3 adds a pure model for observer events, traffic direction,
//! verdicts, event sources, and event batches. No real eBPF programs
//! are loaded, attached, or created. No ring buffers are opened. No
//! kernel state is mutated. This module defines the *schema* only.

/// Traffic direction observed by an eBPF program.
///
/// In I-3 all events are model-only; no real traffic is observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfTrafficDirection {
    /// Direction is unknown or not applicable (default for model-only events).
    #[default]
    Unknown,
    /// Inbound (received) traffic.
    Rx,
    /// Outbound (transmitted) traffic.
    Tx,
}

impl EbpfTrafficDirection {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Rx => "rx",
            Self::Tx => "tx",
        }
    }
}

/// Verdict of an observer event.
///
/// This enum explicitly does **not** support packet drop. The
/// `DroppedUnsupported` variant means "this model does not support
/// packet drops", not that a packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfObserverVerdict {
    /// Event was observed passively — no decision was made.
    #[default]
    ObservedOnly,
    /// Observer could not produce a decision (e.g., insufficient data).
    NoDecision,
    /// This model does not support packet drops.
    DroppedUnsupported,
}

impl EbpfObserverVerdict {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservedOnly => "observed_only",
            Self::NoDecision => "no_decision",
            Self::DroppedUnsupported => "dropped_unsupported",
        }
    }
}

/// Source of an observer event.
///
/// Tracks whether the event originated from a pure model, a planned
/// ring buffer, or (unsupported) a live kernel path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EbpfEventSource {
    /// Event was produced by a pure data model (default for I-3).
    #[default]
    Model,
    /// Event is planned for ring-buffer delivery (not yet active).
    RingBufferPlanned,
    /// Live kernel event delivery is not supported in this phase.
    KernelLiveUnsupported,
}

impl EbpfEventSource {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Model => "model",
            Self::RingBufferPlanned => "ring_buffer_planned",
            Self::KernelLiveUnsupported => "kernel_live_unsupported",
        }
    }
}

/// A single observer event produced by the eBPF backend model.
///
/// In I-3 no real events are generated. This struct exists as a
/// compile-safe schema for future phases. All optional fields default
/// to `None` and all numeric fields default to zero.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfObserverEvent {
    /// Unique event identifier within a session.
    pub event_id: u64,
    /// The kind of event (telemetry, cgroup, error, noop).
    pub event_kind: super::EbpfEventKind,
    /// Monotonic timestamp in nanoseconds (model-only).
    pub timestamp_ns: u64,
    /// Process ID that generated the event, if known.
    pub pid: Option<u32>,
    /// Thread group ID, if known.
    pub tgid: Option<u32>,
    /// User ID, if known.
    pub uid: Option<u32>,
    /// Cgroup ID, if known.
    pub cgroup_id: Option<u64>,
    /// Socket cookie, if known.
    pub socket_cookie: Option<u64>,
    /// Network interface index, if known.
    pub interface_index: Option<u32>,
    /// Bytes received (rx).
    pub rx_bytes: u64,
    /// Bytes transmitted (tx).
    pub tx_bytes: u64,
    /// Number of packets observed.
    pub packet_count: u64,
    /// Traffic direction.
    pub direction: EbpfTrafficDirection,
    /// Observer verdict (never implies packet drop).
    pub verdict: EbpfObserverVerdict,
    /// Event source origin.
    pub source: EbpfEventSource,
}

/// A batch of observer events produced in a single collection cycle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfEventBatch {
    /// Where this batch originated.
    pub source: EbpfEventSource,
    /// The events in this batch.
    pub events: Vec<EbpfObserverEvent>,
    /// Whether the batch was truncated (events lost).
    pub truncated: bool,
    /// Decode errors encountered while processing events.
    pub decode_errors: Vec<String>,
}

/// Deterministic summary of an event batch.
///
/// Produced by [`summarize_event_batch`]. All fields are derived
/// deterministically from the batch contents.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EbpfEventBatchSummary {
    /// Source label of the batch.
    pub source: EbpfEventSource,
    /// Total number of events in the batch.
    pub event_count: u64,
    /// Sum of all rx_bytes across events.
    pub total_rx_bytes: u64,
    /// Sum of all tx_bytes across events.
    pub total_tx_bytes: u64,
    /// Whether the batch was truncated.
    pub truncated: bool,
    /// Number of decode errors in the batch.
    pub decode_error_count: u64,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create a default observer event (all zeros, no optional fields).
///
/// The default event is observer-only with no enforcement semantics.
pub fn default_observer_event() -> EbpfObserverEvent {
    EbpfObserverEvent::default()
}

/// Validate that an observer event is safe for the model-only phase.
///
/// Currently all events are considered valid. The validator exists
/// as a forward-compatible checkpoint for future invariant enforcement.
pub fn validate_observer_event(_event: &EbpfObserverEvent) -> Result<(), String> {
    // I-3 model phase: all events are structurally valid.
    Ok(())
}

/// Produce a deterministic summary from an event batch.
///
/// The summary is order-independent: it totals rx_bytes, tx_bytes,
/// counts events, preserves the truncated flag, and counts decode
/// errors.
pub fn summarize_event_batch(batch: &EbpfEventBatch) -> EbpfEventBatchSummary {
    let mut total_rx = 0u64;
    let mut total_tx = 0u64;

    for event in &batch.events {
        total_rx += event.rx_bytes;
        total_tx += event.tx_bytes;
    }

    EbpfEventBatchSummary {
        source: batch.source,
        event_count: batch.events.len() as u64,
        total_rx_bytes: total_rx,
        total_tx_bytes: total_tx,
        truncated: batch.truncated,
        decode_error_count: batch.decode_errors.len() as u64,
    }
}
