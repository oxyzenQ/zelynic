// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Ledger bridge model for the Intergalaxion Engine.
//!
//! Phase I-4 adds a pure model for translating observer events into
//! internal ledger bridge records. No ledger files are written. No
//! persistence is performed. No enforcement is applied. Bridge records
//! are internal Intergalaxion model records only — they do not modify
//! the existing v3.1.0 ledger JSON schema.

use crate::intergalaxion_engine::backends::ebpf::{
    EbpfEventBatch, EbpfEventKind, EbpfEventSource, EbpfObserverEvent,
};

/// An internal ledger bridge record produced from an observer event.
///
/// This is an *internal* Intergalaxion model record, not a public
/// ledger export entry. It is never written to disk and never modifies
/// the stable v3.1.0 ledger JSON schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntergalaxionLedgerBridgeRecord {
    /// Unique bridge record identifier.
    pub bridge_id: String,
    /// Source event identifier.
    pub source_event_id: u64,
    /// Source event kind.
    pub source_event_kind: EbpfEventKind,
    /// Monotonic timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Process ID, if known.
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
    /// Bytes received.
    pub rx_bytes: u64,
    /// Bytes transmitted.
    pub tx_bytes: u64,
    /// Combined bytes (rx + tx, saturating).
    pub combined_bytes: u64,
    /// Number of packets observed.
    pub packet_count: u64,
    /// Attribution scope (always honest, e.g. "kernel-observer-model only").
    pub attribution_scope: String,
    /// Whether this record is read-only (always true in I-4).
    pub read_only: bool,
    /// Provenance label (non-empty, identifies the bridge source).
    pub provenance: String,
    /// Enforcement status (always "inactive/not implemented" in I-4).
    pub enforcement_status: String,
}

impl Default for IntergalaxionLedgerBridgeRecord {
    fn default() -> Self {
        Self {
            bridge_id: String::new(),
            source_event_id: 0,
            source_event_kind: EbpfEventKind::default(),
            timestamp_ns: 0,
            pid: None,
            tgid: None,
            uid: None,
            cgroup_id: None,
            socket_cookie: None,
            interface_index: None,
            rx_bytes: 0,
            tx_bytes: 0,
            combined_bytes: 0,
            packet_count: 0,
            attribution_scope: String::from("kernel-observer-model only"),
            read_only: true,
            provenance: String::from("intergalaxion engine model"),
            enforcement_status: String::from("inactive/not implemented"),
        }
    }
}

/// A batch of ledger bridge records produced from an event batch.
///
/// No files are written. No persistence occurs. No enforcement is
/// performed. The batch tracks metadata about the bridge operation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntergalaxionLedgerBridgeBatch {
    /// Where this batch originated.
    pub source: EbpfEventSource,
    /// Successfully bridged records.
    pub records: Vec<IntergalaxionLedgerBridgeRecord>,
    /// Number of events skipped during bridging.
    pub skipped_events: usize,
    /// Bridge error messages.
    pub bridge_errors: Vec<String>,
    /// Whether a filesystem write was performed (always false in I-4).
    pub filesystem_write_performed: bool,
    /// Whether persistence was performed (always false in I-4).
    pub persistence_performed: bool,
    /// Whether enforcement was performed (always false in I-4).
    pub enforcement_performed: bool,
    /// Whether any kernel mutation was performed (always false in I-4).
    pub mutation_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Bridge a single observer event into a ledger bridge record.
///
/// The record is an internal model object — it is never written to disk.
/// `combined_bytes` is computed as `rx_bytes + tx_bytes` using saturating
/// addition. The record is always read-only with enforcement inactive.
pub fn bridge_event_to_ledger_record(
    event: &EbpfObserverEvent,
) -> Result<IntergalaxionLedgerBridgeRecord, String> {
    let record = IntergalaxionLedgerBridgeRecord {
        bridge_id: format!("bridge-{}", event.event_id),
        source_event_id: event.event_id,
        source_event_kind: event.event_kind,
        timestamp_ns: event.timestamp_ns,
        pid: event.pid,
        tgid: event.tgid,
        uid: event.uid,
        cgroup_id: event.cgroup_id,
        socket_cookie: event.socket_cookie,
        interface_index: event.interface_index,
        rx_bytes: event.rx_bytes,
        tx_bytes: event.tx_bytes,
        combined_bytes: event.rx_bytes.saturating_add(event.tx_bytes),
        packet_count: event.packet_count,
        attribution_scope: String::from("kernel-observer-model only"),
        read_only: true,
        provenance: String::from("intergalaxion engine model"),
        enforcement_status: String::from("inactive/not implemented"),
    };
    Ok(record)
}

/// Bridge an event batch into a ledger bridge batch.
///
/// Each event is bridged independently. Failed bridges are recorded as
/// errors and skipped. The resulting batch is an internal model — no
/// files are written and no persistence occurs.
pub fn bridge_event_batch_to_ledger_records(
    batch: &EbpfEventBatch,
) -> IntergalaxionLedgerBridgeBatch {
    let mut records = Vec::new();
    let mut skipped = 0usize;
    let mut errors = Vec::new();

    for event in &batch.events {
        match bridge_event_to_ledger_record(event) {
            Ok(record) => records.push(record),
            Err(err) => {
                skipped += 1;
                errors.push(err);
            }
        }
    }

    IntergalaxionLedgerBridgeBatch {
        source: batch.source,
        records,
        skipped_events: skipped,
        bridge_errors: errors,
        filesystem_write_performed: false,
        persistence_performed: false,
        enforcement_performed: false,
        mutation_performed: false,
    }
}

/// Validate that a ledger bridge record is safe for the model-only phase.
///
/// # Rejected conditions
///
/// * `read_only` is not `true`
/// * `enforcement_status` is not "inactive/not implemented"
/// * `combined_bytes` does not equal `rx_bytes.saturating_add(tx_bytes)`
pub fn validate_bridge_record(record: &IntergalaxionLedgerBridgeRecord) -> Result<(), String> {
    if !record.read_only {
        return Err("read_only must be true".to_string());
    }
    if record.enforcement_status != "inactive/not implemented" {
        return Err(format!(
            "enforcement_status must be 'inactive/not implemented', got '{}'",
            record.enforcement_status
        ));
    }
    let expected_combined = record.rx_bytes.saturating_add(record.tx_bytes);
    if record.combined_bytes != expected_combined {
        return Err(format!(
            "combined_bytes mismatch: expected {}, got {}",
            expected_combined, record.combined_bytes
        ));
    }
    Ok(())
}
