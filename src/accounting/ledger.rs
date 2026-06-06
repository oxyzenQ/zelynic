// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure local ledger data model for v2.9 Network Accounting Lab.
//!
//! This module defines structured types for a future persistent usage ledger
//! and provides pure functions for ledger construction, JSON serialization/
//! deserialization, and human-readable rendering. It performs **no** filesystem
//! reads, **no** filesystem writes, **no** live system reads, **no** enforcement,
//! **no** quota management, **no** network blocking, **no** eBPF, **no** PID
//! movement, and **no** cgroup writes.
//!
//! # Safety
//!
//! - No filesystem I/O — serialization produces/consumes strings only.
//! - No live `/proc/net/dev` or sysfs reads.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//!
//! # Phase 6 Scope
//!
//! Phase 6 implements the pure data model and JSON serialization tests.
//! No filesystem persistence occurs. The ledger exists only in memory and
//! as JSON strings during tests.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// Schema version supported by this module.
pub const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Error type for ledger deserialization and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// JSON parse error.
    JsonParse(String),
    /// Schema version is not supported.
    UnsupportedSchemaVersion(u32),
    /// A required field is missing or invalid.
    Validation(String),
    /// An entry violates safety constraints.
    SafetyViolation(String),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::JsonParse(msg) => write!(f, "JSON parse error: {}", msg),
            LedgerError::UnsupportedSchemaVersion(v) => write!(
                f,
                "unsupported schema version: {} (supported: {})",
                v, SUPPORTED_SCHEMA_VERSION
            ),
            LedgerError::Validation(msg) => write!(f, "validation error: {}", msg),
            LedgerError::SafetyViolation(msg) => write!(f, "safety violation: {}", msg),
        }
    }
}

/// Per-entry reset detail for honest counter decrease reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetDetail {
    /// Which counter reset ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets").
    pub counter_field: String,
    /// Counter value in the previous snapshot.
    pub start_value: u64,
    /// Counter value in the current snapshot (lower than start).
    pub end_value: u64,
    /// Optional human-readable reason hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// A single entry in the local usage ledger.
///
/// Each entry represents either a raw counter snapshot or a computed session
/// delta. Entries are ordered chronologically within the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    /// Unique identifier for this entry (UUID-like string).
    pub entry_id: String,
    /// When this entry was recorded (ISO 8601 timestamp, caller-provided).
    pub timestamp: String,
    /// Entry type: "snapshot" or "delta".
    pub entry_type: String,
    /// Provenance marker (e.g., "model-only", "parsed_sample").
    pub source_label: String,
    /// Network interface name.
    pub interface: String,
    /// Received bytes.
    pub rx_bytes: u64,
    /// Transmitted bytes.
    pub tx_bytes: u64,
    /// Combined bytes (rx + tx, saturating).
    pub combined_bytes: u64,
    /// Received packets (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_packets: Option<u64>,
    /// Transmitted packets (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_packets: Option<u64>,
    /// Whether a counter reset/decrease was detected.
    pub reset_detected: bool,
    /// Reset details if reset_detected is true.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reset_details: Vec<ResetDetail>,
    /// Always true — entries are observational only.
    pub read_only: bool,
    /// Provenance description.
    pub provenance: String,
    /// Attribution scope: always "interface-level only".
    pub attribution_scope: String,
    /// Enforcement status: always "inactive/not implemented".
    pub enforcement_status: String,
}

impl LedgerEntry {
    /// Validate safety constraints on this entry.
    fn validate_safety(&self) -> Result<(), LedgerError> {
        if !self.read_only {
            return Err(LedgerError::SafetyViolation(format!(
                "entry {} has read_only=false, must be true",
                self.entry_id
            )));
        }
        if self.attribution_scope != "interface-level only" {
            return Err(LedgerError::SafetyViolation(format!(
                "entry {} has attribution_scope='{}', must be 'interface-level only'",
                self.entry_id, self.attribution_scope
            )));
        }
        if self.enforcement_status != "inactive/not implemented" {
            return Err(LedgerError::SafetyViolation(format!(
                "entry {} has enforcement_status='{}', must be 'inactive/not implemented'",
                self.entry_id, self.enforcement_status
            )));
        }
        if self.entry_type != "snapshot" && self.entry_type != "delta" {
            return Err(LedgerError::Validation(format!(
                "entry {} has unknown entry_type='{}'",
                self.entry_id, self.entry_type
            )));
        }
        // Validate combined_bytes consistency
        let expected_combined = self.rx_bytes.saturating_add(self.tx_bytes);
        if self.combined_bytes != expected_combined {
            return Err(LedgerError::Validation(format!(
                "entry {} has combined_bytes={} but rx_bytes+tx_bytes={}",
                self.entry_id, self.combined_bytes, expected_combined
            )));
        }
        Ok(())
    }
}

/// The root local usage ledger structure.
///
/// Contains an ordered list of accounting entries for one host/session.
/// The ledger is serialized to JSON for future filesystem persistence
/// (not implemented in phase 6 — serialization produces strings only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ledger {
    /// Schema format version.
    pub schema_version: u32,
    /// Ledger creation timestamp (ISO 8601, caller-provided).
    pub created_at: String,
    /// Last modification timestamp (ISO 8601, caller-provided).
    pub updated_at: String,
    /// Unique host/session identifier (caller-provided, non-sensitive).
    pub host_id: String,
    /// Optional session identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Ordered list of accounting entries.
    pub entries: Vec<LedgerEntry>,
}

impl Ledger {
    /// Validate safety constraints on the entire ledger.
    fn validate_safety(&self) -> Result<(), LedgerError> {
        if self.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(LedgerError::UnsupportedSchemaVersion(self.schema_version));
        }
        for entry in &self.entries {
            entry.validate_safety()?;
        }
        Ok(())
    }
}

/// Create a new empty ledger with the given metadata.
///
/// # Arguments
///
/// * `created_at` - Creation timestamp (ISO 8601 string, caller-provided).
/// * `host_id` - Host/session identifier (caller-provided, non-sensitive).
///
/// # Returns
///
/// A `Ledger` with no entries, schema version 1, and safety fields set.
pub fn new_empty_ledger(created_at: &str, host_id: &str) -> Ledger {
    Ledger {
        schema_version: SUPPORTED_SCHEMA_VERSION,
        created_at: created_at.to_string(),
        updated_at: created_at.to_string(),
        host_id: host_id.to_string(),
        session_id: None,
        entries: Vec::new(),
    }
}

/// Add a snapshot entry to the ledger.
///
/// Creates a new `LedgerEntry` with `entry_type = "snapshot"` and appends it
/// to the ledger's entries list. Updates the `updated_at` timestamp.
#[allow(clippy::too_many_arguments)]
pub fn add_snapshot_entry(
    ledger: &mut Ledger,
    entry_id: &str,
    timestamp: &str,
    source_label: &str,
    interface: &str,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: Option<u64>,
    tx_packets: Option<u64>,
    reset_detected: bool,
    reset_details: Vec<ResetDetail>,
) {
    let combined = rx_bytes.saturating_add(tx_bytes);
    ledger.entries.push(LedgerEntry {
        entry_id: entry_id.to_string(),
        timestamp: timestamp.to_string(),
        entry_type: "snapshot".to_string(),
        source_label: source_label.to_string(),
        interface: interface.to_string(),
        rx_bytes,
        tx_bytes,
        combined_bytes: combined,
        rx_packets,
        tx_packets,
        reset_detected,
        reset_details,
        read_only: true,
        provenance: "read-only parsed snapshot".to_string(),
        attribution_scope: "interface-level only".to_string(),
        enforcement_status: "inactive/not implemented".to_string(),
    });
    ledger.updated_at = timestamp.to_string();
}

/// Add a session delta entry to the ledger.
///
/// Creates a new `LedgerEntry` with `entry_type = "delta"` and appends it
/// to the ledger's entries list. Updates the `updated_at` timestamp.
#[allow(clippy::too_many_arguments)]
pub fn add_session_delta_entry(
    ledger: &mut Ledger,
    entry_id: &str,
    timestamp: &str,
    source_label: &str,
    interface: &str,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: Option<u64>,
    tx_packets: Option<u64>,
    reset_detected: bool,
    reset_details: Vec<ResetDetail>,
) {
    let combined = rx_bytes.saturating_add(tx_bytes);
    ledger.entries.push(LedgerEntry {
        entry_id: entry_id.to_string(),
        timestamp: timestamp.to_string(),
        entry_type: "delta".to_string(),
        source_label: source_label.to_string(),
        interface: interface.to_string(),
        rx_bytes,
        tx_bytes,
        combined_bytes: combined,
        rx_packets,
        tx_packets,
        reset_detected,
        reset_details,
        read_only: true,
        provenance: "read-only session delta model".to_string(),
        attribution_scope: "interface-level only".to_string(),
        enforcement_status: "inactive/not implemented".to_string(),
    });
    ledger.updated_at = timestamp.to_string();
}

/// Serialize a ledger to a deterministic JSON string.
///
/// Uses `serde_json::to_string_pretty` for human-readable output.
/// Returns an error if serialization fails (should not happen for valid
/// ledger structs).
pub fn serialize_ledger_to_json(ledger: &Ledger) -> Result<String, LedgerError> {
    serde_json::to_string_pretty(ledger)
        .map_err(|e| LedgerError::JsonParse(format!("serialization failed: {}", e)))
}

/// Deserialize a ledger from a JSON string.
///
/// Validates schema version, required fields, and safety constraints.
/// Returns an error if the JSON is malformed, the schema version is
/// unsupported, required fields are missing, or safety constraints are
/// violated.
pub fn deserialize_ledger_from_json(json: &str) -> Result<Ledger, LedgerError> {
    let ledger: Ledger =
        serde_json::from_str(json).map_err(|e| LedgerError::JsonParse(format!("{}", e)))?;

    // Validate schema version
    if ledger.schema_version != SUPPORTED_SCHEMA_VERSION {
        return Err(LedgerError::UnsupportedSchemaVersion(ledger.schema_version));
    }

    // Validate all entries
    for entry in &ledger.entries {
        entry.validate_safety()?;
    }

    Ok(ledger)
}

/// Render a ledger summary as a human-readable string.
///
/// The output includes comprehensive safety disclaimers matching the
/// existing v2.9 accounting pattern.
pub fn render_ledger_summary(ledger: &Ledger) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v2.9 local ledger summary (local ledger model only)\n");
    out.push_str(&format!("Schema version: {}\n", ledger.schema_version));
    out.push_str(&format!("Created: {}\n", ledger.created_at));
    out.push_str(&format!("Updated: {}\n", ledger.updated_at));
    out.push_str(&format!("Host: {}\n", ledger.host_id));
    if let Some(ref sid) = ledger.session_id {
        out.push_str(&format!("Session: {}\n", sid));
    }
    out.push_str(&format!("Entries: {}\n", ledger.entries.len()));
    out.push('\n');

    // Per-interface summary
    let mut interfaces: Vec<String> = Vec::new();
    let mut reset_count = 0usize;
    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;

    for entry in &ledger.entries {
        if !interfaces.contains(&entry.interface) {
            interfaces.push(entry.interface.clone());
        }
        if entry.reset_detected {
            reset_count += 1;
        }
        total_rx = total_rx.saturating_add(entry.rx_bytes);
        total_tx = total_tx.saturating_add(entry.tx_bytes);
    }

    if interfaces.is_empty() {
        out.push_str("No entries recorded.\n");
    } else {
        out.push_str(&format!("Interfaces: {}\n", interfaces.join(", ")));
        out.push_str(&format!(
            "Total RX: {} bytes  Total TX: {} bytes\n",
            total_rx, total_tx
        ));
    }

    if reset_count > 0 {
        out.push_str(&format!("Counter resets detected: {}\n", reset_count));
    }
    out.push('\n');

    // Safety disclaimers
    out.push_str("Safety disclaimers:\n");
    out.push_str("  - local ledger model only\n");
    out.push_str("  - no filesystem write was performed\n");
    out.push_str("  - no live /proc or sysfs read was performed\n");
    out.push_str("  - interface-level only (not per-app attribution)\n");
    out.push_str("  - quota enforcement: inactive/not implemented\n");
    out.push_str("  - network blocking: inactive/not implemented\n");
    out.push_str("  - no limiter attach performed\n");
    out.push_str("  - no nft/tc/Zelynic state mutation performed\n");

    out
}
