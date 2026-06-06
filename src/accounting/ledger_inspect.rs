// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Read-only ledger inspect model for v2.9 Network Accounting Lab.
//!
//! This module provides a pure inspection model that computes aggregate
//! statistics from a `Ledger` for future `zelynic usage --ledger` and
//! `zelynic ledger inspect` display contracts. It performs **no**
//! filesystem reads, **no** filesystem writes, **no** live system reads,
//! **no** enforcement, **no** quota management, **no** network blocking,
//! **no** eBPF, **no** PID movement, and **no** cgroup writes.
//!
//! # Safety
//!
//! - No filesystem I/O — operates on in-memory `Ledger` structs only.
//! - No live `/proc/net/dev` or sysfs reads.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//!
//! # Phase 7 Scope
//!
//! Phase 7 implements the inspect/render model. No filesystem persistence
//! occurs. The inspect exists only in memory during tests and future
//! display contracts.

#![allow(dead_code)]

use super::ledger::Ledger;
use std::collections::BTreeSet;

/// Aggregate statistics computed from a ledger for inspection purposes.
///
/// All totals use saturating arithmetic to avoid overflow panics.
/// Interfaces are sorted deterministically via BTreeSet for consistent
/// output ordering regardless of entry insertion order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerInspect {
    /// Total number of entries in the ledger.
    pub total_entries: usize,
    /// Number of snapshot entries.
    pub snapshot_count: usize,
    /// Number of delta entries.
    pub delta_count: usize,
    /// Aggregate RX bytes across all entries (saturating).
    pub total_rx_bytes: u64,
    /// Aggregate TX bytes across all entries (saturating).
    pub total_tx_bytes: u64,
    /// Aggregate combined bytes across all entries (saturating).
    pub total_combined_bytes: u64,
    /// Unique interface names in sorted (deterministic) order.
    pub interfaces: Vec<String>,
    /// Number of entries with reset_detected == true.
    pub reset_warning_count: usize,
    /// Schema version from the ledger.
    pub schema_version: u32,
    /// Ledger creation timestamp.
    pub created_at: String,
    /// Last modification timestamp.
    pub updated_at: String,
    /// Host identifier.
    pub host_id: String,
    /// Optional session identifier.
    pub session_id: Option<String>,
    /// Provenance description derived from entry composition.
    pub provenance: String,
    /// Attribution scope: always "interface-level only".
    pub attribution_scope: String,
    /// Enforcement status: always "inactive/not implemented".
    pub enforcement_status: String,
    /// Read-only flag: true if all entries have read_only == true.
    pub read_only: bool,
}

/// Build a ledger inspect summary from a ledger.
///
/// Computes aggregate statistics using saturating arithmetic and collects
/// interface names in deterministic sorted order via BTreeSet. The
/// provenance is derived from the entry composition (snapshot/delta counts).
///
/// # Arguments
///
/// * `ledger` - A reference to the `Ledger` to inspect.
///
/// # Returns
///
/// A `LedgerInspect` with aggregate statistics, sorted interfaces, and
/// safety metadata.
pub fn build_ledger_inspect(ledger: &Ledger) -> LedgerInspect {
    let mut snapshot_count = 0usize;
    let mut delta_count = 0usize;
    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;
    let mut total_combined: u64 = 0;
    let mut interfaces = BTreeSet::new();
    let mut reset_warning_count = 0usize;
    let mut all_read_only = true;

    for entry in &ledger.entries {
        match entry.entry_type.as_str() {
            "snapshot" => snapshot_count += 1,
            "delta" => delta_count += 1,
            _ => {}
        }
        total_rx = total_rx.saturating_add(entry.rx_bytes);
        total_tx = total_tx.saturating_add(entry.tx_bytes);
        total_combined = total_combined.saturating_add(entry.combined_bytes);
        interfaces.insert(entry.interface.clone());
        if entry.reset_detected {
            reset_warning_count += 1;
        }
        if !entry.read_only {
            all_read_only = false;
        }
    }

    // BTreeSet produces deterministic sorted order
    let sorted_interfaces: Vec<String> = interfaces.into_iter().collect();

    // Derive provenance from entry composition
    let provenance = if ledger.entries.is_empty() {
        "read-only ledger inspect model (empty)".to_string()
    } else if snapshot_count > 0 && delta_count > 0 {
        format!(
            "read-only ledger inspect model ({} snapshots, {} deltas)",
            snapshot_count, delta_count
        )
    } else if snapshot_count > 0 {
        format!(
            "read-only ledger inspect model ({} snapshots)",
            snapshot_count
        )
    } else {
        format!("read-only ledger inspect model ({} deltas)", delta_count)
    };

    LedgerInspect {
        total_entries: ledger.entries.len(),
        snapshot_count,
        delta_count,
        total_rx_bytes: total_rx,
        total_tx_bytes: total_tx,
        total_combined_bytes: total_combined,
        interfaces: sorted_interfaces,
        reset_warning_count,
        schema_version: ledger.schema_version,
        created_at: ledger.created_at.clone(),
        updated_at: ledger.updated_at.clone(),
        host_id: ledger.host_id.clone(),
        session_id: ledger.session_id.clone(),
        provenance,
        attribution_scope: "interface-level only".to_string(),
        enforcement_status: "inactive/not implemented".to_string(),
        read_only: all_read_only,
    }
}

/// Render a ledger inspect summary as a human-readable string.
///
/// The output includes entry breakdown (snapshots/deltas), sorted
/// interface list, aggregate totals (saturating, overflow-safe), reset
/// warning count, and attribution/enforcement metadata.
///
/// # Safety Disclaimers (9 total)
///
/// 1. ledger inspect model only
/// 2. no filesystem read performed
/// 3. no filesystem write performed
/// 4. no live /proc or sysfs read performed
/// 5. interface-level only (not per-app attribution)
/// 6. quota enforcement: inactive/not implemented
/// 7. network blocking: inactive/not implemented
/// 8. no limiter attach performed
/// 9. no nft/tc/Zelynic state mutation performed
pub fn render_ledger_inspect(inspect: &LedgerInspect) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v2.9 ledger inspect (ledger inspect model only)\n");
    out.push_str(&format!("Schema version: {}\n", inspect.schema_version));
    out.push_str(&format!("Created: {}\n", inspect.created_at));
    out.push_str(&format!("Updated: {}\n", inspect.updated_at));
    out.push_str(&format!("Host: {}\n", inspect.host_id));
    if let Some(ref sid) = inspect.session_id {
        out.push_str(&format!("Session: {}\n", sid));
    }
    out.push_str(&format!("Provenance: {}\n", inspect.provenance));
    out.push('\n');

    // Entry breakdown
    out.push_str(&format!(
        "Entries: {} ({} snapshots, {} deltas)\n",
        inspect.total_entries, inspect.snapshot_count, inspect.delta_count
    ));
    out.push('\n');

    // Interfaces (sorted, deterministic)
    if inspect.interfaces.is_empty() {
        out.push_str("No interfaces observed.\n");
    } else {
        out.push_str(&format!("Interfaces: {}\n", inspect.interfaces.join(", ")));
    }
    out.push('\n');

    // Aggregate totals (saturating, overflow-safe)
    out.push_str("Aggregate totals (saturating, overflow-safe):\n");
    out.push_str(&format!(
        "  RX: {} bytes  TX: {} bytes  Combined: {} bytes\n",
        inspect.total_rx_bytes, inspect.total_tx_bytes, inspect.total_combined_bytes
    ));
    out.push('\n');

    // Reset warnings
    out.push_str(&format!(
        "Reset warnings: {}\n",
        inspect.reset_warning_count
    ));
    out.push('\n');

    // Attribution and enforcement metadata
    out.push_str(&format!(
        "Attribution scope: {} (this is not per-app attribution)\n",
        inspect.attribution_scope
    ));
    out.push_str(&format!(
        "Enforcement status: {} (no quota enforcement active)\n",
        inspect.enforcement_status
    ));
    out.push_str(&format!("Read-only: {}\n", inspect.read_only));
    out.push('\n');

    // 9 safety disclaimers
    out.push_str("Safety disclaimers:\n");
    out.push_str("  - ledger inspect model only\n");
    out.push_str("  - no filesystem read performed\n");
    out.push_str("  - no filesystem write performed\n");
    out.push_str("  - no live /proc or sysfs read performed\n");
    out.push_str("  - interface-level only (not per-app attribution)\n");
    out.push_str("  - quota enforcement: inactive/not implemented\n");
    out.push_str("  - network blocking: inactive/not implemented\n");
    out.push_str("  - no limiter attach performed\n");
    out.push_str("  - no nft/tc/Zelynic state mutation performed\n");

    out
}
