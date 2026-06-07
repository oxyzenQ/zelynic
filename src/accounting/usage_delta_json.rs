// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure JSON output model for future `zelynic usage --sample --delta --json` (v3.0 phase 14).
//!
//! This module provides a pure Rust data model and serde serialization for the delta
//! JSON output schema defined in the phase 13 contract
//! (`docs/v3.0-phase-13-usage-delta-json-output-contract.md`). No CLI flag is
//! registered. No JSON output is wired to the CLI. No live filesystem reads are
//! performed by this module. All data is built from `SessionDelta` and two
//! `InterfaceCounterSnapshot` values passed by the caller.
//!
//! # Safety
//!
//! - No eBPF program loading/attachment.
//! - No quota enforcement.
//! - No network traffic blocking.
//! - No limiter attach.
//! - No nftables/tc rule mutation.
//! - No Zelynic runtime state mutation.
//! - No filesystem persistence.
//! - No ledger file read/write.
//! - No PID movement.
//! - No `cgroup.procs` write.
//! - No sysfs/cgroup access.
//! - No CLI command is registered.
//! - No live `/proc/net/dev` reads in this module.
//!
//! # Honesty
//!
//! - Delta JSON data is interface-level aggregate counters, **not** per-app.
//! - All constant boolean honesty flags are frozen in v3.0.
//! - Dynamic flags: `live_read_performed`, `read_count` vary by error scenario.
//! - No wall-clock timestamps are silently generated.
//! - Counter reset warnings remain warnings, never fatal.

#![allow(dead_code)]

use super::interface_counters::InterfaceCounterSnapshot;
use super::live_proc_net_dev::DEFAULT_LIVE_SOURCE_PATH;
use super::session_delta::{build_session_delta, CounterResetWarning};
use serde::{Deserialize, Serialize};

/// Current delta JSON schema version.
pub const DELTA_SCHEMA_VERSION: u32 = 1;

/// Command string for the delta JSON output.
pub const COMMAND_USAGE_SAMPLE_DELTA_JSON: &str = "usage --sample --delta --json";

/// Default delta wait between samples in milliseconds.
pub const DEFAULT_DELTA_WAIT_MS: u32 = 1000;

/// Sample mode string for delta output.
pub const SAMPLE_MODE_DELTA: &str = "delta";

/// Source label for delta JSON output.
pub const SOURCE_LABEL_DELTA_JSON: &str = "live_proc_net_dev";

/// Sample status string for a successful sample.
const SAMPLE_STATUS_SUCCESS: &str = "success";

/// Sample status string for a failed sample.
const SAMPLE_STATUS_ERROR: &str = "error";

// ── Per-interface delta JSON object ──────────────────────────────────

/// Per-interface delta data in the JSON output.
///
/// Contains start/end counters, computed deltas, and detection flags for
/// counter resets, interface additions, and interface removals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaJsonInterface {
    /// Interface name (e.g., `wlan0`, `eth0`, `lo`).
    pub name: String,
    /// Whether this is the loopback interface.
    pub loopback: bool,
    /// RX byte counter from the start sample.
    pub start_rx_bytes: u64,
    /// TX byte counter from the start sample.
    pub start_tx_bytes: u64,
    /// RX byte counter from the end sample.
    pub end_rx_bytes: u64,
    /// TX byte counter from the end sample.
    pub end_tx_bytes: u64,
    /// RX byte delta (end - start, or 0 if counter reset detected).
    pub delta_rx_bytes: u64,
    /// TX byte delta (end - start, or 0 if counter reset detected).
    pub delta_tx_bytes: u64,
    /// Combined delta (delta_rx_bytes + delta_tx_bytes, saturating).
    pub delta_combined_bytes: u64,
    /// RX packet counter from the start sample.
    pub start_rx_packets: u64,
    /// TX packet counter from the start sample.
    pub start_tx_packets: u64,
    /// RX packet counter from the end sample.
    pub end_rx_packets: u64,
    /// TX packet counter from the end sample.
    pub end_tx_packets: u64,
    /// RX packet delta (end - start, or 0 if counter reset detected).
    pub delta_rx_packets: u64,
    /// TX packet delta (end - start, or 0 if counter reset detected).
    pub delta_tx_packets: u64,
    /// True if any counter decreased between start and end.
    pub counter_reset_detected: bool,
    /// True if interface was not in the start sample but is in the end sample.
    pub interface_added: bool,
    /// True if interface was in the start sample but not in the end sample.
    pub interface_removed: bool,
}

// ── Sample summary object ──────────────────────────────────────────

/// Summary data for a single sample (start or end).
///
/// Contains only summary-level counts, not per-interface data.
/// Per-interface data is in the `interfaces` array.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaJsonSampleSummary {
    /// `"success"` if the read and parse succeeded, `"error"` if failed.
    pub status: String,
    /// Number of interfaces in this sample. `0` on error.
    pub interface_count: u64,
    /// Sum of all interface RX byte counters in this sample. `0` on error.
    pub total_rx_bytes: u64,
    /// Sum of all interface TX byte counters in this sample. `0` on error.
    pub total_tx_bytes: u64,
    /// Sum of all interface combined byte counters in this sample. `0` on error.
    pub total_combined_bytes: u64,
}

// ── Totals object ───────────────────────────────────────────────────

/// Aggregate delta totals in the JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaJsonTotals {
    /// Saturating sum of all interface `delta_rx_bytes`.
    pub total_delta_rx_bytes: u64,
    /// Saturating sum of all interface `delta_tx_bytes`.
    pub total_delta_tx_bytes: u64,
    /// Saturating sum of all interface `delta_combined_bytes`.
    pub total_delta_combined_bytes: u64,
    /// Total number of interfaces in the delta output.
    pub interface_count: u64,
    /// Number of loopback interfaces (typically 0 or 1).
    pub loopback_interface_count: u64,
    /// Number of non-loopback interfaces.
    pub non_loopback_interface_count: u64,
    /// Number of interfaces where `counter_reset_detected` is `true`.
    pub counter_reset_count: u64,
    /// Number of interfaces where `interface_added` is `true`.
    pub interface_added_count: u64,
    /// Number of interfaces where `interface_removed` is `true`.
    pub interface_removed_count: u64,
}

// ── Honesty flags ─────────────────────────────────────────────────

/// Honesty flags for delta JSON output.
///
/// Contains 19 flags: 12 constant boolean flags from the snapshot JSON contract,
/// plus 7 delta-specific flags. Dynamic flags (`live_read_performed`, `read_count`)
/// vary by error scenario.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaJsonHonesty {
    /// Data is interface-level aggregate counters. Always `true`.
    pub interface_level_only: bool,
    /// Per-process/per-app traffic attribution is not available. Always `false`.
    pub per_app_attribution: bool,
    /// No quota enforcement is implemented or active. Always `false`.
    pub quota_enforcement_active: bool,
    /// No network traffic is blocked, dropped, or rejected. Always `false`.
    pub network_blocking_active: bool,
    /// No rate limiter is attached. Always `false`.
    pub limiter_attach_performed: bool,
    /// No nftables/tc/Zelynic state mutation. Always `false`.
    pub nft_tc_state_mutation_performed: bool,
    /// No ledger file is read or written. Always `false`.
    pub ledger_persistence_performed: bool,
    /// No eBPF programs are loaded or attached. Always `false`.
    pub ebpf_used: bool,
    /// No cgroup creation, modification, or cgroup.procs write. Always `false`.
    pub cgroup_mutation_performed: bool,
    /// No PIDs are moved between cgroups. Always `false`.
    pub pid_movement_performed: bool,
    /// No filesystem write is performed. Always `false`.
    pub filesystem_write_performed: bool,
    /// No system state mutation of any kind. Always `false`.
    pub state_mutation_performed: bool,
    /// This is a delta JSON output. Always `true`.
    pub delta_json_output: bool,
    /// Whether at least one live read was performed. `false` if first read failed.
    pub live_read_performed: bool,
    /// Number of reads that succeeded: `0`, `1`, or `2`.
    pub read_count: u32,
    /// Command exits after producing output. Always `true`.
    pub single_shot: bool,
    /// No continuous monitoring or watch mode. Always `false`.
    pub loop_watch_mode: bool,
    /// The interval between samples is not user-configurable. Always `false`.
    pub configurable_interval: bool,
    /// No interface filtering is applied. Always `false`.
    pub interface_filtering: bool,
    /// No arbitrary file path was read. Always `false`.
    pub arbitrary_path_read: bool,
}

// ── Error object ──────────────────────────────────────────────────

/// Error information in the delta JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeltaJsonError {
    /// Canonical error type.
    #[serde(rename = "type")]
    pub error_type: DeltaJsonErrorType,
    /// Human-readable error message.
    pub message: String,
}

/// Error type identifiers for delta JSON output.
///
/// Reuses the same error types as the snapshot JSON contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeltaJsonErrorType {
    /// `/proc/net/dev` could not be read.
    #[serde(rename = "read_error")]
    Read,
    /// Content was read but could not be parsed.
    #[serde(rename = "parse_error")]
    Parse,
    /// A flag combination is not supported.
    #[serde(rename = "unsupported_flag_error")]
    UnsupportedFlag,
}

impl std::fmt::Display for DeltaJsonErrorType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeltaJsonErrorType::Read => write!(f, "read_error"),
            DeltaJsonErrorType::Parse => write!(f, "parse_error"),
            DeltaJsonErrorType::UnsupportedFlag => write!(f, "unsupported_flag_error"),
        }
    }
}

// ── Top-level output ───────────────────────────────────────────────

/// The top-level JSON output model for `usage --sample --delta --json`.
///
/// This struct represents the complete delta JSON response including success
/// and error variants. In success, `error` is `None`. In error, `error` is
/// `Some(...)` and data fields are zeroed/empty.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageDeltaJsonOutput {
    /// Schema version for forward compatibility. Currently `1`.
    pub schema_version: u32,
    /// The command that produced this output.
    pub command: String,
    /// Filesystem path of the data source. Always `"/proc/net/dev"`.
    pub source_path: String,
    /// Source identifier. Always `"live_proc_net_dev"`.
    pub source_label: String,
    /// Sampling mode. Always `"delta"`.
    pub sample_mode: String,
    /// Number of samples taken. `2` on full success, `1` if second failed, `0` if first failed.
    pub sample_count: u32,
    /// Wait duration between samples in milliseconds. Fixed at `1000`.
    pub delta_wait_ms: u32,
    /// Number of successful reads. `2` on success, `1` if second failed, `0` if first failed.
    pub read_count: u32,
    /// Start snapshot summary. `null` if first read failed.
    pub start_sample: Option<DeltaJsonSampleSummary>,
    /// End snapshot summary. `null` if second read failed or first read failed.
    pub end_sample: Option<DeltaJsonSampleSummary>,
    /// Per-interface delta data. Empty array on error.
    pub interfaces: Vec<DeltaJsonInterface>,
    /// Aggregate delta totals. Zero totals on error.
    pub totals: DeltaJsonTotals,
    /// Warning messages. Always includes default warnings.
    pub warnings: Vec<String>,
    /// Honesty flags. Present in every JSON response.
    pub honesty: DeltaJsonHonesty,
    /// Error information. `null` on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<DeltaJsonError>,
}

// ── Builder functions ─────────────────────────────────────────────

/// Returns the 13 default warning messages for delta JSON output.
///
/// These warnings are always present in both success and error outputs.
pub fn delta_default_warnings() -> Vec<String> {
    vec![
        "counters may reset after reboot or interface reset".to_string(),
        "delta may be incomplete when counter reset is detected".to_string(),
        "interface-level only, not per-app attribution".to_string(),
        "no quota enforcement".to_string(),
        "no network blocking".to_string(),
        "no limiter attach".to_string(),
        "no nft/tc mutation".to_string(),
        "no ledger persistence".to_string(),
        "no eBPF".to_string(),
        "no cgroup mutation".to_string(),
        "no PID movement".to_string(),
        "no filesystem write".to_string(),
        "no state mutation".to_string(),
    ]
}

/// Returns default honesty flags for delta JSON success output.
///
/// `live_read_performed = true`, `read_count = 2`.
pub fn delta_success_honesty_flags() -> DeltaJsonHonesty {
    DeltaJsonHonesty {
        interface_level_only: true,
        per_app_attribution: false,
        quota_enforcement_active: false,
        network_blocking_active: false,
        limiter_attach_performed: false,
        nft_tc_state_mutation_performed: false,
        ledger_persistence_performed: false,
        ebpf_used: false,
        cgroup_mutation_performed: false,
        pid_movement_performed: false,
        filesystem_write_performed: false,
        state_mutation_performed: false,
        delta_json_output: true,
        live_read_performed: true,
        read_count: 2,
        single_shot: true,
        loop_watch_mode: false,
        configurable_interval: false,
        interface_filtering: false,
        arbitrary_path_read: false,
    }
}

/// Returns error honesty flags for first-read failure.
///
/// `live_read_performed = false`, `read_count = 0`.
pub fn delta_error_first_read_honesty() -> DeltaJsonHonesty {
    DeltaJsonHonesty {
        live_read_performed: false,
        read_count: 0,
        ..delta_success_honesty_flags()
    }
}

/// Returns error honesty flags for second-read failure.
///
/// `live_read_performed = true`, `read_count = 1`.
pub fn delta_error_second_read_honesty() -> DeltaJsonHonesty {
    DeltaJsonHonesty {
        live_read_performed: true,
        read_count: 1,
        ..delta_success_honesty_flags()
    }
}

/// Returns error honesty flags for unsupported flag error.
///
/// `live_read_performed = false`, `read_count = 0`, `sample_count = 0`.
pub fn delta_error_unsupported_flag_honesty() -> DeltaJsonHonesty {
    DeltaJsonHonesty {
        live_read_performed: false,
        read_count: 0,
        ..delta_success_honesty_flags()
    }
}

/// Returns zero delta totals.
fn zero_totals() -> DeltaJsonTotals {
    DeltaJsonTotals {
        total_delta_rx_bytes: 0,
        total_delta_tx_bytes: 0,
        total_delta_combined_bytes: 0,
        interface_count: 0,
        loopback_interface_count: 0,
        non_loopback_interface_count: 0,
        counter_reset_count: 0,
        interface_added_count: 0,
        interface_removed_count: 0,
    }
}

/// Builds a sample summary from an `InterfaceCounterSnapshot`.
fn build_sample_summary(
    snapshot: &InterfaceCounterSnapshot,
    status: &str,
) -> DeltaJsonSampleSummary {
    let total_rx: u64 = snapshot
        .interfaces
        .iter()
        .map(|i| i.rx_bytes)
        .fold(0u64, u64::saturating_add);
    let total_tx: u64 = snapshot
        .interfaces
        .iter()
        .map(|i| i.tx_bytes)
        .fold(0u64, u64::saturating_add);
    DeltaJsonSampleSummary {
        status: status.to_string(),
        interface_count: snapshot.interfaces.len() as u64,
        total_rx_bytes: total_rx,
        total_tx_bytes: total_tx,
        total_combined_bytes: total_rx.saturating_add(total_tx),
    }
}

/// Generates counter reset warning strings for the warnings array.
///
/// Produces strings like:
/// `"counter reset detected on wlan0: rx_bytes (start=1000, end=500)"`
fn build_reset_warning_strings(warnings: &[CounterResetWarning]) -> Vec<String> {
    warnings
        .iter()
        .map(|w| {
            format!(
                "counter reset detected on {}: {} (start={}, end={})",
                w.interface, w.counter_field, w.start_value, w.end_value
            )
        })
        .collect()
}

/// Build a successful `UsageDeltaJsonOutput` from two snapshots.
///
/// Computes the session delta from start and end snapshots and builds the
/// complete delta JSON model including interfaces, totals, warnings, and
/// honesty flags.
///
/// # Arguments
///
/// * `start` - The earlier counter snapshot.
/// * `end` - The later counter snapshot.
///
/// # Returns
///
/// A `UsageDeltaJsonOutput` ready for JSON serialization.
pub fn build_delta_json_success(
    start: &InterfaceCounterSnapshot,
    end: &InterfaceCounterSnapshot,
) -> UsageDeltaJsonOutput {
    let session_delta = build_session_delta(start, end);

    // Build per-interface delta JSON objects
    let mut interfaces: Vec<DeltaJsonInterface> = Vec::new();
    let mut total_delta_rx: u64 = 0;
    let mut total_delta_tx: u64 = 0;
    let mut loopback_count: u64 = 0;
    let mut non_loopback_count: u64 = 0;
    let mut reset_count: u64 = 0;
    let mut added_count: u64 = 0;
    let mut removed_count: u64 = 0;

    for row in &session_delta.rows {
        let start_iface = start.get(&row.interface);
        let end_iface = end.get(&row.interface);

        let start_rx = start_iface.map_or(0, |i| i.rx_bytes);
        let start_tx = start_iface.map_or(0, |i| i.tx_bytes);
        let end_rx = end_iface.map_or(0, |i| i.rx_bytes);
        let end_tx = end_iface.map_or(0, |i| i.tx_bytes);
        let start_rx_packets = start_iface.map_or(0, |i| i.rx_packets);
        let start_tx_packets = start_iface.map_or(0, |i| i.tx_packets);
        let end_rx_packets = end_iface.map_or(0, |i| i.rx_packets);
        let end_tx_packets = end_iface.map_or(0, |i| i.tx_packets);

        let is_loopback = end_iface.or(start_iface).is_some_and(|i| i.is_loopback());

        let has_reset =
            row.rx_reset || row.tx_reset || row.rx_packets_reset || row.tx_packets_reset;

        let is_added = !row.present_in_start && row.present_in_end;
        let is_removed = row.present_in_start && !row.present_in_end;

        if is_loopback {
            loopback_count += 1;
        } else {
            non_loopback_count += 1;
        }
        if has_reset {
            reset_count += 1;
        }
        if is_added {
            added_count += 1;
        }
        if is_removed {
            removed_count += 1;
        }

        total_delta_rx = total_delta_rx.saturating_add(row.rx_delta_bytes);
        total_delta_tx = total_delta_tx.saturating_add(row.tx_delta_bytes);

        interfaces.push(DeltaJsonInterface {
            name: row.interface.clone(),
            loopback: is_loopback,
            start_rx_bytes: start_rx,
            start_tx_bytes: start_tx,
            end_rx_bytes: end_rx,
            end_tx_bytes: end_tx,
            delta_rx_bytes: row.rx_delta_bytes,
            delta_tx_bytes: row.tx_delta_bytes,
            delta_combined_bytes: row.combined_delta_bytes,
            start_rx_packets,
            start_tx_packets,
            end_rx_packets,
            end_tx_packets,
            delta_rx_packets: row.rx_delta_packets,
            delta_tx_packets: row.tx_delta_packets,
            counter_reset_detected: has_reset,
            interface_added: is_added,
            interface_removed: is_removed,
        });
    }

    let total_combined = total_delta_rx.saturating_add(total_delta_tx);

    // Build warnings: default + counter reset warnings
    let mut warnings = delta_default_warnings();
    warnings.extend(build_reset_warning_strings(&session_delta.warnings));

    // Build sample summaries
    let start_summary = build_sample_summary(start, SAMPLE_STATUS_SUCCESS);
    let end_summary = build_sample_summary(end, SAMPLE_STATUS_SUCCESS);
    let iface_count = interfaces.len() as u64;

    UsageDeltaJsonOutput {
        schema_version: DELTA_SCHEMA_VERSION,
        command: COMMAND_USAGE_SAMPLE_DELTA_JSON.to_string(),
        source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
        source_label: SOURCE_LABEL_DELTA_JSON.to_string(),
        sample_mode: SAMPLE_MODE_DELTA.to_string(),
        sample_count: 2,
        delta_wait_ms: DEFAULT_DELTA_WAIT_MS,
        read_count: 2,
        start_sample: Some(start_summary),
        end_sample: Some(end_summary),
        interfaces,
        totals: DeltaJsonTotals {
            total_delta_rx_bytes: total_delta_rx,
            total_delta_tx_bytes: total_delta_tx,
            total_delta_combined_bytes: total_combined,
            interface_count: iface_count,
            loopback_interface_count: loopback_count,
            non_loopback_interface_count: non_loopback_count,
            counter_reset_count: reset_count,
            interface_added_count: added_count,
            interface_removed_count: removed_count,
        },
        warnings,
        honesty: delta_success_honesty_flags(),
        error: None,
    }
}

/// Build an error `UsageDeltaJsonOutput` for a first-read failure.
///
/// `read_count = 0`, `live_read_performed = false`, `sample_count = 0`.
/// Both `start_sample` and `end_sample` are `null`. Interfaces and totals
/// are empty/zero.
pub fn build_delta_json_first_read_error(
    error_type: DeltaJsonErrorType,
    message: &str,
) -> UsageDeltaJsonOutput {
    UsageDeltaJsonOutput {
        schema_version: DELTA_SCHEMA_VERSION,
        command: COMMAND_USAGE_SAMPLE_DELTA_JSON.to_string(),
        source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
        source_label: SOURCE_LABEL_DELTA_JSON.to_string(),
        sample_mode: SAMPLE_MODE_DELTA.to_string(),
        sample_count: 0,
        delta_wait_ms: DEFAULT_DELTA_WAIT_MS,
        read_count: 0,
        start_sample: None,
        end_sample: None,
        interfaces: Vec::new(),
        totals: zero_totals(),
        warnings: delta_default_warnings(),
        honesty: delta_error_first_read_honesty(),
        error: Some(DeltaJsonError {
            error_type,
            message: message.to_string(),
        }),
    }
}

/// Build an error `UsageDeltaJsonOutput` for a second-read failure.
///
/// `read_count = 1`, `live_read_performed = true`, `sample_count = 1`.
/// `start_sample` is populated from the successful first read.
/// `end_sample` is `null`. Interfaces and totals are empty/zero.
pub fn build_delta_json_second_read_error(
    start_snapshot: &InterfaceCounterSnapshot,
    error_type: DeltaJsonErrorType,
    message: &str,
) -> UsageDeltaJsonOutput {
    let start_summary = build_sample_summary(start_snapshot, SAMPLE_STATUS_SUCCESS);
    UsageDeltaJsonOutput {
        schema_version: DELTA_SCHEMA_VERSION,
        command: COMMAND_USAGE_SAMPLE_DELTA_JSON.to_string(),
        source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
        source_label: SOURCE_LABEL_DELTA_JSON.to_string(),
        sample_mode: SAMPLE_MODE_DELTA.to_string(),
        sample_count: 1,
        delta_wait_ms: DEFAULT_DELTA_WAIT_MS,
        read_count: 1,
        start_sample: Some(start_summary),
        end_sample: None,
        interfaces: Vec::new(),
        totals: zero_totals(),
        warnings: delta_default_warnings(),
        honesty: delta_error_second_read_honesty(),
        error: Some(DeltaJsonError {
            error_type,
            message: message.to_string(),
        }),
    }
}

/// Build an error `UsageDeltaJsonOutput` for an unsupported flag error.
///
/// `read_count = 0`, `live_read_performed = false`, `sample_count = 0`.
pub fn build_delta_json_unsupported_flag_error(message: &str) -> UsageDeltaJsonOutput {
    UsageDeltaJsonOutput {
        schema_version: DELTA_SCHEMA_VERSION,
        command: COMMAND_USAGE_SAMPLE_DELTA_JSON.to_string(),
        source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
        source_label: SOURCE_LABEL_DELTA_JSON.to_string(),
        sample_mode: SAMPLE_MODE_DELTA.to_string(),
        sample_count: 0,
        delta_wait_ms: DEFAULT_DELTA_WAIT_MS,
        read_count: 0,
        start_sample: None,
        end_sample: None,
        interfaces: Vec::new(),
        totals: zero_totals(),
        warnings: delta_default_warnings(),
        honesty: delta_error_unsupported_flag_honesty(),
        error: Some(DeltaJsonError {
            error_type: DeltaJsonErrorType::UnsupportedFlag,
            message: message.to_string(),
        }),
    }
}

/// Serialize a `UsageDeltaJsonOutput` to a pretty-printed JSON string.
///
/// Uses deterministic formatting for testability.
pub fn serialize_delta_json(output: &UsageDeltaJsonOutput) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(output)
}

/// Deserialize a JSON string into a `UsageDeltaJsonOutput`.
///
/// Provided for round-trip testing.
pub fn deserialize_delta_json(json_str: &str) -> Result<UsageDeltaJsonOutput, serde_json::Error> {
    serde_json::from_str(json_str)
}
