// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure JSON output model for future `zelynic usage --sample --json` (v3.0 phase 7).
//!
//! This module provides a pure Rust data model and serialization for the JSON output
//! schema defined in the phase 6 contract (`docs/v3.0-phase-6-usage-json-output-contract.md`).
//! No CLI flag is registered. No JSON output is wired to the CLI. No live filesystem
//! reads are performed by this module. All data is built from `InterfaceCounterSnapshot`
//! passed by the caller.
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
//! - Interface counters are aggregate per-interface, **not** per-app.
//! - All 12 honesty boolean flags are constant in v3.0.
//! - Honesty flags are present in both success and error JSON outputs.
//! - `sampled_at` is omitted unless explicitly provided by the caller.
//! - No silent wall-clock timestamp generation.

#![allow(dead_code)]

use super::interface_counters::InterfaceCounterSnapshot;
use super::live_proc_net_dev::{DEFAULT_LIVE_SOURCE_PATH, SOURCE_LABEL_LIVE};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Current JSON schema version.
pub const SCHEMA_VERSION: u32 = 1;

/// Command string identifying the JSON output origin.
pub const COMMAND_USAGE_SAMPLE_JSON: &str = "usage --sample --json";

/// Per-interface data in the JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageJsonInterface {
    /// Interface name (e.g., `wlan0`, `eth0`, `lo`).
    pub name: String,
    /// Cumulative received bytes since boot/interface-up.
    pub rx_bytes: u64,
    /// Cumulative transmitted bytes since boot/interface-up.
    pub tx_bytes: u64,
    /// Combined RX + TX bytes (saturating).
    pub combined_bytes: u64,
    /// Cumulative received packets since boot/interface-up.
    pub rx_packets: u64,
    /// Cumulative transmitted packets since boot/interface-up.
    pub tx_packets: u64,
    /// Whether this is the loopback interface.
    pub loopback: bool,
}

/// Aggregate totals in the JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageJsonTotals {
    /// Sum of all interface RX bytes (saturating).
    pub total_rx_bytes: u64,
    /// Sum of all interface TX bytes (saturating).
    pub total_tx_bytes: u64,
    /// Sum of all interface combined bytes (saturating).
    pub total_combined_bytes: u64,
    /// Number of interfaces in the `interfaces` array.
    pub interface_count: u64,
}

/// Honesty flags present in every JSON response.
///
/// All boolean values are constants in v3.0. These flags must never be `true`
/// for mutation/enforcement fields in v3.0.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageJsonHonesty {
    /// Data is interface-level aggregate counters. Always `true` in v3.0.
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
}

/// Error information in the JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageJsonError {
    /// Error type identifier for programmatic handling.
    #[serde(rename = "type")]
    pub error_type: UsageJsonErrorType,
    /// Human-readable error message.
    pub message: String,
}

/// Error type identifiers for JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum UsageJsonErrorType {
    /// `/proc/net/dev` could not be read (file not found, permission denied, I/O error).
    #[serde(rename = "read_error")]
    Read,
    /// Content was read but could not be parsed (malformed format, invalid fields).
    #[serde(rename = "parse_error")]
    Parse,
    /// A flag combination is not supported in the current phase.
    #[serde(rename = "unsupported_flag_error")]
    UnsupportedFlag,
}

impl fmt::Display for UsageJsonErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageJsonErrorType::Read => write!(f, "read_error"),
            UsageJsonErrorType::Parse => write!(f, "parse_error"),
            UsageJsonErrorType::UnsupportedFlag => write!(f, "unsupported_flag_error"),
        }
    }
}

/// The top-level JSON output model for `usage --sample --json`.
///
/// This struct represents the complete JSON response including success and error
/// variants. In success, `error` is `None` and `interfaces` contains data. In
/// error, `error` is `Some(...)` and `interfaces` is empty with zero totals.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsageJsonOutput {
    /// Schema version for forward compatibility. Currently `1`.
    pub schema_version: u32,
    /// The command that produced this output. Always `"usage --sample --json"`.
    pub command: String,
    /// Filesystem path of the data source. Always `"/proc/net/dev"`.
    pub source_path: String,
    /// Source identifier. `"live_proc_net_dev"` for live reads.
    pub source_label: String,
    /// ISO 8601 timestamp if provided by caller, or `null`/absent if not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampled_at: Option<String>,
    /// Per-interface counter data. Empty in error responses.
    pub interfaces: Vec<UsageJsonInterface>,
    /// Error information. Present only in error responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<UsageJsonError>,
    /// Aggregate totals. All zero in error responses.
    pub totals: UsageJsonTotals,
    /// Honesty flags. Present in every JSON response.
    pub honesty: UsageJsonHonesty,
    /// Warning messages. Always includes counter-reset and attribution warnings.
    pub warnings: Vec<String>,
}

/// Build a `UsageJsonOutput` from an `InterfaceCounterSnapshot`.
///
/// This function creates the JSON model from an existing snapshot without performing
/// any live filesystem reads. The snapshot is passed by the caller (e.g., from the
/// existing reader seam or injected content).
///
/// # Arguments
///
/// * `snapshot` - Parsed interface counter snapshot.
/// * `sampled_at` - Optional timestamp string. Pass `None` to omit the field.
///
/// # Returns
///
/// A `UsageJsonOutput` ready for JSON serialization.
pub fn build_usage_json_from_snapshot(
    snapshot: &InterfaceCounterSnapshot,
    sampled_at: Option<&str>,
) -> UsageJsonOutput {
    let interfaces: Vec<UsageJsonInterface> = snapshot
        .interfaces
        .iter()
        .map(|iface| UsageJsonInterface {
            name: iface.interface.clone(),
            rx_bytes: iface.rx_bytes,
            tx_bytes: iface.tx_bytes,
            combined_bytes: iface.rx_bytes.saturating_add(iface.tx_bytes),
            rx_packets: iface.rx_packets,
            tx_packets: iface.tx_packets,
            loopback: iface.is_loopback(),
        })
        .collect();

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

    UsageJsonOutput {
        schema_version: SCHEMA_VERSION,
        command: COMMAND_USAGE_SAMPLE_JSON.to_string(),
        source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
        source_label: SOURCE_LABEL_LIVE.to_string(),
        sampled_at: sampled_at.map(|s| s.to_string()),
        error: None,
        interfaces,
        totals: UsageJsonTotals {
            total_rx_bytes: total_rx,
            total_tx_bytes: total_tx,
            total_combined_bytes: total_rx.saturating_add(total_tx),
            interface_count: snapshot.interfaces.len() as u64,
        },
        honesty: default_honesty_flags(),
        warnings: default_warnings(),
    }
}

/// Build an error `UsageJsonOutput`.
///
/// Error responses contain empty interfaces and zero totals, but retain full
/// honesty flags and warnings. Errors must not claim partial enforcement or
/// mutation.
///
/// # Arguments
///
/// * `error_type` - The error type.
/// * `message` - Human-readable error message.
/// * `sampled_at` - Optional timestamp string. Pass `None` to omit.
pub fn build_usage_json_error(
    error_type: UsageJsonErrorType,
    message: &str,
    sampled_at: Option<&str>,
) -> UsageJsonOutput {
    UsageJsonOutput {
        schema_version: SCHEMA_VERSION,
        command: COMMAND_USAGE_SAMPLE_JSON.to_string(),
        source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
        source_label: SOURCE_LABEL_LIVE.to_string(),
        sampled_at: sampled_at.map(|s| s.to_string()),
        error: Some(UsageJsonError {
            error_type,
            message: message.to_string(),
        }),
        interfaces: Vec::new(),
        totals: UsageJsonTotals {
            total_rx_bytes: 0,
            total_tx_bytes: 0,
            total_combined_bytes: 0,
            interface_count: 0,
        },
        honesty: default_honesty_flags(),
        warnings: default_warnings(),
    }
}

/// Returns the default v3.0 honesty flags.
///
/// All mutation/enforcement flags are `false`. `interface_level_only` is `true`.
pub(crate) fn default_honesty_flags() -> UsageJsonHonesty {
    UsageJsonHonesty {
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
    }
}

/// Returns the default warning messages for JSON output.
pub(crate) fn default_warnings() -> Vec<String> {
    vec![
        "Counters may reset after reboot or interface reset.".to_string(),
        "Not per-app attribution: interface counters are aggregate per-interface.".to_string(),
    ]
}

/// Serialize a `UsageJsonOutput` to a pretty-printed JSON string.
///
/// Uses deterministic formatting for testability.
pub fn serialize_usage_json(output: &UsageJsonOutput) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(output)
}

/// Deserialize a JSON string into a `UsageJsonOutput`.
///
/// Provided for round-trip testing.
pub fn deserialize_usage_json(json_str: &str) -> Result<UsageJsonOutput, serde_json::Error> {
    serde_json::from_str(json_str)
}
