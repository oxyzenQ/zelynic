// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Live `/proc/net/dev` reader seam for v3.0 Live Read-Only Usage Lab.
//!
//! This module provides a read-only seam model that can eventually read live
//! interface counters from `/proc/net/dev`. In v3.0 phase 3, an **injected reader
//! backend** is added via a `ContentReader` trait, allowing the read path to be
//! exercised with fake content in tests without touching the filesystem. A live
//! read function is also provided but is NOT called from CLI or unit tests.
//!
//! The seam is `pub(crate)` and not reachable from CLI.
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
//! - No live sysfs read.
//! - No CLI command is registered.
//! - Source path is hardcoded to `/proc/net/dev` — no arbitrary path accepted.
//!
//! # Honesty
//!
//! - Interface counters are aggregate per-interface, **not** per-app.
//! - This module does **not** claim per-app attribution.
//! - This module does **not** claim enforcement, quota guard, or blocking.
//! - Counters may reset after reboot or interface reset.
//! - Source label distinguishes injected content from live reads honestly.

#![allow(dead_code)]

use std::fmt;

use super::interface_counters::{
    parse_proc_net_dev, InterfaceCounterSnapshot, ParseError, SourceLabel,
};

/// The hardcoded source path for live `/proc/net/dev` reads.
///
/// This path is not configurable from CLI or user input. The reader seam
/// only reads this exact file when the live read path is implemented
/// in a future phase.
pub const DEFAULT_LIVE_SOURCE_PATH: &str = "/proc/net/dev";

/// Source label used when parsing injected/test content through this seam.
pub const SOURCE_LABEL_INJECTED: &str = "live_proc_net_dev_sample";

/// Source label used when reading from the actual live `/proc/net/dev` file.
pub const SOURCE_LABEL_LIVE: &str = "live_proc_net_dev";

/// Status of a live read attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveReadStatus {
    /// The read has not been attempted yet (planned).
    Planned,
    /// The read succeeded and produced a snapshot.
    Success,
    /// The read failed with an error.
    Error(String),
}

impl fmt::Display for LiveReadStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiveReadStatus::Planned => write!(f, "planned"),
            LiveReadStatus::Success => write!(f, "success"),
            LiveReadStatus::Error(msg) => write!(f, "error: {}", msg),
        }
    }
}

/// A read-only seam model for the live `/proc/net/dev` reader.
///
/// This struct models the state and metadata of a planned or completed
/// read of `/proc/net/dev`. It distinguishes between injected content
/// parsing and actual live filesystem reads using source labels and flags.
///
/// All mutation flags are hardcoded to safe values:
/// - `filesystem_write_performed`: always `false`.
/// - `state_mutation_performed`: always `false`.
/// - `filesystem_read_performed`: `false` for injected content, `true` for live reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveProcNetDevReadPlan {
    /// The source path — always `/proc/net/dev`, hardcoded.
    pub source_path: String,
    /// Source label: "live_proc_net_dev_sample" or "live_proc_net_dev".
    pub source_label: String,
    /// Read status: planned, success, or error.
    pub read_status: LiveReadStatus,
    /// Whether a filesystem read was performed.
    pub filesystem_read_performed: bool,
    /// Whether a filesystem write was performed (always `false`).
    pub filesystem_write_performed: bool,
    /// Whether state mutation was performed (always `false`).
    pub state_mutation_performed: bool,
    /// The parsed snapshot, if content was successfully parsed.
    pub snapshot: Option<InterfaceCounterSnapshot>,
    /// Human-readable reason describing the read plan status.
    pub safe_reason: String,
}

impl LiveProcNetDevReadPlan {
    /// Returns true if the plan represents an injected/test content parse.
    pub fn is_injected(&self) -> bool {
        self.source_label == SOURCE_LABEL_INJECTED
    }

    /// Returns true if the plan represents a live filesystem read.
    pub fn is_live(&self) -> bool {
        self.source_label == SOURCE_LABEL_LIVE
    }
}

/// Build a live `/proc/net/dev` snapshot from injected content.
///
/// Parses the given content string using the existing `parse_proc_net_dev`
/// parser and wraps the result in a `LiveProcNetDevReadPlan` with source
/// label `live_proc_net_dev_sample`. This is the primary function for
/// testing and phase 2 development — no filesystem read is performed.
///
/// # Arguments
///
/// * `content` - The `/proc/net/dev`-style text content to parse.
///
/// # Returns
///
/// A `LiveProcNetDevReadPlan` with:
/// - `source_label` = `"live_proc_net_dev_sample"`
/// - `filesystem_read_performed` = `false`
/// - `filesystem_write_performed` = `false`
/// - `state_mutation_performed` = `false`
/// - `snapshot` = `Some(...)` if parsing succeeded
/// - `snapshot` = `None` if parsing failed
/// - `read_status` = `Success` or `Error(...)` accordingly
///
/// # Errors
///
/// Returns `ParseError` from the underlying parser if content is malformed.
/// The error is propagated in both the `Result` and the `read_status` field.
pub fn build_live_proc_net_dev_snapshot_from_content(
    content: &str,
) -> Result<LiveProcNetDevReadPlan, ParseError> {
    match parse_proc_net_dev(content) {
        Ok(snapshot) => {
            // Override source label to reflect the live seam context.
            let snapshot_with_label = InterfaceCounterSnapshot {
                interfaces: snapshot.interfaces,
                source: super::interface_counters::SourceLabel::ProcNetDevSample,
            };
            Ok(LiveProcNetDevReadPlan {
                source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
                source_label: SOURCE_LABEL_INJECTED.to_string(),
                read_status: LiveReadStatus::Success,
                filesystem_read_performed: false,
                filesystem_write_performed: false,
                state_mutation_performed: false,
                snapshot: Some(snapshot_with_label),
                safe_reason: "injected content parsed successfully (no filesystem read)"
                    .to_string(),
            })
        }
        Err(e) => Err(e),
    }
}

/// Build a live `/proc/net/dev` read plan with no content (planned state).
///
/// Returns a plan in the `Planned` state, with no snapshot. Use this to
/// model a future live read before it is executed.
pub fn build_live_proc_net_dev_read_plan() -> LiveProcNetDevReadPlan {
    LiveProcNetDevReadPlan {
        source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
        source_label: SOURCE_LABEL_LIVE.to_string(),
        read_status: LiveReadStatus::Planned,
        filesystem_read_performed: false,
        filesystem_write_performed: false,
        state_mutation_performed: false,
        snapshot: None,
        safe_reason: "live read planned (not yet executed)".to_string(),
    }
}

/// Build a live `/proc/net/dev` read plan from a parse error.
///
/// Returns a plan in the `Error` state with no snapshot. The error message
/// is captured in `read_status` and `safe_reason`.
pub fn build_live_proc_net_dev_error_plan(error: &ParseError) -> LiveProcNetDevReadPlan {
    LiveProcNetDevReadPlan {
        source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
        source_label: SOURCE_LABEL_INJECTED.to_string(),
        read_status: LiveReadStatus::Error(error.to_string()),
        filesystem_read_performed: false,
        filesystem_write_performed: false,
        state_mutation_performed: false,
        snapshot: None,
        safe_reason: format!("parse error: {}", error),
    }
}

/// Render a live `/proc/net/dev` read plan as a human-readable string.
///
/// The output includes:
/// - Read-only seam identification
/// - Source path and label
/// - Read status and mutation flags
/// - Snapshot summary if available
/// - Comprehensive honesty disclaimers
///
/// # Required Honesty Lines (13 total)
///
/// 1. read-only /proc/net/dev seam
/// 2. interface-level only (not per-app attribution)
/// 3. no quota enforcement active
/// 4. no network blocking active
/// 5. no limiter attach performed
/// 6. no nft/tc/Zelynic state mutation performed
/// 7. no ledger persistence performed
/// 8. no eBPF used
/// 9. no cgroup mutation
/// 10. no PID movement
/// 11. counters may reset after reboot/interface reset
/// 12. filesystem write not performed
/// 13. state mutation not performed
pub fn render_live_proc_net_dev_read_plan(plan: &LiveProcNetDevReadPlan) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v3.0 live /proc/net/dev reader seam (read-only)\n");
    out.push_str(&format!("Source path: {}\n", plan.source_path));
    out.push_str(&format!("Source label: {}\n", plan.source_label));
    out.push_str(&format!("Read status: {}\n", plan.read_status));
    out.push('\n');

    // Mutation flags
    out.push_str(&format!(
        "Filesystem read performed: {}\n",
        plan.filesystem_read_performed
    ));
    out.push_str(&format!(
        "Filesystem write performed: {}\n",
        plan.filesystem_write_performed
    ));
    out.push_str(&format!(
        "State mutation performed: {}\n",
        plan.state_mutation_performed
    ));
    out.push('\n');

    // Snapshot summary
    if let Some(ref snapshot) = plan.snapshot {
        if snapshot.is_empty() {
            out.push_str("Snapshot: empty (no interfaces parsed)\n");
        } else {
            out.push_str(&format!(
                "Snapshot: {} interface(s) parsed\n",
                snapshot.len()
            ));
            for iface in &snapshot.interfaces {
                let loopback_tag = if iface.is_loopback() {
                    " [loopback]"
                } else {
                    ""
                };
                out.push_str(&format!(
                    "  {:16} RX {:>12} bytes  TX {:>12} bytes{}\n",
                    iface.interface, iface.rx_bytes, iface.tx_bytes, loopback_tag,
                ));
            }
            out.push_str(&format!(
                "Totals (excl. loopback): RX {} bytes  TX {} bytes\n",
                snapshot.total_rx_bytes(),
                snapshot.total_tx_bytes()
            ));
        }
    } else {
        out.push_str("Snapshot: none (no parse attempt or parse failed)\n");
    }
    out.push('\n');

    out.push_str(&format!("Reason: {}\n", plan.safe_reason));
    out.push('\n');

    // 13 honesty lines
    out.push_str("Honesty disclaimers:\n");
    out.push_str("  - read-only /proc/net/dev seam\n");
    out.push_str("  - interface-level only (not per-app attribution)\n");
    out.push_str("  - no quota enforcement active\n");
    out.push_str("  - no network blocking active\n");
    out.push_str("  - no limiter attach performed\n");
    out.push_str("  - no nft/tc/Zelynic state mutation performed\n");
    out.push_str("  - no ledger persistence performed\n");
    out.push_str("  - no eBPF used\n");
    out.push_str("  - no cgroup mutation\n");
    out.push_str("  - no PID movement\n");
    out.push_str("  - counters may reset after reboot/interface reset\n");
    out.push_str("  - filesystem write not performed\n");
    out.push_str("  - state mutation not performed\n");

    out
}

// ── Phase 3: Injected Reader Backend ─────────────────────────────────────

/// Error type distinguishing read failures from parse failures in the live
/// reader path.
///
/// - `ReadFailed`: The content source itself failed to provide content
///   (e.g., simulated I/O error, file not found).
/// - `ParseFailed`: The content was read successfully but parsing failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LiveReadError {
    /// The content read itself failed.
    ReadFailed(String),
    /// The read succeeded but parsing the content failed.
    ParseFailed(ParseError),
}

impl fmt::Display for LiveReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiveReadError::ReadFailed(msg) => write!(f, "read failed: {}", msg),
            LiveReadError::ParseFailed(e) => write!(f, "parse failed: {}", e),
        }
    }
}

impl std::error::Error for LiveReadError {}

/// Trait for injecting content into the live reader seam.
///
/// Implementations provide content that simulates reading `/proc/net/dev`.
/// The trait does **not** expose any path configuration — the source path is
/// always the hardcoded `DEFAULT_LIVE_SOURCE_PATH`.
///
/// This trait enables testing the full read → parse pipeline without touching
/// the filesystem. The live read function (`read_live_proc_net_dev`) is the
/// production path; the injected reader is for tests only.
pub trait ContentReader {
    /// Read and return the content string, or an error message on failure.
    fn read_content(&self) -> Result<String, String>;
}

/// Fake reader that returns injected content (simulates a successful read).
///
/// Used in unit tests to exercise the read → parse pipeline without
/// touching the filesystem. The content is provided at construction time.
pub struct InjectedContentReader {
    content: String,
}

impl InjectedContentReader {
    /// Create a new fake reader that returns the given content.
    pub fn new(content: &str) -> Self {
        Self {
            content: content.to_string(),
        }
    }
}

impl ContentReader for InjectedContentReader {
    fn read_content(&self) -> Result<String, String> {
        Ok(self.content.clone())
    }
}

/// Fake reader that simulates a read failure (e.g., permission denied).
///
/// Used in unit tests to verify that read errors are handled correctly
/// without touching the filesystem.
pub struct FakeReadErrorReader {
    error_message: String,
}

impl FakeReadErrorReader {
    /// Create a new fake reader that fails with the given error message.
    pub fn new(error_message: &str) -> Self {
        Self {
            error_message: error_message.to_string(),
        }
    }
}

impl ContentReader for FakeReadErrorReader {
    fn read_content(&self) -> Result<String, String> {
        Err(self.error_message.clone())
    }
}

/// Read `/proc/net/dev` content via an injected reader and parse it.
///
/// Uses the provided `ContentReader` to obtain content, then passes it to
/// the existing `parse_proc_net_dev` parser. The source path is always
/// `DEFAULT_LIVE_SOURCE_PATH` (`/proc/net/dev`) — the reader itself does
/// not accept or expose any path configuration.
///
/// Returns a `LiveProcNetDevReadPlan` with:
/// - `source_label` = `"live_proc_net_dev_sample"` (injected reader)
/// - `filesystem_read_performed` = `true` when read succeeds, `false` on failure
/// - `filesystem_write_performed` = `false` (always)
/// - `state_mutation_performed` = `false` (always)
///
/// Error handling:
/// - Read failure (reader returns `Err`): plan with `read_status = Error("read error: ...")`
/// - Parse failure: plan with `read_status = Error("parse error: ...")`
/// - Success: plan with `read_status = Success` and parsed snapshot
///
/// The source label is `live_proc_net_dev_sample` to honestly indicate this
/// is not a live filesystem read but an injected content parse.
pub fn read_live_proc_net_dev_with_injected_reader(
    reader: &dyn ContentReader,
) -> LiveProcNetDevReadPlan {
    match reader.read_content() {
        Ok(content) => match parse_proc_net_dev(&content) {
            Ok(snapshot) => {
                let snapshot_with_label = InterfaceCounterSnapshot {
                    interfaces: snapshot.interfaces,
                    source: SourceLabel::ProcNetDevSample,
                };
                LiveProcNetDevReadPlan {
                    source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
                    source_label: SOURCE_LABEL_INJECTED.to_string(),
                    read_status: LiveReadStatus::Success,
                    filesystem_read_performed: true,
                    filesystem_write_performed: false,
                    state_mutation_performed: false,
                    snapshot: Some(snapshot_with_label),
                    safe_reason:
                        "injected content read and parsed successfully via injected reader"
                            .to_string(),
                }
            }
            Err(parse_err) => LiveProcNetDevReadPlan {
                source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
                source_label: SOURCE_LABEL_INJECTED.to_string(),
                read_status: LiveReadStatus::Error(format!("parse error: {}", parse_err)),
                filesystem_read_performed: true,
                filesystem_write_performed: false,
                state_mutation_performed: false,
                snapshot: None,
                safe_reason: format!("parse error: {}", parse_err),
            },
        },
        Err(read_err) => LiveProcNetDevReadPlan {
            source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
            source_label: SOURCE_LABEL_INJECTED.to_string(),
            read_status: LiveReadStatus::Error(format!("read error: {}", read_err)),
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            state_mutation_performed: false,
            snapshot: None,
            safe_reason: format!("read error: {}", read_err),
        },
    }
}

/// Read the live `/proc/net/dev` file and parse it.
///
/// This function performs an actual filesystem read of `/proc/net/dev` using
/// `std::fs::read_to_string`. It is the production read path for future use in
/// phase 4+ when the `zelynic usage --sample` command is implemented.
///
/// # Safety
///
/// - Reads **only** `/proc/net/dev` — path is hardcoded, not configurable.
/// - Does **not** write anything.
/// - Does **not** mutate system state.
/// - Does **not** accept arbitrary path input.
/// - Is NOT called from CLI.
/// - Is NOT called in unit tests (tests use `InjectedContentReader`).
///
/// # Errors
///
/// If the file cannot be read (e.g., not found, permission denied), returns
/// a plan with `read_status = Error("read error: ...")`. If the content
/// cannot be parsed, returns a plan with `read_status = Error("parse error: ...")`.
#[allow(dead_code)]
pub fn read_live_proc_net_dev() -> LiveProcNetDevReadPlan {
    match std::fs::read_to_string(DEFAULT_LIVE_SOURCE_PATH) {
        Ok(content) => match parse_proc_net_dev(&content) {
            Ok(snapshot) => {
                let snapshot_with_label = InterfaceCounterSnapshot {
                    interfaces: snapshot.interfaces,
                    source: SourceLabel::ParsedProcNetDev,
                };
                LiveProcNetDevReadPlan {
                    source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
                    source_label: SOURCE_LABEL_LIVE.to_string(),
                    read_status: LiveReadStatus::Success,
                    filesystem_read_performed: true,
                    filesystem_write_performed: false,
                    state_mutation_performed: false,
                    snapshot: Some(snapshot_with_label),
                    safe_reason: "live /proc/net/dev read and parsed successfully".to_string(),
                }
            }
            Err(parse_err) => LiveProcNetDevReadPlan {
                source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
                source_label: SOURCE_LABEL_LIVE.to_string(),
                read_status: LiveReadStatus::Error(format!("parse error: {}", parse_err)),
                filesystem_read_performed: true,
                filesystem_write_performed: false,
                state_mutation_performed: false,
                snapshot: None,
                safe_reason: format!("parse error: {}", parse_err),
            },
        },
        Err(io_err) => LiveProcNetDevReadPlan {
            source_path: DEFAULT_LIVE_SOURCE_PATH.to_string(),
            source_label: SOURCE_LABEL_LIVE.to_string(),
            read_status: LiveReadStatus::Error(format!("read error: {}", io_err)),
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            state_mutation_performed: false,
            snapshot: None,
            safe_reason: format!("read error: {}", io_err),
        },
    }
}

/// Source-level audit constants for verifying the live reader module does not
/// contain forbidden filesystem write API calls. These are checked against the
/// module source text in tests.
///
/// The module does NOT use any write, create, remove, rename, copy, or link
/// filesystem APIs. Only `read_to_string` is used (in `read_live_proc_net_dev`).
pub const FORBIDDEN_FS_WRITE_APIS: &[&str] = &[
    "fs::write",
    "fs::create_dir",
    "fs::remove_file",
    "fs::remove_dir",
    "fs::rename",
    "fs::copy",
    "fs::hard_link",
    "fs::soft_link",
];

/// Verify that the live reader module does not reference forbidden paths.
/// This is a source-level audit constant used in tests.
pub const FORBIDDEN_PATHS: &[&str] = &["/sys/fs/cgroup", "/sys/class/net", "sysfs"];
