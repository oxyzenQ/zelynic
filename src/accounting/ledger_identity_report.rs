// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure Ledger Identity Report model for v3.1 phase 4.
//!
//! This module provides a pure report model that summarizes
//! `LedgerIdentityAttachment` values into deterministic report structures.
//! It performs **no** filesystem reads, **no** filesystem writes, **no**
//! live system reads, **no** enforcement, **no** quota management, **no**
//! network blocking, **no** eBPF, **no** PID movement, and **no** cgroup writes.
//!
//! # Safety
//!
//! - No filesystem I/O — all operations are pure in-memory transformations.
//! - No live `/proc/net/dev` or sysfs reads.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//! - No ledger persistence write path is enabled.
//! - No changes to existing `LedgerEntry` serde schema.
//!
//! # Phase 4 Scope
//!
//! Phase 4 creates a pure report model that consumes existing
//! `LedgerIdentityAttachment` values and produces deterministic summaries
//! by interface, attribution scope, and identity type. It does NOT replace
//! existing `ledger_inspect` — it is a separate additive module.

#![allow(dead_code)]
#![allow(unused_imports)]

use super::identity::UsageAttributionScope;
use super::ledger_identity::LedgerIdentityAttachment;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Report-level honesty and safety flags.
///
/// All enforcement and persistence flags are hard-coded to `false`.
/// Identity attribution is always marked as best-effort.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerIdentityReportHonesty {
    /// Identity attribution is best-effort, not enforcement-grade.
    pub attribution_is_best_effort: bool,
    /// Data source is interface-level counters.
    pub interface_level_data_source: bool,
    /// Per-app attribution may be partial or incomplete.
    pub per_app_attribution_may_be_partial: bool,
    /// Interface-level data remains authoritative.
    pub interface_level_remains_authoritative: bool,
    /// Enforcement is inactive (not implemented).
    pub enforcement_inactive: bool,
    /// Persistence is not performed.
    pub persistence_performed: bool,
    /// Filesystem write is not performed.
    pub filesystem_write: bool,
    /// Network blocking is not active.
    pub network_blocking: bool,
    /// Quota enforcement is not active.
    pub quota: bool,
    /// eBPF is not used.
    pub ebpf: bool,
    /// nft/tc mutation is not performed.
    pub nft_tc_mutation: bool,
    /// Cgroup mutation is not performed.
    pub cgroup_mutation: bool,
    /// Daemon/watch mode is not active.
    pub daemon_watch: bool,
}

/// Aggregate byte totals for the report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerIdentityReportTotals {
    /// Total received bytes across all attachments (saturating).
    pub total_rx_bytes: u64,
    /// Total transmitted bytes across all attachments (saturating).
    pub total_tx_bytes: u64,
    /// Total combined bytes across all attachments (saturating).
    pub total_combined_bytes: u64,
    /// Number of entries in the report.
    pub entry_count: usize,
}

/// Per-target summary within the report.
///
/// Groups byte totals and identity details by a deterministic key derived
/// from interface name, attribution scope, and optional identity fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerIdentityReportTarget {
    /// Deterministic sort key: interface + scope + identity hint.
    pub key: String,
    /// Network interface name.
    pub interface: String,
    /// Attribution scope for this target.
    pub attribution_scope: String,
    /// Whether the interface is loopback.
    pub loopback: bool,
    /// Optional process name (best-effort, from comm field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_comm: Option<String>,
    /// Optional PID (best-effort, PIDs are recycled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_pid: Option<u32>,
    /// Optional cgroup path (best-effort).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_path: Option<String>,
    /// Optional systemd unit (best-effort).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_unit: Option<String>,
    /// Aggregate RX bytes for this target (saturating).
    pub rx_bytes: u64,
    /// Aggregate TX bytes for this target (saturating).
    pub tx_bytes: u64,
    /// Aggregate combined bytes for this target (saturating).
    pub combined_bytes: u64,
    /// Number of entries in this target group.
    pub entry_count: usize,
}

/// Per-interface aggregate summary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerIdentityReportInterface {
    /// Network interface name.
    pub interface: String,
    /// Whether the interface is loopback.
    pub loopback: bool,
    /// Aggregate RX bytes for this interface (saturating).
    pub rx_bytes: u64,
    /// Aggregate TX bytes for this interface (saturating).
    pub tx_bytes: u64,
    /// Aggregate combined bytes for this interface (saturating).
    pub combined_bytes: u64,
    /// Number of entries for this interface.
    pub entry_count: usize,
}

/// Top-level ledger identity report.
///
/// Summarizes a list of `LedgerIdentityAttachment` values into a
/// deterministic report with totals, per-target breakdown, per-interface
/// breakdown, honesty flags, and safety metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LedgerIdentityReport {
    /// Number of attachments in the source input.
    pub total_attachments: usize,
    /// Aggregate byte totals.
    pub totals: LedgerIdentityReportTotals,
    /// Per-target summaries in deterministic key order.
    pub targets: Vec<LedgerIdentityReportTarget>,
    /// Per-interface summaries in deterministic interface name order.
    pub interfaces: Vec<LedgerIdentityReportInterface>,
    /// Number of entries with unknown attribution scope.
    pub unknown_target_count: usize,
    /// Number of entries with no identity (interface-level only, unattached).
    pub no_identity_count: usize,
    /// Number of entries with interface-only scope.
    pub interface_only_count: usize,
    /// Number of entries with process best-effort scope.
    pub process_best_effort_count: usize,
    /// Number of entries with cgroup best-effort scope.
    pub cgroup_best_effort_count: usize,
    /// Number of entries with target best-effort scope.
    pub target_best_effort_count: usize,
    /// Honesty and safety flags.
    pub honesty: LedgerIdentityReportHonesty,
    /// Provenance description.
    pub provenance: String,
}

/// Build a deterministic report from a slice of `LedgerIdentityAttachment` values.
///
/// Groups attachments by a deterministic key (interface + attribution scope +
/// identity hints) using BTreeMap for sorted output. Totals are computed
/// with saturating arithmetic to avoid overflow panics.
pub fn build_ledger_identity_report(
    attachments: &[LedgerIdentityAttachment],
) -> LedgerIdentityReport {
    let total_attachments = attachments.len();

    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;
    let mut total_combined: u64 = 0;

    let mut target_map: BTreeMap<String, LedgerIdentityReportTarget> = BTreeMap::new();
    let mut iface_map: BTreeMap<String, LedgerIdentityReportInterface> = BTreeMap::new();

    let mut unknown_count = 0usize;
    let mut no_identity_count = 0usize;
    let mut interface_only_count = 0usize;
    let mut process_best_effort_count = 0usize;
    let mut cgroup_best_effort_count = 0usize;
    let mut target_best_effort_count = 0usize;

    for att in attachments {
        let entry = &att.entry;
        total_rx = total_rx.saturating_add(entry.rx_bytes);
        total_tx = total_tx.saturating_add(entry.tx_bytes);
        total_combined = total_combined.saturating_add(entry.combined_bytes);

        // Determine scope and identity fields
        let (scope_str, loopback, proc_comm, proc_pid, cg_path, cg_unit) = match &att.identity {
            Some(resolved) => {
                let lb = resolved
                    .identity
                    .interface
                    .as_ref()
                    .map(|i| i.loopback)
                    .unwrap_or(false);
                let pc = resolved
                    .identity
                    .process
                    .as_ref()
                    .and_then(|p| p.comm.clone());
                let pp = resolved.identity.process.as_ref().and_then(|p| p.pid);
                let cp = resolved
                    .identity
                    .cgroup
                    .as_ref()
                    .and_then(|c| c.cgroup_path.clone());
                let cu = resolved
                    .identity
                    .cgroup
                    .as_ref()
                    .and_then(|c| c.systemd_unit.clone());

                let scope = match resolved.attribution_scope {
                    UsageAttributionScope::Unknown => {
                        unknown_count += 1;
                        "unknown".to_string()
                    }
                    UsageAttributionScope::InterfaceOnly => {
                        interface_only_count += 1;
                        "interface_only".to_string()
                    }
                    UsageAttributionScope::ProcessBestEffort => {
                        process_best_effort_count += 1;
                        "process_best_effort".to_string()
                    }
                    UsageAttributionScope::CgroupBestEffort => {
                        cgroup_best_effort_count += 1;
                        "cgroup_best_effort".to_string()
                    }
                    UsageAttributionScope::TargetBestEffort => {
                        target_best_effort_count += 1;
                        "target_best_effort".to_string()
                    }
                };

                (scope, lb, pc, pp, cp, cu)
            }
            None => {
                no_identity_count += 1;
                let lb = entry.interface == "lo";
                ("no_identity".to_string(), lb, None, None, None, None)
            }
        };

        // Build deterministic target key
        let identity_hint = proc_comm.as_deref().unwrap_or("");
        let cgroup_hint = cg_path.as_deref().unwrap_or("");
        let key = format!(
            "{}|{}|{}|{}",
            entry.interface, scope_str, identity_hint, cgroup_hint
        );

        // Accumulate into target map
        let entry_target = LedgerIdentityReportTarget {
            key: key.clone(),
            interface: entry.interface.clone(),
            attribution_scope: scope_str.clone(),
            loopback,
            process_comm: proc_comm.clone(),
            process_pid: proc_pid,
            cgroup_path: cg_path.clone(),
            systemd_unit: cg_unit.clone(),
            rx_bytes: entry.rx_bytes,
            tx_bytes: entry.tx_bytes,
            combined_bytes: entry.combined_bytes,
            entry_count: 1,
        };

        target_map
            .entry(key)
            .and_modify(|existing| {
                existing.rx_bytes = existing.rx_bytes.saturating_add(entry.rx_bytes);
                existing.tx_bytes = existing.tx_bytes.saturating_add(entry.tx_bytes);
                existing.combined_bytes =
                    existing.combined_bytes.saturating_add(entry.combined_bytes);
                existing.entry_count += 1;
            })
            .or_insert(entry_target);

        // Accumulate into interface map
        let iface_entry = LedgerIdentityReportInterface {
            interface: entry.interface.clone(),
            loopback,
            rx_bytes: entry.rx_bytes,
            tx_bytes: entry.tx_bytes,
            combined_bytes: entry.combined_bytes,
            entry_count: 1,
        };

        iface_map
            .entry(entry.interface.clone())
            .and_modify(|existing| {
                existing.rx_bytes = existing.rx_bytes.saturating_add(entry.rx_bytes);
                existing.tx_bytes = existing.tx_bytes.saturating_add(entry.tx_bytes);
                existing.combined_bytes =
                    existing.combined_bytes.saturating_add(entry.combined_bytes);
                existing.entry_count += 1;
            })
            .or_insert(iface_entry);
    }

    // BTreeMap produces deterministic sorted order
    let targets: Vec<LedgerIdentityReportTarget> = target_map.into_values().collect();
    let interfaces: Vec<LedgerIdentityReportInterface> = iface_map.into_values().collect();

    let provenance = if attachments.is_empty() {
        "ledger identity report model (empty)".to_string()
    } else {
        format!(
            "ledger identity report model ({} attachments, {} interfaces, {} targets)",
            total_attachments,
            interfaces.len(),
            targets.len()
        )
    };

    LedgerIdentityReport {
        total_attachments,
        totals: LedgerIdentityReportTotals {
            total_rx_bytes: total_rx,
            total_tx_bytes: total_tx,
            total_combined_bytes: total_combined,
            entry_count: total_attachments,
        },
        targets,
        interfaces,
        unknown_target_count: unknown_count,
        no_identity_count,
        interface_only_count,
        process_best_effort_count,
        cgroup_best_effort_count,
        target_best_effort_count,
        honesty: default_report_honesty(),
        provenance,
    }
}

/// Build default report honesty flags.
///
/// All enforcement/persistence/mutation flags are `false`.
/// Attribution is always best-effort.
pub fn default_report_honesty() -> LedgerIdentityReportHonesty {
    LedgerIdentityReportHonesty {
        attribution_is_best_effort: true,
        interface_level_data_source: true,
        per_app_attribution_may_be_partial: true,
        interface_level_remains_authoritative: true,
        enforcement_inactive: true,
        persistence_performed: false,
        filesystem_write: false,
        network_blocking: false,
        quota: false,
        ebpf: false,
        nft_tc_mutation: false,
        cgroup_mutation: false,
        daemon_watch: false,
    }
}

/// Serialize a report to deterministic JSON.
pub fn serialize_report_json(report: &LedgerIdentityReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

/// Deserialize a report from JSON.
pub fn deserialize_report_json(json: &str) -> Result<LedgerIdentityReport, serde_json::Error> {
    serde_json::from_str(json)
}

/// Render a report as human-readable text.
///
/// Includes per-target breakdown, per-interface breakdown, totals,
/// scope counts, and all safety disclaimers. Deterministic ordering
/// is guaranteed by BTreeMap insertion.
pub fn render_ledger_identity_report(report: &LedgerIdentityReport) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v3.1 ledger identity report (report model only)\n");
    out.push_str(&format!("Provenance: {}\n", report.provenance));
    out.push('\n');

    // Scope counts
    out.push_str("Attribution scope breakdown:\n");
    out.push_str(&format!(
        "  Total attachments: {}\n",
        report.total_attachments
    ));
    out.push_str(&format!(
        "  No identity (interface-only, unattached): {}\n",
        report.no_identity_count
    ));
    out.push_str(&format!(
        "  Interface-only: {}\n",
        report.interface_only_count
    ));
    out.push_str(&format!(
        "  Process best-effort: {}\n",
        report.process_best_effort_count
    ));
    out.push_str(&format!(
        "  Cgroup best-effort: {}\n",
        report.cgroup_best_effort_count
    ));
    out.push_str(&format!(
        "  Target best-effort: {}\n",
        report.target_best_effort_count
    ));
    out.push_str(&format!("  Unknown: {}\n", report.unknown_target_count));
    out.push('\n');

    // Per-interface breakdown
    out.push_str("Interface breakdown:\n");
    if report.interfaces.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for iface in &report.interfaces {
            let lb = if iface.loopback { " (loopback)" } else { "" };
            out.push_str(&format!(
                "  {}{}: rx={} tx={} combined={} entries={}\n",
                iface.interface,
                lb,
                iface.rx_bytes,
                iface.tx_bytes,
                iface.combined_bytes,
                iface.entry_count
            ));
        }
    }
    out.push('\n');

    // Per-target breakdown
    out.push_str("Target breakdown:\n");
    if report.targets.is_empty() {
        out.push_str("  (none)\n");
    } else {
        for target in &report.targets {
            out.push_str(&format!(
                "  [{}] scope={}\n",
                target.key, target.attribution_scope
            ));
            out.push_str(&format!("    Interface: {}", target.interface));
            if target.loopback {
                out.push_str(" (loopback)");
            }
            out.push('\n');
            if let Some(ref comm) = target.process_comm {
                out.push_str(&format!("    Process: {} (best-effort)", comm));
                if let Some(pid) = target.process_pid {
                    out.push_str(&format!(" [PID: {} (best-effort: PIDs are recycled)]", pid));
                }
                out.push('\n');
            }
            if let Some(ref path) = target.cgroup_path {
                out.push_str(&format!("    Cgroup: {} (best-effort)\n", path));
            }
            out.push_str(&format!(
                "    Bytes: rx={} tx={} combined={} entries={}\n",
                target.rx_bytes, target.tx_bytes, target.combined_bytes, target.entry_count
            ));
        }
    }
    out.push('\n');

    // Totals
    out.push_str("Totals:\n");
    out.push_str(&format!("  RX: {} bytes\n", report.totals.total_rx_bytes));
    out.push_str(&format!("  TX: {} bytes\n", report.totals.total_tx_bytes));
    out.push_str(&format!(
        "  Combined: {} bytes\n",
        report.totals.total_combined_bytes
    ));
    out.push_str(&format!("  Entries: {}\n", report.totals.entry_count));
    out.push('\n');

    // Honesty and safety disclaimers
    out.push_str("Honesty and safety:\n");
    out.push_str("  - identity attribution is best-effort\n");
    out.push_str("  - interface-level data source remains authoritative\n");
    out.push_str("  - per-app attribution may be partial\n");
    out.push_str("  - no enforcement\n");
    out.push_str("  - no persistence\n");
    out.push_str("  - no filesystem write\n");
    out.push_str("  - no network blocking\n");
    out.push_str("  - no quota\n");
    out.push_str("  - no eBPF\n");
    out.push_str("  - no nft/tc mutation\n");
    out.push_str("  - no cgroup mutation\n");
    out.push_str("  - no daemon/watch\n");

    out
}
