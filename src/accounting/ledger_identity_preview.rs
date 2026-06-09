// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure Read-Only Report Preview module for v3.1 phase 7.
//!
//! This module provides a fixture-based preview path that builds a
//! `LedgerIdentityReport` from in-memory fixture data only. It performs
//! **no** filesystem reads, **no** filesystem writes, **no** live system
//! reads, **no** enforcement, **no** quota management, **no** network
//! blocking, **no** eBPF, **no** PID movement, **no** cgroup writes,
//! **no** live process scanning, **no** live identity resolution, **no**
//! ledger persistence, and **no** CLI wiring.
//!
//! # Safety
//!
//! - No filesystem I/O — all operations are pure in-memory transformations.
//! - No live `/proc/net/dev` or sysfs reads.
//! - No CLI command is exposed or wired.
//! - No enforcement, blocking, or state mutation.
//! - No ledger persistence read or write path is enabled.
//! - No changes to existing `LedgerEntry` serde schema.
//! - No changes to existing v3.0 usage JSON schema.
//!
//! # Phase 7 Scope
//!
//! Phase 7 creates a pure fixture-based preview that proves the future report
//! pipeline shape:
//!
//! ```text
//! fixture ledger entries
//!   -> optional fixture identities
//!   -> LedgerIdentityAttachment values
//!   -> LedgerIdentityReport
//!   -> human render and/or JSON serialization
//! ```
//!
//! This module reuses existing `LedgerEntry`, `ResolvedUsageTarget`,
//! `LedgerIdentityAttachment`, and `LedgerIdentityReport` types. No new model
//! types are created — the preview is a thin orchestration layer with
//! fixture-specific render output.
//!
//! The preview render includes explicit disclaimers:
//! - read-only preview
//! - in-memory fixture data only
//! - no live resolver
//! - no filesystem read (beyond existing v3.0 usage commands)
//! - no filesystem write
//! - no ledger persistence
//! - no enforcement
//! - no network blocking
//! - no quota
//! - no eBPF
//! - no nft/tc mutation
//! - no cgroup mutation
//! - no PID movement

#![allow(dead_code)]
#![allow(unused_imports)]

use super::identity::ResolvedUsageTarget;
use super::ledger::LedgerEntry;
use super::ledger_identity::{
    build_identity_attachment, build_no_identity_attachment, LedgerIdentityAttachment,
};
use super::ledger_identity_report::{build_ledger_identity_report, LedgerIdentityReport};

/// Build a `LedgerIdentityReport` from in-memory fixture data only.
///
/// Accepts parallel slices of `LedgerEntry` values and optional
/// `ResolvedUsageTarget` identities. When an identity is `None`, the
/// corresponding entry gets interface-level-only attribution via
/// `build_no_identity_attachment`. When an identity is `Some`, it is
/// attached via `build_identity_attachment`.
///
/// Both slices must have the same length. If they differ, only the
/// shorter length is used (excess entries or identities are silently
/// ignored).
///
/// The returned report is built by the existing `build_ledger_identity_report()`
/// function — no new report model is created.
pub fn build_ledger_identity_preview_report(
    entries: &[LedgerEntry],
    identities: &[Option<ResolvedUsageTarget>],
) -> LedgerIdentityReport {
    let len = entries.len().min(identities.len());
    let attachments: Vec<LedgerIdentityAttachment> = (0..len)
        .map(|i| match &identities[i] {
            Some(resolved) => build_identity_attachment(&entries[i], resolved.clone()),
            None => build_no_identity_attachment(&entries[i]),
        })
        .collect();

    build_ledger_identity_report(&attachments)
}

/// Render a preview report with fixture-specific disclaimers.
///
/// Wraps the existing `render_ledger_identity_report()` output with an
/// explicit "read-only preview" header and 13 preview-specific safety
/// disclaimers. The base report content (scope counts, interface/target
/// breakdown, totals, honesty flags) is preserved verbatim.
pub fn render_ledger_identity_preview_report(report: &LedgerIdentityReport) -> String {
    let mut out = String::new();

    out.push_str("=== Zelynic v3.1 Ledger Identity Report Preview ===\n");
    out.push_str("Mode: read-only preview (in-memory fixture data only)\n");
    out.push('\n');

    // Preview-specific disclaimers
    out.push_str("Preview disclaimers:\n");
    out.push_str("  - read-only preview: no commands enabled\n");
    out.push_str("  - in-memory fixture data only: no live system reads\n");
    out.push_str("  - no live resolver: no process scanning or identity resolution\n");
    out.push_str("  - no filesystem read: no /proc, sysfs, or ledger file reads\n");
    out.push_str("  - no filesystem write: no files written to disk\n");
    out.push_str("  - no ledger persistence: no ledger file read or write\n");
    out.push_str("  - no enforcement: no blocking, throttling, or quota active\n");
    out.push_str("  - no network blocking: no traffic blocking or shaping\n");
    out.push_str("  - no quota: no quota enforcement active\n");
    out.push_str("  - no eBPF: no eBPF program loading or attachment\n");
    out.push_str("  - no nft/tc mutation: no nftables or traffic control changes\n");
    out.push_str("  - no cgroup mutation: no cgroup writes\n");
    out.push_str("  - no PID movement: no processes moved between cgroups\n");
    out.push('\n');

    // Append the base report render
    out.push_str(&super::ledger_identity_report::render_ledger_identity_report(report));

    out
}

/// Serialize a preview report to deterministic JSON.
///
/// Reuses `serialize_report_json()` from the report model. The JSON schema
/// is identical to the base report — no new schema version is introduced.
pub fn serialize_preview_report_json(
    report: &LedgerIdentityReport,
) -> Result<String, serde_json::Error> {
    super::ledger_identity_report::serialize_report_json(report)
}

/// Deserialize a preview report from JSON.
///
/// Reuses `deserialize_report_json()` from the report model.
pub fn deserialize_preview_report_json(
    json: &str,
) -> Result<LedgerIdentityReport, serde_json::Error> {
    super::ledger_identity_report::deserialize_report_json(json)
}
