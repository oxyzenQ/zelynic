// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Handler for the `zelynic ledger inspect` command (v3.1 phase 10).
//!
//! This module wires the existing `build_ledger_inspect()` and
//! `render_ledger_inspect()` functions from the accounting layer to the
//! hidden CLI dispatch gate. The handler builds an in-memory fixture
//! `Ledger` (no filesystem reads or writes), computes aggregate inspect
//! statistics, and renders the output as human-readable text or JSON.
//!
//! # Safety
//!
//! - No filesystem reads — the fixture ledger is constructed in memory.
//! - No filesystem writes — no files are written to disk.
//! - No live `/proc/net/dev` or sysfs reads.
//! - No enforcement, blocking, or state mutation.
//! - No ledger persistence — the ledger exists only in memory during
//!   the handler call.
//! - Command remains `#[command(hide = true)]` in clap.

use anyhow::Result;

use crate::accounting::{
    add_session_delta_entry, add_snapshot_entry, build_ledger_inspect, new_empty_ledger,
    render_ledger_inspect, serialize_ledger_to_json, Ledger,
};

/// Build the phase 10 in-memory fixture ledger for inspect preview.
///
/// Creates a deterministic ledger with two snapshot entries and one delta
/// entry across two interfaces (eth0, wlan0). This provides a meaningful
/// inspect output without any filesystem access.
///
/// # Returns
///
/// A `Ledger` struct suitable for `build_ledger_inspect()`.
pub(crate) fn build_fixture_ledger() -> Ledger {
    let mut ledger = new_empty_ledger("2026-06-10T00:00:00Z", "fixture-host");

    // Snapshot 1: wlan0
    add_snapshot_entry(
        &mut ledger,
        "snap-001",
        "2026-06-10T00:00:00Z",
        "fixture-preview",
        "wlan0",
        1_500_000_000,
        320_000_000,
        Some(1_200_000),
        Some(350_000),
        false,
        vec![],
    );

    // Snapshot 2: eth0
    add_snapshot_entry(
        &mut ledger,
        "snap-002",
        "2026-06-10T00:05:00Z",
        "fixture-preview",
        "eth0",
        800_000_000,
        150_000_000,
        Some(950_000),
        Some(180_000),
        false,
        vec![],
    );

    // Delta: wlan0
    add_session_delta_entry(
        &mut ledger,
        "delta-001",
        "2026-06-10T00:10:00Z",
        "fixture-preview",
        "wlan0",
        45_000_000,
        12_000_000,
        Some(30_000),
        Some(8_000),
        false,
        vec![],
    );

    ledger
}

/// Handle the `zelynic ledger inspect` command.
///
/// Builds an in-memory fixture ledger, computes inspect statistics via
/// `build_ledger_inspect()`, and renders the output as human-readable
/// text (default) or JSON (`--json` flag).
///
/// # Arguments
///
/// * `json` - If true, output the fixture ledger as JSON instead of
///   the human-readable inspect summary.
///
/// # Returns
///
/// `Ok(())` with output printed to stdout, or an error.
pub(crate) fn handle_ledger_inspect(json: bool) -> Result<()> {
    let ledger = build_fixture_ledger();

    if json {
        let json_str = serialize_ledger_to_json(&ledger)
            .map_err(|e| anyhow::anyhow!("fixture ledger serialization failed: {}", e))?;
        println!("{}", json_str);
    } else {
        let inspect = build_ledger_inspect(&ledger);
        let rendered = render_ledger_inspect(&inspect);
        println!("{}", rendered);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fixture_ledger_has_three_entries() {
        let ledger = build_fixture_ledger();
        assert_eq!(ledger.entries.len(), 3);
    }

    #[test]
    fn test_fixture_ledger_has_correct_snapshot_delta_counts() {
        let ledger = build_fixture_ledger();
        let snapshots = ledger
            .entries
            .iter()
            .filter(|e| e.entry_type == "snapshot")
            .count();
        let deltas = ledger
            .entries
            .iter()
            .filter(|e| e.entry_type == "delta")
            .count();
        assert_eq!(snapshots, 2);
        assert_eq!(deltas, 1);
    }

    #[test]
    fn test_fixture_ledger_interfaces_sorted() {
        let ledger = build_fixture_ledger();
        let inspect = build_ledger_inspect(&ledger);
        assert_eq!(inspect.interfaces, vec!["eth0", "wlan0"]);
    }

    #[test]
    fn test_fixture_ledger_read_only() {
        let ledger = build_fixture_ledger();
        let inspect = build_ledger_inspect(&ledger);
        assert!(inspect.read_only);
    }

    #[test]
    fn test_fixture_inspect_totals() {
        let ledger = build_fixture_ledger();
        let inspect = build_ledger_inspect(&ledger);
        assert_eq!(inspect.total_rx_bytes, 2_345_000_000);
        assert_eq!(inspect.total_tx_bytes, 482_000_000);
        assert_eq!(inspect.snapshot_count, 2);
        assert_eq!(inspect.delta_count, 1);
        assert_eq!(inspect.total_entries, 3);
        assert_eq!(inspect.reset_warning_count, 0);
    }

    #[test]
    fn test_fixture_inspect_no_filesystem_access() {
        let ledger = build_fixture_ledger();
        let inspect = build_ledger_inspect(&ledger);
        let rendered = render_ledger_inspect(&inspect);
        assert!(rendered.contains("ledger inspect model only"));
        assert!(rendered.contains("no filesystem read performed"));
        assert!(rendered.contains("no filesystem write performed"));
    }

    #[test]
    fn test_fixture_json_serialization_valid() {
        let ledger = build_fixture_ledger();
        let json_str = serialize_ledger_to_json(&ledger).unwrap();
        // Verify it's valid JSON containing expected fields
        assert!(json_str.contains("schema_version"));
        assert!(json_str.contains("fixture-host"));
        assert!(json_str.contains("wlan0"));
        assert!(json_str.contains("eth0"));
        assert!(json_str.contains("snap-001"));
        assert!(json_str.contains("delta-001"));
    }

    #[test]
    fn test_handle_ledger_inspect_text_output() {
        let ledger = build_fixture_ledger();
        let inspect = build_ledger_inspect(&ledger);
        let rendered = render_ledger_inspect(&inspect);
        // Verify key content in text output
        assert!(rendered.contains("Entries: 3 (2 snapshots, 1 deltas)"));
        assert!(rendered.contains("Interfaces: eth0, wlan0"));
        assert!(rendered.contains("saturating, overflow-safe"));
        assert!(rendered.contains("Read-only: true"));
        assert!(rendered.contains("Reset warnings: 0"));
        assert!(rendered.contains("Schema version: 1"));
    }

    #[test]
    fn test_fixture_ledger_provenance() {
        let ledger = build_fixture_ledger();
        let inspect = build_ledger_inspect(&ledger);
        assert!(inspect.provenance.contains("2 snapshots"));
        assert!(inspect.provenance.contains("1 deltas"));
    }

    #[test]
    fn test_fixture_ledger_enforcement_inactive() {
        let ledger = build_fixture_ledger();
        let inspect = build_ledger_inspect(&ledger);
        assert_eq!(inspect.enforcement_status, "inactive/not implemented");
        assert_eq!(inspect.attribution_scope, "interface-level only");
    }

    #[test]
    fn test_fixture_json_round_trip() {
        let ledger = build_fixture_ledger();
        let json_str = serialize_ledger_to_json(&ledger).unwrap();
        let deserialized = crate::accounting::deserialize_ledger_from_json(&json_str).unwrap();
        assert_eq!(ledger, deserialized);
    }

    #[test]
    fn test_fixture_render_determinism() {
        let ledger = build_fixture_ledger();
        let inspect1 = build_ledger_inspect(&ledger);
        let inspect2 = build_ledger_inspect(&ledger);
        assert_eq!(inspect1, inspect2);
        let r1 = render_ledger_inspect(&inspect1);
        let r2 = render_ledger_inspect(&inspect2);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_fixture_no_persistence_in_json() {
        let ledger = build_fixture_ledger();
        let json_str = serialize_ledger_to_json(&ledger).unwrap();
        // JSON is fixture-only — no path, no persistence metadata
        assert!(!json_str.contains("filesystem"));
        assert!(!json_str.contains("persistence_enabled"));
        assert!(!json_str.contains("directory"));
    }

    #[test]
    fn test_fixture_no_live_proc_read() {
        let ledger = build_fixture_ledger();
        let inspect = build_ledger_inspect(&ledger);
        let rendered = render_ledger_inspect(&inspect);
        assert!(rendered.contains("no live /proc or sysfs read performed"));
    }

    #[test]
    fn test_handle_ledger_inspect_returns_ok() {
        let result = handle_ledger_inspect(false);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_ledger_inspect_json_returns_ok() {
        let result = handle_ledger_inspect(true);
        assert!(result.is_ok());
    }

    // === Section P: Phase 11 — file-read gate design doc content tests ===

    const P11_DOC: &str =
        include_str!("../../docs/v3.1-phase-11-ledger-inspect-file-read-gate-design.md");

    #[test]
    fn v31_p11_design_doc_exists() {
        assert!(
            !P11_DOC.is_empty(),
            "phase 11 design doc must exist and be non-empty"
        );
    }

    #[test]
    fn v31_p11_design_doc_states_future_shape() {
        assert!(
            P11_DOC.contains("ledger inspect --file <PATH>"),
            "design doc must state future shape ledger inspect --file <PATH>"
        );
    }

    #[test]
    fn v31_p11_design_doc_rejects_implicit_default_file_read() {
        assert!(
            P11_DOC.contains("Implicit Default File Read (Rejected)"),
            "design doc must explicitly reject implicit default file read"
        );
    }

    #[test]
    fn v31_p11_design_doc_says_no_fs_read_implemented() {
        assert!(
            P11_DOC.contains("no filesystem read is implemented in this phase"),
            "design doc must say no filesystem read is implemented"
        );
    }

    #[test]
    fn v31_p11_design_doc_says_no_fs_write_implemented() {
        assert!(
            P11_DOC.contains("no filesystem write is implemented in this phase"),
            "design doc must say no filesystem write is implemented"
        );
    }

    #[test]
    fn v31_p11_design_doc_says_no_symlink_following_silently() {
        assert!(
            P11_DOC.contains("no symlink following silently"),
            "design doc must say no symlink following silently"
        );
    }

    #[test]
    fn v31_p11_design_doc_says_path_validation_required() {
        assert!(
            P11_DOC.contains("path validation is required before future read"),
            "design doc must say path validation is required"
        );
    }

    #[test]
    fn v31_p11_design_doc_says_schema_validation_required() {
        assert!(
            P11_DOC.contains("schema validation is required before render"),
            "design doc must say schema validation is required"
        );
    }

    #[test]
    fn v31_p11_handler_uses_no_std_fs_apis() {
        // Verify the handler module source does not import or use std::fs.
        let handler_source = include_str!("mod.rs");
        assert!(
            !handler_source.contains("std::fs"),
            "ledger handler must not use std::fs APIs"
        );
        assert!(
            !handler_source.contains("use std::fs"),
            "ledger handler must not import std::fs"
        );
    }
}
