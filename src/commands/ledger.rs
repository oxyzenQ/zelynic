// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Handler for the `zelynic ledger inspect` command (v3.1 phases 10/12).
//!
//! This module wires the existing `build_ledger_inspect()` and
//! `render_ledger_inspect()` functions from the accounting layer to the
//! hidden CLI dispatch gate. Without `--file`, the handler builds an
//! in-memory fixture `Ledger` (no filesystem reads or writes). With
//! `--file <PATH>`, the handler performs an explicit read-only file read
//! with path validation, schema validation, and safety-checked output.
//!
//! # Safety
//!
//! - Fixture mode: no filesystem reads or writes.
//! - File-read mode: read-only file access only. No writes, no directory
//!   creation, no symlink following, no persistence save, no live resolver,
//!   no enforcement, no nft/tc/cgroup/PID mutation.
//! - No live `/proc/net/dev` or sysfs reads.
//! - Command remains `#[command(hide = true)]` in clap.

use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::accounting::{add_session_delta_entry, add_snapshot_entry};
use crate::accounting::{
    build_ledger_inspect, deserialize_ledger_from_json, new_empty_ledger, render_ledger_inspect,
    serialize_ledger_to_json, Ledger, LedgerInspect,
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

/// Validate an explicit `--file <PATH>` argument for ledger inspect.
///
/// Performs conservative validation before any filesystem read:
/// - Rejects empty paths.
/// - Rejects parent traversal (`..`) components.
/// - Rejects suspicious characters in the filename (only `[a-zA-Z0-9._-]`).
/// - Verifies the path exists and is a regular file (not symlink, not dir).
///
/// # Safety Model Limitations
///
/// This validation is conservative but does not cover all possible attacks:
/// - It does not check file permissions (the OS rejects unreadable files).
/// - It does not resolve mount points or filesystem boundaries.
/// - Symlink detection uses `symlink_metadata` (does not follow symlinks).
fn validate_ledger_file_path(path: &str, prefix: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err(format!("{}: path must not be empty", prefix));
    }

    let path_obj = Path::new(path);

    // Reject parent traversal components
    for component in path_obj.components() {
        if let std::path::Component::ParentDir = component {
            return Err(format!("{}: parent traversal (..) is not allowed", prefix));
        }
    }

    // Validate filename characters
    if let Some(filename) = path_obj.file_name() {
        let name = filename.to_string_lossy();
        if name.is_empty() {
            return Err(format!("{}: filename must not be empty", prefix));
        }
        for ch in name.chars() {
            if !ch.is_ascii_alphanumeric() && ch != '.' && ch != '-' && ch != '_' {
                return Err(format!(
                    "{}: suspicious character '{}' in filename '{}'",
                    prefix, ch, name
                ));
            }
        }
    } else {
        return Err(format!("{}: path has no filename component", prefix));
    }

    // Filesystem checks: must exist, be regular file, not symlink
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| format!("{}: cannot access '{}': {}", prefix, path, e))?;

    if meta.file_type().is_symlink() {
        return Err(format!(
            "{}: '{}' is a symlink; symlinks are not followed",
            prefix, path
        ));
    }

    if !meta.file_type().is_file() {
        return Err(format!("{}: '{}' is not a regular file", prefix, path));
    }

    Ok(path_obj.to_path_buf())
}

/// Backward-compatible wrapper using inspect prefix.
fn validate_inspect_file_path(path: &str) -> Result<PathBuf, String> {
    validate_ledger_file_path(path, "ledger inspect --file")
}

/// Read a ledger file from disk (read-only).
///
/// Reads the file content as a string, then deserializes and validates
/// using the existing `deserialize_ledger_from_json` which checks:
/// - JSON syntax
/// - schema_version is supported
/// - All entries pass `validate_safety()` (read_only, attribution_scope,
///   enforcement_status, combined_bytes consistency)
fn read_ledger_file(path: &Path, prefix: &str) -> Result<Ledger, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("{}: failed to read '{}': {}", prefix, path.display(), e))?;

    deserialize_ledger_from_json(&content)
        .map_err(|e| format!("{}: invalid ledger in '{}': {}", prefix, path.display(), e))
}

/// Backward-compatible wrapper using inspect prefix.
fn read_ledger_file_inspect(path: &Path) -> Result<Ledger, String> {
    read_ledger_file(path, "ledger inspect --file")
}

/// Render file-read inspect output as human-readable text.
///
/// Reuses `LedgerInspect` model data but outputs file-read-specific
/// disclaimers that identify the source as an explicit file read and
/// affirm all read-only safety guarantees.
fn render_file_read_inspect_text(inspect: &LedgerInspect, file_path: &str) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v2.9 ledger inspect (source: explicit file read)\n");
    out.push_str(&format!("File: {}\n", file_path));
    out.push_str(&format!("Schema version: {}\n", inspect.schema_version));
    out.push_str(&format!("Created: {}\n", inspect.created_at));
    out.push_str(&format!("Updated: {}\n", inspect.updated_at));
    out.push_str(&format!("Host: {}\n", inspect.host_id));
    if let Some(ref sid) = inspect.session_id {
        out.push_str(&format!("Session: {}\n", sid));
    }
    out.push_str(&format!("Provenance: {}\n", inspect.provenance));
    out.push('\n');

    out.push_str(&format!(
        "Entries: {} ({} snapshots, {} deltas)\n",
        inspect.total_entries, inspect.snapshot_count, inspect.delta_count
    ));
    out.push('\n');

    if inspect.interfaces.is_empty() {
        out.push_str("No interfaces observed.\n");
    } else {
        out.push_str(&format!("Interfaces: {}\n", inspect.interfaces.join(", ")));
    }
    out.push('\n');

    out.push_str("Aggregate totals (saturating, overflow-safe):\n");
    out.push_str(&format!(
        "  RX: {} bytes  TX: {} bytes  Combined: {} bytes\n",
        inspect.total_rx_bytes, inspect.total_tx_bytes, inspect.total_combined_bytes
    ));
    out.push('\n');

    out.push_str(&format!(
        "Reset warnings: {}\n",
        inspect.reset_warning_count
    ));
    out.push('\n');

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

    out.push_str("Safety disclaimers:\n");
    out.push_str("  - source: explicit file read (read-only, no file write)\n");
    out.push_str("  - no persistence save performed\n");
    out.push_str("  - no live /proc or sysfs read performed\n");
    out.push_str("  - no live app identity resolver performed\n");
    out.push_str("  - interface-level only (not per-app attribution)\n");
    out.push_str("  - quota enforcement: inactive/not implemented\n");
    out.push_str("  - network blocking: inactive/not implemented\n");
    out.push_str("  - no limiter attach performed\n");
    out.push_str("  - no nft/tc/Zelynic state mutation performed\n");

    out
}

/// Handle the `zelynic ledger inspect` command.
///
/// Without `--file`: builds an in-memory fixture ledger (Phase 10 behavior).
/// With `--file <PATH>`: validates the path, reads the file, validates
/// the ledger schema, and renders output (Phase 12 behavior).
///
/// # Arguments
///
/// * `json` - If true, output as JSON instead of human-readable text.
/// * `file` - If Some(path), read the ledger from this explicit file path.
///
/// # Returns
///
/// `Ok(())` with output printed to stdout, or an error.
pub(crate) fn handle_ledger_inspect(json: bool, file: Option<&str>) -> Result<()> {
    match file {
        None => {
            // Fixture-only mode (Phase 10, unchanged).
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
        }
        Some(path) => {
            // Explicit file-read mode (Phase 12).
            let validated =
                validate_inspect_file_path(path).map_err(|e| anyhow::anyhow!("{}", e))?;
            let ledger =
                read_ledger_file_inspect(&validated).map_err(|e| anyhow::anyhow!("{}", e))?;
            if json {
                let json_str = serialize_ledger_to_json(&ledger)
                    .map_err(|e| anyhow::anyhow!("file ledger serialization failed: {}", e))?;
                println!("{}", json_str);
            } else {
                let inspect = build_ledger_inspect(&ledger);
                let rendered = render_file_read_inspect_text(&inspect, path);
                println!("{}", rendered);
            }
        }
    }

    Ok(())
}

/// Handle the `zelynic ledger export` command.
///
/// Requires both `--json` and `--file <PATH>`. Reads the specified ledger
/// file, validates it, and emits the validated ledger JSON to stdout only.
/// No file write, no output file, no overwrite, no persistence.
///
/// # Arguments
///
/// * `json` - Must be true; export requires --json.
/// * `file` - Must be Some(path); export requires explicit --file.
///
/// # Returns
///
/// `Ok(())` with JSON printed to stdout, or an error.
pub(crate) fn handle_ledger_export(json: bool, file: Option<&str>) -> Result<()> {
    // --json is required.
    if !json {
        return Err(anyhow::anyhow!(
            "ledger export: --json is required for export"
        ));
    }

    // --file is required.
    let path = match file {
        Some(p) => p,
        None => {
            return Err(anyhow::anyhow!(
                "ledger export: --file <PATH> is required for export"
            ));
        }
    };

    // Validate path using the same hardened rules as inspect --file.
    let validated = validate_ledger_file_path(path, "ledger export --file")
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Read and validate the ledger via the existing pipeline.
    let ledger = read_ledger_file(&validated, "ledger export --file")
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Reserialize canonically and emit to stdout.
    let json_str = serialize_ledger_to_json(&ledger)
        .map_err(|e| anyhow::anyhow!("ledger export: serialization failed: {}", e))?;
    println!("{}", json_str);

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
        let deserialized = deserialize_ledger_from_json(&json_str).unwrap();
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
        let result = handle_ledger_inspect(false, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_ledger_inspect_json_returns_ok() {
        let result = handle_ledger_inspect(true, None);
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
            "design doc must state future shape"
        );
    }

    #[test]
    fn v31_p11_design_doc_rejects_implicit_default_file_read() {
        assert!(P11_DOC.contains("Implicit Default File Read (Rejected)"));
    }

    #[test]
    fn v31_p11_design_doc_says_no_fs_read_implemented() {
        assert!(P11_DOC.contains("no filesystem read is implemented in this phase"));
    }

    #[test]
    fn v31_p11_design_doc_says_no_fs_write_implemented() {
        assert!(P11_DOC.contains("no filesystem write is implemented in this phase"));
    }

    #[test]
    fn v31_p11_design_doc_says_no_symlink_following_silently() {
        assert!(P11_DOC.contains("no symlink following silently"));
    }

    #[test]
    fn v31_p11_design_doc_says_path_validation_required() {
        assert!(P11_DOC.contains("path validation is required before future read"));
    }

    #[test]
    fn v31_p11_design_doc_says_schema_validation_required() {
        assert!(P11_DOC.contains("schema validation is required before render"));
    }

    #[test]
    fn v31_p11_dispatch_module_uses_no_std_fs() {
        // The dispatch module (mod.rs) must not use std::fs.
        let dispatch_source = include_str!("mod.rs");
        assert!(!dispatch_source.contains("std::fs"));
    }

    // === Section Q: Phase 12 — file-read handler tests ===

    /// Helper: write a valid fixture ledger JSON to a temp file.
    fn write_fixture_to_temp(dir: &str, name: &str) -> std::path::PathBuf {
        let p = std::path::PathBuf::from(dir).join(name);
        let ledger = build_fixture_ledger();
        let json = serialize_ledger_to_json(&ledger).unwrap();
        std::fs::write(&p, json).unwrap();
        p
    }

    #[test]
    fn v31_p12_file_read_valid_text() {
        let dir = std::env::temp_dir().join("zelynic_p12_text");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = write_fixture_to_temp(dir.to_str().unwrap(), "v.json");
        let result = handle_ledger_inspect(false, Some(fp.to_str().unwrap()));
        assert!(result.is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_valid_json() {
        let dir = std::env::temp_dir().join("zelynic_p12_json");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = write_fixture_to_temp(dir.to_str().unwrap(), "v.json");
        let result = handle_ledger_inspect(true, Some(fp.to_str().unwrap()));
        assert!(result.is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_parent_traversal_rejected() {
        let r = validate_inspect_file_path("../bad.json");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("parent traversal"));
    }

    #[test]
    fn v31_p12_file_read_empty_path_rejected() {
        let r = validate_inspect_file_path("");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("empty"));
    }

    #[test]
    fn v31_p12_file_read_symlink_rejected() {
        let dir = std::env::temp_dir().join("zelynic_p12_sym");
        std::fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real.json");
        let sym = dir.join("sym.json");
        write_fixture_to_temp(dir.to_str().unwrap(), "real.json");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &sym).unwrap();
        #[cfg(unix)]
        {
            let r = validate_inspect_file_path(sym.to_str().unwrap());
            assert!(r.is_err());
            assert!(r.unwrap_err().contains("symlink"));
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_malformed_json_error() {
        let dir = std::env::temp_dir().join("zelynic_p12_mal");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = dir.join("bad.json");
        std::fs::write(&fp, "{invalid json").unwrap();
        let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
        let r = read_ledger_file_inspect(&v);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("invalid ledger"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_unsupported_schema_error() {
        let dir = std::env::temp_dir().join("zelynic_p12_sch");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = dir.join("s.json");
        std::fs::write(
            &fp,
            r#"{"schema_version":99,"created_at":"","updated_at":"","host_id":"","entries":[]}"#,
        )
        .unwrap();
        let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
        let r = read_ledger_file_inspect(&v);
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert!(err.contains("schema") || err.contains("Unsupported"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_enforcement_claim_rejected() {
        let dir = std::env::temp_dir().join("zelynic_p12_enf");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = dir.join("e.json");
        let bad = r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"h","entries":[{"entry_id":"e1","timestamp":"2026-01-01T00:00:00Z","entry_type":"snapshot","source_label":"t","interface":"eth0","rx_bytes":100,"tx_bytes":50,"combined_bytes":150,"read_only":true,"provenance":"test","attribution_scope":"interface-level only","enforcement_status":"active","reset_detected":false,"reset_details":[]}]}"#;
        std::fs::write(&fp, bad).unwrap();
        let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
        let r = read_ledger_file_inspect(&v);
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("enforcement_status"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_text_says_explicit_file_read() {
        let dir = std::env::temp_dir().join("zelynic_p12_src");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = write_fixture_to_temp(dir.to_str().unwrap(), "s.json");
        let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
        let loaded = read_ledger_file_inspect(&v).unwrap();
        let ins = build_ledger_inspect(&loaded);
        let rendered = render_file_read_inspect_text(&ins, fp.to_str().unwrap());
        assert!(rendered.contains("source: explicit file read"));
        assert!(rendered.contains("no persistence save"));
        assert!(rendered.contains("no live app identity resolver"));
        assert!(rendered.contains("no nft/tc/Zelynic state mutation"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_json_valid_deterministic() {
        let dir = std::env::temp_dir().join("zelynic_p12_det");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = write_fixture_to_temp(dir.to_str().unwrap(), "d.json");
        let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
        let loaded = read_ledger_file_inspect(&v).unwrap();
        let j1 = serialize_ledger_to_json(&loaded).unwrap();
        let j2 = serialize_ledger_to_json(&loaded).unwrap();
        assert_eq!(j1, j2);
        let parsed: serde_json::Value = serde_json::from_str(&j1).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_suspicious_name_rejected() {
        let r = validate_inspect_file_path("/tmp/ledger;rm-rf.json");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("suspicious character"));
    }

    #[test]
    fn v31_p12_file_read_text_says_no_file_write() {
        let dir = std::env::temp_dir().join("zelynic_p12_nw");
        std::fs::create_dir_all(&dir).unwrap();
        let fp = write_fixture_to_temp(dir.to_str().unwrap(), "n.json");
        let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
        let loaded = read_ledger_file_inspect(&v).unwrap();
        let ins = build_ledger_inspect(&loaded);
        let rendered = render_file_read_inspect_text(&ins, fp.to_str().unwrap());
        assert!(rendered.contains("read-only, no file write"));
        assert!(rendered.contains("no limiter attach performed"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn v31_p12_file_read_handler_no_write_apis() {
        // Verify production code does not use file write APIs.
        // Split at test section to exclude test helper code.
        let source = include_str!("ledger.rs");
        let prod_end = source.find("#[cfg(test)]").unwrap_or(source.len());
        let prod = &source[..prod_end];
        assert!(!prod.contains("create_dir"), "no create_dir");
        assert!(!prod.contains("remove_file"), "no remove_file");
        assert!(!prod.contains("remove_dir"), "no remove_dir");
        assert!(!prod.contains("rename("), "no rename");
        assert!(!prod.contains("fs::copy("), "no fs::copy");
        assert!(!prod.contains("File::create"), "no File::create");
        assert!(!prod.contains("OpenOptions"), "no OpenOptions");
    }
}

#[cfg(test)]
#[path = "ledger_p13_tests.rs"]
mod p13_tests;

#[cfg(test)]
#[path = "ledger_p14_tests.rs"]
mod p14_tests;

#[cfg(test)]
#[path = "ledger_p15_tests.rs"]
mod p15_tests;

#[cfg(test)]
#[path = "ledger_p16_tests.rs"]
mod p16_tests;

#[cfg(test)]
#[path = "ledger_p17_tests.rs"]
mod p17_tests;

#[cfg(test)]
#[path = "ledger_p18_tests.rs"]
mod p18_tests;

#[cfg(test)]
#[path = "ledger_p19_tests.rs"]
mod p19_tests;
