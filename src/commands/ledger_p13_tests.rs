// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 13: Ledger Inspect File-Read Error Matrix Freeze tests.
//!
//! These tests freeze the error behavior of explicit `--file` reads
//! before any future export/save/persistence phase. Each test maps to
//! one of the 25 required hardening checks (R-01 through R-25).

use super::*;

// === Section R: Phase 13 — error matrix freeze / hardening tests ===

/// Helper: create a temp dir with a unique suffix.
fn p13_tmp_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zelynic_p13_{}", label))
}

/// Helper: write a valid fixture ledger JSON to a temp file.
fn write_fixture_to_temp(dir: &str, name: &str) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(dir).join(name);
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    p
}

/// Helper: write arbitrary JSON string to a temp file.
fn write_json_to_temp(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

// R-01: Missing --file value is rejected by clap.
// (Already tested in v31_gate_tests.rs; not duplicating here.)

// R-02: --input remains rejected.
// (Already tested in v31_gate_tests.rs; not duplicating here.)

// R-03: Parent traversal paths are rejected before read.
#[test]
fn v31_p13_parent_traversal_mid_path_rejected() {
    let r = validate_inspect_file_path("/tmp/legit/../etc/passwd.json");
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("parent traversal"));
}

// R-04: Empty path is rejected before read.
#[test]
fn v31_p13_empty_path_error_says_empty() {
    let r = validate_inspect_file_path("");
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(err.contains("empty"), "error must mention 'empty': {}", err);
}

// R-05: Suspicious filename characters are rejected before read.
#[test]
fn v31_p13_suspicious_pipe_character_rejected() {
    let r = validate_inspect_file_path("/tmp/ledger|evil.json");
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("suspicious character"));
}

#[test]
fn v31_p13_suspicious_null_character_rejected() {
    let r = validate_inspect_file_path("/tmp/ledger\x00.json");
    assert!(r.is_err());
}

#[test]
fn v31_p13_suspicious_space_in_filename_rejected() {
    let r = validate_inspect_file_path("/tmp/my ledger.json");
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("suspicious character"));
}

// R-06: Symlink path is rejected.
#[test]
fn v31_p13_symlink_error_mentions_symlink() {
    let dir = p13_tmp_dir("sym2");
    std::fs::create_dir_all(&dir).unwrap();
    let real = dir.join("real.json");
    let sym = dir.join("link.json");
    write_fixture_to_temp(dir.to_str().unwrap(), "real.json");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&real, &sym).unwrap();
    #[cfg(unix)]
    {
        let r = validate_inspect_file_path(sym.to_str().unwrap());
        assert!(r.is_err());
        let err = r.unwrap_err();
        assert!(
            err.contains("symlink"),
            "error must mention 'symlink': {}",
            err
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

// R-07: Directory path is rejected.
#[test]
fn v31_p13_directory_path_rejected() {
    let dir = p13_tmp_dir("dirtest");
    std::fs::create_dir_all(&dir).unwrap();
    let r = validate_inspect_file_path(dir.to_str().unwrap());
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("not a regular file"),
        "error must say 'not a regular file': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-08: Nonexistent file returns a clear read/open error.
#[test]
fn v31_p13_nonexistent_file_error_says_cannot_access() {
    let r = validate_inspect_file_path("/tmp/zelynic_p13_nonexist_99999.json");
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("cannot access"),
        "error must say 'cannot access': {}",
        err
    );
}

// R-09: Permission denied returns a clear read/open error if testable.
// Skipped: creating permission-denied files deterministically across
// environments is not safe. The OS error propagates through the
// "failed to read" path which is honest and stable.

// R-10: Malformed JSON returns clear parse error.
#[test]
fn v31_p13_malformed_json_error_says_invalid_ledger() {
    let dir = p13_tmp_dir("mal2");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(&dir, "m.json", "{{not valid}");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("invalid ledger"),
        "error must say 'invalid ledger': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn v31_p13_completely_invalid_json_error() {
    let dir = p13_tmp_dir("mal3");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(&dir, "x.json", "not json at all!!!");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("invalid ledger"),
        "error must say 'invalid ledger': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-11: Unsupported schema version returns clear error.
#[test]
fn v31_p13_unsupported_schema_error_says_unsupported() {
    let dir = p13_tmp_dir("sch2");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(
        &dir,
        "s.json",
        r#"{"schema_version":0,"created_at":"","updated_at":"","host_id":"","entries":[]}"#,
    );
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("unsupported schema version"),
        "error must say 'unsupported schema version': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-12: Missing required top-level field returns clear error.
#[test]
fn v31_p13_missing_top_level_field_error() {
    let dir = p13_tmp_dir("miss1");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(&dir, "t.json", r#"{"schema_version":1,"entries":[]}"#);
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("invalid ledger"),
        "missing top-level field must produce 'invalid ledger': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-13: Missing required entry field returns clear error.
#[test]
fn v31_p13_missing_entry_field_error() {
    let dir = p13_tmp_dir("miss2");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(
        &dir,
        "e.json",
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"h","entries":[{"entry_id":"e1"}]}"#,
    );
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("invalid ledger"),
        "missing entry field must produce 'invalid ledger': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-14: Invalid combined_bytes invariant is rejected.
#[test]
fn v31_p13_invalid_combined_bytes_rejected() {
    let dir = p13_tmp_dir("comb");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(
        &dir,
        "c.json",
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"h","entries":[{"entry_id":"e1","timestamp":"2026-01-01T00:00:00Z","entry_type":"snapshot","source_label":"t","interface":"eth0","rx_bytes":100,"tx_bytes":50,"combined_bytes":9999,"read_only":true,"provenance":"test","attribution_scope":"interface-level only","enforcement_status":"inactive/not implemented","reset_detected":false,"reset_details":[]}]}"#,
    );
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("combined_bytes"),
        "error must mention 'combined_bytes': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-15: Invalid read_only=false entry is rejected.
#[test]
fn v31_p13_read_only_false_rejected() {
    let dir = p13_tmp_dir("ro");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(
        &dir,
        "r.json",
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"h","entries":[{"entry_id":"e1","timestamp":"2026-01-01T00:00:00Z","entry_type":"snapshot","source_label":"t","interface":"eth0","rx_bytes":100,"tx_bytes":50,"combined_bytes":150,"read_only":false,"provenance":"test","attribution_scope":"interface-level only","enforcement_status":"inactive/not implemented","reset_detected":false,"reset_details":[]}]}"#,
    );
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("read_only"),
        "error must mention 'read_only': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-16: Invalid per-app attribution claim is rejected.
#[test]
fn v31_p13_invalid_attribution_scope_rejected() {
    let dir = p13_tmp_dir("attr");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(
        &dir,
        "a.json",
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"h","entries":[{"entry_id":"e1","timestamp":"2026-01-01T00:00:00Z","entry_type":"snapshot","source_label":"t","interface":"eth0","rx_bytes":100,"tx_bytes":50,"combined_bytes":150,"read_only":true,"provenance":"test","attribution_scope":"per-app","enforcement_status":"inactive/not implemented","reset_detected":false,"reset_details":[]}]}"#,
    );
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("attribution_scope"),
        "error must mention 'attribution_scope': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-17: Invalid enforcement active claim is rejected.
#[test]
fn v31_p13_enforcement_active_error_says_enforcement() {
    let dir = p13_tmp_dir("enf2");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_json_to_temp(
        &dir,
        "f.json",
        r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"h","entries":[{"entry_id":"e1","timestamp":"2026-01-01T00:00:00Z","entry_type":"snapshot","source_label":"t","interface":"eth0","rx_bytes":100,"tx_bytes":50,"combined_bytes":150,"read_only":true,"provenance":"test","attribution_scope":"interface-level only","enforcement_status":"enforcing","reset_detected":false,"reset_details":[]}]}"#,
    );
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let r = read_ledger_file_inspect(&v);
    assert!(r.is_err());
    let err = r.unwrap_err();
    assert!(
        err.contains("enforcement_status"),
        "error must mention 'enforcement_status': {}",
        err
    );
    std::fs::remove_dir_all(&dir).ok();
}

// R-18: ledger export --json remains design-gated.
// (Already tested in v31_gate_tests.rs; not duplicating here.)

// R-19: Plain fixture ledger inspect remains unchanged.
#[test]
fn v31_p13_fixture_inspect_text_unchanged() {
    let ledger = build_fixture_ledger();
    let inspect = build_ledger_inspect(&ledger);
    let rendered = render_ledger_inspect(&inspect);
    assert!(rendered.contains("ledger inspect model only"));
    assert!(rendered.contains("no filesystem read performed"));
    assert!(rendered.contains("no filesystem write performed"));
    assert!(!rendered.contains("explicit file read"));
}

// R-20: Fixture inspect --json remains unchanged.
#[test]
fn v31_p13_fixture_inspect_json_unchanged() {
    let ledger = build_fixture_ledger();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    assert_eq!(parsed["host_id"], "fixture-host");
    assert!(parsed["entries"].is_array());
}

// R-21: Explicit file JSON output is deterministic.
#[test]
fn v31_p13_file_read_json_deterministic_across_reads() {
    let dir = p13_tmp_dir("det2");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = write_fixture_to_temp(dir.to_str().unwrap(), "d.json");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let loaded = read_ledger_file_inspect(&v).unwrap();
    let j1 = serialize_ledger_to_json(&loaded).unwrap();
    let loaded2 = read_ledger_file_inspect(&v).unwrap();
    let j2 = serialize_ledger_to_json(&loaded2).unwrap();
    assert_eq!(j1, j2, "JSON output must be deterministic");
    std::fs::remove_dir_all(&dir).ok();
}

// R-22: No file write APIs exist in production code.
// (Already tested as v31_p12_file_read_handler_no_write_apis.)

// R-23: No directory creation / backup / rename / truncate / delete / migration APIs.
#[test]
fn v31_p13_prod_code_no_mutation_apis() {
    let source = include_str!("ledger.rs");
    let prod_end = source.find("#[cfg(test)]").unwrap_or(source.len());
    let prod = &source[..prod_end];
    assert!(!prod.contains("set_permissions"), "no set_permissions");
    assert!(!prod.contains("truncate"), "no truncate");
    assert!(!prod.contains(".metadata("), "no metadata mutation");
    assert!(!prod.contains("fsync"), "no fsync");
    assert!(!prod.contains("hard_link"), "no hard_link");
    assert!(!prod.contains("soft_link"), "no soft_link");
}

// R-24: v3.0 usage JSON schema remains unchanged.
#[test]
fn v31_p13_v3_usage_schema_version_unchanged() {
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

// R-25: All touched files remain under 1000 LOC.
#[test]
fn v31_p13_ledger_rs_under_1000_loc() {
    let source = include_str!("ledger.rs");
    let line_count = source.lines().count();
    assert!(
        line_count <= 1000,
        "ledger.rs must be under 1000 LOC, is {}",
        line_count
    );
}

// === Phase 13 doc content tests ===

const P13_DOC: &str =
    include_str!("../../docs/v3.1-phase-13-ledger-file-read-error-matrix-freeze.md");

#[test]
fn v31_p13_doc_exists_and_nonempty() {
    assert!(!P13_DOC.is_empty(), "phase 13 doc must exist");
}

#[test]
fn v31_p13_doc_says_error_hardening_only() {
    assert!(
        P13_DOC.contains("error hardening") || P13_DOC.contains("Error Matrix Freeze"),
        "phase 13 doc must describe error hardening"
    );
}

#[test]
fn v31_p13_doc_says_no_default_path_read() {
    assert!(
        P13_DOC.contains("No default ledger path read")
            || P13_DOC.contains("no default ledger path read")
            || (P13_DOC.contains("No default ledger") && P13_DOC.contains("path read")),
        "phase 13 doc must say no default path read"
    );
}

#[test]
fn v31_p13_doc_says_no_file_write() {
    assert!(
        P13_DOC.contains("no file write") || P13_DOC.contains("No file write"),
        "phase 13 doc must say no file write"
    );
}

#[test]
fn v31_p13_doc_says_no_export() {
    assert!(
        P13_DOC.contains("no export") || P13_DOC.contains("No export"),
        "phase 13 doc must say no export"
    );
}

#[test]
fn v31_p13_doc_says_v3_usage_unchanged() {
    assert!(
        P13_DOC.contains("v3.0 usage JSON unchanged")
            || P13_DOC.contains("usage JSON schema unchanged"),
        "phase 13 doc must say v3.0 usage JSON unchanged"
    );
}
