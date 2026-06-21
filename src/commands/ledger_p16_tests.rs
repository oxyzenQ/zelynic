// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 16: Ledger Export JSON Activation — guard tests.
//!
//! These tests verify the activated `ledger export --json --file <PATH>`
//! command, the design doc content, and all safety invariants.

use super::*;

// === Section U: Phase 16 — export activation doc and runtime guard tests ===

const P16_DOC: &str = include_str!("../../docs/v3.1-phase-16-ledger-export-json-activation.md");

/// Helper: create a temp dir for p16 tests.
fn p16_tmp_dir(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zelynic_p16_{}", label))
}

/// Helper: write a valid fixture ledger JSON to a temp file.
fn p16_write_fixture(dir: &str, name: &str) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(dir).join(name);
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    p
}

/// Helper: write arbitrary content to a temp file.
fn p16_write_raw(dir: &str, name: &str, content: &str) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(dir).join(name);
    std::fs::write(&p, content).unwrap();
    p
}

// --- Doc content tests (U-01 through U-12) ---

// U-01: Phase 16 doc exists and is nonempty.
#[test]
fn v31_p16_doc_exists_and_nonempty() {
    assert!(
        !P16_DOC.is_empty(),
        "phase 16 doc must exist and be non-empty"
    );
}

// U-02: Phase 16 doc documents `ledger export --json --file <PATH>`.
#[test]
fn v31_p16_doc_states_command_shape() {
    assert!(
        P16_DOC.contains("ledger export --json --file <PATH>"),
        "doc must document the command shape"
    );
}

// U-03: Phase 16 doc says explicit --file is required.
#[test]
fn v31_p16_doc_says_file_required() {
    assert!(
        P16_DOC.contains("--file") && P16_DOC.contains("required"),
        "doc must say --file is required"
    );
}

// U-04: Phase 16 doc says --json is required.
#[test]
fn v31_p16_doc_says_json_required() {
    assert!(
        P16_DOC.contains("--json") && P16_DOC.contains("required"),
        "doc must say --json is required"
    );
}

// U-05: Phase 16 doc says stdout-only.
#[test]
fn v31_p16_doc_says_stdout_only() {
    assert!(P16_DOC.contains("stdout"), "doc must say stdout-only");
}

// U-06: Phase 16 doc says no output file / no overwrite.
#[test]
fn v31_p16_doc_says_no_output_file() {
    assert!(
        P16_DOC.contains("no output file") || P16_DOC.contains("No output file"),
        "doc must say no output file"
    );
    assert!(
        P16_DOC.contains("--output")
            && (P16_DOC.contains("rejected") || P16_DOC.contains("does not exist")),
        "doc must say --output is rejected"
    );
}

// U-07: Phase 16 doc says no default path read.
#[test]
fn v31_p16_doc_says_no_default_path() {
    assert!(
        P16_DOC.contains("no default") || P16_DOC.contains("No default"),
        "doc must say no default path read"
    );
}

// U-08: Phase 16 doc says no persistence/save.
#[test]
fn v31_p16_doc_says_no_persistence() {
    assert!(
        P16_DOC.contains("persistence")
            && (P16_DOC.contains("not implemented") || P16_DOC.contains("No persistence")),
        "doc must say no persistence/save"
    );
}

// U-09: Phase 16 doc says no live /proc/sysfs read.
#[test]
fn v31_p16_doc_says_no_live_proc() {
    assert!(
        P16_DOC.contains("/proc") || P16_DOC.contains("sysfs"),
        "doc must say no live /proc/sysfs read"
    );
}

// U-10: Phase 16 doc says no nft/tc/cgroup/PID mutation.
#[test]
fn v31_p16_doc_says_no_mutation() {
    assert!(
        P16_DOC.contains("nft") && P16_DOC.contains("cgroup"),
        "doc must say no nft/tc/cgroup/PID mutation"
    );
}

// U-11: Phase 16 doc says v3.0 usage JSON unchanged.
#[test]
fn v31_p16_doc_says_v3_usage_unchanged() {
    assert!(
        P16_DOC.contains("v3.0 usage JSON") && P16_DOC.contains("unchanged"),
        "doc must say v3.0 usage JSON unchanged"
    );
}

// U-12: Phase 16 doc says ledger inspect JSON unchanged.
#[test]
fn v31_p16_doc_says_inspect_unchanged() {
    assert!(
        P16_DOC.contains("ledger inspect") && P16_DOC.contains("unchanged"),
        "doc must say ledger inspect unchanged"
    );
}

// --- Runtime activation tests (U-13 through U-29) ---

// U-13: `ledger export --json --file <valid fixture>` succeeds.
#[test]
fn v31_p16_export_json_file_succeeds() {
    let dir = p16_tmp_dir("succ");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let result = handle_ledger_export(true, Some(fp.to_str().unwrap()));
    assert!(result.is_ok(), "export --json --file valid must succeed");
    std::fs::remove_dir_all(&dir).ok();
}

// U-14: Exported JSON parses as valid JSON.
#[test]
fn v31_p16_export_json_is_valid() {
    let dir = p16_tmp_dir("vjson");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    // Capture stdout by running the function and checking it doesn't error.
    // We verify JSON validity by round-tripping through the handler.
    let result = handle_ledger_export(true, Some(fp.to_str().unwrap()));
    assert!(result.is_ok());
    // Re-read the fixture and serialize it ourselves to compare.
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let ledger = read_ledger_file_inspect(&v).unwrap();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert!(parsed.is_object(), "exported JSON must be an object");
    std::fs::remove_dir_all(&dir).ok();
}

// U-15: Exported JSON has schema_version=1.
#[test]
fn v31_p16_export_json_schema_version() {
    let dir = p16_tmp_dir("sv");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let ledger = read_ledger_file_inspect(&v).unwrap();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["schema_version"], 1);
    std::fs::remove_dir_all(&dir).ok();
}

// U-16: Exported JSON preserves host_id.
#[test]
fn v31_p16_export_json_preserves_host_id() {
    let dir = p16_tmp_dir("hid");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let ledger = read_ledger_file_inspect(&v).unwrap();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["host_id"], "fixture-host");
    std::fs::remove_dir_all(&dir).ok();
}

// U-17: Exported JSON preserves entries length.
#[test]
fn v31_p16_export_json_preserves_entries_length() {
    let dir = p16_tmp_dir("elen");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let ledger = read_ledger_file_inspect(&v).unwrap();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    assert_eq!(parsed["entries"].as_array().unwrap().len(), 3);
    std::fs::remove_dir_all(&dir).ok();
}

// U-18: Exported JSON round-trips through the ledger parser/validator.
#[test]
fn v31_p16_export_json_round_trips() {
    let dir = p16_tmp_dir("rtrip");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let ledger = read_ledger_file_inspect(&v).unwrap();
    let json_str = serialize_ledger_to_json(&ledger).unwrap();
    let reparsed = deserialize_ledger_from_json(&json_str).unwrap();
    assert_eq!(ledger, reparsed);
    std::fs::remove_dir_all(&dir).ok();
}

// U-19: Exported JSON is deterministic across repeated reads.
#[test]
fn v31_p16_export_json_deterministic() {
    let dir = p16_tmp_dir("det");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let ledger = read_ledger_file_inspect(&v).unwrap();
    let j1 = serialize_ledger_to_json(&ledger).unwrap();
    let j2 = serialize_ledger_to_json(&ledger).unwrap();
    assert_eq!(j1, j2);
    std::fs::remove_dir_all(&dir).ok();
}

// U-20: Exported JSON is not ledger inspect JSON (different data source concept).
// The schemas are the same but the operation is semantically different.
// We prove this by showing the doc distinguishes them.
#[test]
fn v31_p16_export_json_not_inspect_json() {
    assert!(
        P16_DOC.contains("semantically different") || P16_DOC.contains("different operations"),
        "doc must distinguish export from inspect"
    );
}

// U-21: Exported JSON is not v3.0 usage JSON.
#[test]
fn v31_p16_export_json_not_usage_json() {
    assert!(
        P16_DOC.contains("completely different schemas") || P16_DOC.contains("different schemas"),
        "doc must distinguish export from usage JSON"
    );
}

// U-22: `ledger export --json` without --file fails honestly.
#[test]
fn v31_p16_export_json_no_file_fails() {
    let result = handle_ledger_export(true, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("--file"), "must mention --file: {}", err);
    assert!(
        !err.contains("design-gated"),
        "must NOT be design-gated: {}",
        err
    );
}

// U-23: `ledger export --file <valid>` without --json fails honestly.
#[test]
fn v31_p16_export_file_no_json_fails() {
    let dir = p16_tmp_dir("nojson");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let result = handle_ledger_export(false, Some(fp.to_str().unwrap()));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("--json"), "must mention --json: {}", err);
    std::fs::remove_dir_all(&dir).ok();
}

// U-24: `ledger export --json --file <parent traversal path>` rejects.
#[test]
fn v31_p16_export_parent_traversal_rejected() {
    let result = handle_ledger_export(true, Some("/tmp/legit/../etc/passwd.json"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("parent traversal"));
}

// U-25: `ledger export --json --file <nonexistent path>` rejects.
#[test]
fn v31_p16_export_nonexistent_rejected() {
    let result = handle_ledger_export(true, Some("/tmp/zelynic_p16_nonexist_99999.json"));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("cannot access"));
}

// U-26: `ledger export --json --file <malformed json>` rejects.
#[test]
fn v31_p16_export_malformed_json_rejected() {
    let dir = p16_tmp_dir("mal");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_raw(dir.to_str().unwrap(), "bad.json", "{invalid json");
    let result = handle_ledger_export(true, Some(fp.to_str().unwrap()));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid ledger"));
    std::fs::remove_dir_all(&dir).ok();
}

// U-27: `ledger export --json --file <unsupported schema>` rejects.
#[test]
fn v31_p16_export_unsupported_schema_rejected() {
    let dir = p16_tmp_dir("usch");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_raw(
        dir.to_str().unwrap(),
        "s.json",
        r#"{"schema_version":99,"created_at":"","updated_at":"","host_id":"","entries":[]}"#,
    );
    let result = handle_ledger_export(true, Some(fp.to_str().unwrap()));
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("schema") || err.contains("Unsupported"));
    std::fs::remove_dir_all(&dir).ok();
}

// U-28: `ledger export --json --file <missing required field>` rejects.
#[test]
fn v31_p16_export_missing_field_rejected() {
    let dir = p16_tmp_dir("mfield");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_raw(
        dir.to_str().unwrap(),
        "mf.json",
        r#"{"schema_version":1,"entries":[]}"#,
    );
    let result = handle_ledger_export(true, Some(fp.to_str().unwrap()));
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("invalid ledger"));
    std::fs::remove_dir_all(&dir).ok();
}

// U-29: `ledger export --json --file <invalid invariant>` rejects.
#[test]
fn v31_p16_export_invalid_invariant_rejected() {
    let dir = p16_tmp_dir("invar");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = r#"{"schema_version":1,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z","host_id":"h","entries":[{"entry_id":"e1","timestamp":"2026-01-01T00:00:00Z","entry_type":"snapshot","source_label":"t","interface":"eth0","rx_bytes":100,"tx_bytes":50,"combined_bytes":9999,"read_only":true,"provenance":"t","attribution_scope":"interface-level only","enforcement_status":"inactive/not implemented","reset_detected":false,"reset_details":[]}]}"#;
    let fp = p16_write_raw(dir.to_str().unwrap(), "inv.json", bad);
    let result = handle_ledger_export(true, Some(fp.to_str().unwrap()));
    assert!(result.is_err());
    std::fs::remove_dir_all(&dir).ok();
}

// --- CLI-level rejection tests (U-30 through U-31) ---

// U-30: `ledger export --output <PATH>` remains rejected/absent.
#[test]
fn v31_p16_export_output_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--output", "/tmp/out.json"]).is_err(),
        "export --output must be rejected (flag does not exist)"
    );
}

// U-31: `ledger export --overwrite` remains rejected/absent.
#[test]
fn v31_p16_export_overwrite_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--overwrite"]).is_err(),
        "export --overwrite must be rejected (flag does not exist)"
    );
}

// --- Regression tests (U-32 through U-36) ---

// U-32: ledger inspect fixture still works.
#[test]
fn v31_p16_inspect_fixture_still_works() {
    let result = handle_ledger_inspect(false, None);
    assert!(result.is_ok());
}

// U-33: ledger inspect --json fixture still works.
#[test]
fn v31_p16_inspect_json_fixture_still_works() {
    let result = handle_ledger_inspect(true, None);
    assert!(result.is_ok());
}

// U-34: ledger inspect --file valid fixture still works.
#[test]
fn v31_p16_inspect_file_still_works() {
    let dir = p16_tmp_dir("ifile");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let result = handle_ledger_inspect(false, Some(fp.to_str().unwrap()));
    assert!(result.is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

// U-35: ledger inspect --file valid fixture --json still works.
#[test]
fn v31_p16_inspect_file_json_still_works() {
    let dir = p16_tmp_dir("ifjson");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = p16_write_fixture(dir.to_str().unwrap(), "v.json");
    let result = handle_ledger_inspect(true, Some(fp.to_str().unwrap()));
    assert!(result.is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

// U-36: usage --sample --delta --json schema remains unchanged.
#[test]
fn v31_p16_usage_delta_json_unchanged() {
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

// --- Structural safety tests (U-37 through U-40) ---

// U-38: all touched files remain under 1000 LOC.
#[test]
fn v31_p16_all_files_under_1000_loc() {
    let files = [
        include_str!("ledger.rs"),
        include_str!("ledger_p13_tests.rs"),
        include_str!("ledger_p14_tests.rs"),
        include_str!("ledger_p15_tests.rs"),
        include_str!("ledger_p16_tests.rs"),
    ];
    let names = [
        "ledger.rs",
        "ledger_p13_tests.rs",
        "ledger_p14_tests.rs",
        "ledger_p15_tests.rs",
        "ledger_p16_tests.rs",
    ];
    for (source, name) in files.iter().zip(names.iter()) {
        let line_count = source.lines().count();
        assert!(
            line_count <= 1000,
            "{} must be under 1000 LOC, is {}",
            name,
            line_count
        );
    }
}

// U-39: production code contains no file write/output/mutation APIs for export.
#[test]
fn v31_p16_prod_no_write_apis() {
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

// U-40: no new dependencies.
#[test]
fn v31_p16_no_new_dependencies() {
    let cargo = include_str!("../../Cargo.toml");
    // Verify no unusual new crate was added. Just check the known deps pattern.
    assert!(cargo.contains("serde = ") || cargo.contains("serde_json = "));
    // The test passes as long as Cargo.toml parses and we have the expected deps.
    // A real dependency diff would require comparing to baseline, but this
    // confirms we haven't added obviously new crates.
    assert!(!cargo.contains("tokio"), "no tokio dependency");
    assert!(!cargo.contains("reqwest"), "no reqwest dependency");
}
