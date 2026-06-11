// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 18: Ledger Export User Docs / UX Examples Polish — guard tests.
//!
//! These tests verify the Phase 18 documentation exists, contains all
//! required content, and that all existing export/inspect/usage behavior
//! remains unchanged.

use super::*;

const P18_DOC: &str =
    include_str!("../../docs/v3.1-phase-18-ledger-export-user-docs-examples-polish.md");

fn p18_tmp(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zelynic_p18_{}", label))
}

fn p18_fixture(dir: &str, name: &str) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(dir).join(name);
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    p
}

// --- Doc content tests (W-01..W-22) ---

// W-01
#[test]
fn v31_p18_doc_exists_and_nonempty() {
    assert!(
        !P18_DOC.is_empty(),
        "phase 18 doc must exist and be non-empty"
    );
}

// W-02
#[test]
fn v31_p18_doc_explains_export_command() {
    assert!(
        P18_DOC.contains("ledger export --json --file <PATH>"),
        "doc must explain the export command"
    );
}

// W-03
#[test]
fn v31_p18_doc_distinguishes_all_five_variants() {
    assert!(
        P18_DOC.contains("ledger inspect"),
        "must mention ledger inspect"
    );
    assert!(
        P18_DOC.contains("ledger inspect --json"),
        "must mention inspect --json"
    );
    assert!(
        P18_DOC.contains("ledger inspect --file <PATH>"),
        "must mention inspect --file"
    );
    assert!(
        P18_DOC.contains("ledger inspect --file <PATH> --json"),
        "must mention inspect --file --json"
    );
    assert!(
        P18_DOC.contains("ledger export --json --file <PATH>"),
        "must mention export --json --file"
    );
}

// W-04
#[test]
fn v31_p18_doc_includes_minimal_valid_example() {
    assert!(
        P18_DOC.contains("schema_version")
            && P18_DOC.contains("created_at")
            && P18_DOC.contains("updated_at")
            && P18_DOC.contains("host_id")
            && P18_DOC.contains("entries"),
        "doc must include minimal valid ledger JSON example fields"
    );
}

// W-05
#[test]
fn v31_p18_doc_includes_all_required_entry_fields() {
    assert!(P18_DOC.contains("entry_id"), "must mention entry_id");
    assert!(P18_DOC.contains("timestamp"), "must mention timestamp");
    assert!(
        P18_DOC.contains("attribution_scope"),
        "must mention attribution_scope"
    );
    assert!(
        P18_DOC.contains("enforcement_status"),
        "must mention enforcement_status"
    );
    assert!(
        P18_DOC.contains("reset_detected"),
        "must mention reset_detected"
    );
    assert!(
        P18_DOC.contains("reset_details"),
        "must mention reset_details"
    );
}

// W-06
#[test]
fn v31_p18_doc_includes_fixture_creation_example() {
    assert!(
        P18_DOC.contains("cat >") && P18_DOC.contains("/tmp/"),
        "doc must include copy-paste fixture creation example"
    );
}

// W-07
#[test]
fn v31_p18_doc_includes_jq_export_example() {
    assert!(
        P18_DOC.contains("jq") && P18_DOC.contains("export"),
        "doc must include jq export example"
    );
}

// W-08
#[test]
fn v31_p18_doc_mentions_shell_redirect_user_controlled() {
    assert!(
        P18_DOC.contains("shell redirection")
            && (P18_DOC.contains("no --output") || P18_DOC.contains("no `--output`")),
        "doc must mention shell redirect is user-controlled and Zelynic has no --output"
    );
}

// W-09
#[test]
fn v31_p18_doc_includes_missing_file_error() {
    assert!(
        P18_DOC.contains("--file <PATH> is required"),
        "doc must include missing --file error"
    );
}

// W-10
#[test]
fn v31_p18_doc_includes_missing_json_error() {
    assert!(
        P18_DOC.contains("--json is required"),
        "doc must include missing --json error"
    );
}

// W-11
#[test]
fn v31_p18_doc_includes_output_rejected() {
    assert!(
        P18_DOC.contains("--output")
            && (P18_DOC.contains("unexpected argument") || P18_DOC.contains("rejected")),
        "doc must include --output rejected"
    );
}

// W-12
#[test]
fn v31_p18_doc_includes_overwrite_rejected() {
    assert!(
        P18_DOC.contains("--overwrite")
            && (P18_DOC.contains("unexpected argument") || P18_DOC.contains("rejected")),
        "doc must include --overwrite rejected"
    );
}

// W-13
#[test]
fn v31_p18_doc_says_stdout_only() {
    assert!(P18_DOC.contains("stdout"), "doc must say stdout-only");
}

// W-14
#[test]
fn v31_p18_doc_says_no_output_file_no_overwrite() {
    assert!(
        P18_DOC.contains("no output file") || P18_DOC.contains("No output file"),
        "doc must say no output file"
    );
    assert!(
        P18_DOC.contains("no overwrite") || P18_DOC.contains("No overwrite"),
        "doc must say no overwrite"
    );
}

// W-15
#[test]
fn v31_p18_doc_says_no_internal_file_write() {
    assert!(
        P18_DOC.contains("no internal file write")
            || P18_DOC.contains("no file write")
            || P18_DOC.contains("No internal file write"),
        "doc must say no internal file write"
    );
}

// W-16
#[test]
fn v31_p18_doc_says_no_persistence_save_default_path() {
    assert!(
        P18_DOC.contains("persistence")
            && (P18_DOC.contains("no persistence") || P18_DOC.contains("No persistence")),
        "doc must say no persistence/save"
    );
    assert!(
        P18_DOC.contains("no default") || P18_DOC.contains("No default"),
        "doc must say no default path read"
    );
}

// W-17
#[test]
fn v31_p18_doc_says_no_live_proc_resolver_enforcement() {
    assert!(
        P18_DOC.contains("/proc") || P18_DOC.contains("sysfs"),
        "doc must say no live /proc/sysfs"
    );
    assert!(
        P18_DOC.contains("resolver"),
        "doc must say no live resolver"
    );
    assert!(
        P18_DOC.contains("no enforcement") || P18_DOC.contains("No enforcement"),
        "doc must say no enforcement"
    );
    assert!(
        P18_DOC.contains("nft") && P18_DOC.contains("cgroup"),
        "doc must say no nft/tc/cgroup/PID mutation"
    );
}

// W-18
#[test]
fn v31_p18_doc_says_export_schema_boundary() {
    assert!(
        P18_DOC.contains("export JSON is ledger JSON")
            || P18_DOC.contains("Export JSON is ledger JSON"),
        "doc must say export JSON is ledger JSON"
    );
    assert!(
        P18_DOC.contains("inspect JSON"),
        "doc must mention inspect JSON boundary"
    );
    assert!(
        P18_DOC.contains("usage JSON") || P18_DOC.contains("v3.0 usage"),
        "doc must mention usage JSON boundary"
    );
}

// W-19
#[test]
fn v31_p18_doc_troubleshoots_missing_entry_id() {
    assert!(
        P18_DOC.contains("entry_id") && P18_DOC.contains("Missing Field"),
        "doc must troubleshoot missing entry_id"
    );
}

// W-20
#[test]
fn v31_p18_doc_troubleshoots_combined_bytes_mismatch() {
    assert!(
        P18_DOC.contains("combined_bytes") && P18_DOC.contains("Mismatch"),
        "doc must troubleshoot combined_bytes mismatch"
    );
}

// W-21
#[test]
fn v31_p18_doc_troubleshoots_read_only_false() {
    assert!(
        P18_DOC.contains("read_only") && P18_DOC.contains("false"),
        "doc must troubleshoot read_only=false"
    );
}

// W-22
#[test]
fn v31_p18_doc_troubleshoots_wrong_scope_enforcement() {
    assert!(
        P18_DOC.contains("attribution_scope") && P18_DOC.contains("Wrong"),
        "doc must troubleshoot wrong attribution_scope"
    );
    assert!(
        P18_DOC.contains("enforcement_status") && P18_DOC.contains("Wrong"),
        "doc must troubleshoot wrong enforcement_status"
    );
}

// --- Export regression tests (W-23..W-31) ---

// W-23
#[test]
fn v31_p18_export_valid_still_succeeds() {
    let d = p18_tmp("succ");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p18_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_export(true, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// W-24
#[test]
fn v31_p18_export_jq_proof_fields() {
    let d = p18_tmp("jq");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p18_fixture(d.to_str().unwrap(), "v.json");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let ledger = read_ledger_file_inspect(&v).unwrap();
    let j = serialize_ledger_to_json(&ledger).unwrap();
    let p: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert_eq!(p["schema_version"], 1);
    assert_eq!(p["host_id"], "fixture-host");
    assert_eq!(p["entries"].as_array().unwrap().len(), 3);
    assert_eq!(p["entries"][0]["entry_id"], "snap-001");
    std::fs::remove_dir_all(&d).ok();
}

// W-25
#[test]
fn v31_p18_export_output_valid_json() {
    let ledger = build_fixture_ledger();
    let j = serialize_ledger_to_json(&ledger).unwrap();
    let p: serde_json::Value = serde_json::from_str(&j).unwrap();
    assert!(p.is_object());
}

// W-26
#[test]
fn v31_p18_export_output_deterministic() {
    let d = p18_tmp("det");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p18_fixture(d.to_str().unwrap(), "v.json");
    let v = validate_inspect_file_path(fp.to_str().unwrap()).unwrap();
    let ledger = read_ledger_file_inspect(&v).unwrap();
    let j1 = serialize_ledger_to_json(&ledger).unwrap();
    let j2 = serialize_ledger_to_json(&ledger).unwrap();
    assert_eq!(j1, j2);
    std::fs::remove_dir_all(&d).ok();
}

// W-27
#[test]
fn v31_p18_export_no_human_header() {
    let ledger = build_fixture_ledger();
    let j = serialize_ledger_to_json(&ledger).unwrap();
    assert!(!j.contains("Zelynic"));
    assert!(!j.contains("ledger inspect"));
}

// W-28
#[test]
fn v31_p18_export_missing_file_still_fails() {
    let r = handle_ledger_export(true, None);
    assert!(r.is_err());
    let e = r.unwrap_err().to_string();
    assert!(e.contains("--file"));
    assert!(!e.contains("design-gated"));
}

// W-29
#[test]
fn v31_p18_export_missing_json_still_fails() {
    let d = p18_tmp("noj");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p18_fixture(d.to_str().unwrap(), "v.json");
    let r = handle_ledger_export(false, Some(fp.to_str().unwrap()));
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("--json"));
    std::fs::remove_dir_all(&d).ok();
}

// W-30
#[test]
fn v31_p18_export_output_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--output", "/tmp/out.json"]).is_err(),
        "export --output must be rejected"
    );
}

// W-31
#[test]
fn v31_p18_export_overwrite_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--overwrite"]).is_err(),
        "export --overwrite must be rejected"
    );
}

// --- Inspect/usage regression tests (W-32..W-36) ---

// W-32
#[test]
fn v31_p18_inspect_fixture_still_works() {
    assert!(handle_ledger_inspect(false, None).is_ok());
}

// W-33
#[test]
fn v31_p18_inspect_json_fixture_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

// W-34
#[test]
fn v31_p18_inspect_file_still_works() {
    let d = p18_tmp("ifile");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p18_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_inspect(false, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// W-35
#[test]
fn v31_p18_inspect_file_json_still_works() {
    let d = p18_tmp("ifjson");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p18_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_inspect(true, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// W-36
#[test]
fn v31_p18_usage_delta_json_unchanged() {
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

// --- Structural safety tests (W-37..W-40) ---

// W-37: Version updated to 3.1.0 in Phase 22.
#[test]
fn v31_p18_version_is_3_1_0() {
    assert!(
        include_str!("../../Cargo.toml").contains("version = \"3.1.0\""),
        "version must be 3.1.0"
    );
}

// W-38
#[test]
fn v31_p18_all_files_under_1000_loc() {
    let files = [
        include_str!("ledger.rs"),
        include_str!("ledger_p13_tests.rs"),
        include_str!("ledger_p14_tests.rs"),
        include_str!("ledger_p15_tests.rs"),
        include_str!("ledger_p16_tests.rs"),
        include_str!("ledger_p17_tests.rs"),
        include_str!("ledger_p18_tests.rs"),
    ];
    let names = [
        "ledger.rs",
        "ledger_p13_tests.rs",
        "ledger_p14_tests.rs",
        "ledger_p15_tests.rs",
        "ledger_p16_tests.rs",
        "ledger_p17_tests.rs",
        "ledger_p18_tests.rs",
    ];
    for (src, name) in files.iter().zip(names.iter()) {
        let lc = src.lines().count();
        assert!(lc <= 1000, "{} must be under 1000 LOC, is {}", name, lc);
    }
}

// W-39
#[test]
fn v31_p18_no_new_dependencies() {
    let cargo = include_str!("../../Cargo.toml");
    assert!(!cargo.contains("tokio"), "no tokio dependency");
    assert!(!cargo.contains("reqwest"), "no reqwest dependency");
}

// W-40
#[test]
fn v31_p18_prod_no_output_file_write_apis() {
    let src = include_str!("ledger.rs");
    let end = src.find("#[cfg(test)]").unwrap_or(src.len());
    let prod = &src[..end];
    assert!(!prod.contains("create_dir"), "no create_dir");
    assert!(!prod.contains("remove_file"), "no remove_file");
    assert!(!prod.contains("remove_dir"), "no remove_dir");
    assert!(!prod.contains("rename("), "no rename");
    assert!(!prod.contains("fs::copy("), "no fs::copy");
    assert!(!prod.contains("File::create"), "no File::create");
    assert!(!prod.contains("OpenOptions"), "no OpenOptions");
}
