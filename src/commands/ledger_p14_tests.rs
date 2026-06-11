// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 14: Ledger Inspect User Docs / Examples Polish — guard tests.
//!
//! These tests verify that the Phase 14 documentation exists, contains
//! all required content, and that all existing runtime behaviors remain
//! unchanged. No production code is tested or modified in this phase.

use super::*;

// === Section S: Phase 14 — doc content and CLI guard tests ===

const P14_DOC: &str =
    include_str!("../../docs/v3.1-phase-14-ledger-inspect-user-docs-examples-polish.md");

// S-01: Phase 14 doc exists and is nonempty.
#[test]
fn v31_p14_doc_exists_and_nonempty() {
    assert!(
        !P14_DOC.is_empty(),
        "phase 14 doc must exist and be non-empty"
    );
}

// S-02: Phase 14 doc includes all four user commands.
#[test]
fn v31_p14_doc_includes_all_four_commands() {
    assert!(P14_DOC.contains("zelynic ledger inspect"));
    assert!(P14_DOC.contains("zelynic ledger inspect --json"));
    assert!(P14_DOC.contains("zelynic ledger inspect --file <PATH>"));
    assert!(P14_DOC.contains("zelynic ledger inspect --file <PATH> --json"));
}

// S-03: Phase 14 doc clearly says no --file means fixture-only preview.
#[test]
fn v31_p14_doc_says_fixture_only_when_no_file() {
    assert!(
        P14_DOC.contains("fixture-only")
            || P14_DOC.contains("fixture only")
            || P14_DOC.contains("fixture preview"),
        "doc must say no --file means fixture-only"
    );
    // Also check that the doc explicitly distinguishes the two modes.
    assert!(
        P14_DOC.contains("No `--file`") || P14_DOC.contains("without `--file`"),
        "doc must mention the no-file case explicitly"
    );
}

// S-04: Phase 14 doc clearly says --file is explicit read-only file inspect.
#[test]
fn v31_p14_doc_says_explicit_read_only_file_inspect() {
    assert!(
        P14_DOC.contains("explicit read-only") || P14_DOC.contains("explicit file read"),
        "doc must say --file is explicit read-only file inspect"
    );
}

// S-05: Phase 14 doc includes a minimal valid ledger JSON example.
#[test]
fn v31_p14_doc_includes_valid_json_example() {
    assert!(P14_DOC.contains("schema_version"));
    assert!(P14_DOC.contains("entries"));
    assert!(P14_DOC.contains("read_only"));
    assert!(P14_DOC.contains("interface-level only"));
    assert!(P14_DOC.contains("inactive/not implemented"));
    assert!(P14_DOC.contains("combined_bytes"));
}

// S-06: Phase 14 doc includes invalid examples.
#[test]
fn v31_p14_doc_includes_invalid_examples() {
    assert!(
        P14_DOC.contains("parent traversal"),
        "doc must show parent traversal example"
    );
    assert!(
        P14_DOC.contains("nonexistent") || P14_DOC.contains("Nonexistent"),
        "doc must show nonexistent file example"
    );
    assert!(
        P14_DOC.contains("malformed JSON") || P14_DOC.contains("Malformed JSON"),
        "doc must show malformed JSON example"
    );
    assert!(
        P14_DOC.contains("unsupported schema"),
        "doc must show unsupported schema version example"
    );
    assert!(
        P14_DOC.contains("missing") || P14_DOC.contains("Missing"),
        "doc must show missing field example"
    );
    assert!(
        P14_DOC.contains("invalid") || P14_DOC.contains("Invalid"),
        "doc must show invalid invariant example"
    );
}

// S-07: Phase 14 doc says ledger export remains gated.
#[test]
fn v31_p14_doc_says_export_gated() {
    assert!(
        P14_DOC.contains("export")
            && (P14_DOC.contains("gated") || P14_DOC.contains("design-gated")),
        "doc must say ledger export remains gated"
    );
}

// S-08: Phase 14 doc says no save/write/persistence.
#[test]
fn v31_p14_doc_says_no_save_write_persistence() {
    assert!(
        P14_DOC.contains("no save") || P14_DOC.contains("No save"),
        "doc must say no save"
    );
    assert!(
        P14_DOC.contains("no file write") || P14_DOC.contains("No file write"),
        "doc must say no file write"
    );
    assert!(
        P14_DOC.contains("persistence")
            && (P14_DOC.contains("not enabled") || P14_DOC.contains("not implemented")),
        "doc must say persistence not enabled"
    );
}

// S-09: Phase 14 doc says no nft/tc/cgroup/PID mutation.
#[test]
fn v31_p14_doc_says_no_nft_tc_cgroup_pid_mutation() {
    assert!(
        P14_DOC.contains("no nft") || P14_DOC.contains("No nft"),
        "doc must say no nft mutation"
    );
    assert!(
        P14_DOC.contains("cgroup") || P14_DOC.contains("PID"),
        "doc must say no cgroup or PID mutation"
    );
}

// S-10: Phase 14 doc says v3.0 usage JSON remains unchanged.
#[test]
fn v31_p14_doc_says_v3_usage_unchanged() {
    assert!(
        P14_DOC.contains("v3.0 usage JSON") && P14_DOC.contains("unchanged"),
        "doc must say v3.0 usage JSON remains unchanged"
    );
}

// S-11: Current ledger inspect still works (fixture text).
#[test]
fn v31_p14_ledger_inspect_still_works() {
    let result = handle_ledger_inspect(false, None);
    assert!(
        result.is_ok(),
        "ledger inspect (fixture text) must still work"
    );
}

// S-12: Current ledger inspect --json still works (fixture JSON).
#[test]
fn v31_p14_ledger_inspect_json_still_works() {
    let result = handle_ledger_inspect(true, None);
    assert!(
        result.is_ok(),
        "ledger inspect --json (fixture JSON) must still work"
    );
}

// S-13: Current ledger inspect --file valid fixture still works.
#[test]
fn v31_p14_ledger_inspect_file_valid_fixture_works() {
    let dir = std::env::temp_dir().join("zelynic_p14_fv");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("v14.json");
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    let result = handle_ledger_inspect(false, Some(p.to_str().unwrap()));
    assert!(
        result.is_ok(),
        "ledger inspect --file valid fixture must still work"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// S-14: Current ledger inspect --file valid fixture --json still works.
#[test]
fn v31_p14_ledger_inspect_file_valid_fixture_json_works() {
    let dir = std::env::temp_dir().join("zelynic_p14_fj");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("v14j.json");
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    let result = handle_ledger_inspect(true, Some(p.to_str().unwrap()));
    assert!(
        result.is_ok(),
        "ledger inspect --file valid fixture --json must still work"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// S-15: ledger export --json is rejected without --file (Phase 16 activated).
#[test]
fn v31_p14_ledger_export_rejected_without_file() {
    use crate::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["zelynic", "ledger", "export", "--json"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("--file"),
        "export must be rejected with --file message: {}",
        err
    );
}

// S-16: No output path / overwrite / save flag exists.
#[test]
fn v31_p14_no_output_overwrite_save_flags() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "inspect", "--output", "/tmp/o.json"]).is_err(),
        "--output must not exist"
    );
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "inspect", "--save"]).is_err(),
        "--save must not exist"
    );
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "inspect", "--overwrite"]).is_err(),
        "--overwrite must not exist"
    );
}

// S-17: Version updated to 3.1.0 in Phase 22.
#[test]
fn v31_p14_version_is_3_1_0() {
    assert!(
        include_str!("../../Cargo.toml").contains("version = \"3.1.0\""),
        "version must be 3.1.0"
    );
}

// S-18: All touched files remain under 1000 LOC.
#[test]
fn v31_p14_all_files_under_1000_loc() {
    let files = [
        include_str!("ledger.rs"),
        include_str!("ledger_p13_tests.rs"),
        include_str!("ledger_p14_tests.rs"),
    ];
    let names = ["ledger.rs", "ledger_p13_tests.rs", "ledger_p14_tests.rs"];
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
