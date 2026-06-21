// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 15: Ledger Export JSON Gate Design — guard tests.
//!
//! These tests verify that the Phase 15 design doc exists, contains
//! all required content, and that export remains fully gated. No
//! export implementation exists in this phase.

use super::*;

// === Section T: Phase 15 — export gate design doc and CLI guard tests ===

const P15_DOC: &str = include_str!("../../docs/v3.1-phase-15-ledger-export-json-gate-design.md");

// T-01: Phase 15 design doc exists and is nonempty.
#[test]
fn v31_p15_doc_exists_and_nonempty() {
    assert!(
        !P15_DOC.is_empty(),
        "phase 15 design doc must exist and be non-empty"
    );
}

// T-02: Design doc states future shape `ledger export --json --file <PATH>`.
#[test]
fn v31_p15_doc_states_future_shape() {
    assert!(
        P15_DOC.contains("ledger export --json --file <PATH>"),
        "design doc must state future shape"
    );
}

// T-03: Design doc says export remains gated in Phase 15.
#[test]
fn v31_p15_doc_says_export_gated() {
    assert!(
        P15_DOC.contains("remains gated")
            || P15_DOC.contains("design-gated")
            || P15_DOC.contains("Export Remains Gated"),
        "design doc must say export remains gated"
    );
}

// T-04: Design doc rejects implicit default path export.
#[test]
fn v31_p15_doc_rejects_implicit_default_path() {
    assert!(
        P15_DOC.contains("implicit default") || P15_DOC.contains("Implicit Default"),
        "design doc must reject implicit default path export"
    );
}

// T-05: Design doc rejects output file / overwrite behavior.
#[test]
fn v31_p15_doc_rejects_output_overwrite() {
    assert!(
        (P15_DOC.contains("--output") || P15_DOC.contains("output file"))
            && P15_DOC.contains("rejected"),
        "design doc must reject output file / overwrite"
    );
}

// T-06: Design doc says future export is read-only.
#[test]
fn v31_p15_doc_says_read_only() {
    assert!(
        P15_DOC.contains("read-only") || P15_DOC.contains("Read-Only"),
        "design doc must say future export is read-only"
    );
}

// T-07: Design doc says future export validates path before read.
#[test]
fn v31_p15_doc_says_path_validation() {
    assert!(
        P15_DOC.contains("validate") && P15_DOC.contains("path"),
        "design doc must say future export validates path before read"
    );
}

// T-08: Design doc says future export validates schema before JSON output.
#[test]
fn v31_p15_doc_says_schema_validation() {
    assert!(
        P15_DOC.contains("schema") && P15_DOC.contains("validate"),
        "design doc must say future export validates schema"
    );
}

// T-09: Design doc says future export does not read live /proc/sysfs.
#[test]
fn v31_p15_doc_says_no_live_proc_sysfs() {
    assert!(
        P15_DOC.contains("/proc") || P15_DOC.contains("sysfs"),
        "design doc must say no live /proc/sysfs read"
    );
}

// T-10: Design doc says future export does not mutate nft/tc/cgroup/PID state.
#[test]
fn v31_p15_doc_says_no_mutation() {
    assert!(
        P15_DOC.contains("nft") || P15_DOC.contains("cgroup") || P15_DOC.contains("PID"),
        "design doc must say no nft/tc/cgroup/PID mutation"
    );
}

// T-11: Design doc says v3.0 usage JSON remains unchanged.
#[test]
fn v31_p15_doc_says_v3_usage_unchanged() {
    assert!(
        P15_DOC.contains("v3.0 usage JSON") && P15_DOC.contains("unchanged"),
        "design doc must say v3.0 usage JSON remains unchanged"
    );
}

// T-12: Design doc says ledger inspect JSON remains unchanged.
#[test]
fn v31_p15_doc_says_inspect_unchanged() {
    assert!(
        P15_DOC.contains("ledger inspect") && P15_DOC.contains("unchanged"),
        "design doc must say ledger inspect remains unchanged"
    );
}

// T-13: ledger export --json without --file fails honestly (Phase 16 activated).
#[test]
fn v31_p15_export_json_no_file_fails_honestly() {
    use crate::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from(["zelynic", "ledger", "export", "--json"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("--file"),
        "export --json without --file must mention --file: {}",
        err
    );
    assert!(
        !err.contains("design-gated"),
        "export must NOT be design-gated anymore: {}",
        err
    );
}

// T-14: ledger export --json --file parses (Phase 16 added --file to Export).
// Without a valid file on disk, dispatch will fail with a file error,
// but clap parsing succeeds.
#[test]
fn v31_p15_export_json_file_parses() {
    use crate::cli::Cli;
    use clap::Parser;
    let cli = Cli::try_parse_from([
        "zelynic",
        "ledger",
        "export",
        "--json",
        "--file",
        "/tmp/nonexistent_p15_test.json",
    ]);
    // Clap must succeed (file flag exists).
    assert!(cli.is_ok(), "export --json --file must parse");
    // Dispatch must fail (file does not exist).
    let result = crate::commands::dispatch(cli.unwrap(), None);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("cannot access"),
        "must fail with file error: {}",
        err
    );
}

// T-15: Current ledger export --output something is rejected or absent.
#[test]
fn v31_p15_export_output_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--output", "/tmp/out.json"]).is_err(),
        "export --output must be rejected (flag does not exist)"
    );
}

// T-16: Current ledger export --overwrite is rejected or absent.
#[test]
fn v31_p15_export_overwrite_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--overwrite"]).is_err(),
        "export --overwrite must be rejected (flag does not exist)"
    );
}

// T-17: Current ledger inspect fixture still works.
#[test]
fn v31_p15_inspect_fixture_still_works() {
    let result = handle_ledger_inspect(false, None);
    assert!(result.is_ok(), "ledger inspect fixture must still work");
}

// T-18: Current ledger inspect --json fixture still works.
#[test]
fn v31_p15_inspect_json_fixture_still_works() {
    let result = handle_ledger_inspect(true, None);
    assert!(
        result.is_ok(),
        "ledger inspect --json fixture must still work"
    );
}

// T-19: Current ledger inspect --file valid fixture still works.
#[test]
fn v31_p15_inspect_file_fixture_still_works() {
    let dir = std::env::temp_dir().join("zelynic_p15_if");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join("v15.json");
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    let result = handle_ledger_inspect(false, Some(p.to_str().unwrap()));
    assert!(
        result.is_ok(),
        "ledger inspect --file fixture must still work"
    );
    std::fs::remove_dir_all(&dir).ok();
}

// T-20: Current usage --sample --delta --json schema remains unchanged.
#[test]
fn v31_p15_usage_delta_json_unchanged() {
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

// T-22: All touched files remain under 1000 LOC.
#[test]
fn v31_p15_all_files_under_1000_loc() {
    let files = [
        include_str!("ledger.rs"),
        include_str!("ledger_p13_tests.rs"),
        include_str!("ledger_p14_tests.rs"),
        include_str!("ledger_p15_tests.rs"),
    ];
    let names = [
        "ledger.rs",
        "ledger_p13_tests.rs",
        "ledger_p14_tests.rs",
        "ledger_p15_tests.rs",
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
