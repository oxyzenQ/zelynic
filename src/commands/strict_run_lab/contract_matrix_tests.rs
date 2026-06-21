// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Contract + matrix invariant tests.
//!
//! Validates doc invariants, CLI visibility, schema/version stability,
//! and forbidden-feature absence for the strict-run-lab experiment.

use super::strict_run_lab_tests::module_source;
use clap::CommandFactory;

// === Section M: Contract + matrix invariants ===

const CONTRACT_DOC: &str = include_str!("../../../docs/strict-run-wrapper-stable-contract.md");
const MATRIX_DOC: &str = include_str!("../../../docs/strict-run-lab-manual-validation-matrix.md");

#[test]
fn contract_doc_has_required_sections() {
    let d = CONTRACT_DOC;
    assert!(d.contains("Chosen Future Stable Command Shape"));
    assert!(d.contains("Safety Contract"));
    assert!(d.contains("Traffic Proof Contract"));
    assert!(d.contains("Cleanup Contract"));
    assert!(d.contains("Compatibility Contract"));
    assert!(d.contains("Required Before Stable Promotion"));
    assert!(d.contains("strict --run"));
    assert!(d.contains("run --net-limit"));
}

#[test]
fn matrix_doc_exists_with_all_scenarios() {
    for id in [
        "SRL-MVM-001",
        "SRL-MVM-002",
        "SRL-MVM-003",
        "SRL-MVM-004",
        "SRL-MVM-005",
        "SRL-MVM-006",
        "SRL-MVM-007",
        "SRL-MVM-008",
        "SRL-MVM-009",
        "SRL-MVM-010",
        "SRL-MVM-011",
        "SRL-MVM-012",
    ] {
        assert!(MATRIX_DOC.contains(id), "missing scenario {id}");
    }
}

#[test]
fn matrix_doc_includes_counter_fields() {
    let d = MATRIX_DOC;
    assert!(d.contains("nft socket cgroupv2 counter behavior"));
    assert!(d.contains("ct mark counter behavior"));
    assert!(d.contains("download policer counter behavior"));
    assert!(d.contains("drop counter behavior"));
}

#[test]
fn matrix_doc_includes_cleanup_criteria() {
    assert!(MATRIX_DOC.contains("expected cleanup behavior"));
    assert!(MATRIX_DOC.contains("orphaned"));
}

#[test]
fn matrix_doc_says_experimental() {
    assert!(MATRIX_DOC.contains("experimental"));
    assert!(MATRIX_DOC.contains("NOT promote"));
}

#[test]
fn matrix_doc_says_stable_not_implemented() {
    assert!(MATRIX_DOC.contains("does NOT implement stable wrapper"));
    assert!(MATRIX_DOC.contains("does NOT promote"));
}

#[test]
fn no_stable_alias_in_cli() {
    assert!(!crate::cli::Cli::command()
        .find_subcommand_mut("run")
        .unwrap()
        .render_long_help()
        .to_string()
        .contains("net-limit"));
    // --run-lab is hidden; check normal help (render_long_help shows hidden args).
    let h = crate::cli::Cli::command()
        .find_subcommand_mut("strict")
        .unwrap()
        .render_help()
        .to_string();
    assert!(!h.contains("--run "), "stable --run must not exist");
    assert!(!h.contains("run-lab"), "hidden --run-lab must not appear");
}

#[test]
fn matrix_hidden_from_help() {
    assert!(!crate::cli::Cli::command()
        .render_help()
        .to_string()
        .contains("strict-run-lab"));
}

#[test]
fn matrix_json_schema_unchanged() {
    let s = module_source();
    assert!(!s.contains("schema_version") && !s.contains("UsageSnapshot"));
}

#[test]
fn matrix_strict_unchanged() {
    let s = module_source();
    assert!(!s.contains("handle_strict(") && !s.contains("force_reconnect"));
}

#[test]
fn matrix_no_forbidden_features() {
    let s = module_source();
    assert!(
        !s.contains("daemon")
            && !s.contains("watch")
            && !s.contains("quota")
            && !s.contains("LedgerPersistencePlan")
            && !s.contains("ebpf")
            && !s.contains("eBPF")
    );
}
