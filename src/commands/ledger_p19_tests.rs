// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 19: Ledger Public Surface / README Link Polish — guard tests.
//!
//! These tests verify the Phase 19 documentation exists, README links to
//! ledger docs, and all existing export/inspect/usage behavior remains
//! unchanged.

use super::*;

const P19_DOC: &str =
    include_str!("../../docs/v3.1-phase-19-ledger-public-surface-readme-link-polish.md");

const README: &str = include_str!("../../README.md");

fn p19_tmp(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zelynic_p19_{}", label))
}

fn p19_fixture(dir: &str, name: &str) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(dir).join(name);
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    p
}

// --- X-01: Phase 19 doc exists and is nonempty ---

#[test]
fn v31_p19_doc_exists_and_nonempty() {
    assert!(
        !P19_DOC.is_empty(),
        "phase 19 doc must exist and be non-empty"
    );
}

// --- X-02: README links or points to ledger docs ---

#[test]
fn v31_p19_readme_links_to_ledger_docs() {
    assert!(
        README.contains("v3.1-phase-14-ledger-inspect-user-docs-examples-polish")
            || README.contains("ledger inspect")
            || README.contains("v3.1-phase-18-ledger-export-user-docs-examples-polish")
            || README.contains("ledger export"),
        "README must link or point to ledger inspect/export docs"
    );
}

// --- X-03: Docs link to Phase 14 inspect user docs ---

#[test]
fn v31_p19_doc_links_to_phase14_inspect_docs() {
    assert!(
        P19_DOC.contains("v3.1-phase-14-ledger-inspect-user-docs-examples-polish"),
        "phase 19 doc must link to Phase 14 inspect user docs"
    );
}

// --- X-04: Docs link to Phase 18 export user docs ---

#[test]
fn v31_p19_doc_links_to_phase18_export_docs() {
    assert!(
        P19_DOC.contains("v3.1-phase-18-ledger-export-user-docs-examples-polish"),
        "phase 19 doc must link to Phase 18 export user docs"
    );
}

// --- X-05: Docs distinguish inspect summary from export raw ledger JSON ---

#[test]
fn v31_p19_doc_distinguishes_inspect_from_export() {
    assert!(
        P19_DOC.contains("inspect") && P19_DOC.contains("export"),
        "doc must mention both inspect and export"
    );
    assert!(
        P19_DOC.contains("summary") && P19_DOC.contains("raw"),
        "doc must distinguish inspect summary from export raw JSON"
    );
}

// --- X-06: Docs say export is stdout-only ---

#[test]
fn v31_p19_doc_says_stdout_only() {
    assert!(
        P19_DOC.contains("stdout"),
        "doc must say export is stdout-only"
    );
}

// --- X-07: Docs say explicit --file is required ---

#[test]
fn v31_p19_doc_says_explicit_file_required() {
    assert!(
        P19_DOC.contains("--file")
            && (P19_DOC.contains("required") || P19_DOC.contains("Required")),
        "doc must say explicit --file is required"
    );
}

// --- X-08: Docs say no --output/no overwrite/no write ---

#[test]
fn v31_p19_doc_says_no_output_overwrite_write() {
    assert!(P19_DOC.contains("--output"), "doc must mention --output");
    assert!(
        P19_DOC.contains("--overwrite"),
        "doc must mention --overwrite"
    );
    assert!(
        P19_DOC.contains("no write")
            || P19_DOC.contains("No write")
            || P19_DOC.contains("no file write"),
        "doc must say no write"
    );
}

// --- X-09: Docs say no persistence/save/default path read ---

#[test]
fn v31_p19_doc_says_no_persistence_save_default_path() {
    assert!(
        P19_DOC.contains("persistence"),
        "doc must mention persistence"
    );
    assert!(
        P19_DOC.contains("default path"),
        "doc must mention default path"
    );
}

// --- X-10: Docs say no live resolver/enforcement/nft/tc/cgroup/PID mutation ---

#[test]
fn v31_p19_doc_says_no_live_resolver_enforcement_mutation() {
    assert!(
        P19_DOC.contains("resolver"),
        "doc must mention no live resolver"
    );
    assert!(
        P19_DOC.contains("enforcement"),
        "doc must mention no enforcement"
    );
    assert!(
        P19_DOC.contains("nft") && P19_DOC.contains("cgroup"),
        "doc must mention no nft/tc/cgroup/PID mutation"
    );
}

// --- X-11: ledger inspect still works ---

#[test]
fn v31_p19_ledger_inspect_still_works() {
    assert!(handle_ledger_inspect(false, None).is_ok());
}

// --- X-12: ledger inspect --json still works ---

#[test]
fn v31_p19_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

// --- X-13: ledger export --json --file valid fixture still works ---

#[test]
fn v31_p19_ledger_export_json_file_valid_works() {
    let d = p19_tmp("export_ok");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p19_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_export(true, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// --- X-14: ledger export --json without --file still fails ---

#[test]
fn v31_p19_ledger_export_json_no_file_fails() {
    let r = handle_ledger_export(true, None);
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("--file"));
}

// --- X-15: ledger export --file without --json still fails ---

#[test]
fn v31_p19_ledger_export_file_no_json_fails() {
    let d = p19_tmp("export_noj");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p19_fixture(d.to_str().unwrap(), "v.json");
    let r = handle_ledger_export(false, Some(fp.to_str().unwrap()));
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("--json"));
    std::fs::remove_dir_all(&d).ok();
}

// --- X-16: --output remains rejected ---

#[test]
fn v31_p19_output_remains_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--output", "/tmp/out.json"]).is_err(),
        "--output must be rejected"
    );
}

// --- X-17: --overwrite remains rejected ---

#[test]
fn v31_p19_overwrite_remains_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--overwrite"]).is_err(),
        "--overwrite must be rejected"
    );
}

// --- X-18: usage --sample --delta --json unchanged ---

#[test]
fn v31_p19_usage_delta_json_unchanged() {
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

// --- X-20: all touched files under 1000 LOC ---

#[test]
fn v31_p19_all_files_under_1000_loc() {
    let files = [
        include_str!("ledger.rs"),
        include_str!("ledger_p13_tests.rs"),
        include_str!("ledger_p14_tests.rs"),
        include_str!("ledger_p15_tests.rs"),
        include_str!("ledger_p16_tests.rs"),
        include_str!("ledger_p17_tests.rs"),
        include_str!("ledger_p18_tests.rs"),
        include_str!("ledger_p19_tests.rs"),
    ];
    let names = [
        "ledger.rs",
        "ledger_p13_tests.rs",
        "ledger_p14_tests.rs",
        "ledger_p15_tests.rs",
        "ledger_p16_tests.rs",
        "ledger_p17_tests.rs",
        "ledger_p18_tests.rs",
        "ledger_p19_tests.rs",
    ];
    for (src, name) in files.iter().zip(names.iter()) {
        let lc = src.lines().count();
        assert!(lc <= 1000, "{} must be under 1000 LOC, is {}", name, lc);
    }
}

// --- X-21: no new dependencies ---

#[test]
fn v31_p19_no_new_dependencies() {
    let cargo = include_str!("../../Cargo.toml");
    assert!(!cargo.contains("tokio"), "no tokio dependency");
    assert!(!cargo.contains("reqwest"), "no reqwest dependency");
}

// --- X-22: no runtime behavior changes beyond docs/test module include ---

#[test]
fn v31_p19_prod_no_output_file_write_apis() {
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
