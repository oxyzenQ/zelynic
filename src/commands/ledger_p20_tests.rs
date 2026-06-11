// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 20: Ledger Release Readiness Freeze — guard tests.
//!
//! These tests verify the Phase 20 documentation exists, README links to
//! ledger docs, all existing export/inspect/usage behavior remains
//! unchanged, and no runtime behavior was added.

use super::*;

const P20_DOC: &str = include_str!("../../docs/v3.1-phase-20-ledger-release-readiness-freeze.md");

const README: &str = include_str!("../../README.md");

fn p20_tmp(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zelynic_p20_{}", label))
}

fn p20_fixture(dir: &str, name: &str) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(dir).join(name);
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    p
}

// --- Y-01: Phase 20 doc exists and is nonempty ---

#[test]
fn v31_p20_doc_exists_and_nonempty() {
    assert!(
        !P20_DOC.is_empty(),
        "phase 20 doc must exist and be non-empty"
    );
}

// --- Y-02: Doc says release-readiness freeze only ---

#[test]
fn v31_p20_doc_says_release_readiness_freeze_only() {
    assert!(
        P20_DOC.contains("release-readiness freeze")
            || P20_DOC.contains("Release Readiness Freeze"),
        "doc must say release-readiness freeze"
    );
}

// --- Y-03: Doc says no runtime behavior change ---

#[test]
fn v31_p20_doc_says_no_runtime_behavior_change() {
    assert!(
        P20_DOC.contains("no runtime behavior") || P20_DOC.contains("No runtime behavior"),
        "doc must say no runtime behavior change"
    );
}

// --- Y-04: Doc says no CLI visibility change ---

#[test]
fn v31_p20_doc_says_no_cli_visibility_change() {
    assert!(
        P20_DOC.contains("No CLI Visibility Changed")
            || P20_DOC.contains("no CLI visibility")
            || (P20_DOC.contains("CLI") && P20_DOC.contains("unchanged")),
        "doc must say no CLI visibility change"
    );
}

// --- Y-05: Doc lists all five ledger command shapes ---

#[test]
fn v31_p20_doc_lists_all_five_command_shapes() {
    assert!(
        P20_DOC.contains("ledger inspect"),
        "must list ledger inspect"
    );
    assert!(
        P20_DOC.contains("ledger inspect --json"),
        "must list ledger inspect --json"
    );
    assert!(
        P20_DOC.contains("ledger inspect --file"),
        "must list ledger inspect --file"
    );
    assert!(P20_DOC.contains("ledger export"), "must list ledger export");
    assert!(
        P20_DOC.contains("export --json --file"),
        "must list export --json --file"
    );
}

// --- Y-06: Doc distinguishes inspect summary from export raw ledger JSON ---

#[test]
fn v31_p20_doc_distinguishes_inspect_summary_from_export_raw() {
    assert!(
        P20_DOC.contains("summary") && P20_DOC.contains("raw"),
        "doc must distinguish inspect summary from export raw JSON"
    );
}

// --- Y-07: Doc says export is stdout-only ---

#[test]
fn v31_p20_doc_says_export_stdout_only() {
    assert!(
        P20_DOC.contains("stdout-only") || P20_DOC.contains("stdout only"),
        "doc must say export is stdout-only"
    );
}

// --- Y-08: Doc says explicit --file required ---

#[test]
fn v31_p20_doc_says_explicit_file_required() {
    assert!(
        P20_DOC.contains("--file")
            && (P20_DOC.contains("required") || P20_DOC.contains("Required")),
        "doc must say explicit --file is required"
    );
}

// --- Y-09: Doc says --json required ---

#[test]
fn v31_p20_doc_says_json_required() {
    assert!(
        P20_DOC.contains("--json required")
            || (P20_DOC.contains("--json") && P20_DOC.contains("mandatory")),
        "doc must say --json is required"
    );
}

// --- Y-10: Doc says path validation before read ---

#[test]
fn v31_p20_doc_says_path_validation_before_read() {
    assert!(
        P20_DOC.contains("path validation") || P20_DOC.contains("Path validation"),
        "doc must say path validation before read"
    );
}

// --- Y-11: Doc says schema validation before output ---

#[test]
fn v31_p20_doc_says_schema_validation_before_output() {
    assert!(
        P20_DOC.contains("schema validation") || P20_DOC.contains("Schema validation"),
        "doc must say schema validation before output"
    );
}

// --- Y-12: Doc says no output file / no overwrite ---

#[test]
fn v31_p20_doc_says_no_output_file_no_overwrite() {
    assert!(P20_DOC.contains("--output"), "doc must mention --output");
    assert!(
        P20_DOC.contains("--overwrite"),
        "doc must mention --overwrite"
    );
    assert!(
        P20_DOC.contains("no output file") || P20_DOC.contains("No output file"),
        "doc must say no output file"
    );
}

// --- Y-13: Doc says no internal file write ---

#[test]
fn v31_p20_doc_says_no_internal_file_write() {
    assert!(
        P20_DOC.contains("No internal file write")
            || P20_DOC.contains("no internal file write")
            || (P20_DOC.contains("no file write") && P20_DOC.contains("production")),
        "doc must say no internal file write"
    );
}

// --- Y-14: Doc says no persistence/save/default path read ---

#[test]
fn v31_p20_doc_says_no_persistence_save_default_path() {
    assert!(
        P20_DOC.contains("persistence"),
        "doc must mention persistence"
    );
    assert!(P20_DOC.contains("default"), "doc must mention default path");
}

// --- Y-15: Doc says no live /proc/sysfs read ---

#[test]
fn v31_p20_doc_says_no_live_proc_sysfs_read() {
    assert!(
        P20_DOC.contains("/proc") || P20_DOC.contains("proc"),
        "doc must mention /proc"
    );
}

// --- Y-16: Doc says no live resolver / no enforcement / no permission mode ---

#[test]
fn v31_p20_doc_says_no_live_resolver_no_enforcement_no_permission() {
    assert!(
        P20_DOC.contains("resolver"),
        "doc must mention no live resolver"
    );
    assert!(
        P20_DOC.contains("enforcement"),
        "doc must mention no enforcement"
    );
    assert!(
        P20_DOC.contains("permission"),
        "doc must mention no permission mode"
    );
}

// --- Y-17: Doc says no quota / no eBPF / no daemon-watch ---

#[test]
fn v31_p20_doc_says_no_quota_no_ebpf_no_daemon_watch() {
    assert!(P20_DOC.contains("quota"), "doc must mention no quota");
    assert!(
        P20_DOC.contains("eBPF") || P20_DOC.contains("ebpf"),
        "doc must mention no eBPF"
    );
    assert!(
        P20_DOC.contains("daemon") || P20_DOC.contains("watch"),
        "doc must mention no daemon/watch"
    );
}

// --- Y-18: Doc says no nft/tc/cgroup/PID/Zelynic mutation ---

#[test]
fn v31_p20_doc_says_no_nft_tc_cgroup_pid_mutation() {
    assert!(P20_DOC.contains("nft"), "doc must mention nft");
    assert!(P20_DOC.contains("tc"), "doc must mention tc");
    assert!(P20_DOC.contains("cgroup"), "doc must mention cgroup");
    assert!(P20_DOC.contains("PID"), "doc must mention PID");
}

// --- Y-19: Doc says v3.0 usage JSON unchanged ---

#[test]
fn v31_p20_doc_says_v30_usage_json_unchanged() {
    assert!(
        P20_DOC.contains("v3.0 usage") && P20_DOC.contains("unchanged"),
        "doc must say v3.0 usage JSON unchanged"
    );
}

// --- Y-20: Doc says ledger inspect JSON unchanged ---

#[test]
fn v31_p20_doc_says_ledger_inspect_json_unchanged() {
    assert!(
        P20_DOC.contains("inspect JSON")
            && (P20_DOC.contains("unchanged") || P20_DOC.contains("frozen")),
        "doc must say ledger inspect JSON unchanged"
    );
}

// --- Y-21: Doc says export JSON unchanged ---

#[test]
fn v31_p20_doc_says_export_json_unchanged() {
    assert!(
        P20_DOC.contains("export JSON")
            && (P20_DOC.contains("unchanged") || P20_DOC.contains("frozen")),
        "doc must say export JSON unchanged"
    );
}

// --- Y-22: Doc says no version bump/tag/release/publish in Phase 20 ---

#[test]
fn v31_p20_doc_says_no_version_bump_tag_release_publish() {
    assert!(
        P20_DOC.contains("No version bump") || P20_DOC.contains("no version bump"),
        "doc must say no version bump"
    );
    assert!(
        P20_DOC.contains("No tag") || P20_DOC.contains("no tag"),
        "doc must say no tag"
    );
    assert!(P20_DOC.contains("release"), "doc must mention release");
    assert!(P20_DOC.contains("publish"), "doc must mention publish");
}

// --- Y-23: README still links to Phase 14 inspect docs ---

#[test]
fn v31_p20_readme_still_links_phase14_inspect() {
    assert!(
        README.contains("v3.1-phase-14-ledger-inspect-user-docs-examples-polish"),
        "README must still link to Phase 14 inspect docs"
    );
}

// --- Y-24: README still links to Phase 18 export docs ---

#[test]
fn v31_p20_readme_still_links_phase18_export() {
    assert!(
        README.contains("v3.1-phase-18-ledger-export-user-docs-examples-polish"),
        "README must still link to Phase 18 export docs"
    );
}

// --- Y-25: README or Phase 19/20 docs preserve hidden/experimental ledger wording ---

#[test]
fn v31_p20_hidden_experimental_wording_preserved() {
    let has_readme = README.contains("experimental") || README.contains("hidden");
    let has_p20 = P20_DOC.contains("experimental") || P20_DOC.contains("hidden");
    assert!(
        has_readme || has_p20,
        "README or Phase 20 doc must preserve hidden/experimental wording"
    );
}

// --- Y-26: ledger inspect still works ---

#[test]
fn v31_p20_ledger_inspect_still_works() {
    assert!(handle_ledger_inspect(false, None).is_ok());
}

// --- Y-27: ledger inspect --json still works ---

#[test]
fn v31_p20_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

// --- Y-28: ledger inspect --file <valid> still works ---

#[test]
fn v31_p20_ledger_inspect_file_valid_still_works() {
    let d = p20_tmp("inspect_file");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p20_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_inspect(false, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// --- Y-29: ledger inspect --file <valid> --json still works ---

#[test]
fn v31_p20_ledger_inspect_file_json_still_works() {
    let d = p20_tmp("inspect_filej");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p20_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_inspect(true, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// --- Y-30: ledger export --json --file <valid> still works ---

#[test]
fn v31_p20_ledger_export_json_file_valid_still_works() {
    let d = p20_tmp("export_ok");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p20_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_export(true, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// --- Y-31: ledger export --json without --file still fails honestly ---

#[test]
fn v31_p20_ledger_export_json_no_file_fails() {
    let r = handle_ledger_export(true, None);
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("--file"));
}

// --- Y-32: ledger export --file <valid> without --json still fails honestly ---

#[test]
fn v31_p20_ledger_export_file_no_json_fails() {
    let d = p20_tmp("export_noj");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p20_fixture(d.to_str().unwrap(), "v.json");
    let r = handle_ledger_export(false, Some(fp.to_str().unwrap()));
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("--json"));
    std::fs::remove_dir_all(&d).ok();
}

// --- Y-33: ledger export --output <PATH> remains rejected ---

#[test]
fn v31_p20_output_remains_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--output", "/tmp/out.json"]).is_err(),
        "--output must be rejected"
    );
}

// --- Y-34: ledger export --overwrite remains rejected ---

#[test]
fn v31_p20_overwrite_remains_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--overwrite"]).is_err(),
        "--overwrite must be rejected"
    );
}

// --- Y-35: usage --sample --delta --json schema remains unchanged ---

#[test]
fn v31_p20_usage_delta_json_schema_unchanged() {
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

// --- Y-36: Ledger command remains hidden from public help ---

#[test]
fn v31_p20_ledger_remains_hidden() {
    use crate::cli::Cli;
    use clap::CommandFactory;
    let help = Cli::command().render_help().to_string();
    assert!(
        !help.contains("ledger"),
        "ledger must not appear in normal --help output"
    );
}

// --- Y-37: No new dependencies ---

#[test]
fn v31_p20_no_new_dependencies() {
    let cargo = include_str!("../../Cargo.toml");
    assert!(!cargo.contains("tokio"), "no tokio dependency");
    assert!(!cargo.contains("reqwest"), "no reqwest dependency");
}

// --- Y-38: Version updated to 3.1.0 in Phase 22 ---

#[test]
fn v31_p20_version_is_3_1_0() {
    assert!(
        include_str!("../../Cargo.toml").contains("version = \"3.1.0\""),
        "version must be 3.1.0"
    );
}

// --- Y-39: All touched files under 1000 LOC ---

#[test]
fn v31_p20_all_files_under_1000_loc() {
    let files = [
        include_str!("ledger.rs"),
        include_str!("ledger_p13_tests.rs"),
        include_str!("ledger_p14_tests.rs"),
        include_str!("ledger_p15_tests.rs"),
        include_str!("ledger_p16_tests.rs"),
        include_str!("ledger_p17_tests.rs"),
        include_str!("ledger_p18_tests.rs"),
        include_str!("ledger_p19_tests.rs"),
        include_str!("ledger_p20_tests.rs"),
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
        "ledger_p20_tests.rs",
    ];
    for (src, name) in files.iter().zip(names.iter()) {
        let lc = src.lines().count();
        assert!(lc <= 1000, "{} must be under 1000 LOC, is {}", name, lc);
    }
}

// --- Y-40: Production export path contains no output-file write APIs ---

#[test]
fn v31_p20_prod_no_output_file_write_apis() {
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

// --- Y-41: Production ledger path contains no persistence/save/default-path auto-read behavior ---

#[test]
fn v31_p20_prod_no_persistence_auto_read() {
    let src = include_str!("ledger.rs");
    let end = src.find("#[cfg(test)]").unwrap_or(src.len());
    let prod = &src[..end];
    assert!(
        !prod.contains("persistence_enabled"),
        "no persistence_enabled"
    );
    assert!(
        !prod.contains("default_ledger_path"),
        "no default ledger path auto-read"
    );
    assert!(!prod.contains("XDG"), "no XDG auto-discovery");
    assert!(!prod.contains("auto_save"), "no auto_save");
}

// --- Y-42: Production ledger path contains no enforcement/mutation APIs added ---

#[test]
fn v31_p20_prod_no_enforcement_mutation_apis() {
    let src = include_str!("ledger.rs");
    let end = src.find("#[cfg(test)]").unwrap_or(src.len());
    let prod = &src[..end];
    assert!(
        !prod.contains("apply_limit"),
        "no apply_limit in ledger path"
    );
    assert!(
        !prod.contains("nft_add_rule"),
        "no nft_add_rule in ledger path"
    );
    assert!(
        !prod.contains("tc_add_class"),
        "no tc_add_class in ledger path"
    );
    assert!(!prod.contains("attach_pid"), "no attach_pid in ledger path");
    assert!(
        !prod.contains("enforce_quota"),
        "no enforce_quota in ledger path"
    );
}
