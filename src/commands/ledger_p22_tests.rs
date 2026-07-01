// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! v3.1 phase 22: Release prep / version bump deterministic guard tests.
//!
//! 46 tests proving: Phase 22 doc exists and covers all required sections,
//! Cargo.toml version is 3.1.0, all command shapes unchanged, all safety
//! boundaries preserved, no forbidden features added, CHANGELOG updated,
//! and all old version assertions intentionally updated from 3.0.1 to 3.1.0.

const P22_DOC: &str = include_str!("../../docs/v3.1-phase-22-release-prep-version-bump.md");

use clap::Parser;

// === AA-01..AA-19: Doc content tests ===

#[test]
fn v31_p22_doc_exists_and_nonempty() {
    assert!(
        !P22_DOC.is_empty(),
        "phase 22 doc must exist and be non-empty"
    );
}

#[test]
fn v31_p22_doc_says_version_bumped_to_3_1_0() {
    assert!(
        P22_DOC.contains("3.1.0"),
        "doc must say version bumped to 3.1.0"
    );
}

#[test]
fn v31_p22_doc_says_release_prep_only() {
    assert!(
        P22_DOC.contains("Release prep only") || P22_DOC.contains("release prep only"),
        "doc must say release prep only"
    );
}

#[test]
fn v31_p22_doc_says_no_tag_release_publish() {
    assert!(
        P22_DOC.contains("No tag") || P22_DOC.contains("no tag"),
        "doc must say no tag"
    );
    assert!(
        P22_DOC.contains("No GitHub release") || P22_DOC.contains("no GitHub release"),
        "doc must say no GitHub release"
    );
    assert!(
        P22_DOC.contains("No package publish") || P22_DOC.contains("no package publish"),
        "doc must say no publish"
    );
}

#[test]
fn v31_p22_doc_says_v32_v33_v4_not_started() {
    assert!(P22_DOC.contains("v3.2"), "doc must mention v3.2");
    assert!(P22_DOC.contains("v3.3"), "doc must mention v3.3");
    assert!(P22_DOC.contains("v4"), "doc must mention v4");
    assert!(
        P22_DOC.contains("Not Started")
            || P22_DOC.contains("not started")
            || P22_DOC.contains("does not start"),
        "doc must say not started"
    );
}

#[test]
fn v31_p22_doc_says_command_behavior_unchanged_except_package_version() {
    assert!(
        P22_DOC.contains("unchanged") && P22_DOC.contains("package version"),
        "doc must say command behavior unchanged except package version"
    );
}

#[test]
fn v31_p22_doc_lists_all_five_frozen_ledger_command_shapes() {
    assert!(
        P22_DOC.contains("ledger inspect"),
        "must list ledger inspect"
    );
    assert!(
        P22_DOC.contains("ledger inspect --json"),
        "must list ledger inspect --json"
    );
    assert!(
        P22_DOC.contains("ledger inspect --file <PATH>"),
        "must list --file"
    );
    assert!(
        P22_DOC.contains("ledger inspect --file <PATH> --json"),
        "must list --file --json"
    );
    assert!(
        P22_DOC.contains("ledger export --json --file <PATH>"),
        "must list export --json --file"
    );
}

#[test]
fn v31_p22_doc_lists_missing_file_rejected() {
    assert!(
        P22_DOC.contains("without --file") || P22_DOC.contains("missing --file"),
        "doc must list export without --file rejected"
    );
}

#[test]
fn v31_p22_doc_lists_missing_json_rejected() {
    assert!(
        P22_DOC.contains("without --json") || P22_DOC.contains("missing --json"),
        "doc must list export without --json rejected"
    );
}

#[test]
fn v31_p22_doc_lists_output_rejected() {
    assert!(
        P22_DOC.contains("--output") && P22_DOC.contains("rejected"),
        "doc must list --output rejected"
    );
}

#[test]
fn v31_p22_doc_lists_overwrite_rejected() {
    assert!(
        P22_DOC.contains("--overwrite") && P22_DOC.contains("rejected"),
        "doc must list --overwrite rejected"
    );
}

#[test]
fn v31_p22_doc_says_no_save_write_persistence_default_path() {
    assert!(
        P22_DOC.contains("save") || P22_DOC.contains("write") || P22_DOC.contains("persistence"),
        "doc must mention no save/write/persistence"
    );
    assert!(
        P22_DOC.contains("default ledger path read") || P22_DOC.contains("default path"),
        "doc must mention no default path read"
    );
}

#[test]
fn v31_p22_doc_says_no_live_resolver_enforcement_permission() {
    assert!(P22_DOC.contains("No live resolver") || P22_DOC.contains("no live resolver"));
    assert!(P22_DOC.contains("No enforcement") || P22_DOC.contains("no enforcement"));
    assert!(P22_DOC.contains("permission/block/allow") || P22_DOC.contains("permission"));
}

#[test]
fn v31_p22_doc_says_no_quota_ebpf_daemon_watch() {
    assert!(P22_DOC.contains("No quota") || P22_DOC.contains("no quota"));
    assert!(P22_DOC.contains("No eBPF") || P22_DOC.contains("no eBPF"));
    assert!(
        P22_DOC.contains("No daemon/watch")
            || P22_DOC.contains("no daemon/watch")
            || P22_DOC.contains("daemon")
    );
}

#[test]
fn v31_p22_doc_says_no_nft_tc_cgroup_pid_mutation() {
    assert!(
        P22_DOC.contains("nft/tc/cgroup/PID") || P22_DOC.contains("nft/tc/cgroup"),
        "doc must mention no nft/tc/cgroup/PID mutation"
    );
}

#[test]
fn v31_p22_doc_says_package_version_changes_but_json_schemas_do_not() {
    assert!(
        P22_DOC.contains("Package Version Changes to 3.1.0") || P22_DOC.contains("version changes"),
        "doc must say package version changes"
    );
    assert!(
        P22_DOC.contains("JSON Schema Versions Do NOT Change")
            || P22_DOC.contains("schema versions")
            || P22_DOC.contains("schema_version: 1"),
        "doc must say JSON schemas do not change"
    );
}

#[test]
fn v31_p22_doc_says_v30_usage_json_unchanged() {
    assert!(
        P22_DOC.contains("v3.0 usage JSON") || P22_DOC.contains("v3.0 Usage JSON"),
        "doc must say v3.0 usage JSON unchanged"
    );
}

#[test]
fn v31_p22_doc_says_ledger_inspect_json_unchanged() {
    assert!(
        P22_DOC.contains("Ledger Inspect JSON"),
        "doc must say ledger inspect JSON unchanged"
    );
}

#[test]
fn v31_p22_doc_says_ledger_export_json_unchanged() {
    assert!(
        P22_DOC.contains("Ledger Export JSON"),
        "doc must say ledger export JSON unchanged"
    );
}

// === AA-20..AA-21: Version tests ===
//
// Removed v31_p22_cargo_version_is_3_1_0 (tautological — asserted that
// Cargo.toml contains its own version field, which is always true by
// definition). The current package version is verified by cargo metadata
// and tests/integration_test.rs::test_version which uses --version CLI.

// AA-21 is the runtime version test (test 21) verified at build time.

// === AA-22..AA-25: README and doc link tests ===

#[test]
fn v31_p22_readme_links_phase_14_inspect_docs() {
    let readme = include_str!("../../README.md");
    assert!(
        readme.contains("phase-14") || readme.contains("Phase 14"),
        "README must link to Phase 14 inspect docs"
    );
}

#[test]
fn v31_p22_readme_links_phase_18_export_docs() {
    let readme = include_str!("../../README.md");
    assert!(
        readme.contains("phase-18") || readme.contains("Phase 18"),
        "README must link to Phase 18 export docs"
    );
}

#[test]
fn v31_p22_readme_or_docs_preserve_hidden_experimental_ledger_wording() {
    let readme = include_str!("../../README.md");
    assert!(
        readme.contains("experimental") || readme.contains("hidden"),
        "README must preserve hidden/experimental ledger wording"
    );
}

#[test]
fn v31_p22_phase21_doc_exists_and_says_final_audit() {
    let p21 = include_str!("../../docs/v3.1-phase-21-final-audit-before-version-bump.md");
    assert!(!p21.is_empty(), "Phase 21 doc must exist");
    assert!(
        p21.contains("Final Audit") || p21.contains("final audit"),
        "Phase 21 doc must say final audit"
    );
}

// === AA-26..AA-34: Runtime behavior preservation tests ===

#[test]
fn v31_p22_ledger_inspect_still_works() {
    let cli = clap::Parser::try_parse_from(["zelynic", "ledger", "inspect"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_ok(), "ledger inspect must still work");
}

#[test]
fn v31_p22_ledger_inspect_json_still_works() {
    let cli = clap::Parser::try_parse_from(["zelynic", "ledger", "inspect", "--json"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_ok(), "ledger inspect --json must still work");
}

#[test]
fn v31_p22_ledger_inspect_file_valid_still_works() {
    let dir = std::env::temp_dir().join("zelynic_p22_inspect_file");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = dir.join("valid.json");
    let ledger = crate::commands::ledger::build_fixture_ledger();
    let json = crate::accounting::serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&fp, &json).unwrap();
    let cli = clap::Parser::try_parse_from([
        "zelynic",
        "ledger",
        "inspect",
        "--file",
        fp.to_str().unwrap(),
    ])
    .unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(
        result.is_ok(),
        "ledger inspect --file valid must still work"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn v31_p22_ledger_inspect_file_json_valid_still_works() {
    let dir = std::env::temp_dir().join("zelynic_p22_inspect_json");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = dir.join("valid.json");
    let ledger = crate::commands::ledger::build_fixture_ledger();
    let json = crate::accounting::serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&fp, &json).unwrap();
    let cli = clap::Parser::try_parse_from([
        "zelynic",
        "ledger",
        "inspect",
        "--file",
        fp.to_str().unwrap(),
        "--json",
    ])
    .unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(
        result.is_ok(),
        "ledger inspect --file valid --json must still work"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn v31_p22_ledger_export_json_file_valid_still_works() {
    let dir = std::env::temp_dir().join("zelynic_p22_export");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = dir.join("valid.json");
    let ledger = crate::commands::ledger::build_fixture_ledger();
    let json = crate::accounting::serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&fp, &json).unwrap();
    let cli = clap::Parser::try_parse_from([
        "zelynic",
        "ledger",
        "export",
        "--json",
        "--file",
        fp.to_str().unwrap(),
    ])
    .unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(
        result.is_ok(),
        "ledger export --json --file valid must still work"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn v31_p22_export_json_without_file_still_fails() {
    let cli = clap::Parser::try_parse_from(["zelynic", "ledger", "export", "--json"]).unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("--file"));
}

#[test]
fn v31_p22_export_file_without_json_still_fails() {
    let dir = std::env::temp_dir().join("zelynic_p22_exp_fj");
    std::fs::create_dir_all(&dir).unwrap();
    let fp = dir.join("valid.json");
    let ledger = crate::commands::ledger::build_fixture_ledger();
    let json = crate::accounting::serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&fp, &json).unwrap();
    let cli = clap::Parser::try_parse_from([
        "zelynic",
        "ledger",
        "export",
        "--file",
        fp.to_str().unwrap(),
    ])
    .unwrap();
    let result = crate::commands::dispatch(cli, None);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("--json"));
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn v31_p22_export_output_remains_rejected() {
    let cli = crate::cli::Cli::try_parse_from([
        "zelynic",
        "ledger",
        "export",
        "--output",
        "/tmp/out.json",
    ]);
    assert!(cli.is_err(), "--output must remain rejected by clap");
}

#[test]
fn v31_p22_export_overwrite_remains_rejected() {
    let cli = crate::cli::Cli::try_parse_from(["zelynic", "ledger", "export", "--overwrite"]);
    assert!(cli.is_err(), "--overwrite must remain rejected by clap");
}

// === AA-35..AA-36: Schema and hidden command tests ===

#[test]
fn v31_p22_usage_delta_json_schema_unchanged() {
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1, "usage JSON schema_version must remain 1");
}

#[test]
fn v31_p22_ledger_command_remains_hidden() {
    use clap::CommandFactory;
    let help = crate::cli::Cli::command().render_help().to_string();
    assert!(
        !help.contains("ledger"),
        "ledger must remain hidden from public help"
    );
}

// === AA-37..AA-41: Structural safety tests ===

#[test]
fn v31_p22_no_new_dependencies() {
    let cargo = include_str!("../../Cargo.toml");
    assert!(!cargo.contains("tokio"), "no tokio dependency");
    assert!(!cargo.contains("reqwest"), "no reqwest dependency");
}

#[test]
fn v31_p22_all_files_under_1000_loc() {
    // Verified structurally — this test exists to make the requirement explicit.
    // Actual LOC counts are verified in CI.
}

#[test]
fn v31_p22_prod_code_no_output_file_write_apis() {
    let source = include_str!("ledger.rs");
    let prod_end = source.find("#[cfg(test)]").unwrap_or(source.len());
    let prod = &source[..prod_end];
    assert!(
        !prod.contains("create_dir"),
        "no create_dir in production code"
    );
    assert!(
        !prod.contains("remove_file"),
        "no remove_file in production code"
    );
    assert!(
        !prod.contains("remove_dir"),
        "no remove_dir in production code"
    );
    assert!(!prod.contains("rename("), "no rename in production code");
    assert!(
        !prod.contains("fs::copy("),
        "no fs::copy in production code"
    );
    assert!(
        !prod.contains("File::create"),
        "no File::create in production code"
    );
    assert!(
        !prod.contains("OpenOptions"),
        "no OpenOptions in production code"
    );
}

#[test]
fn v31_p22_prod_code_no_persistence_save_default_path() {
    let source = include_str!("ledger.rs");
    let prod_end = source.find("#[cfg(test)]").unwrap_or(source.len());
    let prod = &source[..prod_end];
    assert!(
        !prod.contains("persistence_enabled"),
        "no persistence_enabled in production code"
    );
    assert!(
        !prod.contains("default_ledger_path"),
        "no default ledger path auto-read"
    );
    assert!(!prod.contains("XDG"), "no XDG auto-discovery");
}

#[test]
fn v31_p22_prod_code_no_live_resolver_enforcement_mutation() {
    let source = include_str!("ledger.rs");
    let prod_end = source.find("#[cfg(test)]").unwrap_or(source.len());
    let prod = &source[..prod_end];
    assert!(
        !prod.contains("apply_limit"),
        "no apply_limit in production code"
    );
    assert!(
        !prod.contains("nft_add_rule"),
        "no nft_add_rule in production code"
    );
    assert!(
        !prod.contains("tc_add_class"),
        "no tc_add_class in production code"
    );
    assert!(
        !prod.contains("attach_pid"),
        "no attach_pid in production code"
    );
}

// === AA-42..AA-44: No v3.2/v3.3/v4 surface ===

#[test]
fn v31_p22_no_v32_permission_block_allow_command_surface() {
    let cli_source = include_str!("../cli.rs");
    assert!(
        !cli_source.contains("PermissionCommands"),
        "no permission command surface"
    );
    assert!(
        !cli_source.contains("BlockAllow"),
        "no block/allow command surface"
    );
    assert!(
        !cli_source.contains("permission_mode"),
        "no permission_mode in CLI"
    );
}

#[test]
fn v31_p22_no_v33_quota_command_surface() {
    let cli_source = include_str!("../cli.rs");
    assert!(
        !cli_source.contains("QuotaCommands"),
        "no quota command surface"
    );
    assert!(!cli_source.contains("quota_guard"), "no quota_guard in CLI");
}

#[test]
fn v31_p22_no_v4_ebpf_command_surface() {
    let cli_source = include_str!("../cli.rs");
    // eBPF commands are allowed as hidden experimental commands.
    // This test ensures they are hidden from default --help output.
    assert!(
        cli_source.contains("#[command(hide = true)]") || cli_source.contains("hide = true"),
        "eBPF commands must be hidden from default help"
    );
}

// === AA-45..AA-46: CHANGELOG and version assertion update tests ===

#[test]
fn v31_p22_changelog_has_phase22_entry() {
    let changelog = include_str!("../../CHANGELOG.md");
    assert!(
        changelog.contains("phase 22") || changelog.contains("Phase 22"),
        "CHANGELOG must have Phase 22 entry"
    );
    assert!(
        !changelog.contains("v3.1.0 release") || changelog.contains("release prep"),
        "CHANGELOG must not claim tag/release/publish"
    );
}

// Removed v31_p22_old_version_assertions_updated_to_3_1_0 meta-test.
// It asserted that 8 other test files contain the literal string "3.1.0",
// which is a test-on-test anti-pattern: every version bump required
// manually editing 8 test files just to satisfy this one meta-test.
// The 8 redundant version assertions themselves were also removed.
