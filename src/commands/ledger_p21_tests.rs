// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Phase 21: Final Audit Before Version Bump — guard tests.
//!
//! These tests verify the Phase 21 documentation exists, all existing
//! export/inspect/usage behavior remains unchanged, all safety boundaries
//! are preserved, and no runtime behavior was added. This is the final
//! audit gate before any version bump, tag, release, or publish.

use super::*;

const P21_DOC: &str = include_str!("../../docs/v3.1-phase-21-final-audit-before-version-bump.md");

const P20_DOC: &str = include_str!("../../docs/v3.1-phase-20-ledger-release-readiness-freeze.md");

const README: &str = include_str!("../../README.md");

const CHANGELOG: &str = include_str!("../../CHANGELOG.md");

fn p21_tmp(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("zelynic_p21_{}", label))
}

fn p21_fixture(dir: &str, name: &str) -> std::path::PathBuf {
    let p = std::path::PathBuf::from(dir).join(name);
    let ledger = build_fixture_ledger();
    let json = serialize_ledger_to_json(&ledger).unwrap();
    std::fs::write(&p, json).unwrap();
    p
}

// --- Z-01: Phase 21 doc exists and is nonempty ---

#[test]
fn v31_p21_doc_exists_and_nonempty() {
    assert!(
        !P21_DOC.is_empty(),
        "phase 21 doc must exist and be non-empty"
    );
}

// --- Z-02: Doc says final audit only ---

#[test]
fn v31_p21_doc_says_final_audit_only() {
    assert!(
        P21_DOC.contains("final audit only")
            || P21_DOC.contains("Final audit only")
            || P21_DOC.contains("final audit gate"),
        "doc must say final audit only"
    );
}

// --- Z-03: Doc says no version bump ---

#[test]
fn v31_p21_doc_says_no_version_bump() {
    assert!(
        P21_DOC.contains("No version bump") || P21_DOC.contains("no version bump"),
        "doc must say no version bump"
    );
}

// --- Z-04: Doc says no tag/release/publish ---

#[test]
fn v31_p21_doc_says_no_tag_release_publish() {
    assert!(
        P21_DOC.contains("No tag") || P21_DOC.contains("no tag"),
        "doc must say no tag"
    );
    assert!(
        P21_DOC.contains("No GitHub release") || P21_DOC.contains("no GitHub release"),
        "doc must say no GitHub release"
    );
    assert!(
        P21_DOC.contains("package publish") || P21_DOC.contains("No package publish"),
        "doc must say no package publish"
    );
}

// --- Z-05: Doc says v3.1 is release-ready candidate ---

#[test]
fn v31_p21_doc_says_v31_release_ready_candidate() {
    assert!(
        P21_DOC.contains("release-ready candidate") || P21_DOC.contains("release-ready"),
        "doc must say v3.1 is release-ready candidate"
    );
}

// --- Z-06: Doc says Phase 21 is before version bump/release prep ---

#[test]
fn v31_p21_doc_says_before_version_bump_release_prep() {
    assert!(
        P21_DOC.contains("before")
            && (P21_DOC.contains("version bump")
                || P21_DOC.contains("release-preparation")
                || P21_DOC.contains("release prep")),
        "doc must say Phase 21 is before version bump/release prep"
    );
}

// --- Z-07: Doc lists all five frozen ledger command shapes ---

#[test]
fn v31_p21_doc_lists_all_five_command_shapes() {
    assert!(
        P21_DOC.contains("ledger inspect"),
        "must list ledger inspect"
    );
    assert!(
        P21_DOC.contains("ledger inspect --json"),
        "must list ledger inspect --json"
    );
    assert!(
        P21_DOC.contains("ledger inspect --file"),
        "must list ledger inspect --file"
    );
    assert!(P21_DOC.contains("ledger export"), "must list ledger export");
    assert!(
        P21_DOC.contains("export --json --file"),
        "must list export --json --file"
    );
}

// --- Z-08: Doc lists rejected export missing --file ---

#[test]
fn v31_p21_doc_lists_rejected_export_missing_file() {
    assert!(
        P21_DOC.contains("export --json") && P21_DOC.contains("without --file"),
        "doc must list rejected export missing --file"
    );
}

// --- Z-09: Doc lists rejected export missing --json ---

#[test]
fn v31_p21_doc_lists_rejected_export_missing_json() {
    assert!(
        P21_DOC.contains("export --file") && P21_DOC.contains("without --json"),
        "doc must list rejected export missing --json"
    );
}

// --- Z-10: Doc lists rejected --output ---

#[test]
fn v31_p21_doc_lists_rejected_output() {
    assert!(
        P21_DOC.contains("--output"),
        "doc must list rejected --output"
    );
}

// --- Z-11: Doc lists rejected --overwrite ---

#[test]
fn v31_p21_doc_lists_rejected_overwrite() {
    assert!(
        P21_DOC.contains("--overwrite"),
        "doc must list rejected --overwrite"
    );
}

// --- Z-12: Doc says no save/write/persistence/default path ---

#[test]
fn v31_p21_doc_says_no_save_write_persistence_default_path() {
    assert!(
        P21_DOC.contains("persistence"),
        "doc must mention persistence"
    );
    assert!(P21_DOC.contains("default"), "doc must mention default path");
    assert!(
        P21_DOC.contains("save") || P21_DOC.contains("write"),
        "doc must mention save/write"
    );
}

// --- Z-13: Doc says no live resolver/enforcement/permission/block/allow ---

#[test]
fn v31_p21_doc_says_no_live_resolver_enforcement_permission() {
    assert!(
        P21_DOC.contains("resolver"),
        "doc must mention no live resolver"
    );
    assert!(
        P21_DOC.contains("enforcement"),
        "doc must mention no enforcement"
    );
    assert!(
        P21_DOC.contains("permission") || P21_DOC.contains("block/allow"),
        "doc must mention no permission/block/allow"
    );
}

// --- Z-14: Doc says no quota/eBPF/daemon-watch ---

#[test]
fn v31_p21_doc_says_no_quota_ebpf_daemon_watch() {
    assert!(P21_DOC.contains("quota"), "doc must mention no quota");
    assert!(
        P21_DOC.contains("eBPF") || P21_DOC.contains("ebpf"),
        "doc must mention no eBPF"
    );
    assert!(
        P21_DOC.contains("daemon") || P21_DOC.contains("watch"),
        "doc must mention no daemon/watch"
    );
}

// --- Z-15: Doc says no nft/tc/cgroup/PID/Zelynic mutation ---

#[test]
fn v31_p21_doc_says_no_nft_tc_cgroup_pid_zelynic_mutation() {
    assert!(P21_DOC.contains("nft"), "doc must mention nft");
    assert!(P21_DOC.contains("tc"), "doc must mention tc");
    assert!(P21_DOC.contains("cgroup"), "doc must mention cgroup");
    assert!(P21_DOC.contains("PID"), "doc must mention PID");
}

// --- Z-16: Doc says v3.0 usage JSON unchanged ---

#[test]
fn v31_p21_doc_says_v30_usage_json_unchanged() {
    assert!(
        P21_DOC.contains("v3.0 usage") && P21_DOC.contains("unchanged"),
        "doc must say v3.0 usage JSON unchanged"
    );
}

// --- Z-17: Doc says ledger inspect JSON unchanged ---

#[test]
fn v31_p21_doc_says_ledger_inspect_json_unchanged() {
    assert!(
        P21_DOC.contains("inspect JSON")
            && (P21_DOC.contains("unchanged") || P21_DOC.contains("frozen")),
        "doc must say ledger inspect JSON unchanged"
    );
}

// --- Z-18: Doc says ledger export JSON unchanged ---

#[test]
fn v31_p21_doc_says_ledger_export_json_unchanged() {
    assert!(
        P21_DOC.contains("export JSON")
            && (P21_DOC.contains("unchanged") || P21_DOC.contains("frozen")),
        "doc must say ledger export JSON unchanged"
    );
}

// --- Z-19: README still links to Phase 14 inspect docs ---

#[test]
fn v31_p21_readme_still_links_phase14_inspect() {
    assert!(
        README.contains("v3.1-phase-14-ledger-inspect-user-docs-examples-polish"),
        "README must still link to Phase 14 inspect docs"
    );
}

// --- Z-20: README still links to Phase 18 export docs ---

#[test]
fn v31_p21_readme_still_links_phase18_export() {
    assert!(
        README.contains("v3.1-phase-18-ledger-export-user-docs-examples-polish"),
        "README must still link to Phase 18 export docs"
    );
}

// --- Z-21: Phase 20 doc exists and says release-readiness freeze ---

#[test]
fn v31_p21_phase20_doc_exists_and_says_freeze() {
    assert!(
        !P20_DOC.is_empty(),
        "phase 20 doc must exist and be non-empty"
    );
    assert!(
        P20_DOC.contains("release-readiness freeze")
            || P20_DOC.contains("Release Readiness Freeze"),
        "phase 20 doc must say release-readiness freeze"
    );
}

// --- Z-22: ledger inspect still works ---

#[test]
fn v31_p21_ledger_inspect_still_works() {
    assert!(handle_ledger_inspect(false, None).is_ok());
}

// --- Z-23: ledger inspect --json still works ---

#[test]
fn v31_p21_ledger_inspect_json_still_works() {
    assert!(handle_ledger_inspect(true, None).is_ok());
}

// --- Z-24: ledger inspect --file <valid> still works ---

#[test]
fn v31_p21_ledger_inspect_file_valid_still_works() {
    let d = p21_tmp("inspect_file");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p21_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_inspect(false, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// --- Z-25: ledger inspect --file <valid> --json still works ---

#[test]
fn v31_p21_ledger_inspect_file_json_still_works() {
    let d = p21_tmp("inspect_filej");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p21_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_inspect(true, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// --- Z-26: ledger export --json --file <valid> still works ---

#[test]
fn v31_p21_ledger_export_json_file_valid_still_works() {
    let d = p21_tmp("export_ok");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p21_fixture(d.to_str().unwrap(), "v.json");
    assert!(handle_ledger_export(true, Some(fp.to_str().unwrap())).is_ok());
    std::fs::remove_dir_all(&d).ok();
}

// --- Z-27: ledger export --json without --file still fails honestly ---

#[test]
fn v31_p21_ledger_export_json_no_file_fails() {
    let r = handle_ledger_export(true, None);
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("--file"));
}

// --- Z-28: ledger export --file <valid> without --json still fails honestly ---

#[test]
fn v31_p21_ledger_export_file_no_json_fails() {
    let d = p21_tmp("export_noj");
    std::fs::create_dir_all(&d).unwrap();
    let fp = p21_fixture(d.to_str().unwrap(), "v.json");
    let r = handle_ledger_export(false, Some(fp.to_str().unwrap()));
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("--json"));
    std::fs::remove_dir_all(&d).ok();
}

// --- Z-29: ledger export --output <PATH> remains rejected ---

#[test]
fn v31_p21_output_remains_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--output", "/tmp/out.json"]).is_err(),
        "--output must be rejected"
    );
}

// --- Z-30: ledger export --overwrite remains rejected ---

#[test]
fn v31_p21_overwrite_remains_rejected() {
    use crate::cli::Cli;
    use clap::Parser;
    assert!(
        Cli::try_parse_from(["zelynic", "ledger", "export", "--overwrite"]).is_err(),
        "--overwrite must be rejected"
    );
}

// --- Z-31: usage --sample --delta --json schema remains unchanged ---

#[test]
fn v31_p21_usage_delta_json_schema_unchanged() {
    use crate::accounting::SCHEMA_VERSION;
    assert_eq!(SCHEMA_VERSION, 1);
}

// --- Z-32: Ledger command remains hidden from public help ---

#[test]
fn v31_p21_ledger_remains_hidden() {
    use crate::cli::Cli;
    use clap::CommandFactory;
    let help = Cli::command().render_help().to_string();
    assert!(
        !help.contains("ledger"),
        "ledger must not appear in normal --help output"
    );
}

// --- Z-33: No new dependencies ---

#[test]
fn v31_p21_no_new_dependencies() {
    let cargo = include_str!("../../Cargo.toml");
    assert!(!cargo.contains("tokio"), "no tokio dependency");
    assert!(!cargo.contains("reqwest"), "no reqwest dependency");
}

// --- Z-34: No version bump ---

#[test]
fn v31_p21_no_version_bump() {
    assert!(
        include_str!("../../Cargo.toml").contains("version = \"3.0.1\""),
        "version must remain 3.0.1"
    );
}

// --- Z-35: All touched files under 1000 LOC ---

#[test]
fn v31_p21_all_files_under_1000_loc() {
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
        include_str!("ledger_p21_tests.rs"),
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
        "ledger_p21_tests.rs",
    ];
    for (src, name) in files.iter().zip(names.iter()) {
        let lc = src.lines().count();
        assert!(lc <= 1000, "{} must be under 1000 LOC, is {}", name, lc);
    }
}

// --- Z-36: Production ledger/export code contains no output-file write APIs ---

#[test]
fn v31_p21_prod_no_output_file_write_apis() {
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

// --- Z-37: Production code contains no persistence/save/default-path auto-read ---

#[test]
fn v31_p21_prod_no_persistence_auto_read() {
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

// --- Z-38: Production code contains no enforcement/mutation APIs ---

#[test]
fn v31_p21_prod_no_enforcement_mutation_apis() {
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

// --- Z-39: No v3.2 permission/block/allow command surface added ---

#[test]
fn v31_p21_no_v32_permission_command_surface() {
    let src = include_str!("ledger.rs");
    let end = src.find("#[cfg(test)]").unwrap_or(src.len());
    let prod = &src[..end];
    // Check for command surface additions, not safety wording strings.
    assert!(
        !prod.contains("PermissionCommands"),
        "no PermissionCommands struct in ledger production code"
    );
    assert!(
        !prod.contains("BlockAllow"),
        "no BlockAllow mode in ledger production code"
    );
    assert!(
        !prod.contains("block_mode"),
        "no block_mode in ledger production code"
    );
    assert!(
        !prod.contains("allow_mode"),
        "no allow_mode in ledger production code"
    );
}

// --- Z-40: No v3.3 quota command surface added ---

#[test]
fn v31_p21_no_v33_quota_command_surface() {
    let src = include_str!("ledger.rs");
    let end = src.find("#[cfg(test)]").unwrap_or(src.len());
    let prod = &src[..end];
    // Check for command surface additions, not safety wording strings.
    // The word "quota" appears in safety disclaimers ("quota enforcement:
    // inactive/not implemented") which is expected and correct.
    assert!(
        !prod.contains("QuotaCommands"),
        "no QuotaCommands struct in ledger production code"
    );
    assert!(
        !prod.contains("threshold_alert"),
        "no threshold_alert in ledger production code"
    );
    assert!(
        !prod.contains("enforce_quota"),
        "no enforce_quota in ledger production code"
    );
}

// --- Z-41: No v4 eBPF command surface added ---

#[test]
fn v31_p21_no_v4_ebpf_command_surface() {
    let src = include_str!("ledger.rs");
    let end = src.find("#[cfg(test)]").unwrap_or(src.len());
    let prod = &src[..end];
    assert!(
        !prod.contains("eBPF") && !prod.contains("ebpf") && !prod.contains("bpf_"),
        "no eBPF in ledger production code"
    );
}

// --- Z-42: CHANGELOG has Phase 21 entry but does not claim release/tag/publish ---

#[test]
fn v31_p21_changelog_has_entry_no_release_claim() {
    assert!(
        CHANGELOG.contains("phase 21") || CHANGELOG.contains("Phase 21"),
        "CHANGELOG must have a Phase 21 entry"
    );
    // Ensure the Phase 21 entry does NOT claim release/tag/publish
    let p21_section_start = CHANGELOG
        .find("phase 21")
        .or(CHANGELOG.find("Phase 21"))
        .unwrap();
    let p21_section = &CHANGELOG[p21_section_start..];
    // Find the end of the Phase 21 bullet (next "- **" or end of [Unreleased] section)
    let next_entry = p21_section[10..]
        .find("- **")
        .map(|i| i + 10)
        .unwrap_or(p21_section[10..].len());
    let entry_text = &p21_section[..=next_entry.min(p21_section.len() - 1)];
    // The Phase 21 entry must explicitly disclaim tag/release/publish/version bump
    assert!(
        entry_text.contains("no tag")
            || entry_text.contains("no release")
            || entry_text.contains("no publish")
            || entry_text.contains("no version bump"),
        "Phase 21 changelog entry must explicitly disclaim tag/release/publish/version bump"
    );
}
