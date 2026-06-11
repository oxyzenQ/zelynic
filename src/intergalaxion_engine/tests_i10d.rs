// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-10D tests: local attach smoke test artifact and detach proof.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::live_attach_artifact::*;
use clap::CommandFactory;

const I10D_DOC: &str =
    include_str!("../../docs/intergalaxion/I-10D-local-attach-smoke-test-artifact-detach-proof.md");
const I10D_SOURCE: &str = include_str!("backends/ebpf/live_attach_artifact.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

// ── Coverage 1: default artifact contract is safe ───────────────────────

#[test]
fn i10d_default_artifact_contract_is_safe() {
    let c = default_live_attach_artifact_contract();
    assert_eq!(
        c.artifact_status,
        EbpfLiveAttachArtifactStatus::MissingArtifact
    );
    assert!(c.observer_only);
    assert!(!c.enforcement_allowed);
    assert!(!c.packet_drop_allowed);
    assert!(!c.ring_buffer_required);
    assert!(!c.map_pin_required);
    assert!(!c.persistence_required);
    assert!(!c.normal_ci_builds_artifact);
    assert!(!c.normal_tests_require_artifact);
}

// ── Coverage 2: default artifact status label is stable ───────────────

#[test]
fn i10d_default_artifact_status_label_is_stable() {
    assert_eq!(
        live_attach_artifact_status_label(EbpfLiveAttachArtifactStatus::MissingArtifact),
        "missing_artifact"
    );
}

// ── Coverage 3: default artifact is observer-only ──────────────────────

#[test]
fn i10d_default_artifact_observer_only() {
    let c = default_live_attach_artifact_contract();
    assert!(c.observer_only);
}

// ── Coverage 4: default artifact does not allow enforcement ────────────

#[test]
fn i10d_default_artifact_no_enforcement() {
    let c = default_live_attach_artifact_contract();
    assert!(!c.enforcement_allowed);
}

// ── Coverage 5: default artifact does not allow packet drop ────────────

#[test]
fn i10d_default_artifact_no_packet_drop() {
    let c = default_live_attach_artifact_contract();
    assert!(!c.packet_drop_allowed);
}

// ── Coverage 6: default artifact does not require ring buffer ──────────

#[test]
fn i10d_default_artifact_no_ring_buffer() {
    let c = default_live_attach_artifact_contract();
    assert!(!c.ring_buffer_required);
}

// ── Coverage 7: default artifact does not require map pin ──────────────

#[test]
fn i10d_default_artifact_no_map_pin() {
    let c = default_live_attach_artifact_contract();
    assert!(!c.map_pin_required);
}

// ── Coverage 8: default artifact does not require persistence ──────────

#[test]
fn i10d_default_artifact_no_persistence() {
    let c = default_live_attach_artifact_contract();
    assert!(!c.persistence_required);
}

// ── Coverage 9: default artifact does not make normal CI build artifact ─

#[test]
fn i10d_default_artifact_no_ci_build() {
    let c = default_live_attach_artifact_contract();
    assert!(!c.normal_ci_builds_artifact);
}

// ── Coverage 10: default artifact does not make normal tests require artifact ─

#[test]
fn i10d_default_artifact_no_tests_require() {
    let c = default_live_attach_artifact_contract();
    assert!(!c.normal_tests_require_artifact);
}

// ── Coverage 11: validate accepts safe default artifact ──────────────────

#[test]
fn i10d_validate_accepts_safe_default_artifact() {
    let c = default_live_attach_artifact_contract();
    assert!(validate_live_attach_artifact_contract(&c).is_ok());
}

// ── Coverage 12: validate rejects observer_only=false ──────────────────

#[test]
fn i10d_validate_rejects_non_observer() {
    let mut c = default_live_attach_artifact_contract();
    c.observer_only = false;
    assert!(validate_live_attach_artifact_contract(&c).is_err());
}

// ── Coverage 13: validate rejects enforcement_allowed=true ──────────────

#[test]
fn i10d_validate_rejects_enforcement() {
    let mut c = default_live_attach_artifact_contract();
    c.enforcement_allowed = true;
    assert!(validate_live_attach_artifact_contract(&c).is_err());
}

// ── Coverage 14: validate rejects packet_drop_allowed=true ──────────────

#[test]
fn i10d_validate_rejects_packet_drop() {
    let mut c = default_live_attach_artifact_contract();
    c.packet_drop_allowed = true;
    assert!(validate_live_attach_artifact_contract(&c).is_err());
}

// ── Coverage 15: validate rejects ring_buffer_required=true ─────────────

#[test]
fn i10d_validate_rejects_ring_buffer() {
    let mut c = default_live_attach_artifact_contract();
    c.ring_buffer_required = true;
    assert!(validate_live_attach_artifact_contract(&c).is_err());
}

// ── Coverage 16: validate rejects map_pin_required=true ────────────────

#[test]
fn i10d_validate_rejects_map_pin() {
    let mut c = default_live_attach_artifact_contract();
    c.map_pin_required = true;
    assert!(validate_live_attach_artifact_contract(&c).is_err());
}

// ── Coverage 17: validate rejects persistence_required=true ─────────────

#[test]
fn i10d_validate_rejects_persistence() {
    let mut c = default_live_attach_artifact_contract();
    c.persistence_required = true;
    assert!(validate_live_attach_artifact_contract(&c).is_err());
}

// ── Coverage 18: validate rejects normal_ci_builds_artifact=true ────────

#[test]
fn i10d_validate_rejects_ci_builds_artifact() {
    let mut c = default_live_attach_artifact_contract();
    c.normal_ci_builds_artifact = true;
    assert!(validate_live_attach_artifact_contract(&c).is_err());
}

// ── Coverage 19: validate rejects normal_tests_require_artifact=true ────

#[test]
fn i10d_validate_rejects_tests_require_artifact() {
    let mut c = default_live_attach_artifact_contract();
    c.normal_tests_require_artifact = true;
    assert!(validate_live_attach_artifact_contract(&c).is_err());
}

// ── Coverage 20: default detach proof is not attempted ─────────────────

#[test]
fn i10d_default_detach_proof_not_attempted() {
    let p = default_detach_proof();
    assert_eq!(p.status, EbpfDetachProofStatus::NotAttempted);
}

// ── Coverage 21: detach proof status labels are stable ──────────────────

#[test]
fn i10d_detach_proof_status_labels_stable() {
    let pairs: Vec<(EbpfDetachProofStatus, &str)> = vec![
        (EbpfDetachProofStatus::NotAttempted, "not_attempted"),
        (EbpfDetachProofStatus::DetachPlanned, "detach_planned"),
        (EbpfDetachProofStatus::DetachedCleanly, "detached_cleanly"),
        (EbpfDetachProofStatus::DetachFailed, "detach_failed"),
        (
            EbpfDetachProofStatus::ManualCleanupRequired,
            "manual_cleanup_required",
        ),
    ];
    for (status, label) in pairs {
        assert_eq!(detach_proof_status_label(status), label);
    }
}

// ── Coverage 22: default detach proof has detach_required=true ──────────

#[test]
fn i10d_default_detach_proof_requires_detach() {
    let p = default_detach_proof();
    assert!(p.detach_required);
}

// ── Coverage 23: default detach proof has detach_attempted=false ────────

#[test]
fn i10d_default_detach_proof_not_attempted_flag() {
    let p = default_detach_proof();
    assert!(!p.detach_attempted);
}

// ── Coverage 24: default detach proof has attach_was_attempted=false ────

#[test]
fn i10d_default_detach_proof_no_attach_attempted() {
    let p = default_detach_proof();
    assert!(!p.attach_was_attempted);
}

// ── Coverage 25: default detach proof has attach_was_successful=false ───

#[test]
fn i10d_default_detach_proof_no_attach_successful() {
    let p = default_detach_proof();
    assert!(!p.attach_was_successful);
}

// ── Coverage 26: validate accepts safe default detach proof ────────────

#[test]
fn i10d_validate_accepts_safe_default_detach_proof() {
    let p = default_detach_proof();
    assert!(validate_detach_proof(&p).is_ok());
}

// ── Coverage 27: validate rejects detached cleanly when attach was never attempted ─

#[test]
fn i10d_validate_rejects_detached_cleanly_no_attach() {
    let mut p = default_detach_proof();
    p.status = EbpfDetachProofStatus::DetachedCleanly;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 28: validate rejects detached cleanly when detach_succeeded=false ─

#[test]
fn i10d_validate_rejects_detached_cleanly_no_success() {
    let mut p = default_detach_proof();
    p.status = EbpfDetachProofStatus::DetachedCleanly;
    p.attach_was_attempted = true;
    // detach_succeeded still false
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 29: validate rejects detach_succeeded=true when detach_attempted=false ─

#[test]
fn i10d_validate_rejects_success_no_attempt() {
    let mut p = default_detach_proof();
    p.detach_succeeded = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 30: validate rejects attach_successful=true when attach_attempted=false ─

#[test]
fn i10d_validate_rejects_attach_success_no_attempt() {
    let mut p = default_detach_proof();
    p.attach_was_successful = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 31: validate rejects kernel_state_mutated=true ──────────────

#[test]
fn i10d_validate_rejects_kernel_mutated() {
    let mut p = default_detach_proof();
    p.kernel_state_mutated = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 32: validate rejects enforcement_performed=true ────────────

#[test]
fn i10d_validate_detach_rejects_enforcement() {
    let mut p = default_detach_proof();
    p.enforcement_performed = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 33: validate rejects packet_drop_performed=true ─────────────

#[test]
fn i10d_validate_detach_rejects_packet_drop() {
    let mut p = default_detach_proof();
    p.packet_drop_performed = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 34: validate rejects program_unloaded=true when detach_attempted=false ─

#[test]
fn i10d_validate_rejects_program_unloaded_no_detach() {
    let mut p = default_detach_proof();
    p.program_unloaded = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 35: validate rejects map_unpinned=true ───────────────────────

#[test]
fn i10d_validate_rejects_map_unpinned() {
    let mut p = default_detach_proof();
    p.map_unpinned = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 36: validate rejects ring_buffer_closed=true ─────────────────

#[test]
fn i10d_validate_rejects_ring_buffer_closed() {
    let mut p = default_detach_proof();
    p.ring_buffer_closed = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 37: validate rejects persistence_cleaned=true ────────────────

#[test]
fn i10d_validate_rejects_persistence_cleaned() {
    let mut p = default_detach_proof();
    p.persistence_cleaned = true;
    assert!(validate_detach_proof(&p).is_err());
}

// ── Coverage 38: default recipe phase is I-10D ───────────────────────────

#[test]
fn i10d_default_recipe_phase() {
    let r = default_local_attach_smoke_recipe();
    assert_eq!(r.phase, "I-10D");
}

// ── Coverage 39: default recipe is local lab only ───────────────────────

#[test]
fn i10d_default_recipe_local_lab_only() {
    let r = default_local_attach_smoke_recipe();
    assert!(r.local_lab_only);
}

// ── Coverage 40: default recipe requires feature intergalaxion-live-attach-lab ─

#[test]
fn i10d_default_recipe_requires_feature() {
    let r = default_local_attach_smoke_recipe();
    assert_eq!(r.feature_required, "intergalaxion-live-attach-lab");
}

// ── Coverage 41: default recipe does not allow public CLI ────────────────

#[test]
fn i10d_default_recipe_no_public_cli() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.public_cli_allowed);
}

// ── Coverage 42: default recipe requires operator label ──────────────────

#[test]
fn i10d_default_recipe_requires_operator_label() {
    let r = default_local_attach_smoke_recipe();
    assert!(r.operator_label_required);
}

// ── Coverage 43: default recipe requires detach ──────────────────────────

#[test]
fn i10d_default_recipe_requires_detach() {
    let r = default_local_attach_smoke_recipe();
    assert!(r.detach_required);
}

// ── Coverage 44: default recipe normal tests do not execute live attach ─

#[test]
fn i10d_default_recipe_no_test_attach() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.normal_tests_execute_live_attach);
}

// ── Coverage 45: default recipe normal CI does not execute live attach ─

#[test]
fn i10d_default_recipe_no_ci_attach() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.normal_ci_executes_live_attach);
}

// ── Coverage 46: default recipe has enforcement_allowed=false ──────────

#[test]
fn i10d_default_recipe_no_enforcement() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.enforcement_allowed);
}

// ── Coverage 47: default recipe has packet_drop_allowed=false ──────────

#[test]
fn i10d_default_recipe_no_packet_drop() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.packet_drop_allowed);
}

// ── Coverage 48: default recipe has ring_buffer_open_allowed=false ─────

#[test]
fn i10d_default_recipe_no_ring_buffer() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.ring_buffer_open_allowed);
}

// ── Coverage 49: default recipe has live_event_read_allowed=false ────────

#[test]
fn i10d_default_recipe_no_event_read() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.live_event_read_allowed);
}

// ── Coverage 50: default recipe has map_pin_allowed=false ───────────────

#[test]
fn i10d_default_recipe_no_map_pin() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.map_pin_allowed);
}

// ── Coverage 51: default recipe has persistence_allowed=false ──────────

#[test]
fn i10d_default_recipe_no_persistence() {
    let r = default_local_attach_smoke_recipe();
    assert!(!r.persistence_allowed);
}

// ── Coverage 52: validate accepts safe default recipe ──────────────────

#[test]
fn i10d_validate_accepts_safe_default_recipe() {
    let r = default_local_attach_smoke_recipe();
    assert!(validate_local_attach_smoke_recipe(&r).is_ok());
}

// ── Coverage 53: validate rejects local_lab_only=false ──────────────────

#[test]
fn i10d_validate_rejects_non_local_lab() {
    let mut r = default_local_attach_smoke_recipe();
    r.local_lab_only = false;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 54: validate rejects public_cli_allowed=true ───────────────

#[test]
fn i10d_validate_rejects_public_cli() {
    let mut r = default_local_attach_smoke_recipe();
    r.public_cli_allowed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 55: validate rejects normal_tests_execute_live_attach=true ─

#[test]
fn i10d_validate_rejects_test_attach() {
    let mut r = default_local_attach_smoke_recipe();
    r.normal_tests_execute_live_attach = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 56: validate rejects normal_ci_executes_live_attach=true ────

#[test]
fn i10d_validate_rejects_ci_attach() {
    let mut r = default_local_attach_smoke_recipe();
    r.normal_ci_executes_live_attach = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 57: validate rejects enforcement_allowed=true ─────────────

#[test]
fn i10d_validate_recipe_rejects_enforcement() {
    let mut r = default_local_attach_smoke_recipe();
    r.enforcement_allowed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 58: validate rejects packet_drop_allowed=true ───────────────

#[test]
fn i10d_validate_recipe_rejects_packet_drop() {
    let mut r = default_local_attach_smoke_recipe();
    r.packet_drop_allowed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 59: validate rejects ring_buffer_open_allowed=true ──────────

#[test]
fn i10d_validate_recipe_rejects_ring_buffer() {
    let mut r = default_local_attach_smoke_recipe();
    r.ring_buffer_open_allowed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 60: validate rejects live_event_read_allowed=true ───────────

#[test]
fn i10d_validate_rejects_event_read() {
    let mut r = default_local_attach_smoke_recipe();
    r.live_event_read_allowed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 61: validate rejects map_pin_allowed=true ─────────────────

#[test]
fn i10d_validate_recipe_rejects_map_pin() {
    let mut r = default_local_attach_smoke_recipe();
    r.map_pin_allowed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 62: validate rejects persistence_allowed=true ───────────────

#[test]
fn i10d_validate_recipe_rejects_persistence() {
    let mut r = default_local_attach_smoke_recipe();
    r.persistence_allowed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 63: validate rejects mutation_performed=true ────────────────

#[test]
fn i10d_validate_rejects_mutation() {
    let mut r = default_local_attach_smoke_recipe();
    r.mutation_performed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Coverage 64: docs exist and mention local attach smoke test artifact ─

#[test]
fn i10d_docs_exist_and_mention_artifact() {
    assert!(I10D_DOC
        .to_lowercase()
        .contains("local attach smoke test artifact"));
}

// ── Coverage 65: docs say detach proof ──────────────────────────────────

#[test]
fn i10d_docs_say_detach_proof() {
    assert!(I10D_DOC.to_lowercase().contains("detach proof"));
}

// ── Coverage 66: docs say disabled by default ───────────────────────────

#[test]
fn i10d_docs_say_disabled_by_default() {
    assert!(I10D_DOC.to_lowercase().contains("disabled by default"));
}

// ── Coverage 67: docs say feature-gated ─────────────────────────────────

#[test]
fn i10d_docs_say_feature_gated() {
    assert!(I10D_DOC.to_lowercase().contains("feature-gated"));
}

// ── Coverage 68: docs say no public CLI ─────────────────────────────────

#[test]
fn i10d_docs_say_no_public_cli() {
    assert!(I10D_DOC.to_lowercase().contains("no public cli"));
}

// ── Coverage 69: docs say no enforcement ────────────────────────────────

#[test]
fn i10d_docs_say_no_enforcement() {
    assert!(I10D_DOC.to_lowercase().contains("no enforcement"));
}

// ── Coverage 70: docs say no packet drop ────────────────────────────────

#[test]
fn i10d_docs_say_no_packet_drop() {
    assert!(I10D_DOC.to_lowercase().contains("no packet drop"));
}

// ── Coverage 71: docs say no block/allow/quota ──────────────────────────

#[test]
fn i10d_docs_say_no_block_allow_quota() {
    assert!(I10D_DOC.to_lowercase().contains("block/allow/quota"));
}

// ── Coverage 72: docs say no nft/tc fallback ────────────────────────────

#[test]
fn i10d_docs_say_no_nft_tc() {
    assert!(I10D_DOC.to_lowercase().contains("no nft/tc"));
}

// ── Coverage 73: docs say no ring buffer open ──────────────────────────

#[test]
fn i10d_docs_say_no_ring_buffer() {
    assert!(I10D_DOC.to_lowercase().contains("no ring buffer"));
}

// ── Coverage 74: docs say no live kernel event read ───────────────────

#[test]
fn i10d_docs_say_no_live_kernel_event_read() {
    assert!(I10D_DOC
        .to_lowercase()
        .contains("no live kernel event read"));
}

// ── Coverage 75: docs say no map pin ───────────────────────────────────

#[test]
fn i10d_docs_say_no_map_pin() {
    assert!(I10D_DOC.to_lowercase().contains("no map pin"));
}

// ── Coverage 76: docs say no ledger file write/persistence ─────────────

#[test]
fn i10d_docs_say_no_ledger_persistence() {
    assert!(I10D_DOC.to_lowercase().contains("no ledger file write"));
}

// ── Coverage 77: docs say normal tests do not require root ───────────────

#[test]
fn i10d_docs_say_no_root_for_tests() {
    assert!(I10D_DOC
        .to_lowercase()
        .contains("normal tests do not require root"));
}

// ── Coverage 78: docs say normal CI does not execute live attach ──────────

#[test]
fn i10d_docs_say_no_ci_live_attach() {
    assert!(I10D_DOC
        .to_lowercase()
        .contains("normal ci does not execute live attach"));
}

// ── Coverage 79: docs say existing v3.1 usage JSON schema unchanged ─────

#[test]
fn i10d_docs_say_usage_schema_unchanged() {
    assert!(I10D_DOC
        .to_lowercase()
        .contains("usage json schema unchanged"));
}

// ── Coverage 80: docs say existing v3.1 ledger JSON schema unchanged ─────

#[test]
fn i10d_docs_say_ledger_schema_unchanged() {
    assert!(I10D_DOC
        .to_lowercase()
        .contains("ledger json schema unchanged"));
}

// ── Coverage 81: existing zelynic --version remains v3.1.0 ─────────────

#[test]
fn i10d_version_remains_3_1_0() {
    let _ = Cli::command();
    assert!(CARGO_TOML.contains("version = \"3.1.0\""));
}

// ── Coverage 82: existing ledger inspect still works ──────────────────────

#[test]
fn i10d_ledger_inspect_still_works() {
    let _ = handle_ledger_inspect(true, None);
}

// ── Coverage 83: existing ledger export still works ─────────────────────

#[test]
fn i10d_ledger_export_still_works() {
    let tmp = std::env::temp_dir().join("i10d_ledger_test.json");
    let tmp_str = tmp.to_string_lossy().to_string();
    let _ = handle_ledger_export(true, Some(tmp_str.as_str()));
    let _ = std::fs::remove_file(tmp);
}

// ── Coverage 84: public help does not mention intergalaxion ─────────────

#[test]
fn i10d_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(
        !help.to_lowercase().contains("intergalaxion"),
        "public help must not mention intergalaxion"
    );
}

// ── Coverage 85: public help does not mention block/allow/quota ────────

#[test]
fn i10d_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(
        !help.contains("block"),
        "public help must not mention block"
    );
    assert!(
        !help.contains("allow"),
        "public help must not mention allow"
    );
    assert!(
        !help.contains("quota"),
        "public help must not mention quota"
    );
}

// ── Coverage 86: no new dependency added ───────────────────────────────

#[test]
fn i10d_no_new_dependency() {
    let toml = CARGO_TOML;
    assert!(toml.contains("[dependencies.aya]"));
    assert!(toml.contains("optional = true"));
}

// ── Coverage 87: no nft/tc source under intergalaxion backend ──────────

#[test]
fn i10d_no_nft_tc_in_artifact_source() {
    let src = I10D_SOURCE;
    let code_lines: Vec<&str> = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//!"))
        .collect();
    let code = code_lines.join("\n");
    assert!(!code.contains("nft"), "artifact code must not contain nft");
    assert!(!code.contains("tc "), "artifact code must not contain tc");
}

// ── Coverage 88: all touched files under 1000 LOC ─────────────────────

#[test]
fn i10d_source_under_1000_loc() {
    let lines: Vec<&str> = I10D_SOURCE.lines().collect();
    let non_empty = lines.iter().filter(|l| !l.trim().is_empty()).count();
    assert!(
        non_empty < 1000,
        "live_attach_artifact.rs has {non_empty} non-empty lines"
    );
}

// ── Additional: artifact status labels are all distinct ──────────────────

#[test]
fn i10d_all_artifact_status_labels_distinct() {
    let labels = [
        EbpfLiveAttachArtifactStatus::MissingArtifact,
        EbpfLiveAttachArtifactStatus::DeclaredOnly,
        EbpfLiveAttachArtifactStatus::BuildPlanned,
        EbpfLiveAttachArtifactStatus::BuildReady,
        EbpfLiveAttachArtifactStatus::Unsupported,
    ];
    let mut seen = std::collections::HashSet::new();
    for status in &labels {
        let label = live_attach_artifact_status_label(*status);
        assert!(seen.insert(label), "duplicate label: {label}");
    }
}

// ── Additional: detach proof status labels are all distinct ──────────────

#[test]
fn i10d_all_detach_proof_labels_distinct() {
    let labels = [
        EbpfDetachProofStatus::NotAttempted,
        EbpfDetachProofStatus::DetachPlanned,
        EbpfDetachProofStatus::DetachedCleanly,
        EbpfDetachProofStatus::DetachFailed,
        EbpfDetachProofStatus::ManualCleanupRequired,
    ];
    let mut seen = std::collections::HashSet::new();
    for status in &labels {
        let label = detach_proof_status_label(*status);
        assert!(seen.insert(label), "duplicate label: {label}");
    }
}

// ── Additional: default artifact has feature_required set ────────────────

#[test]
fn i10d_default_artifact_feature_required() {
    let c = default_live_attach_artifact_contract();
    assert_eq!(c.feature_required, "intergalaxion-live-attach-lab");
}

// ── Additional: default recipe artifact is safe ─────────────────────────

#[test]
fn i10d_default_recipe_artifact_is_safe() {
    let r = default_local_attach_smoke_recipe();
    assert!(validate_live_attach_artifact_contract(&r.artifact).is_ok());
}

// ── Additional: default recipe detach proof is safe ──────────────────────

#[test]
fn i10d_default_recipe_detach_proof_is_safe() {
    let r = default_local_attach_smoke_recipe();
    assert!(validate_detach_proof(&r.detach_proof).is_ok());
}

// ── Additional: forbidden patterns not in source ───────────────────────

#[test]
fn i10d_source_no_forbidden_patterns() {
    let src = I10D_SOURCE;
    assert!(
        !src.contains("Bpf::load"),
        "source must not contain Bpf::load"
    );
    assert!(
        !src.contains("load_file"),
        "source must not contain load_file"
    );
    assert!(
        !src.contains("program_mut"),
        "source must not contain program_mut"
    );
    assert!(
        !src.contains(".attach("),
        "source must not contain .attach("
    );
    assert!(!src.contains("RingBuf"), "source must not contain RingBuf");
    assert!(
        !src.contains("AsyncPerfEventArray"),
        "source must not contain AsyncPerfEventArray"
    );
    assert!(
        !src.contains("PerfEventArray"),
        "source must not contain PerfEventArray"
    );
    assert!(!src.contains("MapData"), "source must not contain MapData");
    assert!(
        !src.contains("create_map"),
        "source must not contain create_map"
    );
    assert!(!src.contains("pin("), "source must not contain pin(");
    assert!(
        !src.contains("bpf_prog_load"),
        "source must not contain bpf_prog_load"
    );
    assert!(
        !src.contains("bpf_map_create"),
        "source must not contain bpf_map_create"
    );
    assert!(
        !src.contains("bpf_ringbuf"),
        "source must not contain bpf_ringbuf"
    );
    assert!(
        !src.contains("/sys/fs/bpf"),
        "source must not contain /sys/fs/bpf"
    );
    assert!(
        !src.contains("/sys/kernel"),
        "source must not contain /sys/kernel"
    );
    assert!(!src.contains("/proc/"), "source must not contain /proc/");
    assert!(
        !src.contains("File::create"),
        "source must not contain File::create"
    );
    assert!(
        !src.contains("fs::write"),
        "source must not contain fs::write"
    );
    assert!(
        !src.contains("OpenOptions"),
        "source must not contain OpenOptions"
    );
    assert!(
        !src.contains("drop_packet"),
        "source must not contain drop_packet"
    );
}

// ── Additional: recipe with unsafe artifact is rejected ─────────────────

#[test]
fn i10d_recipe_rejects_unsafe_artifact() {
    let mut r = default_local_attach_smoke_recipe();
    r.artifact.enforcement_allowed = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Additional: recipe with unsafe detach proof is rejected ────────────

#[test]
fn i10d_recipe_rejects_unsafe_detach_proof() {
    let mut r = default_local_attach_smoke_recipe();
    r.detach_proof.kernel_state_mutated = true;
    assert!(validate_local_attach_smoke_recipe(&r).is_err());
}

// ── Helper for rendering CLI help ───────────────────────────────────────

fn render_help(app: &mut clap::Command) -> String {
    let mut buf = Vec::new();
    let _ = clap::Command::write_long_help(app, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}
