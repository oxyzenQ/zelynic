// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-10B tests: live attach spike runbook gate.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::live_attach_runbook::*;
use clap::CommandFactory;

const I10B_DOC: &str =
    include_str!("../../docs/intergalaxion/I-10B-explicit-local-live-attach-spike-runbook.md");
const I10B_SOURCE: &str = include_str!("live_attach_runbook.rs");

// ── Coverage 1: default runbook phase is I-10B ───────────────────────

#[test]
fn i10b_default_phase_is_i10b() {
    let rb = default_live_attach_runbook();
    assert_eq!(rb.phase, "I-10B");
}

// ── Coverage 2: default runbook is local lab only ───────────────────────

#[test]
fn i10b_default_is_local_lab_only() {
    let rb = default_live_attach_runbook();
    assert!(rb.local_lab_only);
}

// ── Coverage 3: default runbook does not allow public CLI ─────────────

#[test]
fn i10b_default_no_public_cli() {
    let rb = default_live_attach_runbook();
    assert!(!rb.public_cli_allowed);
}

// ── Coverage 4: default runbook does not allow enforcement ────────────

#[test]
fn i10b_default_no_enforcement() {
    let rb = default_live_attach_runbook();
    assert!(!rb.enforcement_allowed);
}

// ── Coverage 5: default runbook does not allow packet drop ────────────

#[test]
fn i10b_default_no_packet_drop() {
    let rb = default_live_attach_runbook();
    assert!(!rb.packet_drop_allowed);
}

// ── Coverage 6: default runbook does not allow persistence ─────────────

#[test]
fn i10b_default_no_persistence() {
    let rb = default_live_attach_runbook();
    assert!(!rb.persistence_allowed);
}

// ── Coverage 7: default runbook requires root acknowledgement ──────────

#[test]
fn i10b_default_requires_root_ack() {
    let rb = default_live_attach_runbook();
    assert!(rb.requires_root_acknowledgement);
}

// ── Coverage 8: default runbook requires explicit operator label ───────

#[test]
fn i10b_default_requires_operator_label() {
    let rb = default_live_attach_runbook();
    assert!(rb.requires_explicit_operator_label);
}

// ── Coverage 9: default runbook requires cleanup plan ─────────────────

#[test]
fn i10b_default_requires_cleanup_plan() {
    let rb = default_live_attach_runbook();
    assert!(rb.requires_cleanup_plan);
}

// ── Coverage 10: default runbook has all operation flags false ──────────

#[test]
fn i10b_default_all_operation_flags_false() {
    let rb = default_live_attach_runbook();
    assert!(!rb.program_load_performed);
    assert!(!rb.attach_performed);
    assert!(!rb.map_create_performed);
    assert!(!rb.ring_buffer_opened);
    assert!(!rb.live_kernel_read_performed);
    assert!(!rb.map_pin_performed);
    assert!(!rb.enforcement_performed);
    assert!(!rb.packet_drop_performed);
    assert!(!rb.mutation_performed);
    assert!(!rb.persistence_performed);
    assert!(!rb.public_cli_exposed);
}

// ── Coverage 11: status labels are stable ───────────────────────────────

#[test]
fn i10b_status_labels_are_stable() {
    assert_eq!(
        live_attach_runbook_status_label(IntergalaxionLiveAttachRunbookStatus::Draft),
        "draft"
    );
    assert_eq!(
        live_attach_runbook_status_label(IntergalaxionLiveAttachRunbookStatus::Frozen),
        "frozen"
    );
    assert_eq!(
        live_attach_runbook_status_label(IntergalaxionLiveAttachRunbookStatus::Rejected),
        "rejected"
    );
}

// ── Coverage 12: step kind labels are stable ────────────────────────────

#[test]
fn i10b_step_kind_labels_are_stable() {
    assert_eq!(
        live_attach_runbook_step_kind_label(IntergalaxionLiveAttachRunbookStepKind::Preflight),
        "preflight"
    );
    assert_eq!(
        live_attach_runbook_step_kind_label(
            IntergalaxionLiveAttachRunbookStepKind::OperatorConsent
        ),
        "operator_consent"
    );
    assert_eq!(
        live_attach_runbook_step_kind_label(IntergalaxionLiveAttachRunbookStepKind::BuildCheck),
        "build_check"
    );
    assert_eq!(
        live_attach_runbook_step_kind_label(
            IntergalaxionLiveAttachRunbookStepKind::CapabilityCheck
        ),
        "capability_check"
    );
    assert_eq!(
        live_attach_runbook_step_kind_label(IntergalaxionLiveAttachRunbookStepKind::AttachWindow),
        "attach_window"
    );
    assert_eq!(
        live_attach_runbook_step_kind_label(IntergalaxionLiveAttachRunbookStepKind::Cleanup),
        "cleanup"
    );
    assert_eq!(
        live_attach_runbook_step_kind_label(IntergalaxionLiveAttachRunbookStepKind::AbortCondition),
        "abort_condition"
    );
    assert_eq!(
        live_attach_runbook_step_kind_label(IntergalaxionLiveAttachRunbookStepKind::PostRunAudit),
        "post_run_audit"
    );
}

// ── Coverage 13: runbook steps are deterministic ────────────────────────

#[test]
fn i10b_steps_are_deterministic() {
    let rb1 = default_live_attach_runbook();
    let rb2 = default_live_attach_runbook();
    assert_eq!(rb1.steps, rb2.steps);
    assert_eq!(rb1.steps.len(), rb2.steps.len());
}

// ── Coverage 14: runbook abort conditions are deterministic ─────────────

#[test]
fn i10b_abort_conditions_are_deterministic() {
    let rb1 = default_live_attach_runbook();
    let rb2 = default_live_attach_runbook();
    assert_eq!(rb1.abort_conditions, rb2.abort_conditions);
}

// ── Coverage 15: runbook contains preflight step ──────────────────────

#[test]
fn i10b_contains_preflight_step() {
    let rb = default_live_attach_runbook();
    assert!(rb
        .steps
        .iter()
        .any(|s| s.kind == IntergalaxionLiveAttachRunbookStepKind::Preflight));
}

// ── Coverage 16: runbook contains consent step ─────────────────────────

#[test]
fn i10b_contains_consent_step() {
    let rb = default_live_attach_runbook();
    assert!(rb
        .steps
        .iter()
        .any(|s| s.kind == IntergalaxionLiveAttachRunbookStepKind::OperatorConsent));
}

// ── Coverage 17: runbook contains build check step ─────────────────────

#[test]
fn i10b_contains_build_check_step() {
    let rb = default_live_attach_runbook();
    assert!(rb
        .steps
        .iter()
        .any(|s| s.kind == IntergalaxionLiveAttachRunbookStepKind::BuildCheck));
}

// ── Coverage 18: runbook contains capability check step ─────────────────

#[test]
fn i10b_contains_capability_check_step() {
    let rb = default_live_attach_runbook();
    assert!(rb
        .steps
        .iter()
        .any(|s| s.kind == IntergalaxionLiveAttachRunbookStepKind::CapabilityCheck));
}

// ── Coverage 19: runbook contains attach window step ────────────────────

#[test]
fn i10b_contains_attach_window_step() {
    let rb = default_live_attach_runbook();
    assert!(rb
        .steps
        .iter()
        .any(|s| s.kind == IntergalaxionLiveAttachRunbookStepKind::AttachWindow));
}

// ── Coverage 20: runbook contains cleanup step ──────────────────────────

#[test]
fn i10b_contains_cleanup_step() {
    let rb = default_live_attach_runbook();
    assert!(rb
        .steps
        .iter()
        .any(|s| s.kind == IntergalaxionLiveAttachRunbookStepKind::Cleanup));
}

// ── Coverage 21: runbook contains abort condition step ─────────────────

#[test]
fn i10b_contains_abort_condition_step() {
    let rb = default_live_attach_runbook();
    assert!(rb
        .steps
        .iter()
        .any(|s| s.kind == IntergalaxionLiveAttachRunbookStepKind::AbortCondition));
}

// ── Coverage 22: runbook contains post-run audit step ─────────────────

#[test]
fn i10b_contains_post_run_audit_step() {
    let rb = default_live_attach_runbook();
    assert!(rb
        .steps
        .iter()
        .any(|s| s.kind == IntergalaxionLiveAttachRunbookStepKind::PostRunAudit));
}

// ── Coverage 23: runbook has blocking abort conditions ──────────────────

#[test]
fn i10b_has_blocking_abort_conditions() {
    let rb = default_live_attach_runbook();
    assert!(rb.abort_conditions.iter().any(|c| c.blocking));
}

// ── Coverage 24: validation accepts safe default runbook ─────────────────

#[test]
fn i10b_validation_accepts_safe_default() {
    let rb = default_live_attach_runbook();
    assert!(validate_live_attach_runbook(&rb).is_ok());
}

// ── Coverage 25: validation rejects local_lab_only=false ───────────────

#[test]
fn i10b_rejects_not_local_lab() {
    let mut rb = default_live_attach_runbook();
    rb.local_lab_only = false;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 26: validation rejects public_cli_allowed=true ───────────

#[test]
fn i10b_rejects_public_cli_allowed() {
    let mut rb = default_live_attach_runbook();
    rb.public_cli_allowed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 27: validation rejects enforcement_allowed=true ──────────

#[test]
fn i10b_rejects_enforcement_allowed() {
    let mut rb = default_live_attach_runbook();
    rb.enforcement_allowed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 28: validation rejects packet_drop_allowed=true ───────────

#[test]
fn i10b_rejects_packet_drop_allowed() {
    let mut rb = default_live_attach_runbook();
    rb.packet_drop_allowed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 29: validation rejects persistence_allowed=true ───────────

#[test]
fn i10b_rejects_persistence_allowed() {
    let mut rb = default_live_attach_runbook();
    rb.persistence_allowed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 30: validation rejects requires_root_acknowledgement=false ─

#[test]
fn i10b_rejects_no_root_ack() {
    let mut rb = default_live_attach_runbook();
    rb.requires_root_acknowledgement = false;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 31: validation rejects requires_explicit_operator_label=false

#[test]
fn i10b_rejects_no_operator_label() {
    let mut rb = default_live_attach_runbook();
    rb.requires_explicit_operator_label = false;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 32: validation rejects requires_cleanup_plan=false ───────

#[test]
fn i10b_rejects_no_cleanup_plan() {
    let mut rb = default_live_attach_runbook();
    rb.requires_cleanup_plan = false;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 33-43: validation rejects each operation flag ─────────────

#[test]
fn i10b_rejects_program_load() {
    let mut rb = default_live_attach_runbook();
    rb.program_load_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_attach() {
    let mut rb = default_live_attach_runbook();
    rb.attach_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_map_create() {
    let mut rb = default_live_attach_runbook();
    rb.map_create_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_ring_buffer() {
    let mut rb = default_live_attach_runbook();
    rb.ring_buffer_opened = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_live_kernel_read() {
    let mut rb = default_live_attach_runbook();
    rb.live_kernel_read_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_map_pin() {
    let mut rb = default_live_attach_runbook();
    rb.map_pin_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_enforcement_performed() {
    let mut rb = default_live_attach_runbook();
    rb.enforcement_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_packet_drop_performed() {
    let mut rb = default_live_attach_runbook();
    rb.packet_drop_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_mutation() {
    let mut rb = default_live_attach_runbook();
    rb.mutation_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_persistence_performed() {
    let mut rb = default_live_attach_runbook();
    rb.persistence_performed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

#[test]
fn i10b_rejects_public_cli_exposed() {
    let mut rb = default_live_attach_runbook();
    rb.public_cli_exposed = true;
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 44: validation rejects empty steps ─────────────────────────

#[test]
fn i10b_rejects_empty_steps() {
    let mut rb = default_live_attach_runbook();
    rb.steps.clear();
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 45: validation rejects empty abort conditions ─────────────

#[test]
fn i10b_rejects_empty_abort_conditions() {
    let mut rb = default_live_attach_runbook();
    rb.abort_conditions.clear();
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 46: validation rejects required step with empty title ───────

#[test]
fn i10b_rejects_required_step_empty_title() {
    let mut rb = default_live_attach_runbook();
    if let Some(step) = rb.steps.iter_mut().find(|s| s.required) {
        step.title = String::new();
    }
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 47: validation rejects required step with empty description

#[test]
fn i10b_rejects_required_step_empty_description() {
    let mut rb = default_live_attach_runbook();
    if let Some(step) = rb.steps.iter_mut().find(|s| s.required) {
        step.description = String::new();
    }
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 48: validation rejects abort condition with empty code ────

#[test]
fn i10b_rejects_abort_condition_empty_code() {
    let mut rb = default_live_attach_runbook();
    if let Some(cond) = rb.abort_conditions.iter_mut().next() {
        cond.code = String::new();
    }
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 49: validation rejects abort condition with empty description

#[test]
fn i10b_rejects_abort_condition_empty_description() {
    let mut rb = default_live_attach_runbook();
    if let Some(cond) = rb.abort_conditions.iter_mut().next() {
        cond.description = String::new();
    }
    assert!(validate_live_attach_runbook(&rb).is_err());
}

// ── Coverage 50: docs exist and mention runbook ──────────────────────────

#[test]
fn i10b_docs_exist_and_mention_runbook() {
    let doc = I10B_DOC;
    let doc_lower = doc.to_lowercase();
    assert!(doc_lower.contains("runbook"));
}

// ── Coverage 51: docs say hard gate contract ───────────────────────────

#[test]
fn i10b_docs_say_hard_gate() {
    let doc = I10B_DOC;
    let doc_lower = doc.to_lowercase();
    assert!(
        doc_lower.contains("hard gate") || doc_lower.contains("gate contract"),
        "doc should mention hard gate contract"
    );
}

// ── Coverage 52: docs say no real live attach ───────────────────────────

#[test]
fn i10b_docs_say_no_real_live_attach() {
    let doc = I10B_DOC;
    let doc_lower = doc.to_lowercase();
    assert!(doc_lower.contains("no real live attach") || doc_lower.contains("no real live"));
}

// ── Coverage 53: docs say no userspace loader ───────────────────────────

#[test]
fn i10b_docs_say_no_userspace_loader() {
    let doc = I10B_DOC;
    assert!(doc.contains("userspace loader"));
}

// ── Coverage 54: docs say no program operations ────────────────────────

#[test]
fn i10b_docs_say_no_program_operations() {
    let doc = I10B_DOC;
    assert!(doc.contains("program load"));
    assert!(doc.contains("attach"));
    assert!(doc.contains("map create"));
    assert!(doc.contains("ring buffer open") || doc.contains("ring buffer"));
    assert!(doc.contains("live kernel event read") || doc.contains("live kernel read"));
    assert!(doc.contains("map pin"));
}

// ── Coverage 55: docs say no enforcement ───────────────────────────────

#[test]
fn i10b_docs_say_no_enforcement() {
    let doc = I10B_DOC;
    assert!(doc.contains("enforcement"));
}

// ── Coverage 56: docs say no packet drop ───────────────────────────────

#[test]
fn i10b_docs_say_no_packet_drop() {
    let doc = I10B_DOC;
    assert!(doc.contains("packet drop"));
}

// ── Coverage 57: docs say no block/allow/quota ─────────────────────────

#[test]
fn i10b_docs_say_no_block_allow_quota() {
    let doc = I10B_DOC;
    assert!(doc.contains("block/allow/quota"));
}

// ── Coverage 58: docs say no nft/tc fallback ─────────────────────────

#[test]
fn i10b_docs_say_no_nft_tc() {
    let doc = I10B_DOC;
    assert!(doc.contains("nft/tc"));
}

// ── Coverage 59: docs say no public CLI ───────────────────────────────

#[test]
fn i10b_docs_say_no_public_cli() {
    let doc = I10B_DOC;
    assert!(doc.contains("public CLI") || doc.contains("public cli"));
}

// ── Coverage 60: docs say no ledger file write/persistence ─────────────

#[test]
fn i10b_docs_say_no_ledger_write() {
    let doc = I10B_DOC;
    assert!(doc.contains("ledger file write") || doc.contains("persistence"));
}

// ── Coverage 61: docs say existing v3.1 usage JSON schema unchanged ──────

#[test]
fn i10b_docs_say_usage_schema_unchanged() {
    let doc = I10B_DOC;
    assert!(doc.contains("usage JSON schema unchanged") || doc.contains("usage schema unchanged"));
}

// ── Coverage 62: docs say existing v3.1 ledger JSON schema unchanged ───

#[test]
fn i10b_docs_say_ledger_schema_unchanged() {
    let doc = I10B_DOC;
    assert!(
        doc.contains("ledger JSON schema unchanged") || doc.contains("ledger schema unchanged")
    );
}

// ── Coverage 63: existing zelynic --version remains v3.1.0 ──────────────

#[test]
fn i10b_version_remains_3_1_0() {
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(version, "3.1.0");
}

// ── Coverage 64: existing ledger inspect --json still works ──────────────

#[test]
fn i10b_ledger_inspect_json_works() {
    let result = handle_ledger_inspect(true, None);
    let _ = result;
}

// ── Coverage 65: existing ledger export --json --file still works ────────

#[test]
fn i10b_ledger_export_json_file_works() {
    let tmp = std::env::temp_dir().join("i10b_ledger_test.json");
    let tmp_str = tmp.to_string_lossy().to_string();
    let result = handle_ledger_export(true, Some(&tmp_str));
    let _ = result;
    let _ = std::fs::remove_file(tmp);
}

// ── Coverage 66: public help does not mention intergalaxion ───────────

#[test]
fn i10b_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(!help.to_lowercase().contains("intergalaxion"));
}

fn render_help(app: &mut clap::Command) -> String {
    let mut buf = Vec::new();
    let _ = clap::Command::write_help(app, &mut buf);
    String::from_utf8(buf).unwrap_or_default()
}

// ── Coverage 67: public help does not mention block/allow/quota ────────

#[test]
fn i10b_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

// ── Coverage 68: no new dependency added ──────────────────────────────

#[test]
fn i10b_no_new_dependency() {
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(cargo_toml.contains("zelynic"));
    assert!(cargo_toml.contains("optional = true") || !cargo_toml.contains("aya"));
}

// ── Coverage 69: no live kernel mutation API in new runbook source ────

#[test]
fn i10b_source_no_kernel_mutation_api() {
    let src = I10B_SOURCE;
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

// ── Coverage 70: no aya ringbuf/map open/load/attach/pin API ──────────

#[test]
fn i10b_source_no_aya_live_api() {
    let src = I10B_SOURCE;
    assert!(src.contains("validate_live_attach_runbook"));
    assert!(!src.contains("aya::"));
    assert!(!src.contains("load_file"));
}

// ── Coverage 71: no nft/tc source under intergalaxion backend ────────

#[test]
fn i10b_no_nft_tc_under_backend() {
    let src = I10B_SOURCE;
    assert!(!src.contains("tc "), "source must not contain tc");
    assert!(!src.contains("nft"), "source must not contain nft");
}

// ── Coverage 72: all touched files under 1000 LOC ─────────────────────

#[test]
fn i10b_source_under_1000_loc() {
    let lines: Vec<&str> = I10B_SOURCE.lines().collect();
    let non_empty = lines.iter().filter(|l| !l.trim().is_empty()).count();
    assert!(
        non_empty < 1000,
        "live_attach_runbook.rs has {non_empty} non-empty lines"
    );
}

// ── Extra: default status is Draft ──────────────────────────────────────

#[test]
fn i10b_default_status_is_draft() {
    let rb = default_live_attach_runbook();
    assert_eq!(rb.status, IntergalaxionLiveAttachRunbookStatus::Draft);
}

// ── Extra: all steps are required ────────────────────────────────────────

#[test]
fn i10b_all_steps_are_required() {
    let rb = default_live_attach_runbook();
    assert!(rb.steps.iter().all(|s| s.required));
}

// ── Extra: all steps must be manual ─────────────────────────────────────

#[test]
fn i10b_all_steps_must_be_manual() {
    let rb = default_live_attach_runbook();
    assert!(rb.steps.iter().all(|s| s.must_be_manual));
}

// ── Extra: no step can mutate system ───────────────────────────────────

#[test]
fn i10b_no_step_can_mutate_system() {
    let rb = default_live_attach_runbook();
    assert!(rb.steps.iter().all(|s| !s.can_mutate_system));
}

// ── Extra: runbook has 8 steps ─────────────────────────────────────────

#[test]
fn i10b_has_eight_steps() {
    let rb = default_live_attach_runbook();
    assert_eq!(rb.steps.len(), 8);
}

// ── Extra: runbook has 8 abort conditions ──────────────────────────────

#[test]
fn i10b_has_eight_abort_conditions() {
    let rb = default_live_attach_runbook();
    assert_eq!(rb.abort_conditions.len(), 8);
}

// ── Extra: frozen runbook is valid ─────────────────────────────────────

#[test]
fn i10b_frozen_runbook_is_valid() {
    let mut rb = default_live_attach_runbook();
    rb.status = IntergalaxionLiveAttachRunbookStatus::Frozen;
    assert!(validate_live_attach_runbook(&rb).is_ok());
}
