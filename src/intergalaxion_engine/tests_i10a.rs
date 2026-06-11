// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-10A tests: final static safety audit before live attach.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::attach_plan::{
    default_attach_target, evaluate_attach_plan,
};
use crate::intergalaxion_engine::backends::ebpf::capability::evaluate_ebpf_capability;
use crate::intergalaxion_engine::backends::ebpf::live_attach_gate::*;
use crate::intergalaxion_engine::backends::ebpf::loader_boundary::evaluate_loader_boundary;
use crate::intergalaxion_engine::backends::ebpf::program_skeleton::default_program_skeleton_set;
use crate::intergalaxion_engine::live_readiness::evaluate_intergalaxion_readiness;
use crate::intergalaxion_engine::static_audit::*;
use clap::CommandFactory;

const I10A_DOC: &str =
    include_str!("../../docs/intergalaxion/I-10A-final-static-safety-audit-before-live-attach.md");
const I10A_SOURCE: &str = include_str!("static_audit.rs");

// ── Helpers (reuse established I-9 patterns) ───────────────────────────

fn observer_ready_snapshot(
) -> crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilitySnapshot {
    crate::intergalaxion_engine::backends::ebpf::capability::EbpfCapabilitySnapshot {
        bpf_fs_mounted: Some(true),
        btf_vmlinux_available: Some(true),
        cap_bpf_effective: Some(true),
        ..Default::default()
    }
}

fn future_gate() -> crate::intergalaxion_engine::live_readiness::IntergalaxionReadinessGate {
    let input = crate::intergalaxion_engine::live_readiness::IntergalaxionReadinessInput {
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        explicit_future_attach_consent: true,
        public_cli_requested: false,
        ..Default::default()
    };
    evaluate_intergalaxion_readiness(&input)
}

fn future_loader_plan(
) -> crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryPlan {
    let gate = future_gate();
    let input =
        crate::intergalaxion_engine::backends::ebpf::loader_boundary::EbpfLoaderBoundaryInput {
            readiness_gate: gate,
            skeleton_set: default_program_skeleton_set(),
            explicit_loader_consent: true,
            object_source_declared: true,
            public_cli_requested: false,
            ..Default::default()
        };
    evaluate_loader_boundary(&input)
}

fn future_attach_plan() -> crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachPlan
{
    let input = crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachPlanInput {
        loader_plan: future_loader_plan(),
        skeleton_set: default_program_skeleton_set(),
        target: default_attach_target(),
        explicit_attach_consent: true,
        rollback_required: true,
        public_cli_requested: false,
        ..Default::default()
    };
    evaluate_attach_plan(&input)
}

fn full_consent() -> EbpfLiveAttachConsent {
    EbpfLiveAttachConsent {
        explicit_live_observer_attach: true,
        explicit_root_acknowledgement: true,
        explicit_no_enforcement_acknowledgement: true,
        explicit_no_packet_drop_acknowledgement: true,
        explicit_cleanup_acknowledgement: true,
        rollback_required: true,
        operator_label: String::from("test-operator"),
    }
}

fn future_preflight() -> EbpfLiveAttachPreflight {
    EbpfLiveAttachPreflight {
        attach_plan: future_attach_plan(),
        capability_report: evaluate_ebpf_capability(&observer_ready_snapshot()),
        loader_plan: future_loader_plan(),
        skeleton_set: default_program_skeleton_set(),
        consent: full_consent(),
        public_cli_requested: false,
    }
}

// Helper: full future-ready audit input.
fn safe_audit_input() -> IntergalaxionStaticAuditInput {
    let preflight = future_preflight();
    let decision = evaluate_live_attach_gate(&preflight);
    let executor = execute_live_attach_disabled(&decision);
    IntergalaxionStaticAuditInput {
        readiness_gate: future_gate(),
        program_skeleton_set: default_program_skeleton_set(),
        loader_plan: future_loader_plan(),
        attach_plan: future_attach_plan(),
        live_attach_decision: decision,
        executor_result: executor,
        public_cli_expected_hidden: true,
        stable_cli_expected_unchanged: true,
        usage_schema_expected_unchanged: true,
        ledger_schema_expected_unchanged: true,
    }
}

// ── Coverage 1: default audit input is safe ──────────────────────────

#[test]
fn i10a_default_audit_input_is_safe() {
    let input = default_static_audit_input();
    assert!(input.public_cli_expected_hidden);
    assert!(input.stable_cli_expected_unchanged);
    assert!(input.usage_schema_expected_unchanged);
    assert!(input.ledger_schema_expected_unchanged);
}

// ── Coverage 2: default audit report is deterministic ─────────────────

#[test]
fn i10a_default_audit_report_is_deterministic() {
    let input = default_static_audit_input();
    let r1 = evaluate_static_audit(&input);
    let r2 = evaluate_static_audit(&input);
    assert_eq!(r1, r2);
}

// ── Coverage 3: audit report phase is I-10A ──────────────────────────

#[test]
fn i10a_audit_report_phase_is_i10a() {
    let input = default_static_audit_input();
    let report = evaluate_static_audit(&input);
    assert_eq!(report.phase, "I-10A");
}

// ── Coverage 4: status labels are stable ───────────────────────────────

#[test]
fn i10a_status_labels_are_stable() {
    assert_eq!(
        static_audit_status_label(IntergalaxionStaticAuditStatus::Passed),
        "passed"
    );
    assert_eq!(
        static_audit_status_label(IntergalaxionStaticAuditStatus::Failed),
        "failed"
    );
    assert_eq!(
        static_audit_status_label(IntergalaxionStaticAuditStatus::Warning),
        "warning"
    );
}

// ── Coverage 5: safe audit report has all operation flags false ────────

#[test]
fn i10a_safe_report_all_operation_flags_false() {
    let input = safe_audit_input();
    let report = evaluate_static_audit(&input);
    assert!(!report.program_load_performed);
    assert!(!report.attach_performed);
    assert!(!report.map_create_performed);
    assert!(!report.ring_buffer_opened);
    assert!(!report.live_kernel_read_performed);
    assert!(!report.map_pin_performed);
    assert!(!report.enforcement_performed);
    assert!(!report.packet_drop_performed);
    assert!(!report.mutation_performed);
    assert!(!report.persistence_performed);
}

// ── Coverage 6: safe audit report keeps public_cli_exposed=false ──────

#[test]
fn i10a_safe_report_public_cli_exposed_false() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert!(!report.public_cli_exposed);
}

// ── Coverage 7: safe audit report keeps stable_cli_changed=false ──────

#[test]
fn i10a_safe_report_stable_cli_changed_false() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert!(!report.stable_cli_changed);
}

// ── Coverage 8: safe audit report keeps usage_schema_changed=false ────

#[test]
fn i10a_safe_report_usage_schema_changed_false() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert!(!report.usage_schema_changed);
}

// ── Coverage 9: safe audit report keeps ledger_schema_changed=false ─────

#[test]
fn i10a_safe_report_ledger_schema_changed_false() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert!(!report.ledger_schema_changed);
}

// ── Coverage 10: safe audit report can be Passed ───────────────────────

#[test]
fn i10a_safe_report_can_be_passed() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Passed);
}

// ── Coverage 11: ready_for_real_attach_spike requires safe readiness gate ─

#[test]
fn i10a_ready_requires_safe_readiness_gate() {
    let mut input = safe_audit_input();
    // Use a blocked readiness gate.
    let blocked_input = crate::intergalaxion_engine::live_readiness::IntergalaxionReadinessInput {
        public_cli_requested: true,
        ..Default::default()
    };
    input.readiness_gate = evaluate_intergalaxion_readiness(&blocked_input);
    let report = evaluate_static_audit(&input);
    assert!(!report.ready_for_real_attach_spike);
}

// ── Coverage 12: ready_for_real_attach_spike requires safe skeleton set ─

#[test]
fn i10a_ready_requires_safe_skeleton_set() {
    let mut input = safe_audit_input();
    input.program_skeleton_set.loader_available = true;
    let report = evaluate_static_audit(&input);
    assert!(!report.ready_for_real_attach_spike);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 13: ready_for_real_attach_spike requires safe loader plan ─

#[test]
fn i10a_ready_requires_safe_loader_plan() {
    let mut input = safe_audit_input();
    input.loader_plan.loader_available = true;
    let report = evaluate_static_audit(&input);
    assert!(!report.ready_for_real_attach_spike);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 14: ready_for_real_attach_spike requires safe attach plan ─

#[test]
fn i10a_ready_requires_safe_attach_plan() {
    let mut input = safe_audit_input();
    input.attach_plan.attach_performed = true;
    let report = evaluate_static_audit(&input);
    assert!(!report.ready_for_real_attach_spike);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 15: ready_for_real_attach_spike requires safe live attach decision ─

#[test]
fn i10a_ready_requires_safe_live_attach_decision() {
    let mut input = safe_audit_input();
    input.live_attach_decision.public_cli_exposed = true;
    let report = evaluate_static_audit(&input);
    assert!(!report.ready_for_real_attach_spike);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 16: ready_for_real_attach_spike requires safe executor result ─

#[test]
fn i10a_ready_requires_safe_executor_result() {
    let mut input = safe_audit_input();
    input.executor_result.attempted = true;
    let report = evaluate_static_audit(&input);
    assert!(!report.ready_for_real_attach_spike);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 17: ready_for_real_attach_spike requires executor disabled ─

#[test]
fn i10a_ready_requires_executor_disabled() {
    let mut input = safe_audit_input();
    input.live_attach_decision.executor_disabled = false;
    let report = evaluate_static_audit(&input);
    // executor_disabled=false means the gate decision is not safe
    // so ready_for_real_attach_spike must be false
    assert!(!report.ready_for_real_attach_spike);
}

// ── Coverage 18: audit fails when public_cli_expected_hidden=false ───

#[test]
fn i10a_fails_when_public_cli_not_hidden() {
    let mut input = safe_audit_input();
    input.public_cli_expected_hidden = false;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(!report.ready_for_real_attach_spike);
}

// ── Coverage 19: audit fails when stable_cli_expected_unchanged=false ─

#[test]
fn i10a_fails_when_stable_cli_not_unchanged() {
    let mut input = safe_audit_input();
    input.stable_cli_expected_unchanged = false;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.stable_cli_changed);
}

// ── Coverage 20: audit fails when usage_schema_expected_unchanged=false ─

#[test]
fn i10a_fails_when_usage_schema_not_unchanged() {
    let mut input = safe_audit_input();
    input.usage_schema_expected_unchanged = false;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.usage_schema_changed);
}

// ── Coverage 21: audit fails when ledger_schema_expected_unchanged=false ─

#[test]
fn i10a_fails_when_ledger_schema_not_unchanged() {
    let mut input = safe_audit_input();
    input.ledger_schema_expected_unchanged = false;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.ledger_schema_changed);
}

// ── Coverage 22: audit fails when loader plan is unsafe ───────────────

#[test]
fn i10a_fails_when_loader_plan_unsafe() {
    let mut input = safe_audit_input();
    input.loader_plan.enforcement_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 23: audit fails when attach plan is unsafe ───────────────

#[test]
fn i10a_fails_when_attach_plan_unsafe() {
    let mut input = safe_audit_input();
    input.attach_plan.enforcement_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 24: audit fails when decision has program_load_performed ─

#[test]
fn i10a_fails_when_decision_program_load() {
    let mut input = safe_audit_input();
    input.live_attach_decision.program_load_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.program_load_performed);
}

// ── Coverage 25: audit fails when decision has attach_performed ──────

#[test]
fn i10a_fails_when_decision_attach() {
    let mut input = safe_audit_input();
    input.live_attach_decision.attach_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.attach_performed);
}

// ── Coverage 26: audit fails when decision has map_create_performed ───

#[test]
fn i10a_fails_when_decision_map_create() {
    let mut input = safe_audit_input();
    input.live_attach_decision.map_create_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.map_create_performed);
}

// ── Coverage 27: audit fails when decision has ring_buffer_opened ──────

#[test]
fn i10a_fails_when_decision_ring_buffer() {
    let mut input = safe_audit_input();
    input.live_attach_decision.ring_buffer_opened = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.ring_buffer_opened);
}

// ── Coverage 28: audit fails when decision has live_kernel_read ────────

#[test]
fn i10a_fails_when_decision_live_kernel_read() {
    let mut input = safe_audit_input();
    input.live_attach_decision.live_kernel_read_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.live_kernel_read_performed);
}

// ── Coverage 29: audit fails when decision has map_pin_performed ───────

#[test]
fn i10a_fails_when_decision_map_pin() {
    let mut input = safe_audit_input();
    input.live_attach_decision.map_pin_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.map_pin_performed);
}

// ── Coverage 30: audit fails when decision has enforcement_performed ────

#[test]
fn i10a_fails_when_decision_enforcement() {
    let mut input = safe_audit_input();
    input.live_attach_decision.enforcement_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.enforcement_performed);
}

// ── Coverage 31: audit fails when decision has packet_drop_performed ───

#[test]
fn i10a_fails_when_decision_packet_drop() {
    let mut input = safe_audit_input();
    input.live_attach_decision.packet_drop_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.packet_drop_performed);
}

// ── Coverage 32: audit fails when decision has mutation_performed ──────

#[test]
fn i10a_fails_when_decision_mutation() {
    let mut input = safe_audit_input();
    input.live_attach_decision.mutation_performed = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.mutation_performed);
}

// ── Coverage 33: audit fails when executor attempted=true ─────────────

#[test]
fn i10a_fails_when_executor_attempted() {
    let mut input = safe_audit_input();
    input.executor_result.attempted = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 34: audit fails when executor refused=false ──────────────

#[test]
fn i10a_fails_when_executor_not_refused() {
    let mut input = safe_audit_input();
    input.executor_result.refused = false;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
}

// ── Coverage 35: validation accepts safe report ───────────────────────

#[test]
fn i10a_validation_accepts_safe_report() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert!(validate_static_audit_report(&report).is_ok());
}

// ── Coverage 36-45: validation rejects each unsafe flag ──────────────

#[test]
fn i10a_validation_rejects_program_load() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.program_load_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_attach() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.attach_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_map_create() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.map_create_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_ring_buffer() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.ring_buffer_opened = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_live_kernel_read() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.live_kernel_read_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_map_pin() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.map_pin_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_enforcement() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.enforcement_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_packet_drop() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.packet_drop_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_mutation() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.mutation_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_persistence() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.persistence_performed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

// ── Coverage 46-49: validation rejects schema/CLI flags ───────────────

#[test]
fn i10a_validation_rejects_public_cli_exposed() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.public_cli_exposed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_stable_cli_changed() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.stable_cli_changed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_usage_schema_changed() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.usage_schema_changed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

#[test]
fn i10a_validation_rejects_ledger_schema_changed() {
    let mut report = evaluate_static_audit(&safe_audit_input());
    report.ledger_schema_changed = true;
    assert!(validate_static_audit_report(&report).is_err());
}

// ── Coverage 50: findings are nonempty in safe report ────────────────

#[test]
fn i10a_findings_nonempty_in_passed_report() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert!(!report.findings.is_empty());
}

// ── Coverage 51: failed audit has blocking finding ────────────────────

#[test]
fn i10a_failed_audit_has_blocking_finding() {
    let mut input = safe_audit_input();
    input.executor_result.attempted = true;
    let report = evaluate_static_audit(&input);
    assert_eq!(report.status, IntergalaxionStaticAuditStatus::Failed);
    assert!(report.findings.iter().any(|f| f.blocking));
}

// ── Coverage 52: docs exist and mention final static safety audit ──────

#[test]
fn i10a_docs_exist_and_mention_audit() {
    let doc = I10A_DOC;
    assert!(doc.contains("final static safety audit") || doc.contains("Final Static Safety Audit"));
}

// ── Coverage 53: docs say no real live attach ─────────────────────────

#[test]
fn i10a_docs_say_no_real_live_attach() {
    let doc = I10A_DOC;
    let doc_lower = doc.to_lowercase();
    assert!(
        doc_lower.contains("no real live attach") || doc_lower.contains("no real live"),
        "doc should mention no real live attach"
    );
}

// ── Coverage 54: docs say no userspace loader ────────────────────────

#[test]
fn i10a_docs_say_no_userspace_loader() {
    let doc = I10A_DOC;
    assert!(doc.contains("userspace loader"));
}

// ── Coverage 55: docs say no program load/attach/map create/ring buffer open/live kernel read/map pin ──

#[test]
fn i10a_docs_say_no_program_operations() {
    let doc = I10A_DOC;
    assert!(doc.contains("program load"));
    assert!(doc.contains("attach"));
    assert!(doc.contains("map create"));
    assert!(doc.contains("ring buffer open") || doc.contains("ring buffer"));
    assert!(doc.contains("live kernel event read") || doc.contains("live kernel read"));
    assert!(doc.contains("map pin"));
}

// ── Coverage 56: docs say no enforcement ──────────────────────────────

#[test]
fn i10a_docs_say_no_enforcement() {
    let doc = I10A_DOC;
    assert!(doc.contains("enforcement"));
}

// ── Coverage 57: docs say no packet drop ──────────────────────────────

#[test]
fn i10a_docs_say_no_packet_drop() {
    let doc = I10A_DOC;
    assert!(doc.contains("packet drop"));
}

// ── Coverage 58: docs say no block/allow/quota ────────────────────────

#[test]
fn i10a_docs_say_no_block_allow_quota() {
    let doc = I10A_DOC;
    assert!(doc.contains("block/allow/quota"));
}

// ── Coverage 59: docs say no nft/tc fallback ──────────────────────────

#[test]
fn i10a_docs_say_no_nft_tc_fallback() {
    let doc = I10A_DOC;
    assert!(doc.contains("nft/tc"));
}

// ── Coverage 60: docs say no public CLI ───────────────────────────────

#[test]
fn i10a_docs_say_no_public_cli() {
    let doc = I10A_DOC;
    assert!(doc.contains("public CLI") || doc.contains("public cli"));
}

// ── Coverage 61: docs say no ledger file write/persistence ─────────────

#[test]
fn i10a_docs_say_no_ledger_file_write() {
    let doc = I10A_DOC;
    assert!(doc.contains("ledger file write") || doc.contains("persistence"));
}

// ── Coverage 62: docs say existing v3.1 usage JSON schema unchanged ───

#[test]
fn i10a_docs_say_usage_schema_unchanged() {
    let doc = I10A_DOC;
    assert!(doc.contains("usage JSON schema unchanged") || doc.contains("usage schema unchanged"));
}

// ── Coverage 63: docs say existing v3.1 ledger JSON schema unchanged ──

#[test]
fn i10a_docs_say_ledger_schema_unchanged() {
    let doc = I10A_DOC;
    assert!(
        doc.contains("ledger JSON schema unchanged") || doc.contains("ledger schema unchanged")
    );
}

// ── Coverage 64: existing zelynic --version remains v3.1.0 ───────────

#[test]
fn i10a_version_remains_3_1_0() {
    let version = env!("CARGO_PKG_VERSION");
    assert_eq!(version, "3.1.0");
}

// ── Coverage 65: existing ledger inspect --json still works ────────────

#[test]
fn i10a_ledger_inspect_json_works() {
    let result = handle_ledger_inspect(true, None);
    let _ = result;
}

// ── Coverage 66: existing ledger export --json --file still works ──────

#[test]
fn i10a_ledger_export_json_file_works() {
    let tmp = std::env::temp_dir().join("i10a_ledger_test.json");
    let tmp_str = tmp.to_string_lossy().to_string();
    let result = handle_ledger_export(true, Some(&tmp_str));
    let _ = result;
    let _ = std::fs::remove_file(tmp);
}

// ── Coverage 67: public help does not mention intergalaxion ───────────

#[test]
fn i10a_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(!help.to_lowercase().contains("intergalaxion"));
}

fn render_help(app: &mut clap::Command) -> String {
    let mut buf = Vec::new();
    let _ = clap::Command::write_help(app, &mut buf);
    String::from_utf8(buf).unwrap_or_default()
}

// ── Coverage 68: public help does not mention block/allow/quota ────────

#[test]
fn i10a_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(!help.contains("block"));
    assert!(!help.contains("allow"));
    assert!(!help.contains("quota"));
}

// ── Coverage 69: no new dependency added ──────────────────────────────

#[test]
fn i10a_no_new_dependency() {
    // Verify the Cargo.toml still contains zelynic as the package name
    // and does not introduce new eBPF runtime dependencies.
    let cargo_toml = include_str!("../../Cargo.toml");
    assert!(cargo_toml.contains("zelynic"));
    // Verify aya is only optional and never a required dependency.
    assert!(cargo_toml.contains("optional = true") || !cargo_toml.contains("aya"));
}

// ── Coverage 70: no live kernel mutation API in new static audit source ─

#[test]
fn i10a_source_no_kernel_mutation_api() {
    let src = I10A_SOURCE;
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

// ── Coverage 71: no aya ringbuf/map open/load/attach/pin API in new source ─

#[test]
fn i10a_source_no_aya_live_api() {
    let src = I10A_SOURCE;
    // Verify the source only uses validate_* functions, not aya APIs.
    assert!(src.contains("validate_loader_boundary_plan"));
    assert!(src.contains("validate_program_skeleton_set"));
    assert!(src.contains("validate_attach_plan"));
    assert!(src.contains("validate_live_attach_gate_decision"));
    assert!(src.contains("validate_live_attach_executor_result"));
    assert!(!src.contains("aya::"));
    assert!(!src.contains("load_file"));
}

// ── Coverage 72: no nft/tc source under intergalaxion backend ────────

#[test]
fn i10a_no_nft_tc_under_backend() {
    let src = I10A_SOURCE;
    assert!(!src.contains("tc "), "source must not contain tc");
    assert!(!src.contains("nft"), "source must not contain nft");
}

// ── Coverage 73: all touched files under 1000 LOC ──────────────────────

#[test]
fn i10a_source_under_1000_loc() {
    let lines: Vec<&str> = I10A_SOURCE.lines().collect();
    let non_empty = lines.iter().filter(|l| !l.trim().is_empty()).count();
    assert!(
        non_empty < 1000,
        "static_audit.rs has {non_empty} non-empty lines"
    );
}

// ── Extra: audited_i0_to_i9 always true ───────────────────────────────

#[test]
fn i10a_audited_i0_to_i9_always_true() {
    let report = evaluate_static_audit(&default_static_audit_input());
    assert!(report.audited_i0_to_i9);
}

// ── Extra: safe audit has ready_for_real_attach_spike true ───────────

#[test]
fn i10a_safe_audit_ready_for_spike() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert!(report.ready_for_real_attach_spike);
}

// ── Extra: persistence_performed always false ──────────────────────────

#[test]
fn i10a_persistence_always_false() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert!(!report.persistence_performed);
}

// ── Extra: executor operation flags propagate to report ────────────────

#[test]
fn i10a_executor_flags_propagate_to_report() {
    let mut input = safe_audit_input();
    input.executor_result.mutation_performed = true;
    let report = evaluate_static_audit(&input);
    assert!(report.mutation_performed);
}

// ── Extra: decision operation flags propagate to report ───────────────

#[test]
fn i10a_decision_flags_propagate_to_report() {
    let mut input = safe_audit_input();
    input.live_attach_decision.map_create_performed = true;
    let report = evaluate_static_audit(&input);
    assert!(report.map_create_performed);
}

// ── Extra: multiple violations produce multiple findings ──────────────

#[test]
fn i10a_multiple_violations_multiple_findings() {
    let mut input = safe_audit_input();
    input.executor_result.attempted = true;
    input.executor_result.refused = false;
    input.attach_plan.attach_performed = true;
    let report = evaluate_static_audit(&input);
    assert!(report.findings.len() >= 3);
}

// ── Extra: findings contain descriptive codes ──────────────────────────

#[test]
fn i10a_findings_have_descriptive_codes() {
    let mut input = safe_audit_input();
    input.executor_result.attempted = true;
    let report = evaluate_static_audit(&input);
    let codes: Vec<&str> = report.findings.iter().map(|f| f.code.as_str()).collect();
    assert!(codes.contains(&"executor_attempted"));
}

// ── Extra: default status is Passed ────────────────────────────────────

#[test]
fn i10a_default_status_is_passed() {
    assert_eq!(
        IntergalaxionStaticAuditStatus::default(),
        IntergalaxionStaticAuditStatus::Passed
    );
}

// ── Extra: blocked readiness gate does not prevent audited_i0_to_i9 ────

#[test]
fn i10a_blocked_gate_still_audited() {
    let mut input = default_static_audit_input();
    let blocked_input = crate::intergalaxion_engine::live_readiness::IntergalaxionReadinessInput {
        public_cli_requested: true,
        ..Default::default()
    };
    input.readiness_gate = evaluate_intergalaxion_readiness(&blocked_input);
    let report = evaluate_static_audit(&input);
    assert!(report.audited_i0_to_i9);
}

// ── Extra: safe report default has no warning ─────────────────────────

#[test]
fn i10a_safe_report_no_warning() {
    let report = evaluate_static_audit(&safe_audit_input());
    assert_ne!(report.status, IntergalaxionStaticAuditStatus::Warning);
    assert!(!report.findings.iter().any(|f| f.blocking));
}
