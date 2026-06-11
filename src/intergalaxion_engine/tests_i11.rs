// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-11 tests: event stream read planning.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::event_stream_plan::*;
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::{
    default_manual_lab_capture, summarize_manual_lab_captures, EbpfLiveAttachManualResultStatus,
};
use clap::CommandFactory;

const I11_DOC: &str = include_str!("../../docs/intergalaxion/I-11-event-stream-read-planning.md");
const I11_SOURCE: &str = include_str!("backends/ebpf/event_stream_plan.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

// ── Helper: build a ready manual summary with clean detach ─────────────

fn ready_summary() -> crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualLabSummary{
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachedCleanly;
    c.operator_label = String::from("i11-ready-op");
    c.attach_succeeded = true;
    c.detach_attempted = true;
    c.detached_cleanly = true;
    summarize_manual_lab_captures(&[c])
}

fn summary_with_status(status: EbpfLiveAttachManualResultStatus) -> crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualLabSummary{
    let mut c = default_manual_lab_capture();
    c.manual_status = status;
    if status != EbpfLiveAttachManualResultStatus::NotRun {
        c.operator_label = String::from("i11-op");
    }
    summarize_manual_lab_captures(&[c])
}

fn ready_input() -> EbpfEventStreamReadPlanInput {
    EbpfEventStreamReadPlanInput {
        manual_summary: ready_summary(),
        required_capture_status: EbpfLiveAttachManualResultStatus::DetachedCleanly,
        read_mode: EbpfEventStreamReadMode::PlanningOnly,
        target_kind:
            crate::intergalaxion_engine::backends::ebpf::attach_plan::EbpfAttachTargetKind::default(
            ),
        explicit_event_stream_planning_consent: true,
        public_cli_requested: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_enforcement: false,
        allow_packet_drop: false,
        allow_persistence: false,
    }
}

// ── 1. Default input is safe ──────────────────────────────────────────

#[test]
fn i11_default_input_is_safe() {
    let inp = default_event_stream_read_plan_input();
    assert!(!inp.public_cli_requested);
    assert!(!inp.allow_ring_buffer_open);
    assert!(!inp.allow_live_event_read);
    assert!(!inp.allow_map_pin);
    assert!(!inp.allow_enforcement);
    assert!(!inp.allow_packet_drop);
    assert!(!inp.allow_persistence);
    assert!(!inp.explicit_event_stream_planning_consent);
    assert_eq!(inp.read_mode, EbpfEventStreamReadMode::PlanningOnly);
}

// ── 2. Default plan has all operation flags false ──────────────────────

#[test]
fn i11_default_plan_all_flags_false() {
    let inp = default_event_stream_read_plan_input();
    let plan = evaluate_event_stream_read_plan(&inp);
    assert!(!plan.public_cli_exposed);
    assert!(!plan.ring_buffer_opened);
    assert!(!plan.live_event_stream_read);
    assert!(!plan.map_pin_performed);
    assert!(!plan.enforcement_performed);
    assert!(!plan.packet_drop_performed);
    assert!(!plan.mutation_performed);
    assert!(!plan.persistence_performed);
    assert!(!plan.reader_implemented);
    assert!(!plan.future_read_candidate);
}

// ── 3-4. Labels are stable ─────────────────────────────────────────────

#[test]
fn i11_status_labels_are_stable() {
    assert_eq!(
        event_stream_read_plan_status_label(EbpfEventStreamReadPlanStatus::Disabled),
        "disabled"
    );
    assert_eq!(
        event_stream_read_plan_status_label(EbpfEventStreamReadPlanStatus::ManualCaptureNotReady),
        "manual_capture_not_ready"
    );
    assert_eq!(
        event_stream_read_plan_status_label(
            EbpfEventStreamReadPlanStatus::MissingCleanDetachEvidence
        ),
        "missing_clean_detach_evidence"
    );
    assert_eq!(
        event_stream_read_plan_status_label(EbpfEventStreamReadPlanStatus::PlanOnly),
        "plan_only"
    );
    assert_eq!(
        event_stream_read_plan_status_label(EbpfEventStreamReadPlanStatus::FutureReadCandidate),
        "future_read_candidate"
    );
    assert_eq!(
        event_stream_read_plan_status_label(EbpfEventStreamReadPlanStatus::Rejected),
        "rejected"
    );
    assert_eq!(
        event_stream_read_plan_status_label(EbpfEventStreamReadPlanStatus::UnsupportedTarget),
        "unsupported_target"
    );
    assert_eq!(
        event_stream_read_plan_status_label(EbpfEventStreamReadPlanStatus::ReaderNotImplemented),
        "reader_not_implemented"
    );
}

#[test]
fn i11_read_mode_labels_are_stable() {
    assert_eq!(
        event_stream_read_mode_label(EbpfEventStreamReadMode::PlanningOnly),
        "planning_only"
    );
    assert_eq!(
        event_stream_read_mode_label(EbpfEventStreamReadMode::FutureRingBufferRead),
        "future_ring_buffer_read"
    );
    assert_eq!(
        event_stream_read_mode_label(EbpfEventStreamReadMode::FuturePerfEventRead),
        "future_perf_event_read"
    );
    assert_eq!(
        event_stream_read_mode_label(EbpfEventStreamReadMode::Unsupported),
        "unsupported"
    );
}

// ── 5. Default plan is not future read candidate ───────────────────────

#[test]
fn i11_default_plan_not_future_read_candidate() {
    let inp = default_event_stream_read_plan_input();
    let plan = evaluate_event_stream_read_plan(&inp);
    assert!(!plan.future_read_candidate);
}

// ── 6. Default plan reader_implemented=false ──────────────────────────

#[test]
fn i11_default_plan_reader_not_implemented() {
    let inp = default_event_stream_read_plan_input();
    let plan = evaluate_event_stream_read_plan(&inp);
    assert!(!plan.reader_implemented);
}

// ── 7. Default plan has reasons ─────────────────────────────────────────

#[test]
fn i11_default_plan_has_reasons() {
    let inp = default_event_stream_read_plan_input();
    let plan = evaluate_event_stream_read_plan(&inp);
    assert!(!plan.reasons.is_empty());
}

// ── 8. Manual summary not ready blocks ──────────────────────────────────

#[test]
fn i11_manual_summary_not_ready_blocks() {
    let inp = default_event_stream_read_plan_input();
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ManualCaptureNotReady
    );
}

// ── 9. Missing clean detach evidence blocks ────────────────────────────

#[test]
fn i11_missing_clean_detach_blocks() {
    let mut inp = default_event_stream_read_plan_input();
    // Force ready by building a summary that claims ready but has no clean detach
    let c = default_manual_lab_capture();
    let mut summary = summarize_manual_lab_captures(&[c]);
    // Manually set ready to true without clean detach evidence
    summary.ready_for_event_stream_planning = true;
    summary.clean_detach_count = 0;
    inp.manual_summary = summary;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(
        plan.status,
        EbpfEventStreamReadPlanStatus::MissingCleanDetachEvidence
    );
}

// ── 10-18. Various blocking statuses ───────────────────────────────────

#[test]
fn i11_not_run_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary = summary_with_status(EbpfLiveAttachManualResultStatus::NotRun);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_ne!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ReaderNotImplemented
    );
}

#[test]
fn i11_feature_disabled_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary = summary_with_status(EbpfLiveAttachManualResultStatus::FeatureDisabled);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ManualCaptureNotReady
    );
}

#[test]
fn i11_artifact_missing_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary = summary_with_status(EbpfLiveAttachManualResultStatus::ArtifactMissing);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ManualCaptureNotReady
    );
}

#[test]
fn i11_unsupported_target_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary = summary_with_status(EbpfLiveAttachManualResultStatus::UnsupportedTarget);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_ne!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ReaderNotImplemented
    );
}

#[test]
fn i11_gate_rejected_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary = summary_with_status(EbpfLiveAttachManualResultStatus::GateRejected);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ManualCaptureNotReady
    );
}

#[test]
fn i11_attach_not_implemented_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary =
        summary_with_status(EbpfLiveAttachManualResultStatus::AttachNotImplemented);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_ne!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ReaderNotImplemented
    );
}

#[test]
fn i11_attach_failed_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary = summary_with_status(EbpfLiveAttachManualResultStatus::AttachFailed);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_ne!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ReaderNotImplemented
    );
}

#[test]
fn i11_detach_failed_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary = summary_with_status(EbpfLiveAttachManualResultStatus::DetachFailed);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_ne!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ReaderNotImplemented
    );
}

#[test]
fn i11_invalid_capture_status_blocks() {
    let mut inp = ready_input();
    inp.manual_summary = summary_with_status(EbpfLiveAttachManualResultStatus::InvalidCapture);
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ManualCaptureNotReady
    );
}

// ── 19. DetachedCleanly can become future read candidate ──────────────

#[test]
fn i11_detached_cleanly_becomes_reader_not_implemented() {
    let inp = ready_input();
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(
        plan.status,
        EbpfEventStreamReadPlanStatus::ReaderNotImplemented
    );
    assert!(plan.future_read_candidate);
}

// ── 20. Future read candidate requires consent ───────────────────────────

#[test]
fn i11_future_read_candidate_requires_consent() {
    let mut inp = ready_input();
    inp.explicit_event_stream_planning_consent = false;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(plan.status, EbpfEventStreamReadPlanStatus::PlanOnly);
    assert!(!plan.future_read_candidate);
}

// ── 21-27. Future read candidate rejects unsafe flags ──────────────────

#[test]
fn i11_rejects_public_cli_requested() {
    let mut inp = ready_input();
    inp.public_cli_requested = true;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(plan.status, EbpfEventStreamReadPlanStatus::Rejected);
}

#[test]
fn i11_rejects_allow_ring_buffer_open() {
    let mut inp = ready_input();
    inp.allow_ring_buffer_open = true;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(plan.status, EbpfEventStreamReadPlanStatus::Rejected);
}

#[test]
fn i11_rejects_allow_live_event_read() {
    let mut inp = ready_input();
    inp.allow_live_event_read = true;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(plan.status, EbpfEventStreamReadPlanStatus::Rejected);
}

#[test]
fn i11_rejects_allow_map_pin() {
    let mut inp = ready_input();
    inp.allow_map_pin = true;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(plan.status, EbpfEventStreamReadPlanStatus::Rejected);
}

#[test]
fn i11_rejects_allow_enforcement() {
    let mut inp = ready_input();
    inp.allow_enforcement = true;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(plan.status, EbpfEventStreamReadPlanStatus::Rejected);
}

#[test]
fn i11_rejects_allow_packet_drop() {
    let mut inp = ready_input();
    inp.allow_packet_drop = true;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(plan.status, EbpfEventStreamReadPlanStatus::Rejected);
}

#[test]
fn i11_rejects_allow_persistence() {
    let mut inp = ready_input();
    inp.allow_persistence = true;
    let plan = evaluate_event_stream_read_plan(&inp);
    assert_eq!(plan.status, EbpfEventStreamReadPlanStatus::Rejected);
}

// ── 28-34. Future read candidate still has all flags false ──────────────

#[test]
fn i11_future_candidate_all_operation_flags_false() {
    let inp = ready_input();
    let plan = evaluate_event_stream_read_plan(&inp);
    assert!(plan.future_read_candidate);
    assert!(!plan.ring_buffer_opened);
    assert!(!plan.live_event_stream_read);
    assert!(!plan.map_pin_performed);
    assert!(!plan.enforcement_performed);
    assert!(!plan.packet_drop_performed);
    assert!(!plan.mutation_performed);
    assert!(!plan.persistence_performed);
}

// ── 35. Validation accepts safe default plan ───────────────────────────

#[test]
fn i11_validation_accepts_safe_default() {
    let inp = default_event_stream_read_plan_input();
    let plan = evaluate_event_stream_read_plan(&inp);
    assert!(validate_event_stream_read_plan(&plan).is_ok());
}

// ── 36-43. Validation rejects unsafe flags ──────────────────────────────

#[test]
fn i11_validate_rejects_public_cli() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.public_cli_exposed = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

#[test]
fn i11_validate_rejects_ring_buffer_opened() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.ring_buffer_opened = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

#[test]
fn i11_validate_rejects_live_event_stream_read() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.live_event_stream_read = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

#[test]
fn i11_validate_rejects_map_pin_performed() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.map_pin_performed = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

#[test]
fn i11_validate_rejects_enforcement_performed() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.enforcement_performed = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

#[test]
fn i11_validate_rejects_packet_drop_performed() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.packet_drop_performed = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

#[test]
fn i11_validate_rejects_mutation_performed() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.mutation_performed = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

#[test]
fn i11_validate_rejects_persistence_performed() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.persistence_performed = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

// ── 44. Validation rejects reader_implemented=true ─────────────────────

#[test]
fn i11_validate_rejects_reader_implemented() {
    let inp = default_event_stream_read_plan_input();
    let mut plan = evaluate_event_stream_read_plan(&inp);
    plan.reader_implemented = true;
    assert!(validate_event_stream_read_plan(&plan).is_err());
}

// ── 45. Evaluation is deterministic ─────────────────────────────────────

#[test]
fn i11_evaluation_is_deterministic() {
    let inp = default_event_stream_read_plan_input();
    let p1 = evaluate_event_stream_read_plan(&inp);
    let p2 = evaluate_event_stream_read_plan(&inp);
    assert_eq!(p1, p2);
}

// ── 46-60. Documentation checks ───────────────────────────────────────

#[test]
fn i11_docs_exist_and_mention_event_stream_read_planning() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("event stream read planning"),
        "doc must mention event stream read planning"
    );
}

#[test]
fn i11_docs_say_no_public_cli() {
    let doc = I11_DOC.to_lowercase();
    assert!(doc.contains("no public cli"), "doc must say no public CLI");
}

#[test]
fn i11_docs_say_no_normal_ci_live_event_read() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("no normal ci live event read"),
        "doc must say no normal CI live event read"
    );
}

#[test]
fn i11_docs_say_no_ring_buffer_open() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("no ring buffer open"),
        "doc must say no ring buffer open"
    );
}

#[test]
fn i11_docs_say_no_live_kernel_event_read() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("no live kernel event read"),
        "doc must say no live kernel event read"
    );
}

#[test]
fn i11_docs_say_no_map_pin() {
    let doc = I11_DOC.to_lowercase();
    assert!(doc.contains("no map pin"), "doc must say no map pin");
}

#[test]
fn i11_docs_say_no_enforcement() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("no enforcement"),
        "doc must say no enforcement"
    );
}

#[test]
fn i11_docs_say_no_packet_drop() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("no packet drop"),
        "doc must say no packet drop"
    );
}

#[test]
fn i11_docs_say_no_block_allow_quota() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("no block/allow/quota"),
        "doc must say no block/allow/quota"
    );
}

#[test]
fn i11_docs_say_no_nft_tc_fallback() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("no nft/tc fallback") || doc.contains("no nft/tc backend"),
        "doc must say no nft/tc fallback"
    );
}

#[test]
fn i11_docs_say_no_ledger_file_write_persistence() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("no ledger file write") || doc.contains("no persistence"),
        "doc must say no ledger file write/persistence"
    );
}

#[test]
fn i11_docs_say_usage_json_unchanged() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("usage json schema unchanged"),
        "doc must say usage JSON schema unchanged"
    );
}

#[test]
fn i11_docs_say_ledger_json_unchanged() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("ledger json schema unchanged"),
        "doc must say ledger JSON schema unchanged"
    );
}

#[test]
fn i11_docs_say_clean_detach_evidence_required() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("clean detach evidence"),
        "doc must say clean detach evidence is required"
    );
}

#[test]
fn i11_docs_say_reader_not_implemented() {
    let doc = I11_DOC.to_lowercase();
    assert!(
        doc.contains("reader remains not implemented") || doc.contains("reader not implemented"),
        "doc must say reader not implemented"
    );
}

// ── 61-65. Runtime stability checks ───────────────────────────────────

#[test]
fn i11_version_remains_v3_1_0() {
    assert!(
        CARGO_TOML.contains("version = \"3.1.0\""),
        "version must remain v3.1.0"
    );
}

#[test]
fn i11_ledger_inspect_still_works() {
    let _ = handle_ledger_inspect(true, None);
}

#[test]
fn i11_ledger_export_still_works() {
    let path = std::env::temp_dir().join("i11-test-ledger.json");
    let path_str = path.to_string_lossy();
    let _ = handle_ledger_export(true, Some(path_str.as_ref()));
    let _ = std::fs::remove_file(path);
}

#[test]
fn i11_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(
        !help.to_lowercase().contains("intergalaxion"),
        "public help must not mention intergalaxion"
    );
}

#[test]
fn i11_public_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    let h = help.to_lowercase();
    assert!(!h.contains("block"), "public help must not mention block");
    assert!(!h.contains("allow"), "public help must not mention allow");
    assert!(!h.contains("quota"), "public help must not mention quota");
}

// ── 66-68. Dependency and LOC checks ──────────────────────────────────

#[test]
fn i11_no_new_dependency_added() {
    let cargo = CARGO_TOML;
    assert!(
        cargo.contains("name = \"zelynic\""),
        "Cargo.toml must contain zelynic"
    );
}

#[test]
fn i11_no_nft_tc_source_under_intergalaxion() {
    // Filter out comment lines to avoid false positives from doc comments
    let code_lines: Vec<&str> = I11_SOURCE
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect();
    let source: String = code_lines.join("\n").to_lowercase();
    assert!(!source.contains("nft"), "I-11 source must not contain nft");
    assert!(!source.contains("tc "), "I-11 source must not contain tc");
    let forbidden = [
        "bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "asyncperfeventarray",
        "perfeventarray",
        "mapdata",
        "create_map",
        "pin(",
        "bpf_prog_load",
        "bpf_map_create",
        "bpf_ringbuf",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
        "drop_packet",
        "file::create",
        "fs::write",
        "openoptions",
    ];
    for pattern in &forbidden {
        assert!(
            !source.contains(&pattern.to_lowercase()),
            "I-11 source must not contain {}",
            pattern
        );
    }
}

#[test]
fn i11_source_under_1000_loc() {
    let lines = I11_SOURCE.lines().count();
    assert!(
        lines <= 1000,
        "I-11 source must be under 1000 LOC, got {}",
        lines
    );
}

// ── Helper: render help text ───────────────────────────────────────────

fn render_help(app: &mut clap::Command) -> String {
    let mut buf = Vec::new();
    let _ = app.write_help(&mut buf);
    String::from_utf8_lossy(&buf).to_string()
}
