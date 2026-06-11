// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Phase I-10F tests: manual lab result capture and validation.

use crate::cli::Cli;
use crate::commands::ledger::{handle_ledger_export, handle_ledger_inspect};
use crate::intergalaxion_engine::backends::ebpf::live_attach_executor::default_live_attach_lab_input;
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab::{
    default_live_attach_lab_execution_input, safe_base_result_internal, EbpfLiveAttachLabStatus,
};
use crate::intergalaxion_engine::backends::ebpf::live_attach_lab_result::*;
use clap::CommandFactory;

const I10F_DOC: &str =
    include_str!("../../docs/intergalaxion/I-10F-local-live-attach-manual-lab-result-capture.md");
const I10F_SOURCE: &str = include_str!("backends/ebpf/live_attach_lab_result.rs");
const CARGO_TOML: &str = include_str!("../../Cargo.toml");

// ── Helper: build a default lab input with feature enabled ────────────

fn safe_lab_input(
) -> crate::intergalaxion_engine::backends::ebpf::live_attach_executor::EbpfLiveAttachLabInput {
    let lab_input = default_live_attach_lab_input();
    crate::intergalaxion_engine::backends::ebpf::live_attach_executor::EbpfLiveAttachLabInput {
        explicit_local_lab_feature_enabled: true,
        explicit_operator_label: String::from("i10f-test-operator"),
        explicit_detach_required: true,
        allow_live_attempt: true,
        ..lab_input
    }
}

fn safe_execution_input(
) -> crate::intergalaxion_engine::backends::ebpf::live_attach_lab::EbpfLiveAttachLabExecutionInput {
    let lab_input = safe_lab_input();
    crate::intergalaxion_engine::backends::ebpf::live_attach_lab::EbpfLiveAttachLabExecutionInput {
        lab_input,
        ..default_live_attach_lab_execution_input()
    }
}

// ── 1. Default capture phase is I-10F ─────────────────────────────────

#[test]
fn i10f_default_capture_phase_is_i10f() {
    let c = default_manual_lab_capture();
    assert_eq!(c.phase, "I-10F");
}

// ── 2. Default capture is local lab only ──────────────────────────────

#[test]
fn i10f_default_capture_is_local_lab_only() {
    let c = default_manual_lab_capture();
    assert!(c.local_lab_only);
}

// ── 3. Default capture status is NotRun ────────────────────────────────

#[test]
fn i10f_default_capture_status_is_not_run() {
    let c = default_manual_lab_capture();
    assert_eq!(c.manual_status, EbpfLiveAttachManualResultStatus::NotRun);
}

// ── 4. Default capture has all safety flags false ──────────────────────

#[test]
fn i10f_default_capture_all_safety_flags_false() {
    let c = default_manual_lab_capture();
    assert!(!c.public_cli_exposed);
    assert!(!c.ring_buffer_opened);
    assert!(!c.live_event_stream_read);
    assert!(!c.map_pin_performed);
    assert!(!c.enforcement_performed);
    assert!(!c.packet_drop_performed);
    assert!(!c.mutation_performed);
    assert!(!c.persistence_performed);
    assert!(!c.attach_attempted);
    assert!(!c.attach_succeeded);
    assert!(!c.detach_attempted);
    assert!(!c.detached_cleanly);
}

// ── 5-7. Status/evidence/recommendation labels are stable ──────────────

#[test]
fn i10f_status_labels_are_stable() {
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::NotRun),
        "not_run"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::FeatureDisabled),
        "feature_disabled"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::ArtifactMissing),
        "artifact_missing"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::UnsupportedTarget),
        "unsupported_target"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::GateRejected),
        "gate_rejected"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::AttachNotImplemented),
        "attach_not_implemented"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::AttachAttempted),
        "attach_attempted"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::AttachSucceeded),
        "attach_succeeded"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::AttachFailed),
        "attach_failed"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::DetachAttempted),
        "detach_attempted"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::DetachedCleanly),
        "detached_cleanly"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::DetachFailed),
        "detach_failed"
    );
    assert_eq!(
        manual_result_status_label(EbpfLiveAttachManualResultStatus::InvalidCapture),
        "invalid_capture"
    );
}

#[test]
fn i10f_evidence_level_labels_are_stable() {
    assert_eq!(
        manual_evidence_level_label(EbpfLiveAttachManualEvidenceLevel::None),
        "none"
    );
    assert_eq!(
        manual_evidence_level_label(EbpfLiveAttachManualEvidenceLevel::OperatorReported),
        "operator_reported"
    );
    assert_eq!(
        manual_evidence_level_label(EbpfLiveAttachManualEvidenceLevel::CommandOutputCaptured),
        "command_output_captured"
    );
    assert_eq!(
        manual_evidence_level_label(EbpfLiveAttachManualEvidenceLevel::DetachProofCaptured),
        "detach_proof_captured"
    );
    assert_eq!(
        manual_evidence_level_label(EbpfLiveAttachManualEvidenceLevel::AuditReady),
        "audit_ready"
    );
}

#[test]
fn i10f_recommendation_labels_are_stable() {
    assert_eq!(
        manual_recommendation_label(EbpfLiveAttachManualRecommendation::Stop),
        "stop"
    );
    assert_eq!(
        manual_recommendation_label(EbpfLiveAttachManualRecommendation::FixArtifact),
        "fix_artifact"
    );
    assert_eq!(
        manual_recommendation_label(EbpfLiveAttachManualRecommendation::FixGate),
        "fix_gate"
    );
    assert_eq!(
        manual_recommendation_label(EbpfLiveAttachManualRecommendation::RetryLocalLab),
        "retry_local_lab"
    );
    assert_eq!(
        manual_recommendation_label(EbpfLiveAttachManualRecommendation::CaptureDetachProof),
        "capture_detach_proof"
    );
    assert_eq!(
        manual_recommendation_label(
            EbpfLiveAttachManualRecommendation::ReadyForEventStreamPlanning
        ),
        "ready_for_event_stream_planning"
    );
}

// ── 8-12. Capture from lab result preserves correct status ─────────────

#[test]
fn i10f_capture_from_feature_disabled() {
    let result = safe_base_result_internal();
    let c = capture_manual_lab_result(result, "op-1", "test cmd");
    assert_eq!(
        c.manual_status,
        EbpfLiveAttachManualResultStatus::FeatureDisabled
    );
    assert_eq!(c.operator_label, "op-1");
    assert_eq!(c.command_summary, "test cmd");
}

#[test]
fn i10f_capture_from_artifact_missing() {
    let mut result = safe_base_result_internal();
    result.status = EbpfLiveAttachLabStatus::ArtifactMissing;
    let c = capture_manual_lab_result(result, "op-2", "missing");
    assert_eq!(
        c.manual_status,
        EbpfLiveAttachManualResultStatus::ArtifactMissing
    );
    assert_eq!(
        c.recommendation,
        EbpfLiveAttachManualRecommendation::FixArtifact
    );
}

#[test]
fn i10f_capture_from_unsupported_target() {
    let mut result = safe_base_result_internal();
    result.status = EbpfLiveAttachLabStatus::UnsupportedTarget;
    let c = capture_manual_lab_result(result, "op-3", "unsupported");
    assert_eq!(
        c.manual_status,
        EbpfLiveAttachManualResultStatus::UnsupportedTarget
    );
}

#[test]
fn i10f_capture_from_gate_rejected() {
    let mut result = safe_base_result_internal();
    result.status = EbpfLiveAttachLabStatus::LabGateRejected;
    let c = capture_manual_lab_result(result, "op-4", "rejected");
    assert_eq!(
        c.manual_status,
        EbpfLiveAttachManualResultStatus::GateRejected
    );
    assert_eq!(
        c.recommendation,
        EbpfLiveAttachManualRecommendation::FixGate
    );
}

#[test]
fn i10f_capture_from_attach_not_implemented() {
    let mut result = safe_base_result_internal();
    result.status = EbpfLiveAttachLabStatus::AttachNotImplemented;
    let c = capture_manual_lab_result(result, "op-5", "not impl");
    assert_eq!(
        c.manual_status,
        EbpfLiveAttachManualResultStatus::AttachNotImplemented
    );
}

// ── 13-14. Capture preserves operator label and command summary ─────────

#[test]
fn i10f_capture_preserves_operator_label() {
    let result = safe_base_result_internal();
    let c = capture_manual_lab_result(result, "operator-xyz", "some command");
    assert_eq!(c.operator_label, "operator-xyz");
}

#[test]
fn i10f_capture_preserves_command_summary() {
    let result = safe_base_result_internal();
    let c = capture_manual_lab_result(result, "op", "special-command-output");
    assert_eq!(c.command_summary, "special-command-output");
}

// ── 15-16. Capture rejects empty capture_id and phase ──────────────────

#[test]
fn i10f_validate_rejects_empty_capture_id() {
    let mut c = default_manual_lab_capture();
    c.capture_id = String::new();
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_empty_phase() {
    let mut c = default_manual_lab_capture();
    c.phase = String::new();
    assert!(validate_manual_lab_capture(&c).is_err());
}

// ── 17. Capture rejects empty operator_label for non-NotRun ───────────

#[test]
fn i10f_validate_rejects_empty_operator_for_non_notrun() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::AttachFailed;
    c.operator_label = String::new();
    assert!(validate_manual_lab_capture(&c).is_err());
}

// ── 18. Capture rejects local_lab_only=false ───────────────────────────

#[test]
fn i10f_validate_rejects_local_lab_false() {
    let mut c = default_manual_lab_capture();
    c.local_lab_only = false;
    assert!(validate_manual_lab_capture(&c).is_err());
}

// ── 19-26. Capture rejects unsafe flags ────────────────────────────────

#[test]
fn i10f_validate_rejects_public_cli_exposed() {
    let mut c = default_manual_lab_capture();
    c.public_cli_exposed = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_ring_buffer_opened() {
    let mut c = default_manual_lab_capture();
    c.ring_buffer_opened = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_live_event_stream_read() {
    let mut c = default_manual_lab_capture();
    c.live_event_stream_read = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_map_pin_performed() {
    let mut c = default_manual_lab_capture();
    c.map_pin_performed = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_enforcement_performed() {
    let mut c = default_manual_lab_capture();
    c.enforcement_performed = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_packet_drop_performed() {
    let mut c = default_manual_lab_capture();
    c.packet_drop_performed = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_mutation_performed() {
    let mut c = default_manual_lab_capture();
    c.mutation_performed = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_persistence_performed() {
    let mut c = default_manual_lab_capture();
    c.persistence_performed = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

// ── 27-28. AttachSucceeded consistency checks ────────────────────────

#[test]
fn i10f_validate_rejects_attach_success_without_attempt() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::AttachSucceeded;
    c.attach_attempted = false;
    c.attach_succeeded = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_attach_success_without_success_flag() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::AttachSucceeded;
    c.attach_attempted = true;
    c.attach_succeeded = false;
    assert!(validate_manual_lab_capture(&c).is_err());
}

// ── 29-31. DetachedCleanly consistency checks ─────────────────────────

#[test]
fn i10f_validate_rejects_detached_cleanly_without_attach_success() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachedCleanly;
    c.attach_succeeded = false;
    c.detach_attempted = true;
    c.detached_cleanly = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_detached_cleanly_without_detach_attempt() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachedCleanly;
    c.attach_succeeded = true;
    c.detach_attempted = false;
    c.detached_cleanly = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_validate_rejects_detached_cleanly_without_clean_flag() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachedCleanly;
    c.attach_succeeded = true;
    c.detach_attempted = true;
    c.detached_cleanly = false;
    assert!(validate_manual_lab_capture(&c).is_err());
}

// ── 32-34. Accepts honest failure and clean states ────────────────────

#[test]
fn i10f_validate_accepts_honest_attach_failed() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::AttachFailed;
    c.operator_label = String::from("op-fail");
    assert!(validate_manual_lab_capture(&c).is_ok());
}

#[test]
fn i10f_validate_accepts_honest_detach_failed() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachFailed;
    c.operator_label = String::from("op-dfail");
    assert!(validate_manual_lab_capture(&c).is_ok());
}

#[test]
fn i10f_validate_accepts_honest_detached_cleanly() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachedCleanly;
    c.operator_label = String::from("op-clean");
    c.attach_succeeded = true;
    c.detach_attempted = true;
    c.detached_cleanly = true;
    assert!(validate_manual_lab_capture(&c).is_ok());
}

// ── 35-36. ReadyForEventStreamPlanning checks ───────────────────────────

#[test]
fn i10f_ready_requires_detached_cleanly() {
    let mut c = default_manual_lab_capture();
    c.recommendation = EbpfLiveAttachManualRecommendation::ReadyForEventStreamPlanning;
    c.detached_cleanly = false;
    assert!(validate_manual_lab_capture(&c).is_err());
}

#[test]
fn i10f_ready_rejects_unsafe_flags() {
    let mut c = default_manual_lab_capture();
    c.recommendation = EbpfLiveAttachManualRecommendation::ReadyForEventStreamPlanning;
    c.detached_cleanly = true;
    c.ring_buffer_opened = true;
    assert!(validate_manual_lab_capture(&c).is_err());
}

// ── 37-43. Summary counts ─────────────────────────────────────────────

#[test]
fn i10f_summary_is_deterministic() {
    let caps = vec![default_manual_lab_capture()];
    let s1 = summarize_manual_lab_captures(&caps);
    let s2 = summarize_manual_lab_captures(&caps);
    assert_eq!(s1, s2);
}

#[test]
fn i10f_summary_counts_total() {
    let caps = vec![
        default_manual_lab_capture(),
        default_manual_lab_capture(),
        default_manual_lab_capture(),
    ];
    let s = summarize_manual_lab_captures(&caps);
    assert_eq!(s.total_captures, 3);
}

#[test]
fn i10f_summary_counts_successful_attach() {
    let mut c = default_manual_lab_capture();
    c.attach_succeeded = true;
    let s = summarize_manual_lab_captures(&[c]);
    assert_eq!(s.successful_attach_count, 1);
}

#[test]
fn i10f_summary_counts_clean_detach() {
    let mut c = default_manual_lab_capture();
    c.detached_cleanly = true;
    let s = summarize_manual_lab_captures(&[c]);
    assert_eq!(s.clean_detach_count, 1);
}

#[test]
fn i10f_summary_counts_failed_attach() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::AttachFailed;
    c.operator_label = String::from("op");
    let s = summarize_manual_lab_captures(&[c]);
    assert_eq!(s.failed_attach_count, 1);
}

#[test]
fn i10f_summary_counts_failed_detach() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachFailed;
    c.operator_label = String::from("op");
    let s = summarize_manual_lab_captures(&[c]);
    assert_eq!(s.failed_detach_count, 1);
}

#[test]
fn i10f_summary_counts_not_run() {
    let s = summarize_manual_lab_captures(&[default_manual_lab_capture()]);
    assert_eq!(s.not_run_count, 1);
}

// ── 44. Summary not ready when empty ──────────────────────────────────

#[test]
fn i10f_summary_not_ready_when_empty() {
    let s = summarize_manual_lab_captures(&[]);
    assert!(!s.ready_for_event_stream_planning);
}

// ── 45-46. Summary not ready for ArtifactMissing/AttachNotImplemented ─

#[test]
fn i10f_summary_not_ready_for_artifact_missing() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::ArtifactMissing;
    c.operator_label = String::from("op");
    let s = summarize_manual_lab_captures(&[c]);
    assert!(!s.ready_for_event_stream_planning);
}

#[test]
fn i10f_summary_not_ready_for_attach_not_implemented() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::AttachNotImplemented;
    c.operator_label = String::from("op");
    let s = summarize_manual_lab_captures(&[c]);
    assert!(!s.ready_for_event_stream_planning);
}

// ── 47. Summary ready only after clean detach ─────────────────────────

#[test]
fn i10f_summary_ready_after_clean_detach() {
    let mut c = default_manual_lab_capture();
    c.manual_status = EbpfLiveAttachManualResultStatus::DetachedCleanly;
    c.operator_label = String::from("op");
    c.attach_succeeded = true;
    c.detach_attempted = true;
    c.detached_cleanly = true;
    let s = summarize_manual_lab_captures(&[c]);
    assert!(s.ready_for_event_stream_planning);
    assert_eq!(
        s.recommendation,
        EbpfLiveAttachManualRecommendation::ReadyForEventStreamPlanning
    );
}

// ── 48-55. Summary rejects unsafe flags ────────────────────────────────

#[test]
fn i10f_summary_validate_rejects_public_cli() {
    let mut c = default_manual_lab_capture();
    c.public_cli_exposed = true;
    let mut s = summarize_manual_lab_captures(&[c]);
    s.public_cli_exposed = true;
    assert!(validate_manual_lab_summary(&s).is_err());
}

#[test]
fn i10f_summary_validate_rejects_ring_buffer() {
    let mut c = default_manual_lab_capture();
    c.ring_buffer_opened = true;
    let mut s = summarize_manual_lab_captures(&[c]);
    s.ring_buffer_opened = true;
    assert!(validate_manual_lab_summary(&s).is_err());
}

#[test]
fn i10f_summary_validate_rejects_event_stream() {
    let mut c = default_manual_lab_capture();
    c.live_event_stream_read = true;
    let mut s = summarize_manual_lab_captures(&[c]);
    s.live_event_stream_read = true;
    assert!(validate_manual_lab_summary(&s).is_err());
}

#[test]
fn i10f_summary_validate_rejects_map_pin() {
    let mut c = default_manual_lab_capture();
    c.map_pin_performed = true;
    let mut s = summarize_manual_lab_captures(&[c]);
    s.map_pin_performed = true;
    assert!(validate_manual_lab_summary(&s).is_err());
}

#[test]
fn i10f_summary_validate_rejects_enforcement() {
    let mut c = default_manual_lab_capture();
    c.enforcement_performed = true;
    let mut s = summarize_manual_lab_captures(&[c]);
    s.enforcement_performed = true;
    assert!(validate_manual_lab_summary(&s).is_err());
}

#[test]
fn i10f_summary_validate_rejects_packet_drop() {
    let mut c = default_manual_lab_capture();
    c.packet_drop_performed = true;
    let mut s = summarize_manual_lab_captures(&[c]);
    s.packet_drop_performed = true;
    assert!(validate_manual_lab_summary(&s).is_err());
}

#[test]
fn i10f_summary_validate_rejects_mutation() {
    let mut c = default_manual_lab_capture();
    c.mutation_performed = true;
    let mut s = summarize_manual_lab_captures(&[c]);
    s.mutation_performed = true;
    assert!(validate_manual_lab_summary(&s).is_err());
}

#[test]
fn i10f_summary_validate_rejects_persistence() {
    let mut c = default_manual_lab_capture();
    c.persistence_performed = true;
    let mut s = summarize_manual_lab_captures(&[c]);
    s.persistence_performed = true;
    assert!(validate_manual_lab_summary(&s).is_err());
}

// ── 56-71. Documentation checks ───────────────────────────────────────

#[test]
fn i10f_docs_exist_and_mention_manual_lab_result_capture() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("manual lab result capture"),
        "doc must mention manual lab result capture"
    );
}

#[test]
fn i10f_docs_say_no_public_cli() {
    let doc = I10F_DOC.to_lowercase();
    assert!(doc.contains("no public cli"), "doc must say no public CLI");
}

#[test]
fn i10f_docs_say_no_normal_ci_live_attach() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no normal ci live attach"),
        "doc must say no normal CI live attach"
    );
}

#[test]
fn i10f_docs_say_no_automatic_live_attach_detach() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no automatic live attach") || doc.contains("no automatic detach"),
        "doc must say no automatic live attach/detach"
    );
}

#[test]
fn i10f_docs_say_no_ring_buffer_open() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no ring buffer open"),
        "doc must say no ring buffer open"
    );
}

#[test]
fn i10f_docs_say_no_live_kernel_event_read() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no live kernel event read"),
        "doc must say no live kernel event read"
    );
}

#[test]
fn i10f_docs_say_no_map_pin() {
    let doc = I10F_DOC.to_lowercase();
    assert!(doc.contains("no map pin"), "doc must say no map pin");
}

#[test]
fn i10f_docs_say_no_enforcement() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no enforcement"),
        "doc must say no enforcement"
    );
}

#[test]
fn i10f_docs_say_no_packet_drop() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no packet drop"),
        "doc must say no packet drop"
    );
}

#[test]
fn i10f_docs_say_no_block_allow_quota() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no block/allow/quota"),
        "doc must say no block/allow/quota"
    );
}

#[test]
fn i10f_docs_say_no_nft_tc_fallback() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no nft/tc fallback") || doc.contains("no nft/tc backend"),
        "doc must say no nft/tc fallback"
    );
}

#[test]
fn i10f_docs_say_no_ledger_file_write_persistence() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no ledger file write") || doc.contains("no persistence"),
        "doc must say no ledger file write/persistence"
    );
}

#[test]
fn i10f_docs_say_usage_json_unchanged() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("usage json schema unchanged"),
        "doc must say usage JSON schema unchanged"
    );
}

#[test]
fn i10f_docs_say_ledger_json_unchanged() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("ledger json schema unchanged"),
        "doc must say ledger JSON schema unchanged"
    );
}

#[test]
fn i10f_docs_say_no_fake_attach_success() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no fake attach success") || doc.contains("not fake attach success"),
        "doc must say no fake attach success"
    );
}

#[test]
fn i10f_docs_say_no_fake_detach_success() {
    let doc = I10F_DOC.to_lowercase();
    assert!(
        doc.contains("no fake detach success") || doc.contains("not fake detach success"),
        "doc must say no fake detach success"
    );
}

// ── 72-76. Runtime stability checks ───────────────────────────────────

#[test]
fn i10f_version_remains_v3_1_0() {
    assert!(
        CARGO_TOML.contains("version = \"3.1.0\""),
        "version must remain v3.1.0"
    );
}

#[test]
fn i10f_ledger_inspect_still_works() {
    let _ = handle_ledger_inspect(true, None);
}

#[test]
fn i10f_ledger_export_still_works() {
    let path = std::env::temp_dir().join("i10f-test-ledger.json");
    let path_str = path.to_string_lossy();
    let _ = handle_ledger_export(true, Some(path_str.as_ref()));
    let _ = std::fs::remove_file(path);
}

#[test]
fn i10f_public_help_no_intergalaxion() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    assert!(
        !help.to_lowercase().contains("intergalaxion"),
        "public help must not mention intergalaxion"
    );
}

#[test]
fn i10f_public_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let help = render_help(&mut app);
    let h = help.to_lowercase();
    assert!(!h.contains("block"), "public help must not mention block");
    assert!(!h.contains("allow"), "public help must not mention allow");
    assert!(!h.contains("quota"), "public help must not mention quota");
}

// ── 77-79. Dependency and LOC checks ──────────────────────────────────

#[test]
fn i10f_no_new_dependency_added() {
    let cargo = CARGO_TOML;
    // Check aya is still optional and not a new mandatory dep
    assert!(
        cargo.contains("name = \"zelynic\""),
        "Cargo.toml must contain zelynic"
    );
}

#[test]
fn i10f_no_nft_tc_source_under_intergalaxion() {
    let source = I10F_SOURCE.to_lowercase();
    // Forbidden patterns from spec
    assert!(!source.contains("nft"), "I-10F source must not contain nft");
    assert!(!source.contains("tc "), "I-10F source must not contain tc");
    // Check more forbidden patterns
    let forbidden = [
        "Bpf::load",
        "load_file",
        "program_mut",
        ".attach(",
        "RingBuf",
        "AsyncPerfEventArray",
        "PerfEventArray",
        "MapData",
        "create_map",
        "pin(",
        "bpf_prog_load",
        "bpf_map_create",
        "bpf_ringbuf",
        "/sys/fs/bpf",
        "/sys/kernel",
        "/proc/",
        "drop_packet",
        "File::create",
        "fs::write",
        "OpenOptions",
    ];
    for pattern in &forbidden {
        assert!(
            !source.contains(&pattern.to_lowercase()),
            "I-10F source must not contain {}",
            pattern
        );
    }
}

#[test]
fn i10f_source_under_1000_loc() {
    let lines = I10F_SOURCE.lines().count();
    assert!(
        lines <= 1000,
        "I-10F source must be under 1000 LOC, got {}",
        lines
    );
}

// ── Helper: render help text ───────────────────────────────────────────

fn render_help(app: &mut clap::Command) -> String {
    let mut buf = Vec::new();
    let _ = app.write_help(&mut buf);
    String::from_utf8_lossy(&buf).to_string()
}
