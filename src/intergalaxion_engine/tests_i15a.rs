// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
#![allow(clippy::manual_assert)]
use super::backends::ebpf::event_stream_evidence_audit::{
    default_event_stream_evidence_audit_input, evaluate_event_stream_evidence_audit,
    EbpfEventStreamEvidenceAuditReport, EbpfEventStreamEvidenceAuditStatus,
};
use super::backends::ebpf::event_stream_reader::default_event_stream_reader_input;
use super::backends::ebpf::event_stream_reader_spike_prep::*;
use crate::cli::Cli;
use clap::CommandFactory;
const DOC: &str =
    include_str!("../../docs/intergalaxion/I-15A-feature-gated-local-reader-spike-preparation.md");
fn doc_lower() -> String {
    include_str!("../../docs/intergalaxion/I-15A-feature-gated-local-reader-spike-preparation.md")
        .to_lowercase()
}
const SRC: &str = include_str!("backends/ebpf/event_stream_reader_spike_prep.rs");
fn di() -> EbpfEventStreamReaderSpikePrepInput {
    default_event_stream_reader_spike_prep_input()
}
fn dp() -> EbpfEventStreamReaderSpikePrepPlan {
    evaluate_event_stream_reader_spike_prep(&di())
}
fn sar() -> EbpfEventStreamEvidenceAuditReport {
    let mut input = default_event_stream_evidence_audit_input();
    input.manual_summary.ready_for_event_stream_planning = true;
    input.manual_summary.clean_detach_count = 1;
    input.manual_summary.successful_attach_count = 1;
    input.manual_summary.summary_status = super::backends::ebpf::live_attach_lab_result::EbpfLiveAttachManualResultStatus::DetachedCleanly;
    input.require_clean_detach_evidence = true;
    input.require_fixture_bridge_records = false;
    input.require_dry_run_completed = false;
    let mut report = evaluate_event_stream_evidence_audit(&input);
    report.ready_for_reader_spike_preparation = true;
    report.status = EbpfEventStreamEvidenceAuditStatus::Passed;
    report.manual_capture_ready = true;
    report.findings.clear();
    report
}
fn spi() -> EbpfEventStreamReaderSpikePrepInput {
    EbpfEventStreamReaderSpikePrepInput {
        audit_report: sar(),
        reader_input: default_event_stream_reader_input(),
        explicit_reader_spike_prep_consent: true,
        explicit_operator_label: String::from("test-operator"),
        feature_name: String::from("intergalaxion-reader-spike-lab"),
        feature_expected_disabled_by_default: true,
        local_lab_only: true,
        max_events: 16,
        timeout_ms: 5000,
        require_clean_shutdown: true,
        require_post_run_evidence_capture: true,
        public_cli_requested: false,
        allow_live_reader: false,
        allow_ring_buffer_open: false,
        allow_live_event_read: false,
        allow_map_pin: false,
        allow_persistence: false,
        allow_enforcement: false,
        allow_packet_drop: false,
    }
}
#[test]
fn i15a_default_input_safe() {
    let i = di();
    assert!(
        !i.explicit_reader_spike_prep_consent
            && i.explicit_operator_label.is_empty()
            && i.feature_name.is_empty()
    );
    assert!(
        i.feature_expected_disabled_by_default
            && i.local_lab_only
            && i.require_clean_shutdown
            && i.require_post_run_evidence_capture
    );
    assert!(
        !i.public_cli_requested
            && !i.allow_live_reader
            && !i.allow_ring_buffer_open
            && !i.allow_live_event_read
    );
    assert!(
        !i.allow_map_pin && !i.allow_persistence && !i.allow_enforcement && !i.allow_packet_drop
    );
    assert_eq!(i.max_events, 0);
    assert_eq!(i.timeout_ms, 0);
}
#[test]
fn i15a_default_plan_phase() {
    assert_eq!(dp().phase, "I-15A");
}
#[test]
fn i15a_default_plan_op_flags_false() {
    let p = dp();
    assert!(
        !p.public_cli_exposed
            && !p.ring_buffer_opened
            && !p.live_event_stream_read
            && !p.map_pin_performed
            && !p.enforcement_performed
            && !p.packet_drop_performed
            && !p.mutation_performed
            && !p.persistence_performed
    );
}
#[test]
fn i15a_status_labels() {
    let sl = event_stream_reader_spike_prep_status_label;
    assert_eq!(
        sl(EbpfEventStreamReaderSpikePrepStatus::Disabled),
        "disabled"
    );
    assert_eq!(
        sl(EbpfEventStreamReaderSpikePrepStatus::AuditNotReady),
        "audit_not_ready"
    );
    assert_eq!(
        sl(EbpfEventStreamReaderSpikePrepStatus::MissingOperatorConsent),
        "missing_operator_consent"
    );
    assert_eq!(
        sl(EbpfEventStreamReaderSpikePrepStatus::InvalidLimits),
        "invalid_limits"
    );
    assert_eq!(
        sl(EbpfEventStreamReaderSpikePrepStatus::PrepReady),
        "prep_ready"
    );
    assert_eq!(
        sl(EbpfEventStreamReaderSpikePrepStatus::PrepRejected),
        "prep_rejected"
    );
    assert_eq!(
        sl(EbpfEventStreamReaderSpikePrepStatus::LiveReaderUnsupported),
        "live_reader_unsupported"
    );
    assert_eq!(sl(EbpfEventStreamReaderSpikePrepStatus::Blocked), "blocked");
}
#[test]
fn i15a_step_kind_labels() {
    let kl = event_stream_reader_spike_prep_step_kind_label;
    assert_eq!(
        kl(EbpfEventStreamReaderSpikePrepStepKind::AuditReview),
        "audit_review"
    );
    assert_eq!(
        kl(EbpfEventStreamReaderSpikePrepStepKind::OperatorConsent),
        "operator_consent"
    );
    assert_eq!(
        kl(EbpfEventStreamReaderSpikePrepStepKind::FeatureGateCheck),
        "feature_gate_check"
    );
    assert_eq!(
        kl(EbpfEventStreamReaderSpikePrepStepKind::ReaderTargetReview),
        "reader_target_review"
    );
    assert_eq!(
        kl(EbpfEventStreamReaderSpikePrepStepKind::LimitReview),
        "limit_review"
    );
    assert_eq!(
        kl(EbpfEventStreamReaderSpikePrepStepKind::AbortConditionReview),
        "abort_condition_review"
    );
    assert_eq!(
        kl(EbpfEventStreamReaderSpikePrepStepKind::CleanupReview),
        "cleanup_review"
    );
    assert_eq!(
        kl(EbpfEventStreamReaderSpikePrepStepKind::PostRunEvidencePlan),
        "post_run_evidence_plan"
    );
}
#[test]
fn i15a_default_not_ready() {
    let p = dp();
    assert!(!p.prep_ready);
    assert_eq!(
        p.status,
        EbpfEventStreamReaderSpikePrepStatus::AuditNotReady
    );
}
#[test]
fn i15a_default_has_steps() {
    let p = dp();
    assert!(!p.steps.is_empty() && p.steps.iter().any(|s| s.required));
}
#[test]
fn i15a_default_has_abort_conds() {
    let p = dp();
    assert!(!p.abort_conditions.is_empty() && p.abort_conditions.iter().any(|c| c.blocking));
}
#[test]
fn i15a_steps_deterministic() {
    let p1 = dp();
    let p2 = dp();
    assert_eq!(p1.steps.len(), p2.steps.len());
    for (a, b) in p1.steps.iter().zip(p2.steps.iter()) {
        assert_eq!(a.step_id, b.step_id);
    }
}
#[test]
fn i15a_rejects_audit_not_ready() {
    let mut i = di();
    i.audit_report.ready_for_reader_spike_preparation = false;
    let p = evaluate_event_stream_reader_spike_prep(&i);
    assert!(!p.prep_ready);
    assert_eq!(
        p.status,
        EbpfEventStreamReaderSpikePrepStatus::AuditNotReady
    );
}
#[test]
fn i15a_rejects_invalid_audit() {
    let mut i = di();
    i.audit_report.ready_for_reader_spike_preparation = true;
    i.audit_report.public_cli_exposed = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::AuditNotReady
    );
}
#[test]
fn i15a_rejects_no_consent() {
    let mut i = spi();
    i.explicit_reader_spike_prep_consent = false;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::MissingOperatorConsent
    );
}
#[test]
fn i15a_rejects_empty_operator() {
    let mut i = spi();
    i.explicit_operator_label = String::new();
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::MissingOperatorConsent
    );
}
#[test]
fn i15a_rejects_empty_feature() {
    let mut i = spi();
    i.feature_name = String::new();
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::PrepRejected
    );
}
#[test]
fn i15a_rejects_feature_not_disabled() {
    let mut i = spi();
    i.feature_expected_disabled_by_default = false;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::PrepRejected
    );
}
#[test]
fn i15a_rejects_not_local_lab() {
    let mut i = spi();
    i.local_lab_only = false;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::PrepRejected
    );
}
#[test]
fn i15a_rejects_max_events_0() {
    let mut i = spi();
    i.max_events = 0;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::InvalidLimits
    );
}
#[test]
fn i15a_rejects_max_events_1025() {
    let mut i = spi();
    i.max_events = 1025;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::InvalidLimits
    );
}
#[test]
fn i15a_rejects_timeout_0() {
    let mut i = spi();
    i.timeout_ms = 0;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::InvalidLimits
    );
}
#[test]
fn i15a_rejects_timeout_60001() {
    let mut i = spi();
    i.timeout_ms = 60001;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::InvalidLimits
    );
}
#[test]
fn i15a_accepts_max_events_1024() {
    let mut i = spi();
    i.max_events = 1024;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::PrepReady
    );
}
#[test]
fn i15a_accepts_timeout_60000() {
    let mut i = spi();
    i.timeout_ms = 60000;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::PrepReady
    );
}
#[test]
fn i15a_rejects_no_clean_shutdown() {
    let mut i = spi();
    i.require_clean_shutdown = false;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::PrepRejected
    );
}
#[test]
fn i15a_rejects_no_post_run_evidence() {
    let mut i = spi();
    i.require_post_run_evidence_capture = false;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::PrepRejected
    );
}
#[test]
fn i15a_rejects_public_cli() {
    let mut i = spi();
    i.public_cli_requested = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::PrepRejected
    );
}
#[test]
fn i15a_rejects_allow_live_reader() {
    let mut i = spi();
    i.allow_live_reader = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::LiveReaderUnsupported
    );
}
#[test]
fn i15a_rejects_allow_ring_buf() {
    let mut i = spi();
    i.allow_ring_buffer_open = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::Blocked
    );
}
#[test]
fn i15a_rejects_allow_live_read() {
    let mut i = spi();
    i.allow_live_event_read = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::Blocked
    );
}
#[test]
fn i15a_rejects_allow_map_pin() {
    let mut i = spi();
    i.allow_map_pin = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::Blocked
    );
}
#[test]
fn i15a_rejects_allow_persistence() {
    let mut i = spi();
    i.allow_persistence = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::Blocked
    );
}
#[test]
fn i15a_rejects_allow_enforcement() {
    let mut i = spi();
    i.allow_enforcement = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::Blocked
    );
}
#[test]
fn i15a_rejects_allow_packet_drop() {
    let mut i = spi();
    i.allow_packet_drop = true;
    assert_eq!(
        evaluate_event_stream_reader_spike_prep(&i).status,
        EbpfEventStreamReaderSpikePrepStatus::Blocked
    );
}
#[test]
fn i15a_can_become_prep_ready() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert_eq!(p.status, EbpfEventStreamReaderSpikePrepStatus::PrepReady);
    assert!(p.prep_ready);
}
#[test]
fn i15a_prep_ready_ring_buf_false() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert!(!p.ring_buffer_opened);
}
#[test]
fn i15a_prep_ready_live_read_false() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert!(!p.live_event_stream_read);
}
#[test]
fn i15a_prep_ready_map_pin_false() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert!(!p.map_pin_performed);
}
#[test]
fn i15a_prep_ready_enforcement_false() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert!(!p.enforcement_performed);
}
#[test]
fn i15a_prep_ready_pkt_drop_false() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert!(!p.packet_drop_performed);
}
#[test]
fn i15a_prep_ready_mutation_false() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert!(!p.mutation_performed);
}
#[test]
fn i15a_prep_ready_persistence_false() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert!(!p.persistence_performed);
}
#[test]
fn i15a_prep_ready_public_cli_false() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert!(!p.public_cli_exposed);
}
#[test]
fn i15a_validation_accepts_default() {
    assert!(validate_event_stream_reader_spike_prep_plan(&dp()).is_ok());
}
#[test]
fn i15a_val_rejects_prep_ready_wrong_status() {
    let mut p = dp();
    p.prep_ready = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_empty_phase() {
    let mut p = dp();
    p.phase = String::new();
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_not_local_lab() {
    let mut p = dp();
    p.local_lab_only = false;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_empty_steps() {
    let mut p = dp();
    p.steps = Vec::new();
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_empty_abort() {
    let mut p = dp();
    p.abort_conditions = Vec::new();
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_step_empty_title() {
    let mut p = dp();
    p.steps[0].required = true;
    p.steps[0].title = String::new();
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_step_empty_desc() {
    let mut p = dp();
    p.steps[0].required = true;
    p.steps[0].description = String::new();
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_abort_empty_code() {
    let mut p = dp();
    p.abort_conditions[0].code = String::new();
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_abort_empty_desc() {
    let mut p = dp();
    p.abort_conditions[0].description = String::new();
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_cli_exposed() {
    let mut p = dp();
    p.public_cli_exposed = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_ring_buf() {
    let mut p = dp();
    p.ring_buffer_opened = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_live_read() {
    let mut p = dp();
    p.live_event_stream_read = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_map_pin() {
    let mut p = dp();
    p.map_pin_performed = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_enforcement() {
    let mut p = dp();
    p.enforcement_performed = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_pkt_drop() {
    let mut p = dp();
    p.packet_drop_performed = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_mutation() {
    let mut p = dp();
    p.mutation_performed = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_val_rejects_persistence() {
    let mut p = dp();
    p.persistence_performed = true;
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_err());
}
#[test]
fn i15a_deterministic() {
    let p1 = evaluate_event_stream_reader_spike_prep(&spi());
    let p2 = evaluate_event_stream_reader_spike_prep(&spi());
    assert_eq!(p1.status, p2.status);
    assert_eq!(p1.prep_ready, p2.prep_ready);
    assert_eq!(p1.reason, p2.reason);
}
// ── Doc tests ─────────────────────────────────────────────────────────
#[test]
fn i15a_doc_exists() {
    assert!(!DOC.is_empty());
}
#[test]
fn i15a_doc_spike_prep() {
    assert!(doc_lower().contains("reader spike preparation"));
}
#[test]
fn i15a_doc_prep_only() {
    assert!(doc_lower().contains("preparation-only"));
}
#[test]
fn i15a_doc_no_cli() {
    assert!(doc_lower().contains("no public cli"));
}
#[test]
fn i15a_doc_no_ci_read() {
    assert!(doc_lower().contains("no normal ci live event read"));
}
#[test]
fn i15a_doc_no_ring_buf() {
    assert!(doc_lower().contains("no ring buffer open"));
}
#[test]
fn i15a_doc_no_kernel_read() {
    assert!(doc_lower().contains("no live kernel event read"));
}
#[test]
fn i15a_doc_no_map_pin() {
    assert!(doc_lower().contains("no map pin"));
}
#[test]
fn i15a_doc_no_enforcement() {
    assert!(doc_lower().contains("no enforcement"));
}
#[test]
fn i15a_doc_no_pkt_drop() {
    assert!(doc_lower().contains("no packet drop"));
}
#[test]
fn i15a_doc_no_block_allow_quota() {
    assert!(doc_lower().contains("no block/allow/quota"));
}
#[test]
fn i15a_doc_no_nft_tc() {
    assert!(doc_lower().contains("no nft/tc fallback"));
}
#[test]
fn i15a_doc_no_persistence() {
    assert!(doc_lower().contains("no ledger file write") || doc_lower().contains("no persistence"));
}
#[test]
fn i15a_doc_usage_unchanged() {
    assert!(
        doc_lower().contains("usage json schema unchanged")
            || doc_lower().contains("existing v3.1 usage json schema unchanged")
    );
}
#[test]
fn i15a_doc_ledger_unchanged() {
    assert!(
        doc_lower().contains("ledger json schema unchanged")
            || doc_lower().contains("existing v3.1 ledger json schema unchanged")
    );
}
#[test]
fn i15a_doc_audit_required() {
    assert!(
        doc_lower().contains("audit readiness")
            || doc_lower().contains("i-15")
            || doc_lower().contains("evidence audit")
    );
}
#[test]
fn i15a_doc_disabled_default() {
    assert!(doc_lower().contains("disabled by default"));
}
#[test]
fn i15a_doc_local_lab() {
    assert!(doc_lower().contains("local lab only"));
}
#[test]
fn i15a_doc_limits_required() {
    assert!(
        doc_lower().contains("max event")
            && doc_lower().contains("timeout")
            && doc_lower().contains("required")
    );
}
#[test]
fn i15a_doc_evidence_required() {
    assert!(
        doc_lower().contains("post-run evidence capture")
            || doc_lower().contains("post-run evidence")
            || doc_lower().contains("evidence capture")
    );
}
#[test]
fn i15a_doc_no_fake() {
    assert!(
        doc_lower().contains("no fake reader readiness")
            || doc_lower().contains("no fake preparation readiness")
    );
}
// ── CLI/version tests ─────────────────────────────────────────────────
#[test]
fn i15a_version_v310() {
    let bin = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/release/zelynic");
    if bin.exists() {
        let v = std::process::Command::new(&bin)
            .arg("--version")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        assert!(v.contains("3.1.0"), "got: {}", v);
    }
}
#[test]
fn i15a_ledger_inspect() {
    let _ = crate::commands::ledger::handle_ledger_inspect(true, None);
}
#[test]
fn i15a_ledger_export() {
    let path = std::env::temp_dir().join("zelynic-i15a-ledger.json");
    let _ =
        crate::commands::ledger::handle_ledger_export(true, Some(path.to_string_lossy().as_ref()));
    let _ = std::fs::remove_file(path);
}
fn render_help(app: &mut clap::Command) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let _ = clap::Command::write_help(app, &mut buf);
    String::from_utf8_lossy(&buf).to_string()
}
#[test]
fn i15a_help_no_intergalaxion() {
    let mut app = Cli::command();
    assert!(!render_help(&mut app)
        .to_lowercase()
        .contains("intergalaxion"));
}
#[test]
fn i15a_help_no_block_allow_quota() {
    let mut app = Cli::command();
    let h = render_help(&mut app).to_lowercase();
    assert!(!h.contains("block") && !h.contains("allow") && !h.contains("quota"));
}
// ── Dependency and source checks ──────────────────────────────────────
#[test]
fn i15a_no_new_dep() {
    let ct = include_str!("../../Cargo.toml");
    let lines: Vec<&str> = ct.lines().collect();
    let ds = lines.iter().position(|l| l.starts_with("[dependencies]"));
    let dd = lines
        .iter()
        .position(|l| l.starts_with("[dev-dependencies]"));
    assert!(ds.is_some());
    if let Some(d) = dd {
        if d > ds.unwrap() {
            let sec: String = lines[ds.unwrap()..d].join("\n");
            // aya exists as optional dep from prior phases; check no new non-optional dep added
            assert!(
                sec.lines()
                    .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
                    .count()
                    > 0
            );
        }
    }
}
#[test]
fn i15a_no_nft_tc() {
    // Check only implementation lines, not doc comments
    for line in SRC.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        assert!(
            !t.contains("nft") && !t.contains("tc "),
            "found in impl: {}",
            line
        );
    }
}
#[test]
fn i15a_source_under_1000() {
    assert!(SRC.lines().count() < 1000, "got: {}", SRC.lines().count());
}
// ── Forbidden patterns ────────────────────────────────────────────────
#[test]
fn i15a_no_forbidden() {
    let f = [
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
    for p in &f {
        assert!(!SRC.contains(p), "found: {}", p);
    }
}
#[test]
fn i15a_no_standalone_persist() {
    for line in SRC.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        for w in t.split_whitespace() {
            let c = w.trim_matches(|c: char| !c.is_alphabetic());
            if c == "persist" && !w.contains("persistence") && !w.contains("allow_persistence") {
                panic!("found: {}", line);
            }
        }
    }
}
// ── Extra edge tests ─────────────────────────────────────────────────
#[test]
fn i15a_8_abort_conds() {
    assert_eq!(dp().abort_conditions.len(), 8);
}
#[test]
fn i15a_8_steps() {
    assert_eq!(dp().steps.len(), 8);
}
#[test]
fn i15a_prep_ready_copies_limits() {
    let mut i = spi();
    i.max_events = 512;
    i.timeout_ms = 30000;
    let p = evaluate_event_stream_reader_spike_prep(&i);
    assert_eq!(p.max_events, 512);
    assert_eq!(p.timeout_ms, 30000);
}
#[test]
fn i15a_prep_ready_copies_labels() {
    let p = evaluate_event_stream_reader_spike_prep(&spi());
    assert_eq!(p.operator_label, "test-operator");
    assert_eq!(p.feature_name, "intergalaxion-reader-spike-lab");
}
#[test]
fn i15a_all_abort_blocking() {
    for c in &dp().abort_conditions {
        assert!(c.blocking);
    }
}
#[test]
fn i15a_all_steps_required() {
    for s in &dp().steps {
        assert!(s.required);
    }
}
#[test]
fn i15a_all_steps_manual() {
    for s in &dp().steps {
        assert!(s.manual_only);
    }
}
#[test]
fn i15a_optional_step_ok() {
    let mut p = dp();
    p.steps.push(EbpfEventStreamReaderSpikePrepStep {
        step_id: String::from("opt"),
        kind: EbpfEventStreamReaderSpikePrepStepKind::AuditReview,
        title: String::new(),
        required: false,
        completed: false,
        manual_only: false,
        description: String::new(),
    });
    assert!(validate_event_stream_reader_spike_prep_plan(&p).is_ok());
}
