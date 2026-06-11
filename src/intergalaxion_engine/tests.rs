// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Compile-safe and invariant tests for the Intergalaxion Engine (Phase I-0).
//!
//! These tests verify that:
//! 1. All modules compile.
//! 2. All model defaults are safe (observer-only, no enforcement).
//! 3. No existing CLI behavior is changed.

use super::*;
use crate::intergalaxion_engine::backends::ebpf::*;
use crate::intergalaxion_engine::identity::ProcessIdentity;
use crate::intergalaxion_engine::ledger_bridge::{BridgeEvent, BridgeResult};
use crate::intergalaxion_engine::safety::{check_i0_invariants, SafetyCheck, SafetyViolation};
use crate::intergalaxion_engine::telemetry::TelemetrySummary;

// ── Module compilation smoke tests ───────────────────────────────────

#[test]
fn intergalaxion_module_compiles() {
    let _state = EngineState::default();
}

#[test]
fn ebpf_backend_module_compiles() {
    let _status = EbpfBackendStatus::default();
    let _cap = EbpfCapabilityReport::default();
    let _obs = EbpfObserverState::default();
    let _attach = EbpfAttachState::default();
    let _event = EbpfEventKind::default();
    let _plan = EbpfMapPlan::default();
}

// ── Default safety tests ────────────────────────────────────────────

#[test]
fn capability_report_defaults_to_unavailable() {
    let report = EbpfCapabilityReport::default();
    assert_eq!(report.backend_status, EbpfCapabilityStatus::Unavailable);
    assert!(!report.kernel_supported);
    assert!(!report.has_bpf_caps);
    assert!(!report.bpf_fs_mounted);
    assert!(!report.kernel_config_ok);
}

#[test]
fn observer_state_defaults_to_inactive() {
    assert_eq!(EbpfObserverState::default(), EbpfObserverState::Inactive);
}

#[test]
fn attach_state_defaults_to_not_attached() {
    assert_eq!(EbpfAttachState::default(), EbpfAttachState::NotAttached);
}

#[test]
fn packet_drop_enabled_defaults_false() {
    let state = EngineState::default();
    assert!(!state.packet_drop_enabled);
}

#[test]
fn enforcement_enabled_defaults_false() {
    let state = EngineState::default();
    assert!(!state.enforcement_enabled);
}

#[test]
fn quota_enabled_defaults_false() {
    let state = EngineState::default();
    assert!(!state.quota_enabled);
}

#[test]
fn mutation_performed_defaults_false() {
    let state = EngineState::default();
    assert!(!state.mutation_performed);
}

#[test]
fn backend_available_defaults_false() {
    let state = EngineState::default();
    assert!(!state.backend_available);
}

#[test]
fn observer_active_defaults_false() {
    let state = EngineState::default();
    assert!(!state.observer_active);
}

// ── Safety invariant tests ──────────────────────────────────────────

#[test]
fn safety_check_ok_for_default_state() {
    let result = check_i0_invariants(false, false, false);
    assert_eq!(result, SafetyCheck::Ok);
}

#[test]
fn safety_check_rejects_enforcement() {
    let result = check_i0_invariants(false, true, false);
    assert_eq!(
        result,
        SafetyCheck::Violation(SafetyViolation::EnforcementInObserverMode)
    );
}

#[test]
fn safety_check_rejects_mutation() {
    let result = check_i0_invariants(false, false, true);
    assert_eq!(
        result,
        SafetyCheck::Violation(SafetyViolation::MutationNotAllowed)
    );
}

#[test]
fn safety_check_allows_active_observer() {
    let result = check_i0_invariants(true, false, false);
    assert_eq!(result, SafetyCheck::Ok);
}

// ── Model struct tests ──────────────────────────────────────────────

#[test]
fn process_identity_defaults_are_none() {
    let id = ProcessIdentity::default();
    assert!(id.pid.is_none());
    assert!(id.cgroup_path.is_none());
    assert!(id.label.is_none());
}

#[test]
fn telemetry_summary_defaults_to_zero() {
    let summary = TelemetrySummary::default();
    assert_eq!(summary.total_rx_bytes, 0);
    assert_eq!(summary.total_tx_bytes, 0);
    assert_eq!(summary.sample_count, 0);
}

#[test]
fn bridge_event_defaults() {
    let event = BridgeEvent::default();
    assert!(event.identity_label.is_empty());
    assert_eq!(event.rx_bytes, 0);
    assert_eq!(event.tx_bytes, 0);
    assert!(!event.committed);
}

#[test]
fn bridge_result_defaults_to_not_operational() {
    assert_eq!(BridgeResult::default(), BridgeResult::NotOperational);
}

#[test]
fn ebpf_event_kind_defaults_to_noop() {
    assert_eq!(EbpfEventKind::default(), EbpfEventKind::Noop);
}

#[test]
fn ebpf_map_plan_defaults_to_empty() {
    let plan = EbpfMapPlan::default();
    assert!(plan.maps.is_empty());
}

#[test]
fn ebpf_probe_descriptor_defaults_gated() {
    let probe = crate::intergalaxion_engine::backends::ebpf::EbpfProbeDescriptor::default();
    assert!(probe.gated);
}
