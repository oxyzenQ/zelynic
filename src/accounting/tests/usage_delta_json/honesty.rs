// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Honesty flag tests for delta JSON output.

use super::*;

// ── Honesty flags: all 19 present ──────────────────────────────────

#[test]
fn success_honesty_has_all_19_flags() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let h = &output.honesty;
    assert!(h.interface_level_only);
    assert!(!h.per_app_attribution);
    assert!(!h.quota_enforcement_active);
    assert!(!h.network_blocking_active);
    assert!(!h.limiter_attach_performed);
    assert!(!h.nft_tc_state_mutation_performed);
    assert!(!h.ledger_persistence_performed);
    assert!(!h.ebpf_used);
    assert!(!h.cgroup_mutation_performed);
    assert!(!h.pid_movement_performed);
    assert!(!h.filesystem_write_performed);
    assert!(!h.state_mutation_performed);
    assert!(h.delta_json_output);
    assert!(h.live_read_performed);
    assert_eq!(h.read_count, 2);
    assert!(h.single_shot);
    assert!(!h.loop_watch_mode);
    assert!(!h.configurable_interval);
    assert!(!h.interface_filtering);
    assert!(!h.arbitrary_path_read);
}

// ── Honesty: default helpers ────────────────────────────────────────

#[test]
fn default_honesty_flags_are_v30_constants() {
    let flags = delta_success_honesty_flags();
    assert!(flags.interface_level_only);
    assert!(!flags.per_app_attribution);
    assert!(!flags.quota_enforcement_active);
    assert!(flags.delta_json_output);
    assert!(flags.single_shot);
    assert!(!flags.loop_watch_mode);
    assert_eq!(flags.read_count, 2);
}

#[test]
fn first_read_error_honesty() {
    let flags = delta_error_first_read_honesty();
    assert!(!flags.live_read_performed);
    assert_eq!(flags.read_count, 0);
}

#[test]
fn second_read_error_honesty() {
    let flags = delta_error_second_read_honesty();
    assert!(flags.live_read_performed);
    assert_eq!(flags.read_count, 1);
}

// ── Error preserves honesty flags ────────────────────────────────────

#[test]
fn error_preserves_all_19_honesty_flags() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test");
    let h = &output.honesty;
    assert!(h.interface_level_only);
    assert!(!h.per_app_attribution);
    assert!(!h.quota_enforcement_active);
    assert!(!h.network_blocking_active);
    assert!(!h.limiter_attach_performed);
    assert!(!h.nft_tc_state_mutation_performed);
    assert!(!h.ledger_persistence_performed);
    assert!(!h.ebpf_used);
    assert!(!h.cgroup_mutation_performed);
    assert!(!h.pid_movement_performed);
    assert!(!h.filesystem_write_performed);
    assert!(!h.state_mutation_performed);
    assert!(h.delta_json_output);
    assert!(!h.live_read_performed);
    assert_eq!(h.read_count, 0);
    assert!(h.single_shot);
    assert!(!h.loop_watch_mode);
    assert!(!h.configurable_interval);
    assert!(!h.interface_filtering);
    assert!(!h.arbitrary_path_read);
}

// ── Serialization includes all honesty flags ──────────────────────────

#[test]
fn serialized_json_includes_all_honesty_flags() {
    let start = parse(START_SAMPLE);
    let end = parse(END_SAMPLE_NORMAL);
    let output = build_delta_json_success(&start, &end);
    let json = serialize_delta_json(&output).unwrap();
    let required_flags = [
        "interface_level_only",
        "per_app_attribution",
        "quota_enforcement_active",
        "network_blocking_active",
        "limiter_attach_performed",
        "nft_tc_state_mutation_performed",
        "ledger_persistence_performed",
        "ebpf_used",
        "cgroup_mutation_performed",
        "pid_movement_performed",
        "filesystem_write_performed",
        "state_mutation_performed",
        "delta_json_output",
        "live_read_performed",
        "read_count",
        "single_shot",
        "loop_watch_mode",
        "configurable_interval",
        "interface_filtering",
        "arbitrary_path_read",
    ];
    for flag in &required_flags {
        assert!(
            json.contains(flag),
            "missing honesty flag in JSON: {}",
            flag
        );
    }
}

#[test]
fn error_serialized_json_includes_all_honesty_flags() {
    let output = build_delta_json_first_read_error(DeltaJsonErrorType::Read, "test error");
    let json = serialize_delta_json(&output).unwrap();
    let required_flags = [
        "interface_level_only",
        "per_app_attribution",
        "quota_enforcement_active",
        "delta_json_output",
        "read_count",
        "single_shot",
        "loop_watch_mode",
        "configurable_interval",
        "interface_filtering",
        "arbitrary_path_read",
    ];
    for flag in &required_flags {
        assert!(
            json.contains(flag),
            "error JSON missing honesty flag: {}",
            flag
        );
    }
}
