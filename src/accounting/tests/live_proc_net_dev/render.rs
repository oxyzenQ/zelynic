// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Render output tests for the live `/proc/net/dev` reader seam.
//!
//! Tests all render output honesty disclaimers, mutation flags, source labels,
//! snapshot summaries, determinism, planned/error states, and both direct
//! (build_*) and injected-reader render paths. All tests use injected/fake
//! content — no live filesystem reads.

use super::*;

// ── Render: read-only seam statement ──────────────────────────────

#[test]
fn render_includes_read_only_seam_statement() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("read-only /proc/net/dev seam"),
        "render must include read-only seam statement"
    );
}

// ── Render: honesty denials ───────────────────────────────────────

#[test]
fn render_denies_per_app_attribution() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("not per-app attribution"),
        "render must deny per-app attribution"
    );
}

#[test]
fn render_denies_quota_enforcement() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no quota enforcement active"),
        "render must deny quota enforcement"
    );
}

#[test]
fn render_denies_network_blocking() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no network blocking active"),
        "render must deny network blocking"
    );
}

#[test]
fn render_denies_limiter_attach() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no limiter attach performed"),
        "render must deny limiter attach"
    );
}

#[test]
fn render_denies_nft_tc_state_mutation() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no nft/tc/Zelynic state mutation performed"),
        "render must deny nft/tc/state mutation"
    );
}

#[test]
fn render_denies_ledger_persistence() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no ledger persistence performed"),
        "render must deny ledger persistence"
    );
}

#[test]
fn render_denies_ebpf() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no eBPF used"), "render must deny eBPF");
}

#[test]
fn render_denies_cgroup_mutation() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no cgroup mutation"),
        "render must deny cgroup mutation"
    );
}

#[test]
fn render_denies_pid_movement() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("no PID movement"),
        "render must deny PID movement"
    );
}

// ── Render: counters may reset ────────────────────────────────────

#[test]
fn render_warns_counters_may_reset() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("counters may reset after reboot/interface reset"),
        "render must warn about counter reset"
    );
}

// ── Render: mutation flags ─────────────────────────────────────────

#[test]
fn render_includes_filesystem_write_not_performed() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("filesystem write not performed"),
        "render must state filesystem write not performed"
    );
}

#[test]
fn render_includes_state_mutation_not_performed() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("state mutation not performed"),
        "render must state state mutation not performed"
    );
}

// ── Render: source path and label ─────────────────────────────────

#[test]
fn render_includes_source_path() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("/proc/net/dev"),
        "render must include source path"
    );
    assert!(
        rendered.contains("live_proc_net_dev_sample"),
        "render must include source label"
    );
}

// ── Render: planned state ─────────────────────────────────────────

#[test]
fn render_planned_plan_shows_planned_status() {
    let plan = build_live_proc_net_dev_read_plan();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("Read status: planned"),
        "render must show planned status"
    );
    assert!(
        rendered.contains("Snapshot: none"),
        "render must show no snapshot for planned"
    );
}

// ── Render: snapshot summary ────────────────────────────────────

#[test]
fn render_shows_snapshot_summary() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("3 interface(s) parsed"),
        "render must show interface count"
    );
    assert!(
        rendered.contains("wlan0"),
        "render must include interface names"
    );
    assert!(
        rendered.contains("eth0"),
        "render must include interface names"
    );
}

#[test]
fn render_shows_empty_snapshot() {
    let plan = build_live_proc_net_dev_snapshot_from_content("").unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("empty (no interfaces parsed)"),
        "render must show empty snapshot message"
    );
}

// ── Render: determinism ───────────────────────────────────────────

#[test]
fn render_is_deterministic() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered1 = render_live_proc_net_dev_read_plan(&plan);
    let rendered2 = render_live_proc_net_dev_read_plan(&plan);
    assert_eq!(rendered1, rendered2, "render output must be deterministic");
}

// ── Render: mutation flags ────────────────────────────────────────

#[test]
fn render_shows_mutation_flags() {
    let plan = build_live_proc_net_dev_snapshot_from_content(LIVE_SEAM_SAMPLE).unwrap();
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("Filesystem read performed: false"),
        "render must show filesystem_read_performed = false"
    );
    assert!(
        rendered.contains("Filesystem write performed: false"),
        "render must show filesystem_write_performed = false"
    );
    assert!(
        rendered.contains("State mutation performed: false"),
        "render must show state_mutation_performed = false"
    );
}

// ── Render: error plan ───────────────────────────────────────────

#[test]
fn render_error_plan_shows_error_status() {
    let err_content = "wlan0: abc 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
    let result = build_live_proc_net_dev_snapshot_from_content(err_content);
    let parse_err = result.unwrap_err();
    let plan = build_live_proc_net_dev_error_plan(&parse_err);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(
        rendered.contains("Read status: error:"),
        "render must show error status"
    );
    assert!(
        rendered.contains("Snapshot: none"),
        "render must show no snapshot for error"
    );
    // Error plan still has honesty disclaimers
    assert!(
        rendered.contains("read-only /proc/net/dev seam"),
        "error plan must still have honesty disclaimers"
    );
}

// ── Rendered success output honesty (injected reader) ────────────────

#[test]
fn rendered_injected_success_denies_per_app_attribution() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("not per-app attribution"));
}

#[test]
fn rendered_injected_success_denies_quota_enforcement() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no quota enforcement active"));
}

#[test]
fn rendered_injected_success_denies_network_blocking() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no network blocking active"));
}

#[test]
fn rendered_injected_success_denies_limiter_attach() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no limiter attach performed"));
}

#[test]
fn rendered_injected_success_denies_nft_tc_state_mutation() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
}

#[test]
fn rendered_injected_success_denies_ledger_persistence() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no ledger persistence performed"));
}

#[test]
fn rendered_injected_success_denies_ebpf() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no eBPF used"));
}

#[test]
fn rendered_injected_success_denies_cgroup_mutation() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no cgroup mutation"));
}

#[test]
fn rendered_injected_success_denies_pid_movement() {
    let reader = InjectedContentReader::new(LIVE_SEAM_SAMPLE);
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no PID movement"));
}

// ── Rendered error output honesty ────────────────────────────────────

#[test]
fn rendered_read_error_denies_per_app_attribution() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("not per-app attribution"));
}

#[test]
fn rendered_read_error_denies_quota_enforcement() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no quota enforcement active"));
}

#[test]
fn rendered_read_error_denies_network_blocking() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no network blocking active"));
}

#[test]
fn rendered_read_error_denies_limiter_attach() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no limiter attach performed"));
}

#[test]
fn rendered_read_error_denies_nft_tc_state_mutation() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
}

#[test]
fn rendered_read_error_denies_ledger_persistence() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no ledger persistence performed"));
}

#[test]
fn rendered_read_error_denies_ebpf() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no eBPF used"));
}

#[test]
fn rendered_read_error_denies_cgroup_mutation() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no cgroup mutation"));
}

#[test]
fn rendered_read_error_denies_pid_movement() {
    let reader = FakeReadErrorReader::new("permission denied");
    let plan = read_live_proc_net_dev_with_injected_reader(&reader);
    let rendered = render_live_proc_net_dev_read_plan(&plan);
    assert!(rendered.contains("no PID movement"));
}
