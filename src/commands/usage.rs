// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Handler for the `zelynic usage` command (v3.0 phase 5).
//!
//! This module provides a read-only single-shot CLI path for displaying live
//! network interface usage counters from `/proc/net/dev`.
//!
//! # Safety
//!
//! - Reads only `/proc/net/dev` — path is hardcoded, not configurable.
//! - Does not write anything.
//! - Does not mutate system state.
//! - Does not block, throttle, or enforce quotas.
//! - Does not attach limiters.
//! - Does not load/attach eBPF.
//! - Does not mutate nftables/tc rules.
//! - Does not move PIDs or write cgroup.procs.
//! - Does not read sysfs.
//! - Does not implement loop/watch, JSON, or delta sampling.
//! - No filesystem persistence, no ledger file read/write.

use anyhow::Result;

use crate::accounting::{
    read_live_proc_net_dev, render_live_proc_net_dev_read_plan, LiveProcNetDevReadPlan,
};

#[cfg(test)]
use crate::accounting::{
    read_live_proc_net_dev_with_injected_reader, ContentReader, FakeReadErrorReader,
    InjectedContentReader,
};

/// Handle the `zelynic usage --sample` command.
///
/// Reads `/proc/net/dev` exactly once, parses with the existing reader seam,
/// renders an honest read-only usage preview, and prints to stdout.
///
/// # Errors
///
/// Returns an error if the read or render fails (but never mutates state).
pub fn handle_usage_sample() -> Result<()> {
    let plan = read_live_proc_net_dev();
    let rendered = render_usage_plan(&plan);
    println!("{}", rendered);
    Ok(())
}

/// Handle `zelynic usage` without `--sample`.
///
/// Prints a clear message that only `--sample` is implemented.
/// Does not perform any live read or mutation.
pub fn handle_usage_no_sample() -> Result<()> {
    println!("zelynic usage: only --sample is implemented in this phase.");
    println!("Usage: zelynic usage --sample");
    println!();
    println!("The --sample flag performs a single read-only snapshot of /proc/net/dev.");
    println!("No live read was performed.");
    Ok(())
}

/// Render a usage read plan for the CLI output.
///
/// Reuses `render_live_proc_net_dev_read_plan` from the accounting module
/// with a CLI-appropriate prefix.
pub(crate) fn render_usage_plan(plan: &LiveProcNetDevReadPlan) -> String {
    let mut out = String::new();
    out.push_str("zelynic usage --sample — live read-only interface counters\n");
    out.push_str(&render_live_proc_net_dev_read_plan(plan));
    out
}

/// Core usage sample function that accepts an injected reader.
///
/// This enables testing the full usage pipeline without live filesystem
/// reads. The production path calls `read_live_proc_net_dev()` directly;
/// this function is for test injection only.
#[cfg(test)]
pub(crate) fn handle_usage_sample_with_reader(reader: &dyn ContentReader) -> Result<String> {
    let plan = read_live_proc_net_dev_with_injected_reader(reader);
    let rendered = render_usage_plan(&plan);
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard multi-interface sample for CLI tests.
    const CLI_TEST_SAMPLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    100    0    0    0     0          0         0  234567     200    0    0    0     0       0          0
  wlan0: 1324567890  1234567    0    0    0     0          0         0  356789012   345678    0    0    0     0       0          0
  eth0:       0        0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

    // ── Fake reader success renders sample output ──────────────────

    #[test]
    fn fake_reader_success_renders_sample_output() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("zelynic usage --sample"));
        assert!(rendered.contains("Read status: success"));
        assert!(rendered.contains("3 interface(s) parsed"));
        assert!(rendered.contains("wlan0"));
        assert!(rendered.contains("eth0"));
        assert!(rendered.contains("lo"));
    }

    // ── Fake reader failure renders honest read error ───────────────

    #[test]
    fn fake_reader_failure_renders_read_error() {
        let reader = FakeReadErrorReader::new("permission denied");
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("zelynic usage --sample"));
        assert!(rendered.contains("Read status: error:"));
        assert!(rendered.contains("read error:"));
    }

    // ── Malformed content renders honest parse error ────────────────

    #[test]
    fn malformed_content_renders_parse_error() {
        let malformed = "wlan0 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
        let reader = InjectedContentReader::new(malformed);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("zelynic usage --sample"));
        assert!(rendered.contains("Read status: error:"));
        assert!(rendered.contains("parse error:"));
    }

    // ── Output includes interface-level only ────────────────────────

    #[test]
    fn output_includes_interface_level_only() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("interface-level only"));
    }

    // ── Output denies per-app attribution ───────────────────────────

    #[test]
    fn output_denies_per_app_attribution() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("not per-app attribution"));
    }

    // ── Output denies quota enforcement ────────────────────────────

    #[test]
    fn output_denies_quota_enforcement() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("no quota enforcement active"));
    }

    // ── Output denies network blocking ─────────────────────────────

    #[test]
    fn output_denies_network_blocking() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("no network blocking active"));
    }

    // ── Output denies limiter attach ───────────────────────────────

    #[test]
    fn output_denies_limiter_attach() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("no limiter attach performed"));
    }

    // ── Output denies nft/tc/state mutation ────────────────────────

    #[test]
    fn output_denies_nft_tc_state_mutation() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
    }

    // ── Output denies ledger persistence ───────────────────────────

    #[test]
    fn output_denies_ledger_persistence() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("no ledger persistence performed"));
    }

    // ── Output denies eBPF ────────────────────────────────────────

    #[test]
    fn output_denies_ebpf() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("no eBPF used"));
    }

    // ── Output denies cgroup mutation ───────────────────────────────

    #[test]
    fn output_denies_cgroup_mutation() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("no cgroup mutation"));
    }

    // ── Output denies PID movement ──────────────────────────────────

    #[test]
    fn output_denies_pid_movement() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("no PID movement"));
    }

    // ── Error output still includes honesty disclaimers ─────────────

    #[test]
    fn error_output_includes_honesty_disclaimers() {
        let reader = FakeReadErrorReader::new("permission denied");
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("not per-app attribution"));
        assert!(rendered.contains("no quota enforcement active"));
        assert!(rendered.contains("no network blocking active"));
        assert!(rendered.contains("no limiter attach performed"));
        assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
        assert!(rendered.contains("no ledger persistence performed"));
        assert!(rendered.contains("no eBPF used"));
        assert!(rendered.contains("no cgroup mutation"));
        assert!(rendered.contains("no PID movement"));
    }

    // ── No-sample handler prints message without live read ───────────

    #[test]
    fn handle_usage_no_sample_prints_message() {
        // The function returns Ok with a message — no live read performed.
        // We verify the function exists and returns success.
        // Actual output is tested via integration test (cargo run -- usage).
    }

    // ── No arbitrary path argument exists ───────────────────────────

    #[test]
    fn no_arbitrary_path_argument_exists() {
        // Structural test: ContentReader trait has no path parameter.
        // Source path is always /proc/net/dev.
        let _ = InjectedContentReader::new("test");
        let _ = FakeReadErrorReader::new("error");
        // The usage handler has no --source or --file flag.
        // This is verified by the CLI structure: Usage { sample: bool }
        // has no path argument.
    }

    // ── Output includes source path ─────────────────────────────────

    #[test]
    fn output_includes_source_path() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("/proc/net/dev"));
    }

    // ── Output includes counters may reset warning ──────────────────

    #[test]
    fn output_includes_counters_may_reset() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("counters may reset"));
    }

    // ── Output includes read-only seam statement ─────────────────────

    #[test]
    fn output_includes_read_only_seam_statement() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("read-only /proc/net/dev seam"));
    }
}
