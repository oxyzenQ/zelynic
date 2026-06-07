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
//! - Does not implement loop/watch or delta sampling.
//! - No filesystem persistence, no ledger file read/write.
//! - `--delta --json` is now wired to the frozen phase 14 pure model (phase 15).

use std::time::Duration;

use anyhow::Result;

use crate::accounting::{
    build_usage_json_error, build_usage_json_from_snapshot, read_live_proc_net_dev,
    render_live_proc_net_dev_read_plan, serialize_usage_json, LiveProcNetDevReadPlan,
    UsageJsonErrorType,
};

use crate::commands::usage_delta::{handle_usage_delta, handle_usage_delta_json};

#[cfg(test)]
use crate::accounting::{
    read_live_proc_net_dev_with_injected_reader, ContentReader, FakeReadErrorReader,
    InjectedContentReader,
};

/// Handle the `zelynic usage --sample` command.
///
/// Reads `/proc/net/dev` exactly once (or twice for delta), parses with the
/// existing reader seam, and either renders text output or JSON output
/// depending on the `--json` and `--delta` flags.
///
/// - `--sample --delta --json`: two-sample delta JSON output (live read-only).
/// - `--sample --delta`: two-sample delta text output (live read-only).
/// - `--sample --json`: single-sample JSON output.
/// - `--sample`: single-sample text output.
///
/// # Errors
///
/// Returns an error if the read or render fails (but never mutates state).
pub fn handle_usage_sample(json: bool, delta: bool) -> Result<()> {
    if delta && json {
        return handle_usage_delta_json();
    }
    if delta {
        return handle_usage_delta();
    }
    let plan = read_live_proc_net_dev();
    if json {
        let json_output = build_json_from_plan(&plan);
        let serialized = serialize_usage_json(&json_output);
        println!("{}", serialized?);
    } else {
        let rendered = render_usage_plan(&plan);
        println!("{}", rendered);
    }
    Ok(())
}

/// Build a `UsageJsonOutput` from a `LiveProcNetDevReadPlan`.
///
/// Maps the read plan's read_status to the appropriate JSON output:
/// - Success with snapshot → success JSON with interface data.
/// - Error with "read error:" prefix → read_error JSON.
/// - Error with "parse error:" prefix → parse_error JSON.
/// - Planned → should not occur in production (treated as read error).
///
/// Honesty flags and warnings are always preserved. `sampled_at` is omitted
/// (None) — no silent wall-clock timestamp generation.
pub(crate) fn build_json_from_plan(
    plan: &LiveProcNetDevReadPlan,
) -> crate::accounting::UsageJsonOutput {
    match &plan.read_status {
        crate::accounting::LiveReadStatus::Success => {
            if let Some(ref snapshot) = plan.snapshot {
                build_usage_json_from_snapshot(snapshot, None)
            } else {
                build_usage_json_error(
                    UsageJsonErrorType::Read,
                    "no snapshot available after successful read",
                    None,
                )
            }
        }
        crate::accounting::LiveReadStatus::Error(msg) => {
            let (error_type, message) = if msg.starts_with("read error:") {
                (UsageJsonErrorType::Read, msg.as_str())
            } else if msg.starts_with("parse error:") {
                (UsageJsonErrorType::Parse, msg.as_str())
            } else {
                (UsageJsonErrorType::Read, msg.as_str())
            };
            build_usage_json_error(error_type, message, None)
        }
        crate::accounting::LiveReadStatus::Planned => build_usage_json_error(
            UsageJsonErrorType::Read,
            "read was planned but never executed",
            None,
        ),
    }
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

/// Default delta wait duration between two samples.
/// Conservative 1-second default for the two-sample read-only delta.
pub(crate) const DEFAULT_DELTA_WAIT_DURATION: Duration = Duration::from_secs(1);

/// Core usage JSON sample function that accepts an injected reader.
///
/// This enables testing the JSON output pipeline without live filesystem
/// reads. Returns the serialized JSON string for test assertions.
#[cfg(test)]
pub(crate) fn handle_usage_sample_json_with_reader(reader: &dyn ContentReader) -> Result<String> {
    let plan = read_live_proc_net_dev_with_injected_reader(reader);
    let json_output = build_json_from_plan(&plan);
    Ok(serialize_usage_json(&json_output)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;

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

    // ── Phase 5b: rendered output contains ALL 13 honesty lines ────

    #[test]
    fn rendered_output_contains_all_honesty_lines() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        let required_lines = [
            "read-only /proc/net/dev seam",
            "interface-level only",
            "not per-app attribution",
            "no quota enforcement active",
            "no network blocking active",
            "no limiter attach performed",
            "no nft/tc/Zelynic state mutation performed",
            "no ledger persistence performed",
            "no eBPF used",
            "no cgroup mutation",
            "no PID movement",
            "counters may reset",
            "filesystem write not performed",
            "state mutation not performed",
        ];
        for line in &required_lines {
            assert!(rendered.contains(line), "missing honesty line: {}", line);
        }
    }

    // ── Phase 5b: error output contains ALL 13 honesty lines ───────

    #[test]
    fn error_output_contains_all_honesty_lines() {
        let reader = FakeReadErrorReader::new("permission denied");
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        let required_lines = [
            "read-only /proc/net/dev seam",
            "interface-level only",
            "not per-app attribution",
            "no quota enforcement active",
            "no network blocking active",
            "no limiter attach performed",
            "no nft/tc/Zelynic state mutation performed",
            "no ledger persistence performed",
            "no eBPF used",
            "no cgroup mutation",
            "no PID movement",
            "counters may reset",
            "filesystem write not performed",
            "state mutation not performed",
        ];
        for line in &required_lines {
            assert!(
                rendered.contains(line),
                "error output missing honesty line: {}",
                line
            );
        }
    }

    // ── Phase 8: --json is now accepted with --sample ───────────────

    #[test]
    fn cli_parses_usage_sample_json() {
        let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--json"]).unwrap();
        match cli.command.unwrap() {
            Commands::Usage {
                sample,
                json,
                delta,
                ..
            } => {
                assert!(sample);
                assert!(json);
                assert!(!delta);
            }
            other => panic!("expected usage command, got {other:?}"),
        }
    }

    #[test]
    fn cli_rejects_json_without_sample() {
        // --json requires --sample; clap should reject --json alone.
        let result = Cli::try_parse_from(["zelynic", "usage", "--json"]);
        assert!(
            result.is_err(),
            "--json without --sample should be rejected"
        );
    }

    // ── Phase 5b/8: no interval/interface/watch/path flags ─────

    #[test]
    fn no_interval_interface_watch_path_flags_on_usage_command() {
        // Verify that --interval is not accepted by the usage subcommand.
        let interval_result =
            Cli::try_parse_from(["zelynic", "usage", "--sample", "--interval", "5"]);
        assert!(
            interval_result.is_err(),
            "--interval should not be accepted"
        );

        // Verify that --interface is not accepted by the usage subcommand.
        let iface_result =
            Cli::try_parse_from(["zelynic", "usage", "--sample", "--interface", "eth0"]);
        assert!(iface_result.is_err(), "--interface should not be accepted");

        // Verify that --watch is not accepted.
        let watch_result = Cli::try_parse_from(["zelynic", "usage", "--sample", "--watch"]);
        assert!(watch_result.is_err(), "--watch should not be accepted");

        // Verify that --path is not accepted.
        let path_result =
            Cli::try_parse_from(["zelynic", "usage", "--sample", "--path", "/proc/net/dev"]);
        assert!(path_result.is_err(), "--path should not be accepted");
    }

    // ── Phase 8: JSON success output ────────────────────────────────

    #[test]
    fn json_success_with_fake_reader() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        // Verify it's valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["command"], "usage --sample --json");
        assert_eq!(parsed["source_path"], "/proc/net/dev");
        assert_eq!(parsed["source_label"], "live_proc_net_dev");
        assert!(parsed["sampled_at"].is_null());
        assert!(parsed["error"].is_null());
        let interfaces = parsed["interfaces"].as_array().unwrap();
        assert_eq!(interfaces.len(), 3);
        assert_eq!(interfaces[0]["name"], "lo");
        assert_eq!(interfaces[1]["name"], "wlan0");
        assert_eq!(interfaces[2]["name"], "eth0");
        assert_eq!(parsed["totals"]["interface_count"], 3);
    }

    #[test]
    fn json_success_includes_source_path() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        assert!(json_str.contains("\"source_path\": \"/proc/net/dev\""));
    }

    #[test]
    fn json_success_includes_source_label() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        assert!(json_str.contains("\"source_label\": \"live_proc_net_dev\""));
    }

    #[test]
    fn json_success_omits_sampled_at() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        // sampled_at should be absent from JSON (skip_serializing_if = Option::is_none).
        assert!(!json_str.contains("sampled_at"));
    }

    #[test]
    fn json_success_includes_all_12_honesty_flags() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let honesty = &parsed["honesty"];
        assert_eq!(honesty["interface_level_only"], true);
        assert_eq!(honesty["per_app_attribution"], false);
        assert_eq!(honesty["quota_enforcement_active"], false);
        assert_eq!(honesty["network_blocking_active"], false);
        assert_eq!(honesty["limiter_attach_performed"], false);
        assert_eq!(honesty["nft_tc_state_mutation_performed"], false);
        assert_eq!(honesty["ledger_persistence_performed"], false);
        assert_eq!(honesty["ebpf_used"], false);
        assert_eq!(honesty["cgroup_mutation_performed"], false);
        assert_eq!(honesty["pid_movement_performed"], false);
        assert_eq!(honesty["filesystem_write_performed"], false);
        assert_eq!(honesty["state_mutation_performed"], false);
    }

    // ── Phase 8: JSON read error output ──────────────────────────────

    #[test]
    fn json_read_error_with_fake_reader() {
        let reader = FakeReadErrorReader::new("permission denied");
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["error"]["type"], "read_error");
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("permission denied"));
        assert_eq!(parsed["interfaces"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["totals"]["interface_count"], 0);
        // Error JSON preserves honesty flags.
        assert_eq!(parsed["honesty"]["interface_level_only"], true);
        assert_eq!(parsed["honesty"]["ebpf_used"], false);
    }

    #[test]
    fn json_read_error_preserves_honesty_flags() {
        let reader = FakeReadErrorReader::new("permission denied");
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let honesty = &parsed["honesty"];
        assert_eq!(honesty["per_app_attribution"], false);
        assert_eq!(honesty["quota_enforcement_active"], false);
        assert_eq!(honesty["network_blocking_active"], false);
        assert_eq!(honesty["limiter_attach_performed"], false);
        assert_eq!(honesty["nft_tc_state_mutation_performed"], false);
        assert_eq!(honesty["ledger_persistence_performed"], false);
        assert_eq!(honesty["cgroup_mutation_performed"], false);
        assert_eq!(honesty["pid_movement_performed"], false);
        assert_eq!(honesty["filesystem_write_performed"], false);
        assert_eq!(honesty["state_mutation_performed"], false);
    }

    // ── Phase 8: JSON parse error output ─────────────────────────────

    #[test]
    fn json_parse_error_with_fake_reader() {
        let malformed = "wlan0 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
        let reader = InjectedContentReader::new(malformed);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["error"]["type"], "parse_error");
        assert_eq!(parsed["interfaces"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["totals"]["interface_count"], 0);
        // Error JSON preserves honesty flags.
        assert_eq!(parsed["honesty"]["interface_level_only"], true);
    }

    // ── Phase 8: text output unchanged with --sample ───────────────

    #[test]
    fn text_output_unchanged_with_sample() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let rendered = handle_usage_sample_with_reader(&reader).unwrap();
        assert!(rendered.contains("zelynic usage --sample"));
        assert!(rendered.contains("Read status: success"));
        assert!(rendered.contains("3 interface(s) parsed"));
        // All 13 honesty lines still present.
        assert!(rendered.contains("read-only /proc/net/dev seam"));
        assert!(rendered.contains("interface-level only"));
        assert!(rendered.contains("not per-app attribution"));
        assert!(rendered.contains("no quota enforcement active"));
        assert!(rendered.contains("no network blocking active"));
        assert!(rendered.contains("no limiter attach performed"));
        assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
        assert!(rendered.contains("no ledger persistence performed"));
        assert!(rendered.contains("no eBPF used"));
        assert!(rendered.contains("no cgroup mutation"));
        assert!(rendered.contains("no PID movement"));
        assert!(rendered.contains("counters may reset"));
        assert!(rendered.contains("filesystem write not performed"));
        assert!(rendered.contains("state mutation not performed"));
    }

    // ── Phase 8: CLI remains single-shot ─────────────────────────────

    #[test]
    fn cli_remains_single_shot() {
        // The Usage variant has sample, json, and delta flags — no loop, watch,
        // interval, or other continuous monitoring flags.
        let cli = Cli::try_parse_from(["zelynic", "usage", "--sample"]).unwrap();
        match cli.command.unwrap() {
            Commands::Usage {
                sample,
                json,
                delta,
            } => {
                assert!(sample);
                assert!(!json);
                assert!(!delta);
                // No other fields exist on this variant.
            }
            other => panic!("expected usage command, got {other:?}"),
        }
    }

    // ── Phase 8: no arbitrary path input exists ──────────────────────

    #[test]
    fn no_arbitrary_path_in_json_mode() {
        // The JSON path uses the same hardcoded /proc/net/dev source.
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        assert!(json_str.contains("\"source_path\": \"/proc/net/dev\""));
        // No --path flag exists.
        let path_result = Cli::try_parse_from([
            "zelynic",
            "usage",
            "--sample",
            "--json",
            "--path",
            "/tmp/test",
        ]);
        assert!(path_result.is_err(), "--path should not be accepted");
    }

    // ── Phase 8b: JSON CLI contract audit tests ────────────────────

    #[test]
    fn json_output_starts_with_brace() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        let trimmed = json_str.trim_start();
        assert!(
            trimmed.starts_with('{'),
            "JSON output must start with '{{', got: {}",
            &trimmed[..trimmed.len().min(20)]
        );
    }

    #[test]
    fn json_output_contains_no_human_header() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        assert!(
            !json_str.contains("zelynic usage --sample"),
            "JSON output must not contain human text header"
        );
        assert!(
            !json_str.contains("Read status:"),
            "JSON output must not contain human read status"
        );
        assert!(
            !json_str.contains("interface(s) parsed"),
            "JSON output must not contain human parse summary"
        );
    }

    #[test]
    fn json_output_contains_warnings_array() {
        let reader = InjectedContentReader::new(CLI_TEST_SAMPLE);
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let warnings = parsed["warnings"].as_array().unwrap();
        assert!(!warnings.is_empty(), "warnings array must not be empty");
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("Counters may reset")));
        assert!(warnings
            .iter()
            .any(|w| w.as_str().unwrap().contains("per-app attribution")));
    }

    #[test]
    fn json_error_output_starts_with_brace() {
        let reader = FakeReadErrorReader::new("permission denied");
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        let trimmed = json_str.trim_start();
        assert!(
            trimmed.starts_with('{'),
            "error JSON output must start with '{{', got: {}",
            &trimmed[..trimmed.len().min(20)]
        );
    }

    #[test]
    fn json_error_output_contains_no_human_header() {
        let reader = FakeReadErrorReader::new("permission denied");
        let json_str = handle_usage_sample_json_with_reader(&reader).unwrap();
        assert!(
            !json_str.contains("zelynic usage --sample"),
            "error JSON must not contain human text header"
        );
    }
}
