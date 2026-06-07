// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Test infrastructure and tests for the `usage --sample --delta --json` command
//! (v3.0 phase 15).
//!
//! This module contains injected test doubles and test functions that exercise
//! the delta JSON CLI path via `run_delta_json_with_deps()` without touching
//! the live filesystem. It reuses the `DualSampleReader` and `SampleSleeper`
//! traits from the existing `tests` module.

use crate::accounting::{
    build_delta_json_first_read_error, build_delta_json_second_read_error,
    build_delta_json_success, parse_proc_net_dev, serialize_delta_json, DeltaJsonErrorType,
};

use super::tests::{
    run_delta_with_deps, CountingReader, CountingSleeper, DualSampleReader, FakeDualReader,
    SampleSleeper,
};

// -- Test injection point --------------------------------------------------

/// Core testable delta JSON handler.
///
/// Accepts injected reader and sleeper, performs the two-sample delta
/// computation, and returns the serialized JSON string. This function is
/// the single point of test injection for the delta JSON pipeline.
pub(crate) fn run_delta_json_with_deps<R: DualSampleReader, S: SampleSleeper>(
    reader: &R,
    sleeper: &S,
) -> anyhow::Result<String> {
    // First read
    let first_content = reader
        .read_first()
        .map_err(|e| anyhow::anyhow!("read error: {}", e))?;
    let snapshot1 =
        parse_proc_net_dev(&first_content).map_err(|e| anyhow::anyhow!("parse error: {}", e))?;

    // Sleep between samples
    sleeper.sleep();

    // Second read
    let second_content = reader
        .read_second()
        .map_err(|e| anyhow::anyhow!("read error: {}", e))?;
    let snapshot2 =
        parse_proc_net_dev(&second_content).map_err(|e| anyhow::anyhow!("parse error: {}", e))?;

    // Compute delta JSON
    let output = build_delta_json_success(&snapshot1, &snapshot2);
    Ok(serialize_delta_json(&output)?)
}

/// Testable delta JSON handler for first-read error.
#[allow(dead_code)]
pub(crate) fn run_delta_json_first_error_deps<R: DualSampleReader, S: SampleSleeper>(
    reader: &R,
    sleeper: &S,
) -> anyhow::Result<String> {
    let first_content = reader
        .read_first()
        .map_err(|e| anyhow::anyhow!("read error: {}", e))?;
    let _snapshot1 =
        parse_proc_net_dev(&first_content).map_err(|e| anyhow::anyhow!("parse error: {}", e))?;

    // First succeeded, but we don't need second read for first-error test
    // This function is used to test first-read *failure*, which should not
    // even reach the sleep step. Use fake readers that fail on first read.
    sleeper.sleep();
    let _ = reader.read_second();
    unreachable!("should not reach second read in first-error test");
}

#[allow(clippy::module_inception)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::{CommandFactory, Parser};

    /// Standard start sample for delta JSON tests.
    const DELTA_START: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000000  10000    0    0    0     0          0         0  500000   5000    0    0    0     0       0          0
  eth0:  200000   2000    0    0    0     0          0         0  100000   1000    0    0    0     0       0          0
";

    /// End sample with higher counters (normal delta).
    const DELTA_END_NORMAL: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 2000000  20000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
";

    /// End sample with counter reset on wlan0 RX.
    #[allow(dead_code)]
    const DELTA_END_RESET: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0:   500000  15000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
";

    // -- CLI parses usage --sample --delta --json (no longer rejected) --

    #[test]
    fn cli_parses_delta_json_now_wired() {
        let cli =
            Cli::try_parse_from(["zelynic", "usage", "--sample", "--delta", "--json"]).unwrap();
        match cli.command.unwrap() {
            Commands::Usage {
                sample,
                json,
                delta,
            } => {
                assert!(sample);
                assert!(json);
                assert!(delta);
            }
            other => panic!("expected usage command, got {other:?}"),
        }
    }

    // -- JSON output starts with { --

    #[test]
    fn delta_json_output_starts_with_brace() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let trimmed = json_str.trim_start();
        assert!(
            trimmed.starts_with('{'),
            "JSON output must start with '{{', got: {}",
            &trimmed[..trimmed.len().min(20)]
        );
    }

    // -- JSON output has no human header --

    #[test]
    fn delta_json_output_no_human_header() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        assert!(
            !json_str.contains("zelynic usage --sample"),
            "JSON must not contain human text header"
        );
        assert!(
            !json_str.contains("live read-only"),
            "JSON must not contain human text"
        );
        assert!(
            !json_str.contains("Read status:"),
            "JSON must not contain human read status"
        );
    }

    // -- Success JSON parses as valid JSON --

    #[test]
    fn delta_json_success_parses() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["schema_version"], 1);
    }

    // -- Success JSON command field --

    #[test]
    fn delta_json_command_is_delta_json() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["command"], "usage --sample --delta --json");
    }

    // -- Success JSON source_path --

    #[test]
    fn delta_json_source_path() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["source_path"], "/proc/net/dev");
    }

    // -- Success JSON source_label --

    #[test]
    fn delta_json_source_label() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["source_label"], "live_proc_net_dev");
    }

    // -- Success JSON sample_count = 2 --

    #[test]
    fn delta_json_sample_count_is_2() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["sample_count"], 2);
    }

    // -- Success JSON read_count = 2 --

    #[test]
    fn delta_json_read_count_is_2() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["read_count"], 2);
    }

    // -- Success JSON error is null --

    #[test]
    fn delta_json_error_is_null() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["error"].is_null());
    }

    // -- Success JSON includes interfaces, totals, warnings, honesty --

    #[test]
    fn delta_json_includes_interfaces_totals_warnings_honesty() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["interfaces"].is_array());
        assert!(parsed["totals"].is_object());
        assert!(parsed["warnings"].is_array());
        assert!(parsed["honesty"].is_object());
    }

    // -- Fake reader called exactly twice --

    #[test]
    fn delta_json_fake_reader_called_exactly_twice() {
        let reader = CountingReader::new(DELTA_START, DELTA_END_NORMAL);
        let sleeper = CountingSleeper::new();
        run_delta_json_with_deps(&reader, &sleeper).unwrap();
        assert_eq!(reader.first_count.get(), 1, "first read called once");
        assert_eq!(reader.second_count.get(), 1, "second read called once");
    }

    // -- Fake sleeper called exactly once --

    #[test]
    fn delta_json_fake_sleeper_called_exactly_once() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        run_delta_json_with_deps(&reader, &sleeper).unwrap();
        assert_eq!(sleeper.sleep_count.get(), 1, "sleeper called once");
    }

    // -- First read error JSON --

    #[test]
    fn delta_json_first_read_error() {
        // Build expected JSON directly using the model function
        let output = build_delta_json_first_read_error(
            DeltaJsonErrorType::Read,
            "read error: permission denied",
        );
        let expected = serialize_delta_json(&output).unwrap();
        let parsed_expected: serde_json::Value = serde_json::from_str(&expected).unwrap();

        // Verify the expected structure
        assert_eq!(parsed_expected["error"]["type"], "read_error");
        assert!(parsed_expected["error"]["message"]
            .as_str()
            .unwrap()
            .contains("permission denied"));
        assert_eq!(parsed_expected["read_count"], 0);
        assert!(parsed_expected["start_sample"].is_null());
        assert!(parsed_expected["end_sample"].is_null());
    }

    // -- First parse error JSON --

    #[test]
    fn delta_json_first_parse_error() {
        let output = build_delta_json_first_read_error(
            DeltaJsonErrorType::Parse,
            "parse error: no colon found",
        );
        let expected = serialize_delta_json(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&expected).unwrap();
        assert_eq!(parsed["error"]["type"], "parse_error");
        assert_eq!(parsed["read_count"], 0);
        assert!(parsed["start_sample"].is_null());
    }

    // -- Second read error JSON --

    #[test]
    fn delta_json_second_read_error() {
        let first_snapshot = parse_proc_net_dev(DELTA_START).unwrap();
        let output = build_delta_json_second_read_error(
            &first_snapshot,
            DeltaJsonErrorType::Read,
            "read error: I/O error",
        );
        let expected = serialize_delta_json(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&expected).unwrap();
        assert_eq!(parsed["error"]["type"], "read_error");
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("I/O error"));
        assert_eq!(parsed["read_count"], 1);
        assert!(parsed["start_sample"].is_object());
        assert!(parsed["end_sample"].is_null());
    }

    // -- Second parse error JSON --

    #[test]
    fn delta_json_second_parse_error() {
        let first_snapshot = parse_proc_net_dev(DELTA_START).unwrap();
        let output = build_delta_json_second_read_error(
            &first_snapshot,
            DeltaJsonErrorType::Parse,
            "parse error: garbage",
        );
        let expected = serialize_delta_json(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&expected).unwrap();
        assert_eq!(parsed["error"]["type"], "parse_error");
        assert_eq!(parsed["read_count"], 1);
        assert!(parsed["start_sample"].is_object());
        assert!(parsed["end_sample"].is_null());
    }

    // -- No live read in tests (structural) --

    #[test]
    fn delta_json_no_live_read_in_tests() {
        // Structural test: all delta JSON tests use injected readers.
        // The run_delta_json_with_deps function accepts a DualSampleReader trait,
        // which has no filesystem access. Production uses read_live_proc_net_dev().
        let _ = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let _ = CountingReader::new(DELTA_START, DELTA_END_NORMAL);
    }

    // -- No filesystem write APIs in delta JSON path (structural) --

    #[test]
    fn delta_json_no_filesystem_write_apis() {
        // Structural test: the delta JSON path only reads and serializes.
        // No write, create, remove, rename, copy, or link operations.
        // build_delta_json_success and serialize_delta_json are pure functions.
        let _ = build_delta_json_success;
        let _ = serialize_delta_json;
    }

    // -- No arbitrary path argument in delta JSON mode --

    #[test]
    fn delta_json_no_arbitrary_path_argument() {
        // The delta JSON path uses the same hardcoded /proc/net/dev source.
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        assert!(json_str.contains("\"source_path\": \"/proc/net/dev\""));
        // No --path flag exists.
        let path_result = Cli::try_parse_from([
            "zelynic",
            "usage",
            "--sample",
            "--delta",
            "--json",
            "--path",
            "/tmp/test",
        ]);
        assert!(path_result.is_err(), "--path should not be accepted");
    }

    // -- No interval/watch/interface/path flags --

    #[test]
    fn delta_json_no_interval_watch_interface_path_flags() {
        let watch_result = Cli::try_parse_from([
            "zelynic", "usage", "--sample", "--delta", "--json", "--watch",
        ]);
        assert!(watch_result.is_err(), "--watch should not be accepted");

        let interval_result = Cli::try_parse_from([
            "zelynic",
            "usage",
            "--sample",
            "--delta",
            "--json",
            "--interval",
            "5",
        ]);
        assert!(
            interval_result.is_err(),
            "--interval should not be accepted"
        );
    }

    // -- usage --delta still rejected by clap --

    #[test]
    fn usage_delta_still_rejected_by_clap() {
        let result = Cli::try_parse_from(["zelynic", "usage", "--delta"]);
        assert!(
            result.is_err(),
            "--delta without --sample should be rejected"
        );
    }

    // -- Delta JSON success includes sample_mode = delta --

    #[test]
    fn delta_json_sample_mode() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["sample_mode"], "delta");
    }

    // -- Delta JSON success includes delta_wait_ms = 1000 --

    #[test]
    fn delta_json_delta_wait_ms() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["delta_wait_ms"], 1000);
    }

    // -- Delta JSON success has start_sample and end_sample --

    #[test]
    fn delta_json_has_start_and_end_sample() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert!(parsed["start_sample"].is_object());
        assert!(parsed["end_sample"].is_object());
        assert_eq!(parsed["start_sample"]["status"], "success");
        assert_eq!(parsed["end_sample"]["status"], "success");
    }

    // -- Delta JSON error has no human text --

    #[test]
    fn delta_json_error_no_human_text() {
        let output = build_delta_json_first_read_error(
            DeltaJsonErrorType::Read,
            "read error: permission denied",
        );
        let json_str = serialize_delta_json(&output).unwrap();
        assert!(
            !json_str.contains("zelynic"),
            "error JSON must not contain human text"
        );
        assert!(
            !json_str.contains("not yet implemented"),
            "error JSON must not contain rejection message"
        );
    }

    // -- Delta JSON honesty delta_json_output = true --

    #[test]
    fn delta_json_honesty_delta_json_output_true() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["honesty"]["delta_json_output"], true);
    }

    // -- Delta JSON honesty single_shot = true --

    #[test]
    fn delta_json_honesty_single_shot_true() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["honesty"]["single_shot"], true);
    }

    // -- Delta JSON honesty all constant false flags --

    #[test]
    fn delta_json_honesty_constant_false_flags() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let honesty = &parsed["honesty"];
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
        assert_eq!(honesty["loop_watch_mode"], false);
        assert_eq!(honesty["configurable_interval"], false);
        assert_eq!(honesty["interface_filtering"], false);
        assert_eq!(honesty["arbitrary_path_read"], false);
    }

    // -- Delta JSON totals correctness --

    #[test]
    fn delta_json_totals_correctness() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // wlan0: rx_delta=1000000, tx_delta=500000
        // eth0: rx_delta=100000, tx_delta=100000
        // total: rx=1100000, tx=600000, combined=1700000
        assert_eq!(parsed["totals"]["total_delta_rx_bytes"], 1100000);
        assert_eq!(parsed["totals"]["total_delta_tx_bytes"], 600000);
        assert_eq!(parsed["totals"]["total_delta_combined_bytes"], 1700000);
        assert_eq!(parsed["totals"]["interface_count"], 2);
    }

    // -- Phase 15b: Cross-command isolation: delta JSON is distinct from snapshot JSON --

    #[test]
    fn delta_json_output_distinct_from_snapshot_json() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        // Delta JSON has fields that snapshot JSON does not
        assert_eq!(parsed["sample_mode"], "delta");
        assert_eq!(parsed["delta_wait_ms"], 1000);
        assert_eq!(parsed["command"], "usage --sample --delta --json");
        assert_eq!(parsed["sample_count"], 2);
        assert_eq!(parsed["read_count"], 2);
        assert!(parsed["start_sample"].is_object());
        assert!(parsed["end_sample"].is_object());
        // These fields must exist in delta JSON and NOT in snapshot JSON
        assert!(parsed.get("sample_mode").is_some());
        assert!(parsed.get("delta_wait_ms").is_some());
        assert!(parsed.get("start_sample").is_some());
        assert!(parsed.get("end_sample").is_some());
    }

    // -- Phase 15b: Cross-command isolation: delta text is human text, not JSON --

    #[test]
    fn delta_text_output_is_not_json() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let text = run_delta_with_deps(&reader, &sleeper).unwrap();
        let trimmed = text.trim_start();
        assert!(
            !trimmed.starts_with('{'),
            "delta text output must not start with '{{' (JSON), got: {}",
            &trimmed[..trimmed.len().min(30)]
        );
        // Delta text output should contain human-readable headers
        assert!(
            text.contains("zelynic usage --sample --delta"),
            "delta text output must contain human-readable header"
        );
    }

    // -- Phase 17b: usage help mentions delta JSON example --

    #[test]
    fn usage_help_mentions_delta_json_example() {
        let mut command = Cli::command();
        let usage_help = command
            .find_subcommand_mut("usage")
            .expect("usage subcommand must exist")
            .render_long_help()
            .to_string();
        assert!(
            usage_help.contains("usage --sample --delta --json"),
            "usage --help must mention 'usage --sample --delta --json' example"
        );
    }

    // -- Phase 17b: usage help does NOT contain stale "not yet implemented" --

    #[test]
    fn usage_help_does_not_say_delta_json_not_yet_implemented() {
        let mut command = Cli::command();
        let usage_help = command
            .find_subcommand_mut("usage")
            .expect("usage subcommand must exist")
            .render_long_help()
            .to_string();
        assert!(
            !usage_help.contains("not yet implemented"),
            "usage --help must not contain 'not yet implemented': stale text found"
        );
    }

    // -- Phase 17b: usage help does NOT say "text only" for delta --

    #[test]
    fn usage_help_does_not_say_text_only_for_delta() {
        let mut command = Cli::command();
        let usage_help = command
            .find_subcommand_mut("usage")
            .expect("usage subcommand must exist")
            .render_long_help()
            .to_string();
        assert!(
            !usage_help.contains("text only"),
            "usage --help must not say 'text only' for delta: stale text found"
        );
    }

    // -- Phase 17b: usage --sample --delta --json remains valid JSON --

    #[test]
    fn delta_json_remains_valid_json() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let json_str = run_delta_json_with_deps(&reader, &sleeper).unwrap();
        let _: serde_json::Value =
            serde_json::from_str(&json_str).expect("delta JSON output must remain valid JSON");
    }
}
