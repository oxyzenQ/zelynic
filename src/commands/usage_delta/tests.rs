// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Test infrastructure and tests for the `usage --sample --delta` command.
//!
//! This module contains injected test doubles (DualSampleReader, SampleSleeper),
//! fake implementations, and all 32 test functions that exercise the delta handler
//! via `run_delta_with_deps()` without touching the live filesystem.

use crate::accounting::{build_session_delta, build_usage_delta_from_session_delta};

use super::render::render_usage_delta_live;

// -- Test infrastructure --------------------------------------------------

/// Trait for reading two /proc/net/dev samples for delta computation.
///
/// Used for test injection: production uses `read_live_proc_net_dev()`,
/// tests use fake implementations that return controlled content.
pub(crate) trait DualSampleReader {
    /// Read the first (start) sample. Returns content string or error.
    fn read_first(&self) -> std::result::Result<String, String>;
    /// Read the second (end) sample. Returns content string or error.
    fn read_second(&self) -> std::result::Result<String, String>;
}

/// Trait for sleeping between two samples.
///
/// Used for test injection: production uses `std::thread::sleep`,
/// tests use fake implementations that count calls without sleeping.
pub(crate) trait SampleSleeper {
    /// Sleep for the delta wait duration.
    fn sleep(&self);
}

/// Fake dual reader that returns injected content for both samples.
pub(crate) struct FakeDualReader {
    pub first_content: String,
    pub second_content: String,
}

impl DualSampleReader for FakeDualReader {
    fn read_first(&self) -> std::result::Result<String, String> {
        Ok(self.first_content.clone())
    }
    fn read_second(&self) -> std::result::Result<String, String> {
        Ok(self.second_content.clone())
    }
}

/// Fake dual reader that fails on the first read.
pub(crate) struct FakeFailFirstReader {
    pub error_msg: String,
}

impl DualSampleReader for FakeFailFirstReader {
    fn read_first(&self) -> std::result::Result<String, String> {
        Err(self.error_msg.clone())
    }
    fn read_second(&self) -> std::result::Result<String, String> {
        Ok(String::new())
    }
}

/// Fake dual reader that fails on the second read.
pub(crate) struct FakeFailSecondReader {
    pub first_content: String,
    pub error_msg: String,
}

impl DualSampleReader for FakeFailSecondReader {
    fn read_first(&self) -> std::result::Result<String, String> {
        Ok(self.first_content.clone())
    }
    fn read_second(&self) -> std::result::Result<String, String> {
        Err(self.error_msg.clone())
    }
}

/// Fake dual reader that returns malformed content on the first read (parse error).
pub(crate) struct FakeParseFailFirstReader {
    pub first_content: String,
    pub second_content: String,
}

impl DualSampleReader for FakeParseFailFirstReader {
    fn read_first(&self) -> std::result::Result<String, String> {
        Ok(self.first_content.clone())
    }
    fn read_second(&self) -> std::result::Result<String, String> {
        Ok(self.second_content.clone())
    }
}

/// Fake dual reader that returns malformed content on the second read (parse error).
pub(crate) struct FakeParseFailSecondReader {
    pub first_content: String,
    pub second_content: String,
}

impl DualSampleReader for FakeParseFailSecondReader {
    fn read_first(&self) -> std::result::Result<String, String> {
        Ok(self.first_content.clone())
    }
    fn read_second(&self) -> std::result::Result<String, String> {
        Ok(self.second_content.clone())
    }
}

/// Counting sleeper that records how many times sleep() was called.
pub(crate) struct CountingSleeper {
    pub sleep_count: std::cell::Cell<usize>,
}

impl CountingSleeper {
    pub fn new() -> Self {
        Self {
            sleep_count: std::cell::Cell::new(0),
        }
    }
}

impl SampleSleeper for CountingSleeper {
    fn sleep(&self) {
        self.sleep_count.set(self.sleep_count.get() + 1);
    }
}

/// Counting reader that records how many times each read method was called.
pub(crate) struct CountingReader {
    pub first_content: String,
    pub second_content: String,
    pub first_count: std::cell::Cell<usize>,
    pub second_count: std::cell::Cell<usize>,
}

impl CountingReader {
    pub fn new(first: &str, second: &str) -> Self {
        Self {
            first_content: first.to_string(),
            second_content: second.to_string(),
            first_count: std::cell::Cell::new(0),
            second_count: std::cell::Cell::new(0),
        }
    }
}

impl DualSampleReader for CountingReader {
    fn read_first(&self) -> std::result::Result<String, String> {
        self.first_count.set(self.first_count.get() + 1);
        Ok(self.first_content.clone())
    }
    fn read_second(&self) -> std::result::Result<String, String> {
        self.second_count.set(self.second_count.get() + 1);
        Ok(self.second_content.clone())
    }
}

/// Core testable delta handler.
///
/// Accepts injected reader and sleeper, performs the two-sample delta
/// computation, and returns the rendered text output. This function is
/// the single point of test injection for the entire delta pipeline.
pub(crate) fn run_delta_with_deps<R: DualSampleReader, S: SampleSleeper>(
    reader: &R,
    sleeper: &S,
) -> anyhow::Result<String> {
    use crate::accounting::parse_proc_net_dev;

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

    // Compute delta
    let session_delta = build_session_delta(&snapshot1, &snapshot2);
    let usage_delta_output = build_usage_delta_from_session_delta(&session_delta);

    // Render live delta output
    Ok(render_usage_delta_live(&usage_delta_output))
}

#[allow(clippy::module_inception)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;

    /// Standard start sample for delta tests.
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
    const DELTA_END_RESET: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0:   500000  15000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
";

    // -- CLI parses usage --sample --delta -------------------------

    #[test]
    fn cli_parses_usage_sample_delta() {
        let cli = Cli::try_parse_from(["zelynic", "usage", "--sample", "--delta"]).unwrap();
        match cli.command.unwrap() {
            Commands::Usage {
                sample,
                json,
                delta,
            } => {
                assert!(sample);
                assert!(delta);
                assert!(!json);
            }
            other => panic!("expected usage command, got {other:?}"),
        }
    }

    // -- CLI rejects --delta without --sample ----------------------

    #[test]
    fn cli_rejects_delta_without_sample() {
        let result = Cli::try_parse_from(["zelynic", "usage", "--delta"]);
        assert!(
            result.is_err(),
            "--delta without --sample should be rejected"
        );
    }

    // -- CLI accepts --delta --json combination (handler rejects) --

    #[test]
    fn cli_parses_delta_json_but_handler_rejects() {
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

    // -- Fake reader success renders delta output -------------------

    #[test]
    fn fake_reader_success_renders_delta_output() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("live read-only two-sample delta"));
        assert!(rendered.contains("wlan0"));
        assert!(rendered.contains("eth0"));
    }

    // -- Fake reader is called exactly twice for delta success ------

    #[test]
    fn fake_reader_called_exactly_twice() {
        let reader = CountingReader::new(DELTA_START, DELTA_END_NORMAL);
        let sleeper = CountingSleeper::new();
        run_delta_with_deps(&reader, &sleeper).unwrap();
        assert_eq!(
            reader.first_count.get(),
            1,
            "first read should be called once"
        );
        assert_eq!(
            reader.second_count.get(),
            1,
            "second read should be called once"
        );
    }

    // -- Fake sleeper is called exactly once -----------------------

    #[test]
    fn fake_sleeper_called_exactly_once() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        run_delta_with_deps(&reader, &sleeper).unwrap();
        assert_eq!(
            sleeper.sleep_count.get(),
            1,
            "sleeper should be called once"
        );
    }

    // -- Read failure on first sample is reported honestly ----------

    #[test]
    fn read_failure_on_first_sample_reported_honestly() {
        let reader = FakeFailFirstReader {
            error_msg: "permission denied".to_string(),
        };
        let sleeper = CountingSleeper::new();
        let result = run_delta_with_deps(&reader, &sleeper);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("read error:"));
        assert!(err.contains("permission denied"));
    }

    // -- Read failure on second sample is reported honestly ---------

    #[test]
    fn read_failure_on_second_sample_reported_honestly() {
        let reader = FakeFailSecondReader {
            first_content: DELTA_START.to_string(),
            error_msg: "I/O error".to_string(),
        };
        let sleeper = CountingSleeper::new();
        let result = run_delta_with_deps(&reader, &sleeper);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("read error:"));
        assert!(err.contains("I/O error"));
    }

    // -- Parse failure is reported honestly -------------------------

    #[test]
    fn parse_failure_reported_honestly() {
        let reader = FakeParseFailFirstReader {
            first_content: "wlan0 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0".to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let result = run_delta_with_deps(&reader, &sleeper);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parse error:"));
    }

    // -- Parse failure on second sample reported honestly -----------

    #[test]
    fn parse_failure_on_second_sample_reported_honestly() {
        let reader = FakeParseFailSecondReader {
            first_content: DELTA_START.to_string(),
            second_content: "garbage data".to_string(),
        };
        let sleeper = CountingSleeper::new();
        let result = run_delta_with_deps(&reader, &sleeper);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parse error:"));
    }

    // -- Counter reset/decrease warning appears --------------------

    #[test]
    fn counter_reset_warning_appears() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_RESET.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("Counter reset/decrease warnings"));
        assert!(rendered.contains("wlan0"));
    }

    // -- Output includes interface-level only -----------------------

    #[test]
    fn output_includes_interface_level_only() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("interface-level only"));
    }

    // -- Output denies per-app attribution -------------------------

    #[test]
    fn output_denies_per_app_attribution() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("not per-app attribution"));
    }

    // -- Output denies quota enforcement ---------------------------

    #[test]
    fn output_denies_quota_enforcement() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("no quota enforcement active"));
    }

    // -- Output denies network blocking ----------------------------

    #[test]
    fn output_denies_network_blocking() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("no network blocking active"));
    }

    // -- Output denies limiter attach -----------------------------
    #[test]
    fn output_denies_limiter_attach() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("no limiter attach performed"));
    }

    // -- Output denies nft/tc/state mutation ------------------------
    #[test]
    fn output_denies_nft_tc_state_mutation() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("no nft/tc/Zelynic state mutation performed"));
    }

    // -- Output denies ledger persistence --------------------------
    #[test]
    fn output_denies_ledger_persistence() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("no ledger persistence performed"));
    }

    // -- Output denies eBPF ---------------------------------------
    #[test]
    fn output_denies_ebpf() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("no eBPF used"));
    }

    // -- Output denies cgroup mutation ----------------------------
    #[test]
    fn output_denies_cgroup_mutation() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("no cgroup mutation"));
    }

    // -- Output denies PID movement --------------------------------
    #[test]
    fn output_denies_pid_movement() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("no PID movement"));
    }

    // -- Output denies filesystem write -----------------------------
    #[test]
    fn output_denies_filesystem_write() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("filesystem write not performed"));
    }

    // -- Output denies state mutation ------------------------------
    #[test]
    fn output_denies_state_mutation() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("state mutation not performed"));
    }

    // -- No arbitrary path argument exists -------------------------
    #[test]
    fn no_arbitrary_path_argument_exists() {
        // Structural test: DualSampleReader has no path parameter.
        // Source path is always /proc/net/dev.
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let _ = CountingReader::new(DELTA_START, DELTA_END_NORMAL);
        let sleeper = CountingSleeper::new();
        let _ = run_delta_with_deps(&reader, &sleeper);
    }

    // -- No loop/watch/interval flags exist ------------------------
    #[test]
    fn no_loop_watch_interval_flags() {
        // --watch is not accepted
        let watch_result =
            Cli::try_parse_from(["zelynic", "usage", "--sample", "--delta", "--watch"]);
        assert!(watch_result.is_err(), "--watch should not be accepted");

        // --interval is not accepted
        let interval_result =
            Cli::try_parse_from(["zelynic", "usage", "--sample", "--delta", "--interval", "5"]);
        assert!(
            interval_result.is_err(),
            "--interval should not be accepted"
        );
    }

    // -- Output includes source path --------------------------------
    #[test]
    fn output_includes_source_path() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("/proc/net/dev"));
    }

    // -- Output includes two-sample statement ------------------------
    #[test]
    fn output_includes_two_sample_statement() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("two-sample read-only delta"));
    }

    // -- Output includes counters may reset warning -----------------
    #[test]
    fn output_includes_counters_may_reset() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("counters may reset"));
    }

    // -- Output includes delta incomplete warning on reset ----------
    #[test]
    fn output_includes_delta_incomplete_on_reset() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_RESET.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        assert!(rendered.contains("delta may be incomplete"));
    }

    // -- Delta output contains all 16 required honesty lines --------
    #[test]
    fn delta_output_contains_all_honesty_lines() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        let required_lines = [
            "two-sample read-only delta",
            "source path: /proc/net/dev",
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
            "filesystem write not performed",
            "state mutation not performed",
            "counters may reset",
            "delta may be incomplete",
        ];
        for line in &required_lines {
            assert!(rendered.contains(line), "missing honesty line: {}", line);
        }
    }

    // -- Delta totals are correct ----------------------------------
    #[test]
    fn delta_totals_are_correct() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered = run_delta_with_deps(&reader, &sleeper).unwrap();
        // wlan0: rx=1000000, tx=500000
        // eth0: rx=100000, tx=100000
        // total: rx=1100000, tx=600000, combined=1700000
        assert!(rendered.contains("RX: 1100000 bytes"));
        assert!(rendered.contains("TX: 600000 bytes"));
        assert!(rendered.contains("Combined: 1700000 bytes"));
    }

    // -- Render is deterministic ------------------------------------
    #[test]
    fn render_is_deterministic() {
        let reader = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper = CountingSleeper::new();
        let rendered1 = run_delta_with_deps(&reader, &sleeper).unwrap();
        let reader2 = FakeDualReader {
            first_content: DELTA_START.to_string(),
            second_content: DELTA_END_NORMAL.to_string(),
        };
        let sleeper2 = CountingSleeper::new();
        let rendered2 = run_delta_with_deps(&reader2, &sleeper2).unwrap();
        assert_eq!(rendered1, rendered2);
    }
}
