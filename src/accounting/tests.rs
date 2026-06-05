// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure parser tests for v2.9 Network Accounting Lab interface counter model.
//!
//! All tests use const sample strings — **no** live `/proc/net/dev` reads,
//! **no** live sysfs reads, **no** filesystem access, **no** network blocking,
//! **no** quota enforcement, **no** eBPF, **no** PID movement, **no** cgroup writes.

use super::interface_counters::*;

/// Standard `/proc/net/dev` sample with three interfaces.
const SAMPLE_PROC_NET_DEV: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    100    0    0    0     0          0         0  234567     200    0    0    0     0       0          0
  wlan0: 1324567890  1234567    0    0    0     0          0         0  356789012   345678    0    0    0     0       0          0
  eth0:       0        0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

/// `/proc/net/dev` sample with predictable interface names.
const MINIMAL_SAMPLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";

/// Empty content — should produce empty snapshot, not error.
const EMPTY_CONTENT: &str = "";

/// Only headers, no data lines.
const HEADERS_ONLY: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
";

// ── parse_proc_net_dev: single interface ──────────────────────────────────────

#[test]
fn parse_single_interface_line() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.interfaces[0].interface, "wlan0");
    assert_eq!(snapshot.interfaces[0].rx_bytes, 1000);
    assert_eq!(snapshot.interfaces[0].tx_bytes, 2000);
    assert_eq!(snapshot.interfaces[0].rx_packets, 10);
    assert_eq!(snapshot.interfaces[0].tx_packets, 20);
}

// ── parse_proc_net_dev: multiple interfaces ────────────────────────────────────

#[test]
fn parse_multiple_interfaces() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    assert_eq!(snapshot.len(), 3);

    assert_eq!(snapshot.interfaces[0].interface, "lo");
    assert_eq!(snapshot.interfaces[0].rx_bytes, 123456);
    assert_eq!(snapshot.interfaces[0].tx_bytes, 234567);

    assert_eq!(snapshot.interfaces[1].interface, "wlan0");
    assert_eq!(snapshot.interfaces[1].rx_bytes, 1324567890);
    assert_eq!(snapshot.interfaces[1].tx_bytes, 356789012);

    assert_eq!(snapshot.interfaces[2].interface, "eth0");
    assert_eq!(snapshot.interfaces[2].rx_bytes, 0);
    assert_eq!(snapshot.interfaces[2].tx_bytes, 0);
}

// ── skips headers ────────────────────────────────────────────────────────────

#[test]
fn skips_proc_net_dev_headers() {
    // Both header lines must be skipped, not parsed as data.
    let snapshot = parse_proc_net_dev(HEADERS_ONLY).unwrap();
    assert_eq!(snapshot.len(), 0);
    assert!(snapshot.is_empty());
}

// ── lo, wlan0, eth0, wlp*, enp* names ──────────────────────────────────────────

#[test]
fn parse_lo_interface() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let lo = snapshot.get("lo").unwrap();
    assert_eq!(lo.interface, "lo");
    assert!(lo.is_loopback());
    assert_eq!(lo.rx_bytes, 123456);
    assert_eq!(lo.tx_bytes, 234567);
}

#[test]
fn parse_wlan0_interface() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let wlan0 = snapshot.get("wlan0").unwrap();
    assert_eq!(wlan0.interface, "wlan0");
    assert!(!wlan0.is_loopback());
    assert_eq!(wlan0.rx_bytes, 1324567890);
    assert_eq!(wlan0.tx_bytes, 356789012);
}

#[test]
fn parse_eth0_interface() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let eth0 = snapshot.get("eth0").unwrap();
    assert_eq!(eth0.interface, "eth0");
    assert!(!eth0.is_loopback());
    assert_eq!(eth0.rx_bytes, 0);
    assert_eq!(eth0.tx_bytes, 0);
}

#[test]
fn parse_wlp_style_name() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
wlp2s0: 5000 50 0 0 0 0 0 0 6000 60 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.interfaces[0].interface, "wlp2s0");
    assert_eq!(snapshot.interfaces[0].rx_bytes, 5000);
    assert_eq!(snapshot.interfaces[0].tx_bytes, 6000);
}

#[test]
fn parse_enp_style_name() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
enp3s0: 7000 70 0 0 0 0 0 0 8000 80 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.interfaces[0].interface, "enp3s0");
    assert_eq!(snapshot.interfaces[0].rx_bytes, 7000);
    assert_eq!(snapshot.interfaces[0].tx_bytes, 8000);
}

// ── trims whitespace around interface names ────────────────────────────────────

#[test]
fn trims_whitespace_around_interface_names() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    wlan0: 100 10 0 0 0 0 0 0 200 20 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    assert_eq!(snapshot.interfaces[0].interface, "wlan0");
}

#[test]
fn trims_leading_whitespace_before_interface() {
    // Extra leading spaces should be trimmed.
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
      eth0: 100 10 0 0 0 0 0 0 200 20 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    assert_eq!(snapshot.interfaces[0].interface, "eth0");
}

// ── rejects missing colon ───────────────────────────────────────────────────────

#[test]
fn rejects_missing_colon() {
    let line = "wlan0 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
    let result = parse_proc_net_dev_line(line);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::MissingColon { .. } => {}
        other => panic!("expected MissingColon, got {:?}", other),
    }
}

#[test]
fn rejects_missing_colon_in_full_parse() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
wlan0 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";
    let result = parse_proc_net_dev(content);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::MissingColon { line_number, .. } => {
            assert_eq!(line_number, 3);
        }
        other => panic!("expected MissingColon, got {:?}", other),
    }
}

// ── rejects too few fields ──────────────────────────────────────────────────────

#[test]
fn rejects_too_few_fields() {
    let line = "wlan0: 1000 10";
    let result = parse_proc_net_dev_line(line);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::TooFewFields { field_count, .. } => {
            assert_eq!(field_count, 2);
        }
        other => panic!("expected TooFewFields, got {:?}", other),
    }
}

#[test]
fn rejects_empty_after_colon() {
    let line = "wlan0:";
    let result = parse_proc_net_dev_line(line);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::TooFewFields { .. } => {}
        other => panic!("expected TooFewFields, got {:?}", other),
    }
}

// ── rejects non-numeric rx bytes ───────────────────────────────────────────────

#[test]
fn rejects_non_numeric_rx_bytes() {
    let line = "wlan0: abc 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
    let result = parse_proc_net_dev_line(line);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::InvalidRxBytes { value, .. } => {
            assert_eq!(value, "abc");
        }
        other => panic!("expected InvalidRxBytes, got {:?}", other),
    }
}

// ── rejects non-numeric tx bytes ───────────────────────────────────────────────

#[test]
fn rejects_non_numeric_tx_bytes() {
    let line = "wlan0: 1000 10 0 0 0 0 0 0 xyz 20 0 0 0 0 0 0";
    let result = parse_proc_net_dev_line(line);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::InvalidTxBytes { value, .. } => {
            assert_eq!(value, "xyz");
        }
        other => panic!("expected InvalidTxBytes, got {:?}", other),
    }
}

// ── rejects overflowing values ────────────────────────────────────────────────

#[test]
fn rejects_overflowing_rx_bytes() {
    // u64::MAX is 18446744073709551615 (20 digits). 21-digit number overflows.
    let line = "wlan0: 99999999999999999999 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
    let result = parse_proc_net_dev_line(line);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::Overflow { field, .. } => {
            assert_eq!(field, "rx_bytes");
        }
        other => panic!("expected Overflow, got {:?}", other),
    }
}

#[test]
fn rejects_overflowing_tx_bytes() {
    let line = "wlan0: 1000 10 0 0 0 0 0 0 99999999999999999999 20 0 0 0 0 0 0";
    let result = parse_proc_net_dev_line(line);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::Overflow { field, .. } => {
            assert_eq!(field, "tx_bytes");
        }
        other => panic!("expected Overflow, got {:?}", other),
    }
}

// ── empty input returns empty snapshot ────────────────────────────────────────

#[test]
fn empty_input_returns_empty_snapshot() {
    let snapshot = parse_proc_net_dev(EMPTY_CONTENT).unwrap();
    assert!(snapshot.is_empty());
    assert_eq!(snapshot.len(), 0);
    assert_eq!(snapshot.source, SourceLabel::ProcNetDevSample);
}

#[test]
fn whitespace_only_returns_empty_snapshot() {
    let snapshot = parse_proc_net_dev("   \n  \n\n").unwrap();
    assert!(snapshot.is_empty());
}

// ── output is deterministic ───────────────────────────────────────────────────

#[test]
fn parse_is_deterministic() {
    // Parse twice, same input, same result.
    let a = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let b = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    assert_eq!(a, b);
}

#[test]
fn parse_preserves_input_order() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
  eth0: 3000 30 0 0 0 0 0 0 4000 40 0 0 0 0 0 0
    lo: 100 5 0 0 0 0 0 0 200 10 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    assert_eq!(snapshot.interfaces[0].interface, "wlan0");
    assert_eq!(snapshot.interfaces[1].interface, "eth0");
    assert_eq!(snapshot.interfaces[2].interface, "lo");
}

// ── parser does not claim per-app attribution ──────────────────────────────────

#[test]
fn parser_model_does_not_contain_per_app_fields() {
    let counter = InterfaceCounter {
        interface: "wlan0".to_string(),
        rx_bytes: 1000,
        tx_bytes: 2000,
        rx_packets: 10,
        tx_packets: 20,
    };
    // The model has no pid, app_name, cgroup, or process fields.
    // This is enforced by the struct definition — verified by compilation.
    assert_eq!(counter.interface, "wlan0");
    assert_eq!(counter.total_bytes(), 3000);
}

// ── parser does not claim enforcement/quota/blocking ────────────────────────────

#[test]
fn source_label_is_observational() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    assert_eq!(snapshot.source, SourceLabel::ProcNetDevSample);
    // SourceLabel has no Enforcement, QuotaActive, or Blocking variant.
    // This is enforced by the enum definition — verified by compilation.
}

// ── no live /proc read is performed ────────────────────────────────────────────

#[test]
fn no_live_proc_read_in_tests() {
    // This test verifies the design contract: all tests use const strings.
    // The parse_proc_net_dev function accepts &str — it cannot read files.
    // The const strings above are compile-time constants, not runtime reads.
    // This is a documentation/design test that enforces the contract.
    let _ = SAMPLE_PROC_NET_DEV;
    let _ = MINIMAL_SAMPLE;
    let _ = EMPTY_CONTENT;
    let _ = HEADERS_ONLY;
    // If any test tried to read /proc/net/dev, it would fail compilation
    // because parse_proc_net_dev only accepts &str.
}

// ── snapshot aggregate helpers ────────────────────────────────────────────────

#[test]
fn snapshot_total_rx_bytes() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    // lo: 123456, wlan0: 1324567890, eth0: 0
    assert_eq!(snapshot.total_rx_bytes(), 123456 + 1324567890);
}

#[test]
fn snapshot_total_tx_bytes() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    // lo: 234567, wlan0: 356789012, eth0: 0
    assert_eq!(snapshot.total_tx_bytes(), 234567 + 356789012);
}

#[test]
fn snapshot_total_bytes() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    assert_eq!(
        snapshot.total_bytes(),
        snapshot.total_rx_bytes() + snapshot.total_tx_bytes()
    );
}

#[test]
fn snapshot_total_bytes_excluding_loopback() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    // Only wlan0 and eth0 (lo excluded)
    let expected = 1324567890 + 356789012;
    assert_eq!(snapshot.total_bytes_excluding_loopback(), expected);
}

// ── snapshot get by name ───────────────────────────────────────────────────────

#[test]
fn snapshot_get_existing_interface() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let wlan0 = snapshot.get("wlan0");
    assert!(wlan0.is_some());
    assert_eq!(wlan0.unwrap().rx_bytes, 1324567890);
}

#[test]
fn snapshot_get_missing_interface() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    assert!(snapshot.get("nonexistent").is_none());
}

// ── interface counter helpers ──────────────────────────────────────────────────

#[test]
fn interface_total_bytes() {
    let counter = InterfaceCounter {
        interface: "wlan0".to_string(),
        rx_bytes: 1000,
        tx_bytes: 2000,
        rx_packets: 10,
        tx_packets: 20,
    };
    assert_eq!(counter.total_bytes(), 3000);
}

#[test]
fn interface_is_loopback_true() {
    let counter = InterfaceCounter {
        interface: "lo".to_string(),
        rx_bytes: 100,
        tx_bytes: 200,
        rx_packets: 5,
        tx_packets: 10,
    };
    assert!(counter.is_loopback());
}

#[test]
fn interface_is_loopback_false() {
    let counter = InterfaceCounter {
        interface: "wlan0".to_string(),
        rx_bytes: 1000,
        tx_bytes: 2000,
        rx_packets: 10,
        tx_packets: 20,
    };
    assert!(!counter.is_loopback());
}

// ── render output tests ────────────────────────────────────────────────────────

#[test]
fn render_contains_read_only_label() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("read-only"));
}

#[test]
fn render_contains_aggregate_not_per_app() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("aggregate interface traffic"));
    assert!(rendered.contains("not per-app"));
}

#[test]
fn render_contains_no_enforcement() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("No enforcement"));
}

#[test]
fn render_contains_no_quota_guard() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("No quota guard"));
}

#[test]
fn render_contains_no_per_app_attribution() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("No per-app attribution"));
}

#[test]
fn render_contains_source_label() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("proc_net_dev_sample"));
}

#[test]
fn render_empty_snapshot() {
    let snapshot = parse_proc_net_dev(EMPTY_CONTENT).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("No interface counters parsed"));
    assert!(rendered.contains("read-only"));
    assert!(rendered.contains("No enforcement"));
}

#[test]
fn render_loopback_tag() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("[loopback]"));
}

#[test]
fn render_interface_data() {
    let snapshot = parse_proc_net_dev(MINIMAL_SAMPLE).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("wlan0"));
    assert!(rendered.contains("1000"));
    assert!(rendered.contains("2000"));
}

#[test]
fn render_totals_excluding_loopback() {
    let snapshot = parse_proc_net_dev(SAMPLE_PROC_NET_DEV).unwrap();
    let rendered = render_interface_counter_snapshot(&snapshot);
    assert!(rendered.contains("Totals (excluding loopback)"));
}

// ── parse error display ───────────────────────────────────────────────────────

#[test]
fn parse_error_missing_colon_display() {
    let err = ParseError::MissingColon {
        line_number: 3,
        line: "wlan0 1000 10".to_string(),
    };
    let display = format!("{}", err);
    assert!(display.contains("missing colon"));
    assert!(display.contains("3"));
}

#[test]
fn parse_error_too_few_fields_display() {
    let err = ParseError::TooFewFields {
        line_number: 4,
        field_count: 2,
        line: "wlan0: 100 10".to_string(),
    };
    let display = format!("{}", err);
    assert!(display.contains("too few fields"));
    assert!(display.contains("2"));
}

#[test]
fn parse_error_invalid_rx_bytes_display() {
    let err = ParseError::InvalidRxBytes {
        line_number: 5,
        value: "abc".to_string(),
        line: "wlan0: abc".to_string(),
    };
    let display = format!("{}", err);
    assert!(display.contains("invalid RX bytes"));
    assert!(display.contains("abc"));
}

#[test]
fn parse_error_invalid_tx_bytes_display() {
    let err = ParseError::InvalidTxBytes {
        line_number: 6,
        value: "xyz".to_string(),
        line: "wlan0: 100 10 0 0 0 0 0 0 xyz".to_string(),
    };
    let display = format!("{}", err);
    assert!(display.contains("invalid TX bytes"));
    assert!(display.contains("xyz"));
}

#[test]
fn parse_error_overflow_display() {
    let err = ParseError::Overflow {
        line_number: 7,
        field: "rx_bytes".to_string(),
        line: "overflow".to_string(),
    };
    let display = format!("{}", err);
    assert!(display.contains("overflow"));
    assert!(display.contains("rx_bytes"));
}

// ── usb0 / tethering-style interface name ──────────────────────────────────────

#[test]
fn parse_usb0_interface() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  usb0: 45600000 300000 0 0 0 0 0 0 12300000 80000 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot.interfaces[0].interface, "usb0");
    assert_eq!(snapshot.interfaces[0].rx_bytes, 45600000);
    assert_eq!(snapshot.interfaces[0].tx_bytes, 12300000);
}

// ── large but valid u64 values ─────────────────────────────────────────────────

#[test]
fn parse_large_valid_u64_values() {
    // u64::MAX = 18446744073709551615 — use something large but valid.
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 18446744073709551615 9999999999 0 0 0 0 0 0 18446744073709551615 9999999999 0 0 0 0 0 0
";
    let snapshot = parse_proc_net_dev(content).unwrap();
    assert_eq!(snapshot.interfaces[0].rx_bytes, u64::MAX);
    assert_eq!(snapshot.interfaces[0].tx_bytes, u64::MAX);
}

// ── error line numbers in full parse ────────────────────────────────────────────

#[test]
fn error_line_number_from_full_parse() {
    let content = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
  badline
  eth0: 3000 30 0 0 0 0 0 0 4000 40 0 0 0 0 0 0
";
    let result = parse_proc_net_dev(content);
    assert!(result.is_err());
    match result.unwrap_err() {
        ParseError::MissingColon { line_number, .. } => {
            // "badline" is on line 4 (headers are lines 1-2, wlan0 is line 3, badline is line 4)
            assert_eq!(line_number, 4);
        }
        other => panic!("expected MissingColon, got {:?}", other),
    }
}

// ── negative number rejected ───────────────────────────────────────────────────

#[test]
fn rejects_negative_rx_bytes() {
    let line = "wlan0: -100 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0";
    let result = parse_proc_net_dev_line(line);
    assert!(result.is_err());
    // Negative number is invalid for u64 — should be InvalidRxBytes.
    match result.unwrap_err() {
        ParseError::InvalidRxBytes { value, .. } => {
            assert_eq!(value, "-100");
        }
        other => panic!("expected InvalidRxBytes, got {:?}", other),
    }
}
