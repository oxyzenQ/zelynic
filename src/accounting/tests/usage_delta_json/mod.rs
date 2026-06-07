// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Tests for v3.0 phase 14 pure delta JSON model and serialization.
//!
//! All tests use injected/parsed content — no live `/proc/net/dev` reads,
//! no filesystem writes, no CLI flags, no enforcement, no mutation.
//! Every test constructs `InterfaceCounterSnapshot` values from `const` strings
//! and passes them to the builder functions.
//!
//! v3.0 phase 14b: split from monolithic 973-LOC file into focused sub-modules
//! for maintainability. Refactor/split only — no behavior changes.

mod errors;
mod honesty;
mod safety;
mod success;
mod warnings;

use crate::accounting::interface_counters::parse_proc_net_dev;
use crate::accounting::usage_delta_json::*;
use crate::accounting::{InterfaceCounterSnapshot, SourceLabel};

// ── Sample data ─────────────────────────────────────────────────────

/// Standard start sample with two interfaces.
pub(in crate::accounting::tests) const START_SAMPLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000000  10000    0    0    0     0          0         0  500000   5000    0    0    0     0       0          0
  eth0:  200000   2000    0    0    0     0          0         0  100000   1000    0    0    0     0       0          0
";

/// End sample with higher counters (normal delta).
pub(in crate::accounting::tests) const END_SAMPLE_NORMAL: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 2000000  20000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
";

/// End sample with counter reset on wlan0 RX (decreased from start).
pub(in crate::accounting::tests) const END_SAMPLE_RESET: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0:   500000  15000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
";

/// End sample with a new interface (wlan1 added).
pub(in crate::accounting::tests) const END_SAMPLE_ADDED_INTERFACE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 2000000  20000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
  eth0:  300000   3000    0    0    0     0          0         0  200000   2000    0    0    0     0       0          0
  wlan1: 100000   1000    0    0    0     0          0         0   50000    500    0    0    0     0       0          0
";

/// End sample with an interface removed (eth0 gone).
pub(in crate::accounting::tests) const END_SAMPLE_REMOVED_INTERFACE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 2000000  20000    0    0    0     0          0         0  1000000  10000    0    0    0     0       0          0
";

/// Multi-interface sample with loopback for snapshot summary tests.
pub(in crate::accounting::tests) const MULTI_IFACE_WITH_LO: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    100    0    0    0     0          0         0  234567     200    0    0    0     0       0          0
  wlan0: 1324567890  1234567    0    0    0     0          0         0  356789012   345678    0    0    0     0       0          0
  eth0:       0        0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

// ── Helpers ─────────────────────────────────────────────────────────

pub(in crate::accounting::tests) fn parse(content: &str) -> InterfaceCounterSnapshot {
    parse_proc_net_dev(content).expect("parse should succeed")
}
