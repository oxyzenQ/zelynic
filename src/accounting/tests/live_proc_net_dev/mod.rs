// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Tests for the live `/proc/net/dev` reader seam (v3.0 phases 2–3).
//!
//! All tests use injected/fake content — **no** live `/proc/net/dev` reads,
//! **no** live sysfs reads, **no** filesystem access, **no** network blocking,
//! **no** quota enforcement, **no** eBPF, **no** PID movement, **no** cgroup writes,
//! **no** CLI command registration.
//!
//! Phase 2 tests exercise the injected content parsing path.
//! Phase 3 tests exercise the `ContentReader` trait, fake readers, boundary
//! audit, and the injected reader backend function.
//!
//! v3.0 phase 3b: split from monolithic 924-LOC file into focused sub-modules
//! for maintainability. Refactor/split only — no behavior changes.

mod boundary_audit;
mod injected_reader;
mod render;
mod seam;

use super::*;
use crate::accounting::live_proc_net_dev::*;
use crate::accounting::ParseError;

/// Standard multi-interface sample for live seam tests.
pub(in crate::accounting::tests) const LIVE_SEAM_SAMPLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    100    0    0    0     0          0         0  234567     200    0    0    0     0       0          0
  wlan0: 1324567890  1234567    0    0    0     0          0         0  356789012   345678    0    0    0     0       0          0
  eth0:       0        0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

/// Minimal single-interface sample.
pub(in crate::accounting::tests) const LIVE_SEAM_MINIMAL: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 5000 50 0 0 0 0 0 0 6000 60 0 0 0 0 0 0
";

/// Sample with unusual interface names.
pub(in crate::accounting::tests) const LIVE_SEAM_UNUSUAL_NAMES: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlp2s0: 100000 200 0 0 0 0 0 0 200000 400 0 0 0 0 0 0
  enp3s0: 300000 600 0 0 0 0 0 0 400000 800 0 0 0 0 0 0
  usb0: 4096 8 0 0 0 0 0 0 8192 16 0 0 0 0 0 0
";

/// Malformed content — missing colon.
pub(in crate::accounting::tests) const LIVE_SEAM_MALFORMED_NO_COLON: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";

/// Malformed content — too few fields.
pub(in crate::accounting::tests) const LIVE_SEAM_MALFORMED_TOO_FEW: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000
";

/// Malformed content — non-numeric rx_bytes.
pub(in crate::accounting::tests) const LIVE_SEAM_MALFORMED_NON_NUMERIC: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: abc 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";
