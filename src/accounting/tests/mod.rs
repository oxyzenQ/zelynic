// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Accounting test module — split from monolithic tests.rs in v2.9 phase 3b.
//!
//! All tests use const sample strings — **no** live `/proc/net/dev` reads,
//! **no** live sysfs reads, **no** filesystem access, **no** network blocking,
//! **no** quota enforcement, **no** eBPF, **no** PID movement, **no** cgroup writes.

mod identity;
mod interface_counters;
mod ledger;
mod ledger_inspect;
mod ledger_path;
mod ledger_persistence;
mod live_proc_net_dev;
mod session_delta;
mod usage_delta;
mod usage_delta_json;
mod usage_json;
mod usage_preview;

/// Standard `/proc/net/dev` sample with three interfaces.
pub(crate) const SAMPLE_PROC_NET_DEV: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 123456    100    0    0    0     0          0         0  234567     200    0    0    0     0       0          0
  wlan0: 1324567890  1234567    0    0    0     0          0         0  356789012   345678    0    0    0     0       0          0
  eth0:       0        0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
";

/// `/proc/net/dev` sample with predictable interface names.
pub(crate) const MINIMAL_SAMPLE: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
  wlan0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0
";

/// Empty content — should produce empty snapshot, not error.
pub(crate) const EMPTY_CONTENT: &str = "";

/// Only headers, no data lines.
pub(crate) const HEADERS_ONLY: &str = "\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
";
