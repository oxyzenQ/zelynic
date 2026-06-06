// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Handler for the `zelynic usage --sample --delta` command (v3.0 phase 12).
//!
//! This module implements the actual two-sample read-only delta CLI that reads
//! `/proc/net/dev` twice, waits a bounded duration between samples, computes
//! per-interface byte deltas using the existing `SessionDelta` model, and
//! renders honest interface-level delta output before exiting.
//!
//! # Safety
//!
//! - Reads only `/proc/net/dev` -- path is hardcoded, not configurable.
//! - Exactly two reads, then exit. No loop, no watch, no daemon.
//! - Does not write anything.
//! - Does not mutate system state.
//! - Does not block, throttle, or enforce quotas.
//! - Does not attach limiters.
//! - Does not load/attach eBPF.
//! - Does not mutate nftables/tc rules.
//! - Does not move PIDs or write cgroup.procs.
//! - Does not read sysfs.
//! - Does not implement interval sampling (wait duration is hardcoded).
//! - No filesystem persistence, no ledger file read/write.
//! - No delta JSON output (deferred to phase 13).
//! - CLI remains finite and single-shot.

pub(crate) mod handler;
pub(crate) mod render;

#[cfg(test)]
pub(crate) mod tests;

pub(crate) use handler::handle_usage_delta;
