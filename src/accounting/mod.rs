// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! v2.9 Network Accounting Lab — Pure read-only interface counter model and parser.
//!
//! This module provides a pure Rust model for parsing `/proc/net/dev`-style content
//! into structured interface counters. It performs **no** live system reads, **no**
//! filesystem access, **no** network blocking, **no** quota enforcement, **no** eBPF,
//! **no** PID movement, and **no** cgroup writes.
//!
//! # Safety
//!
//! - No live `/proc/net/dev` reads — parser accepts `&str` input only.
//! - No live sysfs reads.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//!
//! # Honesty
//!
//! - Interface counters are aggregate per-interface, **not** per-app.
//! - This module does **not** claim per-app attribution.
//! - This module does **not** claim enforcement, quota guard, or blocking.

mod interface_counters;
mod usage_preview;

#[cfg(test)]
mod tests;

// Re-exports for internal use by tests and future phases.
// Currently unused from main.rs — no CLI command yet.
#[allow(unused_imports)]
pub(crate) use interface_counters::{
    parse_proc_net_dev, parse_proc_net_dev_line, render_interface_counter_snapshot,
    InterfaceCounter, InterfaceCounterSnapshot, ParseError, SourceLabel,
};
#[allow(unused_imports)]
pub(crate) use usage_preview::{
    build_usage_preview, format_bytes_human, render_usage_preview, UsagePreview, UsagePreviewRow,
};
