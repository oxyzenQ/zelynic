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
mod ledger;
mod ledger_inspect;
mod ledger_path;
mod ledger_persistence;
mod live_proc_net_dev;
mod session_delta;
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
pub(crate) use ledger::{
    add_session_delta_entry, add_snapshot_entry, deserialize_ledger_from_json, new_empty_ledger,
    render_ledger_summary, serialize_ledger_to_json, Ledger, LedgerEntry, LedgerError, ResetDetail,
};
#[allow(unused_imports)]
pub(crate) use ledger_inspect::{build_ledger_inspect, render_ledger_inspect, LedgerInspect};
#[allow(unused_imports)]
pub(crate) use ledger_path::{
    build_default_ledger_path_plan, build_ledger_path_plan, render_ledger_path_plan,
    LedgerPathPlan, PathError, PathStatus,
};
#[allow(unused_imports)]
pub(crate) use ledger_persistence::{
    build_ledger_persistence_plan, build_ledger_read_plan, build_ledger_write_plan,
    render_ledger_persistence_plan, LedgerPersistencePlan, PersistenceError, PersistenceOperation,
    PersistenceStatus, BLOCKED_REASON,
};
#[allow(unused_imports)]
pub(crate) use live_proc_net_dev::{
    build_live_proc_net_dev_error_plan, build_live_proc_net_dev_read_plan,
    build_live_proc_net_dev_snapshot_from_content, read_live_proc_net_dev,
    read_live_proc_net_dev_with_injected_reader, render_live_proc_net_dev_read_plan, ContentReader,
    FakeReadErrorReader, InjectedContentReader, LiveProcNetDevReadPlan, LiveReadError,
    LiveReadStatus, DEFAULT_LIVE_SOURCE_PATH, FORBIDDEN_FS_WRITE_APIS, FORBIDDEN_PATHS,
    SOURCE_LABEL_INJECTED, SOURCE_LABEL_LIVE,
};
#[allow(unused_imports)]
pub(crate) use session_delta::{
    build_session_delta, render_session_delta, CounterResetWarning, SessionDelta, SessionDeltaRow,
};
#[allow(unused_imports)]
pub(crate) use usage_preview::{
    build_usage_preview, format_bytes_human, render_usage_preview, UsagePreview, UsagePreviewRow,
};
