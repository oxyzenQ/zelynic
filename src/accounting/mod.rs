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

mod identity;
mod interface_counters;
mod ledger;
mod ledger_identity;
mod ledger_identity_report;
mod ledger_inspect;
mod ledger_path;
mod ledger_persistence;
mod live_proc_net_dev;
mod session_delta;
mod usage_delta;
mod usage_delta_json;
mod usage_json;
mod usage_preview;

#[cfg(test)]
mod tests;

// Re-exports for internal use by tests and future phases.
// Currently unused from main.rs — no CLI command yet.
#[allow(unused_imports)]
pub(crate) use identity::{
    default_identity_honesty, deserialize_identity_json, render_resolved_target,
    serialize_identity_honesty, serialize_identity_json, CgroupIdentity, IdentityHonesty,
    InterfaceIdentity, ProcessIdentity, ResolvedUsageTarget, TargetIdentity, UsageAttributionScope,
};
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
pub(crate) use ledger_identity::{
    build_identity_attachment, build_interface_only_attachment, build_no_identity_attachment,
    render_identity_summary, render_ledger_identity_attachment, LedgerIdentityAttachment,
};
#[allow(unused_imports)]
pub(crate) use ledger_identity_report::{
    build_ledger_identity_report, default_report_honesty, deserialize_report_json,
    render_ledger_identity_report, serialize_report_json, LedgerIdentityReport,
    LedgerIdentityReportHonesty, LedgerIdentityReportInterface, LedgerIdentityReportTarget,
    LedgerIdentityReportTotals,
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
pub(crate) use usage_delta::{
    build_usage_delta_from_session_delta, render_usage_delta, UsageDeltaOutput, UsageDeltaRow,
};
#[allow(unused_imports)]
pub(crate) use usage_delta_json::{
    build_delta_json_first_read_error, build_delta_json_second_read_error,
    build_delta_json_success, build_delta_json_unsupported_flag_error, delta_default_warnings,
    delta_error_first_read_honesty, delta_error_second_read_honesty,
    delta_error_unsupported_flag_honesty, delta_success_honesty_flags, deserialize_delta_json,
    serialize_delta_json, DeltaJsonError, DeltaJsonErrorType, DeltaJsonHonesty, DeltaJsonInterface,
    DeltaJsonSampleSummary, DeltaJsonTotals, UsageDeltaJsonOutput, COMMAND_USAGE_SAMPLE_DELTA_JSON,
    DEFAULT_DELTA_WAIT_MS, DELTA_SCHEMA_VERSION, SAMPLE_MODE_DELTA, SOURCE_LABEL_DELTA_JSON,
};
#[allow(unused_imports)]
pub(crate) use usage_json::{
    build_usage_json_error, build_usage_json_from_snapshot, default_honesty_flags,
    default_warnings, deserialize_usage_json, serialize_usage_json, UsageJsonError,
    UsageJsonErrorType, UsageJsonHonesty, UsageJsonInterface, UsageJsonOutput, UsageJsonTotals,
    COMMAND_USAGE_SAMPLE_JSON, SCHEMA_VERSION,
};
#[allow(unused_imports)]
pub(crate) use usage_preview::{
    build_usage_preview, format_bytes_human, render_usage_preview, UsagePreview, UsagePreviewRow,
};
