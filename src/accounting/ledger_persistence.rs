// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Hard-blocked persistence I/O contract seam for v2.9 Network Accounting Lab.
//!
//! This module provides a pure model for future ledger persistence read/write
//! operations. Every operation is **hard-blocked** — no filesystem reads, **no**
//! filesystem writes, **no** directory creation, **no** file creation, **no**
//! file removal, **no** live system reads, **no** enforcement, **no** quota
//! management, **no** network blocking, **no** eBPF, **no** PID movement,
//! and **no** cgroup writes.
//!
//! # Safety
//!
//! - No filesystem I/O — all persistence operations return blocked/not implemented.
//! - No `std::fs` read/write/create/remove APIs.
//! - No live `/proc/net/dev` or sysfs reads.
//! - No directory or file creation on disk.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//!
//! # Phase 9 Scope
//!
//! Phase 9 implements the persistence I/O contract seam. No actual filesystem
//! persistence occurs. All persistence plans are hard-blocked and perform no
//! I/O. The contract exists only in memory during tests and future persistence
//! phases.

#![allow(dead_code)]

use super::ledger_path::{build_ledger_path_plan, LedgerPathPlan, PathStatus};

/// Canonical reason why persistence operations are hard-blocked.
pub const BLOCKED_REASON: &str = "persistence I/O is not implemented in v2.9 — hard-blocked seam";

/// Error type for persistence contract failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistenceError {
    /// The persistence operation is hard-blocked in v2.9.
    HardBlocked(String),
    /// The ledger path plan is unsafe for the requested operation.
    UnsafePath(String),
}

impl std::fmt::Display for PersistenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceError::HardBlocked(reason) => {
                write!(f, "hard-blocked: {}", reason)
            }
            PersistenceError::UnsafePath(reason) => {
                write!(f, "unsafe path: {}", reason)
            }
        }
    }
}

/// The type of persistence operation being planned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceOperation {
    /// Read a ledger file from disk.
    ReadLedger,
    /// Write a ledger file to disk.
    WriteLedger,
    /// Atomically replace a ledger file (write + rename).
    AtomicReplace,
    /// Create a backup copy of a ledger file.
    Backup,
    /// Validate a ledger path without performing I/O.
    ValidatePath,
}

impl std::fmt::Display for PersistenceOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistenceOperation::ReadLedger => write!(f, "read ledger"),
            PersistenceOperation::WriteLedger => write!(f, "write ledger"),
            PersistenceOperation::AtomicReplace => write!(f, "atomic replace"),
            PersistenceOperation::Backup => write!(f, "backup"),
            PersistenceOperation::ValidatePath => write!(f, "validate path"),
        }
    }
}

/// The outcome status of a planned persistence operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistenceStatus {
    /// The operation is hard-blocked / not implemented.
    Blocked(String),
    /// The operation was rejected because the path plan is unsafe.
    Rejected(String),
}

/// A planned persistence I/O operation that is always hard-blocked.
///
/// This struct models future read/write operations without performing any
/// filesystem I/O. All mutation flags are hardcoded to false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerPersistencePlan {
    /// The type of persistence operation planned.
    pub operation: PersistenceOperation,
    /// The ledger path plan used for the operation.
    pub path_plan: LedgerPathPlan,
    /// The outcome status of the planned operation.
    pub persistence_status: PersistenceStatus,
    /// Human-readable reason for the blocked/rejected status.
    pub blocked_reason: String,
    /// Always true — this is a model-only construct.
    pub model_only: bool,
    /// Always false — no filesystem read was performed.
    pub filesystem_read_performed: bool,
    /// Always false — no filesystem write was performed.
    pub filesystem_write_performed: bool,
    /// Always false — no directory was created.
    pub directory_create_performed: bool,
    /// Always false — no file was created.
    pub file_create_performed: bool,
    /// Always false — no file was removed.
    pub file_remove_performed: bool,
    /// Always false — no state mutation was performed.
    pub state_mutation_performed: bool,
    /// Always false — persistence is not enabled in v2.9.
    pub persistence_enabled: bool,
}

/// Build a persistence plan for a ledger read operation.
///
/// Always returns a hard-blocked plan. Validates the path plan structurally
/// but performs no filesystem I/O.
pub fn build_ledger_read_plan(
    base_directory: &str,
    namespace_label: &str,
    ledger_filename: &str,
) -> LedgerPersistencePlan {
    build_persistence_plan(
        PersistenceOperation::ReadLedger,
        base_directory,
        namespace_label,
        ledger_filename,
    )
}

/// Build a persistence plan for a ledger write operation.
///
/// Always returns a hard-blocked plan. Validates the path plan structurally
/// but performs no filesystem I/O.
pub fn build_ledger_write_plan(
    base_directory: &str,
    namespace_label: &str,
    ledger_filename: &str,
) -> LedgerPersistencePlan {
    build_persistence_plan(
        PersistenceOperation::WriteLedger,
        base_directory,
        namespace_label,
        ledger_filename,
    )
}

/// Build a persistence plan with a custom operation type.
///
/// Always returns a hard-blocked plan regardless of operation type.
/// Validates the path plan structurally — if the path is rejected,
/// the persistence plan is also rejected. Otherwise it is hard-blocked
/// because persistence is not implemented in v2.9.
pub fn build_ledger_persistence_plan(
    operation: PersistenceOperation,
    base_directory: &str,
    namespace_label: &str,
    ledger_filename: &str,
) -> LedgerPersistencePlan {
    build_persistence_plan(operation, base_directory, namespace_label, ledger_filename)
}

/// Internal helper that builds the persistence plan from operation and path inputs.
fn build_persistence_plan(
    operation: PersistenceOperation,
    base_directory: &str,
    namespace_label: &str,
    ledger_filename: &str,
) -> LedgerPersistencePlan {
    let path_plan = build_ledger_path_plan(base_directory, namespace_label, ledger_filename);

    // If the path plan itself is rejected, the operation is also rejected.
    if let PathStatus::Rejected(reason) = path_plan.path_status.clone() {
        let rejection_reason = format!("rejected: unsafe path for {} operation", operation);
        return LedgerPersistencePlan {
            operation,
            path_plan,
            persistence_status: PersistenceStatus::Rejected(reason),
            blocked_reason: rejection_reason,
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            directory_create_performed: false,
            file_create_performed: false,
            file_remove_performed: false,
            state_mutation_performed: false,
            persistence_enabled: false,
        };
    }

    // Path is accepted, but persistence is not implemented => hard-blocked.
    LedgerPersistencePlan {
        operation,
        path_plan,
        persistence_status: PersistenceStatus::Blocked(BLOCKED_REASON.to_string()),
        blocked_reason: format!(
            "hard-blocked: {} is not implemented in v2.9 — persistence I/O seam",
            operation
        ),
        model_only: true,
        filesystem_read_performed: false,
        filesystem_write_performed: false,
        directory_create_performed: false,
        file_create_performed: false,
        file_remove_performed: false,
        state_mutation_performed: false,
        persistence_enabled: false,
    }
}

/// Render a ledger persistence plan as a human-readable string.
///
/// The output includes the planned operation, path information, blocked
/// status, model flags, and comprehensive safety disclaimers.
///
/// # Safety Disclaimers (12 total)
///
/// 1. persistence I/O seam is hard-blocked
/// 2. no filesystem read was performed
/// 3. no filesystem write was performed
/// 4. no ledger file was created
/// 5. no ledger file was read
/// 6. no ledger file was saved
/// 7. no directory was created
/// 8. no file was removed
/// 9. persistence is not enabled
/// 10. no live /proc or sysfs read was performed
/// 11. no quota enforcement or network blocking is active
/// 12. no nft/tc/Zelynic state mutation was performed
pub fn render_ledger_persistence_plan(plan: &LedgerPersistencePlan) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v2.9 persistence I/O plan (persistence I/O contract model only)\n");
    out.push('\n');

    // Operation
    out.push_str(&format!("Operation: {}\n", plan.operation));
    out.push('\n');

    // Path components
    out.push_str(&format!(
        "Base directory: {}\n",
        plan.path_plan.base_directory
    ));
    out.push_str(&format!(
        "Namespace label: {}\n",
        plan.path_plan.namespace_label
    ));
    out.push_str(&format!(
        "Ledger filename: {}\n",
        plan.path_plan.ledger_filename
    ));
    out.push_str(&format!(
        "Full ledger path: {}\n",
        plan.path_plan.full_ledger_path
    ));
    out.push_str(&format!(
        "Path status: {}\n",
        match &plan.path_plan.path_status {
            PathStatus::Accepted => "accepted".to_string(),
            PathStatus::Rejected(r) => format!("rejected: {}", r),
        }
    ));
    out.push('\n');

    // Persistence status
    match &plan.persistence_status {
        PersistenceStatus::Blocked(reason) => {
            out.push_str("Persistence status: HARD-BLOCKED\n");
            out.push_str(&format!("Reason: {}\n", reason));
        }
        PersistenceStatus::Rejected(reason) => {
            out.push_str("Persistence status: rejected\n");
            out.push_str(&format!("Reason: {}\n", reason));
        }
    }
    out.push_str(&format!("Blocked reason: {}\n", plan.blocked_reason));
    out.push('\n');

    // Model flags
    out.push_str(&format!("Model only: {}\n", plan.model_only));
    out.push_str(&format!(
        "Filesystem read performed: {}\n",
        plan.filesystem_read_performed
    ));
    out.push_str(&format!(
        "Filesystem write performed: {}\n",
        plan.filesystem_write_performed
    ));
    out.push_str(&format!(
        "Directory create performed: {}\n",
        plan.directory_create_performed
    ));
    out.push_str(&format!(
        "File create performed: {}\n",
        plan.file_create_performed
    ));
    out.push_str(&format!(
        "File remove performed: {}\n",
        plan.file_remove_performed
    ));
    out.push_str(&format!(
        "State mutation performed: {}\n",
        plan.state_mutation_performed
    ));
    out.push_str(&format!(
        "Persistence enabled: {}\n",
        plan.persistence_enabled
    ));
    out.push('\n');

    // 12 safety disclaimers
    out.push_str("Safety disclaimers:\n");
    out.push_str("  - persistence I/O seam is hard-blocked\n");
    out.push_str("  - no filesystem read was performed\n");
    out.push_str("  - no filesystem write was performed\n");
    out.push_str("  - no ledger file was created\n");
    out.push_str("  - no ledger file was read\n");
    out.push_str("  - no ledger file was saved\n");
    out.push_str("  - no directory was created\n");
    out.push_str("  - no file was removed\n");
    out.push_str("  - persistence is not enabled\n");
    out.push_str("  - no live /proc or sysfs read was performed\n");
    out.push_str("  - no quota enforcement or network blocking is active\n");
    out.push_str("  - no nft/tc/Zelynic state mutation was performed\n");

    out
}
