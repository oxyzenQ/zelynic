// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Persistence path planning model for v2.9 Network Accounting Lab.
//!
//! This module provides a pure model for planning future ledger persistence
//! paths. It performs **no** filesystem reads, **no** filesystem writes, **no**
//! live system reads, **no** enforcement, **no** quota management, **no**
//! network blocking, **no** eBPF, **no** PID movement, and **no** cgroup writes.
//!
//! # Safety
//!
//! - No filesystem I/O — all path validation is string-based only.
//! - No `std::fs` read/write/create/remove APIs.
//! - No live `/proc/net/dev` or sysfs reads.
//! - No canonicalization using live filesystem.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//!
//! # Phase 9 Scope
//!
//! Phase 9 reviews and hardens the persistence path seam model. Adds
//! `symlink_resolution_performed` flag (always false) and 10th render
//! disclaimer. No filesystem persistence occurs. Paths are validated
//! structurally (string analysis) only. The path plan exists only in
//! memory during tests and future persistence phases.

#![allow(dead_code)]

/// Default ledger filename used when no explicit filename is provided.
pub const DEFAULT_LEDGER_FILENAME: &str = "network-ledger-v1.json";

/// Default Zelynic namespace label under XDG data directory.
pub const DEFAULT_NAMESPACE_LABEL: &str = "zelynic";

/// Error type for path validation failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The base directory is empty.
    EmptyBaseDirectory,
    /// The filename is empty.
    EmptyFilename,
    /// The filename is an absolute path (must be relative).
    AbsoluteFilename(String),
    /// The filename contains parent traversal components.
    ParentTraversalInFilename(String),
    /// The base path contains parent traversal components.
    ParentTraversalInBasePath(String),
    /// The resolved path is outside the configured namespace.
    OutsideNamespace { path: String, namespace: String },
    /// The filename contains suspicious characters.
    SuspiciousFilename(String),
}

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PathError::EmptyBaseDirectory => write!(f, "base directory must not be empty"),
            PathError::EmptyFilename => write!(f, "filename must not be empty"),
            PathError::AbsoluteFilename(name) => {
                write!(f, "filename must be relative, got absolute: {:?}", name)
            }
            PathError::ParentTraversalInFilename(name) => {
                write!(f, "filename contains parent traversal: {:?}", name)
            }
            PathError::ParentTraversalInBasePath(path) => {
                write!(f, "base path contains parent traversal: {:?}", path)
            }
            PathError::OutsideNamespace { path, namespace } => {
                write!(f, "path {:?} is outside namespace {:?}", path, namespace)
            }
            PathError::SuspiciousFilename(name) => {
                write!(f, "filename contains suspicious characters: {:?}", name)
            }
        }
    }
}

/// Status of a planned ledger path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathStatus {
    /// The path plan is valid and accepted.
    Accepted,
    /// The path plan was rejected with a specific reason.
    Rejected(String),
}

/// A planned ledger persistence path model.
///
/// This struct models the future persistence path boundary without performing
/// any filesystem I/O. All fields are computed from string inputs using pure
/// validation logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerPathPlan {
    /// Configured base directory (e.g., "/home/user/.local/share").
    pub base_directory: String,
    /// Ledger filename (e.g., "network-ledger-v1.json").
    pub ledger_filename: String,
    /// Full planned ledger path (base_directory / namespace / ledger_filename).
    pub full_ledger_path: String,
    /// State/cache namespace label (e.g., "zelynic").
    pub namespace_label: String,
    /// Whether the path plan is accepted or rejected.
    pub path_status: PathStatus,
    /// Human-readable reason for acceptance or rejection.
    pub safe_reason: String,
    /// Always true — this is a model-only construct.
    pub model_only: bool,
    /// Always false — no filesystem read was performed.
    pub filesystem_read_performed: bool,
    /// Always false — no filesystem write was performed.
    pub filesystem_write_performed: bool,
    /// Always false — persistence is not enabled in v2.9.
    pub persistence_enabled: bool,
    /// Always false — no symlink resolution was performed.
    pub symlink_resolution_performed: bool,
}

/// Check whether a filename contains suspicious characters.
///
/// Suspicious characters are anything outside `[a-zA-Z0-9._-]`.
fn is_filename_suspicious(filename: &str) -> bool {
    !filename.is_empty()
        && !filename
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

/// Check whether a path string contains parent traversal (`..`).
fn contains_parent_traversal(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    parts.contains(&"..")
}

/// Build a default ledger path plan using the given base directory.
///
/// Uses the default namespace label ("zelynic") and default ledger filename
/// ("network-ledger-v1.json"). Validates the path structurally.
///
/// # Arguments
///
/// * `base_directory` - The base directory under which the ledger will live
///   (e.g., "/home/user/.local/share").
///
/// # Returns
///
/// A `LedgerPathPlan` with the computed full path and validation status.
pub fn build_default_ledger_path_plan(base_directory: &str) -> LedgerPathPlan {
    build_ledger_path_plan(
        base_directory,
        DEFAULT_NAMESPACE_LABEL,
        DEFAULT_LEDGER_FILENAME,
    )
}

/// Build a ledger path plan with explicit parameters.
///
/// Validates all inputs structurally (string-based only, no filesystem access).
/// Rejects empty base directory, empty filename, absolute filenames, parent
/// traversal, paths outside the namespace, and suspicious filenames.
///
/// # Arguments
///
/// * `base_directory` - The base directory (e.g., "/home/user/.local/share").
/// * `namespace_label` - The namespace label (e.g., "zelynic").
/// * `ledger_filename` - The ledger filename (e.g., "network-ledger-v1.json").
///
/// # Returns
///
/// A `LedgerPathPlan` with the computed full path and validation status.
pub fn build_ledger_path_plan(
    base_directory: &str,
    namespace_label: &str,
    ledger_filename: &str,
) -> LedgerPathPlan {
    // Validate base directory
    if base_directory.is_empty() {
        return LedgerPathPlan {
            base_directory: String::new(),
            ledger_filename: ledger_filename.to_string(),
            full_ledger_path: String::new(),
            namespace_label: namespace_label.to_string(),
            path_status: PathStatus::Rejected("empty base directory".to_string()),
            safe_reason: "rejected: empty base directory".to_string(),
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            persistence_enabled: false,
            symlink_resolution_performed: false,
        };
    }

    // Validate filename
    if ledger_filename.is_empty() {
        return LedgerPathPlan {
            base_directory: base_directory.to_string(),
            ledger_filename: String::new(),
            full_ledger_path: String::new(),
            namespace_label: namespace_label.to_string(),
            path_status: PathStatus::Rejected("empty filename".to_string()),
            safe_reason: "rejected: empty filename".to_string(),
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            persistence_enabled: false,
            symlink_resolution_performed: false,
        };
    }

    // Validate namespace label
    if namespace_label.is_empty() {
        return LedgerPathPlan {
            base_directory: base_directory.to_string(),
            ledger_filename: ledger_filename.to_string(),
            full_ledger_path: String::new(),
            namespace_label: namespace_label.to_string(),
            path_status: PathStatus::Rejected("empty namespace label".to_string()),
            safe_reason: "rejected: empty namespace label".to_string(),
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            persistence_enabled: false,
            symlink_resolution_performed: false,
        };
    }

    // Reject absolute filenames
    if ledger_filename.starts_with('/') {
        return LedgerPathPlan {
            base_directory: base_directory.to_string(),
            ledger_filename: ledger_filename.to_string(),
            full_ledger_path: String::new(),
            namespace_label: namespace_label.to_string(),
            path_status: PathStatus::Rejected(format!(
                "absolute filename rejected: {:?}",
                ledger_filename
            )),
            safe_reason: format!(
                "rejected: filename must be relative, got absolute: {:?}",
                ledger_filename
            ),
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            persistence_enabled: false,
            symlink_resolution_performed: false,
        };
    }

    // Reject parent traversal in filename
    if contains_parent_traversal(ledger_filename) {
        return LedgerPathPlan {
            base_directory: base_directory.to_string(),
            ledger_filename: ledger_filename.to_string(),
            full_ledger_path: String::new(),
            namespace_label: namespace_label.to_string(),
            path_status: PathStatus::Rejected(format!(
                "parent traversal in filename: {:?}",
                ledger_filename
            )),
            safe_reason: format!(
                "rejected: filename contains parent traversal: {:?}",
                ledger_filename
            ),
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            persistence_enabled: false,
            symlink_resolution_performed: false,
        };
    }

    // Reject parent traversal in base path
    if contains_parent_traversal(base_directory) {
        return LedgerPathPlan {
            base_directory: base_directory.to_string(),
            ledger_filename: ledger_filename.to_string(),
            full_ledger_path: String::new(),
            namespace_label: namespace_label.to_string(),
            path_status: PathStatus::Rejected(format!(
                "parent traversal in base path: {:?}",
                base_directory
            )),
            safe_reason: format!(
                "rejected: base path contains parent traversal: {:?}",
                base_directory
            ),
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            persistence_enabled: false,
            symlink_resolution_performed: false,
        };
    }

    // Reject suspicious filenames
    if is_filename_suspicious(ledger_filename) {
        return LedgerPathPlan {
            base_directory: base_directory.to_string(),
            ledger_filename: ledger_filename.to_string(),
            full_ledger_path: String::new(),
            namespace_label: namespace_label.to_string(),
            path_status: PathStatus::Rejected(format!(
                "suspicious filename: {:?}",
                ledger_filename
            )),
            safe_reason: format!(
                "rejected: filename contains suspicious characters: {:?}",
                ledger_filename
            ),
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            persistence_enabled: false,
            symlink_resolution_performed: false,
        };
    }

    // Build full path: base_directory / namespace_label / ledger_filename
    let full_path = format!(
        "{}/{}/{}",
        base_directory.trim_end_matches('/'),
        namespace_label,
        ledger_filename
    );

    // Validate namespace containment
    // The full path must contain the namespace label as a path component
    let ns_component = format!("/{}", namespace_label);
    if !full_path.contains(&ns_component) {
        return LedgerPathPlan {
            base_directory: base_directory.to_string(),
            ledger_filename: ledger_filename.to_string(),
            full_ledger_path: full_path.clone(),
            namespace_label: namespace_label.to_string(),
            path_status: PathStatus::Rejected(format!(
                "path {:?} is outside namespace {:?}",
                full_path, namespace_label
            )),
            safe_reason: format!(
                "rejected: path {:?} is outside configured namespace {:?}",
                full_path, namespace_label
            ),
            model_only: true,
            filesystem_read_performed: false,
            filesystem_write_performed: false,
            persistence_enabled: false,
            symlink_resolution_performed: false,
        };
    }

    LedgerPathPlan {
        base_directory: base_directory.to_string(),
        ledger_filename: ledger_filename.to_string(),
        full_ledger_path: full_path,
        namespace_label: namespace_label.to_string(),
        path_status: PathStatus::Accepted,
        safe_reason: "path accepted: within configured namespace".to_string(),
        model_only: true,
        filesystem_read_performed: false,
        filesystem_write_performed: false,
        persistence_enabled: false,
        symlink_resolution_performed: false,
    }
}

/// Render a ledger path plan as a human-readable string.
///
/// The output includes the planned path components, validation status, and
/// comprehensive safety disclaimers.
///
/// # Safety Disclaimers (10 total)
///
/// 1. persistence path model only
/// 2. no filesystem read was performed
/// 3. no filesystem write was performed
/// 4. no ledger file was created
/// 5. no ledger file was read
/// 6. persistence is not enabled
/// 7. no live /proc or sysfs read was performed
/// 8. no quota enforcement or network blocking is active
/// 9. no nft/tc/Zelynic state mutation was performed
/// 10. no symlink resolution was performed
pub fn render_ledger_path_plan(plan: &LedgerPathPlan) -> String {
    let mut out = String::new();

    out.push_str("Zelynic v2.9 persistence path plan (persistence path model only)\n");
    out.push('\n');

    // Path components
    out.push_str(&format!("Base directory: {}\n", plan.base_directory));
    out.push_str(&format!("Namespace label: {}\n", plan.namespace_label));
    out.push_str(&format!("Ledger filename: {}\n", plan.ledger_filename));
    out.push_str(&format!("Full ledger path: {}\n", plan.full_ledger_path));
    out.push('\n');

    // Status
    match &plan.path_status {
        PathStatus::Accepted => {
            out.push_str("Path status: accepted\n");
            out.push_str(&format!("Reason: {}\n", plan.safe_reason));
        }
        PathStatus::Rejected(reason) => {
            out.push_str("Path status: rejected\n");
            out.push_str(&format!("Reason: {}\n", reason));
        }
    }
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
        "Persistence enabled: {}\n",
        plan.persistence_enabled
    ));
    out.push('\n');

    // 9 safety disclaimers
    out.push_str("Safety disclaimers:\n");
    out.push_str("  - persistence path model only\n");
    out.push_str("  - no filesystem read was performed\n");
    out.push_str("  - no filesystem write was performed\n");
    out.push_str("  - no ledger file was created\n");
    out.push_str("  - no ledger file was read\n");
    out.push_str("  - persistence is not enabled\n");
    out.push_str("  - no live /proc or sysfs read was performed\n");
    out.push_str("  - no quota enforcement or network blocking is active\n");
    out.push_str("  - no nft/tc/Zelynic state mutation was performed\n");
    out.push_str("  - no symlink resolution was performed\n");

    out
}
