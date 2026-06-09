// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure ledger-identity alignment model for v3.1 phase 3.
//!
//! This module provides a pure adapter between the existing ledger model
//! (v2.9 `Ledger` / `LedgerEntry`) and the v3.1 identity model
//! (`TargetIdentity`, `ResolvedUsageTarget`, `UsageAttributionScope`).
//! It performs **no** filesystem reads, **no** filesystem writes, **no**
//! live system reads, **no** enforcement, **no** quota management, **no**
//! network blocking, **no** eBPF, **no** PID movement, and **no** cgroup writes.
//!
//! # Safety
//!
//! - No filesystem I/O — all operations are pure in-memory transformations.
//! - No live `/proc/net/dev` or sysfs reads.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//! - No ledger persistence write path is enabled.
//! - No changes to existing `LedgerEntry` serde schema.
//!
//! # Phase 3 Scope
//!
//! Phase 3 aligns the existing ledger model with the v3.1 identity model
//! without enabling persistence or runtime resolution. The attachment is
//! a separate model-only construct — existing ledger entries are NOT mutated
//! and existing JSON deserialization remains fully backward compatible.

#![allow(dead_code)]
#![allow(unused_imports)]

use super::identity::{
    default_identity_honesty, IdentityHonesty, InterfaceIdentity, ProcessIdentity,
    ResolvedUsageTarget, TargetIdentity, UsageAttributionScope,
};
use super::ledger::LedgerEntry;

/// Optional identity attachment for a ledger entry.
///
/// This is a **separate** model construct that wraps identity information
/// alongside a ledger entry's existing fields. The ledger entry itself is
/// NOT modified — the attachment lives alongside it.
///
/// When `identity` is `None`, the entry has interface-level-only attribution
/// (the existing default). When `identity` is `Some`, best-effort attribution
/// is provided via the attached `ResolvedUsageTarget`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerIdentityAttachment {
    /// The original ledger entry (borrowed conceptually, cloned here for
    /// pure-model ownership).
    pub entry: LedgerEntry,
    /// Optional identity resolved for this entry. `None` means interface-level
    /// only (no per-app claim).
    pub identity: Option<ResolvedUsageTarget>,
    /// Honesty flags for this attachment. Always uses default identity
    /// honesty — attribution is always best-effort.
    pub honesty: IdentityHonesty,
}

/// Build an identity attachment from a ledger entry with interface-only scope.
///
/// This derives a `ResolvedUsageTarget` from the entry's interface field.
/// No process or cgroup identity is claimed — attribution scope is
/// `InterfaceOnly`.
pub fn build_interface_only_attachment(entry: &LedgerEntry) -> LedgerIdentityAttachment {
    let loopback = entry.interface == "lo";
    let resolved = ResolvedUsageTarget::interface_only(&entry.interface, loopback);
    LedgerIdentityAttachment {
        entry: entry.clone(),
        identity: Some(resolved),
        honesty: default_identity_honesty(),
    }
}

/// Build an identity attachment with explicit identity information.
///
/// This allows attaching a pre-built `ResolvedUsageTarget` (with process
/// or cgroup best-effort identity) to a ledger entry. The attribution
/// scope comes from the provided identity.
pub fn build_identity_attachment(
    entry: &LedgerEntry,
    identity: ResolvedUsageTarget,
) -> LedgerIdentityAttachment {
    LedgerIdentityAttachment {
        entry: entry.clone(),
        identity: Some(identity),
        honesty: default_identity_honesty(),
    }
}

/// Build an attachment with no identity (interface-level only, no attachment).
///
/// This represents the default case where the ledger entry has no
/// per-app identity claim — it remains interface-level only.
pub fn build_no_identity_attachment(entry: &LedgerEntry) -> LedgerIdentityAttachment {
    LedgerIdentityAttachment {
        entry: entry.clone(),
        identity: None,
        honesty: default_identity_honesty(),
    }
}

/// Render a ledger identity attachment as a human-readable string.
///
/// When identity is present, includes the resolved target information with
/// best-effort disclaimers. When identity is absent, states that the entry
/// has interface-level-only attribution with no per-app claim.
pub fn render_ledger_identity_attachment(attachment: &LedgerIdentityAttachment) -> String {
    let mut out = String::new();

    out.push_str(&format!("Entry: {}\n", attachment.entry.entry_id));
    out.push_str(&format!("Interface: {}\n", attachment.entry.interface));
    out.push_str(&format!("Entry type: {}\n", attachment.entry.entry_type));

    match &attachment.identity {
        Some(resolved) => {
            out.push_str(&format!(
                "Attribution scope: {} (best-effort)\n",
                resolved.attribution_scope
            ));
            out.push_str("Identity: present (best-effort, not enforcement-grade)\n");

            let id = &resolved.identity;
            if let Some(ref iface) = id.interface {
                let lb = if iface.loopback { " (loopback)" } else { "" };
                out.push_str(&format!("  Interface: {}{}\n", iface.name, lb));
            }
            if let Some(ref proc) = id.process {
                if let Some(pid) = proc.pid {
                    out.push_str(&format!(
                        "  PID: {} (best-effort: PIDs are recycled)\n",
                        pid
                    ));
                }
                if let Some(ref comm) = proc.comm {
                    out.push_str(&format!("  Comm: {}\n", comm));
                }
                if let Some(ref path) = proc.executable_path {
                    out.push_str(&format!("  Executable: {}\n", path));
                }
            }
            if let Some(ref cg) = id.cgroup {
                if let Some(ref path) = cg.cgroup_path {
                    out.push_str(&format!("  Cgroup: {}\n", path));
                }
                if let Some(ref unit) = cg.systemd_unit {
                    out.push_str(&format!("  Systemd unit: {} (best-effort)\n", unit));
                }
            }

            out.push('\n');
            out.push_str("Identity attribution is best-effort.\n");
        }
        None => {
            out.push_str("Attribution: interface-level only (no per-app identity)\n");
        }
    }

    out.push_str("No enforcement, no persistence, no mutation.\n");

    out
}

/// Render a summary for multiple identity attachments.
///
/// Provides a count breakdown of entries with and without identity,
/// and lists the attribution scopes present.
pub fn render_identity_summary(attachments: &[LedgerIdentityAttachment]) -> String {
    let mut out = String::new();

    let total = attachments.len();
    let with_identity: usize = attachments.iter().filter(|a| a.identity.is_some()).count();
    let without_identity = total - with_identity;

    out.push_str(&format!(
        "Ledger identity alignment summary ({} entries)\n",
        total
    ));
    out.push_str(&format!(
        "  With identity (best-effort): {}\n",
        with_identity
    ));
    out.push_str(&format!(
        "  Without identity (interface-only): {}\n",
        without_identity
    ));

    let mut scopes: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for att in attachments {
        match &att.identity {
            Some(resolved) => {
                scopes.insert(resolved.attribution_scope.to_string());
            }
            None => {
                scopes.insert("interface-level only".to_string());
            }
        }
    }

    if !scopes.is_empty() {
        out.push_str(&format!(
            "  Attribution scopes: {}\n",
            scopes.iter().cloned().collect::<Vec<_>>().join(", ")
        ));
    }

    out.push('\n');
    out.push_str("All identity attribution is best-effort.\n");
    out.push_str("No enforcement, no persistence, no mutation.\n");

    out
}
