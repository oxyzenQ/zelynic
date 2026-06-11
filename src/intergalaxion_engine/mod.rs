// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Intergalaxion Engine — pure eBPF experimental engine skeleton (Phase I-0).
//!
//! This module is the future core engine for zelynic. In the current
//! intergalaxion branch it exists as a **compile-safe, observer-only**
//! skeleton with no live kernel side effects, no enforcement, and no
//! mutation of nft/tc/cgroup/PID state.
//!
//! # Design constraints (I-0)
//!
//! * Observer-only — no packet drop, no enforcement, no quota.
//! * No live eBPF program attach in this phase.
//! * No new CLI commands, no block/allow/quota, no nft/tc backend.
//! * No changes to existing stable CLI behavior or ledger JSON schemas.
//! * No changes to v3.1.0 release artifacts.
//!
//! # Public submodules
//!
//! | Module | Purpose |
//! |---|---|
//! | [`identity`] | Process and cgroup identity anchor |
//! | [`telemetry`] | eBPF telemetry data model |
//! | [`ledger_bridge`] | Bridge between eBPF events and the stable ledger |
//! | [`safety`] | Safety boundaries and invariant checks |
//! | [`backends`] | Backend state management (eBPF only in this branch) |

#![allow(dead_code)]

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_i10a;
#[cfg(test)]
mod tests_i10b;
#[cfg(test)]
mod tests_i10c;
#[cfg(test)]
mod tests_i10d;
#[cfg(test)]
mod tests_i10e;
#[cfg(test)]
mod tests_i3;
#[cfg(test)]
mod tests_i4;
#[cfg(test)]
mod tests_i5;
#[cfg(test)]
mod tests_i6;
#[cfg(test)]
mod tests_i7;
#[cfg(test)]
mod tests_i8;
#[cfg(test)]
mod tests_i9;

pub mod live_attach_runbook;
pub mod live_readiness;
pub mod static_audit;

pub mod backends;
pub mod identity;
pub mod ledger_bridge;
pub mod safety;
pub mod telemetry;

/// Live-readiness gate module.
#[allow(unused_imports)]
pub use live_readiness::*;

/// Static safety audit module.
#[allow(unused_imports)]
pub use static_audit::*;

/// Live attach runbook module.
#[allow(unused_imports)]
pub use live_attach_runbook::*;

/// Top-level engine state summary for the intergalaxion branch.
///
/// All fields default to their safest values: backend unavailable,
/// observer inactive, no enforcement, no mutation.
#[derive(Debug, Clone, Default)]
pub struct EngineState {
    /// Whether any backend is detected and available.
    pub backend_available: bool,
    /// Whether the observer loop is running.
    pub observer_active: bool,
    /// Whether packet drop is enabled (always false in I-0).
    pub packet_drop_enabled: bool,
    /// Whether enforcement is enabled (always false in I-0).
    pub enforcement_enabled: bool,
    /// Whether quota tracking is enabled (always false in I-0).
    pub quota_enabled: bool,
    /// Whether any kernel mutation was performed (always false in I-0).
    pub mutation_performed: bool,
}
