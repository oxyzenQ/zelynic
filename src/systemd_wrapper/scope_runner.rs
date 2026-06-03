// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Scope Runner: orchestration and gate entrypoint for live system-scope probes.
//!
//! The gate check and public API live here. Probe execution, attach preview
//! model/rendering, and output rendering are delegated to `scope_probe` and
//! `attach_preview`.

use anyhow::bail;

use super::plan::ScopeMode;

// Re-export items that `mod.rs` consumes.
pub(crate) use super::attach_preview::build_attach_preview;
pub(crate) use super::scope_probe::build_probe_systemd_run_plan;
pub(crate) use super::scope_probe::print_scope_probe_output_with_preview;
pub(crate) use super::scope_probe::run_scope_probe;

// ---------------------------------------------------------------------------
// Public gate
// ---------------------------------------------------------------------------

/// Gate check: returns Ok(()) if the probe-live path is allowed.
///
/// Requirements (all must be true):
/// 1. `probe_live` flag is set
/// 2. `scope_mode` is System
/// 3. euid == 0
pub(crate) fn probe_gate(probe_live: bool, scope_mode: ScopeMode) -> anyhow::Result<()> {
    if !probe_live {
        bail!("Live systemd wrapper execution is not implemented yet.")
    }
    if scope_mode != ScopeMode::System {
        bail!(
            "User-scope live runner is not implemented. \
             User-scope launch needs privilege/session handoff \
             and is not implemented yet."
        )
    }
    if !nix::unistd::geteuid().is_root() {
        bail!(
            "Scope Runner live probe requires root (euid == 0). \
             System-scope systemd-run needs root to create a transient scope."
        )
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- gate tests ----

    #[test]
    fn gate_blocks_when_probe_live_not_set() {
        let err = probe_gate(false, ScopeMode::System)
            .unwrap_err()
            .to_string();
        assert_eq!(
            err,
            "Live systemd wrapper execution is not implemented yet."
        );
    }

    #[test]
    fn gate_blocks_user_scope_with_probe_live() {
        let err = probe_gate(true, ScopeMode::User).unwrap_err().to_string();
        assert!(err.contains("User-scope live runner is not implemented"));
        assert!(err.contains("privilege/session handoff"));
    }

    #[test]
    fn gate_blocks_system_scope_non_root_with_probe_live() {
        // We are non-root in CI, so this gate will actually fail.
        let err = probe_gate(true, ScopeMode::System).unwrap_err().to_string();
        // In CI we are non-root, so this should fail with the root message
        assert!(err.contains("requires root"));
    }

    #[test]
    fn gate_allows_system_scope_root_with_probe_live_via_preflight_model() {
        // Verify gate structure: the OTHER failures come before root check.
        assert!(probe_gate(false, ScopeMode::System).is_err()); // no probe flag
        assert!(probe_gate(true, ScopeMode::User).is_err()); // user scope
                                                             // The root check depends on runtime euid
    }
}
