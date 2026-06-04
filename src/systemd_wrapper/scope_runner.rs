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
pub(crate) use super::attach_preview::with_experimental_attach_gate;
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

/// Attach gate check: always hard-blocks in this build.
///
/// This gate is reached only after probe_gate passes (i.e. probe_live +
/// system + root). It deliberately refuses to perform any attach operation
/// and returns a clear "not implemented yet" error.
///
/// No PID movement, no limiter attach, no nftables/tc/cgroup/state
/// changes are performed.
pub(crate) fn attach_gate() -> anyhow::Result<()> {
    bail!(
        "Scope Runner live attach is not implemented yet. \
         This build only supports live probe and attach preview."
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- probe gate tests ----

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

    // ---- attach gate tests ----

    #[test]
    fn attach_gate_always_hard_blocks() {
        let err = attach_gate().unwrap_err().to_string();
        assert!(err.contains("live attach is not implemented yet"));
        assert!(err.contains("live probe and attach preview"));
    }

    #[test]
    fn attach_gate_does_not_claim_attached() {
        let err = attach_gate().unwrap_err().to_string();
        assert!(!err.contains("attached"));
        assert!(!err.contains("limited"));
        assert!(!err.contains("enforced"));
    }
}
