// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Safety boundary module for the Intergalaxion Engine.
//!
//! This module defines the safety invariant model. In I-0 the engine
//! guarantees that no kernel mutation, no enforcement, and no packet
//! drop can occur regardless of internal state.

/// Safety invariant violations that would prevent engine activation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyViolation {
    /// Attempted to activate enforcement in observer-only mode.
    EnforcementInObserverMode,
    /// Attempted to attach an eBPF program without an explicit gate.
    AttachWithoutGate,
    /// Attempted to mutate nft/tc/cgroup/PID state.
    MutationNotAllowed,
    /// Attempted to enable packet drop in observer-only mode.
    PacketDropInObserverMode,
}

/// Safety check result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyCheck {
    /// All invariants are satisfied; operation is allowed.
    Ok,
    /// One or more violations detected.
    Violation(SafetyViolation),
}

/// Run the I-0 safety invariant check.
///
/// In I-0, the only valid state is observer-only with no mutations.
/// This function always returns `SafetyCheck::Ok` for the default
/// engine state because no operations are allowed that could violate
/// the invariants.
pub fn check_i0_invariants(
    engine_active: bool,
    enforcement: bool,
    mutation: bool,
) -> SafetyCheck {
    if enforcement {
        return SafetyCheck::Violation(SafetyViolation::EnforcementInObserverMode);
    }
    if mutation {
        return SafetyCheck::Violation(SafetyViolation::MutationNotAllowed);
    }
    let _ = engine_active;
    SafetyCheck::Ok
}
