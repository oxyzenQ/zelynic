// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//! Local attach smoke test artifact contract and detach proof for the
//! Intergalaxion Engine.
//!
//! Phase I-10D adds pure model types for an eBPF object artifact contract,
//! detach proof, and local lab run recipe. This phase must NOT implement
//! real live attach, NOT call BPF load APIs, NOT attach programs, NOT
//! create maps, NOT open ring buffers, NOT read live kernel events, NOT
//! pin maps, NOT enforce, NOT mutate, and NOT expose public CLI. The
//! artifact contract models honestly whether an eBPF object exists, and
//! the detach proof tracks whether cleanup was performed correctly.
//!
//! # Design constraints (I-10D)
//!
//! * Disabled by default — no live attach without the
//! * `intergalaxion-live-attach-lab` Cargo feature.
//! * No public CLI exposure.
//! * No enforcement, no packet drop, no block/allow/quota.
//! * No nft/tc backend.
//! * No ring buffer open.
//! * No live kernel event read.
//! * No map pin.
//! * No ledger file write.
//! * No persistence.
//! * Normal tests remain rootless.
//! * Normal CI does not perform live attach.
//! * Artifact absence must be reported honestly.
//! * Detach proof must not fake success.

/// Status of an eBPF live attach artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfLiveAttachArtifactStatus {
    /// No artifact exists at all.
    MissingArtifact,
    /// Artifact is declared but not yet built.
    DeclaredOnly,
    /// Artifact build is planned but not yet compiled.
    BuildPlanned,
    /// Artifact is built and ready for potential attach.
    BuildReady,
    /// Artifact target is unsupported on this host.
    Unsupported,
}

impl EbpfLiveAttachArtifactStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingArtifact => "missing_artifact",
            Self::DeclaredOnly => "declared_only",
            Self::BuildPlanned => "build_planned",
            Self::BuildReady => "build_ready",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Contract describing an eBPF live attach artifact.
///
/// Models whether an eBPF object artifact exists, how it is built, and
/// what safety constraints apply. All forbidden-operation fields default
/// to their safest values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLiveAttachArtifactContract {
    /// Human-readable name of the artifact.
    pub artifact_name: String,
    /// Current status of the artifact.
    pub artifact_status: EbpfLiveAttachArtifactStatus,
    /// Whether actual object bytes are embedded in the binary.
    pub object_bytes_embedded: bool,
    /// Whether an object file path is declared.
    pub object_path_declared: bool,
    /// Whether a BPF build target is declared.
    pub build_target_declared: bool,
    /// Whether normal CI builds this artifact (must be false).
    pub normal_ci_builds_artifact: bool,
    /// Whether normal tests require this artifact (must be false).
    pub normal_tests_require_artifact: bool,
    /// The Cargo feature required to enable artifact use.
    pub feature_required: String,
    /// Whether this artifact is observer-only (must be true).
    pub observer_only: bool,
    /// Whether enforcement is allowed (must be false).
    pub enforcement_allowed: bool,
    /// Whether packet drop is allowed (must be false).
    pub packet_drop_allowed: bool,
    /// Whether a ring buffer is required (must be false).
    pub ring_buffer_required: bool,
    /// Whether map pinning is required (must be false).
    pub map_pin_required: bool,
    /// Whether persistence is required (must be false).
    pub persistence_required: bool,
}

/// Status of the detach proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EbpfDetachProofStatus {
    /// Detach has not been attempted.
    NotAttempted,
    /// Detach is planned but not yet executed.
    DetachPlanned,
    /// Programs were detached cleanly.
    DetachedCleanly,
    /// Detach failed.
    DetachFailed,
    /// Manual cleanup is required.
    ManualCleanupRequired,
}

impl EbpfDetachProofStatus {
    /// Stable lowercase label used by tests and future reports.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not_attempted",
            Self::DetachPlanned => "detach_planned",
            Self::DetachedCleanly => "detached_cleanly",
            Self::DetachFailed => "detach_failed",
            Self::ManualCleanupRequired => "manual_cleanup_required",
        }
    }
}

/// Proof that detach was performed (or not) after a live attach spike.
///
/// Tracks whether programs were unloaded, maps unpinned, ring buffers
/// closed, and whether any unsafe operations occurred. All operation
/// flags default to their safest values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfDetachProof {
    /// Current status of the detach proof.
    pub status: EbpfDetachProofStatus,
    /// Whether detach is required.
    pub detach_required: bool,
    /// Whether detach was attempted.
    pub detach_attempted: bool,
    /// Whether detach succeeded.
    pub detach_succeeded: bool,
    /// Whether manual cleanup is required.
    pub manual_cleanup_required: bool,
    /// Whether attach was ever attempted.
    pub attach_was_attempted: bool,
    /// Whether attach was successful.
    pub attach_was_successful: bool,
    /// Whether the program was unloaded.
    pub program_unloaded: bool,
    /// Whether maps were unpinned.
    pub map_unpinned: bool,
    /// Whether ring buffers were closed.
    pub ring_buffer_closed: bool,
    /// Whether persistence was cleaned.
    pub persistence_cleaned: bool,
    /// Whether kernel state was mutated.
    pub kernel_state_mutated: bool,
    /// Whether enforcement was performed.
    pub enforcement_performed: bool,
    /// Whether packet drop was performed.
    pub packet_drop_performed: bool,
    /// Human-readable notes.
    pub notes: Vec<String>,
}

/// Local lab run recipe for a future minimal live observer attach smoke
/// test.
///
/// Combines the artifact contract, detach proof, and safety constraints
/// into a single recipe. The default recipe is entirely inert — no live
/// attach occurs, no CI/test integration, and all forbidden-operation
/// flags are false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfLocalAttachSmokeRecipe {
    /// The phase label for this recipe (always "I-10D").
    pub phase: String,
    /// Whether this recipe is restricted to local lab only.
    pub local_lab_only: bool,
    /// The Cargo feature required to enable the recipe.
    pub feature_required: String,
    /// Whether public CLI is allowed (always false).
    pub public_cli_allowed: bool,
    /// Whether root is required for manual lab execution.
    pub root_required_for_manual_lab: bool,
    /// Whether an explicit operator label is required.
    pub operator_label_required: bool,
    /// Whether detach is required.
    pub detach_required: bool,
    /// The embedded artifact contract.
    pub artifact: EbpfLiveAttachArtifactContract,
    /// The embedded detach proof.
    pub detach_proof: EbpfDetachProof,
    /// Whether normal tests execute live attach (must be false).
    pub normal_tests_execute_live_attach: bool,
    /// Whether normal CI executes live attach (must be false).
    pub normal_ci_executes_live_attach: bool,
    /// Whether enforcement is allowed (must be false).
    pub enforcement_allowed: bool,
    /// Whether packet drop is allowed (must be false).
    pub packet_drop_allowed: bool,
    /// Whether ring buffer open is allowed (must be false).
    pub ring_buffer_open_allowed: bool,
    /// Whether live event read is allowed (must be false).
    pub live_event_read_allowed: bool,
    /// Whether map pin is allowed (must be false).
    pub map_pin_allowed: bool,
    /// Whether persistence is allowed (must be false).
    pub persistence_allowed: bool,
    /// Whether mutation was performed (must be false).
    pub mutation_performed: bool,
}

// ── Helper functions ──────────────────────────────────────────────────

/// Create the default live attach artifact contract.
///
/// The default contract honestly reports `MissingArtifact` and has all
/// safety flags in their safest configuration.
pub fn default_live_attach_artifact_contract() -> EbpfLiveAttachArtifactContract {
    EbpfLiveAttachArtifactContract {
        artifact_name: String::from("intergalaxion-observer"),
        artifact_status: EbpfLiveAttachArtifactStatus::MissingArtifact,
        object_bytes_embedded: false,
        object_path_declared: false,
        build_target_declared: false,
        normal_ci_builds_artifact: false,
        normal_tests_require_artifact: false,
        feature_required: String::from("intergalaxion-live-attach-lab"),
        observer_only: true,
        enforcement_allowed: false,
        packet_drop_allowed: false,
        ring_buffer_required: false,
        map_pin_required: false,
        persistence_required: false,
    }
}

/// Create the default detach proof.
///
/// The default proof honestly reports `NotAttempted` with `detach_required`
/// true and `detach_attempted` false. No operation flags are set.
pub fn default_detach_proof() -> EbpfDetachProof {
    EbpfDetachProof {
        status: EbpfDetachProofStatus::NotAttempted,
        detach_required: true,
        detach_attempted: false,
        detach_succeeded: false,
        manual_cleanup_required: false,
        attach_was_attempted: false,
        attach_was_successful: false,
        program_unloaded: false,
        map_unpinned: false,
        ring_buffer_closed: false,
        persistence_cleaned: false,
        kernel_state_mutated: false,
        enforcement_performed: false,
        packet_drop_performed: false,
        notes: Vec::new(),
    }
}

/// Create the default local attach smoke recipe.
///
/// The default recipe is entirely inert: local lab only, no public CLI,
/// no enforcement, no packet drop, no ring buffer, no event read, no
/// map pin, no persistence, no mutation, and no live attach in normal
/// tests or CI.
pub fn default_local_attach_smoke_recipe() -> EbpfLocalAttachSmokeRecipe {
    EbpfLocalAttachSmokeRecipe {
        phase: String::from("I-10D"),
        local_lab_only: true,
        feature_required: String::from("intergalaxion-live-attach-lab"),
        public_cli_allowed: false,
        root_required_for_manual_lab: true,
        operator_label_required: true,
        detach_required: true,
        artifact: default_live_attach_artifact_contract(),
        detach_proof: default_detach_proof(),
        normal_tests_execute_live_attach: false,
        normal_ci_executes_live_attach: false,
        enforcement_allowed: false,
        packet_drop_allowed: false,
        ring_buffer_open_allowed: false,
        live_event_read_allowed: false,
        map_pin_allowed: false,
        persistence_allowed: false,
        mutation_performed: false,
    }
}

/// Validate that a live attach artifact contract does not have any
/// unsafe configuration.
///
/// Returns `Ok(())` if the contract is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
pub fn validate_live_attach_artifact_contract(
    contract: &EbpfLiveAttachArtifactContract,
) -> Result<(), String> {
    if !contract.observer_only {
        return Err("observer_only must be true".to_string());
    }
    if contract.enforcement_allowed {
        return Err("enforcement_allowed must be false".to_string());
    }
    if contract.packet_drop_allowed {
        return Err("packet_drop_allowed must be false".to_string());
    }
    if contract.ring_buffer_required {
        return Err("ring_buffer_required must be false".to_string());
    }
    if contract.map_pin_required {
        return Err("map_pin_required must be false".to_string());
    }
    if contract.persistence_required {
        return Err("persistence_required must be false".to_string());
    }
    if contract.normal_ci_builds_artifact {
        return Err("normal_ci_builds_artifact must be false".to_string());
    }
    if contract.normal_tests_require_artifact {
        return Err("normal_tests_require_artifact must be false".to_string());
    }
    if contract.artifact_name.is_empty() {
        return Err("artifact_name must not be empty".to_string());
    }
    if contract.feature_required.is_empty() {
        return Err("feature_required must not be empty".to_string());
    }
    Ok(())
}

/// Validate that a detach proof does not have any inconsistent or unsafe
/// flags.
///
/// Returns `Ok(())` if the proof is safe. Returns `Err(description)`
/// if any unsafe or inconsistent condition is detected.
pub fn validate_detach_proof(proof: &EbpfDetachProof) -> Result<(), String> {
    if proof.kernel_state_mutated {
        return Err("kernel_state_mutated must be false".to_string());
    }
    if proof.enforcement_performed {
        return Err("enforcement_performed must be false".to_string());
    }
    if proof.packet_drop_performed {
        return Err("packet_drop_performed must be false".to_string());
    }
    if proof.program_unloaded && !proof.detach_attempted {
        return Err("program_unloaded requires detach_attempted".to_string());
    }
    if proof.map_unpinned {
        return Err("map_unpinned must be false".to_string());
    }
    if proof.ring_buffer_closed {
        return Err("ring_buffer_closed must be false".to_string());
    }
    if proof.persistence_cleaned {
        return Err("persistence_cleaned must be false".to_string());
    }
    if proof.attach_was_successful && !proof.attach_was_attempted {
        return Err("attach_was_successful requires attach_was_attempted".to_string());
    }
    if proof.detach_succeeded && !proof.detach_attempted {
        return Err("detach_succeeded requires detach_attempted".to_string());
    }
    match proof.status {
        EbpfDetachProofStatus::DetachedCleanly => {
            if !proof.attach_was_attempted {
                return Err("DetachedCleanly requires attach_was_attempted".to_string());
            }
            if !proof.detach_succeeded {
                return Err("DetachedCleanly requires detach_succeeded".to_string());
            }
        }
        EbpfDetachProofStatus::ManualCleanupRequired => {
            if matches!(proof.status, EbpfDetachProofStatus::DetachedCleanly) {
                return Err(
                    "ManualCleanupRequired conflicts with DetachedCleanly status".to_string(),
                );
            }
        }
        _ => {}
    }
    Ok(())
}

/// Validate that a local attach smoke recipe does not have any unsafe
/// configuration.
///
/// Returns `Ok(())` if the recipe is safe. Returns `Err(description)`
/// if any unsafe condition is detected.
pub fn validate_local_attach_smoke_recipe(
    recipe: &EbpfLocalAttachSmokeRecipe,
) -> Result<(), String> {
    if !recipe.local_lab_only {
        return Err("local_lab_only must be true".to_string());
    }
    if recipe.public_cli_allowed {
        return Err("public_cli_allowed must be false".to_string());
    }
    if recipe.normal_tests_execute_live_attach {
        return Err("normal_tests_execute_live_attach must be false".to_string());
    }
    if recipe.normal_ci_executes_live_attach {
        return Err("normal_ci_executes_live_attach must be false".to_string());
    }
    if recipe.enforcement_allowed {
        return Err("enforcement_allowed must be false".to_string());
    }
    if recipe.packet_drop_allowed {
        return Err("packet_drop_allowed must be false".to_string());
    }
    if recipe.ring_buffer_open_allowed {
        return Err("ring_buffer_open_allowed must be false".to_string());
    }
    if recipe.live_event_read_allowed {
        return Err("live_event_read_allowed must be false".to_string());
    }
    if recipe.map_pin_allowed {
        return Err("map_pin_allowed must be false".to_string());
    }
    if recipe.persistence_allowed {
        return Err("persistence_allowed must be false".to_string());
    }
    if recipe.mutation_performed {
        return Err("mutation_performed must be false".to_string());
    }
    if recipe.phase.is_empty() {
        return Err("phase must not be empty".to_string());
    }
    if recipe.feature_required.is_empty() {
        return Err("feature_required must not be empty".to_string());
    }
    validate_live_attach_artifact_contract(&recipe.artifact)?;
    validate_detach_proof(&recipe.detach_proof)?;
    Ok(())
}

/// Map a live attach artifact status to a stable human-readable label.
pub fn live_attach_artifact_status_label(status: EbpfLiveAttachArtifactStatus) -> &'static str {
    status.as_str()
}

/// Map a detach proof status to a stable human-readable label.
pub fn detach_proof_status_label(status: EbpfDetachProofStatus) -> &'static str {
    status.as_str()
}
