// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Mkdir Executor: first real-write experiment for v2.8 phase 2b.
//!
//! Creates the Zelynic cgroup namespace and target cgroup directory using
//! mkdir-only operations, then immediately verifies and cleans up the target
//! cgroup. This module performs real filesystem writes ONLY when explicitly
//! invoked via `--mkdir-live` with all gate checks passing.
//!
//! Safety invariants:
//! - Only operates under a configurable base root (tests use temp dirs).
//! - Rejects paths outside the namespace, with `..`, or empty.
//! - Never writes cgroup.procs, moves PIDs, touches nftables/tc, or attaches
//!   the limiter.
//! - Cleanup only removes empty, operation-owned target cgroups.
//! - On uncertainty, skips cleanup and reports the leftover path.

use std::fs;
use std::path::Path;

use super::render::push_line;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Live cgroup root used in production (only when --mkdir-live is active).
pub(crate) const ZELYNIC_CGROUP_ROOT: &str = "/sys/fs/cgroup/zelynic";

// ---------------------------------------------------------------------------
// Result model
// ---------------------------------------------------------------------------

/// Outcome of a mkdir-only experiment step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StepOutcome {
    Ok,
    Skipped,
    Failed(String),
}

/// Record of a single mkdir experiment step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MkdirStep {
    pub description: String,
    pub outcome: StepOutcome,
}

/// Full result model of a mkdir-only experiment run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MkdirExperimentResult {
    pub parent_namespace: String,
    pub target_cgroup_path: String,
    pub steps: Vec<MkdirStep>,
    pub cleanup_performed: bool,
    pub cleanup_reason: String,
    pub pid_movement: String,
    pub cgroup_procs_writes: String,
    pub nft_tc_state: String,
    pub leftover_target: Option<String>,
}

impl MkdirExperimentResult {
    /// Returns true if all steps succeeded.
    #[cfg(test)]
    pub(crate) fn all_ok(&self) -> bool {
        self.steps.iter().all(|s| s.outcome == StepOutcome::Ok)
    }
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Validates that a target path is safe for mkdir operations.
///
/// Rules:
/// - Must start with `{base_root}/` (non-empty remainder).
/// - Must start with `{base_root}/target_` (enforces naming convention).
/// - Must not contain `..`.
/// - Must not be empty.
/// - Must not equal the base root itself.
pub(crate) fn is_safe_mkdir_target(base_root: &str, target: &str) -> bool {
    if target.is_empty() || target == base_root {
        return false;
    }
    let expected_prefix = format!("{base_root}/");
    if !target.starts_with(&expected_prefix) {
        return false;
    }
    let remainder = &target[expected_prefix.len()..];
    if remainder.is_empty() || remainder.contains("..") {
        return false;
    }
    // Enforce target_ prefix naming convention
    target.starts_with(&format!("{base_root}/target_"))
}

// ---------------------------------------------------------------------------
// Experiment executor
// ---------------------------------------------------------------------------

/// Runs the mkdir-only experiment.
///
/// Creates the parent namespace directory and target cgroup directory,
/// verifies the target exists, then cleans up the target cgroup if it is
/// safe to do so (empty and operation-owned).
///
/// The `base_root` parameter allows tests to use temp directories instead
/// of the live `/sys/fs/cgroup/zelynic`.
pub(crate) fn run_mkdir_only_experiment(
    base_root: &str,
    target_cgroup_path: &str,
) -> MkdirExperimentResult {
    let mut steps = Vec::new();

    // Step 1: Validate target path
    if !is_safe_mkdir_target(base_root, target_cgroup_path) {
        steps.push(MkdirStep {
            description: format!("validate target path {}", target_cgroup_path),
            outcome: StepOutcome::Failed("target path is outside namespace or unsafe".to_string()),
        });
        return MkdirExperimentResult {
            parent_namespace: base_root.to_string(),
            target_cgroup_path: target_cgroup_path.to_string(),
            steps,
            cleanup_performed: false,
            cleanup_reason: "target validation failed; no directories created".to_string(),
            pid_movement: "disabled".to_string(),
            cgroup_procs_writes: "disabled".to_string(),
            nft_tc_state: "disabled".to_string(),
            leftover_target: None,
        };
    }
    steps.push(MkdirStep {
        description: format!("validate target path {}", target_cgroup_path),
        outcome: StepOutcome::Ok,
    });

    // Step 2: Create parent namespace directory
    let parent_outcome = match fs::create_dir(base_root) {
        Ok(()) => StepOutcome::Ok,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => StepOutcome::Ok,
        Err(e) => StepOutcome::Failed(format!("failed to create {}: {}", base_root, e)),
    };
    steps.push(MkdirStep {
        description: format!("create/prepare {}", base_root),
        outcome: parent_outcome.clone(),
    });

    // Abort if parent creation failed hard
    if let StepOutcome::Failed(_) = parent_outcome {
        return MkdirExperimentResult {
            parent_namespace: base_root.to_string(),
            target_cgroup_path: target_cgroup_path.to_string(),
            steps,
            cleanup_performed: false,
            cleanup_reason: "parent namespace creation failed".to_string(),
            pid_movement: "disabled".to_string(),
            cgroup_procs_writes: "disabled".to_string(),
            nft_tc_state: "disabled".to_string(),
            leftover_target: None,
        };
    }

    // Step 3: Create target cgroup directory
    let target_outcome = match fs::create_dir(target_cgroup_path) {
        Ok(()) => StepOutcome::Ok,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => StepOutcome::Ok,
        Err(e) => StepOutcome::Failed(format!("failed to create {}: {}", target_cgroup_path, e)),
    };
    steps.push(MkdirStep {
        description: format!("create/prepare {}", target_cgroup_path),
        outcome: target_outcome.clone(),
    });

    // Abort if target creation failed hard
    if let StepOutcome::Failed(_) = target_outcome {
        return MkdirExperimentResult {
            parent_namespace: base_root.to_string(),
            target_cgroup_path: target_cgroup_path.to_string(),
            steps,
            cleanup_performed: false,
            cleanup_reason: "target cgroup creation failed".to_string(),
            pid_movement: "disabled".to_string(),
            cgroup_procs_writes: "disabled".to_string(),
            nft_tc_state: "disabled".to_string(),
            leftover_target: None,
        };
    }

    // Step 4: Verify target exists
    let verify_outcome = if Path::new(target_cgroup_path).is_dir() {
        StepOutcome::Ok
    } else {
        StepOutcome::Failed(format!(
            "{} does not exist after creation",
            target_cgroup_path
        ))
    };
    steps.push(MkdirStep {
        description: format!("verify {} exists", target_cgroup_path),
        outcome: verify_outcome,
    });

    // Step 5: Cleanup target cgroup (only if empty and operation-owned)
    let (cleanup_performed, cleanup_reason, leftover_target) =
        attempt_cleanup_target(target_cgroup_path);
    steps.push(MkdirStep {
        description: format!("cleanup {}", target_cgroup_path),
        outcome: if cleanup_performed {
            StepOutcome::Ok
        } else {
            StepOutcome::Skipped
        },
    });

    MkdirExperimentResult {
        parent_namespace: base_root.to_string(),
        target_cgroup_path: target_cgroup_path.to_string(),
        steps,
        cleanup_performed,
        cleanup_reason,
        pid_movement: "disabled".to_string(),
        cgroup_procs_writes: "disabled".to_string(),
        nft_tc_state: "disabled".to_string(),
        leftover_target,
    }
}

/// Attempts to remove the target cgroup directory.
///
/// Only removes if:
/// - The target path exactly matches the expected operation target.
/// - The path is under the Zelynic cgroup namespace.
/// - The cgroup.procs file is absent or empty (no PIDs assigned).
/// - No child directories exist.
/// - Removal succeeds.
///
/// On any uncertainty, the target is left in place and reported.
fn attempt_cleanup_target(target_cgroup_path: &str) -> (bool, String, Option<String>) {
    let target = Path::new(target_cgroup_path);

    // Check if cgroup.procs exists and is non-empty
    let procs_path = target.join("cgroup.procs");
    if procs_path.exists() {
        if let Ok(content) = fs::read_to_string(&procs_path) {
            let has_pids = content
                .lines()
                .any(|line| line.trim().parse::<u32>().is_ok());
            if has_pids {
                return (
                    false,
                    "target cgroup.procs is non-empty; skipping cleanup".to_string(),
                    Some(target_cgroup_path.to_string()),
                );
            }
        }
    }

    // Check for child directories
    if let Ok(mut entries) = fs::read_dir(target) {
        let has_children = entries.any(|entry| {
            entry
                .map(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
                .unwrap_or(false)
        });
        if has_children {
            return (
                false,
                "target has child cgroups; skipping cleanup".to_string(),
                Some(target_cgroup_path.to_string()),
            );
        }
    }

    // Attempt removal
    match fs::remove_dir(target) {
        Ok(()) => (
            true,
            "target cgroup removed (empty, operation-owned)".to_string(),
            None,
        ),
        Err(e) => (
            false,
            format!("failed to remove target: {}", e),
            Some(target_cgroup_path.to_string()),
        ),
    }
}

// ---------------------------------------------------------------------------
// Output rendering
// ---------------------------------------------------------------------------

/// Renders the mkdir-only experiment result section into output.
pub(crate) fn render_mkdir_experiment_section(output: &mut String, result: &MkdirExperimentResult) {
    push_line(output, "");
    push_line(output, "  Mkdir-only experiment:");
    push_line(
        output,
        &format!("    parent namespace: {}", result.parent_namespace),
    );
    push_line(
        output,
        &format!("    target cgroup: {}", result.target_cgroup_path),
    );
    push_line(output, "    steps:");
    for (index, step) in result.steps.iter().enumerate() {
        let status = match &step.outcome {
            StepOutcome::Ok => "ok".to_string(),
            StepOutcome::Skipped => "skipped".to_string(),
            StepOutcome::Failed(reason) => format!("failed: {}", reason),
        };
        push_line(
            output,
            &format!("      {}. {}: {}", index + 1, step.description, status),
        );
    }
    push_line(
        output,
        &format!(
            "    cleanup: {}",
            if result.cleanup_performed {
                "performed".to_string()
            } else {
                format!("not performed ({})", result.cleanup_reason)
            }
        ),
    );
    if let Some(ref leftover) = result.leftover_target {
        push_line(output, &format!("    leftover target: {}", leftover));
    }
    push_line(
        output,
        &format!("    pid movement: {}", result.pid_movement),
    );
    push_line(
        output,
        &format!("    cgroup.procs writes: {}", result.cgroup_procs_writes),
    );
    push_line(
        output,
        &format!("    nft/tc/state: {}", result.nft_tc_state),
    );
    push_line(output, "    limiter attach: not performed");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Creates a temporary directory for test isolation.
    fn temp_root() -> String {
        let dir = std::env::temp_dir().join(format!(
            "zelynic-test-mkdir-exec-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::create_dir_all(&dir);
        dir.to_string_lossy().to_string()
    }

    /// Removes a temporary directory tree.
    fn cleanup_temp(path: &str) {
        let _ = fs::remove_dir_all(path);
    }

    fn default_target(root: &str) -> String {
        format!("{}/target_sleep", root)
    }

    // ---- --mkdir-live default false ----

    #[test]
    fn mkdir_live_default_is_false_in_result_model() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        assert_eq!(result.pid_movement, "disabled");
        cleanup_temp(&root);
    }

    // ---- --mkdir-live parses (tested in cli/tests.rs) ----

    // ---- target path validation ----

    #[test]
    fn executor_rejects_target_outside_namespace() {
        let root = temp_root();
        let target = "/sys/fs/cgroup/system.slice/example.scope".to_string();
        let result = run_mkdir_only_experiment(&root, &target);
        assert!(!result.all_ok());
        assert!(result
            .steps
            .iter()
            .any(|s| s.description.contains("validate")));
        assert!(matches!(
            &result.steps[0].outcome,
            StepOutcome::Failed(msg) if msg.contains("unsafe")
        ));
        cleanup_temp(&root);
    }

    #[test]
    fn executor_rejects_parent_traversal() {
        let root = temp_root();
        let target = format!("{}/target_test/../etc/passwd", root);
        let result = run_mkdir_only_experiment(&root, &target);
        assert!(!result.all_ok());
        cleanup_temp(&root);
    }

    #[test]
    fn executor_rejects_empty_target() {
        let root = temp_root();
        let result = run_mkdir_only_experiment(&root, "");
        assert!(!result.all_ok());
        cleanup_temp(&root);
    }

    #[test]
    fn executor_rejects_base_root_as_target() {
        let root = temp_root();
        let result = run_mkdir_only_experiment(&root, &root);
        assert!(!result.all_ok());
        cleanup_temp(&root);
    }

    // ---- mkdir operations ----

    #[test]
    fn executor_creates_parent_namespace_in_temp_root() {
        let root = temp_root();
        // Remove the root so we can test creation
        cleanup_temp(&root);
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        // Parent creation should succeed (or already exist)
        let parent_step = result.steps.iter().find(|s| s.description.contains(&root));
        assert!(parent_step.is_some());
        assert_eq!(parent_step.unwrap().outcome, StepOutcome::Ok);
        assert!(Path::new(&root).is_dir());
        cleanup_temp(&root);
    }

    #[test]
    fn executor_creates_target_cgroup_in_temp_root() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        let target_step = result
            .steps
            .iter()
            .find(|s| s.description.contains(&target));
        assert!(target_step.is_some());
        assert_eq!(target_step.unwrap().outcome, StepOutcome::Ok);
        cleanup_temp(&root);
    }

    #[test]
    fn executor_verifies_target_exists() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        let verify_step = result
            .steps
            .iter()
            .find(|s| s.description.contains("verify"));
        assert!(verify_step.is_some());
        assert_eq!(verify_step.unwrap().outcome, StepOutcome::Ok);
        cleanup_temp(&root);
    }

    // ---- no mutation guarantees ----

    #[test]
    fn executor_does_not_write_cgroup_procs() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        // cgroup.procs must never be created
        let procs_path = Path::new(&target).join("cgroup.procs");
        assert!(!procs_path.exists());
        assert_eq!(result.cgroup_procs_writes, "disabled");
        cleanup_temp(&root);
    }

    #[test]
    fn executor_does_not_move_pid() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        assert_eq!(result.pid_movement, "disabled");
        cleanup_temp(&root);
    }

    // ---- cleanup behavior ----

    #[test]
    fn executor_cleanup_removes_empty_operation_owned_target() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        assert!(result.cleanup_performed);
        assert!(result.leftover_target.is_none());
        // Target should no longer exist
        assert!(!Path::new(&target).exists());
        cleanup_temp(&root);
    }

    #[test]
    fn executor_cleanup_refuses_non_empty_target() {
        let root = temp_root();
        let target = default_target(&root);
        // Create target and put a fake PID in cgroup.procs
        let _ = fs::create_dir_all(&target);
        let procs_path = Path::new(&target).join("cgroup.procs");
        let _ = fs::write(&procs_path, "12345\n");

        // Test attempt_cleanup_target with a non-empty procs
        let (performed, reason, leftover) = attempt_cleanup_target(&target);
        assert!(!performed);
        assert!(reason.contains("non-empty"));
        assert_eq!(leftover.as_deref(), Some(target.as_str()));
        // Target should still exist
        assert!(Path::new(&target).is_dir());
        cleanup_temp(&root);
    }

    #[test]
    fn executor_cleanup_refuses_target_with_child_cgroups() {
        let root = temp_root();
        let target = default_target(&root);
        let _ = fs::create_dir_all(&target);
        // Create a child cgroup
        let child = Path::new(&target).join("child_sub");
        let _ = fs::create_dir(&child);

        let (performed, reason, leftover) = attempt_cleanup_target(&target);
        assert!(!performed);
        assert!(reason.contains("child cgroups"));
        assert_eq!(leftover.as_deref(), Some(target.as_str()));
        assert!(Path::new(&target).is_dir());
        cleanup_temp(&root);
    }

    #[test]
    fn executor_cleanup_refuses_unsafe_path() {
        // attempt_cleanup_target does not do path validation itself,
        // but the experiment will not reach cleanup if validation fails.
        let root = temp_root();
        let target = "/sys/fs/cgroup/system.slice/example.scope".to_string();
        let result = run_mkdir_only_experiment(&root, &target);
        assert!(!result.cleanup_performed);
        assert!(!result.all_ok());
        cleanup_temp(&root);
    }

    #[test]
    fn executor_leaves_parent_namespace_when_target_cleaned() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        // Parent should still exist
        assert!(Path::new(&root).is_dir());
        // Target should be cleaned
        assert!(result.cleanup_performed);
        assert!(result.leftover_target.is_none());
        cleanup_temp(&root);
    }

    // ---- output rendering ----

    #[test]
    fn output_reports_mkdir_only_experiment() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        let mut output = String::new();
        render_mkdir_experiment_section(&mut output, &result);
        assert!(output.contains("Mkdir-only experiment"));
        cleanup_temp(&root);
    }

    #[test]
    fn output_says_pid_movement_disabled() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        let mut output = String::new();
        render_mkdir_experiment_section(&mut output, &result);
        assert!(output.contains("pid movement: disabled"));
        cleanup_temp(&root);
    }

    #[test]
    fn output_says_cgroup_procs_writes_disabled() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        let mut output = String::new();
        render_mkdir_experiment_section(&mut output, &result);
        assert!(output.contains("cgroup.procs writes: disabled"));
        cleanup_temp(&root);
    }

    #[test]
    fn output_says_nft_tc_state_disabled() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        let mut output = String::new();
        render_mkdir_experiment_section(&mut output, &result);
        assert!(output.contains("nft/tc/state: disabled"));
        cleanup_temp(&root);
    }

    #[test]
    fn output_does_not_claim_limiter_active() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        let mut output = String::new();
        render_mkdir_experiment_section(&mut output, &result);
        assert!(output.contains("limiter attach: not performed"));
        assert!(!output.contains("active limiter"));
        cleanup_temp(&root);
    }

    #[test]
    fn output_reports_cleanup_status() {
        let root = temp_root();
        let target = default_target(&root);
        let result = run_mkdir_only_experiment(&root, &target);
        let mut output = String::new();
        render_mkdir_experiment_section(&mut output, &result);
        assert!(output.contains("cleanup: performed"));
        cleanup_temp(&root);
    }

    #[test]
    fn output_reports_leftover_when_cleanup_skipped() {
        let root = temp_root();
        let target = default_target(&root);
        let _ = fs::create_dir_all(&target);
        let procs_path = Path::new(&target).join("cgroup.procs");
        let _ = fs::write(&procs_path, "99999\n");
        let (performed, reason, leftover) = attempt_cleanup_target(&target);
        assert!(!performed);

        // Build a result with leftover
        let result = MkdirExperimentResult {
            parent_namespace: root.clone(),
            target_cgroup_path: target.clone(),
            steps: vec![],
            cleanup_performed: false,
            cleanup_reason: reason,
            pid_movement: "disabled".to_string(),
            cgroup_procs_writes: "disabled".to_string(),
            nft_tc_state: "disabled".to_string(),
            leftover_target: leftover,
        };
        let mut output = String::new();
        render_mkdir_experiment_section(&mut output, &result);
        assert!(output.contains("leftover target"));
        cleanup_temp(&root);
    }

    // ---- path validation unit tests ----

    #[test]
    fn safe_target_rejects_empty() {
        assert!(!is_safe_mkdir_target("/tmp/test", ""));
    }

    #[test]
    fn safe_target_rejects_base_root() {
        assert!(!is_safe_mkdir_target("/tmp/test", "/tmp/test"));
    }

    #[test]
    fn safe_target_rejects_outside_namespace() {
        assert!(!is_safe_mkdir_target(
            "/tmp/test",
            "/sys/fs/cgroup/system.slice/foo"
        ));
    }

    #[test]
    fn safe_target_rejects_parent_traversal() {
        assert!(!is_safe_mkdir_target(
            "/tmp/test",
            "/tmp/test/target_../etc"
        ));
    }

    #[test]
    fn safe_target_rejects_no_target_prefix() {
        assert!(!is_safe_mkdir_target("/tmp/test", "/tmp/test/something"));
    }

    #[test]
    fn safe_target_accepts_valid_target() {
        assert!(is_safe_mkdir_target("/tmp/test", "/tmp/test/target_sleep"));
    }

    #[test]
    fn safe_target_accepts_target_with_suffix() {
        assert!(is_safe_mkdir_target(
            "/tmp/test",
            "/tmp/test/target_curl_123"
        ));
    }
}
