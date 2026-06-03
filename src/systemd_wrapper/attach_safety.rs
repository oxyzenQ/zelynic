// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Attach Safety: pure, non-mutating preflight model for future live attach.
//!
//! This module does not read `/proc`, write cgroups, call nftables/tc, write
//! Zelynic state, or call the limiter attach execution path.

use super::original_cgroup_preview::{
    build_pending_original_cgroup_previews, OriginalCgroupCapturePreview,
    OriginalCgroupCaptureStatus,
};
use super::render::push_line;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachSafetyPreflight {
    pub discovered_pids: Vec<u32>,
    pub future_target_cgroup: String,
    pub original_cgroup_capture: String,
    pub original_cgroup_previews: Vec<OriginalCgroupCapturePreview>,
    pub pid_liveness_check: String,
    pub self_protection_check: String,
    pub rollback_plan: Vec<String>,
    pub mutation_checklist: Vec<String>,
    pub mutation_status: String,
    pub live_attach_status: String,
    pub readiness: String,
}

pub(crate) fn build_attach_safety_preflight(
    discovered_pids: &[u32],
    future_target_cgroup: &str,
) -> AttachSafetyPreflight {
    AttachSafetyPreflight {
        discovered_pids: discovered_pids.to_vec(),
        future_target_cgroup: future_target_cgroup.to_string(),
        original_cgroup_capture:
            "required before attach; not read in this probe".to_string(),
        original_cgroup_previews: build_pending_original_cgroup_previews(discovered_pids),
        pid_liveness_check: "required before attach; reject dead PIDs".to_string(),
        self_protection_check:
            "required before attach; reject Zelynic itself, dead PIDs, and already managed Zelynic cgroups until explicitly supported".to_string(),
        rollback_plan: vec![
            "restore PID(s) to captured original cgroup path".to_string(),
            "cleanup Zelynic target cgroup only if safe and empty".to_string(),
            "remove nftables/tc state only if created by this future attach operation".to_string(),
        ],
        mutation_checklist: vec![
            "future: create/prepare Zelynic target cgroup".to_string(),
            "future: move validated PID(s) after original cgroup capture".to_string(),
            "future: install nftables/tc state owned by this attach operation".to_string(),
            "today: all mutations are blocked".to_string(),
        ],
        mutation_status: "blocked".to_string(),
        live_attach_status: "not implemented".to_string(),
        readiness: "preview only; not evaluated live".to_string(),
    }
}

pub(crate) fn render_attach_safety_preflight_section(
    output: &mut String,
    preflight: &AttachSafetyPreflight,
) {
    push_line(output, "");
    push_line(output, "  Attach safety preflight:");
    push_line(output, &format!("    status: {}", preflight.readiness));
    if preflight.discovered_pids.is_empty() {
        push_line(output, "    discovered PID(s): (none)");
    } else {
        push_line(
            output,
            &format!(
                "    discovered PID(s): {}",
                format_pid_list(&preflight.discovered_pids)
            ),
        );
    }
    push_line(
        output,
        &format!(
            "    future target cgroup: {}",
            preflight.future_target_cgroup
        ),
    );
    push_line(
        output,
        &format!("    PID liveness: {}", preflight.pid_liveness_check),
    );
    push_line(
        output,
        &format!(
            "    original cgroup capture: {}",
            preflight.original_cgroup_capture
        ),
    );
    render_original_cgroup_capture_preview(output, &preflight.original_cgroup_previews);
    push_line(
        output,
        &format!("    self-protection: {}", preflight.self_protection_check),
    );
    push_line(output, "    rollback plan: required before attach");
    for item in &preflight.rollback_plan {
        push_line(output, &format!("      - {}", item));
    }
    push_line(output, "    mutation checklist:");
    for item in &preflight.mutation_checklist {
        push_line(output, &format!("      - {}", item));
    }
    push_line(
        output,
        &format!("    mutation status: {}", preflight.mutation_status),
    );
    push_line(
        output,
        &format!("    live attach: {}", preflight.live_attach_status),
    );
}

fn render_original_cgroup_capture_preview(
    output: &mut String,
    previews: &[OriginalCgroupCapturePreview],
) {
    push_line(output, "    original cgroup capture preview:");
    if previews.is_empty() {
        push_line(
            output,
            "      status: required before attach; not read in this probe",
        );
        push_line(
            output,
            "      rollback target: pending original cgroup capture",
        );
        return;
    }

    if previews
        .iter()
        .all(|preview| preview.status == OriginalCgroupCaptureStatus::Required)
    {
        push_line(
            output,
            "      status: required before attach; not read in this probe",
        );
        push_line(
            output,
            "      rollback target: pending original cgroup capture",
        );
        let pending_pids = previews
            .iter()
            .map(|preview| preview.pid)
            .collect::<Vec<_>>();
        push_line(
            output,
            &format!(
                "      PID capture: pending for {}",
                format_pid_list(&pending_pids)
            ),
        );
        return;
    }

    for preview in previews {
        match preview.rollback_target_path.as_deref() {
            Some(rollback_target) => push_line(
                output,
                &format!(
                    "      PID {}: {}; rollback target: {}",
                    preview.pid,
                    preview.status.label(),
                    rollback_target
                ),
            ),
            None => push_line(
                output,
                &format!(
                    "      PID {}: {}; rollback target: pending original cgroup capture ({})",
                    preview.pid,
                    preview.status.label(),
                    preview.reason
                ),
            ),
        }
    }
}

fn format_pid_list(pids: &[u32]) -> String {
    pids.iter()
        .map(|pid| pid.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd_wrapper::original_cgroup_preview::build_original_cgroup_preview_from_sample;

    fn sample_preflight() -> AttachSafetyPreflight {
        build_attach_safety_preflight(&[12345, 12346], "/sys/fs/cgroup/zelynic/target_sleep")
    }

    #[test]
    fn safety_model_includes_discovered_pids() {
        let preflight = sample_preflight();
        assert_eq!(preflight.discovered_pids, vec![12345, 12346]);
    }

    #[test]
    fn safety_model_includes_original_cgroup_capture_requirement() {
        let preflight = sample_preflight();
        assert!(preflight
            .original_cgroup_capture
            .contains("required before attach"));
        assert!(preflight
            .original_cgroup_capture
            .contains("not read in this probe"));
        assert!(preflight.original_cgroup_previews.iter().all(|preview| {
            preview.status == OriginalCgroupCaptureStatus::Required
                && preview.rollback_target_path.is_none()
        }));
    }

    #[test]
    fn safety_model_includes_pid_liveness_requirement() {
        let preflight = sample_preflight();
        assert!(preflight
            .pid_liveness_check
            .contains("required before attach"));
        assert!(preflight.pid_liveness_check.contains("dead PIDs"));
    }

    #[test]
    fn safety_model_includes_self_protection_requirement() {
        let preflight = sample_preflight();
        assert!(preflight.self_protection_check.contains("Zelynic itself"));
        assert!(preflight
            .self_protection_check
            .contains("already managed Zelynic cgroups"));
    }

    #[test]
    fn safety_model_includes_rollback_plan_requirement() {
        let preflight = sample_preflight();
        assert!(preflight
            .rollback_plan
            .iter()
            .any(|item| item.contains("restore PID(s)")));
        assert!(preflight
            .rollback_plan
            .iter()
            .any(|item| item.contains("safe and empty")));
        assert!(preflight
            .rollback_plan
            .iter()
            .any(|item| item.contains("nftables/tc state")));
    }

    #[test]
    fn safety_model_says_mutation_is_blocked() {
        let preflight = sample_preflight();
        assert_eq!(preflight.mutation_status, "blocked");
        assert!(preflight
            .mutation_checklist
            .iter()
            .any(|item| item.contains("today: all mutations are blocked")));
    }

    #[test]
    fn safety_model_says_live_attach_is_not_implemented() {
        let preflight = sample_preflight();
        assert_eq!(preflight.live_attach_status, "not implemented");
        assert_eq!(preflight.readiness, "preview only; not evaluated live");
    }

    #[test]
    fn rendered_safety_output_is_preview_only_and_non_mutating() {
        let preflight = sample_preflight();
        let mut output = String::new();

        render_attach_safety_preflight_section(&mut output, &preflight);

        assert!(output.contains("Attach safety preflight"));
        assert!(output.contains("status: preview only; not evaluated live"));
        assert!(output.contains("PID liveness: required before attach"));
        assert!(output
            .contains("original cgroup capture: required before attach; not read in this probe"));
        assert!(output.contains("original cgroup capture preview"));
        assert!(output.contains("rollback target: pending original cgroup capture"));
        assert!(output.contains("self-protection: required before attach"));
        assert!(output.contains("rollback plan: required before attach"));
        assert!(output.contains("mutation status: blocked"));
        assert!(output.contains("live attach: not implemented"));
    }

    #[test]
    fn rendered_safety_output_does_not_claim_rollback_ready_without_sample_capture() {
        let preflight = sample_preflight();
        let mut output = String::new();

        render_attach_safety_preflight_section(&mut output, &preflight);

        assert!(!output.contains("captured from sample"));
        assert!(!output.contains("/sys/fs/cgroup/system.slice/example.scope"));
        assert!(output.contains("rollback target: pending original cgroup capture"));
    }

    #[test]
    fn rendered_safety_output_can_show_sample_rollback_ready_state() {
        let mut preflight = sample_preflight();
        preflight.original_cgroup_previews = vec![build_original_cgroup_preview_from_sample(
            12345,
            "0::/system.slice/example.scope\n",
        )];
        let mut output = String::new();

        render_attach_safety_preflight_section(&mut output, &preflight);

        assert!(output.contains("PID 12345: captured from sample"));
        assert!(output.contains("rollback target: /sys/fs/cgroup/system.slice/example.scope"));
        assert!(output.contains("mutation status: blocked"));
        assert!(output.contains("live attach: not implemented"));
    }
}
