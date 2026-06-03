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
    pub pid_safety_checks: Vec<crate::systemd_wrapper::pid_safety::PidSafetyCheck>,
    pub pid_liveness_check: String,
    pub self_protection_check: String,
    pub attach_transaction_plan: crate::systemd_wrapper::attach_transaction::AttachTransactionPlan,
    pub live_attach_status: String,
    pub readiness: String,
}

pub(crate) fn build_attach_safety_preflight(
    discovered_pids: &[u32],
    future_target_cgroup: &str,
    live_cgroup_previews: Option<Vec<OriginalCgroupCapturePreview>>,
) -> AttachSafetyPreflight {
    let (original_cgroup_capture, original_cgroup_previews, pid_safety_checks) =
        match live_cgroup_previews {
            Some(previews) => {
                let checks = previews
                    .iter()
                    .map(crate::systemd_wrapper::pid_safety::evaluate_pid_safety_live)
                    .collect();
                ("read-only capture completed".to_string(), previews, checks)
            }
            None => {
                let previews = build_pending_original_cgroup_previews(discovered_pids);
                let checks = previews
                    .iter()
                    .map(|p| crate::systemd_wrapper::pid_safety::evaluate_pid_safety(p, 0, false))
                    .collect();
                (
                    "required before attach; not read in this probe".to_string(),
                    previews,
                    checks,
                )
            }
        };

    AttachSafetyPreflight {
        discovered_pids: discovered_pids.to_vec(),
        future_target_cgroup: future_target_cgroup.to_string(),
        original_cgroup_capture,
        original_cgroup_previews,
        pid_safety_checks,
        pid_liveness_check: "required before attach; reject dead PIDs".to_string(),
        self_protection_check:
            "required before attach; reject Zelynic itself, dead PIDs, and already managed Zelynic cgroups until explicitly supported".to_string(),
        attach_transaction_plan: crate::systemd_wrapper::attach_transaction::build_attach_transaction_plan(),
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
    render_pid_safety_checks(output, &preflight.pid_safety_checks);
    render_attach_transaction_plan(output, &preflight.attach_transaction_plan);
    push_line(
        output,
        &format!("    live attach: {}", preflight.live_attach_status),
    );
}

fn render_attach_transaction_plan(
    output: &mut String,
    plan: &crate::systemd_wrapper::attach_transaction::AttachTransactionPlan,
) {
    push_line(output, "    Future attach transaction plan:");
    push_line(output, &format!("      status: {}", plan.status));
    push_line(output, "      steps:");
    for step in &plan.steps {
        push_line(output, &format!("        {}", step));
    }
    push_line(output, "      rollback:");
    for step in &plan.rollback {
        push_line(output, &format!("        {}", step));
    }
    push_line(output, &format!("      execution: {}", plan.execution));
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
            Some(rollback_target) => {
                if preview.status == OriginalCgroupCaptureStatus::CapturedLive {
                    push_line(
                        output,
                        &format!(
                            "      PID {}: captured original cgroup: {}",
                            preview.pid,
                            preview.original_cgroup_path.as_deref().unwrap_or("")
                        ),
                    );
                    push_line(
                        output,
                        &format!("      rollback target: {}", rollback_target),
                    );
                } else {
                    push_line(
                        output,
                        &format!(
                            "      PID {}: {}; rollback target: {}",
                            preview.pid,
                            preview.status.label(),
                            rollback_target
                        ),
                    );
                }
            }
            None => {
                if preview.reason == "original cgroup capture unavailable/stale" {
                    push_line(
                        output,
                        &format!(
                            "      PID {}: original cgroup capture unavailable/stale",
                            preview.pid
                        ),
                    );
                    push_line(
                        output,
                        "      rollback target: pending original cgroup capture",
                    );
                } else {
                    push_line(
                        output,
                        &format!(
                            "      PID {}: {}; rollback target: pending original cgroup capture ({})",
                            preview.pid,
                            preview.status.label(),
                            preview.reason
                        ),
                    );
                }
            }
        }
    }
}

fn render_pid_safety_checks(
    output: &mut String,
    checks: &[crate::systemd_wrapper::pid_safety::PidSafetyCheck],
) {
    push_line(output, "    PID safety checks:");
    if checks.is_empty() {
        push_line(output, "      (none)");
        return;
    }
    for check in checks {
        use crate::systemd_wrapper::pid_safety::{AttachEligibility, LivenessStatus};
        if check.eligibility == AttachEligibility::Pending {
            push_line(
                output,
                &format!("      PID {}: pending live evaluation", check.pid),
            );
            continue;
        }

        push_line(
            output,
            &format!(
                "      PID {}: liveness: {}",
                check.pid,
                check.liveness.label()
            ),
        );

        if check.liveness != LivenessStatus::Missing {
            push_line(
                output,
                &format!(
                    "      PID {}: self-protection: {}",
                    check.pid,
                    check.self_protection.label()
                ),
            );
        }
        push_line(
            output,
            &format!(
                "      PID {}: future attach eligibility: {}",
                check.pid,
                check.eligibility.label()
            ),
        );
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
        build_attach_safety_preflight(&[12345, 12346], "/sys/fs/cgroup/zelynic/target_sleep", None)
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
    fn safety_model_includes_attach_transaction_plan() {
        let preflight = sample_preflight();
        assert_eq!(
            preflight.attach_transaction_plan.status,
            "model only; not executed"
        );
        assert_eq!(preflight.attach_transaction_plan.execution, "blocked");
        assert!(!preflight.attach_transaction_plan.steps.is_empty());
        assert!(!preflight.attach_transaction_plan.rollback.is_empty());
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
        assert!(output.contains("Future attach transaction plan:"));
        assert!(output.contains("status: model only; not executed"));
        assert!(output.contains("execution: blocked"));
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
        assert!(output.contains("execution: blocked"));
        assert!(output.contains("live attach: not implemented"));
    }

    #[test]
    fn rendered_safety_output_can_show_live_safety_checks() {
        use crate::systemd_wrapper::pid_safety::{
            AttachEligibility, LivenessStatus, PidSafetyCheck, SelfProtectionStatus,
        };

        let mut preflight = sample_preflight();
        preflight.pid_safety_checks = vec![PidSafetyCheck {
            pid: 12345,
            liveness: LivenessStatus::Alive,
            self_protection: SelfProtectionStatus::Allowed,
            eligibility: AttachEligibility::PreflightOk,
            reason: "test".to_string(),
        }];
        let mut output = String::new();

        render_attach_safety_preflight_section(&mut output, &preflight);

        assert!(output.contains("PID safety checks:"));
        assert!(output.contains("PID 12345: liveness: alive"));
        assert!(output.contains("PID 12345: self-protection: allowed"));
        assert!(output
            .contains("PID 12345: future attach eligibility: preflight ok; attach still blocked"));
    }

    #[test]
    fn rendered_safety_output_can_show_missing_pid_blocked() {
        use crate::systemd_wrapper::pid_safety::{
            AttachEligibility, LivenessStatus, PidSafetyCheck, SelfProtectionStatus,
        };

        let mut preflight = sample_preflight();
        preflight.pid_safety_checks = vec![PidSafetyCheck {
            pid: 12345,
            liveness: LivenessStatus::Missing,
            self_protection: SelfProtectionStatus::Unknown,
            eligibility: AttachEligibility::Blocked,
            reason: "test".to_string(),
        }];
        let mut output = String::new();

        render_attach_safety_preflight_section(&mut output, &preflight);

        assert!(output.contains("PID safety checks:"));
        assert!(output.contains("PID 12345: liveness: missing/stale"));
        // missing should not print self-protection
        assert!(!output.contains("PID 12345: self-protection"));
        assert!(output.contains("PID 12345: future attach eligibility: blocked"));
    }
}
