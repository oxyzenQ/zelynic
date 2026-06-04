// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Target Cgroup Preflight: pure model for future target cgroup environment
//! checks before any single-PID move-only experiment.
//!
//! This module only validates and renders paths. It does not read live cgroup
//! metadata, create directories, write cgroup.procs, move PIDs, call nftables
//! or tc, write Zelynic state, or execute commands.

use super::cgroup_environment::{
    build_cgroup_environment_diagnostics, render_cgroup_environment_diagnostics_section,
    CgroupEnvironmentDiagnostics,
};
use super::render::push_line;

pub(crate) const ZELYNIC_CGROUP_ROOT: &str = "/sys/fs/cgroup/zelynic";
const CGROUP_FS_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TargetCgroupPreflight {
    pub status: String,
    pub target_namespace: String,
    pub target_cgroup: String,
    pub target_cgroup_procs: Option<String>,
    pub rollback_cgroup_procs: Option<String>,
    pub parent_status: CgroupPathStatus,
    pub target_status: CgroupPathStatus,
    pub cgroup_environment: CgroupEnvironmentDiagnostics,
    pub execution: String,
    pub blocked_reasons: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CgroupPathStatus {
    MissingFutureCreationNeeded,
    Unsafe,
}

impl CgroupPathStatus {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::MissingFutureCreationNeeded => {
                "not created by this probe; future creation needed"
            }
            Self::Unsafe => "unsafe",
        }
    }
}

pub(crate) fn build_target_cgroup_preflight(
    target_cgroup: &str,
    rollback_cgroup: Option<&str>,
) -> TargetCgroupPreflight {
    let mut blocked_reasons = Vec::new();
    let target_safe = validate_target_cgroup_path(target_cgroup);
    if let Err(reason) = target_safe {
        blocked_reasons.push(reason.to_string());
    }

    let rollback_cgroup_procs = rollback_cgroup.map(append_cgroup_procs);

    TargetCgroupPreflight {
        status: "model only; not executed".to_string(),
        target_namespace: ZELYNIC_CGROUP_ROOT.to_string(),
        target_cgroup: target_cgroup.to_string(),
        target_cgroup_procs: if blocked_reasons.is_empty() {
            Some(append_cgroup_procs(target_cgroup))
        } else {
            None
        },
        rollback_cgroup_procs,
        parent_status: if blocked_reasons.is_empty() {
            CgroupPathStatus::MissingFutureCreationNeeded
        } else {
            CgroupPathStatus::Unsafe
        },
        target_status: if blocked_reasons.is_empty() {
            CgroupPathStatus::MissingFutureCreationNeeded
        } else {
            CgroupPathStatus::Unsafe
        },
        cgroup_environment: build_cgroup_environment_diagnostics(None),
        execution: "blocked".to_string(),
        blocked_reasons,
    }
}

pub(crate) fn render_target_cgroup_preflight_section(
    output: &mut String,
    preflight: &TargetCgroupPreflight,
) {
    push_line(output, "");
    push_line(output, "      Target cgroup preflight:");
    push_line(output, &format!("        status: {}", preflight.status));
    push_line(
        output,
        &format!("        target namespace: {}", preflight.target_namespace),
    );
    push_line(
        output,
        &format!("        target cgroup: {}", preflight.target_cgroup),
    );
    push_line(
        output,
        &format!(
            "        target cgroup.procs: {}",
            preflight
                .target_cgroup_procs
                .as_deref()
                .unwrap_or("blocked")
        ),
    );
    push_line(
        output,
        &format!(
            "        rollback cgroup.procs: {}",
            preflight
                .rollback_cgroup_procs
                .as_deref()
                .unwrap_or("pending original cgroup capture")
        ),
    );
    push_line(
        output,
        &format!("        parent status: {}", preflight.parent_status.label()),
    );
    push_line(
        output,
        &format!("        target status: {}", preflight.target_status.label()),
    );
    if !preflight.blocked_reasons.is_empty() {
        push_line(
            output,
            &format!(
                "        blocked reason: {}",
                preflight.blocked_reasons.join("; ")
            ),
        );
    }
    render_cgroup_environment_diagnostics_section(output, &preflight.cgroup_environment);
    push_line(
        output,
        &format!("        execution: {}", preflight.execution),
    );
}

fn validate_target_cgroup_path(path: &str) -> Result<(), &'static str> {
    if path == CGROUP_FS_ROOT || path == "/" {
        return Err("target cgroup must not be the cgroup filesystem root");
    }

    if path.contains("..") {
        return Err("target cgroup must not contain parent traversal");
    }

    let Some(remainder) = path.strip_prefix(&format!("{ZELYNIC_CGROUP_ROOT}/")) else {
        return Err("target cgroup must be under /sys/fs/cgroup/zelynic/");
    };

    if remainder.is_empty() {
        return Err("target cgroup must not be the Zelynic namespace root");
    }

    Ok(())
}

fn append_cgroup_procs(path: &str) -> String {
    format!("{}/cgroup.procs", path.trim_end_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_preflight() -> TargetCgroupPreflight {
        build_target_cgroup_preflight(
            "/sys/fs/cgroup/zelynic/target_sleep",
            Some("/sys/fs/cgroup/user.slice/session-2.scope"),
        )
    }

    #[test]
    fn valid_zelynic_target_path_is_modelled() {
        let preflight = valid_preflight();
        assert!(preflight.blocked_reasons.is_empty());
        assert_eq!(
            preflight.target_cgroup,
            "/sys/fs/cgroup/zelynic/target_sleep"
        );
    }

    #[test]
    fn path_outside_zelynic_namespace_is_blocked() {
        let preflight =
            build_target_cgroup_preflight("/sys/fs/cgroup/system.slice/foo.scope", None);

        assert!(preflight
            .blocked_reasons
            .contains(&"target cgroup must be under /sys/fs/cgroup/zelynic/".to_string()));
        assert_eq!(preflight.target_status, CgroupPathStatus::Unsafe);
    }

    #[test]
    fn path_with_parent_traversal_is_blocked() {
        let preflight =
            build_target_cgroup_preflight("/sys/fs/cgroup/zelynic/../target_sleep", None);

        assert!(preflight
            .blocked_reasons
            .contains(&"target cgroup must not contain parent traversal".to_string()));
    }

    #[test]
    fn cgroup_filesystem_root_is_blocked() {
        let preflight = build_target_cgroup_preflight("/sys/fs/cgroup", None);

        assert!(preflight
            .blocked_reasons
            .contains(&"target cgroup must not be the cgroup filesystem root".to_string()));
    }

    #[test]
    fn target_cgroup_procs_path_is_modelled_correctly() {
        let preflight = valid_preflight();
        assert_eq!(
            preflight.target_cgroup_procs.as_deref(),
            Some("/sys/fs/cgroup/zelynic/target_sleep/cgroup.procs")
        );
    }

    #[test]
    fn rollback_cgroup_procs_path_is_modelled_correctly() {
        let preflight = valid_preflight();
        assert_eq!(
            preflight.rollback_cgroup_procs.as_deref(),
            Some("/sys/fs/cgroup/user.slice/session-2.scope/cgroup.procs")
        );
    }

    #[test]
    fn missing_parent_status_is_future_creation_needed_not_created_now() {
        let preflight = valid_preflight();
        assert_eq!(
            preflight.parent_status,
            CgroupPathStatus::MissingFutureCreationNeeded
        );
        assert_eq!(
            preflight.parent_status.label(),
            "not created by this probe; future creation needed"
        );
    }

    #[test]
    fn output_says_model_only_not_executed() {
        let mut output = String::new();
        render_target_cgroup_preflight_section(&mut output, &valid_preflight());

        assert!(output.contains("status: model only; not executed"));
    }

    #[test]
    fn output_says_execution_blocked() {
        let mut output = String::new();
        render_target_cgroup_preflight_section(&mut output, &valid_preflight());

        assert!(output.contains("execution: blocked"));
    }

    #[test]
    fn output_includes_cgroup_environment_diagnostics() {
        let mut output = String::new();
        render_target_cgroup_preflight_section(&mut output, &valid_preflight());

        assert!(output.contains("Cgroup environment diagnostics:"));
        assert!(output.contains("cgroup v2 mount: not checked"));
        assert!(output.contains("cgroup.procs writes: blocked"));
    }

    #[test]
    fn output_does_not_claim_created_moved_attached_limited_or_enforced() {
        let mut output = String::new();
        render_target_cgroup_preflight_section(&mut output, &valid_preflight());

        assert!(!output.contains("created target"));
        assert!(!output.contains("created cgroup"));
        assert!(!output.contains("moved"));
        assert!(!output.contains("attached"));
        assert!(!output.contains("limited"));
        assert!(!output.contains("enforced"));
    }
}
