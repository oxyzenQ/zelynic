// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! PID Safety model for Zelynic Attach Preflight.
//!
//! Evaluates read-only liveness and self-protection rules.

use crate::systemd_wrapper::original_cgroup_preview::{
    OriginalCgroupCapturePreview, OriginalCgroupCaptureStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LivenessStatus {
    Alive,
    Missing,
    Unknown,
}

impl LivenessStatus {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Alive => "alive",
            Self::Missing => "missing/stale",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelfProtectionStatus {
    Allowed,
    RejectZelynicSelf,
    RejectZelynicManaged,
    Unknown,
}

impl SelfProtectionStatus {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::RejectZelynicSelf => "reject (zelynic self)",
            Self::RejectZelynicManaged => "reject (zelynic managed cgroup)",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AttachEligibility {
    PreflightOk,
    Blocked,
    Pending,
}

impl AttachEligibility {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::PreflightOk => "preflight ok; attach still blocked",
            Self::Blocked => "blocked",
            Self::Pending => "pending",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PidSafetyCheck {
    pub pid: u32,
    pub liveness: LivenessStatus,
    pub self_protection: SelfProtectionStatus,
    pub eligibility: AttachEligibility,
    pub reason: String,
}

pub(crate) fn evaluate_pid_safety_live(
    original_cgroup: &OriginalCgroupCapturePreview,
) -> PidSafetyCheck {
    let zelynic_pid = std::process::id();
    // To check if a process is alive without sending a signal,
    // we can check if /proc/<pid> exists. This is a lightweight read-only check.
    let is_alive = std::path::Path::new(&format!("/proc/{}", original_cgroup.pid)).exists();
    evaluate_pid_safety(original_cgroup, zelynic_pid, is_alive)
}

pub(crate) fn evaluate_pid_safety(
    original_cgroup: &OriginalCgroupCapturePreview,
    zelynic_pid: u32,
    is_alive: bool,
) -> PidSafetyCheck {
    let pid = original_cgroup.pid;

    // 1. Check Liveness
    let liveness = if original_cgroup.status == OriginalCgroupCaptureStatus::Missing || !is_alive {
        LivenessStatus::Missing
    } else if original_cgroup.status == OriginalCgroupCaptureStatus::Required {
        LivenessStatus::Unknown
    } else {
        LivenessStatus::Alive
    };

    // 2. Check Self-Protection
    let self_protection = if pid == zelynic_pid {
        SelfProtectionStatus::RejectZelynicSelf
    } else if original_cgroup.status == OriginalCgroupCaptureStatus::ZelynicManaged {
        SelfProtectionStatus::RejectZelynicManaged
    } else if original_cgroup.status == OriginalCgroupCaptureStatus::Required {
        SelfProtectionStatus::Unknown
    } else {
        SelfProtectionStatus::Allowed
    };

    // 3. Determine Final Eligibility
    if liveness == LivenessStatus::Missing {
        PidSafetyCheck {
            pid,
            liveness,
            self_protection,
            eligibility: AttachEligibility::Blocked,
            reason: "PID is missing or stale".to_string(),
        }
    } else if self_protection == SelfProtectionStatus::RejectZelynicSelf {
        PidSafetyCheck {
            pid,
            liveness,
            self_protection,
            eligibility: AttachEligibility::Blocked,
            reason: "cannot attach Zelynic to itself".to_string(),
        }
    } else if self_protection == SelfProtectionStatus::RejectZelynicManaged {
        PidSafetyCheck {
            pid,
            liveness,
            self_protection,
            eligibility: AttachEligibility::Blocked,
            reason: "PID is already in a Zelynic-managed cgroup".to_string(),
        }
    } else if original_cgroup.status == OriginalCgroupCaptureStatus::Unsafe {
        PidSafetyCheck {
            pid,
            liveness,
            self_protection,
            eligibility: AttachEligibility::Blocked,
            reason: "original cgroup path is unsafe".to_string(),
        }
    } else if original_cgroup.status == OriginalCgroupCaptureStatus::Required {
        PidSafetyCheck {
            pid,
            liveness,
            self_protection,
            eligibility: AttachEligibility::Pending,
            reason: "safety checks pending live evaluation".to_string(),
        }
    } else {
        PidSafetyCheck {
            pid,
            liveness,
            self_protection,
            eligibility: AttachEligibility::PreflightOk,
            reason: "passed all preflight safety checks".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_cgroup(status: OriginalCgroupCaptureStatus) -> OriginalCgroupCapturePreview {
        OriginalCgroupCapturePreview {
            pid: 12345,
            status,
            original_cgroup_path: None,
            rollback_target_path: None,
            reason: "dummy".to_string(),
        }
    }

    #[test]
    fn test_normal_pid_is_preflight_ok() {
        let cg = dummy_cgroup(OriginalCgroupCaptureStatus::CapturedLive);
        let check = evaluate_pid_safety(&cg, 9999, true);

        assert_eq!(check.liveness, LivenessStatus::Alive);
        assert_eq!(check.self_protection, SelfProtectionStatus::Allowed);
        assert_eq!(check.eligibility, AttachEligibility::PreflightOk);
    }

    #[test]
    fn test_missing_pid_is_blocked() {
        let cg = dummy_cgroup(OriginalCgroupCaptureStatus::CapturedLive);
        let check = evaluate_pid_safety(&cg, 9999, false);

        assert_eq!(check.liveness, LivenessStatus::Missing);
        assert_eq!(check.eligibility, AttachEligibility::Blocked);
    }

    #[test]
    fn test_missing_cgroup_implies_missing_liveness() {
        let cg = dummy_cgroup(OriginalCgroupCaptureStatus::Missing);
        let check = evaluate_pid_safety(&cg, 9999, true); // Even if true, Missing status wins

        assert_eq!(check.liveness, LivenessStatus::Missing);
        assert_eq!(check.eligibility, AttachEligibility::Blocked);
    }

    #[test]
    fn test_zelynic_pid_is_blocked() {
        let cg = dummy_cgroup(OriginalCgroupCaptureStatus::CapturedLive);
        let check = evaluate_pid_safety(&cg, 12345, true);

        assert_eq!(check.liveness, LivenessStatus::Alive);
        assert_eq!(
            check.self_protection,
            SelfProtectionStatus::RejectZelynicSelf
        );
        assert_eq!(check.eligibility, AttachEligibility::Blocked);
    }

    #[test]
    fn test_zelynic_managed_cgroup_is_blocked() {
        let cg = dummy_cgroup(OriginalCgroupCaptureStatus::ZelynicManaged);
        let check = evaluate_pid_safety(&cg, 9999, true);

        assert_eq!(check.liveness, LivenessStatus::Alive);
        assert_eq!(
            check.self_protection,
            SelfProtectionStatus::RejectZelynicManaged
        );
        assert_eq!(check.eligibility, AttachEligibility::Blocked);
    }

    #[test]
    fn test_unsafe_cgroup_is_blocked() {
        let cg = dummy_cgroup(OriginalCgroupCaptureStatus::Unsafe);
        let check = evaluate_pid_safety(&cg, 9999, true);

        assert_eq!(check.liveness, LivenessStatus::Alive);
        assert_eq!(check.self_protection, SelfProtectionStatus::Allowed);
        assert_eq!(check.eligibility, AttachEligibility::Blocked);
    }

    #[test]
    fn test_required_cgroup_is_pending() {
        let cg = dummy_cgroup(OriginalCgroupCaptureStatus::Required);
        let check = evaluate_pid_safety(&cg, 9999, true);

        assert_eq!(check.liveness, LivenessStatus::Unknown);
        assert_eq!(check.self_protection, SelfProtectionStatus::Unknown);
        assert_eq!(check.eligibility, AttachEligibility::Pending);
    }
}
