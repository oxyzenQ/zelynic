// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};
use std::collections::HashSet;

use super::process::{ProcessMatchReason, ResolvedPid};
use super::state::LimitRecord;

/// Source metadata for a PID that has already been resolved for strict attach.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResolvedTargetPidSource {
    ProcessResolver {
        reason: ProcessMatchReason,
        matched: String,
    },
    SystemdScope {
        detail: String,
    },
}

/// PID plus enough source metadata for diagnostics and future launch handoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedTargetPid {
    pub pid: u32,
    pub source: ResolvedTargetPidSource,
    pub original_cgroup_path: Option<String>,
}

impl ResolvedTargetPid {
    #[allow(dead_code)]
    pub(crate) fn systemd_scope(pid: u32, detail: impl Into<String>) -> Self {
        Self {
            pid,
            source: ResolvedTargetPidSource::SystemdScope {
                detail: detail.into(),
            },
            original_cgroup_path: None,
        }
    }

    pub(crate) fn diagnostic_label(&self) -> String {
        match &self.source {
            ResolvedTargetPidSource::ProcessResolver { reason, matched } => {
                format!("reason={} {}", reason, matched)
            }
            ResolvedTargetPidSource::SystemdScope { detail } => {
                format!("source=systemd {}", detail)
            }
        }
    }
}

impl From<ResolvedPid> for ResolvedTargetPid {
    fn from(resolved: ResolvedPid) -> Self {
        Self {
            pid: resolved.pid,
            source: ResolvedTargetPidSource::ProcessResolver {
                reason: resolved.reason,
                matched: resolved.matched,
            },
            original_cgroup_path: None,
        }
    }
}

pub(crate) fn dedupe_resolved_target_pids(
    resolved_pids: Vec<ResolvedTargetPid>,
) -> Result<Vec<ResolvedTargetPid>> {
    if resolved_pids.is_empty() {
        bail!("strict attach requires at least one resolved PID");
    }

    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for resolved in resolved_pids {
        if seen.insert(resolved.pid) {
            deduped.push(resolved);
        }
    }
    deduped.sort_by_key(|resolved| resolved.pid);
    Ok(deduped)
}

#[derive(Debug, Clone)]
pub(crate) struct LimitRecordTemplate {
    pub target: String,
    pub download_bytes_per_sec: Option<u64>,
    pub upload_bytes_per_sec: Option<u64>,
    pub download_display: Option<String>,
    pub upload_display: Option<String>,
    pub interface: String,
    pub cgroup_id: Option<u64>,
    pub target_cgroup_path: Option<String>,
}

pub(crate) fn build_limit_record(
    template: &LimitRecordTemplate,
    resolved: &ResolvedTargetPid,
    class_id: u32,
    applied_at: String,
) -> LimitRecord {
    LimitRecord {
        target: template.target.clone(),
        pid: resolved.pid,
        download_bytes_per_sec: template.download_bytes_per_sec,
        upload_bytes_per_sec: template.upload_bytes_per_sec,
        download_display: template.download_display.clone(),
        upload_display: template.upload_display.clone(),
        interface: template.interface.clone(),
        class_id,
        applied_at,
        ingress_handle: None,
        cgroup_id: template.cgroup_id,
        target_cgroup_path: template.target_cgroup_path.clone(),
        original_cgroup_path: resolved.original_cgroup_path.clone(),
        uid: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_resolved(pid: u32) -> ResolvedTargetPid {
        ResolvedTargetPid {
            pid,
            source: ResolvedTargetPidSource::ProcessResolver {
                reason: ProcessMatchReason::CommExact,
                matched: "brave".to_string(),
            },
            original_cgroup_path: None,
        }
    }

    #[test]
    fn resolved_pid_attach_rejects_empty_pid_list() {
        let err = dedupe_resolved_target_pids(Vec::new())
            .unwrap_err()
            .to_string();

        assert_eq!(err, "strict attach requires at least one resolved PID");
    }

    #[test]
    fn duplicate_resolved_pids_are_deduped() {
        let deduped = dedupe_resolved_target_pids(vec![
            process_resolved(22),
            process_resolved(11),
            process_resolved(22),
        ])
        .unwrap();

        assert_eq!(
            deduped.iter().map(|pid| pid.pid).collect::<Vec<_>>(),
            vec![11, 22]
        );
    }

    #[test]
    fn systemd_source_has_diagnostic_label() {
        let resolved = ResolvedTargetPid::systemd_scope(1234, "MainPID from transient scope");

        assert_eq!(
            resolved.diagnostic_label(),
            "source=systemd MainPID from transient scope"
        );
    }

    #[test]
    fn limit_record_builder_preserves_target_and_rate_metadata() {
        let template = LimitRecordTemplate {
            target: "helium".to_string(),
            download_bytes_per_sec: Some(62_500),
            upload_bytes_per_sec: Some(62_500),
            download_display: Some("500 Kbit/s".to_string()),
            upload_display: Some("500 Kbit/s".to_string()),
            interface: "wlp1s0".to_string(),
            cgroup_id: Some(42),
            target_cgroup_path: Some("/sys/fs/cgroup/zelynic/target_helium".to_string()),
        };
        let mut resolved = process_resolved(1234);
        resolved.original_cgroup_path = Some("/sys/fs/cgroup/user.slice/session.scope".to_string());

        let record = build_limit_record(&template, &resolved, 100, "now".to_string());

        assert_eq!(record.target, "helium");
        assert_eq!(record.pid, 1234);
        assert_eq!(record.download_bytes_per_sec, Some(62_500));
        assert_eq!(record.upload_display.as_deref(), Some("500 Kbit/s"));
        assert_eq!(record.interface, "wlp1s0");
        assert_eq!(
            record.original_cgroup_path.as_deref(),
            Some("/sys/fs/cgroup/user.slice/session.scope")
        );
    }
}
