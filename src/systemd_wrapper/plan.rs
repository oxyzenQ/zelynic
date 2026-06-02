// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};

use super::discovery::{build_pid_handoff_plan, PidHandoffPlan};
use super::sanitize::sanitize_scope_component;
use crate::units::BandwidthRate;

const CGROUP_BASE: &str = "/sys/fs/cgroup/zelynic";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RunDryRunPlan {
    pub target: String,
    pub scope_name: String,
    pub attach_target_cgroup: String,
    pub command: Vec<String>,
    pub download: Option<String>,
    pub upload: Option<String>,
    pub systemd_run: SystemdRunPlan,
    pub pid_handoff: PidHandoffPlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScopeMode {
    System,
}

impl ScopeMode {
    pub(super) fn label(self) -> &'static str {
        match self {
            ScopeMode::System => "system",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SystemdRunPlan {
    pub scope_unit_name: String,
    pub description: String,
    pub command_argv: Vec<String>,
    pub scope_mode: ScopeMode,
    pub target: String,
    pub attach_target_cgroup: String,
}

pub(super) fn build_dry_run_plan(
    target: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    command: &[String],
) -> Result<RunDryRunPlan> {
    if command.is_empty() {
        bail!("zelynic run requires a command after --");
    }

    let target_name = target
        .map(str::to_string)
        .unwrap_or_else(|| command_basename(&command[0]));
    let sanitized = sanitize_scope_component(&target_name);
    let scope_unit_name = format!("zelynic-run-{}", sanitized);
    let attach_target_cgroup = format!("{}/target_{}", CGROUP_BASE, sanitized);
    let systemd_run = SystemdRunPlan {
        scope_unit_name: scope_unit_name.clone(),
        description: format!("Zelynic target {}", target_name),
        command_argv: command.to_vec(),
        scope_mode: ScopeMode::System,
        target: target_name.clone(),
        attach_target_cgroup: attach_target_cgroup.clone(),
    };
    let pid_handoff = build_pid_handoff_plan(&systemd_run);

    Ok(RunDryRunPlan {
        target: target_name,
        scope_name: format!("{}.scope", scope_unit_name),
        attach_target_cgroup,
        command: command.to_vec(),
        download: parse_rate_display(download)?,
        upload: parse_rate_display(upload)?,
        systemd_run,
        pid_handoff,
    })
}

pub(super) fn systemd_run_argv(plan: &SystemdRunPlan) -> Vec<String> {
    let mut argv = vec!["systemd-run".to_string()];

    if plan.scope_mode == ScopeMode::System {
        argv.push("--scope".to_string());
    }

    argv.extend([
        "--unit".to_string(),
        plan.scope_unit_name.clone(),
        "--description".to_string(),
        plan.description.clone(),
        "--".to_string(),
    ]);
    argv.extend(plan.command_argv.clone());
    argv
}

fn command_basename(command: &str) -> String {
    command
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(command)
        .to_string()
}

fn parse_rate_display(rate: Option<&str>) -> Result<Option<String>> {
    rate.map(|value| BandwidthRate::parse(value).map(|parsed| parsed.to_string()))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd_wrapper::render::render_command;

    #[test]
    fn dry_run_plan_uses_command_basename_as_default_target() {
        let command = vec!["/usr/bin/helium".to_string(), "--new-window".to_string()];
        let plan = build_dry_run_plan(None, Some("500kbit"), Some("1mb"), &command).unwrap();

        assert_eq!(plan.target, "helium");
        assert_eq!(plan.scope_name, "zelynic-run-helium.scope");
        assert_eq!(
            plan.attach_target_cgroup,
            "/sys/fs/cgroup/zelynic/target_helium"
        );
        assert_eq!(plan.download.as_deref(), Some("500 Kbit/s"));
        assert_eq!(plan.upload.as_deref(), Some("1 MB/s"));
        assert_eq!(plan.systemd_run.scope_unit_name, "zelynic-run-helium");
        assert_eq!(plan.systemd_run.scope_mode, ScopeMode::System);
    }

    #[test]
    fn dry_run_plan_respects_explicit_target() {
        let command = vec!["echo".to_string(), "hello world".to_string()];
        let plan = build_dry_run_plan(Some("custom target"), None, None, &command).unwrap();

        assert_eq!(plan.target, "custom target");
        assert_eq!(plan.scope_name, "zelynic-run-custom_target.scope");
        assert_eq!(
            plan.attach_target_cgroup,
            "/sys/fs/cgroup/zelynic/target_custom_target"
        );
        assert_eq!(render_command(&plan.command), "echo 'hello world'");
    }

    #[test]
    fn explicit_target_affects_scope_name_and_description() {
        let command = vec!["helium".to_string()];
        let plan = build_dry_run_plan(Some("Helium Browser!"), None, None, &command).unwrap();

        assert_eq!(plan.scope_name, "zelynic-run-helium_browser.scope");
        assert_eq!(
            plan.attach_target_cgroup,
            "/sys/fs/cgroup/zelynic/target_helium_browser"
        );
        assert_eq!(
            plan.systemd_run.description,
            "Zelynic target Helium Browser!"
        );
    }
}
