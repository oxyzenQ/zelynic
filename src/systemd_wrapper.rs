// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};
use colored::Colorize;

use crate::units::BandwidthRate;

const CGROUP_BASE: &str = "/sys/fs/cgroup/zelynic";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDryRunPlan {
    pub target: String,
    pub scope_name: String,
    pub target_cgroup_path: String,
    pub command: Vec<String>,
    pub download: Option<String>,
    pub upload: Option<String>,
}

pub fn run_systemd_wrapper_dry_run(
    dry_run: bool,
    target: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    command: &[String],
) -> Result<()> {
    if !dry_run {
        bail!("zelynic run is dry-run only in this release. Re-run with --dry-run.");
    }

    let plan = build_dry_run_plan(target, download, upload, command)?;
    print_dry_run_plan(&plan);
    Ok(())
}

pub fn build_dry_run_plan(
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

    Ok(RunDryRunPlan {
        target: target_name,
        scope_name: format!("zelynic-run-{}.scope", sanitized),
        target_cgroup_path: format!("{}/target_{}", CGROUP_BASE, sanitized),
        command: command.to_vec(),
        download: parse_rate_display(download)?,
        upload: parse_rate_display(upload)?,
    })
}

pub fn sanitize_scope_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let sanitized = sanitized.trim_matches('_');
    if sanitized.is_empty() {
        "target".to_string()
    } else {
        sanitized.to_string()
    }
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

fn render_command(command: &[String]) -> String {
    command
        .iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "-_./:=+".contains(ch))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn print_dry_run_plan(plan: &RunDryRunPlan) {
    println!("{}", "zelynic run dry-run".green().bold());
    println!("  Target: {}", plan.target.cyan());
    println!("  Scope: {}", plan.scope_name.cyan());
    println!("  Command: {}", render_command(&plan.command));
    println!(
        "  Download: {}",
        plan.download.as_deref().unwrap_or("unlimited")
    );
    println!(
        "  Upload: {}",
        plan.upload.as_deref().unwrap_or("unlimited")
    );
    println!("  Planned cgroup: {}", plan.target_cgroup_path);
    println!();
    println!("  No process was launched.");
    println!("  No nftables, tc, cgroup, or state changes were made.");
    println!("  Live systemd scope wrapper mode is future work.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_component_sanitizes_unsafe_characters() {
        assert_eq!(
            sanitize_scope_component("Helium Browser!/Main"),
            "Helium_Browser__Main"
        );
        assert_eq!(sanitize_scope_component("///"), "target");
    }

    #[test]
    fn dry_run_plan_uses_command_basename_as_default_target() {
        let command = vec!["/usr/bin/helium".to_string(), "--new-window".to_string()];
        let plan = build_dry_run_plan(None, Some("500kbit"), Some("1mb"), &command).unwrap();

        assert_eq!(plan.target, "helium");
        assert_eq!(plan.scope_name, "zelynic-run-helium.scope");
        assert_eq!(
            plan.target_cgroup_path,
            "/sys/fs/cgroup/zelynic/target_helium"
        );
        assert_eq!(plan.download.as_deref(), Some("500 Kbit/s"));
        assert_eq!(plan.upload.as_deref(), Some("1 MB/s"));
    }

    #[test]
    fn dry_run_plan_respects_explicit_target() {
        let command = vec!["echo".to_string(), "hello world".to_string()];
        let plan = build_dry_run_plan(Some("custom target"), None, None, &command).unwrap();

        assert_eq!(plan.target, "custom target");
        assert_eq!(plan.scope_name, "zelynic-run-custom_target.scope");
        assert_eq!(
            plan.target_cgroup_path,
            "/sys/fs/cgroup/zelynic/target_custom_target"
        );
        assert_eq!(render_command(&plan.command), "echo 'hello world'");
    }
}
