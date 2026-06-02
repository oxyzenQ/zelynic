// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Result};
use colored::Colorize;

use crate::units::BandwidthRate;

const CGROUP_BASE: &str = "/sys/fs/cgroup/zelynic";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunDryRunPlan {
    pub target: String,
    pub scope_name: String,
    pub attach_target_cgroup: String,
    pub command: Vec<String>,
    pub download: Option<String>,
    pub upload: Option<String>,
    pub systemd_run: SystemdRunPlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeMode {
    System,
}

impl ScopeMode {
    fn label(self) -> &'static str {
        match self {
            ScopeMode::System => "system",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemdRunPlan {
    pub scope_unit_name: String,
    pub description: String,
    pub command_argv: Vec<String>,
    pub scope_mode: ScopeMode,
    pub target: String,
    pub attach_target_cgroup: String,
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

    Ok(RunDryRunPlan {
        target: target_name,
        scope_name: format!("{}.scope", scope_unit_name),
        attach_target_cgroup,
        command: command.to_vec(),
        download: parse_rate_display(download)?,
        upload: parse_rate_display(upload)?,
        systemd_run,
    })
}

pub fn sanitize_scope_component(value: &str) -> String {
    let mut sanitized = String::new();
    let mut last_was_separator = false;

    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator && !sanitized.is_empty() {
            sanitized.push('_');
            last_was_separator = true;
        }
    }

    if sanitized.ends_with('_') {
        sanitized.pop();
    }

    if sanitized.is_empty() {
        "target".to_string()
    } else {
        sanitized
    }
}

pub fn systemd_run_argv(plan: &SystemdRunPlan) -> Vec<String> {
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

pub fn render_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn render_systemd_run_command(plan: &SystemdRunPlan) -> String {
    render_argv(&systemd_run_argv(plan))
}

pub fn render_dry_run_plan(plan: &RunDryRunPlan) -> String {
    let mut output = String::new();

    push_line(&mut output, "zelynic run dry-run");
    push_line(&mut output, &format!("  Target: {}", plan.target));
    push_line(
        &mut output,
        &format!("  Scope mode: {}", plan.systemd_run.scope_mode.label()),
    );
    push_line(&mut output, &format!("  Scope: {}", plan.scope_name));
    push_line(
        &mut output,
        &format!("  Command: {}", render_command(&plan.command)),
    );
    push_line(
        &mut output,
        &format!(
            "  Download: {}",
            plan.download.as_deref().unwrap_or("unlimited")
        ),
    );
    push_line(
        &mut output,
        &format!(
            "  Upload: {}",
            plan.upload.as_deref().unwrap_or("unlimited")
        ),
    );
    push_line(
        &mut output,
        &format!("  Future attach target: {}", plan.attach_target_cgroup),
    );
    push_line(&mut output, "");
    push_line(&mut output, "  Future launch command:");
    push_line(
        &mut output,
        &format!("  {}", render_systemd_run_command(&plan.systemd_run)),
    );
    push_line(&mut output, "");
    push_line(&mut output, "  Planned flow:");
    push_line(
        &mut output,
        "  1. launch command in transient systemd scope",
    );
    push_line(&mut output, "  2. discover launched PID(s)");
    push_line(
        &mut output,
        "  3. apply existing Zelynic strict attach backend",
    );
    push_line(
        &mut output,
        "  4. enforce nftables + HTB limits on the Zelynic target cgroup",
    );
    push_line(&mut output, "");
    push_line(&mut output, "  No process was launched.");
    push_line(
        &mut output,
        "  No nftables, tc, cgroup, or state changes were made.",
    );
    push_line(&mut output, "  Live launch is not implemented yet.");

    output
}

fn push_line(output: &mut String, line: &str) {
    output.push_str(line);
    output.push('\n');
}

fn colorize_dry_run_plan(rendered: &str) {
    for (index, line) in rendered.lines().enumerate() {
        if index == 0 {
            println!("{}", line.green().bold());
        } else if let Some(target) = line.strip_prefix("  Target: ") {
            println!("  Target: {}", target.cyan());
        } else if let Some(scope) = line.strip_prefix("  Scope: ") {
            println!("  Scope: {}", scope.cyan());
        } else {
            println!("{line}");
        }
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
    render_argv(command)
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "-_./:=+".contains(ch))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn print_dry_run_plan(plan: &RunDryRunPlan) {
    colorize_dry_run_plan(&render_dry_run_plan(plan));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_component_sanitizes_unsafe_characters() {
        assert_eq!(sanitize_scope_component("helium"), "helium");
        assert_eq!(
            sanitize_scope_component("Helium Browser!"),
            "helium_browser"
        );
        assert_eq!(sanitize_scope_component("foo///bar"), "foo_bar");
        assert_eq!(sanitize_scope_component("///"), "target");
    }

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
    fn systemd_run_plan_renders_simple_command() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = build_dry_run_plan(Some("helium"), Some("500kbit"), None, &command).unwrap();

        assert_eq!(
            render_systemd_run_command(&plan.systemd_run),
            "systemd-run --scope --unit zelynic-run-helium --description 'Zelynic target helium' -- echo hello"
        );
    }

    #[test]
    fn command_rendering_quotes_spaces_and_special_characters() {
        let argv = vec![
            "systemd-run".to_string(),
            "--".to_string(),
            "helium".to_string(),
            "--new-window".to_string(),
            "https://fast.com".to_string(),
            "hello world".to_string(),
            "$(touch /tmp/nope)".to_string(),
            "that's-fine".to_string(),
        ];

        assert_eq!(
            render_argv(&argv),
            "systemd-run -- helium --new-window https://fast.com 'hello world' '$(touch /tmp/nope)' 'that'\\''s-fine'"
        );
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

    #[test]
    fn dry_run_output_includes_launch_command_attach_target_and_no_mutation_notice() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = build_dry_run_plan(None, Some("500kbit"), Some("500kbit"), &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("Future launch command"));
        assert!(rendered.contains("Future attach target"));
        assert!(rendered.contains("systemd-run --scope --unit zelynic-run-echo"));
        assert!(!rendered.contains("Planned cgroup"));
        assert!(rendered.contains("No process was launched."));
        assert!(rendered.contains("No nftables, tc, cgroup, or state changes were made."));
    }

    #[test]
    fn dry_run_output_describes_launch_then_attach_flow() {
        let command = vec!["helium".to_string()];
        let plan =
            build_dry_run_plan(Some("helium"), Some("500kbit"), Some("500kbit"), &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("Planned flow"));
        assert!(rendered.contains("1. launch command in transient systemd scope"));
        assert!(rendered.contains("2. discover launched PID(s)"));
        assert!(rendered.contains("3. apply existing Zelynic strict attach backend"));
        assert!(rendered.contains("4. enforce nftables + HTB limits on the Zelynic target cgroup"));
        assert!(rendered.contains("Live launch is not implemented yet."));
    }
}
