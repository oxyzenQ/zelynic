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
    pub pid_handoff: PidHandoffPlan,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidHandoffPlan {
    pub method: String,
    pub fallback: String,
    pub attach: String,
    pub discovery_commands: Vec<Vec<String>>,
    pub scope_unit_name: String,
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

pub fn build_pid_handoff_plan(systemd_run: &SystemdRunPlan) -> PidHandoffPlan {
    let scope_name = format!("{}.scope", systemd_run.scope_unit_name);
    PidHandoffPlan {
        method: format!(
            "systemctl show {} --property MainPID,ControlGroup",
            scope_name
        ),
        fallback: "scan cgroup.procs under the reported ControlGroup".to_string(),
        attach: "move discovered PID(s) into the Zelynic target cgroup".to_string(),
        discovery_commands: vec![
            systemctl_show_argv(systemd_run),
            vec![
                "cat".to_string(),
                "/sys/fs/cgroup/<reported-control-group>/cgroup.procs".to_string(),
            ],
        ],
        scope_unit_name: scope_name,
        attach_target_cgroup: systemd_run.attach_target_cgroup.clone(),
    }
}

pub fn render_discovery_commands(plan: &PidHandoffPlan) -> Vec<String> {
    plan.discovery_commands
        .iter()
        .map(|argv| render_argv(argv))
        .collect()
}

fn systemctl_show_argv(plan: &SystemdRunPlan) -> Vec<String> {
    let mut argv = vec!["systemctl".to_string()];
    if plan.scope_mode == ScopeMode::System {
        argv.push("show".to_string());
    }
    argv.extend([
        format!("{}.scope", plan.scope_unit_name),
        "--property".to_string(),
        "MainPID".to_string(),
        "--property".to_string(),
        "ControlGroup".to_string(),
        "--value".to_string(),
    ]);
    argv
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
    push_line(&mut output, "  Future PID discovery:");
    push_line(
        &mut output,
        &format!("    method: {}", plan.pid_handoff.method),
    );
    push_line(
        &mut output,
        "    parser: planned; MainPID=0 will fall back to ControlGroup scan",
    );
    push_line(
        &mut output,
        &format!("    fallback: {}", plan.pid_handoff.fallback),
    );
    push_line(
        &mut output,
        &format!("    attach: {}", plan.pid_handoff.attach),
    );
    push_line(
        &mut output,
        "    note: systemd ControlGroup and Zelynic attach target are distinct",
    );
    push_line(&mut output, "");
    push_line(&mut output, "  Future PID discovery commands:");
    for command in render_discovery_commands(&plan.pid_handoff) {
        push_line(&mut output, &format!("    {}", command));
    }
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

#[allow(dead_code)]
mod pid_discovery {
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct SystemctlShowMetadata {
        pub main_pid: Option<u32>,
        pub control_group: Option<String>,
        pub warnings: Vec<String>,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum PidDiscoveryDecision {
        UseMainPid(u32),
        ScanControlGroup {
            control_group: String,
            cgroup_procs_path: String,
        },
        UseMainPidAndMaybeScan {
            pid: u32,
            control_group: String,
            cgroup_procs_path: String,
        },
        NoUsableDiscovery(String),
    }

    pub fn parse_systemctl_show_output(output: &str) -> SystemctlShowMetadata {
        let mut metadata = SystemctlShowMetadata {
            main_pid: None,
            control_group: None,
            warnings: Vec::new(),
        };
        let lines: Vec<&str> = output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();

        if lines.is_empty() {
            metadata
                .warnings
                .push("systemctl show output was empty".to_string());
            return metadata;
        }

        if lines.iter().any(|line| line.contains('=')) {
            parse_key_value_systemctl_lines(&lines, &mut metadata);
        } else {
            parse_value_systemctl_lines(&lines, &mut metadata);
        }

        metadata
    }

    pub fn decide_pid_discovery(metadata: &SystemctlShowMetadata) -> PidDiscoveryDecision {
        let valid_control_group = metadata.control_group.as_deref().and_then(|control_group| {
            control_group_to_cgroup_procs_path(control_group)
                .ok()
                .map(|path| (control_group, path))
        });

        match (metadata.main_pid, valid_control_group) {
            (Some(pid), Some((control_group, cgroup_procs_path))) => {
                PidDiscoveryDecision::UseMainPidAndMaybeScan {
                    pid,
                    control_group: control_group.to_string(),
                    cgroup_procs_path,
                }
            }
            (Some(pid), None) => PidDiscoveryDecision::UseMainPid(pid),
            (None, Some((control_group, cgroup_procs_path))) => {
                PidDiscoveryDecision::ScanControlGroup {
                    control_group: control_group.to_string(),
                    cgroup_procs_path,
                }
            }
            (None, None) => PidDiscoveryDecision::NoUsableDiscovery(
                "no usable MainPID or ControlGroup from systemd metadata".to_string(),
            ),
        }
    }

    pub fn control_group_to_cgroup_procs_path(control_group: &str) -> Result<String, String> {
        let control_group = validate_control_group(control_group)?;
        Ok(format!(
            "/sys/fs/cgroup/{}/cgroup.procs",
            control_group.trim_start_matches('/')
        ))
    }

    fn parse_key_value_systemctl_lines(lines: &[&str], metadata: &mut SystemctlShowMetadata) {
        for line in lines {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "MainPID" => metadata.main_pid = parse_main_pid(value, &mut metadata.warnings),
                "ControlGroup" => {
                    metadata.control_group = parse_control_group(value, &mut metadata.warnings);
                }
                _ => {}
            }
        }
    }

    fn parse_value_systemctl_lines(lines: &[&str], metadata: &mut SystemctlShowMetadata) {
        let Some(first) = lines.first() else {
            return;
        };

        if first.starts_with('/') {
            metadata.control_group = parse_control_group(first, &mut metadata.warnings);
        } else {
            metadata.main_pid = parse_main_pid(first, &mut metadata.warnings);
            if let Some(second) = lines.get(1) {
                metadata.control_group = parse_control_group(second, &mut metadata.warnings);
            }
        }
    }

    fn parse_main_pid(value: &str, warnings: &mut Vec<String>) -> Option<u32> {
        let value = value.trim();
        if value.is_empty() {
            warnings.push("MainPID was empty".to_string());
            return None;
        }

        match value.parse::<u32>() {
            Ok(0) => {
                warnings.push("MainPID=0 is not usable".to_string());
                None
            }
            Ok(pid) => Some(pid),
            Err(_) => {
                warnings.push(format!("invalid MainPID: {}", value));
                None
            }
        }
    }

    fn parse_control_group(value: &str, warnings: &mut Vec<String>) -> Option<String> {
        match validate_control_group(value) {
            Ok(control_group) => Some(control_group),
            Err(error) => {
                warnings.push(error);
                None
            }
        }
    }

    fn validate_control_group(value: &str) -> Result<String, String> {
        let value = value.trim();

        if value.is_empty() {
            return Err("ControlGroup was empty".to_string());
        }
        if !value.starts_with('/') {
            return Err(format!("ControlGroup must start with '/': {}", value));
        }
        if value == "/" {
            return Err("ControlGroup '/' is not specific enough".to_string());
        }
        if value.contains("..") {
            return Err(format!("ControlGroup contains unsafe '..': {}", value));
        }
        if value.chars().any(char::is_control) {
            return Err("ControlGroup contains control characters".to_string());
        }
        if value.split('/').skip(1).any(str::is_empty) {
            return Err(format!(
                "ControlGroup contains empty path segment: {}",
                value
            ));
        }

        Ok(value.to_string())
    }
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
    use super::pid_discovery::{
        control_group_to_cgroup_procs_path, decide_pid_discovery, parse_systemctl_show_output,
        PidDiscoveryDecision,
    };
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

    #[test]
    fn dry_run_output_includes_future_pid_discovery_section() {
        let command = vec!["helium".to_string()];
        let plan = build_dry_run_plan(Some("helium"), None, None, &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("Future PID discovery"));
        assert!(rendered.contains("method: systemctl show zelynic-run-helium.scope"));
        assert!(rendered.contains("fallback: scan cgroup.procs under the reported ControlGroup"));
        assert!(rendered.contains("attach: move discovered PID(s) into the Zelynic target cgroup"));
    }

    #[test]
    fn pid_discovery_command_preview_uses_scope_unit() {
        let command = vec!["helium".to_string()];
        let plan = build_dry_run_plan(Some("Helium Browser!"), None, None, &command).unwrap();
        let commands = render_discovery_commands(&plan.pid_handoff);

        assert_eq!(
            commands[0],
            "systemctl show zelynic-run-helium_browser.scope --property MainPID --property ControlGroup --value"
        );
    }

    #[test]
    fn cgroup_procs_fallback_is_template_not_guessed_path() {
        let command = vec!["helium".to_string()];
        let plan = build_dry_run_plan(Some("helium"), None, None, &command).unwrap();
        let commands = render_discovery_commands(&plan.pid_handoff);

        assert_eq!(
            commands[1],
            "cat '/sys/fs/cgroup/<reported-control-group>/cgroup.procs'"
        );
        assert!(!commands[1].contains("zelynic-run-helium.scope"));
    }

    #[test]
    fn output_states_systemd_controlgroup_and_attach_target_are_distinct() {
        let command = vec!["helium".to_string()];
        let plan = build_dry_run_plan(Some("helium"), None, None, &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("systemd ControlGroup and Zelynic attach target are distinct"));
        assert!(rendered.contains("/sys/fs/cgroup/zelynic/target_helium"));
    }

    #[test]
    fn parses_key_value_systemctl_show_output() {
        let parsed =
            parse_systemctl_show_output("MainPID=12345\nControlGroup=/system.slice/foo.scope\n");

        assert_eq!(parsed.main_pid, Some(12345));
        assert_eq!(
            parsed.control_group.as_deref(),
            Some("/system.slice/foo.scope")
        );
        assert!(parsed.warnings.is_empty());
    }

    #[test]
    fn parses_value_systemctl_show_output() {
        let parsed = parse_systemctl_show_output("12345\n/system.slice/foo.scope\n");

        assert_eq!(parsed.main_pid, Some(12345));
        assert_eq!(
            parsed.control_group.as_deref(),
            Some("/system.slice/foo.scope")
        );
    }

    #[test]
    fn main_pid_zero_falls_back_to_control_group() {
        let parsed =
            parse_systemctl_show_output("MainPID=0\nControlGroup=/system.slice/foo.scope\n");

        assert_eq!(parsed.main_pid, None);
        assert_eq!(
            decide_pid_discovery(&parsed),
            PidDiscoveryDecision::ScanControlGroup {
                control_group: "/system.slice/foo.scope".to_string(),
                cgroup_procs_path: "/sys/fs/cgroup/system.slice/foo.scope/cgroup.procs".to_string(),
            }
        );
        assert!(parsed
            .warnings
            .iter()
            .any(|warning| warning.contains("MainPID=0")));
    }

    #[test]
    fn missing_main_pid_with_control_group_scans_control_group() {
        let parsed = parse_systemctl_show_output("ControlGroup=/system.slice/foo.scope\n");

        assert_eq!(
            decide_pid_discovery(&parsed),
            PidDiscoveryDecision::ScanControlGroup {
                control_group: "/system.slice/foo.scope".to_string(),
                cgroup_procs_path: "/sys/fs/cgroup/system.slice/foo.scope/cgroup.procs".to_string(),
            }
        );
    }

    #[test]
    fn valid_main_pid_with_missing_control_group_uses_main_pid() {
        let parsed = parse_systemctl_show_output("MainPID=12345\n");

        assert_eq!(
            decide_pid_discovery(&parsed),
            PidDiscoveryDecision::UseMainPid(12345)
        );
    }

    #[test]
    fn empty_output_has_no_usable_discovery() {
        let parsed = parse_systemctl_show_output("");

        assert_eq!(parsed.main_pid, None);
        assert_eq!(parsed.control_group, None);
        assert_eq!(
            decide_pid_discovery(&parsed),
            PidDiscoveryDecision::NoUsableDiscovery(
                "no usable MainPID or ControlGroup from systemd metadata".to_string()
            )
        );
        assert!(parsed
            .warnings
            .contains(&"systemctl show output was empty".to_string()));
    }

    #[test]
    fn unsafe_control_group_with_parent_segment_is_rejected() {
        let parsed = parse_systemctl_show_output("MainPID=0\nControlGroup=/system.slice/../bad\n");

        assert_eq!(parsed.control_group, None);
        assert!(parsed
            .warnings
            .iter()
            .any(|warning| warning.contains("unsafe '..'")));
    }

    #[test]
    fn root_control_group_is_rejected() {
        let parsed = parse_systemctl_show_output("ControlGroup=/\n");

        assert_eq!(parsed.control_group, None);
        assert!(parsed
            .warnings
            .contains(&"ControlGroup '/' is not specific enough".to_string()));
    }

    #[test]
    fn control_group_converts_to_cgroup_procs_path() {
        assert_eq!(
            control_group_to_cgroup_procs_path("/system.slice/foo.scope").unwrap(),
            "/sys/fs/cgroup/system.slice/foo.scope/cgroup.procs"
        );
    }

    #[test]
    fn decision_model_uses_main_pid_and_maybe_scan_when_both_available() {
        let parsed =
            parse_systemctl_show_output("MainPID=12345\nControlGroup=/system.slice/foo.scope\n");

        assert_eq!(
            decide_pid_discovery(&parsed),
            PidDiscoveryDecision::UseMainPidAndMaybeScan {
                pid: 12345,
                control_group: "/system.slice/foo.scope".to_string(),
                cgroup_procs_path: "/sys/fs/cgroup/system.slice/foo.scope/cgroup.procs".to_string(),
            }
        );
    }
}
