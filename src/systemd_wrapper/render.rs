// SPDX-License-Identifier: GPL-3.0-only
use colored::Colorize;
use std::io::{self, Write};

use super::discovery::PidHandoffPlan;
use super::plan::{systemd_run_argv, LiveRunPlan, RunDryRunPlan, SystemdRunPlan};

pub(super) fn print_dry_run_plan(plan: &RunDryRunPlan) {
    colorize_dry_run_plan(&render_dry_run_plan(plan));
    let _ = io::stdout().flush();
}

pub(super) fn print_live_run_plan(plan: &LiveRunPlan) {
    colorize_dry_run_plan(&render_live_run_plan(plan));
    let _ = io::stdout().flush();
}

pub(super) fn render_dry_run_plan(plan: &RunDryRunPlan) -> String {
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

pub(super) fn render_live_run_plan(plan: &LiveRunPlan) -> String {
    let mut output = String::new();

    push_line(&mut output, "zelynic run execute plan");
    push_line(&mut output, &format!("  Target: {}", plan.target));
    push_line(
        &mut output,
        &format!("  Scope mode: {}", plan.scope_mode.label()),
    );
    push_line(&mut output, &format!("  Scope: {}", plan.scope_unit));
    push_line(
        &mut output,
        &format!("  Command: {}", render_command(&plan.command_argv)),
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
    push_line(&mut output, "  Future launch argv:");
    push_line(
        &mut output,
        &format!("  {}", render_argv(&plan.systemd_run_argv)),
    );
    push_line(&mut output, "");
    push_line(&mut output, "  Future PID discovery argv:");
    for command in &plan.pid_discovery_argv {
        push_line(&mut output, &format!("    {}", render_argv(command)));
    }
    push_line(&mut output, "");
    push_line(
        &mut output,
        &format!("  Future strict attach: {}", plan.strict_attach_step),
    );
    push_line(&mut output, "  No process was launched.");
    push_line(
        &mut output,
        "  No nftables, tc, cgroup, or state changes were made.",
    );

    output
}

pub(super) fn render_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|part| shell_quote(part))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn render_systemd_run_command(plan: &SystemdRunPlan) -> String {
    render_argv(&systemd_run_argv(plan))
}

pub(super) fn render_discovery_commands(plan: &PidHandoffPlan) -> Vec<String> {
    plan.discovery_commands
        .iter()
        .map(|argv| render_argv(argv))
        .collect()
}

pub(super) fn render_command(command: &[String]) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd_wrapper::plan::build_dry_run_plan;

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
    fn live_run_output_is_execute_plan_without_mutation_notice() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = crate::systemd_wrapper::plan::build_live_run_plan(
            None,
            Some("500kbit"),
            None,
            &command,
        )
        .unwrap();
        let rendered = render_live_run_plan(&plan);

        assert!(rendered.contains("zelynic run execute plan"));
        assert!(rendered.contains("Future launch argv"));
        assert!(rendered.contains("Future PID discovery argv"));
        assert!(rendered.contains("Future strict attach"));
        assert!(rendered.contains("systemd-run --scope --unit zelynic-run-echo"));
        assert!(rendered.contains("No process was launched."));
        assert!(rendered.contains("No nftables, tc, cgroup, or state changes were made."));
    }
}
