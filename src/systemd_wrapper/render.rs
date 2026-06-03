// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use colored::Colorize;
use std::io::{self, Write};

use super::contract::build_run_contract;
use super::discovery::PidHandoffPlan;
use super::plan::{systemd_run_argv, LiveRunPlan, RunDryRunPlan, ScopeMode, SystemdRunPlan};

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
    push_line(&mut output, &format!("  Scope note: {}", scope_note()));
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
        "  1. launch command in transient systemd scope (backgrounded)",
    );
    push_line(
        &mut output,
        "  2. discover ControlGroup path from scope unit",
    );
    push_line(
        &mut output,
        "  3. read PID(s) from cgroup.procs under discovered ControlGroup",
    );
    push_line(
        &mut output,
        "  4. apply existing Zelynic strict attach backend",
    );
    push_line(
        &mut output,
        "  5. enforce nftables + HTB limits on the Zelynic target cgroup",
    );
    push_line(&mut output, "");
    push_line(&mut output, "  Future PID discovery (ControlGroup-first):");
    push_line(
        &mut output,
        "    primary: ControlGroup from systemd scope unit",
    );
    push_line(
        &mut output,
        &format!(
            "    step 1: read ControlGroup path from '{}'",
            scope_aware_show_command(plan.systemd_run.scope_mode)
        ),
    );
    push_line(
        &mut output,
        "    step 2: read PIDs from /sys/fs/cgroup${ControlGroup}/cgroup.procs",
    );
    push_line(
        &mut output,
        &format!("    method: {}", plan.pid_handoff.method),
    );
    push_line(
        &mut output,
        "    MainPID: optional/diagnostic only; scope units may report MainPID=0 or absent",
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
    push_contract_section(&mut output, &plan.systemd_run.scope_mode);
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
    push_line(&mut output, &format!("  Scope note: {}", scope_note()));
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
    push_line(&mut output, "  Future PID discovery (ControlGroup-first):");
    push_line(&mut output, "    primary: ControlGroup from scope unit");
    push_line(
        &mut output,
        &format!(
            "    step 1: read ControlGroup from '{}'",
            scope_aware_show_command(plan.scope_mode)
        ),
    );
    push_line(
        &mut output,
        "    step 2: read PIDs from /sys/fs/cgroup${ControlGroup}/cgroup.procs",
    );
    push_line(
        &mut output,
        "    MainPID: optional/diagnostic only; scope units may report MainPID=0 or absent",
    );
    push_line(&mut output, "  Future PID discovery argv:");
    for command in &plan.pid_discovery_argv {
        push_line(&mut output, &format!("    {}", render_argv(command)));
    }
    push_line(&mut output, "");
    push_line(&mut output, "  Execution preflight:");
    push_line(
        &mut output,
        &format!("    scope mode: {}", plan.preflight.scope_mode.label()),
    );
    push_line(
        &mut output,
        &format!("    launch: {}", plan.preflight.launch),
    );
    push_line(
        &mut output,
        &format!("    attach: {}", plan.preflight.attach),
    );
    push_line(
        &mut output,
        &format!("    readiness: {}", plan.preflight.readiness.label()),
    );
    push_line(
        &mut output,
        &format!("    reason: {}", plan.preflight.reason),
    );
    push_line(&mut output, "");
    push_line(
        &mut output,
        &format!("  Future strict attach: {}", plan.strict_attach_step),
    );
    push_line(&mut output, "");
    push_contract_section(&mut output, &plan.scope_mode);
    push_line(&mut output, "");
    push_line(&mut output, "  No process was launched.");
    push_line(
        &mut output,
        "  No nftables, tc, cgroup, or state changes were made.",
    );
    push_line(&mut output, "  Live launch is not implemented yet.");

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

fn scope_aware_show_command(scope_mode: ScopeMode) -> String {
    match scope_mode {
        ScopeMode::User => "systemctl --user show <unit> --property ControlGroup".to_string(),
        ScopeMode::System => "systemctl show <unit> --property ControlGroup".to_string(),
    }
}

fn push_contract_section(output: &mut String, scope_mode: &ScopeMode) {
    let contract = build_run_contract(*scope_mode);
    push_line(output, "  Future launch/discover/attach contract:");
    for (index, step) in contract.steps.iter().enumerate() {
        push_line(
            output,
            &format!(
                "    {}. {}: [{}] {} (privilege: {})",
                index + 1,
                step.phase.label(),
                if step.implemented {
                    "ready"
                } else {
                    "not implemented"
                },
                step.description,
                step.privilege.label(),
            ),
        );
    }
    push_line(
        output,
        &format!(
            "    live execution implemented: {}",
            contract.live_execution_implemented,
        ),
    );
}

fn scope_note() -> &'static str {
    "user scope is the default to avoid system Polkit prompts; system scope is explicit planning-only"
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
            "systemd-run --user --scope --unit zelynic-run-helium --description 'Zelynic target helium' -- echo hello"
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
        assert!(rendered.contains("Scope mode: user"));
        assert!(rendered.contains("user scope is the default to avoid system Polkit prompts"));
        assert!(rendered.contains("systemd-run --user --scope --unit zelynic-run-echo"));
        assert!(!rendered.contains("Planned cgroup"));
        assert!(rendered.contains("No process was launched."));
        assert!(rendered.contains("No nftables, tc, cgroup, or state changes were made."));
    }

    #[test]
    fn dry_run_output_describes_control_group_first_flow() {
        let command = vec!["helium".to_string()];
        let plan =
            build_dry_run_plan(Some("helium"), Some("500kbit"), Some("500kbit"), &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("Planned flow"));
        assert!(rendered.contains("1. launch command in transient systemd scope (backgrounded)"));
        assert!(rendered.contains("2. discover ControlGroup path from scope unit"));
        assert!(rendered.contains("3. read PID(s) from cgroup.procs under discovered ControlGroup"));
        assert!(rendered.contains("4. apply existing Zelynic strict attach backend"));
        assert!(rendered.contains("5. enforce nftables + HTB limits on the Zelynic target cgroup"));
        assert!(rendered.contains("Live launch is not implemented yet."));
    }

    #[test]
    fn dry_run_user_scope_discovery_wording_uses_systemctl_user_show() {
        let command = vec!["helium".to_string()];
        let plan = build_dry_run_plan(Some("helium"), None, None, &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("Future PID discovery (ControlGroup-first)"));
        assert!(rendered.contains("primary: ControlGroup from systemd scope unit"));
        assert!(rendered.contains(
            "step 1: read ControlGroup path from 'systemctl --user show <unit> --property ControlGroup'"
        ));
        assert!(rendered.contains("MainPID: optional/diagnostic only"));
        assert!(rendered.contains("method: systemctl --user show zelynic-run-helium.scope"));
        assert!(rendered.contains("fallback: scan cgroup.procs under the reported ControlGroup"));
        assert!(rendered.contains("attach: move discovered PID(s) into the Zelynic target cgroup"));
    }

    #[test]
    fn dry_run_system_scope_discovery_wording_uses_systemctl_show() {
        let command = vec!["echo".to_string()];
        let plan = crate::systemd_wrapper::plan::build_dry_run_plan_with_scope_mode(
            None,
            None,
            None,
            &command,
            ScopeMode::System,
        )
        .unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("Scope mode: system"));
        assert!(rendered.contains(
            "step 1: read ControlGroup path from 'systemctl show <unit> --property ControlGroup'"
        ));
        // Must NOT contain --user in the step 1 wording for system scope
        assert!(!rendered.contains("step 1: read ControlGroup path from 'systemctl --user show"));
        assert!(rendered.contains("method: systemctl show zelynic-run-echo.scope"));
    }

    #[test]
    fn execute_plan_user_scope_discovery_uses_systemctl_user_show() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = crate::systemd_wrapper::plan::build_live_run_plan(
            None,
            Some("500kbit"),
            None,
            &command,
        )
        .unwrap();
        let rendered = render_live_run_plan(&plan);

        assert!(rendered.contains(
            "step 1: read ControlGroup from 'systemctl --user show <unit> --property ControlGroup'"
        ));
    }

    #[test]
    fn execute_plan_system_scope_discovery_uses_systemctl_show() {
        let command = vec!["echo".to_string()];
        let plan = crate::systemd_wrapper::plan::build_live_run_plan_with_scope_mode(
            None,
            None,
            None,
            &command,
            ScopeMode::System,
            crate::systemd_wrapper::preflight::evaluate_execution_preflight(
                crate::systemd_wrapper::preflight::ExecutionPreflightInput {
                    scope_mode: ScopeMode::System,
                    is_root: false,
                },
            ),
        )
        .unwrap();
        let rendered = render_live_run_plan(&plan);

        assert!(rendered.contains("Scope mode: system"));
        assert!(rendered.contains(
            "step 1: read ControlGroup from 'systemctl show <unit> --property ControlGroup'"
        ));
        // Must NOT contain --user in step 1 wording for system scope
        assert!(!rendered.contains("step 1: read ControlGroup from 'systemctl --user show"));
    }

    #[test]
    fn pid_discovery_command_preview_uses_scope_unit() {
        let command = vec!["helium".to_string()];
        let plan = build_dry_run_plan(Some("Helium Browser!"), None, None, &command).unwrap();
        let commands = render_discovery_commands(&plan.pid_handoff);

        assert_eq!(
            commands[0],
            "systemctl --user show zelynic-run-helium_browser.scope --property MainPID --property ControlGroup --value"
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
    fn execute_output_preserves_all_safety_wording() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = crate::systemd_wrapper::plan::build_live_run_plan(
            None,
            Some("500kbit"),
            None,
            &command,
        )
        .unwrap();
        let rendered = render_live_run_plan(&plan);

        assert!(rendered.contains("Future PID discovery (ControlGroup-first)"));
        assert!(rendered.contains("primary: ControlGroup from scope unit"));
        assert!(rendered.contains("MainPID: optional/diagnostic only"));
        assert!(rendered.contains("No process was launched."));
        assert!(rendered.contains("No nftables, tc, cgroup, or state changes were made."));
        assert!(rendered.contains("Live launch is not implemented yet."));
    }

    #[test]
    fn dry_run_output_can_preview_system_scope_explicitly() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = crate::systemd_wrapper::plan::build_dry_run_plan_with_scope_mode(
            None,
            Some("500kbit"),
            None,
            &command,
            crate::systemd_wrapper::ScopeMode::System,
        )
        .unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("Scope mode: system"));
        assert!(rendered.contains("systemd-run --scope --unit zelynic-run-echo"));
        assert!(rendered.contains(
            "systemctl show zelynic-run-echo.scope --property MainPID --property ControlGroup --value"
        ));
    }

    #[test]
    fn dry_run_contract_section_present_and_not_implemented() {
        let command = vec!["echo".to_string()];
        let plan = build_dry_run_plan(None, Some("500kbit"), None, &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("Future launch/discover/attach contract:"));
        assert!(rendered.contains("1. launch: [not implemented]"));
        assert!(rendered.contains("2. discover: [not implemented]"));
        assert!(rendered.contains("3. attach: [not implemented]"));
        assert!(rendered.contains("live execution implemented: false"));
        assert!(rendered.contains("privilege: user"));
        assert!(rendered.contains("privilege: root"));
    }

    #[test]
    fn dry_run_contract_user_scope_uses_user_scope_launch_command() {
        let command = vec!["helium".to_string()];
        let plan = build_dry_run_plan(Some("helium"), None, None, &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("--user --scope"));
        assert!(rendered.contains("systemctl --user show"));
    }

    #[test]
    fn dry_run_contract_system_scope_uses_system_scope_launch_command() {
        let command = vec!["echo".to_string()];
        let plan = crate::systemd_wrapper::plan::build_dry_run_plan_with_scope_mode(
            None,
            None,
            None,
            &command,
            crate::systemd_wrapper::ScopeMode::System,
        )
        .unwrap();
        let rendered = render_dry_run_plan(&plan);

        assert!(rendered.contains("--scope"));
        assert!(!rendered.contains("1. launch: [not implemented] create transient systemd scope via systemd-run --user --scope"));
        assert!(rendered.contains("systemctl show <unit> --property ControlGroup"));
    }

    #[test]
    fn dry_run_contract_attach_step_requires_root() {
        let command = vec!["echo".to_string()];
        let plan = build_dry_run_plan(None, None, None, &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        // The attach step line should have "privilege: root"
        assert!(rendered.contains("privilege: root"));
    }

    #[test]
    fn dry_run_contract_preserves_safety_wording_after_contract_section() {
        let command = vec!["echo".to_string()];
        let plan = build_dry_run_plan(None, None, None, &command).unwrap();
        let rendered = render_dry_run_plan(&plan);

        // Safety lines must still be present
        assert!(rendered.contains("No process was launched."));
        assert!(rendered.contains("No nftables, tc, cgroup, or state changes were made."));
        assert!(rendered.contains("Live launch is not implemented yet."));
    }

    #[test]
    fn execute_contract_section_present_and_not_implemented() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = crate::systemd_wrapper::plan::build_live_run_plan(
            None,
            Some("500kbit"),
            None,
            &command,
        )
        .unwrap();
        let rendered = render_live_run_plan(&plan);

        assert!(rendered.contains("Future launch/discover/attach contract:"));
        assert!(rendered.contains("1. launch: [not implemented]"));
        assert!(rendered.contains("2. discover: [not implemented]"));
        assert!(rendered.contains("3. attach: [not implemented]"));
        assert!(rendered.contains("live execution implemented: false"));
    }

    #[test]
    fn execute_contract_preserves_all_safety_wording() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = crate::systemd_wrapper::plan::build_live_run_plan(
            None,
            Some("500kbit"),
            None,
            &command,
        )
        .unwrap();
        let rendered = render_live_run_plan(&plan);

        assert!(rendered.contains("No process was launched."));
        assert!(rendered.contains("No nftables, tc, cgroup, or state changes were made."));
        assert!(rendered.contains("Live launch is not implemented yet."));
    }

    #[test]
    fn execute_contract_system_scope_uses_system_commands() {
        let command = vec!["echo".to_string()];
        let plan = crate::systemd_wrapper::plan::build_live_run_plan_with_scope_mode(
            None,
            None,
            None,
            &command,
            crate::systemd_wrapper::ScopeMode::System,
            crate::systemd_wrapper::preflight::evaluate_execution_preflight(
                crate::systemd_wrapper::preflight::ExecutionPreflightInput {
                    scope_mode: crate::systemd_wrapper::ScopeMode::System,
                    is_root: false,
                },
            ),
        )
        .unwrap();
        let rendered = render_live_run_plan(&plan);

        assert!(rendered.contains("Future launch/discover/attach contract:"));
        assert!(rendered.contains("1. launch: [not implemented]"));
    }
}
