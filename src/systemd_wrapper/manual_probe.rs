// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use super::plan::{RunDryRunPlan, ScopeMode};
use super::render::{push_line, shell_quote};

pub(super) fn push_manual_probe_recipe(output: &mut String, plan: &RunDryRunPlan) {
    let scope_mode = plan.systemd_run.scope_mode;
    let unit = &plan.scope_name;
    let scope_unit_name = &plan.systemd_run.scope_unit_name;
    let description = &plan.systemd_run.description;
    let command_str = plan
        .command
        .iter()
        .map(|c| shell_quote(c))
        .collect::<Vec<_>>()
        .join(" ");

    push_line(
        output,
        "  Manual probe recipe (copy/paste only, not executed by Zelynic):",
    );

    if scope_mode == ScopeMode::System {
        push_line(output, "    WARNING: system scope may require root/sudo.");
        push_line(
            output,
            "    Plain non-root system scope can trigger Polkit/floating auth.",
        );
        push_line(
            output,
            "    Do not run from automation unless privilege/session behavior is understood.",
        );
    }

    let scope_flags = match scope_mode {
        ScopeMode::User => "--user --scope",
        ScopeMode::System => "--scope",
    };
    let sudo = match scope_mode {
        ScopeMode::User => "",
        ScopeMode::System => "sudo ",
    };

    // 1. start backgrounded scope
    push_line(output, "    1. start backgrounded scope:");
    push_line(
        output,
        &format!(
            "       {}systemd-run {} --unit {} --description {} -- {} &",
            sudo,
            scope_flags,
            scope_unit_name,
            shell_quote(description),
            command_str
        ),
    );

    // 2. inspect scope unit
    push_line(output, "    2. inspect scope unit:");
    let show_cmd = match scope_mode {
        ScopeMode::User => format!("systemctl --user show {}", unit),
        ScopeMode::System => format!("systemctl show {}", unit),
    };
    push_line(
        output,
        &format!(
            "       {} --property MainPID --property ControlGroup --property ActiveState --property SubState",
            show_cmd
        ),
    );

    // 3. read PID(s) from cgroup.procs
    push_line(output, "    3. read PID(s) from cgroup.procs:");
    let cg_cmd = match scope_mode {
        ScopeMode::User => format!(
            "systemctl --user show {} --property ControlGroup --value",
            unit
        ),
        ScopeMode::System => {
            format!("systemctl show {} --property ControlGroup --value", unit)
        }
    };
    push_line(output, &format!("       cg=$({}) && \\", cg_cmd));
    push_line(output, "       cat \"/sys/fs/cgroup${cg}/cgroup.procs\"");

    // 4. cleanup
    push_line(output, "    4. cleanup:");
    let stop_cmd = match scope_mode {
        ScopeMode::User => format!("systemctl --user stop {}", unit),
        ScopeMode::System => format!("systemctl stop {}", unit),
    };
    push_line(output, &format!("       {}{}", sudo, stop_cmd));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd_wrapper::plan::build_dry_run_plan;
    use crate::systemd_wrapper::plan::build_dry_run_plan_with_scope_mode;

    #[test]
    fn user_scope_includes_manual_probe_recipe() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let plan = build_dry_run_plan(None, Some("500kbit"), None, &command).unwrap();
        let mut output = String::new();
        push_manual_probe_recipe(&mut output, &plan);

        assert!(output.contains("Manual probe recipe (copy/paste only, not executed by Zelynic):"));
        assert!(output.contains("1. start backgrounded scope:"));
        assert!(output.contains("2. inspect scope unit:"));
        assert!(output.contains("3. read PID(s) from cgroup.procs:"));
        assert!(output.contains("4. cleanup:"));
    }

    #[test]
    fn user_scope_recipe_uses_backgrounded_systemd_run_user_scope() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let plan = build_dry_run_plan(None, Some("500kbit"), None, &command).unwrap();
        let mut output = String::new();
        push_manual_probe_recipe(&mut output, &plan);

        assert!(
            output.contains("systemd-run --user --scope --unit zelynic-run-sleep"),
            "recipe should include systemd-run --user --scope with scope unit name"
        );
        let start_line = output
            .lines()
            .find(|l| l.contains("systemd-run --user --scope"))
            .expect("should have recipe start line with systemd-run");
        assert!(
            start_line.trim().ends_with('&'),
            "recipe start command should end with & for backgrounding"
        );
        assert!(
            !output.contains("sudo systemd-run"),
            "user scope recipe should not contain sudo"
        );
    }

    #[test]
    fn user_scope_recipe_includes_systemctl_user_show_and_stop() {
        let command = vec!["echo".to_string(), "hello".to_string()];
        let plan = build_dry_run_plan(Some("echo"), None, None, &command).unwrap();
        let mut output = String::new();
        push_manual_probe_recipe(&mut output, &plan);

        assert!(
            output.contains("systemctl --user show zelynic-run-echo.scope --property MainPID"),
            "recipe inspect should use systemctl --user show with unit"
        );
        assert!(
            output.contains("systemctl --user stop zelynic-run-echo.scope"),
            "recipe cleanup should use systemctl --user stop with unit"
        );
        assert!(
            output.contains("cgroup.procs"),
            "recipe must mention cgroup.procs"
        );
        assert!(
            !output.contains("WARNING: system scope may require root/sudo"),
            "user scope recipe should not have system scope warning"
        );
    }

    #[test]
    fn system_scope_recipe_includes_root_polkit_warning() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let plan =
            build_dry_run_plan_with_scope_mode(None, None, None, &command, ScopeMode::System)
                .unwrap();
        let mut output = String::new();
        push_manual_probe_recipe(&mut output, &plan);

        assert!(output.contains("WARNING: system scope may require root/sudo."));
        assert!(output.contains("Plain non-root system scope can trigger Polkit/floating auth."));
        assert!(output.contains(
            "Do not run from automation unless privilege/session behavior is understood."
        ));
    }

    #[test]
    fn system_scope_recipe_uses_system_scope_commands_and_sudo() {
        let command = vec!["sleep".to_string(), "30".to_string()];
        let plan =
            build_dry_run_plan_with_scope_mode(None, None, None, &command, ScopeMode::System)
                .unwrap();
        let mut output = String::new();
        push_manual_probe_recipe(&mut output, &plan);

        assert!(
            output.contains("sudo systemd-run --scope --unit zelynic-run-sleep"),
            "system scope recipe should use sudo systemd-run --scope"
        );
        assert!(
            output.contains("systemctl show zelynic-run-sleep.scope --property MainPID"),
            "system scope recipe inspect should use systemctl show without --user"
        );
        assert!(
            output.contains("sudo systemctl stop zelynic-run-sleep.scope"),
            "system scope recipe cleanup should use sudo systemctl stop"
        );
    }
}
