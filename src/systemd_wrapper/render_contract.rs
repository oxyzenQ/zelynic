// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use super::contract::build_run_contract;
use super::plan::ScopeMode;
use super::render::push_line;

pub(super) fn push_contract_section(output: &mut String, scope_mode: &ScopeMode) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd_wrapper::ScopeMode;

    #[test]
    fn contract_section_present_and_not_implemented() {
        let mut output = String::new();
        push_contract_section(&mut output, &ScopeMode::User);

        assert!(output.contains("Future launch/discover/attach contract:"));
        assert!(output.contains("1. launch: [not implemented]"));
        assert!(output.contains("2. discover: [not implemented]"));
        assert!(output.contains("3. attach: [not implemented]"));
        assert!(output.contains("live execution implemented: false"));
        assert!(output.contains("privilege: user manager"));
        assert!(output.contains("privilege: root"));
    }

    #[test]
    fn contract_user_scope_uses_user_scope_launch_command() {
        let mut output = String::new();
        push_contract_section(&mut output, &ScopeMode::User);

        assert!(output.contains("--user --scope"));
        assert!(output.contains("systemctl --user show"));
    }

    #[test]
    fn contract_system_scope_uses_system_scope_launch_command() {
        let mut output = String::new();
        push_contract_section(&mut output, &ScopeMode::System);

        assert!(output.contains("--scope"));
        assert!(!output.contains("create transient systemd scope via systemd-run --user --scope"));
        assert!(output.contains("systemctl show <unit> --property ControlGroup"));
        // System scope launch must show system manager privilege, not user
        assert!(output.contains("privilege: system manager / root-or-polkit"));
        // System scope launch line must NOT say "privilege: user manager"
        let launch_line = output
            .lines()
            .find(|l| l.contains("1. launch:"))
            .expect("should have a launch line");
        assert!(!launch_line.contains("privilege: user manager"));
    }

    #[test]
    fn contract_system_scope_discover_privilege_is_system_manager() {
        let mut output = String::new();
        push_contract_section(&mut output, &ScopeMode::System);

        let discover_line = output
            .lines()
            .find(|l| l.contains("2. discover:"))
            .expect("should have a discover line");
        assert!(
            !discover_line.contains("privilege: user manager"),
            "system scope discover must not show user manager privilege"
        );
        assert!(
            discover_line.contains("privilege: system manager / root-or-polkit"),
            "system scope discover should show system manager privilege"
        );
    }

    #[test]
    fn contract_user_scope_discover_privilege_is_user_manager() {
        let mut output = String::new();
        push_contract_section(&mut output, &ScopeMode::User);

        let discover_line = output
            .lines()
            .find(|l| l.contains("2. discover:"))
            .expect("should have a discover line");
        assert!(
            discover_line.contains("privilege: user manager"),
            "user scope discover should show user manager privilege"
        );
    }

    #[test]
    fn contract_attach_step_requires_root() {
        let mut output = String::new();
        push_contract_section(&mut output, &ScopeMode::User);

        // The attach step line should have "privilege: root"
        assert!(output.contains("privilege: root"));
    }
}
