// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure data model for the launch / discover / attach contract.
//!
//! This module defines the design contract for future live run support.
//! It is data-only and pure logic: no Command execution, no filesystem mutation,
//! no systemd calls, no nftables/tc/cgroup mutation.
//!
//! The contract represents three sequential phases:
//!
//! 1. **Launch**: create a transient systemd scope (user or system).
//! 2. **Discover**: read ControlGroup from the scope unit, then read PIDs from cgroup.procs.
//! 3. **Attach**: move discovered PIDs into the Zelynic target cgroup and apply limits.
//!
//! Live execution is not implemented. This contract is a planning artifact.

use super::plan::ScopeMode;

/// A single step in the launch/discover/attach contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContractStep {
    /// Human-readable label for this step (e.g. "launch", "discover", "attach").
    pub phase: ContractPhase,
    /// Whether this step is currently implemented (always false).
    pub implemented: bool,
    /// Human-readable description of what this step would do.
    pub description: String,
    /// Privilege level required for this step.
    pub privilege: StepPrivilege,
    /// Scope mode this step targets.
    pub scope_mode: ScopeMode,
}

/// The three phases of the launch/discover/attach contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ContractPhase {
    Launch,
    Discover,
    Attach,
}

impl ContractPhase {
    pub(crate) fn label(self) -> &'static str {
        match self {
            ContractPhase::Launch => "launch",
            ContractPhase::Discover => "discover",
            ContractPhase::Attach => "attach",
        }
    }
}

/// Privilege requirements for a contract step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepPrivilege {
    /// No special privilege needed (user context).
    User,
    /// Root privilege required.
    Root,
}

impl StepPrivilege {
    pub(crate) fn label(self) -> &'static str {
        match self {
            StepPrivilege::User => "user",
            StepPrivilege::Root => "root",
        }
    }
}

/// Safety gate / blocker that prevents live execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SafetyGate {
    /// Human-readable reason why live execution is blocked.
    pub reason: String,
}

/// The full launch/discover/attach contract for a planned run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunContract {
    /// Ordered steps: launch, discover, attach.
    pub steps: Vec<ContractStep>,
    /// Safety gates preventing live execution.
    pub safety_gates: Vec<SafetyGate>,
    /// Whether live execution is implemented (always false).
    pub live_execution_implemented: bool,
}

/// Build the launch/discover/attach contract for the given scope mode.
pub(crate) fn build_run_contract(scope_mode: ScopeMode) -> RunContract {
    let launch_scope_arg = match scope_mode {
        ScopeMode::User => "--user --scope",
        ScopeMode::System => "--scope",
    };
    let discover_show = match scope_mode {
        ScopeMode::User => "systemctl --user show <unit> --property ControlGroup",
        ScopeMode::System => "systemctl show <unit> --property ControlGroup",
    };

    let steps = vec![
        ContractStep {
            phase: ContractPhase::Launch,
            implemented: false,
            description: format!(
                "create transient systemd scope via systemd-run {} --unit <unit> -- <command>",
                launch_scope_arg
            ),
            privilege: StepPrivilege::User,
            scope_mode,
        },
        ContractStep {
            phase: ContractPhase::Discover,
            implemented: false,
            description: format!(
                "read ControlGroup from '{}', then read PID(s) from /sys/fs/cgroup${{ControlGroup}}/cgroup.procs",
                discover_show
            ),
            privilege: StepPrivilege::User,
            scope_mode,
        },
        ContractStep {
            phase: ContractPhase::Attach,
            implemented: false,
            description: "move discovered PID(s) into Zelynic target cgroup and apply nftables + tc HTB limits".to_string(),
            privilege: StepPrivilege::Root,
            scope_mode,
        },
    ];

    let safety_gates = vec![
        SafetyGate {
            reason: "live execution is not implemented yet".to_string(),
        },
        SafetyGate {
            reason: format!(
                "attach step requires root; {}-scope launch runs in user context",
                scope_mode.label()
            ),
        },
    ];

    RunContract {
        steps,
        safety_gates,
        live_execution_implemented: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_scope_contract_has_user_launch_and_root_attach() {
        let contract = build_run_contract(ScopeMode::User);

        assert_eq!(contract.steps.len(), 3);
        assert_eq!(contract.steps[0].phase, ContractPhase::Launch);
        assert_eq!(contract.steps[0].privilege, StepPrivilege::User);
        assert_eq!(contract.steps[0].scope_mode, ScopeMode::User);
        assert!(!contract.steps[0].implemented);
        assert!(contract.steps[0].description.contains("--user --scope"));

        assert_eq!(contract.steps[1].phase, ContractPhase::Discover);
        assert_eq!(contract.steps[1].privilege, StepPrivilege::User);
        assert!(contract.steps[1]
            .description
            .contains("systemctl --user show"));
        assert!(contract.steps[1].description.contains("cgroup.procs"));

        assert_eq!(contract.steps[2].phase, ContractPhase::Attach);
        assert_eq!(contract.steps[2].privilege, StepPrivilege::Root);
        assert!(!contract.steps[2].implemented);
    }

    #[test]
    fn system_scope_contract_uses_system_scope_commands() {
        let contract = build_run_contract(ScopeMode::System);

        assert_eq!(contract.steps[0].scope_mode, ScopeMode::System);
        assert!(contract.steps[0].description.contains("--scope"));
        assert!(!contract.steps[0].description.contains("--user --scope"));

        assert!(contract.steps[1]
            .description
            .contains("systemctl show <unit>"));
        assert!(!contract.steps[1]
            .description
            .contains("systemctl --user show"));

        assert_eq!(contract.steps[2].privilege, StepPrivilege::Root);
    }

    #[test]
    fn discover_phase_is_control_group_first() {
        let contract = build_run_contract(ScopeMode::User);

        let discover = &contract.steps[1];
        assert_eq!(discover.phase, ContractPhase::Discover);
        // ControlGroup is read first, then cgroup.procs
        let desc = &discover.description;
        let cg_pos = desc.find("ControlGroup").unwrap();
        let procs_pos = desc.find("cgroup.procs").unwrap();
        assert!(
            cg_pos < procs_pos,
            "ControlGroup should be mentioned before cgroup.procs"
        );
    }

    #[test]
    fn main_pid_is_not_mentioned_in_contract_steps() {
        let contract = build_run_contract(ScopeMode::User);
        for step in &contract.steps {
            assert!(!step.description.contains("MainPID"));
        }
    }

    #[test]
    fn attach_requires_root() {
        let contract = build_run_contract(ScopeMode::User);
        assert_eq!(contract.steps[2].privilege, StepPrivilege::Root);

        let contract = build_run_contract(ScopeMode::System);
        assert_eq!(contract.steps[2].privilege, StepPrivilege::Root);
    }

    #[test]
    fn live_execution_implemented_is_always_false() {
        let contract_user = build_run_contract(ScopeMode::User);
        let contract_system = build_run_contract(ScopeMode::System);

        assert!(!contract_user.live_execution_implemented);
        assert!(!contract_system.live_execution_implemented);
    }

    #[test]
    fn contract_has_safety_gates() {
        let contract = build_run_contract(ScopeMode::User);

        assert!(!contract.safety_gates.is_empty());
        assert!(contract
            .safety_gates
            .iter()
            .any(|g| g.reason.contains("not implemented")));
        assert!(contract
            .safety_gates
            .iter()
            .any(|g| g.reason.contains("requires root")));
    }

    #[test]
    fn contract_does_not_require_mutation_or_execution_side_effects() {
        let contract = build_run_contract(ScopeMode::User);

        // The contract is pure data — just strings and enums.
        // Verify no fn pointers, no trait objects, no Command.
        assert_eq!(contract.steps.len(), 3);
        for step in &contract.steps {
            let _ = step.phase.label();
            let _ = step.privilege.label();
            let _ = &step.description;
            let _ = step.implemented;
            let _ = step.scope_mode;
        }
    }

    #[test]
    fn system_scope_contract_safety_gate_mentions_system_scope() {
        let contract = build_run_contract(ScopeMode::System);
        assert!(contract
            .safety_gates
            .iter()
            .any(|g| g.reason.contains("system-scope")));
    }

    #[test]
    fn all_steps_are_marked_not_implemented() {
        let contract = build_run_contract(ScopeMode::User);
        for step in &contract.steps {
            assert!(!step.implemented);
        }
    }
}
