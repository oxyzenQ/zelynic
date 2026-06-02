// SPDX-License-Identifier: GPL-3.0-only
use super::plan::ScopeMode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutionPreflight {
    pub scope_mode: ScopeMode,
    pub launch: String,
    pub attach: String,
    pub readiness: ExecutionReadiness,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExecutionReadiness {
    Blocked,
    FutureCapable,
}

impl ExecutionReadiness {
    pub(super) fn label(self) -> &'static str {
        match self {
            ExecutionReadiness::Blocked => "blocked",
            ExecutionReadiness::FutureCapable => "future-capable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ExecutionPreflightInput {
    pub scope_mode: ScopeMode,
    pub is_root: bool,
}

pub(super) fn current_execution_preflight(scope_mode: ScopeMode) -> ExecutionPreflight {
    evaluate_execution_preflight(ExecutionPreflightInput {
        scope_mode,
        is_root: nix::unistd::geteuid().is_root(),
    })
}

pub(super) fn evaluate_execution_preflight(input: ExecutionPreflightInput) -> ExecutionPreflight {
    match (input.scope_mode, input.is_root) {
        (ScopeMode::User, false) => ExecutionPreflight {
            scope_mode: input.scope_mode,
            launch: "user scope preview".to_string(),
            attach: "requires root".to_string(),
            readiness: ExecutionReadiness::Blocked,
            reason: "User-scope launch is available, but applying limits requires root. Live run is not implemented until privilege handoff is designed.".to_string(),
        },
        (ScopeMode::User, true) => ExecutionPreflight {
            scope_mode: input.scope_mode,
            launch: "requires explicit target user/session context".to_string(),
            attach: "root available".to_string(),
            readiness: ExecutionReadiness::Blocked,
            reason: "Root can attach limits, but user-scope launch needs an explicit target user/session context.".to_string(),
        },
        (ScopeMode::System, false) => ExecutionPreflight {
            scope_mode: input.scope_mode,
            launch: "system scope requires root".to_string(),
            attach: "requires root".to_string(),
            readiness: ExecutionReadiness::Blocked,
            reason: "System scope requires root; refusing to trigger Polkit prompts.".to_string(),
        },
        (ScopeMode::System, true) => ExecutionPreflight {
            scope_mode: input.scope_mode,
            launch: "system scope preview as root".to_string(),
            attach: "root available".to_string(),
            readiness: ExecutionReadiness::FutureCapable,
            reason: "System scope can be attempted by root in a future implementation.".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preflight(scope_mode: ScopeMode, is_root: bool) -> ExecutionPreflight {
        evaluate_execution_preflight(ExecutionPreflightInput {
            scope_mode,
            is_root,
        })
    }

    #[test]
    fn user_scope_non_root_is_blocked_because_attach_requires_root() {
        let result = preflight(ScopeMode::User, false);

        assert_eq!(result.readiness, ExecutionReadiness::Blocked);
        assert_eq!(result.launch, "user scope preview");
        assert_eq!(result.attach, "requires root");
        assert!(result.reason.contains("applying limits requires root"));
    }

    #[test]
    fn user_scope_root_is_blocked_until_user_session_context_is_explicit() {
        let result = preflight(ScopeMode::User, true);

        assert_eq!(result.readiness, ExecutionReadiness::Blocked);
        assert_eq!(
            result.launch,
            "requires explicit target user/session context"
        );
        assert_eq!(result.attach, "root available");
        assert!(result
            .reason
            .contains("explicit target user/session context"));
    }

    #[test]
    fn system_scope_non_root_is_blocked_to_avoid_polkit() {
        let result = preflight(ScopeMode::System, false);

        assert_eq!(result.readiness, ExecutionReadiness::Blocked);
        assert_eq!(result.launch, "system scope requires root");
        assert_eq!(result.attach, "requires root");
        assert_eq!(
            result.reason,
            "System scope requires root; refusing to trigger Polkit prompts."
        );
    }

    #[test]
    fn system_scope_root_is_future_capable_but_not_live() {
        let result = preflight(ScopeMode::System, true);

        assert_eq!(result.readiness, ExecutionReadiness::FutureCapable);
        assert_eq!(result.launch, "system scope preview as root");
        assert_eq!(result.attach, "root available");
        assert_eq!(
            result.reason,
            "System scope can be attempted by root in a future implementation."
        );
    }
}
