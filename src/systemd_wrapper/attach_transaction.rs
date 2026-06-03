// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Attach Transaction: pure data model for a future live attach mutation sequence.
//!
//! This module defines the steps and rollback boundaries for future attach
//! execution. It is a model only and does not perform any mutations.

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttachTransactionPlan {
    pub status: String,
    pub steps: Vec<String>,
    pub rollback: Vec<String>,
    pub execution: String,
}

pub(crate) fn build_attach_transaction_plan() -> AttachTransactionPlan {
    AttachTransactionPlan {
        status: "model only; not executed".to_string(),
        steps: vec![
            "1. verify preflight snapshot is still fresh".to_string(),
            "2. create/prepare Zelynic target cgroup".to_string(),
            "3. confirm original cgroup capture for each PID".to_string(),
            "4. move validated PID(s) into target cgroup".to_string(),
            "5. install nftables/tc state owned by this operation".to_string(),
            "6. persist Zelynic state owned by this operation".to_string(),
        ],
        rollback: vec![
            "1. restore PID(s) to captured original cgroup path".to_string(),
            "2. remove tc/nftables state created by this operation".to_string(),
            "3. remove Zelynic state created by this operation".to_string(),
            "4. remove target cgroup only if safe and empty".to_string(),
        ],
        execution: "blocked".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_plan_is_pure_and_says_model_only() {
        let plan = build_attach_transaction_plan();
        assert_eq!(plan.status, "model only; not executed");
        assert_eq!(plan.execution, "blocked");
    }

    #[test]
    fn transaction_plan_includes_ordered_attach_steps() {
        let plan = build_attach_transaction_plan();
        let steps = plan.steps.join("\n");
        assert!(steps.contains("1. verify preflight"));
        assert!(steps.contains("2. create/prepare Zelynic target cgroup"));
        assert!(steps.contains("3. confirm original cgroup capture"));
        assert!(steps.contains("4. move validated PID(s)"));
        assert!(steps.contains("5. install nftables/tc state"));
        assert!(steps.contains("6. persist Zelynic state"));
    }

    #[test]
    fn rollback_plan_includes_reverse_cleanup_steps() {
        let plan = build_attach_transaction_plan();
        let rollback = plan.rollback.join("\n");
        assert!(rollback.contains("1. restore PID(s)"));
        assert!(rollback.contains("2. remove tc/nftables state"));
        assert!(rollback.contains("3. remove Zelynic state"));
        assert!(rollback.contains("4. remove target cgroup"));
    }

    #[test]
    fn plan_includes_ownership_labels() {
        let plan = build_attach_transaction_plan();
        let steps = plan.steps.join("\n");
        let rollback = plan.rollback.join("\n");

        assert!(steps.contains("owned by this operation"));
        assert!(rollback.contains("created by this operation"));
    }
}
