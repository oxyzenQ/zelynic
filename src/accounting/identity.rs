// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Pure App Identity model for v3.1 phase 2 (App Identity + Network Ledger).
//!
//! This module provides a pure Rust data model for app/target identity
//! attribution. No live filesystem reads, no process scanning, no PID movement,
//! no cgroup mutation, no nft/tc mutation, no network blocking, no quota
//! enforcement, no eBPF, no persistence. All types are serializable via serde
//! for future JSON report integration.
//!
//! # Safety
//!
//! - No live `/proc` reads.
//! - No live sysfs reads.
//! - No CLI command is exposed.
//! - No enforcement, blocking, or state mutation.
//! - No filesystem writes.
//! - No PID movement.
//! - No cgroup mutation.
//!
//! # Honesty
//!
//! - All identity fields are optional/best-effort.
//! - Attribution scope makes honesty explicit (InterfaceOnly, ProcessBestEffort,
//!   CgroupBestEffort, etc.).
//! - Identity honesty flags are constant: `attribution_is_best_effort = true`,
//!   `enforcement_active = false`, `persistence_performed = false`.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::fmt;

/// Attribution scope for a resolved usage target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UsageAttributionScope {
    InterfaceOnly,
    ProcessBestEffort,
    CgroupBestEffort,
    TargetBestEffort,
    Unknown,
}

impl fmt::Display for UsageAttributionScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsageAttributionScope::InterfaceOnly => write!(f, "interface_only"),
            UsageAttributionScope::ProcessBestEffort => write!(f, "process_best_effort"),
            UsageAttributionScope::CgroupBestEffort => write!(f, "cgroup_best_effort"),
            UsageAttributionScope::TargetBestEffort => write!(f, "target_best_effort"),
            UsageAttributionScope::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub argv0: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable_path: Option<String>,
}

impl ProcessIdentity {
    pub fn empty() -> Self {
        Self {
            pid: None,
            comm: None,
            argv0: None,
            cmdline: None,
            executable_path: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pid.is_none()
            && self.comm.is_none()
            && self.argv0.is_none()
            && self.cmdline.is_none()
            && self.executable_path.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CgroupIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub systemd_scope: Option<String>,
}

impl CgroupIdentity {
    pub fn empty() -> Self {
        Self {
            cgroup_path: None,
            systemd_unit: None,
            systemd_scope: None,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cgroup_path.is_none() && self.systemd_unit.is_none() && self.systemd_scope.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InterfaceIdentity {
    pub name: String,
    pub loopback: bool,
}

impl InterfaceIdentity {
    pub fn new(name: &str, loopback: bool) -> Self {
        Self {
            name: name.to_string(),
            loopback,
        }
    }

    pub fn is_loopback_name(name: &str) -> bool {
        name == "lo"
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TargetIdentity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<CgroupIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<InterfaceIdentity>,
}

impl TargetIdentity {
    pub fn empty() -> Self {
        Self {
            process: None,
            cgroup: None,
            interface: None,
        }
    }

    pub fn interface_only(name: &str, loopback: bool) -> Self {
        Self {
            process: None,
            cgroup: None,
            interface: Some(InterfaceIdentity::new(name, loopback)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.process.is_none() && self.cgroup.is_none() && self.interface.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvedUsageTarget {
    pub identity: TargetIdentity,
    pub attribution_scope: UsageAttributionScope,
}

impl ResolvedUsageTarget {
    pub fn new(identity: TargetIdentity, attribution_scope: UsageAttributionScope) -> Self {
        Self {
            identity,
            attribution_scope,
        }
    }

    pub fn unknown() -> Self {
        Self {
            identity: TargetIdentity::empty(),
            attribution_scope: UsageAttributionScope::Unknown,
        }
    }

    pub fn interface_only(name: &str, loopback: bool) -> Self {
        Self {
            identity: TargetIdentity::interface_only(name, loopback),
            attribution_scope: UsageAttributionScope::InterfaceOnly,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityHonesty {
    pub attribution_is_best_effort: bool,
    pub interface_level_data_source: bool,
    pub per_app_attribution_may_be_partial: bool,
    pub enforcement_active: bool,
    pub persistence_performed: bool,
}

pub fn default_identity_honesty() -> IdentityHonesty {
    IdentityHonesty {
        attribution_is_best_effort: true,
        interface_level_data_source: true,
        per_app_attribution_may_be_partial: true,
        enforcement_active: false,
        persistence_performed: false,
    }
}

pub fn render_resolved_target(target: &ResolvedUsageTarget) -> String {
    let mut lines: Vec<String> = Vec::new();

    lines.push(format!("Attribution scope: {}", target.attribution_scope));

    let id = &target.identity;
    if let Some(ref iface) = id.interface {
        let loopback_str = if iface.loopback { " (loopback)" } else { "" };
        lines.push(format!("Interface: {}{}", iface.name, loopback_str));
    }
    if let Some(ref proc) = id.process {
        if let Some(pid) = proc.pid {
            lines.push(format!("PID: {} (best-effort: PIDs are recycled)", pid));
        }
        if let Some(ref comm) = proc.comm {
            lines.push(format!("Comm: {}", comm));
        }
        if let Some(ref argv0) = proc.argv0 {
            lines.push(format!("Argv0: {} (may differ from comm)", argv0));
        }
        if let Some(ref path) = proc.executable_path {
            lines.push(format!("Executable: {}", path));
        }
    }
    if let Some(ref cg) = id.cgroup {
        if let Some(ref path) = cg.cgroup_path {
            lines.push(format!("Cgroup: {}", path));
        }
        if let Some(ref unit) = cg.systemd_unit {
            lines.push(format!("Systemd unit: {} (best-effort)", unit));
        }
        if let Some(ref scope) = cg.systemd_scope {
            lines.push(format!("Systemd scope: {}", scope));
        }
    }

    lines.push(String::new());
    lines.push("Identity attribution is best-effort.".to_string());
    lines.push("No enforcement, no persistence, no mutation.".to_string());

    lines.join("\n")
}

pub fn serialize_identity_json(target: &ResolvedUsageTarget) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(target)
}

pub fn deserialize_identity_json(json_str: &str) -> Result<ResolvedUsageTarget, serde_json::Error> {
    serde_json::from_str(json_str)
}

pub fn serialize_identity_honesty(honesty: &IdentityHonesty) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(honesty)
}
