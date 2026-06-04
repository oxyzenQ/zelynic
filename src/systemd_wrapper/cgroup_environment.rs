// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Cgroup Environment: pure parser/model for future read-only cgroup
//! diagnostics before any move-only attach experiment.
//!
//! This module parses sample mountinfo text and renders diagnostics. It does
//! not read live files, create directories, write cgroup.procs, move PIDs, call
//! nftables/tc, write Zelynic state, or execute commands.

use super::render::push_line;

const EXPECTED_CGROUP2_MOUNT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CgroupEnvironmentDiagnostics {
    pub status: String,
    pub cgroup2_mount: Option<String>,
    pub mount_mode: MountMode,
    pub mount_status: Cgroup2MountStatus,
    pub target_namespace_exists: EnvironmentFactStatus,
    pub target_cgroup_exists: EnvironmentFactStatus,
    pub cgroup_procs_writes: String,
    pub execution: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MountMode {
    ReadWrite,
    ReadOnly,
    Unknown,
}

impl MountMode {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::ReadWrite => "read-write",
            Self::ReadOnly => "read-only",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Cgroup2MountStatus {
    Expected,
    UnexpectedPath,
    Missing,
    NotChecked,
}

impl Cgroup2MountStatus {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Expected => "expected",
            Self::UnexpectedPath => "unexpected path",
            Self::Missing => "missing",
            Self::NotChecked => "not checked",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvironmentFactStatus {
    NotChecked,
}

impl EnvironmentFactStatus {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::NotChecked => "not checked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cgroup2MountFacts {
    pub mount_path: Option<String>,
    pub mount_mode: MountMode,
    pub status: Cgroup2MountStatus,
}

pub(crate) fn parse_cgroup2_mountinfo(input: &str) -> Cgroup2MountFacts {
    for line in input.lines() {
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let left_fields = left.split_whitespace().collect::<Vec<_>>();
        let right_fields = right.split_whitespace().collect::<Vec<_>>();

        if right_fields.first() != Some(&"cgroup2") {
            continue;
        }

        let Some(mount_path) = left_fields.get(4) else {
            continue;
        };
        let mount_options = left_fields.get(5).copied().unwrap_or("");
        let mount_mode = parse_mount_mode(mount_options);
        let status = if *mount_path == EXPECTED_CGROUP2_MOUNT {
            Cgroup2MountStatus::Expected
        } else {
            Cgroup2MountStatus::UnexpectedPath
        };

        return Cgroup2MountFacts {
            mount_path: Some((*mount_path).to_string()),
            mount_mode,
            status,
        };
    }

    Cgroup2MountFacts {
        mount_path: None,
        mount_mode: MountMode::Unknown,
        status: Cgroup2MountStatus::Missing,
    }
}

pub(crate) fn build_cgroup_environment_diagnostics(
    mountinfo: Option<&str>,
) -> CgroupEnvironmentDiagnostics {
    let mount_facts = mountinfo.map(parse_cgroup2_mountinfo);
    let (cgroup2_mount, mount_mode, mount_status) = match mount_facts {
        Some(facts) => (facts.mount_path, facts.mount_mode, facts.status),
        None => (None, MountMode::Unknown, Cgroup2MountStatus::NotChecked),
    };

    CgroupEnvironmentDiagnostics {
        status: "model/read-only diagnostics; no mutation".to_string(),
        cgroup2_mount,
        mount_mode,
        mount_status,
        target_namespace_exists: EnvironmentFactStatus::NotChecked,
        target_cgroup_exists: EnvironmentFactStatus::NotChecked,
        cgroup_procs_writes: "blocked".to_string(),
        execution: "blocked".to_string(),
    }
}

pub(crate) fn render_cgroup_environment_diagnostics_section(
    output: &mut String,
    diagnostics: &CgroupEnvironmentDiagnostics,
) {
    push_line(output, "");
    push_line(output, "        Cgroup environment diagnostics:");
    push_line(output, &format!("          status: {}", diagnostics.status));
    push_line(
        output,
        &format!(
            "          cgroup v2 mount: {}",
            diagnostics
                .cgroup2_mount
                .as_deref()
                .unwrap_or("not checked")
        ),
    );
    push_line(
        output,
        &format!("          mount mode: {}", diagnostics.mount_mode.label()),
    );
    push_line(
        output,
        &format!(
            "          mount status: {}",
            diagnostics.mount_status.label()
        ),
    );
    push_line(
        output,
        &format!(
            "          target namespace exists: {}",
            diagnostics.target_namespace_exists.label()
        ),
    );
    push_line(
        output,
        &format!(
            "          target cgroup exists: {}",
            diagnostics.target_cgroup_exists.label()
        ),
    );
    push_line(
        output,
        &format!(
            "          cgroup.procs writes: {}",
            diagnostics.cgroup_procs_writes
        ),
    );
    push_line(
        output,
        &format!("          execution: {}", diagnostics.execution),
    );
}

fn parse_mount_mode(options: &str) -> MountMode {
    if options.split(',').any(|option| option == "ro") {
        MountMode::ReadOnly
    } else if options.split(',').any(|option| option == "rw") {
        MountMode::ReadWrite
    } else {
        MountMode::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW_MOUNTINFO: &str =
        "26 22 0:24 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n";
    const RO_MOUNTINFO: &str =
        "26 22 0:24 / /sys/fs/cgroup ro,nosuid,nodev,noexec,relatime - cgroup2 cgroup ro\n";
    const UNEXPECTED_MOUNTINFO: &str =
        "26 22 0:24 / /host/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup rw\n";
    const NO_CGROUP2_MOUNTINFO: &str =
        "24 22 0:22 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";

    #[test]
    fn parses_cgroup2_mount_path_from_sample_mountinfo() {
        let facts = parse_cgroup2_mountinfo(RW_MOUNTINFO);

        assert_eq!(facts.mount_path.as_deref(), Some("/sys/fs/cgroup"));
        assert_eq!(facts.status, Cgroup2MountStatus::Expected);
    }

    #[test]
    fn detects_read_write_mount() {
        let facts = parse_cgroup2_mountinfo(RW_MOUNTINFO);

        assert_eq!(facts.mount_mode, MountMode::ReadWrite);
    }

    #[test]
    fn detects_read_only_mount() {
        let facts = parse_cgroup2_mountinfo(RO_MOUNTINFO);

        assert_eq!(facts.mount_mode, MountMode::ReadOnly);
    }

    #[test]
    fn missing_cgroup2_mount_is_reported() {
        let facts = parse_cgroup2_mountinfo(NO_CGROUP2_MOUNTINFO);

        assert_eq!(facts.mount_path, None);
        assert_eq!(facts.status, Cgroup2MountStatus::Missing);
    }

    #[test]
    fn unexpected_mount_path_is_reported() {
        let facts = parse_cgroup2_mountinfo(UNEXPECTED_MOUNTINFO);

        assert_eq!(facts.mount_path.as_deref(), Some("/host/cgroup"));
        assert_eq!(facts.status, Cgroup2MountStatus::UnexpectedPath);
    }

    #[test]
    fn output_says_read_only_diagnostics_no_mutation() {
        let diagnostics = build_cgroup_environment_diagnostics(Some(RW_MOUNTINFO));
        let mut output = String::new();

        render_cgroup_environment_diagnostics_section(&mut output, &diagnostics);

        assert!(output.contains("status: model/read-only diagnostics; no mutation"));
    }

    #[test]
    fn output_says_cgroup_procs_writes_blocked() {
        let diagnostics = build_cgroup_environment_diagnostics(None);
        let mut output = String::new();

        render_cgroup_environment_diagnostics_section(&mut output, &diagnostics);

        assert!(output.contains("cgroup.procs writes: blocked"));
    }

    #[test]
    fn output_says_execution_blocked() {
        let diagnostics = build_cgroup_environment_diagnostics(None);
        let mut output = String::new();

        render_cgroup_environment_diagnostics_section(&mut output, &diagnostics);

        assert!(output.contains("execution: blocked"));
    }

    #[test]
    fn output_does_not_claim_created_moved_attached_limited_or_enforced() {
        let diagnostics = build_cgroup_environment_diagnostics(None);
        let mut output = String::new();

        render_cgroup_environment_diagnostics_section(&mut output, &diagnostics);

        assert!(!output.contains("created"));
        assert!(!output.contains("moved"));
        assert!(!output.contains("attached"));
        assert!(!output.contains("limited"));
        assert!(!output.contains("enforced"));
    }
}
