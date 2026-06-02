// SPDX-License-Identifier: GPL-3.0-only
use super::plan::{ScopeMode, SystemdRunPlan};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PidHandoffPlan {
    pub method: String,
    pub fallback: String,
    pub attach: String,
    pub discovery_commands: Vec<Vec<String>>,
    pub scope_unit_name: String,
    pub attach_target_cgroup: String,
}

pub(super) fn build_pid_handoff_plan(systemd_run: &SystemdRunPlan) -> PidHandoffPlan {
    let scope_name = format!("{}.scope", systemd_run.scope_unit_name);
    PidHandoffPlan {
        method: systemctl_show_method(systemd_run, &scope_name),
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

fn systemctl_show_method(plan: &SystemdRunPlan, scope_name: &str) -> String {
    match plan.scope_mode {
        ScopeMode::User => format!(
            "systemctl --user show {} --property MainPID,ControlGroup",
            scope_name
        ),
        ScopeMode::System => format!(
            "systemctl show {} --property MainPID,ControlGroup",
            scope_name
        ),
    }
}

fn systemctl_show_argv(plan: &SystemdRunPlan) -> Vec<String> {
    let mut argv = vec!["systemctl".to_string()];
    match plan.scope_mode {
        ScopeMode::User => {
            argv.push("--user".to_string());
            argv.push("show".to_string());
        }
        ScopeMode::System => {
            argv.push("show".to_string());
        }
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

#[allow(dead_code)]
pub(super) mod pid_discovery {
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

#[cfg(test)]
mod tests {
    use super::pid_discovery::{
        control_group_to_cgroup_procs_path, decide_pid_discovery, parse_systemctl_show_output,
        PidDiscoveryDecision,
    };
    use super::*;

    fn systemd_run_plan(scope_unit_name: &str) -> SystemdRunPlan {
        SystemdRunPlan {
            scope_unit_name: scope_unit_name.to_string(),
            description: "Zelynic target helium".to_string(),
            command_argv: vec!["helium".to_string()],
            scope_mode: ScopeMode::User,
            target: "helium".to_string(),
            attach_target_cgroup: "/sys/fs/cgroup/zelynic/target_helium".to_string(),
        }
    }

    #[test]
    fn pid_discovery_command_preview_uses_scope_unit() {
        let plan = build_pid_handoff_plan(&systemd_run_plan("zelynic-run-helium_browser"));

        assert_eq!(
            plan.discovery_commands[0],
            vec![
                "systemctl",
                "--user",
                "show",
                "zelynic-run-helium_browser.scope",
                "--property",
                "MainPID",
                "--property",
                "ControlGroup",
                "--value",
            ]
        );
    }

    #[test]
    fn pid_discovery_command_preview_can_use_system_scope() {
        let mut system_plan = systemd_run_plan("zelynic-run-helium_browser");
        system_plan.scope_mode = ScopeMode::System;
        let plan = build_pid_handoff_plan(&system_plan);

        assert_eq!(
            plan.discovery_commands[0],
            vec![
                "systemctl",
                "show",
                "zelynic-run-helium_browser.scope",
                "--property",
                "MainPID",
                "--property",
                "ControlGroup",
                "--value",
            ]
        );
        assert_eq!(
            plan.method,
            "systemctl show zelynic-run-helium_browser.scope --property MainPID,ControlGroup"
        );
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
