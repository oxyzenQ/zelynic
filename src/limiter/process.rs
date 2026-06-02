// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;

/// Get the UID of a process.
pub(super) fn get_process_uid(pid: u32) -> Option<u32> {
    let uid_path = format!("/proc/{}/status", pid);
    if let Ok(content) = fs::read_to_string(&uid_path) {
        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() > 1 {
                    return parts[1].parse::<u32>().ok();
                }
            }
        }
    }
    None
}
/// Resolve all PIDs of a process tree (parent + all descendants).
///
/// This is critical for multi-process applications like browsers (Brave, Chrome, Firefox)
/// which spawn many child processes (renderers, GPU, network service, sandbox, etc.).
/// Only the processes that actually do network I/O need to be in the cgroup, but
/// to be safe we move the entire tree.
#[allow(dead_code)]
pub fn resolve_process_tree(root_pids: &[u32]) -> Vec<u32> {
    let mut all_pids = Vec::new();
    let mut queue: std::collections::VecDeque<u32> = root_pids.iter().copied().collect();

    while let Some(pid) = queue.pop_front() {
        if all_pids.contains(&pid) {
            continue;
        }
        all_pids.push(pid);

        // Find children by scanning /proc for processes whose ppid matches
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name_str = entry.file_name().to_string_lossy().to_string();
                if !name_str.chars().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                let child_pid: u32 = match name_str.parse() {
                    Ok(p) => p,
                    Err(_) => continue,
                };

                // Read stat to get ppid (format: pid (comm) state ppid ...)
                let stat_path = format!("/proc/{}/stat", child_pid);
                if let Ok(stat_content) = fs::read_to_string(&stat_path) {
                    // The comm field can contain spaces and parentheses, so find
                    // the last ')' and parse from there
                    if let Some(close_paren) = stat_content.rfind(')') {
                        let after_comm = &stat_content[close_paren + 2..];
                        let fields: Vec<&str> = after_comm.split_whitespace().collect();
                        // ppid is the first field after ') state'
                        if fields.len() >= 2 {
                            if let Ok(ppid) = fields[1].parse::<u32>() {
                                if ppid == pid && !all_pids.contains(&child_pid) {
                                    queue.push_back(child_pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    all_pids
}

/// Sanitize a target name for use as a cgroup directory name.
///
/// Rules: lowercase, replace non-alphanumeric chars with underscore, max 64 chars.
pub(super) fn sanitize_target_name(target: &str) -> String {
    let sanitized: String = target
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    // Truncate to max 64 characters
    sanitized.chars().take(64).collect()
}
pub(super) fn is_chromium_based_target(target: &str) -> bool {
    let target = target.to_lowercase();
    target.contains("brave") || target.contains("chrome") || target.contains("chromium")
}
/// Why a process was selected by the target resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessMatchReason {
    NumericPid,
    CommExact,
    ExeBasename,
    Argv0Basename,
}

impl fmt::Display for ProcessMatchReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NumericPid => f.write_str("numeric pid"),
            Self::CommExact => f.write_str("comm"),
            Self::ExeBasename => f.write_str("exe basename"),
            Self::Argv0Basename => f.write_str("argv0 basename"),
        }
    }
}

/// A PID selected by the target resolver, including the selected field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPid {
    pub pid: u32,
    pub reason: ProcessMatchReason,
    pub matched: String,
}

fn parse_numeric_pid_target(target: &str) -> Option<u32> {
    if target.is_empty() || !target.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    target.parse().ok()
}

fn basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

fn normalize_process_name(value: &str) -> String {
    basename(value).trim().to_lowercase()
}

fn safe_process_name_match(target: &str, candidate: &str) -> bool {
    let target = normalize_process_name(target);
    let candidate = normalize_process_name(candidate);

    if target.is_empty() || candidate.is_empty() {
        return false;
    }

    if candidate == target {
        return true;
    }

    candidate
        .strip_prefix(&target)
        .and_then(|suffix| suffix.chars().next())
        .is_some_and(|c| matches!(c, '-' | '_' | '.'))
}

fn is_wrapper_process_name(candidate: &str) -> bool {
    matches!(
        normalize_process_name(candidate).as_str(),
        "zelynic"
            | "sudo"
            | "doas"
            | "su"
            | "bash"
            | "zsh"
            | "fish"
            | "sh"
            | "dash"
            | "alacritty"
            | "alacritty-msg"
            | "gnome-terminal"
            | "gnome-terminal-server"
            | "konsole"
            | "kitty"
            | "wezterm"
            | "foot"
            | "tilix"
            | "xterm"
            | "rxvt"
            | "urxvt"
            | "tmux"
            | "screen"
    )
}

fn read_cmdline_argv(pid: u32) -> Vec<String> {
    fs::read(format!("/proc/{}/cmdline", pid))
        .ok()
        .map(|bytes| {
            bytes
                .split(|b| *b == 0)
                .filter(|arg| !arg.is_empty())
                .map(|arg| String::from_utf8_lossy(arg).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn match_process_fields(
    pid: u32,
    target: &str,
    comm: Option<&str>,
    exe_basename: Option<&str>,
    argv0: Option<&str>,
) -> Option<ResolvedPid> {
    if pid == std::process::id() {
        return None;
    }

    if let Some(comm) = comm.map(str::trim) {
        if safe_process_name_match(target, comm) && !is_wrapper_process_name(comm) {
            return Some(ResolvedPid {
                pid,
                reason: ProcessMatchReason::CommExact,
                matched: comm.to_string(),
            });
        }
    }

    if let Some(exe) = exe_basename {
        if safe_process_name_match(target, exe) && !is_wrapper_process_name(exe) {
            return Some(ResolvedPid {
                pid,
                reason: ProcessMatchReason::ExeBasename,
                matched: exe.to_string(),
            });
        }
    }

    if let Some(argv0) = argv0 {
        let argv0_base = basename(argv0);
        if safe_process_name_match(target, argv0_base) && !is_wrapper_process_name(argv0_base) {
            return Some(ResolvedPid {
                pid,
                reason: ProcessMatchReason::Argv0Basename,
                matched: argv0_base.to_string(),
            });
        }
    }

    None
}

/// Resolve a target string (process name or PID) to running PIDs with match reasons.
pub fn resolve_pids_detailed(target: &str) -> Result<Vec<ResolvedPid>> {
    if let Some(pid) = parse_numeric_pid_target(target) {
        if Path::new(&format!("/proc/{}", pid)).exists() {
            return Ok(vec![ResolvedPid {
                pid,
                reason: ProcessMatchReason::NumericPid,
                matched: pid.to_string(),
            }]);
        } else {
            bail!("process with PID {} not found", pid);
        }
    }

    let mut pids = Vec::new();
    let mut seen = HashSet::new();
    let proc_dir = Path::new("/proc");
    let target_lower = target.to_lowercase();

    for entry in fs::read_dir(proc_dir).context("failed to read /proc directory")? {
        let entry = entry?;
        let dir_name = entry.file_name();
        let name_str = dir_name.to_string_lossy();

        if name_str.chars().all(|c| c.is_ascii_digit()) {
            let pid: u32 = match name_str.parse() {
                Ok(p) => p,
                Err(_) => continue,
            };

            let comm = fs::read_to_string(format!("/proc/{}/comm", pid)).ok();
            let exe = fs::read_link(format!("/proc/{}/exe", pid)).ok();
            let exe_basename = exe
                .as_ref()
                .and_then(|path| path.file_name())
                .map(|name| name.to_string_lossy().into_owned());
            let argv = read_cmdline_argv(pid);
            let argv0 = argv.first().map(String::as_str);

            if let Some(resolved) = match_process_fields(
                pid,
                &target_lower,
                comm.as_deref(),
                exe_basename.as_deref(),
                argv0,
            ) {
                if seen.insert(pid) {
                    pids.push(resolved);
                }
            }
        }
    }

    if pids.is_empty() {
        bail!(
            "no running process found matching '{}'.\n  {} Use 'ps aux' to list running processes.",
            target,
            "Hint:".yellow()
        );
    }

    pids.sort_by_key(|resolved| resolved.pid);
    Ok(pids)
}

/// Resolve a target string (process name or PID) to actual running PIDs.
pub fn resolve_pids(target: &str) -> Result<Vec<u32>> {
    Ok(resolve_pids_detailed(target)?
        .into_iter()
        .map(|resolved| resolved.pid)
        .collect())
}

/// Get the process name for a given PID.
pub fn get_process_name(pid: u32) -> String {
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(name) = fs::read_to_string(&comm_path) {
        name.trim().to_string()
    } else {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        if let Ok(cmdline) = fs::read_to_string(&cmdline_path) {
            cmdline
                .split('\0')
                .next()
                .unwrap_or("")
                .rsplit('/')
                .next()
                .unwrap_or("[unknown]")
                .to_string()
        } else {
            "[unknown]".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_target_matches_comm_exact() {
        let resolved = match_process_fields(1000, "brave", Some("brave"), None, None).unwrap();

        assert_eq!(resolved.pid, 1000);
        assert_eq!(resolved.reason, ProcessMatchReason::CommExact);
        assert_eq!(resolved.matched, "brave");
    }

    #[test]
    fn process_target_matches_safe_exe_alias() {
        let resolved =
            match_process_fields(1000, "brave", None, Some("brave-browser"), None).unwrap();

        assert_eq!(resolved.reason, ProcessMatchReason::ExeBasename);
        assert_eq!(resolved.matched, "brave-browser");
    }

    #[test]
    fn process_target_matches_safe_argv0_alias() {
        let resolved = match_process_fields(
            1000,
            "brave",
            None,
            None,
            Some("/usr/bin/brave-browser-stable"),
        )
        .unwrap();

        assert_eq!(resolved.reason, ProcessMatchReason::Argv0Basename);
        assert_eq!(resolved.matched, "brave-browser-stable");
    }

    #[test]
    fn process_target_ignores_shell_cmdline_argument() {
        let resolved = match_process_fields(
            1000,
            "brave",
            Some("bash"),
            Some("bash"),
            Some("/usr/bin/bash"),
        );

        assert!(resolved.is_none());
    }

    #[test]
    fn process_target_ignores_terminal_cmdline_argument() {
        let resolved = match_process_fields(
            1000,
            "brave",
            Some("Alacritty"),
            Some("alacritty"),
            Some("/usr/bin/alacritty"),
        );

        assert!(resolved.is_none());
    }

    #[test]
    fn process_target_ignores_zelynic_itself() {
        let resolved = match_process_fields(
            std::process::id(),
            "zelynic",
            Some("zelynic"),
            Some("zelynic"),
            Some("target/debug/zelynic"),
        );

        assert!(resolved.is_none());
    }

    #[test]
    fn numeric_pid_target_is_exact() {
        let current_pid = std::process::id();
        let resolved = resolve_pids_detailed(&current_pid.to_string()).unwrap();

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].pid, current_pid);
        assert_eq!(resolved[0].reason, ProcessMatchReason::NumericPid);
    }

    #[test]
    fn process_target_substring_matching_is_conservative() {
        assert!(safe_process_name_match("brave", "brave"));
        assert!(safe_process_name_match("brave", "brave-browser"));
        assert!(safe_process_name_match("brave", "brave_browser"));
        assert!(!safe_process_name_match("brave", "bravery"));
        assert!(!safe_process_name_match("brave", "xbrave"));
        assert!(!safe_process_name_match("ave", "brave"));
    }
}
