// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//!
//! Original cgroup capture preview for future Scope Runner rollback planning.
//!
//! This module is pure: it parses sample cgroup text and builds preview data.
//! It does not read `/proc`, write cgroups, call nftables/tc, write Zelynic
//! state, or call the limiter attach execution path.

#![allow(dead_code)]

const CGROUP_FS_ROOT: &str = "/sys/fs/cgroup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OriginalCgroupCaptureStatus {
    Required,
    CapturedFromSample,
    Missing,
    Unsafe,
    ZelynicManaged,
}

impl OriginalCgroupCaptureStatus {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::Required => "required",
            Self::CapturedFromSample => "captured from sample",
            Self::Missing => "missing",
            Self::Unsafe => "unsafe",
            Self::ZelynicManaged => "zelynic-managed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OriginalCgroupCapturePreview {
    pub pid: u32,
    pub status: OriginalCgroupCaptureStatus,
    pub original_cgroup_path: Option<String>,
    pub rollback_target_path: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum OriginalCgroupParseError {
    MissingV2Line,
    MalformedLine,
    EmptyPath,
    UnsafePath,
    ZelynicManaged,
}

impl OriginalCgroupParseError {
    fn reason(&self) -> &'static str {
        match self {
            Self::MissingV2Line => "no cgroup v2 path was present",
            Self::MalformedLine => "cgroup content is malformed",
            Self::EmptyPath => "cgroup v2 path is empty",
            Self::UnsafePath => "cgroup v2 path is unsafe",
            Self::ZelynicManaged => "cgroup v2 path is already Zelynic-managed",
        }
    }
}

pub(crate) fn build_pending_original_cgroup_previews(
    pids: &[u32],
) -> Vec<OriginalCgroupCapturePreview> {
    pids.iter()
        .copied()
        .map(pending_original_cgroup_preview)
        .collect()
}

pub(crate) fn pending_original_cgroup_preview(pid: u32) -> OriginalCgroupCapturePreview {
    OriginalCgroupCapturePreview {
        pid,
        status: OriginalCgroupCaptureStatus::Required,
        original_cgroup_path: None,
        rollback_target_path: None,
        reason: "original cgroup capture required before attach; not read in this probe"
            .to_string(),
    }
}

pub(crate) fn build_original_cgroup_preview_from_sample(
    pid: u32,
    proc_cgroup_content: &str,
) -> OriginalCgroupCapturePreview {
    match parse_proc_cgroup_v2_path(proc_cgroup_content) {
        Ok(path) => OriginalCgroupCapturePreview {
            pid,
            status: OriginalCgroupCaptureStatus::CapturedFromSample,
            rollback_target_path: Some(cgroup_v2_path_to_fs_path(&path)),
            original_cgroup_path: Some(path),
            reason: "rollback target captured from sample cgroup v2 path".to_string(),
        },
        Err(OriginalCgroupParseError::MissingV2Line) => OriginalCgroupCapturePreview {
            pid,
            status: OriginalCgroupCaptureStatus::Missing,
            original_cgroup_path: None,
            rollback_target_path: None,
            reason: OriginalCgroupParseError::MissingV2Line.reason().to_string(),
        },
        Err(OriginalCgroupParseError::ZelynicManaged) => OriginalCgroupCapturePreview {
            pid,
            status: OriginalCgroupCaptureStatus::ZelynicManaged,
            original_cgroup_path: None,
            rollback_target_path: None,
            reason: OriginalCgroupParseError::ZelynicManaged
                .reason()
                .to_string(),
        },
        Err(err) => OriginalCgroupCapturePreview {
            pid,
            status: OriginalCgroupCaptureStatus::Unsafe,
            original_cgroup_path: None,
            rollback_target_path: None,
            reason: err.reason().to_string(),
        },
    }
}

pub(crate) fn parse_proc_cgroup_v2_path(
    proc_cgroup_content: &str,
) -> Result<String, OriginalCgroupParseError> {
    let mut saw_line = false;

    for line in proc_cgroup_content.lines().map(str::trim) {
        if line.is_empty() {
            continue;
        }
        saw_line = true;

        let fields = line.splitn(3, ':').collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(OriginalCgroupParseError::MalformedLine);
        }

        if fields[0] == "0" && fields[1].is_empty() {
            return validate_original_cgroup_v2_path(fields[2]);
        }
    }

    if saw_line {
        Err(OriginalCgroupParseError::MissingV2Line)
    } else {
        Err(OriginalCgroupParseError::MalformedLine)
    }
}

pub(crate) fn validate_original_cgroup_v2_path(
    path: &str,
) -> Result<String, OriginalCgroupParseError> {
    if path.is_empty() {
        return Err(OriginalCgroupParseError::EmptyPath);
    }
    if !path.starts_with('/') {
        return Err(OriginalCgroupParseError::UnsafePath);
    }
    if path.split('/').any(|part| part == "..") {
        return Err(OriginalCgroupParseError::UnsafePath);
    }
    if path == "/zelynic" || path.starts_with("/zelynic/") {
        return Err(OriginalCgroupParseError::ZelynicManaged);
    }

    Ok(path.to_string())
}

pub(crate) fn cgroup_v2_path_to_fs_path(path: &str) -> String {
    if path == "/" {
        CGROUP_FS_ROOT.to_string()
    } else {
        format!("{}/{}", CGROUP_FS_ROOT, path.trim_start_matches('/'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_user_cgroup_v2_path() {
        let path =
            parse_proc_cgroup_v2_path("0::/user.slice/user-1000.slice/session-2.scope\n").unwrap();

        assert_eq!(path, "/user.slice/user-1000.slice/session-2.scope");
    }

    #[test]
    fn parses_valid_system_cgroup_v2_path() {
        let path = parse_proc_cgroup_v2_path("0::/system.slice/example.scope\n").unwrap();

        assert_eq!(path, "/system.slice/example.scope");
    }

    #[test]
    fn rejects_malformed_cgroup_content() {
        let err = parse_proc_cgroup_v2_path("not-a-cgroup-line").unwrap_err();

        assert_eq!(err, OriginalCgroupParseError::MalformedLine);
    }

    #[test]
    fn rejects_empty_cgroup_path() {
        let err = parse_proc_cgroup_v2_path("0::").unwrap_err();

        assert_eq!(err, OriginalCgroupParseError::EmptyPath);
    }

    #[test]
    fn rejects_parent_traversal_path() {
        let err = parse_proc_cgroup_v2_path("0::/user.slice/../bad.scope").unwrap_err();

        assert_eq!(err, OriginalCgroupParseError::UnsafePath);
    }

    #[test]
    fn rejects_zelynic_managed_path() {
        let err = parse_proc_cgroup_v2_path("0::/zelynic/target_sleep").unwrap_err();

        assert_eq!(err, OriginalCgroupParseError::ZelynicManaged);
    }

    #[test]
    fn preview_model_marks_missing_capture_as_pending() {
        let preview = pending_original_cgroup_preview(12345);

        assert_eq!(preview.pid, 12345);
        assert_eq!(preview.status, OriginalCgroupCaptureStatus::Required);
        assert_eq!(preview.rollback_target_path, None);
        assert!(preview.reason.contains("not read in this probe"));
    }

    #[test]
    fn preview_model_marks_valid_sample_as_rollback_ready() {
        let preview =
            build_original_cgroup_preview_from_sample(12345, "0::/system.slice/example.scope\n");

        assert_eq!(
            preview.status,
            OriginalCgroupCaptureStatus::CapturedFromSample
        );
        assert_eq!(
            preview.original_cgroup_path.as_deref(),
            Some("/system.slice/example.scope")
        );
        assert_eq!(
            preview.rollback_target_path.as_deref(),
            Some("/sys/fs/cgroup/system.slice/example.scope")
        );
    }

    #[test]
    fn preview_model_marks_zelynic_sample_as_zelynic_managed() {
        let preview =
            build_original_cgroup_preview_from_sample(12345, "0::/zelynic/target_sleep\n");

        assert_eq!(preview.status, OriginalCgroupCaptureStatus::ZelynicManaged);
        assert_eq!(preview.rollback_target_path, None);
    }

    #[test]
    fn converts_cgroup_path_to_fs_path() {
        assert_eq!(
            cgroup_v2_path_to_fs_path("/system.slice/foo.scope"),
            "/sys/fs/cgroup/system.slice/foo.scope"
        );
    }
}
