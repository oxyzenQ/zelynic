// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::process::Command;

use crate::ebpf::identity::sanitize_comm;
use crate::output::{brand_bold, ok_bold, warn_bold};

const GITHUB_API_URL: &str = "https://api.github.com/repos/oxyzenQ/zelynic/releases/latest";
const RELEASES_URL: &str = "https://github.com/oxyzenQ/zelynic/releases/latest";

/// Root refusal for `--check-update` (NIGHT-hunt-11).
///
/// The update check is a plain network fetch (curl against the GitHub
/// API): running it as root is a privileged network round-trip that buys
/// nothing — curl inherits root's environment wholesale, and any future
/// download step would plant root-owned files into the invoking user's
/// home. The guard refuses euid 0 before any network I/O happens.
///
/// Pure function of the euid fact so both the decision and the wording
/// are unit-pinned below.
fn root_refusal(euid_is_root: bool) -> Option<&'static str> {
    if euid_is_root {
        Some(
            "root refused — update check performs a network fetch, do not use sudo\n  \
             tip: re-run without sudo",
        )
    } else {
        None
    }
}

#[derive(Debug, PartialEq, Eq)]
enum UpdateStatus {
    UpToDate,
    UpdateAvailable,
    CurrentIsNewer,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SemVer {
    major: u64,
    minor: u64,
    patch: u64,
}

impl SemVer {
    fn parse(version: &str) -> Option<Self> {
        let version = version.trim();
        let version = version.strip_prefix('v').unwrap_or(version);
        let version = version
            .split_once('-')
            .map_or(version, |(stable, _)| stable);
        let mut parts = version.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            major,
            minor,
            patch,
        })
    }
}

fn normalize_version(version: &str) -> String {
    let version = version.trim();
    if version.starts_with('v') {
        version.to_string()
    } else {
        format!("v{version}")
    }
}

fn compare_versions(current: &str, latest: &str) -> UpdateStatus {
    match (SemVer::parse(current), SemVer::parse(latest)) {
        (Some(current), Some(latest)) if current == latest => UpdateStatus::UpToDate,
        (Some(current), Some(latest)) if current > latest => UpdateStatus::CurrentIsNewer,
        _ => UpdateStatus::UpdateAvailable,
    }
}

fn extract_tag_name(json: &str) -> Option<String> {
    let key = "\"tag_name\"";
    let rest = json.get(json.find(key)? + key.len()..)?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn curl_failure(code: i32) -> &'static str {
    match code {
        6 => "DNS resolution failed",
        7 => "connection refused",
        28 => "network request timed out",
        35 => "SSL/TLS handshake failed",
        _ => "network request failed",
    }
}

fn http_failure(code: u16) -> &'static str {
    match code {
        403 => "GitHub API request was rate-limited or forbidden",
        404 => "no latest GitHub release found for oxyzenq/zelynic",
        _ => "GitHub API returned an unexpected error",
    }
}

pub fn check_update(current_version: &str) -> Result<(), String> {
    // Privilege guard first (NIGHT-hunt-11): refuse euid 0 before any
    // network I/O — this is the mirror image of the eBPF handlers'
    // ensure_root() ladder, applied to the one command where root is
    // the hazard instead of the requirement.
    if let Some(refusal) = root_refusal(nix::unistd::geteuid().is_root()) {
        return Err(refusal.to_string());
    }

    let output = Command::new("curl")
        .args([
            "--silent",
            "--max-time",
            "15",
            "--header",
            "Accept: application/vnd.github+json",
            "--header",
            "User-Agent: zelynic",
            "--write-out",
            "\n%{http_code}",
            GITHUB_API_URL,
        ])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "curl is not available on PATH".to_string()
            } else {
                format!("failed to run curl: {e}")
            }
        })?;

    if !output.status.success() {
        return Err(curl_failure(output.status.code().unwrap_or(-1)).to_string());
    }

    let raw =
        String::from_utf8(output.stdout).map_err(|_| "response was not valid UTF-8".to_string())?;
    let (body, status) = raw
        .rsplit_once('\n')
        .ok_or_else(|| "GitHub API response was malformed".to_string())?;
    let status = status.trim().parse::<u16>().unwrap_or(0);
    if status != 200 {
        return Err(http_failure(status).to_string());
    }

    let latest_tag = extract_tag_name(body)
        .ok_or_else(|| "could not parse latest release tag from GitHub response".to_string())?;
    // NIGHT-cybersecurity-2: the tag is an untrusted NETWORK string
    // printed to the admin's terminal — the same terminal-injection
    // contract the /proc comm boundary already enforces (sanitize_comm:
    // OSC 52 clipboard rewrites, ANSI corruption, forged output lines).
    // curl inherits the invoking user's proxy environment, so a MITM'd
    // or compromised proxy response is in the threat model even over
    // TLS; the tag never reaches the terminal raw.
    let latest_tag = sanitize_comm(&latest_tag);

    // Branded report (NIGHT-hunt-5): header in brand purple like every
    // other zelynic banner; status verdict colored by semantic (green =
    // current, yellow = attention).
    println_safe!("{}", brand_bold("━━━ zelynic Update Check ━━━"));
    println_safe!("Current: {}", normalize_version(current_version));
    println_safe!("Latest:  {}", normalize_version(&latest_tag));
    let status_line = match compare_versions(current_version, &latest_tag) {
        UpdateStatus::UpToDate => ok_bold("up to date"),
        UpdateStatus::UpdateAvailable => warn_bold("update available"),
        UpdateStatus::CurrentIsNewer => "current is newer than latest release".to_string(),
    };
    println_safe!("Status:  {status_line}");
    println_safe!("Source:  {RELEASES_URL}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NIGHT-hunt-11 drift pin: the root refusal wording is the
    /// owner-facing contract ("do not use sudo for check download") —
    /// it must name the hazard (network fetch), the refusal (do not use
    /// sudo), and the fix (re-run without sudo).
    #[test]
    fn update_check_refuses_root_with_do_not_use_sudo_tip() {
        let msg = root_refusal(true).expect("euid 0 must be refused");
        assert!(
            msg.contains("do not use sudo"),
            "refusal must carry the do-not-use-sudo verdict, got: {msg}"
        );
        assert!(
            msg.contains("network fetch"),
            "refusal must say why: network fetch as root, got: {msg}"
        );
        assert!(
            msg.contains("tip: re-run without sudo"),
            "refusal must carry the actionable tip, got: {msg}"
        );
    }

    /// The inverse contract: a normal user invocation passes the guard
    /// untouched (None means proceed to the network fetch).
    #[test]
    fn update_check_allows_non_root() {
        assert!(
            root_refusal(false).is_none(),
            "non-root must pass the guard"
        );
    }

    #[test]
    fn extracts_tag_name() {
        assert_eq!(
            extract_tag_name(r#"{"tag_name":"v2.6.0"}"#),
            Some("v2.6.0".to_string())
        );
    }

    /// NIGHT-cybersecurity-2: the release tag is an untrusted network
    /// string (curl inherits the user's proxy environment; the threat
    /// model includes a MITM'd or compromised proxy response even over
    /// TLS). The check_update pipeline must print it through
    /// sanitize_comm — the same terminal-injection contract as the
    /// /proc comm boundary: OSC 52 clipboard rewrites, ANSI corruption,
    /// and forged output lines all die at the boundary.
    #[test]
    fn release_tag_from_network_is_sanitized_before_printing() {
        // Forged response: the "tag" carries an OSC 52 clipboard-write
        // payload and a newline-forged verdict line. The body embeds
        // REAL control bytes — extract_tag_name is a substring parser,
        // it passes whatever sits between the quotes straight through.
        let forged = "{\"tag_name\":\"\u{1b}]52;p;SGVsbG8=\u{7}\nv99.0.0\"}";
        let raw = extract_tag_name(forged).expect("forged tag extracts");
        assert!(
            raw.chars().any(|c| c.is_control()),
            "precondition: the raw forged tag carries control chars"
        );
        assert_eq!(
            sanitize_comm(&raw),
            "?]52;p;SGVsbG8=??v99.0.0",
            "ESC, BEL, and the newline all die at the boundary (one ? each)"
        );
    }

    #[test]
    fn compares_versions() {
        assert_eq!(compare_versions("2.6.0", "v2.6.0"), UpdateStatus::UpToDate);
        assert_eq!(
            compare_versions("2.5.0", "v2.6.0"),
            UpdateStatus::UpdateAvailable
        );
        assert_eq!(
            compare_versions("2.7.0", "v2.6.0"),
            UpdateStatus::CurrentIsNewer
        );
        assert_eq!(
            compare_versions("2.8.0", "v2.7.0"),
            UpdateStatus::CurrentIsNewer
        );
    }
}
