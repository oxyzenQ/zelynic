// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! zelynic package information constants and the version report.
///
/// Build metadata is embedded at compile time using env! macros.
/// For custom builds, set these via cargo build flags or build.rs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = "zelynic";
pub const COPYRIGHT: &str = "(c) 2026 rezky_nightky (oxyzenQ)";
pub const LICENSE: &str = "GPL-3.0-only";
pub const REPOSITORY: &str = "https://github.com/oxyzenQ/zelynic";
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

pub fn build_target() -> &'static str {
    // Dynamic build target label: detects arch + libc env at compile time.
    // Returns e.g. "amd64-gnu" (glibc, dynamic) or "amd64-musl" (static)
    // for x86_64 Linux builds. Other arches pass through with env suffix.
    if cfg!(target_env = "musl") {
        if cfg!(target_arch = "x86_64") {
            "amd64-musl"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-musl"
        } else {
            std::env::consts::ARCH
        }
    } else if cfg!(target_env = "gnu") {
        if cfg!(target_arch = "x86_64") {
            "amd64-gnu"
        } else if cfg!(target_arch = "aarch64") {
            "aarch64-gnu"
        } else {
            std::env::consts::ARCH
        }
    } else {
        match std::env::consts::ARCH {
            "x86_64" => "amd64",
            other => other,
        }
    }
}

/// Get the build target string (architecture + OS).
fn build_string() -> String {
    format!("{}-{}", std::env::consts::OS, build_target())
}

/// Canonical build label for the `Build:` line of the version report
/// (cosmostrix `canonical_build_label()` lineage).
///
/// Source of truth: the `ZELYNIC_BUILD` env var forwarded at compile
/// time by build.rs — set by the cargo aliases `pro-native-gnu` /
/// `pro-native-musl` (labels `local-native-gnu` / `local-native-musl`,
/// see .cargo/config.toml), the arch-baseline aliases
/// `pro-linux-amd64-v3-gnu` / `pro-linux-amd64-v4-gnu` /
/// `pro-linux-amd64-v3-musl` / `pro-linux-amd64-v4-musl` (labels
/// `local-linux-amd64-v3-gnu` etc., the release matrix platform id
/// under the `local-` marker, NIGHT-boost-30), or by CI/release
/// scripts (the platform id verbatim, e.g. `linux-amd64-v3-gnu`).
/// When unset (plain `cargo build`), it falls back to the
/// compile-time arch+libc detection, e.g. `linux-amd64-gnu`.
fn build_label() -> String {
    match option_env!("ZELYNIC_BUILD") {
        Some(label) if !label.is_empty() => label.to_string(),
        _ => build_string(),
    }
}

/// Get the git commit hash injected at build time by build.rs.
fn build_hash() -> &'static str {
    option_env!("GIT_HASH").unwrap_or("unknown")
}

/// Get the build timestamp injected at build time by build.rs.
///
/// Computed by Howard Hinnant's civil_from_days algorithm inside
/// build.rs (NIGHT-hunt-6, cosmostrix lineage) — `M/D/YYYY HH:MM (UTC)`
/// — so no time crate (chrono and friends) is needed anywhere in the
/// dependency tree. Falls back to "unknown" only when the build script
/// could not read the system clock (pre-UNIX_EPOCH host clock).
fn build_time() -> &'static str {
    option_env!("ZELYNIC_BUILD_TIME").unwrap_or("unknown")
}

/// The plain-text body of the version report (everything after the
/// brand header). Separated from [`print_version_report`] so tests can
/// assert the full line set without capturing stdout.
fn version_body() -> String {
    format!(
        "Architecture: Cosmic Dragon (pure eBPF)\n\
         Build: {} ({})\n\
         Build-time: {}\n\
         Copyright: {COPYRIGHT}\n\
         License: {LICENSE}\n\
         Source: {REPOSITORY}",
        build_label(),
        build_hash(),
        build_time()
    )
}

/// Print the full version report for `-V` / `--version`.
///
/// cosmostrix-style layout: brand header (name + version, then the
/// one-line description), followed by plain build facts. The header is
/// rendered in brand purple #A855F7 (regular weight, exactly as the
/// cosmostrix `version_report()` does) on a TTY, degrading through
/// 256-color/16-color tiers; when piped (non-TTY) everything is plain
/// text so ANSI codes never leak into scripts or log files. The
/// Architecture line stays on its own line so it is easy to grep from
/// scripts (`zelynic -V | grep Architecture`).
///
/// ```text
/// zelynic: v11.0.0
/// Per-app network rate limiter and traffic monitor for Linux. Pure eBPF. Boring and silent but killer.
/// Architecture: Cosmic Dragon (pure eBPF)
/// Build: linux-amd64-gnu (ad36a81)
/// Build-time: 9/18/2026 01:30 (UTC)
/// Copyright: (c) 2026 rezky_nightky (oxyzenQ)
/// License: GPL-3.0-only
/// Source: https://github.com/oxyzenQ/zelynic
/// ```
///
/// The `Build:` line carries the canonical label from [`build_label`]:
/// `local-native-gnu` / `local-native-musl` for alias builds, the
/// detected `linux-<arch>-<libc>` string for plain builds. The
/// `Build-time:` line (NIGHT-hunt-6, cosmostrix parity) is stamped by
/// build.rs via the Hinnant civil-from-days algorithm — UTC-only, so
/// no timezone database is pulled into the binary and the stamp is
/// identical across build hosts.
pub fn print_version_report() {
    let header = format!("{NAME}: v{VERSION}\n{DESCRIPTION}");
    println_safe!("{}", crate::output::brand(&header));
    println_safe!("{}", version_body());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fallback contract: in a plain `cargo test` build ZELYNIC_BUILD is
    /// not forwarded by build.rs, so the canonical label must equal the
    /// compile-time arch+libc detection. The override path (alias builds
    /// reporting `local-native-gnu` / `local-native-musl`) is verified
    /// live by building with the aliases and reading `zelynic -V`.
    #[test]
    fn build_label_falls_back_to_detected_target_when_env_unset() {
        match option_env!("ZELYNIC_BUILD") {
            Some(_) => { /* alias/CI build: override path, verified live */ }
            None => assert_eq!(build_label(), build_string()),
        }
    }

    /// The detected fallback label must stay lowercase and carry the
    /// arch-libc shape the docs promise (`linux-amd64-gnu` style), so a
    /// drift in build_target() cannot silently reshape the Build: line.
    #[test]
    fn detected_build_label_shape_is_os_arch_libc() {
        let label = build_string();
        assert!(label.contains('-'), "label must be dash-joined: {label}");
        assert!(
            !label.contains(char::is_whitespace),
            "label must be a single token: {label}"
        );
        assert_eq!(label, label.to_lowercase());
    }

    /// NIGHT-hunt-6 contract: the version report carries the Build-time
    /// line between Build and Copyright (cosmostrix parity), and every
    /// documented line is present exactly once.
    #[test]
    fn version_report_carries_build_time_line() {
        let body = version_body();
        for line in [
            "Architecture: Cosmic Dragon (pure eBPF)",
            "Build-time: ",
            "Copyright: (c) 2026 rezky_nightky (oxyzenQ)",
            "License: GPL-3.0-only",
            "Source: https://github.com/oxyzenQ/zelynic",
        ] {
            let count = body.lines().filter(|l| l.contains(line)).count();
            assert_eq!(count, 1, "line must appear exactly once: {line}");
        }
        // Ordering: Build-time sits directly after the Build line.
        let lines: Vec<&str> = body.lines().collect();
        let build_idx = lines
            .iter()
            .position(|l| l.starts_with("Build: "))
            .expect("Build: line present");
        assert!(
            lines[build_idx + 1].starts_with("Build-time: "),
            "Build-time must follow Build, got: {}",
            lines[build_idx + 1]
        );
    }

    /// NIGHT-hunt-6 contract: the stamped build time is either the
    /// documented degraded "unknown" (host clock unreadable at build
    /// time) or matches the Hinnant `M/D/YYYY HH:MM (UTC)` shape with
    /// a plausible year. A malformed stamp (e.g. an accidental local-
    /// time format with an offset suffix) fails here, not in the wild.
    #[test]
    fn build_time_stamp_shape_is_m_d_yyyy_hh_mm_utc() {
        let stamp = build_time();
        if stamp == "unknown" {
            return; // degraded path, documented
        }
        assert!(
            stamp.ends_with(" (UTC)"),
            "stamp must carry the (UTC) suffix: {stamp}"
        );
        let core = stamp.strip_suffix(" (UTC)").expect("suffix checked above");
        // Shape: M/D/YYYY then space then HH:MM (2-digit, zero-padded).
        let (date, time) = core
            .split_once(' ')
            .unwrap_or_else(|| panic!("date and time must be space-separated: {stamp}"));
        let date_parts: Vec<&str> = date.split('/').collect();
        assert_eq!(date_parts.len(), 3, "date must be M/D/YYYY: {stamp}");
        let (month, day, year) = (
            date_parts[0].parse::<u32>().unwrap_or(0),
            date_parts[1].parse::<u32>().unwrap_or(0),
            date_parts[2].parse::<u32>().unwrap_or(0),
        );
        assert!((1..=12).contains(&month), "month out of range: {stamp}");
        assert!((1..=31).contains(&day), "day out of range: {stamp}");
        assert!(year >= 2026, "year implausibly old: {stamp}");
        // Time is HH:MM — two 2-digit fields, hour and minute in range.
        let time_parts: Vec<&str> = time.split(':').collect();
        assert_eq!(time_parts.len(), 2, "time must be HH:MM: {stamp}");
        assert_eq!(time_parts[0].len(), 2, "hour must be 2 digits: {stamp}");
        assert_eq!(time_parts[1].len(), 2, "minute must be 2 digits: {stamp}");
        let hour = time_parts[0].parse::<u32>().unwrap_or(99);
        let minute = time_parts[1].parse::<u32>().unwrap_or(99);
        assert!(hour <= 23, "hour out of range: {stamp}");
        assert!(minute <= 59, "minute out of range: {stamp}");
    }
}
