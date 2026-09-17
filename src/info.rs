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

/// Get the git commit hash injected at build time by build.rs.
fn build_hash() -> &'static str {
    option_env!("GIT_HASH").unwrap_or("unknown")
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
/// zelynic: v10.0.0
/// Per-app network rate limiter and traffic monitor for Linux. Pure eBPF. Silent but killer.
/// Architecture: Dragon (pure eBPF)
/// Build: linux-amd64 (ad36a81)
/// Copyright: (c) 2026 rezky_nightky (oxyzenQ)
/// License: GPL-3.0-only
/// Source: https://github.com/oxyzenQ/zelynic
/// ```
pub fn print_version_report() {
    let header = format!("{NAME}: v{VERSION}\n{DESCRIPTION}");
    let body = format!(
        "Architecture: Dragon (pure eBPF)\n\
         Build: {} ({})\n\
         Copyright: {COPYRIGHT}\n\
         License: {LICENSE}\n\
         Source: {REPOSITORY}",
        build_string(),
        build_hash()
    );

    println!("{}", crate::output::brand(&header));
    println!("{body}");
}
