// SPDX-License-Identifier: GPL-3.0-only
/// zelynic package information constants and display functions.
///
/// Build metadata is embedded at compile time using env! macros.
/// For custom builds, set these via cargo build flags or build.rs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
#[allow(dead_code)]
pub const NAME: &str = "zelynic";
pub fn build_target() -> &'static str {
    option_env!("CARGO_CFG_TARGET_ARCH").unwrap_or("x86_64")
}
pub const COPYRIGHT: &str = "(c) 2026 Rezky_nightky";
pub const LICENSE: &str = "GPL-3.0";
pub const REPOSITORY: &str = "https://github.com/oxyzenq/zelynic";
#[allow(dead_code)]
pub const DESCRIPTION: &str = "Easy userspace bandwidth manager for Linux";

/// Get the full version string.
fn version_string() -> String {
    format!("v{}", VERSION)
}

/// Get the build target string (architecture + OS).
fn build_string() -> String {
    format!("linux-{}", build_target())
}

/// Get the git commit hash injected at build time by build.rs.
fn build_hash() -> &'static str {
    option_env!("GIT_HASH").unwrap_or("unknown")
}

/// Print the package version in a compact format.
///
/// Output: `zelynic v2.0.0`
#[allow(dead_code)]
pub fn print_version() {
    println!("{} {}", NAME, version_string());
}

/// Print detailed package information.
///
/// ```text
/// Version: v2.0.0
/// Build: linux-x86_64 (ad36a81)
/// Copyright: (c) 2026 Rezky_nightky
/// License: GPL-3.0
/// Source: https://github.com/oxyzenq/zelynic
/// ```
pub fn print_info() {
    println!("Version: {}", version_string());
    println!("Build: {} ({})", build_string(), build_hash());
    println!("Copyright: {}", COPYRIGHT);
    println!("License: {}", LICENSE);
    println!("Source: {}", REPOSITORY);
}
