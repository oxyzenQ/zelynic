// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! zelynic package information constants and the version report.
///
/// Build metadata is embedded at compile time using env! macros.
/// For custom builds, set these via cargo build flags or build.rs.
///
/// night-improve-66: the build-facts lane — the canonical label
/// chain (build_target/build_string/build_label), the git-sha and
/// build-time stamps, and the doctor's BUILD block ([`BuildInfo`])
/// — lives in the [`build`] sibling (the theme.rs → terminal_bg.rs
/// split precedent: this file rode the 600-line law's ceiling the
/// moment the BUILD block joined). The version report consumes
/// that lane through the re-exports below; the capability doctor
/// serializes [`BuildInfo`] directly.
mod build;

pub use build::BuildInfo;
pub use build::VERSION;
use build::{build_hash, build_label, build_time};

pub const NAME: &str = "zelynic";
pub const COPYRIGHT: &str = "(c) 2026 rezky_nightky (oxyzenQ)";
pub const REPOSITORY: &str = "https://github.com/oxyzenQ/zelynic";
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// The `License:` line as ONE contiguous literal (NIGHT-blade-4).
///
/// release.yml's AVX-512 (v4) legs verify the artifact WITHOUT
/// executing it — the runner may lack the baseline, so `strings`
/// must find "License: GPL-3.0-only" as contiguous bytes in the
/// rodata. A format! inline capture (`{LICENSE}`) splits the line:
/// the template keeps "License: " and the bare id "GPL-3.0-only"
/// lands elsewhere in rodata, and the strings probe failed on both
/// v4 legs (the v11.0.0-beta.2 release incident). This const IS the
/// whole line, so the bytes stay contiguous by construction; the
/// unit tests below pin the exact bytes the pipeline greps. (The
/// pre-blade-4 `pub const LICENSE` — the bare id, consumed only by
/// the old inline capture — was removed with the capture: zero
/// call sites left, the dependency-audit discipline.)
const LICENSE_LINE: &str = "License: GPL-3.0-only";

/// The `Signature:` line for full-life builds as ONE contiguous
/// literal (NIGHT-dinner-4) — the NIGHT-blade-4 discipline applied to
/// the new line: release.yml's v4 legs prove an artifact through
/// `strings`, so the bytes the pipeline greps stay contiguous by
/// construction (never a format! join). The claim "Pure eBPF
/// builtin" is true of BOTH full-life lanes — source-built objects
/// cross-compiled from the local ebpf/ tree, registry-prebuilt
/// objects staged from ebpf-prebuilt/ — because either way they ride
/// inside the binary (`include_bytes!`): no toolchain, no clang, no
/// separate object files ever touch the target machine. Which lane
/// produced them is the doctor's answer, not the brand surface's
/// (NIGHT-dinner-3: `zelynic doctor` reports build_flavor +
/// ebpf_lane on text and JSON).
const SIGNATURE_LINE: &str =
    "Signature: Pure eBPF builtin — Official Build by rezky_nightky (oxyzenQ)";

/// The dormant-lane Signature (NIGHT-dinner-4): a
/// `--no-default-features` build embeds no eBPF objects at all, and
/// the claims discipline (QA.md) does not let its version report
/// claim "Pure eBPF builtin" about surfaces that answer their honest
/// refusal. Same masterclass shape — prefix, attribution — with the
/// honest claim swapped in.
const SIGNATURE_DORMANT_LINE: &str =
    "Signature: eBPF dormant — Official Build by rezky_nightky (oxyzenQ)";

/// The eBPF object lane this binary was built through (NIGHT-ask-2),
/// stamped by build.rs as `ZELYNIC_EBPF_LANE`:
///
/// - `source-built` — a git checkout: the objects were cross-compiled
///   from the local ebpf/ tree by the nested nightly build (the
///   source-built contract; a tree that HAS the sources builds the
///   sources).
/// - `registry-prebuilt` — a crates.io source extract: cargo's
///   package walk cannot carry the detached ebpf/ workspace (nested
///   packages are auto-excluded), so build.rs staged the
///   maintainer-built objects from ebpf-prebuilt/ — the same bytes the
///   GitHub Release binaries embed, provenance in
///   ebpf-prebuilt/manifest.toml.
/// - `dormant (not compiled)` — a `--no-default-features` build: the
///   eBPF surfaces answer their honest refusal.
///
/// The fallback matches the dormant stamp: every path that compiles
/// eBPF code sets the env explicitly, so the fallback only guards a
/// build script that crashed before stamping (which fails the build
/// anyway) — it can never mislabel a full build as dormant.
///
/// NIGHT-dinner-3: `pub(crate)` — the capability doctor reports this
/// stamp alongside its full-life/half-life verdict, so a downloaded
/// binary answers "which build path am I?" in one place.
/// NIGHT-dinner-4: that report is now the ONLY lane surface — the
/// version report no longer prints an `eBPF objects:` line; it picks
/// its lane-honest Signature line through [`signature_line`] instead
/// (the claim collapses to "Pure eBPF builtin"; the forensic detail
/// stays with the doctor).
pub(crate) fn ebpf_lane() -> &'static str {
    option_env!("ZELYNIC_EBPF_LANE").unwrap_or("dormant (not compiled)")
}

/// The Signature line this binary's version report carries
/// (NIGHT-dinner-4).
///
/// Full-life builds — source-built AND registry-prebuilt lanes
/// alike, since the objects ride inside the binary either way —
/// carry the masterclass signature (the cosmostrix
/// `COSMIC_DRAGON_SIGNATURE` lineage). A dormant build carries no
/// objects at all, and the claims discipline does not let its report
/// say "Pure eBPF" about eBPF surfaces that answer their honest
/// refusal, so it gets the honest variant: same prefix, same
/// attribution, swapped claim. The dormant match keys on the exact
/// stamp value [`ebpf_lane`] documents; every path that compiles
/// eBPF code stamps a lane explicitly, so a full build can never
/// fall into the dormant arm.
fn signature_line() -> &'static str {
    match ebpf_lane() {
        "dormant (not compiled)" => SIGNATURE_DORMANT_LINE,
        _ => SIGNATURE_LINE,
    }
}

/// The plain-text body of the version report (everything after the
/// brand header). Separated from [`print_version_report`] so tests can
/// assert the full line set without capturing stdout.
fn version_body() -> String {
    format!(
        "Build: {} ({})\n\
         Build-time: {}\n\
         {}\n\
         Copyright: {COPYRIGHT}\n\
         {LICENSE_LINE}\n\
         Source: {REPOSITORY}",
        build_label(),
        build_hash(),
        build_time(),
        signature_line()
    )
}

/// Print the full version report for `-V` / `--version`.
///
/// cosmostrix masterclass layout: brand header (name + version, then
/// the one-line description), followed by plain build facts. The
/// header is rendered in brand purple #A855F7 (regular weight,
/// exactly as the cosmostrix `version_report()` does) on a TTY,
/// degrading through 256-color/16-color tiers; when piped (non-TTY)
/// everything is plain text so ANSI codes never leak into scripts or
/// log files. The Signature line stays on its own line so it is easy
/// to grep from scripts (`zelynic -V | grep Signature`).
///
/// ```text
/// zelynic: v11.0.0
/// Per-app network rate limiter and traffic monitor for Linux. Pure eBPF. Boring and silent but killer.
/// Build: linux-amd64-gnu (ad36a81)
/// Build-time: 9/18/2026 01:30 (UTC)
/// Signature: Pure eBPF builtin — Official Build by rezky_nightky (oxyzenQ)
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
/// identical across build hosts. The `Signature:` line
/// (NIGHT-dinner-4) is the lane-honest one-line identity from
/// [`signature_line`] — "Pure eBPF builtin" on every full-life build
/// (the objects are embedded either way), "eBPF dormant" on a
/// `--no-default-features` build that must not claim objects it does
/// not carry — in the cosmostrix `COSMIC_DRAGON_SIGNATURE` style.
/// The lines it replaced live on elsewhere: the per-lane forensic
/// detail (`eBPF objects:`, NIGHT-ask-2) in `zelynic doctor`'s Build
/// line and JSON (`build_flavor` / `ebpf_lane`, NIGHT-dinner-3), the
/// architecture story in the tagline's "Pure eBPF" and
/// docs/COSMIC_DRAGON_ARCHITECTURE.md.
pub fn print_version_report() {
    let header = format!("{NAME}: v{VERSION}\n{DESCRIPTION}");
    println_safe!("{}", crate::output::brand(&header));
    println_safe!("{}", version_body());
}

#[cfg(test)]
mod tests {
    use super::*;
    /// NIGHT-blade-4 contract: the license line exists as ONE
    /// contiguous literal (LICENSE_LINE) — the release pipeline's
    /// AVX-512 legs grep exactly those bytes out of `strings` on
    /// artifacts whose baseline the runner cannot execute. The
    /// literal is pinned verbatim here so a drifted line fails in
    /// the unit run, not on a release day.
    #[test]
    fn license_line_is_the_contiguous_bytes_the_release_probe_greps() {
        assert_eq!(LICENSE_LINE, "License: GPL-3.0-only");
    }

    /// NIGHT-hunt-6 contract: the version report carries the Build-time
    /// line between Build and Copyright (cosmostrix parity), and every
    /// documented line is present exactly once.
    #[test]
    fn version_report_carries_build_time_line() {
        let body = version_body();
        for line in [
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

    /// NIGHT-dinner-4 contract: the Signature line appears exactly
    /// once, directly after Build-time, and is the lane-honest one of
    /// the two documented lines — a full-life build (source-built or
    /// registry-prebuilt: the objects are embedded either way)
    /// carries "Pure eBPF builtin", a dormant build carries "eBPF
    /// dormant" and never the claim it cannot back. The lane detail
    /// itself stays the doctor's answer (build_flavor / ebpf_lane).
    #[test]
    fn signature_line_is_pinned_after_build_time_and_lane_honest() {
        let body = version_body();
        let count = body
            .lines()
            .filter(|l| l.starts_with("Signature: "))
            .count();
        assert_eq!(count, 1, "the Signature line must appear exactly once");
        let expected = signature_line();
        assert!(
            [SIGNATURE_LINE, SIGNATURE_DORMANT_LINE].contains(&expected),
            "signature must be one of the documented lines, got: {expected}"
        );
        let lines: Vec<&str> = body.lines().collect();
        let time_idx = lines
            .iter()
            .position(|l| l.starts_with("Build-time: "))
            .expect("Build-time line present");
        assert_eq!(
            lines[time_idx + 1],
            expected,
            "the Signature line must follow Build-time"
        );
        // Lane honesty: the dormant stamp — and only it — flips the
        // claim. A full build saying "eBPF dormant", or a dormant
        // build saying "Pure eBPF builtin", fails here.
        let lane = ebpf_lane();
        assert!(
            [
                "source-built",
                "registry-prebuilt",
                "dormant (not compiled)"
            ]
            .contains(&lane),
            "lane must be one of the documented values, got: {lane}"
        );
        assert_eq!(
            expected,
            match lane {
                "dormant (not compiled)" => SIGNATURE_DORMANT_LINE,
                _ => SIGNATURE_LINE,
            }
        );
    }

    /// NIGHT-dinner-4 contract: the two retired lines stay retired.
    /// `Architecture:` moved its story into the Signature line and
    /// docs/COSMIC_DRAGON_ARCHITECTURE.md; `eBPF objects:` moved its
    /// lane disclosure into `zelynic doctor`. Either string coming
    /// back is a silent revert of a deliberate owner call and fails
    /// here, not in the wild.
    #[test]
    fn retired_architecture_and_ebpf_objects_lines_stay_retired() {
        let body = version_body();
        for retired in ["Architecture: ", "eBPF objects: "] {
            assert!(
                !body.lines().any(|l| l.starts_with(retired)),
                "retired line must not return: {retired}"
            );
        }
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
