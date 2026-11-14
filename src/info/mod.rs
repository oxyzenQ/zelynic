// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

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
mod signature;

pub use build::BuildInfo;
pub use build::VERSION;
pub(crate) use build::{build_hash, build_label, build_time};
pub(crate) use signature::{identity_of, manifest_fingerprint, provenance_view};
// The materialized identity core feeds only the ebpf-gated engraving
// footer (status stamp + eagle-eyes engraving) — a dormant build
// renders no footer, so the accessor's re-export rides the same gate
// or the dormant lane fails -D warnings on the dead surface.
#[cfg(feature = "ebpf")]
pub(crate) use signature::materialized_identity_core;

pub const NAME: &str = "zelynic";
pub const REPOSITORY: &str = "https://github.com/oxyzenQ/zelynic";
pub const DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// The `License:` line as ONE contiguous literal (NIGHT-blade-4).
///
/// release.yml's AVX-512 (v4) legs verify the artifact WITHOUT
/// executing it — the runner may lack the baseline, so `strings`
/// must find "License: AGPL-3.0-only" as contiguous bytes in the
/// rodata. A format! inline capture (`{LICENSE}`) splits the line:
/// the template keeps "License: " and the bare id "AGPL-3.0-only"
/// lands elsewhere in rodata, and the strings probe failed on both
/// v4 legs (the v11.0.0-beta.2 release incident). This const IS the
/// whole line, so the bytes stay contiguous by construction; the
/// unit tests below pin the exact bytes the pipeline greps. (The
/// pre-blade-4 `pub const LICENSE` — the bare id, consumed only by
/// the old inline capture — was removed with the capture: zero
/// call sites left, the dependency-audit discipline.)
const LICENSE_LINE: &str = "License: AGPL-3.0-only";

// The `Signature:` line source (night-signature-advanced-1): the
// lane-honest manifest is NO LONGER a plaintext literal — the former
// `SIGNATURE_LINE` / `SIGNATURE_DORMANT_LINE` consts carried the
// ownership claim as greppable bytes (strings(1) or rg over the
// artifact found "Official Build by rezky_nightky (oxyzenQ)" and
// handed a thief the mark on a plate, the night-signature-1 gap the
// owner named). The manifest now materializes at runtime from the
// masked layers in [`signature`] — at rest the artifact carries only
// opaque integers, and the release pipeline's strings probe verifies
// the ABSENCE of the identity (the negative probe) instead of its
// presence. The claims discipline (QA.md) is unchanged: the manifest
// this report displays is the lane-honest one, chosen by the same
// stamp law [`ebpf_lane`] documents, and the "License:" line keeps
// its NIGHT-blade-4 contiguous-literal discipline — that line claims
// no identity, so it stays plaintext for the AVX-512 legs.
//
// The Depth-matrix line (night-signature-advanced-1, the owner's
// green mark): the masked scheme's status surface, rendered from the
// same single provenance pass — `fp=<fingerprint>` (the active
// manifest's FNV-1a 64, dual-layer with the authors digest),
// `status=verified|tampered`, `anchor=b3:<blake3>` (the 256-bit seal
// over all three masked layers), and the four storage-layer tokens.
// The line is the one body line the owner marked for color — the
// estate's status green (#50FA7B, the hacker-green tier) — while the
// rest of the body stays plain per the estate-parity law below.

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
fn signature_line() -> String {
    format!("Signature: {}", provenance_view().manifest)
}

/// The plain-text body of the version report (everything after the
/// brand header). Separated from [`print_version_report`] so tests can
/// assert the full line set without capturing stdout.
fn version_body() -> String {
    let provenance = provenance_view();
    // The one body line the owner marked for color
    // (night-signature-advanced-1): the Depth-matrix status line rides
    // the estate's status green — the hacker-green tier — while every
    // sibling line stays plain per the estate-parity law. ok() wraps
    // one line (the color layer refuses multi-line wraps) and degrades
    // to plain text when the capability says so.
    let depth_line = crate::output::ok(&provenance.depth_line);
    format!(
        "Build: {} ({})\n\
         Build-time: {}\n\
         {}\n\
         {depth_line}\n\
         Copyright: (c) 2026 {}\n\
         {LICENSE_LINE}\n\
         Source: {REPOSITORY}",
        build_label(),
        build_hash(),
        build_time(),
        signature_line(),
        provenance.authors,
    )
}

/// Print the full version report for `-V` / `--version`.
///
/// cosmostrix masterclass layout: brand header (name + version, then
/// the one-line description), followed by plain build facts. **Plain
/// is a law, not a default (night-dragon-maintenance-8):** the body
/// rides the terminal's default color — the estate siblings
/// (zejtron, zylaxion, cosmostrix) print their build facts
/// uncolored, and a field report caught the whole body grey below
/// the description when a single grey() wrap spanned the six lines
/// (one SGR open, six painted lines). The color layer now refuses a
/// multi-line wrap in debug builds, and the only color decision this
/// report makes — the brand-wrapped two-line header — lives in
/// [`version_report_payload`], pinned by test. The
/// header is rendered in brand purple #A855F7 (regular weight,
/// exactly as the cosmostrix `version_report()` does) on a TTY,
/// degrading through 256-color/16-color tiers; when piped (non-TTY)
/// everything is plain text so ANSI codes never leak into scripts or
/// log files. The Signature line stays on its own line so it is easy
/// to grep from scripts (`zelynic -V | grep Signature`).
///
/// ```text
/// zelynic: v80.2.0
/// Per-app network rate limiter and traffic monitor for Linux. Pure eBPF. Boring and silent.
/// Build: pro-linux-amd64-v3-musl (ad36a81)
/// Build-time: 2026-09-18 01:30Z
/// Signature: Pure eBPF builtin — Official Build by rezky_nightky (oxyzenQ) 2026
/// Depth-matrix: fp=a60dfb6a39745f34 status=verified anchor=b3:dbcbb0eb... layers=d0:masked-words,d1:masked-words,d2:dual-fingerprint,d3:blake3-anchor
/// Copyright: (c) 2026 rezky_nightky (oxyzenQ) <with dot rezky at gmail dot com>
/// License: AGPL-3.0-only
/// Source: https://github.com/oxyzenQ/zelynic
/// ```
///
/// (The Signature and Depth-matrix values above are the RUNTIME
/// materialization of the masked layers — the artifact itself carries
/// only opaque integers; see [`signature`]. The Depth-matrix line
/// renders in the estate's status green on a TTY, plain when piped.)
///
/// The `Build:` line carries the canonical label from [`build_label`]:
/// `local-pro-native-musl` etc. for local alias builds (the alias
/// name under the `local-` marker), `pro-<platform id>` for release
/// binaries a user downloaded (the estate `pro-` prefix, no
/// `local-`), and `local-` + the detected `linux-<arch>-<libc>`
/// string for plain local builds (a crates.io install included). The
/// `Build-time:` line (NIGHT-hunt-6, cosmostrix parity) is stamped by
/// build.rs via the Hinnant civil-from-days algorithm — ISO 8601
/// `YYYY-MM-DD HH:MMZ` (night-pro-1, the estate-wide format), UTC-only, so
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
    let (header, body) = version_report_payload();
    println_safe!("{header}");
    println_safe!("{body}");
}

/// The `-V` payload in its two terminal shapes, separated so the
/// color law is testable without capturing stdout (the
/// [`version_body`] precedent): the brand-wrapped header lines and
/// the PLAIN build-facts body. Each header line carries its own
/// brand wrap — the single-line law (the two-line header was a
/// second latent instance the choke point caught the day it landed);
/// the body carries no color wrap by construction, so the
/// estate-parity law (default terminal color below the description)
/// cannot regress at the print site.
fn version_report_payload() -> (String, String) {
    (
        format!(
            "{}\n{}",
            crate::output::brand(&format!("{NAME}: v{VERSION}")),
            crate::output::brand(DESCRIPTION),
        ),
        version_body(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    /// night-dragon-maintenance-8 contract: the version report's body
    /// reaches the terminal in the DEFAULT terminal color — the estate
    /// siblings (zejtron, zylaxion, cosmostrix) print their build
    /// facts plain, and the field report was the whole body grey
    /// below the description (one grey() wrap spanning six lines).
    /// The payload pins the split: the body carries no ANSI escape
    /// bytes at all, on every color capability, and the brand header
    /// is the only colored surface this report emits.
    #[test]
    fn version_report_body_color_law() {
        // night-dragon-maintenance-8 estate parity, as amended by the
        // owner's night-signature-advanced-1 green mark: the -V body
        // stays in the DEFAULT terminal color EXCEPT the one body line
        // the owner marked — the Depth-matrix status line, which rides
        // the estate's status green on a color-capable surface. The
        // law's mechanical shape: every line except the Depth-matrix
        // line carries zero ANSI escapes (the color layer's
        // single-line-wrap refusal keeps one painted line from
        // bleeding into its siblings); the Depth-matrix line itself is
        // the only line allowed to carry them, and whether it does is
        // the color capability's call (plain when piped/mono).
        let (_header, body) = version_report_payload();
        for line in body.lines() {
            if line.starts_with("Depth-matrix: ") {
                continue;
            }
            assert!(
                !line.contains('\x1b'),
                "only the Depth-matrix line may carry color — this line leaked escapes: {line}"
            );
        }
    }

    /// NIGHT-blade-4 contract: the license line exists as ONE
    /// contiguous literal (LICENSE_LINE) — the release pipeline's
    /// AVX-512 legs grep exactly those bytes out of `strings` on
    /// artifacts whose baseline the runner cannot execute. The
    /// literal is pinned verbatim here so a drifted line fails in
    /// the unit run, not on a release day.
    #[test]
    fn license_line_is_the_contiguous_bytes_the_release_probe_greps() {
        assert_eq!(LICENSE_LINE, "License: AGPL-3.0-only");
    }

    /// NIGHT-hunt-6 contract: the version report carries the Build-time
    /// line between Build and Copyright (cosmostrix parity), and every
    /// documented line is present exactly once.
    #[test]
    fn version_report_carries_build_time_line() {
        let body = version_body();
        for line in [
            "Build-time: ",
            "Copyright: (c) 2026 rezky_nightky (oxyzenQ) <with dot rezky at gmail dot com>",
            "License: AGPL-3.0-only",
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
        let lines: Vec<&str> = body.lines().collect();
        let time_idx = lines
            .iter()
            .position(|l| l.starts_with("Build-time: "))
            .expect("Build-time line present");
        // The Signature line materializes from the masked layers and
        // must be the lane-honest one: the dormant stamp — and only
        // it — flips the claim (night-signature-advanced-1 keeps the
        // NIGHT-dinner-4 law; only the at-rest encoding changed).
        let expected = signature_line();
        assert_eq!(
            lines[time_idx + 1],
            expected,
            "the Signature line must follow Build-time"
        );
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
        let claim = expected
            .strip_prefix("Signature: ")
            .and_then(|rest| rest.split_once(" — "))
            .map(|(head, _)| head)
            .expect("Signature line carries the claim prefix");
        assert_eq!(
            claim,
            match lane {
                "dormant (not compiled)" => "eBPF dormant",
                _ => "Pure eBPF builtin",
            }
        );
        // The materialized manifest carries the owner identity and the
        // year (the runtime surface the masked layers exist to feed).
        assert!(
            expected.ends_with("Official Build by rezky_nightky (oxyzenQ) 2026"),
            "the materialized manifest must end with the owner identity: {expected}"
        );
    }

    /// night-signature-advanced-1 contract: the Depth-matrix line sits
    /// directly after the Signature line, exactly once, and carries the
    /// four token groups in order (fp, status, anchor, layers). This is
    /// the surface a script greps (`zelynic -V | grep Depth-matrix`),
    /// so its shape is pinned like the License line's.
    #[test]
    fn depth_matrix_line_is_pinned_after_signature() {
        let body = version_body();
        let lines: Vec<&str> = body.lines().collect();
        let sig_idx = lines
            .iter()
            .position(|l| l.starts_with("Signature: "))
            .expect("Signature line present");
        let depth = lines.get(sig_idx + 1).copied().unwrap_or("");
        assert!(
            depth.contains("Depth-matrix: "),
            "depth line follows Signature: {depth}"
        );
        let count = body
            .lines()
            .filter(|l| l.contains("Depth-matrix: "))
            .count();
        assert_eq!(count, 1, "the Depth-matrix line must appear exactly once");
        // Token order: fp, then status, then anchor, then layers.
        let fp_pos = depth.find(" fp=").expect("fp token");
        let status_pos = depth.find(" status=").expect("status token");
        let anchor_pos = depth.find(" anchor=b3:").expect("anchor token");
        let layers_pos = depth.find(" layers=").expect("layers token");
        assert!(fp_pos < status_pos && status_pos < anchor_pos && anchor_pos < layers_pos);
        assert!(depth.ends_with(
            "layers=d0:masked-words,d1:masked-words,d2:dual-fingerprint,d3:blake3-anchor"
        ));
    }

    /// night-signature-advanced-1 contract: the Copyright line carries
    /// the materialized authors string — the same single provenance
    /// pass the Signature line rides — exactly once, in its documented
    /// position after the Depth-matrix line.
    #[test]
    fn copyright_line_is_pinned_after_depth_matrix() {
        let body = version_body();
        let lines: Vec<&str> = body.lines().collect();
        let depth_idx = lines
            .iter()
            .position(|l| l.contains("Depth-matrix: "))
            .expect("Depth-matrix line present");
        assert!(
            lines[depth_idx + 1].starts_with("Copyright: (c) 2026 rezky_nightky (oxyzenQ) <with dot rezky at gmail dot com>"),
            "Copyright must follow Depth-matrix, got: {}",
            lines[depth_idx + 1]
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
    /// time) or matches the ISO 8601 `YYYY-MM-DD HH:MMZ` shape
    /// (night-pro-1, the estate-wide format) with a plausible year.
    /// A malformed stamp (e.g. an accidental local-time format with
    /// an offset suffix) fails here, not in the wild.
    #[test]
    fn build_time_stamp_shape_is_iso8601_yyyy_mm_dd_hh_mm_z() {
        let stamp = build_time();
        if stamp == "unknown" {
            return; // degraded path, documented
        }
        assert!(stamp.ends_with('Z'), "stamp must carry the Z suffix: {stamp}");
        let core = stamp.strip_suffix('Z').expect("suffix checked above");
        // Shape: YYYY-MM-DD then space then HH:MM (2-digit, zero-padded).
        let (date, time) = core
            .split_once(' ')
            .unwrap_or_else(|| panic!("date and time must be space-separated: {stamp}"));
        let date_parts: Vec<&str> = date.split('-').collect();
        assert_eq!(date_parts.len(), 3, "date must be YYYY-MM-DD: {stamp}");
        let (year, month, day) = (
            date_parts[0].parse::<u32>().unwrap_or(0),
            date_parts[1].parse::<u32>().unwrap_or(0),
            date_parts[2].parse::<u32>().unwrap_or(0),
        );
        assert_eq!(date_parts[0].len(), 4, "year must be 4 digits: {stamp}");
        assert_eq!(date_parts[1].len(), 2, "month must be 2 digits: {stamp}");
        assert_eq!(date_parts[2].len(), 2, "day must be 2 digits: {stamp}");
        assert!(year >= 2026, "year implausibly old: {stamp}");
        assert!((1..=12).contains(&month), "month out of range: {stamp}");
        assert!((1..=31).contains(&day), "day out of range: {stamp}");
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
