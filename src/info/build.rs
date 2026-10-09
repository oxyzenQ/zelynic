// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The build-facts lane (night-improve-66's split, the theme.rs →
//! terminal_bg.rs precedent): everything the binary knows about its
//! own construction lives here — the canonical build label chain
//! (build_target → build_string → build_label, the cosmostrix
//! lineage), the git-sha and build-time stamps build.rs injects,
//! and the doctor's BUILD block ([`BuildInfo`]).
//!
//! Split rationale: info/mod.rs rode the 600-line law's ceiling the
//! moment the BUILD block joined (the version report + its pins on
//! one side, the build-facts lane on the other); a cohesive sibling
//! module gives both files headroom. The version report consumes
//! this lane through `pub(crate)` re-exports in the parent; the
//! capability doctor serializes [`BuildInfo`] directly.

use serde::{Deserialize, Serialize};

/// `CARGO_PKG_VERSION` — the crate version this binary was cut from.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── The doctor's BUILD block (night-improve-66) ────────────────────────────
//
// The capability doctor led its report with the flavor/lane verdict
// alone (NIGHT-dinner-3) — the binary answered "what can I do?" but
// stayed silent on "which exact artifact am I?". The cosmostrix
// diagnostics report (the mature reference) carries a full BUILD
// section: version, git_sha, variant, rustc_version, the profile
// facts. This block ports that completeness into zelynic's lean
// single-column shape: every field below is compile-time truth that
// already rode the binary (CARGO_PKG_VERSION, GIT_HASH,
// ZELYNIC_BUILD, ZELYNIC_BUILD_TIME) or joins it here
// (ZELYNIC_RUSTC_VERSION, ZELYNIC_PROFILE, ZELYNIC_OPT_LEVEL —
// stamped by build.rs). No runtime probing, no new dependencies,
// no bloat — just the facts an owner needs before trusting a
// downloaded binary.

/// The rustc that compiled this binary (night-improve-66), stamped
/// by build.rs from the `RUSTC` env cargo itself drives —
/// "rustc 1.98.1 (48a229cea 2026-09-01)" shape, or "unknown" only
/// when the compiler could not answer `--version` (which cannot
/// produce a binary either).
fn rustc_version() -> &'static str {
    option_env!("ZELYNIC_RUSTC_VERSION").unwrap_or("unknown")
}

/// The cargo profile mode this binary was built through
/// (night-improve-66): "release" or "debug", stamped by build.rs
/// from cargo's own PROFILE env — compile-time truth, never a
/// runtime guess. The "unknown" fallback only guards a build
/// without build.rs stamping (which fails anyway).
fn profile_mode() -> &'static str {
    option_env!("ZELYNIC_PROFILE").unwrap_or("unknown")
}

/// The actual optimization level cargo used (night-improve-66):
/// "3" for the shipping release contract, "0" for development
/// builds. Stamped by build.rs from cargo's OPT_LEVEL env — the
/// real number, so a RUSTFLAGS override shows up honestly.
fn opt_level() -> &'static str {
    option_env!("ZELYNIC_OPT_LEVEL").unwrap_or("?")
}

/// The [profile.release] contract as ONE composed literal
/// (night-improve-66): the four facts cargo exposes no env for,
/// read off Cargo.toml's pinned section and drift-guarded by the
/// `release_profile_consts_pin_the_manifest_contract` test below —
/// if the manifest changes, the test fails before the doctor can
/// report a stale contract. Rendered only for release builds; a
/// debug build must not claim the release contract (see
/// [`profile_line`]).
const RELEASE_PROFILE_CONTRACT: &str = "lto=fat, codegen-units=1, panic=unwind, strip=yes";

/// The one-line profile verdict for the doctor's BUILD block
/// (night-improve-66). Release builds state the full contract —
/// mode, the actual opt-level cargo used, then the pinned
/// optimization facts. Every other mode (debug, unknown) states
/// what it is WITHOUT claiming the release contract: a development
/// build reporting "lto=fat" would be the exact provenance lie the
/// claims discipline (QA.md) forbids.
fn profile_line() -> String {
    match profile_mode() {
        "release" => format!(
            "release, opt-level={}, {RELEASE_PROFILE_CONTRACT}",
            opt_level()
        ),
        other => format!(
            "{other}, opt-level={} (not the release contract)",
            opt_level()
        ),
    }
}

/// The build facts the doctor reports on text and JSON
/// (night-improve-66) — the cosmostrix BUILD completeness, zelynic
/// lean. Machine scope mirrors the human scope field-for-field so
/// the two surfaces can never drift apart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildInfo {
    /// The crate version this binary was cut from (raw semver, no
    /// "v" — the human report adds the brand prefix).
    pub version: String,
    /// The commit this binary was built from (7-hex git sha, the
    /// version report's own chain: git -> GITHUB_SHA -> registry
    /// .cargo_vcs_info.json; "unknown" only when every lane failed).
    pub git_sha: String,
    /// The canonical build label — `ZELYNIC_BUILD` (the release
    /// matrix platform id, e.g. "linux-amd64-v3-gnu") or the
    /// detected arch+libc fallback for plain builds.
    pub variant: String,
    /// The UTC build timestamp (Hinnant algorithm, no time crate).
    pub build_time: String,
    /// The rustc that compiled the userspace binary (see
    /// [`rustc_version`]).
    pub rustc_version: String,
    /// The one-line profile verdict (see [`profile_line`]).
    pub profile: String,
}

impl BuildInfo {
    /// Collect the compile-time build facts. Every field is already
    /// baked into the binary — this is assembly, not probing.
    pub(crate) fn collect() -> Self {
        Self {
            version: VERSION.to_string(),
            git_sha: build_hash().to_string(),
            variant: build_label(),
            build_time: build_time().to_string(),
            rustc_version: rustc_version().to_string(),
            profile: profile_line(),
        }
    }
}

// ── The canonical build label chain (cosmostrix lineage) ───────────────────

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
pub(crate) fn build_label() -> String {
    match option_env!("ZELYNIC_BUILD") {
        Some(label) if !label.is_empty() => label.to_string(),
        _ => build_string(),
    }
}

/// Get the git commit hash injected at build time by build.rs.
pub(crate) fn build_hash() -> &'static str {
    option_env!("GIT_HASH").unwrap_or("unknown")
}

/// Get the build timestamp injected at build time by build.rs.
///
/// Computed by Howard Hinnant's civil_from_days algorithm inside
/// build.rs (NIGHT-hunt-6, cosmostrix lineage) — `M/D/YYYY HH:MM (UTC)`
/// — so no time crate (chrono and friends) is needed anywhere in the
/// dependency tree. Falls back to "unknown" only when the build script
/// could not read the system clock (pre-UNIX_EPOCH host clock).
pub(crate) fn build_time() -> &'static str {
    option_env!("ZELYNIC_BUILD_TIME").unwrap_or("unknown")
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

    /// night-improve-66 contract: the BUILD block's rustc fact is the
    /// full "rustc X.Y.Z (...)" shape (or the documented degraded
    /// "unknown") — never empty, never a bare version number, so the
    /// doctor's provenance line is machine-parseable and honest.
    #[test]
    fn rustc_version_is_the_full_shape_or_unknown() {
        let v = rustc_version();
        if v == "unknown" {
            return; // degraded path, documented
        }
        assert!(v.starts_with("rustc "), "must lead with the tool name: {v}");
        assert!(v.contains('('), "must carry the hash-date suffix: {v}");
    }

    /// night-improve-66 contract: the profile verdict states the release
    /// contract ONLY for release builds — every other mode says what it
    /// is and explicitly declines the contract. A debug build claiming
    /// "lto=fat" would be the provenance lie the claims discipline
    /// forbids; a release build missing the contract would be silence
    /// where the owner asked for completeness.
    #[test]
    fn profile_line_claims_the_release_contract_only_in_release() {
        let line = profile_line();
        match profile_mode() {
            "release" => {
                assert!(line.starts_with("release, opt-level="), "got: {line}");
                for fact in ["lto=fat", "codegen-units=1", "panic=unwind", "strip=yes"] {
                    assert!(line.contains(fact), "release must state `{fact}`: {line}");
                }
            }
            other => {
                assert!(line.contains(other), "the mode must be stated: {line}");
                assert!(
                    !line.contains("lto=fat"),
                    "a non-release build must not claim the release contract: {line}"
                );
            }
        }
    }

    /// night-improve-66 drift guard: RELEASE_PROFILE_CONTRACT is a
    /// hand-pinned literal, so a future Cargo.toml profile change MUST
    /// land here too or this test fails — the doctor reports the
    /// manifest's truth, never a stale memory of it. The section slice
    /// is everything between `[profile.release]` and the next section
    /// header; the tokens are the exact `key = value` shapes the
    /// manifest writes (comments ride along, they do not collide).
    #[test]
    fn release_profile_consts_pin_the_manifest_contract() {
        let manifest = include_str!("../../Cargo.toml");
        let profile_section = manifest
            .split("[profile.release]")
            .nth(1)
            .expect("[profile.release] section exists in the root manifest")
            .split('[')
            .next()
            .unwrap_or_default();
        for pinned in [
            "opt-level = 3",
            "lto = \"fat\"",
            "codegen-units = 1",
            "panic = \"unwind\"",
            "strip = true",
        ] {
            assert!(
                profile_section.contains(pinned),
                "the release-profile contract drifted: [profile.release] no longer carries `{pinned}` — update RELEASE_PROFILE_CONTRACT in lockstep"
            );
        }
    }

    /// night-improve-66 contract: the doctor's BUILD block is complete —
    /// every field populated (the degraded "unknown" lanes are honest
    /// values, never empty strings), and the JSON surface carries the
    /// same six keys the human report renders.
    #[test]
    fn build_info_is_complete_and_serializes_the_documented_keys() {
        let info = BuildInfo::collect();
        for field in [
            &info.version,
            &info.git_sha,
            &info.variant,
            &info.build_time,
            &info.rustc_version,
            &info.profile,
        ] {
            assert!(!field.is_empty(), "no BUILD field may be empty: {info:?}");
        }
        let json = serde_json::to_string(&info).unwrap();
        for key in [
            "version",
            "git_sha",
            "variant",
            "build_time",
            "rustc_version",
            "profile",
        ] {
            assert!(
                json.contains(&format!("\"{key}\"")),
                "key `{key}` must ride the JSON: {json}"
            );
        }
    }

    /// night-improve-66 contract: the version fact is the raw semver
    /// (no "v" prefix — the human report adds the brand prefix, the
    /// machine scope stays semver-clean for tooling).
    #[test]
    fn build_info_version_is_raw_semver() {
        let v = BuildInfo::collect().version;
        assert!(!v.starts_with('v'), "raw semver, no brand prefix: {v}");
        assert!(
            v.split('.').count() >= 3,
            "X.Y.Z shape (pre-release suffix allowed): {v}"
        );
    }
}
