// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The capability report's unit battery (night-frontier-Z5 moved it
//! here — the 600-era LOC law's pure move out of mod.rs, the tests
//! byte-identical): the doctor report's contracts, the JSON field
//! law (additive, the pins and build precedents), the flavor and
//! lane verdicts, and the ladder field's honesty pins.

use super::*;

#[test]
fn test_detect_does_not_panic() {
    // detect() should never panic, even in restricted environments.
    let report = detect();
    // We can't assert specific values (depends on environment), but
    // the report should be well-formed.
    assert!(!report.system.kernel.is_empty());
    // night-netrunner-1: the floor verdict is always populated —
    // and it must always AGREE with the pure law on the actual
    // release string (a 5.10 sandbox host and a 6.18 dev rig both
    // detect honestly; the assertion is the law's consistency,
    // never a host assumption).
    assert_eq!(
        report.system.kernel_floor_met,
        crate::ebpf::kernel_floor::kernel_floor_error(&report.system.kernel).is_ok(),
        "floor verdict disagrees with the law on kernel {}",
        report.system.kernel
    );
    // NIGHT-dinner-3: the flavor and lane verdicts are always
    // populated — no environment can produce an empty answer.
    assert!(!report.build_flavor.is_empty());
    assert!(!report.ebpf_lane.is_empty());
    // night-improve-66: the BUILD block is always complete —
    // every field populated, never an empty string (the degraded
    // "unknown" lanes are honest values, not absences).
    let build = report.build.as_ref().expect("detect always collects");
    assert!(!build.version.is_empty());
    assert!(!build.git_sha.is_empty());
    assert!(!build.variant.is_empty());
    assert!(!build.build_time.is_empty());
    assert!(!build.rustc_version.is_empty());
    assert!(!build.profile.is_empty());
}

/// NIGHT-dinner-3: the flavor verdict is compile-time truth — it
/// must match the compiled feature set exactly, and the lane
/// stamp must be one of the three values build.rs can set (the
/// `option_env!` fallback matches the dormant stamp, so an
/// unstamped build is still in the set). This is the contract the
/// doctor's "Build:" line and the JSON surface both report.
#[test]
fn build_flavor_matches_the_compiled_feature_set() {
    if cfg!(feature = "ebpf") {
        assert_eq!(build_flavor(), BUILD_FLAVOR_FULL_LIFE);
    } else {
        assert_eq!(build_flavor(), BUILD_FLAVOR_HALF_LIFE);
    }
    assert!(
        matches!(
            crate::info::ebpf_lane(),
            "source-built" | "registry-prebuilt" | "dormant (not compiled)"
        ),
        "unexpected ZELYNIC_EBPF_LANE stamp: {}",
        crate::info::ebpf_lane()
    );
}

#[test]
fn test_capability_report_serializes() {
    let report = CapabilityReport {
        system: SystemInfo {
            kernel: "6.18.0".to_string(),
            kernel_floor_met: true,
            cgroup_v2: true,
            cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
            bpf_fs_mounted: true,
            is_root: false,
        },
        ebpf_supported: true,
        build_flavor: BUILD_FLAVOR_FULL_LIFE.to_string(),
        ebpf_lane: "source-built".to_string(),
        build: Some(crate::info::BuildInfo::collect()),
        warnings: vec![],
        pins: None,
    };
    let json = report_json(&report);
    assert!(json.contains("cgroup_v2"));
    assert!(json.contains("ebpf_supported"));
    // night-netrunner-1: the floor verdict is first-class JSON —
    // machine consumers get the same 5.15.0 law the human report
    // renders, without re-deriving it from the release string.
    assert!(json.contains("kernel_floor_met"));
    // NIGHT-dinner-3: the flavor verdict is first-class JSON —
    // machine consumers get the full-life/half-life answer and
    // the lane detail without re-encoding feature semantics.
    assert!(json.contains("build_flavor"));
    assert!(json.contains("full-life"));
    assert!(json.contains("ebpf_lane"));
    // night-improve-66: the BUILD block rides the JSON with the
    // same six keys the human report renders — machine consumers
    // get version/git_sha/variant/build_time/rustc_version/profile
    // without re-deriving them from the version report.
    assert!(json.contains("\"build\""));
    for key in [
        "\"version\"",
        "\"git_sha\"",
        "\"variant\"",
        "\"build_time\"",
        "\"rustc_version\"",
        "\"profile\"",
    ] {
        assert!(json.contains(key), "BUILD key {key} must ride: {json}");
    }
    // night-improve-64: a None verdict serializes as ABSENCE —
    // the additive rule (never a fabricated "clean").
    assert!(!json.contains("pins"));
    // night-frontier-Z5, additive: the per-helper capability
    // ladder's verdict rides the JSON — rungs/met/missed, the
    // same numbers the human report's "Helper ladder:" line
    // renders. On the 6.18 fixture the ladder is full (ten
    // rungs, none missed) and the missed array is honestly
    // empty.
    assert!(
        json.contains("\"ladder\":{\"rungs\":10,\"met\":10,\"missed\":[]}"),
        "the ladder verdict must ride: {json}"
    );
}

/// night-frontier-Z5: the ladder verdict is a pure function of
/// the release string — the JSON's met/missed numbers must agree
/// with the summary the human line renders, on a below-floor
/// fixture too (the 5.11 kernel misses exactly the atomic rung).
#[test]
fn ladder_verdicts_ride_the_release_string() {
    let mut report = CapabilityReport {
        system: SystemInfo {
            kernel: "5.11.0".to_string(),
            kernel_floor_met: false,
            cgroup_v2: true,
            cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
            bpf_fs_mounted: true,
            is_root: false,
        },
        ebpf_supported: false,
        build_flavor: BUILD_FLAVOR_FULL_LIFE.to_string(),
        ebpf_lane: "source-built".to_string(),
        build: Some(crate::info::BuildInfo::collect()),
        warnings: vec![],
        pins: None,
    };
    let json = report_json(&report);
    assert!(
        json.contains("\"ladder\":{\"rungs\":10,\"met\":9,"),
        "{json}"
    );
    assert!(json.contains("\"missed\":[\"bpf_atomic_64\"]"), "{json}");
    // An unparsable release reads met:0 with every rung absent
    // from `missed` — unprobeable is not missed (the honesty
    // law: the probe cannot verify, so it does not guess).
    report.system.kernel = "garbage-release".to_string();
    let json = report_json(&report);
    assert!(
        json.contains("\"ladder\":{\"rungs\":10,\"met\":0,\"missed\":[]}"),
        "{json}"
    );
}

/// NIGHT-dinner-3: a half-life report carries the install-path
/// warning — the diagnostic contract that makes the doctor's
/// verdict actionable instead of a bare label.
#[test]
fn half_life_report_carries_the_reinstall_warning() {
    let report = CapabilityReport {
        system: SystemInfo {
            kernel: "6.18.0".to_string(),
            kernel_floor_met: true,
            cgroup_v2: true,
            cgroup2_mount_path: Some("/sys/fs/cgroup".to_string()),
            bpf_fs_mounted: true,
            is_root: false,
        },
        ebpf_supported: true,
        build_flavor: BUILD_FLAVOR_HALF_LIFE.to_string(),
        ebpf_lane: "dormant (not compiled)".to_string(),
        build: Some(crate::info::BuildInfo::collect()),
        warnings: vec![],
        pins: None,
    };
    let json = report_json(&report);
    assert!(json.contains("half-life"));
}
