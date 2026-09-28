// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-critical-infra-1 pins: the update-check cooldown — the
//! one implemented mitigation of the AI-agent-swarm threat model
//! (docs/SAFETY_ANALYSIS.md). Pure arithmetic, pure path
//! resolution, and a temp-file roundtrip on the fail-open read:
//! the swarm bound is one completed network exchange per hour per
//! user, and every broken state (absent, garbage, torn) must
//! resolve to "fetch allowed", never to a suppressed check.

use super::*;

/// The window math: Some(remaining) strictly inside the hour,
/// None at and past the boundary — the fetch is allowed exactly
/// when the window has fully elapsed, and Some(0) never escapes
/// (the caller's `if let Some` arm is the whole throttle
/// decision).
#[test]
fn cooldown_remaining_binds_one_fetch_per_window() {
    assert_eq!(
        cooldown_remaining(1000, 1000),
        Some(3600),
        "a fresh stamp (fetched this second) must hold the full window"
    );
    assert_eq!(
        cooldown_remaining(1000, 700),
        Some(3300),
        "300 seconds elapsed, 3300 remain"
    );
    assert_eq!(
        cooldown_remaining(1000, 999),
        Some(3599),
        "fetched one second ago: 3599 remain"
    );
    assert_eq!(
        cooldown_remaining(3600, 0),
        None,
        "exactly one window elapsed: the boundary belongs to the allowed side"
    );
    assert_eq!(
        cooldown_remaining(3601, 0),
        None,
        "one second past the boundary: allowed"
    );
    assert_eq!(
        cooldown_remaining(100_000, 0),
        None,
        "long-past stamp: allowed"
    );
}

/// A future stamp (clock skew, or the documented /tmp plant)
/// saturates the age to zero and holds the full window — the
/// suppression is the accepted, DISCLOSED risk of the /tmp lane;
/// the verdict line tells the operator how much remains.
#[test]
fn future_stamp_holds_the_full_window() {
    assert_eq!(
        cooldown_remaining(1000, 5000),
        Some(3600),
        "a future stamp must not open the window"
    );
}

/// The stamp path: XDG_RUNTIME_DIR lane when set (per-user 0700
/// tmpfs), /tmp uid-suffixed fallback when not. The lanes must
/// never collide across users.
#[test]
fn stamp_path_resolves_both_lanes() {
    let xdg = stamp_path(Some("/run/user/1001"), 1001);
    assert_eq!(
        xdg,
        PathBuf::from("/run/user/1001/zelynic-update.stamp"),
        "the XDG lane names the per-user runtime dir, got: {xdg:?}"
    );

    let tmp = stamp_path(None, 1001);
    assert_eq!(
        tmp,
        PathBuf::from("/tmp/.zelynic-update-1001"),
        "the fallback carries the uid, got: {tmp:?}"
    );

    // The empty-string XDG is treated as unset (login managers can
    // hand an empty value; the /tmp lane is the honest answer).
    let empty = stamp_path(Some(""), 1001);
    assert_eq!(
        empty,
        PathBuf::from("/tmp/.zelynic-update-1001"),
        "an empty XDG value must fall back, got: {empty:?}"
    );

    // Different users never share a /tmp stamp.
    assert_ne!(
        stamp_path(None, 1001),
        stamp_path(None, 1002),
        "the uid suffix exists so users do not share throttle state"
    );
}

/// The fail-open roundtrip: an absent file reads as None, a
/// written stamp reads back, and GARBAGE reads as None — the read
/// side never turns a broken stamp into a suppressed check.
#[test]
fn stamp_roundtrip_is_fail_open() {
    let dir = std::env::temp_dir().join(format!(
        "zelynic-cooldown-test-{}-{}",
        std::process::id(),
        line!()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("zelynic-update.stamp");

    assert_eq!(
        read_stamp(&path),
        None,
        "absent stamp: fetch allowed (fail-open)"
    );

    write_stamp(&path, 123_456);
    assert_eq!(
        read_stamp(&path),
        Some(123_456),
        "a written stamp reads back exactly"
    );

    std::fs::write(&path, "not a number").expect("plant garbage");
    assert_eq!(
        read_stamp(&path),
        None,
        "garbage stamp: fetch allowed (fail-open)"
    );

    std::fs::write(&path, "  987  \n").expect("plant padded stamp");
    assert_eq!(
        read_stamp(&path),
        Some(987),
        "whitespace padding is tolerated (a torn write must not wedge the surface)"
    );

    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir(&dir);
}
