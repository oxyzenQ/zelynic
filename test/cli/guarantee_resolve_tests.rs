// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! improve-40 (schema v24): the guarantee resolution's wording pins
//! — the validation ladder's every rung, judged by its exact error
//! (the parse-before-execute contract's own evidence: what the
//! owner reads BEFORE the root ask), plus the pass shapes (the one
//! flag setting both directions' rows, the zero sentinel for unset
//! sides, the force-this override riding the rate family's ladder).

use super::resolve_guarantee;
use crate::ebpf::limiter::RateSpec;

/// A both-directions spec at the given rates.
fn spec(dl: Option<u64>, ul: Option<u64>) -> RateSpec {
    RateSpec {
        download: dl,
        upload: ul,
    }
}

/// The pass shape: one flag, both directions' rows, the values the
/// apply family writes — and the zero sentinel for unset sides.
#[test]
fn one_flag_sets_both_directions_rows() {
    let (f, c) = resolve_guarantee(
        Some("100kb"),
        Some("300kb"),
        &spec(Some(1_000_000), Some(500_000)),
        false,
        false,
    )
    .expect("a well-formed bracket resolves");
    assert_eq!(f, 100_000);
    assert_eq!(c, 300_000);

    let (f, c) = resolve_guarantee(None, None, &spec(Some(1_000_000), None), false, false)
        .expect("an absent bracket is the zero sentinel");
    assert_eq!((f, c), (0, 0), "unset sides are 0, the fail-open sentinel");
}

/// A floor equal to its rate is the whole-pool guarantee — the
/// boundary is legal (each leaf may use the full budget when it is
/// the only asker); only ABOVE is a mis-typed rate.
#[test]
fn floor_equal_to_the_rate_is_legal() {
    let (f, _) = resolve_guarantee(
        Some("1mb"),
        None,
        &spec(Some(1_000_000), Some(1_000_000)),
        false,
        false,
    )
    .expect("the boundary resolves");
    assert_eq!(f, 1_000_000);
}

/// The scope call, first rung: the bracket is not offered beside
/// --per-socket, whatever the values would have been.
#[test]
fn the_scope_call_rejects_per_socket() {
    let err = resolve_guarantee(
        Some("100kb"),
        None,
        &spec(Some(1_000_000), None),
        false,
        true,
    )
    .expect_err("the combination is rejected");
    let msg = format!("{err:#}");
    assert!(msg.contains("subprocess leaves"), "the lane named: {msg}");
    assert!(msg.contains("--per-socket"), "the flag named: {msg}");
}

/// The contradiction: a floor above a ceiling, unkeepable in any
/// arithmetic that respects the cap.
#[test]
fn the_contradiction_is_rejected() {
    let err = resolve_guarantee(
        Some("200kb"),
        Some("100kb"),
        &spec(Some(1_000_000), Some(1_000_000)),
        false,
        false,
    )
    .expect_err("floor above ceil");
    let msg = format!("{err:#}");
    assert!(msg.contains("20000"), "the floor's number: {msg}");
    assert!(msg.contains("10000"), "the ceiling's number: {msg}");
    assert!(msg.contains("contradiction"), "the law named: {msg}");
}

/// A ceiling above the rate never binds — and the error names the
/// DIRECTION it could not honor (the one-flag law: both rows carry
/// the bracket, both rates must be able to honor it).
#[test]
fn a_ceiling_above_the_rate_never_binds() {
    let err = resolve_guarantee(
        None,
        Some("2mb"),
        &spec(Some(1_000_000), Some(500_000)),
        false,
        false,
    )
    .expect_err("ceil above the smaller rate");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("download"),
        "the binding direction named: {msg}"
    );
    assert!(msg.contains("never binds"), "the law named: {msg}");
}

/// The floor's own never-binding rung, on the upload side (the
/// per-direction check walks both).
#[test]
fn a_floor_above_the_rate_never_binds() {
    let err = resolve_guarantee(
        Some("600kb"),
        None,
        &spec(Some(1_000_000), Some(500_000)),
        false,
        false,
    )
    .expect_err("floor above the upload rate");
    let msg = format!("{err:#}");
    assert!(msg.contains("upload"), "the binding direction named: {msg}");
    assert!(msg.contains("could never bind"), "the law named: {msg}");
}

/// A direction the invocation removes (the improve-29 law) is not
/// consulted — the bracket validates against the rows that will
/// exist, not the legs being torn down.
#[test]
fn the_unset_direction_is_not_consulted() {
    let (f, c) = resolve_guarantee(
        Some("400kb"),
        Some("900kb"),
        &spec(Some(1_000_000), None),
        false,
        false,
    )
    .expect("the removal-bound upload is not the bracket's question");
    assert_eq!((f, c), (400_000, 900_000));
}

/// The grammar rides the rate family's own ladder: a typo'd bracket
/// surfaces the parser's tip, and the 1kb floor asks --force-this
/// exactly like a rate would.
#[test]
fn the_grammar_rides_the_rate_ladder() {
    let err = resolve_guarantee(
        Some("not-a-rate"),
        None,
        &spec(Some(1_000_000), None),
        false,
        false,
    )
    .expect_err("the parser owns the typo");
    assert!(format!("{err:#}").to_lowercase().contains("rate"));

    let err = resolve_guarantee(
        Some("500"),
        None,
        &spec(Some(1_000_000), None),
        false,
        false,
    )
    .expect_err("sub-1kb asks the override");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("below minimum"),
        "the rate family's own floor: {msg}"
    );

    let (f, _) = resolve_guarantee(Some("500"), None, &spec(Some(1_000_000), None), true, false)
        .expect("force-this overrides the bracket's floor too");
    assert_eq!(f, 500, "the override rides the same ladder");
}
