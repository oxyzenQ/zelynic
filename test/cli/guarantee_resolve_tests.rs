// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! improve-40 (schema v24) / improve-40-b (the per-direction
//! spellings): the guarantee resolution's wording pins — the
//! validation ladder's every rung, judged by its exact error (the
//! parse-before-execute contract's own evidence: what the owner
//! reads BEFORE the root ask), plus the pass shapes (the one-flag
//! law setting both directions' rows, the per-direction spellings
//! setting one, the zero sentinel for unset sides, the force-this
//! override riding the rate family's ladder).

use super::{resolve_guarantee, BracketFlags};
use crate::ebpf::limiter::{BracketPair, RateSpec};

/// A both-directions spec at the given rates.
fn spec(dl: Option<u64>, ul: Option<u64>) -> RateSpec {
    RateSpec {
        download: dl,
        upload: ul,
    }
}

/// The one-flag spelling's flags (`--floor`/`--ceil` only).
fn both<'a>(floor: Option<&'a str>, ceil: Option<&'a str>) -> BracketFlags<'a> {
    BracketFlags {
        floor,
        ceil,
        ..BracketFlags::default()
    }
}

/// The pass shape: one flag, both directions' rows, the values the
/// apply family writes — and the zero sentinel for unset sides.
#[test]
fn one_flag_sets_both_directions_rows() {
    let bracket = resolve_guarantee(
        both(Some("100kb"), Some("300kb")),
        &spec(Some(1_000_000), Some(500_000)),
        false,
        false,
    )
    .expect("a well-formed bracket resolves");
    assert_eq!(bracket.download.floor_bps, 100_000);
    assert_eq!(bracket.download.ceil_bps, 300_000);
    assert_eq!(bracket.upload.floor_bps, 100_000);
    assert_eq!(bracket.upload.ceil_bps, 300_000);

    let bracket = resolve_guarantee(both(None, None), &spec(Some(1_000_000), None), false, false)
        .expect("an absent bracket is the zero sentinel");
    assert!(
        bracket.download == BracketPair::UNSET && bracket.upload == BracketPair::UNSET,
        "unset sides are 0, the fail-open sentinel"
    );
}

/// improve-40-b's pass shape: the per-direction spellings set ONE
/// direction's pair each — the asymmetric link's floor, judged on
/// its own row (a per-direction ceiling may ride the other
/// direction's untouched rate).
#[test]
fn the_per_direction_spellings_set_one_row_each() {
    let flags = BracketFlags {
        floor_download: Some("100kb"),
        ceil_download: Some("300kb"),
        floor_upload: Some("50kb"),
        ceil_upload: Some("200kb"),
        ..BracketFlags::default()
    };
    let bracket = resolve_guarantee(flags, &spec(Some(1_000_000), Some(500_000)), false, false)
        .expect("the asymmetric bracket resolves");
    assert_eq!(bracket.download.floor_bps, 100_000);
    assert_eq!(bracket.download.ceil_bps, 300_000);
    assert_eq!(bracket.upload.floor_bps, 50_000);
    assert_eq!(bracket.upload.ceil_bps, 200_000);
}

/// The mixed spellings compose: a both-directions floor beside a
/// per-direction ceiling — one spelling per SIDE, the law's own
/// seam (`--floor` + `--ceil-download` never collide).
#[test]
fn the_mixed_spellings_compose_per_side() {
    let flags = BracketFlags {
        floor: Some("100kb"),
        ceil_download: Some("400kb"),
        ..BracketFlags::default()
    };
    let bracket = resolve_guarantee(flags, &spec(Some(1_000_000), Some(500_000)), false, false)
        .expect("one spelling per side composes");
    assert_eq!(bracket.download.floor_bps, 100_000);
    assert_eq!(bracket.download.ceil_bps, 400_000);
    assert_eq!(bracket.upload.floor_bps, 100_000);
    assert_eq!(bracket.upload.ceil_bps, 0, "the upload ceiling is unset");
}

/// A floor equal to its rate is the whole-pool guarantee — the
/// boundary is legal (each leaf may use the full budget when it is
/// the only asker); only ABOVE is a mis-typed rate.
#[test]
fn floor_equal_to_the_rate_is_legal() {
    let bracket = resolve_guarantee(
        both(Some("1mb"), None),
        &spec(Some(1_000_000), Some(1_000_000)),
        false,
        false,
    )
    .expect("the boundary resolves");
    assert_eq!(bracket.download.floor_bps, 1_000_000);
}

/// The scope call, first rung: the bracket is not offered beside
/// --per-socket, whatever the values would have been — the
/// per-direction spellings included (the same family, the same call).
#[test]
fn the_scope_call_rejects_per_socket() {
    let err = resolve_guarantee(
        both(Some("100kb"), None),
        &spec(Some(1_000_000), None),
        false,
        true,
    )
    .expect_err("the combination is rejected");
    let msg = format!("{err:#}");
    assert!(msg.contains("subprocess leaves"), "the lane named: {msg}");
    assert!(msg.contains("--per-socket"), "the flag named: {msg}");

    let flags = BracketFlags {
        floor_download: Some("100kb"),
        ..BracketFlags::default()
    };
    let err = resolve_guarantee(flags, &spec(Some(1_000_000), None), false, true)
        .expect_err("the per-direction spelling rides the same scope call");
    assert!(
        format!("{err:#}").contains("--per-socket"),
        "the per-direction spelling names the flag too"
    );
}

/// improve-40-b's one-spelling rung: the both-directions flag and
/// its per-direction twins never combine — a combined spelling is a
/// mis-typed rate, not a wider guarantee.
#[test]
fn the_one_spelling_call_rejects_the_combination() {
    let flags = BracketFlags {
        floor: Some("100kb"),
        floor_download: Some("200kb"),
        ..BracketFlags::default()
    };
    let err = resolve_guarantee(flags, &spec(Some(1_000_000), None), false, false)
        .expect_err("the floor spellings collide");
    let msg = format!("{err:#}");
    assert!(msg.contains("one spelling apart"), "the law named: {msg}");
    assert!(msg.contains("--floor-download"), "the twin named: {msg}");

    let flags = BracketFlags {
        ceil: Some("300kb"),
        ceil_upload: Some("200kb"),
        ..BracketFlags::default()
    };
    let err = resolve_guarantee(flags, &spec(Some(1_000_000), Some(500_000)), false, false)
        .expect_err("the ceil spellings collide");
    assert!(
        format!("{err:#}").contains("one spelling apart"),
        "the ceil twin rides the same rung"
    );
}

/// improve-40-b's removed-direction rung: a per-direction side
/// whose direction the invocation REMOVES (no rate, so no row)
/// refuses before the root ask — a guarantee for a row that will
/// not exist is a mistake, not an intent.
#[test]
fn the_removed_direction_refuses_its_per_direction_side() {
    let flags = BracketFlags {
        floor_download: Some("100kb"),
        ..BracketFlags::default()
    };
    let err = resolve_guarantee(flags, &spec(None, Some(500_000)), false, false)
        .expect_err("no download row will exist");
    let msg = format!("{err:#}");
    assert!(msg.contains("--floor-download"), "the flag named: {msg}");
    assert!(msg.contains("REMOVED"), "the improve-29 law named: {msg}");

    let flags = BracketFlags {
        ceil_upload: Some("200kb"),
        ..BracketFlags::default()
    };
    let err = resolve_guarantee(flags, &spec(Some(1_000_000), None), false, false)
        .expect_err("no upload row will exist");
    assert!(
        format!("{err:#}").contains("--ceil-upload"),
        "the upload twin rides the same rung"
    );
}

/// The contradiction: a floor above a ceiling, unkeepable in any
/// arithmetic that respects the cap — judged PER DIRECTION now (the
/// per-direction spelling names its own row).
#[test]
fn the_contradiction_is_rejected() {
    let err = resolve_guarantee(
        both(Some("200kb"), Some("100kb")),
        &spec(Some(1_000_000), Some(1_000_000)),
        false,
        false,
    )
    .expect_err("floor above ceil");
    let msg = format!("{err:#}");
    assert!(msg.contains("20000"), "the floor's number: {msg}");
    assert!(msg.contains("10000"), "the ceiling's number: {msg}");
    assert!(msg.contains("contradiction"), "the law named: {msg}");

    // The per-direction shape: a download floor above a download
    // ceiling, the upload pair untouched and legal on its own.
    let flags = BracketFlags {
        floor_download: Some("200kb"),
        ceil_download: Some("100kb"),
        ..BracketFlags::default()
    };
    let err = resolve_guarantee(flags, &spec(Some(1_000_000), Some(1_000_000)), false, false)
        .expect_err("the download row's own contradiction");
    let msg = format!("{err:#}");
    assert!(msg.contains("download"), "the row named: {msg}");
    assert!(msg.contains("contradiction"), "the law named: {msg}");
}

/// A ceiling above the rate never binds — and the error names the
/// DIRECTION it could not honor (the one-flag law: both rows carry
/// the bracket, both rates must be able to honor it).
#[test]
fn a_ceiling_above_the_rate_never_binds() {
    let err = resolve_guarantee(
        both(None, Some("2mb")),
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
        both(Some("600kb"), None),
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
    let bracket = resolve_guarantee(
        both(Some("400kb"), Some("900kb")),
        &spec(Some(1_000_000), None),
        false,
        false,
    )
    .expect("the removal-bound upload is not the bracket's question");
    assert_eq!(bracket.download.floor_bps, 400_000);
    assert_eq!(bracket.download.ceil_bps, 900_000);
    // The removal-bound upload keeps the pair the one-flag law
    // resolves (it lands on no row — the rate family owns the
    // removal); the per-direction spelling for a removed direction
    // is the rung above's own refusal.
    assert_eq!(bracket.upload.floor_bps, 400_000);
}

/// The grammar rides the rate family's own ladder: a typo'd bracket
/// surfaces the parser's tip, and the 1kb floor asks --force-this
/// exactly like a rate would.
#[test]
fn the_grammar_rides_the_rate_ladder() {
    let err = resolve_guarantee(
        both(Some("not-a-rate"), None),
        &spec(Some(1_000_000), None),
        false,
        false,
    )
    .expect_err("the parser owns the typo");
    assert!(format!("{err:#}").to_lowercase().contains("rate"));

    let err = resolve_guarantee(
        both(Some("500"), None),
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

    let bracket = resolve_guarantee(
        both(Some("500"), None),
        &spec(Some(1_000_000), None),
        true,
        false,
    )
    .expect("force-this overrides the bracket's floor too");
    assert_eq!(
        bracket.download.floor_bps, 500,
        "the override rides the same ladder"
    );
}
