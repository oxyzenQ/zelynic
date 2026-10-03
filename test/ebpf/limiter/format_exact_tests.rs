// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The exact-twin and comma-lane pins (NIGHT-hunt-Z7, the owner's
//! `-d 100.51kb` and `100,50kb` finds): the config-surface formatters
//! that round-trip through the production grammar, and the number
//! layer's comma diagnosis. One theme, one file: the one-decimal
//! formatter and parser pins live in format_tests.rs.

use super::*;
// The parser bridge, same as the sibling pin file.
use crate::ebpf::limiter::{parse_rate, parse_time_duration};

// ── NIGHT-hunt-Z7: the exact twins (config surfaces) + the comma
//    lanes (the owner's `100,50kb` and `-d 100.51kb` finds) ─────────

/// The exact twins render what the kernel enforces: minimal decimals
/// that round-trip, one-decimal shape when one decimal is already
/// exact, and the honest-tier walk that never rounds UP into the
/// next unit (the one-decimal twin's 999.95 promotion edge).
#[test]
fn test_format_bytes_exact_minimal_digits() {
    // The owner's typed rate: 100.51kb = 100,510 B/s — the
    // one-decimal twin said "100.5 KB" and hid 10 B/s.
    assert_eq!(format_bytes_exact(100_510), "100.51 KB");
    // The GSO burst floor: every byte of the kernel's constant.
    assert_eq!(format_bytes_exact(65_536), "65.536 KB");
    // Round values keep the one-decimal family shape.
    assert_eq!(format_bytes_exact(100_000), "100.0 KB");
    assert_eq!(format_bytes_exact(1_000_000), "1.0 MB");
    assert_eq!(format_bytes_exact(1_000_000_000_000), "1.0 TB");
    // The B tier stays integer; sub-1000 values never gain a unit.
    assert_eq!(format_bytes_exact(500), "500 B");
    assert_eq!(format_bytes_exact(1_005), "1.005 KB");
    // The honest-tier walk: 999,950 stays in KB (never "1.0 MB").
    assert_eq!(format_bytes_exact(999_950), "999.95 KB");
    assert_eq!(format_bytes_exact(999_999), "999.999 KB");
    // The GB tier's deep fraction — 9 digits, inside the cap.
    assert_eq!(format_bytes_exact(1_000_000_001), "1.000000001 GB");
    // The u64 extreme's non-terminating remainder: the exact B
    // fallback, total honesty over compactness.
    assert_eq!(format_bytes_exact(u64::MAX), "18446744073709551615 B");
    // The rate twin keeps the BLOCKED sentinel at 0 (a CONFIGURED 0
    // is the block verdict; measured zeros are "0 B/s" elsewhere).
    assert_eq!(format_rate_exact(0), "BLOCKED");
    assert_eq!(format_rate_exact(100_510), "100.51 KB/s");
}

/// THE contract, as one property: for a spread of values across
/// every tier and the owner's own transcript figures, the exact
/// rate twin's rendering parses back through the PRODUCTION parser
/// to exactly the integer it came from — display and grammar are
/// one round-trip, pinned.
#[test]
fn test_format_rate_exact_round_trips_through_parse_rate() {
    let spread = [
        1_u64,
        500,
        999,
        1_000,
        1_005,
        65_536,
        100_000,
        100_510,
        999_950,
        999_999,
        1_000_000,
        1_000_500,
        5_500_000,
        1_000_000_001,
        750_000_000_000,
        1_000_000_000_000,
    ];
    for value in spread {
        let rendered = format_rate_exact(value);
        // The parser wants lowercase units; the display is uppercase
        // SI — the round-trip crosses at the case boundary.
        let parseable = rendered.to_lowercase().replace("/s", "");
        let parsed =
            parse_rate(&parseable).unwrap_or_else(|e| panic!("'{rendered}' must round-trip: {e}"));
        assert_eq!(
            parsed, value,
            "the exact rendering must parse back to itself ('{rendered}')"
        );
    }
}

/// The comma lanes (NIGHT-hunt-Z7, the owner's `100,50kb` find): a
/// comma-carrying number fails with the repair that names its shape
/// — the locale decimal separator gets the dot form, the thousands
/// grouping gets the separator removal (the dot suggestion would
/// silently scale `1,000` 1000x), and the malformed rest gets the
/// crime named without a fabricated repair.
#[test]
fn test_comma_carrying_rates_get_their_own_repairs() {
    // The owner's shape: `100,50kb` — the locale decimal separator.
    let err = format!("{}", parse_rate("100,50kb").unwrap_err());
    assert!(
        err.contains("use '.' as the decimal separator, not ','"),
        "the separator crime is named, got: {err}"
    );
    assert!(
        err.contains("write '100.50'"),
        "the dot-form repair is suggested, got: {err}"
    );
    assert!(
        !err.contains("expected digits before the decimal point"),
        "the generic digits message never rides a comma, got: {err}"
    );
    // The thousands grouping: `1,000kb` — remove, never re-dot.
    let grouped = format!("{}", parse_rate("1,000kb").unwrap_err());
    assert!(
        grouped.contains("remove the thousands separator"),
        "the grouping crime is named, got: {grouped}"
    );
    assert!(
        grouped.contains("write '1000'"),
        "the separator-removal repair is suggested, got: {grouped}"
    );
    assert!(
        !grouped.contains("write '1.000'"),
        "the dot suggestion would scale the value 1000x, got: {grouped}"
    );
    // A leading comma: `,5kb` — the dot form gains its zero.
    let leading = format!("{}", parse_rate(",5kb").unwrap_err());
    assert!(
        leading.contains("write '0.5'"),
        "the leading comma's repair carries its zero, got: {leading}"
    );
    // The malformed rest: no fabricated repair.
    let messy = format!("{}", parse_rate("1,2,3kb").unwrap_err());
    assert!(
        messy.contains("no commas"),
        "the multi-comma shape names the rule, got: {messy}"
    );
    // The duration grammar shares the number layer — its comma
    // shapes get the same repairs with their own surface wording.
    let dur = format!("{}", parse_time_duration("1,5h").unwrap_err());
    assert!(
        dur.contains("use '.' as the decimal separator, not ','"),
        "the duration twin carries the same repair, got: {dur}"
    );
}
