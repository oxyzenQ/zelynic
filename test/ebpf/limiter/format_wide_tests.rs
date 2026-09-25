// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The wide-ladder pins for format_bytes_wide (NIGHT-lts-5, the
//! server long-endurance ask — "harden and robust for future when
//! reach limit of zelynic like possible 1 zettabyte ZB even
//! quettabyte QB"): the u128 twin of the SI ladder, for the session
//! accounting's surfaces. The u64 formatter keeps its 7-tier
//! honesty (it never renders a tier u64 cannot reach); the wide
//! twin walks the full 2019 SI prefix list to quetta-.

use crate::ebpf::limiter::format_bytes_wide;

/// The zettabyte tier is real now: the exact ZB edge promotes, and
/// a session figure past it renders "1.0 ZB" — the tier the u64
/// ladder could never honestly print. The promotion edge rides the
/// same 999.95 discipline the u64 ladder uses (999.9499... ZB
/// stays, 999.95 ZB promotes to YB).
#[test]
fn the_zettabyte_tier_is_real() {
    assert_eq!(format_bytes_wide(10_u128.pow(21)), "1.0 ZB");
    // 999.9499 ZB: the largest figure that still reads 999.9 ZB.
    assert_eq!(
        format_bytes_wide(999_949 * 10_u128.pow(18) + 999_999_999_999_999_874),
        "999.9 ZB"
    );
    // 999.95 ZB: the round-half-up crosses into the next tier.
    assert_eq!(format_bytes_wide(999_950 * 10_u128.pow(18)), "1.0 YB");
}

/// The full modern ladder: yotta-, ronna-, quetta- — the 2019 SI
/// extension's own tiers, each promoting at the same 999.95 edge
/// the u64 ladder uses.
#[test]
fn the_ladder_reaches_quettabyte() {
    assert_eq!(format_bytes_wide(10_u128.pow(24)), "1.0 YB");
    assert_eq!(format_bytes_wide(10_u128.pow(27)), "1.0 RB");
    assert_eq!(format_bytes_wide(10_u128.pow(30)), "1.0 QB");
    assert_eq!(format_bytes_wide(2 * 10_u128.pow(30)), "2.0 QB");
}

/// The ceiling's honesty: u128::MAX renders the exact QB count,
/// uncapped — the contract past 999.9 QB is "exact", not
/// "8 columns" (a value that large is ~31,700 years of 1-Tbps
/// traffic; the wide integer's job is the figure, not the column).
#[test]
fn the_ceiling_renders_the_exact_quettabyte_count() {
    assert_eq!(format_bytes_wide(u128::MAX), "340282366.9 QB");
}

/// The lower tiers are the u64 ladder, byte-identical: every u64
/// figure formats the same through the wide twin (the session
/// surface renders small totals exactly as before — a regression
/// here would repaint every desktop frame).
#[test]
fn the_lower_tiers_match_the_u64_ladder() {
    assert_eq!(format_bytes_wide(500), "500 B");
    assert_eq!(format_bytes_wide(1_500), "1.5 KB");
    assert_eq!(format_bytes_wide(999_950), "1.0 MB");
    assert_eq!(format_bytes_wide(1_500_000_000_000), "1.5 TB");
    assert_eq!(format_bytes_wide(u64::MAX.into()), "18.4 EB");
}
