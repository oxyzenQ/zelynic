// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! format_count pins (NIGHT-engrave-7) — split from format_tests.rs
//! when the counter-explosion pins pushed that file past the owner's
//! LOC cap (one file per contract, the same discipline that split
//! the format pins out of the inline module at NIGHT-boost-15).
//! `use super::*` reaches the format module through the #[path]
//! wiring in src/ebpf/limiter/format.rs.

use super::*;

/// format_count (NIGHT-engrave-7, the counter-explosion hardening):
/// the owner's exact report — a monitor that opens on "24 packets"
/// reads "2244843 packets" eight hours later. The count ladder is
/// the byte ladder's mirror: decimal SI tiers, one decimal
/// everywhere above 1000, exact raw integers below, and the
/// tier-boundary promotion that never renders a four-digit cell.
#[test]
fn test_format_count_small_values_stay_exact() {
    // The fresh-start figures render verbatim — no unit, no decimal,
    // no punctuation. The owner's opening frame reads "24 packets".
    assert_eq!(format_count(0), "0");
    assert_eq!(format_count(1), "1");
    assert_eq!(format_count(24), "24");
    assert_eq!(format_count(999), "999");
}

#[test]
fn test_format_count_compacts_the_explosion() {
    // The eight-hour figure the owner reported: 2244843 -> "2.2M".
    assert_eq!(format_count(1000), "1.0K");
    assert_eq!(format_count(2_244_843), "2.2M");
    assert_eq!(format_count(1_000_000_000), "1.0G");
    // The honest u64 ceiling, one ladder step per three digits.
    assert_eq!(format_count(u64::MAX), "18.4E");
}

#[test]
fn test_format_count_promotes_at_the_rounding_boundary() {
    // The exact 999.95-of-a-unit threshold (the format_bytes
    // discipline): 999_949 renders "999.9K", 999_950 promotes to
    // "1.0M" — a four-digit cell is a ragged cell, and the compact
    // ladder exists to kill exactly that.
    assert_eq!(format_count(999_949), "999.9K");
    assert_eq!(format_count(999_950), "1.0M");
    // Same edge one tier up: 999_949_999 stays "999.9M".
    assert_eq!(format_count(999_949_999), "999.9M");
    assert_eq!(format_count(999_950_000), "1.0G");
}

#[test]
fn test_format_count_is_decimal_si_never_binary() {
    // 1 K = 1000, never 1024: the 1024th packet is "1.0K" already,
    // the 1_048_576th is "1.0M" — the same decimal contract
    // parse_rate and format_bytes carry (types.rs documents the old
    // 1024 disagreement this family retired).
    assert_eq!(format_count(1024), "1.0K");
    assert_eq!(format_count(1_048_576), "1.0M");
}
