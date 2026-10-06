// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! improve-40-b: the per-direction bracket's read-surface pins —
//! the guarantee line's equal/split/one-sided shapes (the exact-twin
//! law's unchanged face, the split's direction-prefixed halves, the
//! unset half honestly absent) and the census's per-leg pair join
//! (each direction's policy row feeding its own pair). Split from
//! display_tests.rs when the pair pushed the parent past the 500-LOC
//! owner cap (the parse/format split precedent, one lane over).

use super::*;

/// improve-40-b: the guarantee line's per-direction shapes — the
/// one-flag line unchanged when the pairs are equal (the exact-twin
/// law's own face), the split line direction-prefixed when they
/// differ (only the set halves named — an unset direction is
/// honestly absent, never a fabricated zero), and no line at all
/// when neither side is set.
#[test]
fn guarantee_line_pins_the_per_direction_shapes() {
    use crate::ebpf::limiter::types::BracketPair;

    // The one-flag shape: equal pairs, the unchanged single line.
    let line = guarantee_line(
        BracketPair {
            floor_bps: 100_000,
            ceil_bps: 300_000,
        },
        BracketPair {
            floor_bps: 100_000,
            ceil_bps: 300_000,
        },
    )
    .expect("a set bracket renders");
    assert!(
        line.contains("guarantee: floor 100.0 KB/s ceil 300.0 KB/s (per subprocess)")
            && !line.contains("dl "),
        "the equal shape carries no direction prefix: {line}"
    );

    // The split shape: both directions' halves, each prefixed.
    let line = guarantee_line(
        BracketPair {
            floor_bps: 100_000,
            ceil_bps: 300_000,
        },
        BracketPair {
            floor_bps: 50_000,
            ceil_bps: 200_000,
        },
    )
    .expect("a split bracket renders");
    assert!(
        line.contains("dl floor 100.0 KB/s ceil 300.0 KB/s")
            && line.contains(" / ul floor 50.0 KB/s ceil 200.0 KB/s"),
        "the split names each direction's own pair: {line}"
    );

    // The one-sided shape: a download-only bracket (the per-direction
    // spelling on a removed-direction invocation), upload honestly
    // absent.
    let line = guarantee_line(
        BracketPair {
            floor_bps: 100_000,
            ceil_bps: 0,
        },
        BracketPair::UNSET,
    )
    .expect("a one-sided bracket renders");
    assert!(
        line.contains("dl floor 100.0 KB/s") && !line.contains("ul "),
        "only the set half is named: {line}"
    );

    // The unset shape: no line at all.
    assert!(
        guarantee_line(BracketPair::UNSET, BracketPair::UNSET).is_none(),
        "an unset bracket renders no line"
    );
}

/// improve-40-b: the census reads each leg's OWN pair — the
/// download policy row feeds the download pair, the upload row the
/// upload pair, the one-flag law's equal pairs a special case.
#[test]
fn collect_display_data_joins_the_bracket_per_direction() {
    let mut dl_row = PolicyRaw::default();
    dl_row.rate_bps = 1_000_000;
    dl_row.floor_bps = 100_000;
    dl_row.ceil_bps = 300_000;
    let mut ul_row = PolicyRaw::default();
    ul_row.rate_bps = 500_000;
    ul_row.floor_bps = 50_000;
    ul_row.ceil_bps = 200_000;
    let data = collect_display_data(&[(101u32, dl_row)], &[(101u32, ul_row)], &[], &[]);
    assert_eq!(data[0].download.floor_bps, 100_000);
    assert_eq!(data[0].download.ceil_bps, 300_000);
    assert_eq!(data[0].upload.floor_bps, 50_000);
    assert_eq!(data[0].upload.ceil_bps, 200_000);

    // A one-legged row: the absent direction's pair stays unset.
    let data = collect_display_data(&[(102u32, dl_row)], &[], &[], &[]);
    assert_eq!(data[0].download.floor_bps, 100_000);
    assert_eq!(
        data[0].upload,
        crate::ebpf::limiter::types::BracketPair::UNSET,
        "the absent leg's pair is the unset sentinel"
    );
}
