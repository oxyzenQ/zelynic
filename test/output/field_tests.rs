// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The field-row primitive pins (night-dragon-maintenance-1, the
//! masterclass UX-consistency law): the doctor's geometry is the one
//! geometry — two-space indent, the label left-padded so the value
//! column starts at column 14, one primitive behind every banner
//! field surface (doctor, recover, update check, the pin block).
//! These pins hold the geometry so no future surface can drift it
//! back into hand-aligned literals.

use super::field;

/// The doctor's exact byte shape: `  Build:      ` is two spaces,
/// the 6-char label, six pad spaces — value at column 14.
#[test]
fn doctor_geometry_is_byte_exact() {
    assert_eq!(field("Build:", "FULL-LIFE"), "  Build:      FULL-LIFE");
    assert_eq!(field("Version:", "v80.0.0"), "  Version:    v80.0.0");
    assert_eq!(field("Kernel:", "6.1.0"), "  Kernel:     6.1.0");
}

/// The widest current label (`cgroup v2:`, ten chars) still pads to
/// the same column — the alignment the doctor's longest rows own.
#[test]
fn the_widest_label_still_lands_on_column_14() {
    let row = field("cgroup v2:", "YES");
    assert_eq!(row, "  cgroup v2:  YES");
    assert_eq!(row.find("YES"), Some(14), "value starts at column 14");
}

/// A label longer than the column degrades gracefully: one space
/// after the label, the value never swallowed.
#[test]
fn an_over_long_label_keeps_one_separator_space() {
    let row = field("ExtraLongLabel:", "x");
    assert_eq!(row, "  ExtraLongLabel: x");
    assert!(row.ends_with(" x"), "the value keeps one separating space");
}

/// Every label that reaches the primitive ends at the same value
/// column — the alignment contract the four surfaces share.
#[test]
fn every_current_banner_label_aligns_to_column_14() {
    for label in [
        "Build:",
        "Version:",
        "Commit:",
        "Variant:",
        "Built:",
        "Rustc:",
        "Profile:",
        "Kernel:",
        "cgroup v2:",
        "BPF fs:",
        "Root:",
        "eBPF:",
        "Pins:",
        "State:",
        "Action:",
        "Windows:",
        "Census:",
        "Orphans:",
        "Result:",
        "Cause:",
        "Next:",
        "Current:",
        "Latest:",
        "Status:",
        "Source:",
    ] {
        let row = field(label, "VAL");
        assert_eq!(
            &row[14..],
            "VAL",
            "label {label:?} must land its value at column 14"
        );
    }
}
