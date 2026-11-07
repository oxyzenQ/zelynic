// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! Pins for the bypass audit's report section
//! (NIGHT-upgrade-charger-core-1-a): the one-glance shapes the depth
//! report prints after the per-target blocks — the compact clean line,
//! the flagged block with both sides' figures and the triage tail,
//! and the honest unavailability line.

use super::*;

use crate::ebpf::bypass::{
    NicTotals, SHADOW_RX_FLOOR_BYTES, SHADOW_TX_FLOOR_BYTES, ShadowVerdict, shadow_audit,
};

/// A clean window renders ONE line that says the check ran and agrees,
/// with both sides' residual share — the fact the owner asked for,
/// spent on no furniture.
#[test]
fn clean_window_is_one_line_with_both_shares() {
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 1_000_000,
            rx_bytes: 1_000_000,
        }),
        980_000,
        960_000,
        3,
    );
    let lines = bypass_section(&audit);
    assert_eq!(lines.len(), 1, "clean is one line, got {lines:?}");
    let plain: String = strip_ansi(&lines[0]);
    assert!(
        plain.contains("bypass audit:") && plain.contains("clean"),
        "the line names the check and the verdict, got: {plain}"
    );
    assert!(
        plain.contains("tx shadow 2%") && plain.contains("rx shadow 4%"),
        "both sides' shares ride the line, got: {plain}"
    );
    // night-ux-3 (the live run's tx 0% / rx 100% window): this
    // fixture's shadows (20 KB / 40 KB) sit under the absolute
    // floors, so the honest basis is the QUIET-WINDOW wording — the
    // floor held, not the band. "under 25%/40% thresholds" beside
    // these shares would be the false claim night-ux-3 retires.
    assert!(
        plain.contains("quiet window"),
        "a floor-bound clean names the quiet window, got: {plain}"
    );
    assert!(
        plain.contains("under 1 MiB tx / 2 MiB rx floor"),
        "the clean line names the floor it sat under, got: {plain}"
    );
}

/// night-ux-1's shape survives on a window with real traffic: shadows
/// above the floors with shares inside the bands print the band — the
/// thresholds ride the line from the same constants the verdict was
/// computed from (night-ux-3: this is now the BOTH-sides-above-floor
/// arm, not the only clean shape).
#[test]
fn band_clean_window_names_the_thresholds() {
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 100_000_000,
            rx_bytes: 100_000_000,
        }),
        80_000_000,
        70_000_000,
        3,
    );
    assert_eq!(audit.verdict, ShadowVerdict::Clean);
    let plain = strip_ansi(&bypass_section(&audit)[0]);
    assert!(
        plain.contains("under 25%/40% thresholds"),
        "a band-bound clean names the thresholds it cleared, got: {plain}"
    );
    assert!(
        plain.contains("tx shadow 20%") && plain.contains("rx shadow 30%"),
        "both sides' shares ride the line, got: {plain}"
    );
    assert!(
        !plain.contains("quiet window"),
        "a band-bound clean is not a quiet window, got: {plain}"
    );
}

/// night-ux-3's mixed windows: one side floor-bound, the other
/// band-bound — the line names EACH side's own basis, never a band
/// claim over a floor-bound side (the false wording the live run's
/// 100% rx share exposed, one side at a time).
#[test]
fn mixed_windows_name_each_side_basis() {
    // tx quiet (20 KB shadow, under the 1 MiB floor), rx band-clean
    // (35 MB shadow, 35% — above the 2 MiB floor, under the 40% band).
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 1_000_000,
            rx_bytes: 100_000_000,
        }),
        980_000,
        65_000_000,
        3,
    );
    assert_eq!(audit.verdict, ShadowVerdict::Clean);
    let plain = strip_ansi(&bypass_section(&audit)[0]);
    assert!(
        plain.contains("tx under 1 MiB floor; rx under 40% thresholds"),
        "the mixed line names each side's basis, got: {plain}"
    );

    // The mirror: tx band-clean (20%, above the floor), rx quiet
    // (500 KB shadow, under the 2 MiB floor).
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 100_000_000,
            rx_bytes: 2_000_000,
        }),
        80_000_000,
        1_500_000,
        3,
    );
    assert_eq!(audit.verdict, ShadowVerdict::Clean);
    let plain = strip_ansi(&bypass_section(&audit)[0]);
    assert!(
        plain.contains("tx under 25% thresholds; rx under 2 MiB floor"),
        "the mirror mixed line names each side's basis, got: {plain}"
    );
}

/// The flagged block carries every figure a triage needs: the window,
/// both sides' interface and hook numbers, the shadow with its share,
/// the likely paths, and the triage command — a flag without the
/// "what now" just moves the anxiety.
#[test]
fn flagged_window_prints_the_full_triage_block() {
    let audit = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: SHADOW_TX_FLOOR_BYTES + 4_700_000,
            rx_bytes: 0,
        }),
        100_000,
        0,
        3,
    );
    assert_eq!(audit.verdict, ShadowVerdict::BypassedTx);
    let lines = bypass_section(&audit);
    let joined: Vec<String> = lines.iter().map(|l| strip_ansi(l)).collect();
    let text = joined.join("\n");
    assert!(
        text.contains("BYPASS-SHAPED TRAFFIC DETECTED — tx side"),
        "the header names the side, got: {text}"
    );
    for row in [
        "window:",
        "interfaces:",
        "cgroup hooks:",
        "shadow:",
        "likely paths:",
        "triage:",
    ] {
        assert!(
            text.contains(row),
            "the block carries the {row} row, got: {text}"
        );
    }
    assert!(
        text.contains("cannot see or shape"),
        "the shadow row says what the gap means, got: {text}"
    );
    assert!(
        text.contains("'ss -etu'"),
        "the triage row names a command, got: {text}"
    );
}

/// Both sides flagged names both, and the rx-only shape names rx —
/// the side is the one fact the header owes.
#[test]
fn the_verdict_names_its_side() {
    let both = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: SHADOW_TX_FLOOR_BYTES + 5_000_000,
            rx_bytes: SHADOW_RX_FLOOR_BYTES + 5_000_000,
        }),
        0,
        0,
        3,
    );
    assert_eq!(both.verdict, ShadowVerdict::BypassedBoth);
    let lines = bypass_section(&both);
    let header = strip_ansi(&lines[0]);
    assert!(
        header.contains("tx + rx"),
        "the both-side header names both, got: {header}"
    );

    let rx = shadow_audit(
        Some(NicTotals::default()),
        Some(NicTotals {
            tx_bytes: 0,
            rx_bytes: SHADOW_RX_FLOOR_BYTES + 5_000_000,
        }),
        0,
        0,
        3,
    );
    let lines = bypass_section(&rx);
    assert!(
        strip_ansi(&lines[0]).contains("— rx side"),
        "the rx shape names rx, got: {}",
        lines[0]
    );
}

/// The unavailable shape says so in one line — a window that measured
/// fine against unreadable counters is a named state, never a silent
/// clean and never a missing section.
#[test]
fn unavailable_window_says_so() {
    let audit = shadow_audit(None, None, 1_000, 2_000, 3);
    let lines = bypass_section(&audit);
    assert_eq!(lines.len(), 1);
    let plain = strip_ansi(&lines[0]);
    assert!(
        plain.contains("unavailable") && plain.contains("interface counters unreadable"),
        "the line names the failure, got: {plain}"
    );
    assert!(
        plain.contains("window measured fine"),
        "the line separates the audit failure from the traffic measurement, got: {plain}"
    );
}

/// Strip the ANSI escapes so the pins assert content, not color codes
/// (the color layer is the output module's own pinned surface).
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for skip in chars.by_ref() {
                if skip == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
