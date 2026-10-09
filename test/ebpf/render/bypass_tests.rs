// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

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
