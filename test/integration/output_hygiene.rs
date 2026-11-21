// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! Output hygiene law (night-depth-infra-1): every CLI lane ends its
//! output with exactly one newline — never a doubled terminal newline,
//! never a trailing space or tab, never a doubled blank line — on both
//! the stdout and stderr lanes. The census that caught the sig
//! ladder's doubled terminal newline walked every rootless lane
//! byte-exactly and found it was the only offender; this battery pins
//! the law so the next emitter cannot regress it silently. Rootless
//! lanes only: the enforcement surface (strict, probe, the live
//! eagle-eyes frame) needs root + eBPF and rides the #[ignore]d rigs.

use crate::zelynic_cmd;

/// The rootless lanes: the surface every Linux session can drive.
/// The error paths are output too — the usage ladder, the unknown
/// command, the unknown flag — so they sit in the same battery.
const LANES: &[&[&str]] = &[
    &["-V"],
    &["--version"],
    &["--help"],
    &["help"],
    &["doctor"],
    &["doctor", "--print-json"],
    &["sig"],
    &["nonexistent-command"],
    &["strict"],
    &["doctor", "--bogus-flag"],
];

/// One lane, both byte lanes: exactly one terminal newline, no
/// trailing whitespace, no doubled blank line. Exit codes are the
/// lanes' own contracts (pinned elsewhere); this battery owns shape.
fn assert_lane_hygiene(lane: &[&str]) {
    let out = zelynic_cmd()
        .args(lane)
        .output()
        .unwrap_or_else(|e| panic!("lane {lane:?} failed to spawn: {e}"));
    for (name, bytes) in [("stdout", &out.stdout), ("stderr", &out.stderr)] {
        let text = String::from_utf8_lossy(bytes);
        if text.is_empty() {
            continue;
        }
        assert!(
            text.ends_with('\n') && !text.ends_with("\n\n"),
            "lane {lane:?} {name} must end with exactly one newline, tail: {:?}",
            &text[text.len().saturating_sub(12)..],
        );
        assert!(
            !text.contains("\n\n\n"),
            "lane {lane:?} {name} carries a doubled blank line",
        );
        for (idx, line) in text.lines().enumerate() {
            assert!(
                line.trim_end() == line,
                "lane {lane:?} {name} line {} carries trailing whitespace: {line:?}",
                idx + 1,
            );
        }
    }
}

#[test]
fn every_rootless_lane_ends_with_exactly_one_newline() {
    for lane in LANES {
        assert_lane_hygiene(lane);
    }
}

#[test]
fn the_sig_ladder_lands_on_its_note_line() {
    // The lane the census caught: the report's last line is the
    // self-hash note, and the doubled byte behind it is gone.
    let out = zelynic_cmd().arg("sig").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.ends_with("it cannot embed its own digest.\n"),
        "sig stdout must land on the self-hash note with one newline, tail: {:?}",
        &text[text.len().saturating_sub(64)..],
    );
}
