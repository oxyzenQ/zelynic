// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! OSC 11 answer parser pins (NIGHT-boost-26) — the pure core of the
//! terminal-background query. The answer shapes are the ones real
//! terminals send: 16-bit-per-channel `rgb:` (the xterm default),
//! short forms (VTE), `rgba:` with an alpha leg (kitty), each
//! terminated by BEL or ST. The parser must scale each channel by
//! its OWN digit width — mixing widths is legal per spec.

use super::*;

/// The canonical xterm form: 16-bit channels, BEL-terminated.
#[test]
fn parses_sixteen_bit_rgb_bel_terminated() {
    let answer = b"\x1b]11;rgb:2e2e/2e2e/2e2e\x07";
    assert_eq!(parse_osc_11_rgb(answer), Some((46, 46, 46)));
}

/// The ST-terminated twin (ESC-backslash instead of BEL).
#[test]
fn parses_st_terminated_answer() {
    let answer = b"\x1b]11;rgb:1e1e/2c2c/3a3a\x1b\\";
    assert_eq!(parse_osc_11_rgb(answer), Some((30, 44, 58)));
}

/// Short channels scale by their own width: `rgb:80/00/40` is the
/// 8-bit form (128, 0, 64), `rgb:f/0/c` the 4-bit form (255, 0, 204)
/// — a channel's full scale is its digit count, not a fixed 65535.
#[test]
fn scales_short_channels_by_their_own_width() {
    assert_eq!(parse_osc_11_rgb(b"rgb:80/00/40"), Some((128, 0, 64)));
    assert_eq!(parse_osc_11_rgb(b"rgb:f/0/c"), Some((255, 0, 204)));
}

/// The rgba: form (kitty): the alpha leg rides after the triple and
/// is ignored — the background query cares about RGB alone.
#[test]
fn ignores_the_rgba_alpha_leg() {
    assert_eq!(
        parse_osc_11_rgb(b"\x1b]11;rgba:ffff/0000/0000/ffff\x07"),
        Some((255, 0, 0))
    );
}

/// Mixed digit widths are legal: each channel scales independently.
#[test]
fn parses_mixed_digit_widths() {
    assert_eq!(parse_osc_11_rgb(b"rgb:ffff/80/f"), Some((255, 128, 255)));
}

/// Garbage stays garbage: a missing channel, an empty body, or a
/// non-hex payload is `None` — the frame then renders without a
/// background escape (the honest default, never a panic).
#[test]
fn garbage_answers_parse_to_none() {
    assert_eq!(parse_osc_11_rgb(b"\x1b]11;rgb:1/2\x07"), None);
    assert_eq!(parse_osc_11_rgb(b"\x1b]11;rgb:/00/00\x07"), None);
    assert_eq!(parse_osc_11_rgb(b"\x1b]0;title\x07"), None);
    assert_eq!(parse_osc_11_rgb(b""), None);
    assert_eq!(parse_osc_11_rgb(b"\x1b]11;rgb:zz/00/00\x07"), None);
}
