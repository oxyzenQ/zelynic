// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! OSC 11 answer parser pins (NIGHT-boost-26) — the pure core of the
//! terminal-background query. The answer shapes are the ones real
//! terminals send: 16-bit-per-channel `rgb:` (the xterm default),
//! short forms (VTE), `rgba:` with an alpha leg (kitty), each
//! terminated by BEL or ST. The parser must scale each channel by
//! its OWN digit width — mixing widths is legal per spec.
//!
//! NIGHT-boost-32 adds the live-follow pins: `reply_front` (the
//! complete-reply scan) and `BgAsk::absorb` (the tracker that
//! consumes an answer riding the input stream across chunks, hands
//! the leftover bytes back for key classification, and bounds
//! garbled input by patience and cap). `Instant` inputs are
//! synthetic — the state machine is pure given the clock.

use super::*;
use crate::terminal::InputAction;

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

// ── NIGHT-boost-32: the live follow ────────────────────────────────────────

/// One canonical answer at the front: the length runs THROUGH the
/// terminator (the leftover starts clean), the color parses, and
/// trailing key bytes ride after it untouched.
#[test]
fn reply_front_spans_through_the_terminator() {
    let bytes = b"\x1b]11;rgb:2e2e/2e2e/2e2e\x07q";
    let (len, color) = reply_front(bytes).expect("complete reply");
    assert_eq!(len, 24);
    assert_eq!(color, Some((46, 46, 46)));
    assert_eq!(&bytes[len..], b"q");
}

/// The ST twin: the terminator is two bytes (ESC backslash), so the
/// span covers both.
#[test]
fn reply_front_counts_the_st_terminator() {
    let bytes = b"\x1b]11;rgb:1e1e/2c2c/3a3a\x1b\\";
    let (len, color) = reply_front(bytes).expect("complete reply");
    assert_eq!(len, bytes.len());
    assert_eq!(color, Some((30, 44, 58)));
}

/// An answer missing its terminator is NOT a reply yet: the tracker
/// accumulates, the scan says None. A non-answer head (a title set,
/// a CSI) is never a reply either.
#[test]
fn reply_front_requires_head_and_terminator() {
    assert_eq!(reply_front(b"\x1b]11;rgb:2e2e/2e2e"), None);
    assert_eq!(reply_front(b"\x1b]0;title\x07"), None);
    assert_eq!(reply_front(b"\x1b[<0;1;1M"), None);
    assert_eq!(reply_front(b"q"), None);
}

/// A garbled payload completes the SHAPE but parses to no color —
/// the caller keeps the last known good, never a fabricated one.
#[test]
fn reply_front_garbage_payload_is_shape_without_color() {
    let (len, color) = reply_front(b"\x1b]11;zz/00/00\x07").expect("shape complete");
    assert_eq!(color, None);
    assert_eq!(len, 14);
}

/// The split-answer + key contract: the reply lands across two
/// 64-byte wakes with a `q` riding its tail — the tracker consumes
/// the reply, and the leftover `q` still quits. The old fixed-read
/// drain swallowed exactly this key.
#[test]
fn absorb_split_reply_then_key_leftover_quits() {
    let mut ask = BgAsk::new();
    let now = std::time::Instant::now();
    let (action, color) = ask.absorb(b"\x1b]11;rgb:2e2e/2e", now);
    assert_eq!((action, color), (InputAction::None, None));
    let (action, color) = ask.absorb(b"2e/2e\x07q", now);
    assert_eq!(action, InputAction::Quit);
    assert_eq!(color, Some((46, 46, 46)));
    // The tracker is spent: the next chunk classifies fresh.
    let (action, color) = ask.absorb(b"t", now);
    assert_eq!((action, color), (InputAction::ThemeNext, None));
}

/// A late answer to an ask whose patience expired still parses —
/// the head shape is the truth, the deadline only bounds the
/// PARTIAL's lifetime.
#[test]
fn absorb_late_stray_answer_still_parses() {
    let mut ask = BgAsk::new();
    let now = std::time::Instant::now();
    let (action, color) = ask.absorb(b"\x1b]11;rgb:80/00/40\x07", now);
    assert_eq!(action, InputAction::None);
    assert_eq!(color, Some((128, 0, 64)));
}

/// Keys while nothing is in flight classify exactly as before —
/// the tracker is inert for plain input.
#[test]
fn absorb_plain_input_classifies_untouched() {
    let mut ask = BgAsk::new();
    let now = std::time::Instant::now();
    assert_eq!(ask.absorb(b"t", now).0, InputAction::ThemeNext);
    assert_eq!(ask.absorb(b"\x1b[<0;1;1M", now).0, InputAction::None);
    assert_eq!(ask.absorb(&[0x03], now).0, InputAction::None);
    assert_eq!(ask.absorb(b"", now).0, InputAction::None);
}

/// Patience expiry: an ask's partial that never completes is
/// dropped once its deadline passes, and the chunk that arrives
/// after the deadline classifies by its own leading byte — the
/// mid-reply bytes are inert input, never keys.
#[test]
fn absorb_patience_expiry_drops_the_partial() {
    let mut ask = BgAsk::new();
    let now = std::time::Instant::now();
    // Arm the patience directly — send() would write fd 1.
    ask.deadline = Some(now + BG_ASK_PATIENCE);
    let (action, _) = ask.absorb(b"\x1b]11;rgb:2e2e/2e", now);
    assert_eq!(action, InputAction::None);
    assert!(!ask.partial.is_empty());
    let past = now + BG_ASK_PATIENCE + std::time::Duration::from_millis(1);
    let (action, color) = ask.absorb(b"2e/2e\x07t", past);
    // The deadline dropped the stale partial — the chunk's own
    // leading byte ('2', mid-reply hex) classifies as plain input.
    assert_eq!((action, color), (InputAction::None, None));
    assert!(ask.partial.is_empty());
    let (action, _) = ask.absorb(b"t", past);
    assert_eq!(action, InputAction::ThemeNext);
}

/// The cap: a stream that starts with the reply head but never
/// terminates is garbage past the cap — the partial is dropped and
/// the next chunk's own leading byte classifies fresh.
#[test]
fn absorb_cap_drops_unterminated_garbage() {
    let mut ask = BgAsk::new();
    let now = std::time::Instant::now();
    // Arm the patience long — the CAP is the bound under test.
    ask.deadline = Some(now + std::time::Duration::from_secs(10));
    let mut junk = Vec::new();
    junk.extend_from_slice(b"\x1b]11;");
    junk.extend(std::iter::repeat_n(b'z', BG_PARTIAL_CAP));
    let (action, color) = ask.absorb(&junk, now);
    assert_eq!((action, color), (InputAction::None, None));
    assert!(ask.partial.is_empty());
    let (action, _) = ask.absorb(b"t", now);
    assert_eq!(action, InputAction::ThemeNext);
}
