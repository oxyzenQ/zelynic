// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The terminal-following background (NIGHT-boost-26, live since
//! NIGHT-boost-32; its own module since NIGHT-dinner-30, when the
//! theme catalog's twelfth palette pushed theme.rs past the 500-line
//! LOC cap — the background follow is a sibling concern, not theme
//! state, and moved out whole).
//!
//! Owner contract: the frame's BACKGROUND follows the terminal, not
//! the builtin themes — a grey-themed terminal renders a grey frame,
//! grid/data/info keeping the FOREGROUND slots above. The value comes
//! from the OSC 11 query (open path + the live ask's cadence), so a
//! mid-session change is followed within one ask, never frozen at
//! the open-time color (the boost-32 regression). Unpainted depths
//! (Color16, Mono) and a silent terminal paint no background escape.

// The imports ride the same predicates as their users, split by
// family: the atomics and the capability probe serve only the
// `ebpf`-gated store/load items (the static, the setters and
// readers); ColorCapability also serves the `any(test, ebpf)`
// packing/encoding cores, so it stays reachable for the test-only
// lanes. Ungated the block dangles under --no-default-features —
// the using code is compiled out, the imports are not, and a
// -D warnings build reddens on the unused-import lint. This is
// the dinner-30 move's residue: the block's functions carried
// NIGHT-boost-34's dead-code wall with them, the imports did not,
// and in theme.rs they had also served ungated siblings that
// stayed behind (NIGHT-hunt-Z5 rider 2, the find the CI watch
// caught: the no-default-features test lane had been red on every
// fresh checkout since 406ada4 while local gates passed on cached
// builds and a flag-less lane).
#[cfg(feature = "ebpf")]
use std::sync::atomic::AtomicU32;
#[cfg(feature = "ebpf")]
use std::sync::atomic::Ordering;

#[cfg(any(test, feature = "ebpf"))]
use super::color::ColorCapability;
#[cfg(feature = "ebpf")]
use super::color::capability;

/// The queried background (NIGHT-boost-26, live since 32): one
/// atomic word — bit 31 the present flag, bits 23..0 `0xRRGGBB`,
/// lock-free live updates, `0` the honest no-answer default.
///
/// Gated behind the `ebpf` feature (NIGHT-boost-34, the dead-code
/// wall: the callers live in the ebpf tree, this module compiles
/// unconditionally, and a default-feature build saw the block as
/// dead code that CI's `-D warnings` reddened — green locally only
/// because the local gate runs without that flag). The pure packing
/// cores below stay `cfg(test)` so every lane keeps the pins.
#[cfg(feature = "ebpf")]
static TERMINAL_BG: AtomicU32 = AtomicU32::new(0);

/// Record the queried terminal background; the return IS the
/// change verdict (the monitor loop forces the repaint on it).
#[cfg(feature = "ebpf")]
pub(crate) fn set_terminal_bg(bg: Option<(u8, u8, u8)>) -> bool {
    let packed = pack_bg(bg);
    TERMINAL_BG.swap(packed, Ordering::AcqRel) != packed
}

/// The queried terminal background, when a paint-capable depth and
/// an answering terminal agree.
#[cfg(feature = "ebpf")]
pub(crate) fn terminal_bg() -> Option<(u8, u8, u8)> {
    terminal_bg_at(unpack_bg(TERMINAL_BG.load(Ordering::Acquire)), capability())
}

/// Pack one background triple for the atomic word: bit 31 present,
/// bits 23..0 `0xRRGGBB`. Pure — pinned.
#[cfg(any(test, feature = "ebpf"))]
fn pack_bg(bg: Option<(u8, u8, u8)>) -> u32 {
    match bg {
        Some((r, g, b)) => 0x8000_0000 | (u32::from(r) << 16) | (u32::from(g) << 8) | u32::from(b),
        None => 0,
    }
}

/// Unpack the atomic word (None when the present flag is clear).
#[cfg(any(test, feature = "ebpf"))]
fn unpack_bg(packed: u32) -> Option<(u8, u8, u8)> {
    if packed & 0x8000_0000 == 0 {
        return None;
    }
    let v = packed & 0x00FF_FFFF;
    Some(((v >> 16) as u8, (v >> 8) as u8, v as u8))
}

/// Pure core of [`terminal_bg`] (the emit/emit_at discipline): the
/// triple survives only at paint-capable depths; shallow tiers
/// render the terminal default, the honest background there.
#[cfg(any(test, feature = "ebpf"))]
fn terminal_bg_at(stored: Option<(u8, u8, u8)>, cap: ColorCapability) -> Option<(u8, u8, u8)> {
    match cap {
        ColorCapability::TrueColor | ColorCapability::Color256 => stored,
        ColorCapability::Color16 | ColorCapability::Mono => None,
    }
}

/// The background escape the frame's rows open with (NIGHT-boost-26):
/// TrueColor paints the exact triple, Color256 quantizes onto the
/// 6x6x6 cube (the rails' nearest-match); shallow depths paint
/// nothing — a 16-color slot cannot represent an arbitrary grey.
#[cfg(feature = "ebpf")]
pub(crate) fn terminal_bg_escape() -> String {
    terminal_bg_escape_at(terminal_bg(), capability())
}

/// Pure core of [`terminal_bg_escape`] (the emit/emit_at discipline):
/// the escape for one triple at one depth, pinned without touching
/// the process-global caches.
#[cfg(any(test, feature = "ebpf"))]
fn terminal_bg_escape_at(bg: Option<(u8, u8, u8)>, cap: ColorCapability) -> String {
    match bg {
        Some((r, g, b)) => match cap {
            ColorCapability::TrueColor => format!("\x1b[48;2;{r};{g};{b}m"),
            ColorCapability::Color256 => {
                let q = |c: u8| (usize::from(c) * 6 / 256).min(5);
                format!("\x1b[48;5;{}m", 16 + 36 * q(r) + 6 * q(g) + q(b))
            }
            _ => String::new(),
        },
        None => String::new(),
    }
}

// Background pins live under the single test/ tree (cosmostrix
// Pattern C), #[path]-wired like the theme catalog pins.
#[cfg(test)]
#[path = "../../test/output/terminal_bg_tests.rs"]
mod terminal_bg_tests;
