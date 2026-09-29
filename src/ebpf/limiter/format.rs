// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Byte/rate/count formatting, the burst clamp, and small
//! terminal/time helpers for the limiter (NIGHT-private-research-3's
//! LOC-cap split: the value PARSERS moved to the parse sibling —
//! one theme, one module; the re-export surface in limiter/mod.rs is
//! unchanged, so every consumer import stays byte-identical).

use super::types::{BURST_CEIL_BYTES, BURST_FLOOR_BYTES};

/// Compute burst size: 1 second of traffic (rate_bps bits as bytes
/// — an 8-second byte credit), clamped between the 64 KiB GSO
/// super-packet floor and the 100 MB ceiling (NIGHT-lts-8 raised
/// the floor from 4 KB — the bounds live in types.rs).
pub fn default_burst(rate_bps: u64) -> u64 {
    rate_bps.clamp(BURST_FLOOR_BYTES, BURST_CEIL_BYTES)
}

/// Get monotonic time in nanoseconds (CLOCK_MONOTONIC).
pub fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) != 0 {
            return 0;
        }
    }
    (ts.tv_sec as u64).saturating_mul(1_000_000_000) + (ts.tv_nsec as u64)
}

/// Format a byte count using decimal SI units (1 KB = 1000 bytes).
///
/// Consistent with `parse_rate` (1kb = 1000): network rates
/// conventionally use SI units (1 Mbps = 1,000,000 bps).
///
/// One decimal on EVERY tier (status-style audit, NIGHT-style flagship
/// bar: compact/simple/elegant/precise): mixed digit counts read as
/// raggedness inside one aligned column ("100.0 MB/s" above "1.00 GB/s").
/// The TB tier exists because the parser accepts 1tb (MAX_RATE = 1e12)
/// — pre-audit a max-rate policy rendered "1000.00 GB/s" while the CLI
/// said 1tb.
///
/// Tier-boundary promotion (improve-13 precision): a value that ROUNDS
/// UP to 1000.0 of its unit renders in the next unit — 999_950 B is
/// "1.0 MB", never "1000.0 KB": a four-digit cell is a ragged column,
/// and "1000.0 KB/s" (11 columns) pushed the monitor's fixed
/// 10-column RATE budget right by one at exactly the tier edge. The
/// B tier stays integer (no decimal to round up).
///
/// NIGHT-boost-22 (LTS audit): the ladder now runs B -> KB -> MB ->
/// GB -> TB -> PB -> EB, to the u64 ceiling — the old code stopped at
/// TB on a wrong premise (the note claimed "u64::MAX is ~18.4 TB";
/// 2^64 is ~18.4 EXABYTES, and a saturated 10G server crosses the TB
/// ceiling in days). Past 999.95 TB the old formatter rendered
/// five-digit figures ("18446.7 TB") — the promotion contract broken
/// at its own terminal tier. The extended ladder caps every display
/// at 8 columns ("999.9 PB"), u64::MAX rendering "18.4 EB".
/// Zettabytes sit past u64::MAX and stay unreachable IN u64: the
/// zettabyte-and-beyond truth belongs to [`format_bytes_wide`], the
/// u128 twin the session accounting renders through (NIGHT-lts-5).
///
/// Examples: 500 → "500 B", 1500 → "1.5 KB", 999_949 → "999.9 KB",
///           999_950 → "1.0 MB", 1_500_000_000_000 → "1.5 TB",
///           1e15 → "1.0 PB", 1e18 → "1.0 EB", u64::MAX → "18.4 EB"
pub fn format_bytes(bytes: u64) -> String {
    const DIVS: [u64; 7] = [
        1,
        1_000,
        1_000_000,
        1_000_000_000,
        1_000_000_000_000,
        1_000_000_000_000_000,
        1_000_000_000_000_000_000,
    ];
    const UNITS: [&str; 7] = ["B", "KB", "MB", "GB", "TB", "PB", "EB"];

    // Walk up while the one-decimal display of this tier would carry a
    // thousands digit — exact integer threshold (999.95 of a unit,
    // i.e. 1000*div - div/20, the smallest value whose one-decimal
    // rounding reads 1000.0; every DIVS entry divides by 20 exactly,
    // so no float-edge wobble). Tier 6 is the EB terminal: u64::MAX is
    // ~18.4 EB, no eighth unit is reachable, and the walk guard stops
    // at tier 6 BEFORE the 1000x multiple of the EB divisor (1e21)
    // could overflow u64 — the largest threshold the walk ever
    // evaluates is the PB edge, 1e18 - 5e13, well inside the range.
    let mut tier = 0usize;
    while tier < 6 && bytes >= 1000 * DIVS[tier] - DIVS[tier] / 20 {
        tier += 1;
    }

    if tier == 0 {
        format!("{bytes} B")
    } else {
        // Exact one-decimal rendering in u128 (NIGHT-boost-22): the
        // old `bytes as f64` division loses exactness above 2^53
        // (~9 PB) — the u64 domain's upper half — and the
        // nearest-double error (up to 64 at the EB edge) can flip
        // the displayed tenth across the promotion boundary the
        // integer walk just enforced (999_949_999_999_999_999
        // rendered "1000.0 PB"). Integer tenths keep the walk and
        // the display on ONE exact contract; the half-up add is the
        // same round-half-away discipline the rate parser uses.
        let div = u128::from(DIVS[tier]);
        let tenths = (u128::from(bytes) * 10 + div / 2) / div;
        format!("{}.{} {}", tenths / 10, tenths % 10, UNITS[tier])
    }
}

/// Format a rate (bytes per second) with "/s" suffix, decimal SI
/// units consistent with `parse_rate` and `format_bytes`.
/// Examples: 100_000 → "100.0 KB/s", 1_000_000 → "1.0 MB/s"
pub fn format_rate(bps: u64) -> String {
    if bps == 0 {
        "BLOCKED".to_string()
    } else {
        format!("{}/s", format_bytes(bps))
    }
}

/// The wide session-surface byte formatter (NIGHT-lts-5, the server
/// long-endurance ask — "harden and robust for future when reach
/// limit of zelynic like possible 1 zettabyte ZB even quettabyte
/// QB"): the u128 twin of [`format_bytes`], for the monitor's
/// SESSION accounting — the ONE surface whose integer genuinely
/// reaches past the exabyte (u64 wraps at 18.4 EB; the u128 session
/// accumulator sums the wrap-coherent deltas; 1 ZB is ~233 days at
/// 1 Tbps). The ladder runs the full 2019 SI list to quetta-; past
/// 999.9 QB the exact count renders uncapped (u128::MAX is
/// "340282366.9 QB"). Every OTHER surface keeps [`format_bytes`]:
/// u64 IS the kernel map figures' truth. Examples: 1e21 → "1.0 ZB".
pub fn format_bytes_wide(bytes: u128) -> String {
    const DIVS: [u128; 11] = [
        1,
        1_000,
        1_000_000,
        1_000_000_000,
        1_000_000_000_000,
        1_000_000_000_000_000,
        1_000_000_000_000_000_000,
        10_u128.pow(21),
        10_u128.pow(24),
        10_u128.pow(27),
        10_u128.pow(30),
    ];
    const UNITS: [&str; 11] = [
        "B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB", "RB", "QB",
    ];

    // The u64 ladder's walk discipline (the exact 999.95 thresholds,
    // none overflowable in u128), stopping at the QB terminal.
    let mut tier = 0usize;
    while tier < 10 && bytes >= 1000 * DIVS[tier] - DIVS[tier] / 20 {
        tier += 1;
    }

    if tier == 0 {
        format!("{bytes} B")
    } else {
        // Exact tenths without a widening multiply (u128 has none):
        // the REMAINDER's tenth (10*rem + div/2 < 11*div, so 0..=10)
        // carries into the whole on a 10 — the walk's own edge.
        let div = DIVS[tier];
        let mut whole = bytes / div;
        let mut tenths = (bytes % div * 10 + div / 2) / div;
        if tenths == 10 {
            whole += 1;
            tenths = 0;
        }
        format!("{}.{} {}", whole, tenths, UNITS[tier])
    }
}

/// Format a plain COUNT using decimal SI compact units
/// (NIGHT-engrave-7, the counter-explosion hardening).
///
/// The owner's report: a monitor that opens on "24 packets" reads
/// "2244843 packets" eight hours later — a raw u64 that explodes the
/// line and the reader's trust together. Every session-scoped count
/// the monitor renders (packets, hidden rows, process/socket
/// suffixes) now rides THIS ladder, the count-mirror of
/// [`format_bytes`]: the same decimal SI tiers (1 K = 1000, never
/// 1024), the same one-decimal-everywhere display, the same exact
/// u128 tenths math, and the same tier-boundary promotion (a value
/// that rounds up to 1000.0 of its unit renders in the next unit —
/// 999_949 → "999.9K", 999_950 → "1.0M", never a ragged four-digit
/// cell). Small counts stay EXACT and unpunctuated: the fresh-start
/// "24 packets" keeps reading "24 packets" — compacting begins only
/// where the raw figure stops being readable at a glance (>= 1000).
///
/// The unit letters carry no "B" suffix (a packet is not a byte) and
/// no locale separators (the SI ladder IS the punctuation): "2.2M",
/// "1.0K", "18.4E" at the u64 ceiling.
///
/// Examples: 24 → "24", 999 → "999", 1000 → "1.0K",
///           2_244_843 → "2.2M", u64::MAX → "18.4E"
pub fn format_count(n: u64) -> String {
    const DIVS: [u64; 7] = [
        1,
        1_000,
        1_000_000,
        1_000_000_000,
        1_000_000_000_000,
        1_000_000_000_000_000,
        1_000_000_000_000_000_000,
    ];
    const UNITS: [&str; 7] = ["", "K", "M", "G", "T", "P", "E"];

    // The format_bytes walk discipline: promote while the one-decimal
    // display of this tier would carry a thousands digit (the exact
    // 999.95-of-a-unit threshold; every DIVS entry divides by 20
    // exactly). Tier 6 (E) is the terminal: u64::MAX is ~18.4E and
    // the walk guard stops before the EB multiple (1e21) could
    // overflow u64.
    let mut tier = 0usize;
    while tier < 6 && n >= 1000 * DIVS[tier] - DIVS[tier] / 20 {
        tier += 1;
    }

    if tier == 0 {
        format!("{n}")
    } else {
        // Exact one-decimal tenths in u128 — the same half-up
        // rounding the byte ladder uses, no float anywhere.
        let div = u128::from(DIVS[tier]);
        let tenths = (u128::from(n) * 10 + div / 2) / div;
        format!("{}.{}{}", tenths / 10, tenths % 10, UNITS[tier])
    }
}

/// Get terminal width in columns via the shared TIOCGWINSZ probe
/// (the one canonical copy lives in the terminal layer,
/// terminal/diff.rs — NIGHT-hunt-15). Falls back to 80 if detection
/// fails (piped output, no tty).
pub fn terminal_width() -> usize {
    crate::terminal::winsize().map_or(80, |(cols, _)| cols as usize)
}

// NIGHT-hunt-15: terminal_height() was deleted — after the render
// engine's geometry probe switched to the one-call winsize(), no
// caller remained (the status table renders width-only). A fresh
// height consumer should call crate::terminal::winsize() directly.

// NIGHT-boost-15: the format pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired across trees exactly like the
// limiter's math/policy/reclaim pins — the inline `mod tests` moved
// out when the fractional rate layer pushed this file past the LOC
// cap. NIGHT-engrave-7: the format_count pins took their own file
// when the counter-explosion pins pushed format_tests.rs past again.
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/format_tests.rs"]
mod format_tests;

#[cfg(test)]
#[path = "../../../test/ebpf/limiter/format_count_tests.rs"]
mod format_count_tests;

// NIGHT-lts-5: the wide-ladder pins (one contract, one file).
#[cfg(test)]
#[path = "../../../test/ebpf/limiter/format_wide_tests.rs"]
mod format_wide_tests;
