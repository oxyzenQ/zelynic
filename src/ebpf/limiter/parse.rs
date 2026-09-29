// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Value parsing for the limiter (NIGHT-private-research-3's LOC-cap
//! split of the former format.rs — one theme, one module, the same
//! discipline that split policy/policy_lines/stats before it): the
//! strict duration and rate grammars, their bounded monitor-window
//! wrappers, and the rate-bounds validator. The formatters live in
//! the format sibling; the re-export surface in limiter/mod.rs is
//! unchanged, so every consumer import stays byte-identical.

use anyhow::{bail, Result};

use super::types::{MAX_RATE, MIN_RATE};

/// Parse a time duration string. Formats: 1s, 3m, 10h, or plain number (seconds).
/// Returns duration in seconds. 0 = infinity.
///
/// NIGHT-hunt-31 (owner-approved hunt, the NIGHT-boost-15 fractional
/// rate's twin surface): the value layer accepts FRACTIONAL durations
/// — `1.5h` parses to 5,400 seconds. Same strict grammar
/// (`[0-9]+(\.[0-9]+)?` before the unit), same EXACT math (u128
/// mantissa/scale, rounded half-away-from-zero at the final second
/// only — no f64 anywhere), same overflow contract. A fractional
/// input that rounds to zero is REJECTED: 0 means infinity here, the
/// exact opposite of what `0.4s` meant, and that flip must never
/// happen silently.
pub fn parse_time_duration(s: &str) -> Result<u64> {
    let s = s.trim();

    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    let (num_part, multiplier) = if let Some(v) = s.strip_suffix("h") {
        (v, 3600u64)
    } else if let Some(v) = s.strip_suffix("m") {
        (v, 60u64)
    } else if let Some(v) = s.strip_suffix("s") {
        (v, 1u64)
    } else {
        // Flagship typo rescue: suggest the near-miss duration the user
        // probably meant (`3min` -> `3m`, `10sec` -> `10s`, `5H` -> `5h`).
        // The tip line renders white via the line-aware error renderer.
        let mut msg = format!(
            "Invalid duration '{s}'. Use format: 1s, 3m, 1.5h, 10h, or plain number (seconds)"
        );
        if let Some(tip) = crate::cli::ux::duration_tip(s) {
            msg.push_str(&tip);
        }
        bail!("{msg}")
    };

    let (mantissa, scale) = parse_decimal_scaled(num_part.trim()).map_err(|reason| {
        // Same typo rescue as the suffix branch: a near-miss unit
        // (`1kib` strips to number "1ki" + implied b) surfaces here.
        let mut msg = format!("Invalid number in duration '{s}': {reason}");
        if let Some(tip) = crate::cli::ux::duration_tip(s) {
            msg.push_str(&tip);
        }
        anyhow::anyhow!(msg)
    })?;

    // Exact evaluation (NIGHT-hunt-31): mantissa x multiplier /
    // 10^scale in u128 — the only overflow point is the u64 boundary
    // itself, and the rounding happens ONCE, at the final second,
    // half-away-from-zero. NIGHT-improve-10's contract holds: a
    // duration that overflows 64-bit seconds is a meaningless input,
    // error with the original input shown, never the wrapped or
    // saturated value.
    let scaled = mantissa
        .checked_mul(u128::from(multiplier))
        .ok_or_else(|| {
            anyhow::anyhow!("Duration '{s}' is too large — the value overflows 64-bit math.")
        })?;
    let divisor = 10_u128.checked_pow(scale).ok_or_else(|| {
        anyhow::anyhow!("Duration '{s}' is too small to represent — more than 38 decimal places")
    })?;
    let result = scaled / divisor + u128::from((scaled % divisor) * 2 >= divisor);

    if result > u64::MAX as u128 {
        bail!("Duration '{s}' is too large — the value overflows 64-bit math.");
    }
    if result == 0 && scale > 0 {
        bail!(
            "Duration '{s}' rounds to zero seconds — 0 means infinity (no limit). \
             Pass '0' if you mean no limit, or at least 1s."
        );
    }
    Ok(result as u64)
}

/// Parse a monitor refresh interval (NIGHT-hunt-7): 1s to 60s.
///
/// Accepts the same duration grammar as [`parse_time_duration`]
/// (plain seconds, `2s`, `1m`), then clamps to the owner-mandated
/// realtime window: anything below 1s spams the CPU with full-frame
/// redraws, anything above 60s stops feeling like a live monitor.
/// Out-of-range values fail with the bounds spelled out so the fix
/// is obvious.
pub fn parse_monitor_interval(s: &str) -> Result<u64> {
    let secs = parse_time_duration(s)?;
    if !(1..=60).contains(&secs) {
        bail!("Invalid interval '{s}': refresh interval must be between 1s and 60s");
    }
    Ok(secs)
}

/// Parse the eagle-eyes `--depth` network-traffic focus window
/// (NIGHT-private-research-3): 1s to 30s, default 3s.
///
/// The same duration grammar as [`parse_monitor_interval`] (plain
/// seconds, `3s`, `30`), bounded by the one-shot report's own
/// economics: below 1s the observer books nothing worth reporting
/// (the verifier's own load time rivals the window), above 30s a
/// report that is supposed to answer "what IS this cgroup" starts
/// feeling like a monitor session — the live TUI owns that job.
/// Out-of-range values fail with the bounds spelled out, and a
/// typo'd unit rides the shared duration did-you-mean tip
/// (`3min` -> `3m`).
pub fn parse_focus_window(s: &str) -> Result<u64> {
    let secs = parse_time_duration(s)?;
    if !(1..=30).contains(&secs) {
        bail!("Invalid focus window '{s}': must be between 1s and 30s");
    }
    Ok(secs)
}

/// Parse a rate string. Lowercase units only: kb, mb, gb, tb, b.
///
/// NIGHT-boost-15 (hunt-30, owner-approved): the value layer accepts
/// FRACTIONAL rates — `5.5mb` parses to 5,500,000 bytes/s. The grammar
/// is strict (`[0-9]+(.[0-9]+)?` before the unit): a leading dot, a
/// trailing dot, a second dot, signs, and separators are usage errors.
/// The math is EXACT — integer mantissa and decimal scale evaluated in
/// u128, rounded half-away-from-zero at the final byte only — so no f64
/// sits anywhere in the parse path and the integer inputs the strict CLI
/// was built on keep their byte-identical results.
///
/// Returns the rate in bytes per second. On overflow (input too large for u64),
/// returns an error with the original input shown — not the wrapped value.
pub fn parse_rate(s: &str) -> Result<u64> {
    let s = s.trim();

    if let Ok(n) = s.parse::<u64>() {
        return Ok(n);
    }

    let (num_part, multiplier) = if let Some(v) = s.strip_suffix("tb") {
        (v, 1_000_000_000_000u64)
    } else if let Some(v) = s.strip_suffix("gb") {
        (v, 1_000_000_000u64)
    } else if let Some(v) = s.strip_suffix("mb") {
        (v, 1_000_000u64)
    } else if let Some(v) = s.strip_suffix("kb") {
        (v, 1_000u64)
    } else if let Some(v) = s.strip_suffix("b") {
        (v, 1u64)
    } else {
        // Flagship typo rescue: suggest the near-miss rate the user
        // probably meant (`1MB` -> `1mb`, `1kib` -> `1kb`, `10mbps` ->
        // `10mb`, `5.5XB` -> `5.5kb`). The tip line renders white via
        // the line-aware error renderer in the output layer.
        let mut msg = format!(
            "Invalid rate '{s}'. Use lowercase: 1mb, 5.5mb, 500kb, 1gb, 1tb, or plain number"
        );
        if let Some(tip) = crate::cli::ux::rate_tip(s) {
            msg.push_str(&tip);
        }
        bail!("{msg}")
    };

    let (mantissa, scale) = parse_decimal_scaled(num_part.trim()).map_err(|reason| {
        // Same typo rescue as the suffix branch: a near-miss unit
        // like `1kib` strips its trailing 'b' and lands here with
        // the unparsable number "1ki".
        let mut msg = format!("Invalid number in rate '{s}': {reason}");
        if let Some(tip) = crate::cli::ux::rate_tip(s) {
            msg.push_str(&tip);
        }
        anyhow::anyhow!(msg)
    })?;

    // Exact evaluation (NIGHT-boost-15): mantissa x multiplier /
    // 10^scale in u128 — u64 inputs can never overflow u128 here, so
    // the only overflow point is the u64 boundary itself, and the
    // rounding happens ONCE, at the final byte, half-away-from-zero
    // (the rate_bps precedent in the render engine). A fractional
    // input that rounds to zero is rejected below: 0 is the BPF
    // schema's BLOCK verdict, and a user who typed `0.4b` meant a
    // tiny rate, not a silent block.
    let scaled = mantissa
        .checked_mul(u128::from(multiplier))
        .ok_or_else(|| {
            anyhow::anyhow!("Rate '{s}' is too large — the value overflows 64-bit math.")
        })?;
    let divisor = 10_u128.checked_pow(scale).ok_or_else(|| {
        anyhow::anyhow!("Rate '{s}' is too small to represent — more than 38 decimal places")
    })?;
    let result = scaled / divisor + u128::from((scaled % divisor) * 2 >= divisor);

    if result > u64::MAX as u128 {
        bail!("Rate '{s}' is too large — the value overflows 64-bit math.");
    }
    if result == 0 && scale > 0 {
        bail!(
            "Rate '{s}' rounds to zero bytes/s — 0 is the block verdict. \
             Pass '0' if you mean block, or at least 1 B/s."
        );
    }
    Ok(result as u64)
}

/// Parse a plain decimal number into an exact (mantissa, scale) pair
/// (NIGHT-boost-15): `"5"` -> `(5, 0)`, `"5.5"` -> `(55, 1)`,
/// `"0.0005"` -> `(5, 4)`. The grammar is `[0-9]+(\.[0-9]+)?` — the
/// whole part is required before the dot, digits are required after
/// it, and at most one dot: `.5`, `5.`, `5.5.5`, and signed forms are
/// all rejected with a reason the caller folds into its own error
/// shape. The mantissa parses straight to u128 (not u64): a value
/// like `18000000000000000000.5` carries a 21-digit mantissa yet a
/// u64-fitting result, and the overflow contract belongs to the
/// scaled evaluation above, not to the digit string.
fn parse_decimal_scaled(s: &str) -> Result<(u128, u32)> {
    let (int_part, frac_part) = match s.split_once('.') {
        Some((int, frac)) => (int, Some(frac)),
        None => (s, None),
    };
    if int_part.is_empty() || !int_part.bytes().all(|b| b.is_ascii_digit()) {
        bail!("expected digits before the decimal point, got '{s}'");
    }
    let scale = match frac_part {
        Some(frac) => {
            if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
                bail!("expected digits after the decimal point, got '{s}'");
            }
            frac.len() as u32
        }
        None => 0,
    };
    let digits = match frac_part {
        Some(frac) => format!("{int_part}{frac}"),
        None => int_part.to_string(),
    };
    let mantissa: u128 = digits.parse().map_err(|_| {
        anyhow::anyhow!("the digits of '{s}' exceed 128-bit precision — not a rate")
    })?;
    Ok((mantissa, scale))
}

/// Validate rate is within bounds.
/// rate = 0 is allowed (means BLOCK in BPF schema v3+).
/// rate 1-999 is rejected (below minimum, would brick apps).
pub fn validate_rate(rate_bps: u64) -> Result<()> {
    if rate_bps > 0 && rate_bps < MIN_RATE {
        bail!(
            "Rate {} is below minimum ({} B/s = 1 KB/s, decimal SI).\n\
             Use --force-this to override. Use 0 for block.",
            rate_bps,
            MIN_RATE
        );
    }
    if rate_bps > MAX_RATE {
        bail!(
            "Rate {} is above maximum ({} B/s = 1 TB/s).\n\
             Use --force-this to override.",
            rate_bps,
            MAX_RATE
        );
    }
    Ok(())
}
