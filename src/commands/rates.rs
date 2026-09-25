// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI rate-string resolution — positional rate vs per-direction flags.

use anyhow::Result;

// ── The override's silence (NIGHT-improve-30) ─────────────────────────
//
// The former `--allow-dangerous` path printed up to three "[limiter]
// WARNING: rate below minimum — overriding with --allow-dangerous"
// lines per invocation. That was request-echo noise by the
// NIGHT-improve-28 standard: the user typed the override themselves,
// the shell history carries it, and re-reading their own flag name
// back to them three times is the exact verbosity this task retires.
// The unified `--force-this` flag therefore overrides the bounds
// SILENTLY — the flag is the acknowledgment; the enforced rate is
// visible in 'zelynic status' for the verification.

/// Parse a rate string with validation.
#[cfg(feature = "ebpf")]
fn parse_rate_checked(s: &str, force_this: bool) -> Result<u64> {
    use crate::ebpf::limiter::{parse_rate, validate_rate};
    let rate = parse_rate(s)?;
    if !force_this {
        validate_rate(rate)?;
    }
    Ok(rate)
}

/// Resolve rates from CLI args. Priority: -d/-u flags > positional rate.
///
/// If -d or -u is specified, use those (per-direction).
/// If neither -d nor -u, but positional rate exists, use it for BOTH directions.
/// If nothing specified, return empty RateSpec (caller should error).
#[cfg(feature = "ebpf")]
pub(crate) fn resolve_rates(
    rate: Option<&str>,
    download: Option<&str>,
    upload: Option<&str>,
    force_this: bool,
) -> Result<crate::ebpf::limiter::RateSpec> {
    if download.is_some() || upload.is_some() {
        // -d or -u specified → use per-direction.
        parse_rates(download, upload, force_this)
    } else if let Some(r) = rate {
        // No -d/-u, but positional rate → both = rate.
        let r_bps = parse_rate_checked(r, force_this)?;
        Ok(crate::ebpf::limiter::RateSpec {
            download: Some(r_bps),
            upload: Some(r_bps),
        })
    } else {
        // Nothing specified.
        Ok(crate::ebpf::limiter::RateSpec {
            download: None,
            upload: None,
        })
    }
}

// ━━ Helpers ━━

#[cfg(feature = "ebpf")]
fn parse_rates(
    download: Option<&str>,
    upload: Option<&str>,
    force_this: bool,
) -> Result<crate::ebpf::limiter::RateSpec> {
    use crate::ebpf::limiter::{parse_rate, validate_rate};

    let dl = match download {
        Some(s) => {
            let rate = parse_rate(s)?;
            if !force_this {
                validate_rate(rate)?;
            }
            Some(rate)
        }
        None => None,
    };

    let ul = match upload {
        Some(s) => {
            let rate = parse_rate(s)?;
            if !force_this {
                validate_rate(rate)?;
            }
            Some(rate)
        }
        None => None,
    };

    Ok(crate::ebpf::limiter::RateSpec {
        download: dl,
        upload: ul,
    })
}
