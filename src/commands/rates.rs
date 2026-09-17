// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! CLI rate-string resolution — positional rate vs per-direction flags.

use anyhow::Result;

/// Parse a rate string with validation.
#[cfg(feature = "ebpf")]
fn parse_rate_checked(s: &str, allow_dangerous: bool) -> Result<u64> {
    use crate::ebpf::limiter::{parse_rate, validate_rate, MAX_RATE, MIN_RATE};
    let rate = parse_rate(s)?;
    if !allow_dangerous {
        validate_rate(rate)?;
    } else if rate < MIN_RATE {
        eprintln!("[limiter] WARNING: rate below minimum — overriding with --allow-dangerous");
    } else if rate > MAX_RATE {
        eprintln!("[limiter] WARNING: rate above maximum — overriding with --allow-dangerous");
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
    allow_dangerous: bool,
) -> Result<crate::ebpf::limiter::RateSpec> {
    if download.is_some() || upload.is_some() {
        // -d or -u specified → use per-direction.
        parse_rates(download, upload, allow_dangerous)
    } else if let Some(r) = rate {
        // No -d/-u, but positional rate → both = rate.
        let r_bps = parse_rate_checked(r, allow_dangerous)?;
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
    allow_dangerous: bool,
) -> Result<crate::ebpf::limiter::RateSpec> {
    use crate::ebpf::limiter::{parse_rate, validate_rate, MIN_RATE};

    let dl = match download {
        Some(s) => {
            let rate = parse_rate(s)?;
            if !allow_dangerous {
                validate_rate(rate)?;
            } else if rate < MIN_RATE {
                eprintln!(
                    "[limiter] WARNING: rate below minimum — overriding with --allow-dangerous"
                );
            }
            Some(rate)
        }
        None => None,
    };

    let ul = match upload {
        Some(s) => {
            let rate = parse_rate(s)?;
            if !allow_dangerous {
                validate_rate(rate)?;
            } else if rate < MIN_RATE {
                eprintln!(
                    "[limiter] WARNING: rate below minimum — overriding with --allow-dangerous"
                );
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
