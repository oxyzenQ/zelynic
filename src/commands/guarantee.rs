// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! improve-40 (schema v24): the guarantee bracket's CLI resolution —
//! `--floor`/`--ceil` parsed on the rate family's own ladder, then
//! validated against the resolved rates BEFORE the root ask (the
//! parse-before-execute contract every strict handler documents: a
//! contradictory bracket surfaces its wording with the numbers it
//! would have policed, never a privileged round-trip later).
//!
//! THE ONE-FLAG LAW: one `--floor` (or `--ceil`) sets BOTH
//! directions' rows — the `--during` shape, the positional rate's
//! own posture — and validates against EVERY direction the spec
//! sets (a direction the invocation removes is not consulted; the
//! improve-29 law owns that removal). Per-direction brackets are a
//! documented future lane, not a v24 surface.
//!
//! THE VALIDATION LADDER, fail-fast in the order the owner would
//! mis-type it:
//!   * the scope call — the bracket polices the cgroup's subprocess
//!     LEAVES (the DRR fair-share lane); the per-socket lane polices
//!     each connection at the full rate, and the combination is not
//!     a thing v24 does;
//!   * the grammar — the rate family's parser and its 1kb floor
//!     (a typo'd bracket gets the did-you-mean tip, a sub-1kb one
//!     asks --force-this, exactly like a rate);
//!   * the contradiction — a floor above a ceiling is unkeepable in
//!     any arithmetic that respects the cap;
//!   * the never-binding sides — a bracket side above the rate can
//!     never bind (the pool refills at the rate), and a config that
//!     can never bind is a mis-typed rate, not an intent.

// Dormant-mode discipline: the resolver is ebpf-gated, so its
// anyhow imports ride the same gate (a module-level unused import
// breaks the no-default-features leg's -D warnings).
#[cfg(feature = "ebpf")]
use anyhow::{bail, Result};

// improve-40: the wording pins live under the single test/ tree
// (cosmostrix Pattern C), #[path]-wired exactly like the rates
// shadow family one sibling over.
#[cfg(all(test, feature = "ebpf"))]
#[path = "../../test/cli/guarantee_resolve_tests.rs"]
mod guarantee_resolve_tests;

/// Resolve the guarantee bracket for one strict invocation:
/// parse both sides on the rate family's ladder, validate the
/// ladder above, and return the (floor, ceil) pair the apply family
/// writes on every row — the zero sentinel for an unset side.
///
/// The imports live inside the function (the rates.rs dormant-mode
/// discipline): the whole resolver is ebpf-gated, and a
/// module-level import of the limiter tree would break the
/// no-default-features leg's compile.
#[cfg(feature = "ebpf")]
pub(crate) fn resolve_guarantee(
    floor: Option<&str>,
    ceil: Option<&str>,
    rates: &crate::ebpf::limiter::RateSpec,
    force_this: bool,
    per_socket: bool,
) -> Result<(u64, u64)> {
    use crate::ebpf::limiter::{parse_rate, validate_rate};

    // The scope call first (before any parsing: the combination is
    // rejected whatever the values would have been).
    if per_socket && (floor.is_some() || ceil.is_some()) {
        bail!(
            "--floor/--ceil police the target's subprocess leaves (the fair-share lane) \
             and are not offered beside --per-socket (every connection its own budget \
             at the full rate).\n\
             Drop one: --per-socket for the server shape, --floor/--ceil for the \
             subprocess shape."
        );
    }

    let parse_side = |s: &str| -> Result<u64> {
        let rate = parse_rate(s)?;
        if !force_this {
            validate_rate(rate)?;
        }
        Ok(rate)
    };
    let floor_bps = match floor {
        Some(s) => parse_side(s)?,
        None => 0,
    };
    let ceil_bps = match ceil {
        Some(s) => parse_side(s)?,
        None => 0,
    };

    // The contradiction.
    if floor_bps != 0 && ceil_bps != 0 && floor_bps > ceil_bps {
        bail!(
            "floor {} exceeds ceil {} — a guarantee above the cap is a contradiction.\n\
             The cap is the safety law; raise the ceiling or lower the floor.",
            floor_bps,
            ceil_bps
        );
    }

    // The never-binding sides, per SET direction (the one-flag law:
    // both directions' rows carry the bracket, so both rates must
    // be able to honor it; an unset direction is being removed by
    // the improve-29 law and is not consulted).
    for (label, rate) in [("download", rates.download), ("upload", rates.upload)] {
        let Some(rate) = rate else {
            continue;
        };
        if ceil_bps != 0 && ceil_bps > rate {
            bail!(
                "ceil {} exceeds the {} rate {} — the pool refills at the rate, \
                 so a ceiling above it never binds.\n\
                 Raise the rate or lower the ceiling.",
                ceil_bps,
                label,
                rate
            );
        }
        if floor_bps != 0 && floor_bps > rate {
            bail!(
                "floor {} exceeds the {} rate {} — the pool never refills that fast, \
                 so the guarantee could never bind.\n\
                 Over-subscribed floors (many leaves, each floored) are the datapath's \
                 documented degradation; one leaf floored above its own pool is a \
                 mis-typed rate.",
                floor_bps,
                label,
                rate
            );
        }
    }

    Ok((floor_bps, ceil_bps))
}
