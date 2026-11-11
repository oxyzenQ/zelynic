// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The limiter's BPF schema-version contract.
//!
//! Split from types.rs at the NIGHT-private-research-2 bump (the
//! version-history doc block grows one entry per schema bump — the
//! 500-LOC owner cap was already full at v9, and this constant's
//! history is the one piece of types.rs that grows by design).
//! Re-exported through types.rs so every existing
//! `use types::SCHEMA_VERSION_EXPECTED` import resolves unchanged —
//! the parse.rs precedent (NIGHT-private-research-3) applied to the
//! schema anchor.

/// BPF schema version. Must match `SCHEMA_VERSION` in
/// `ebpf/src/bin/limiter.rs`.
/// Increment both when BPF struct layouts or semantics change. Userspace checks
/// the pinned schema_version map on attach — if mismatch, cleans up + reloads.
/// The v1..v30 history ledger moved verbatim to schema_ledger.rs
/// (the 600-line cap's split — night-T-3's v31 hour); v31 and
/// onward append here, beside the anchor.
/// v31 (night-T-3, the measured-RTT RECWN retune — the honest
///     clamp): the recwn_socket_hint row's VALUE semantics change —
///     socket cookie -> the policy's DOWNLOAD RATE in bytes per
///     second (was: the derived receive window). The runtime law
///     the sock_ops program applies at every owned callback is now
///     window = rate x max(measured srtt, 200 ms), the srtt read
///     straight from the sock_ops context (uapi bpf_sock_ops
///     .srtt_us, microseconds << 3, v4.16+ — no new helper, no new
///     map, no userspace involvement: the zero-daemon posture
///     holds). The 200 ms constant re-frames from RTT guess to the
///     receiver's window-update CADENCE floor — the band the v25
///     evidence measured at 145-160 ms topping at 200 ms — so every
///     short link and every unmeasured socket answers the exact v25
///     window byte for byte (the retune can only extend the pipe,
///     never shrink it), while a link LONGER than the band (the
///     satellite class the fixed floor under-admitted at rate x
///     200 ms) now derives its true pipe. The [2 x MSS, 1 MiB] band
///     and the plain-multiply sanitize cap carry unchanged (measured
///     srtt maxes at u32, the product bound holds by construction).
///     The status surfaces stay the v25 shape exactly (additive
///     contract: recwn_limits.enabled / window_bytes /
///     rtt_estimate_us — the derivation is now the cadence-floor
///     FLOOR shape, the number the runtime can only extend above).
///     The bump is REQUIRED, not polite: a pinned v30 hint row
///     holds WINDOW bytes, which a v31 reader would misread as a
///     RATE — the forced reload wipes the stale rows (active limits
///     are dropped once, re-apply after upgrade, the same one-time
///     contract as every bump before it).
pub const SCHEMA_VERSION_EXPECTED: u32 = 31;

#[cfg(test)]
#[path = "../../../test/ebpf/limiter/schema_sync_pin_tests.rs"]
mod sync_pin;

// The ledger half above is a doc-only sibling module, wired here so
// the tree owns the text: it compiles (empty items, zero cost),
// rustfmt checks it, and a reader of either tree finds the history
// one hop from the anchor (the v13 drift lesson's own posture).
#[path = "schema_ledger.rs"]
mod schema_ledger;
