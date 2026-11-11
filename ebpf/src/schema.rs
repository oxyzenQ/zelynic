// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
// NIGHT-improve-44: the schema-version ledger (the v1..v24
// contract history) and the SCHEMA_VERSION const it documents,
// moved out of limiter.rs at the 600-line cap. Same file the
// userspace loader contract names; the doc text is verbatim.
//
// ---------------------------------------------------------------------------
// Shared layout contract with the userspace loader (src/ebpf/limiter/
// types.rs: PolicyRaw, BucketRaw, LimiterStatsRaw) and the C twin. The
// compile-time size pins guarantee the layouts can never drift
// silently; the C side relies on kernel headers for the same
// invariants, the userspace tests assert the third copy.
// (NIGHT-depthbore-1: the struct definitions, the size pins,
// NS_PER_SEC, MAX_ENFORCABLE_BURST, and the enforce math moved to
// math.rs — this block keeps the contract statement.)
// ---------------------------------------------------------------------------

/// Current schema version. Increment when struct layouts or
/// semantics change. Kept in sync with SCHEMA_VERSION_EXPECTED in
/// src/ebpf/limiter/types.rs (the v3..v30 history ledger moved
/// verbatim to schema_ledger.rs — the 600-line cap's split,
/// night-T-3's v31 hour); v31 and onward append here, beside the
/// anchor.
/// v31 (night-T-3, the measured-RTT RECWN retune — the honest
///     clamp): the recwn_socket_hint row's VALUE semantics change —
///     socket cookie -> the policy's DOWNLOAD RATE in bytes per
///     second (was: the derived receive window). The sock_ops
///     program derives the window at every owned callback as
///     window = rate x max(measured srtt, 200 ms), the srtt read
///     straight from the sock_ops context (uapi bpf_sock_ops
///     .srtt_us, microseconds << 3, populated whenever is_fullsock
///     holds — v4.16+, so the 5.13 floor carries it; no new helper,
///     no new map, no userspace involvement). The 200 ms constant
///     re-frames from RTT guess to the receiver's window-update
///     CADENCE floor (the band the v25 evidence measured at
///     145-160 ms topping at 200 ms): every short link and every
///     unmeasured socket answers the exact v25 window byte for
///     byte, a link LONGER than the band derives the pipe the
///     fixed floor under-admitted, and the [2 x MSS, 1 MiB] band
///     plus the plain-multiply sanitize cap carry unchanged (the
///     product bound holds: rate <= 2^32, srtt <= u32). The status
///     derivation stays the v25 shape exactly (the cadence-floor
///     FLOOR shape — the number the runtime can only extend above).
///     The bump is REQUIRED, not polite: a pinned v30 hint row
///     holds WINDOW bytes, which a v31 reader would misread as a
///     RATE — the forced reload wipes the stale rows (active limits
///     are dropped once, re-apply after upgrade, the same one-time
///     contract as every bump before it).
#[allow(dead_code)]
pub(crate) const SCHEMA_VERSION: u32 = 31;

// ---------------------------------------------------------------------------
// Maps. The static names ARE the userspace contract (limiter/mod.rs
// and pin.rs open each map by name or by pin path), so they stay
// lowercase exactly like the C object's symbols; the allow attribute
// suppresses the non-upper-case globals lint for that reason. Every
// map is pinned by name: policies must survive process exit, which
// is the whole point of the /sys/fs/bpf/zelynic directory.
// ---------------------------------------------------------------------------

// ─ Download (ingress) maps ─
