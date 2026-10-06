// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The types.rs pins (Target parsing, rate bounds, the schema-layout
//! size pins, the burst family) — split from types.rs's inline test
//! module at NIGHT-upgrade-charger-core-3b when PolicyRaw's new
//! flags field grew the file past the 500-LOC owner cap: pins live
//! under the single test/ tree, #[path]-wired (cosmostrix Pattern C,
//! the policy_tests/docker_tests lineage). `use super::*` becomes an
//! explicit import list because the parent here is the test wiring,
//! not the module under test.

use crate::ebpf::limiter::types::*;

#[test]
fn test_target_parse_numeric() {
    match Target::parse("73386") {
        Target::CgroupId(id) => assert_eq!(id, 73386),
        _ => panic!("expected CgroupId"),
    }
}

#[test]
fn test_target_parse_name() {
    match Target::parse("firefox") {
        Target::ProcessName(name) => assert_eq!(name, "firefox"),
        _ => panic!("expected ProcessName"),
    }
}

/// NIGHT-boost-37: the canonical display prefix parses to the
/// same direct cgroup ID as the bare numeric form — the output
/// surfaces print `cg:48181` and the suggested command
/// (`sudo zelynic ss cg:48181 100kb`) must work verbatim.
#[test]
fn test_target_parse_cg_prefix_numeric() {
    match Target::parse("cg:48181") {
        Target::CgroupId(id) => assert_eq!(id, 48181),
        _ => panic!("expected CgroupId for cg:-prefixed numeric"),
    }
    // Prefix and bare forms resolve identically — one target.
    assert!(matches!(Target::parse("cg:73386"), Target::CgroupId(id) if id == 73386));
}

/// A non-numeric remainder keeps the WHOLE string as a process
/// name (never the stripped part): a typo like `cg:brave` is the
/// graceful no-match it always was — the prefix never silently
/// rewrites a name target into a different process.
#[test]
fn test_target_parse_cg_prefix_non_numeric_keeps_full_name() {
    match Target::parse("cg:brave") {
        Target::ProcessName(name) => assert_eq!(name, "cg:brave"),
        _ => panic!("expected ProcessName for cg:-prefixed non-numeric"),
    }
}

/// A u32 overflow after the prefix stays a name (graceful no-op,
/// same contract as the bare beyond-u32 target the CLI pins).
#[test]
fn test_target_parse_cg_prefix_overflow_stays_name() {
    match Target::parse("cg:99999999999999999999") {
        Target::ProcessName(name) => assert_eq!(name, "cg:99999999999999999999"),
        _ => panic!("expected ProcessName for cg:-prefixed overflow"),
    }
}

#[test]
fn test_direction_suffix() {
    assert_eq!(Direction::Download.suffix(), "dl");
    assert_eq!(Direction::Upload.suffix(), "ul");
}

#[test]
fn test_bucket_raw_has_frac_rem() {
    // Verify BucketRaw has 3 fields (24 bytes) for schema v2.
    // v1 was 16 bytes (tokens + last_refill_ns only).
    let b = BucketRaw {
        tokens: 1000,
        last_refill_ns: 12345,
        frac_rem: 999_999_999,
    };
    assert_eq!(b.tokens, 1000);
    assert_eq!(b.last_refill_ns, 12345);
    assert_eq!(b.frac_rem, 999_999_999);
    assert_eq!(
        std::mem::size_of::<BucketRaw>(),
        24,
        "BucketRaw must be 24 bytes (3 × u64) for schema v2"
    );
}

#[test]
fn test_fractional_tracking_precision() {
    const NS_PER_SEC: u64 = 1_000_000_000;

    // Simulate: rate = 97,700 bps (97.7 KB/s), 1000 refills of 1ms each.
    let rate_bps: u64 = 97_700;
    let elapsed_ns: u64 = 1_000_000; // 1ms

    let mut tokens: u64 = 0;
    let mut frac_rem: u64 = 0;

    for _ in 0..1000 {
        let product = elapsed_ns * rate_bps;
        let mut refill_whole = product / NS_PER_SEC;
        let refill_frac = product % NS_PER_SEC;

        let mut new_frac = frac_rem + refill_frac;
        if new_frac >= NS_PER_SEC {
            refill_whole += 1;
            new_frac -= NS_PER_SEC;
        }
        frac_rem = new_frac;
        tokens += refill_whole;
    }

    // With fractional tracking, 1000 × 1ms = 1 second of tokens.
    // Expected: 97,700 bytes (exact rate × 1 second).
    // Without fractional tracking: 97,000 bytes (truncated).
    assert_eq!(
        tokens, 97_700,
        "fractional tracking should give exact rate over 1 second"
    );

    // Verify the error is zero (was 0.72% without fractional tracking).
    let error_pct = ((tokens as i64 - 97_700) as f64 / 97_700.0).abs() * 100.0;
    assert!(
        error_pct < 0.01,
        "error should be < 0.01%, got {error_pct}%"
    );
}

#[test]
fn test_truncation_error_without_fractional() {
    const NS_PER_SEC: u64 = 1_000_000_000;

    let rate_bps: u64 = 97_700;
    let elapsed_ns: u64 = 1_000_000;

    let mut tokens: u64 = 0;

    for _ in 0..1000 {
        // Old formula: integer division, no fractional tracking.
        let refill = (elapsed_ns * rate_bps) / NS_PER_SEC;
        tokens += refill;
    }

    // Without fractional tracking: 97,000 (truncated from 97,700).
    // This is a 0.72% error — the problem fractional tracking fixes.
    assert_eq!(tokens, 97_000);
    let error_pct = (97_700 - tokens) as f64 / 97_700.0 * 100.0;
    assert!(error_pct > 0.5, "truncation error should be > 0.5%");
}

#[test]
fn test_schema_version_constant() {
    // Must match SCHEMA_VERSION in ebpf/src/bin/limiter.rs.
    // When this changes, the BPF code must also change.
    // v11 (NIGHT-think-like-light-years-3): the init-path
    // inserts ride BPF_NOEXIST — the first-packet init race
    // can no longer resurrect tokens or roll the window stamp
    // back under a many-CPU burst on a fresh bucket.
    // v12 (NIGHT-perf-0): AMMSP memos are generation-stamped —
    // the leaf-cache value packs (generation << 32) | root and
    // the new ammsp_generation array invalidates every memo a
    // mutation outlives, one O(1) bump per mutation.
    // v13 (charger-core-1c): the individual lane becomes DRR —
    // the shared bucket a pool, every packet spending from a
    // per-leaf quantum bucket (leaf_bucket_dl/ul).
    // v14 (charger-core-3a): the time-series rings. v15
    // (charger-core-3b): Policy.flags (offset-20 padding becomes
    // contract, bit 0 = per-socket) + the socket bucket maps.
    // v16 (dinner-28): the learned-share draw — the DRR take
    // capped by pool/(learned+2) through the two new
    // drr_pool_state_dl/ul maps.
    // v17 (repair-3/4/6): the epoch ledger, carry-formed — the take
    // further capped by the leaf's banked allowance (the pool's
    // 100ms refill split across the drawee PEAK, earned per epoch
    // and carried quantum-capped) through the two new
    // drr_leaf_state_dl/ul maps, the pool-share word re-packed
    // with the peak, both state maps keyed on the AMMSP generation
    // (a mutated budget hands its successor a fresh word), and the
    // note atomic (the v16 plain-read-plus-BPF_ANY insert lost
    // increments to racing writers until the count itself lied).
    // v18 (NIGHT-hunt-Z1): the AMMSP leaf cache splits into TWO
    // direction-scoped maps (ammsp_leaf_cache_dl/ul) — a memo's
    // root is only valid for the direction whose walk produced it,
    // and the shared map let one direction's resolution poison the
    // other's enforcement under single-direction applies.
    // v19 (NIGHT-private-research-4): ECN-first policing — the
    // budgeted lanes' drop verdict becomes a last resort: an
    // ECT-capable packet is delivered CE-marked through
    // bpf_skb_ecn_set_ce and charges the new ecn_debt_dl/ul words,
    // which the lane's own deliveries pay back out of the token
    // stream's leftover (the budget law, ebpf/src/ecn.rs).
    // v20 (CAKE-shaped flow isolation): the DRR lane's leaf splits
    // per flow — attributed packets spend cookie-keyed flow buckets
    // drawing from the leaf under the DRR laws one level down
    // (flow_share_dl/ul + flow_ledger_dl/ul + flow_bucket_dl/ul),
    // the sparse/dense take law riding the flow bucket's draw-stamp
    // epoch. cookie == 0 rides the leaf lane verbatim.
    // v21 (the per-socket convergence closure): the per-socket lane
    // joins the ECN-first family, mark before drop per connection —
    // the debt word inside SocketBucket (now 40 bytes: core,
    // gen_stamp, ecn_debt), belt-zeroed by the generation stamp,
    // the deferred aggregate-collapse question closed by the
    // rootless fleet sims (ecn_tests.rs, the per-socket
    // convergence analysis).
    // v22 (QUIC-aware attribution): the per-socket lane and the v20
    // flow lane key per-connection buckets by the QUIC connection
    // ID when the header carries finer truth than the socket
    // cookie — long headers statelessly, short headers through the
    // confirmation-gated learned hints (quic_cid_hint_dl/ul, the
    // packed word in ebpf/src/quic.rs). Every refusal rides the raw
    // cookie: the feature refines attribution, never degrades it.
    // v23 (the unified --during time windows): a policy row may
    // carry its own lifetime — the policy_window side map (one row
    // per resolved policy root, both hooks sharing it) and the
    // wall_clock_offset bridge Array, the gate reading the window
    // after the policy hit on the policed path only. The full sync
    // contract (this constant vs the BPF-side anchor) lives in
    // schema.rs's sync_pin — the v13 lesson.
    // v24 (NIGHT-improve-40, the guarantee brackets): the Policy
    // row itself grows floor_bps/ceil_bps (24 -> 40 bytes, the
    // first value-size change a bump ever carried — group_id/flags
    // move to 32/36) — the DRR pool's per-LEAF min/max brackets,
    // the zero sentinel unset on both sides (a 0/0 row is the
    // exact v23 arithmetic, the fail-open posture).
    assert_eq!(SCHEMA_VERSION_EXPECTED, 24);
}

// ── night-during, schema v23: the window row's layout pins ────────

/// The PolicyWindowRaw layout contract: 32 bytes, every field at its
/// pinned offset, the kinds distinct with SPAN at 0 (a zeroed row
/// reads as a zero-length span — the never-active belt, the
/// Default row never a surprise verdict), and the row
/// round-tripping through its bytes identical (the map value IS the
/// byte row; a partial write would be a corrupted window).
#[test]
fn policy_window_raw_layout_is_pinned() {
    use crate::ebpf::limiter::types::{PolicyWindowRaw, WINDOW_KIND_DAILY, WINDOW_KIND_SPAN};

    assert_eq!(core::mem::size_of::<PolicyWindowRaw>(), 32);
    assert_eq!(
        core::mem::offset_of!(PolicyWindowRaw, kind),
        0,
        "kind leads the row (the tag the datapath dispatches on)"
    );
    assert_eq!(core::mem::offset_of!(PolicyWindowRaw, reserved), 4);
    assert_eq!(
        core::mem::offset_of!(PolicyWindowRaw, start_mono_ns),
        8,
        "the u64 pair sits at the 8-aligned offsets"
    );
    assert_eq!(core::mem::offset_of!(PolicyWindowRaw, end_mono_ns), 16);
    assert_eq!(core::mem::offset_of!(PolicyWindowRaw, start_s), 24);
    assert_eq!(core::mem::offset_of!(PolicyWindowRaw, end_s), 28);
    // The kinds: SPAN is 0 so the all-zero Default row is the
    // never-active span belt, never a daily window surprise.
    assert_eq!(WINDOW_KIND_SPAN, 0);
    assert_eq!(WINDOW_KIND_DAILY, 1);
    // The Default row is all zeros (the reserved pad too — every
    // byte of the row is written by construction).
    assert_eq!(
        PolicyWindowRaw::default(),
        PolicyWindowRaw {
            kind: 0,
            reserved: 0,
            start_mono_ns: 0,
            end_mono_ns: 0,
            start_s: 0,
            end_s: 0
        }
    );
    // The byte round-trip: the map value is the row's raw bytes,
    // so a Pod transmute of a full row comes back identical.
    let row = PolicyWindowRaw {
        kind: WINDOW_KIND_DAILY,
        reserved: 0,
        start_mono_ns: 0,
        end_mono_ns: 0,
        start_s: 9 * 3600,
        end_s: 17 * 3600,
    };
    let bytes: [u8; 32] = unsafe { core::mem::transmute(row) };
    let back: PolicyWindowRaw = unsafe { core::mem::transmute(bytes) };
    assert_eq!(row, back, "the window row round-trips through its bytes");
}

// ── NIGHT-improve-10 / security-3: overflow-bound pins ──────────

#[test]
fn test_max_enforcable_burst_exact_bound() {
    // The bound is exact, not rounded: the fill-detect product
    // at the bound stays representable, one past it overflows.
    // This is the invariant the BPF-side clamp (MAX_ENFORCABLE_BURST
    // in ebpf/src/bin/limiter.rs) derives its totality proof from —
    // keep both constants textually in sync. Pinned as VALUES
    // (clippy folds boolean asserts on constants, and a pinned
    // number forces a conscious update when the bound moves).
    assert_eq!(MAX_ENFORCABLE_BURST, 9_223_372_036);
    assert_eq!(
        2 * MAX_ENFORCABLE_BURST * 1_000_000_000,
        18_446_744_072_000_000_000,
        "2 * bound * NS_PER_SEC must be the largest representable multiple"
    );
    // Worst pre-cap token sum: sanitized seed + a full fill-detect
    // refill plus the exact-multiply bound — 3 * bound, still far
    // inside u64.
    assert_eq!(
        3 * MAX_ENFORCABLE_BURST,
        27_670_116_108,
        "worst-case tokens + 2*burst must stay representable (and pinned)"
    );
}

#[test]
fn test_max_enforcable_burst_dwarfs_userspace_burst_ceiling() {
    // default_burst clamps to 100 MB; the enforcement-boundary
    // clamp is ~9.2 GB — every legit userspace write passes the
    // kernel-side clamp untouched (invisible for healthy state).
    use crate::ebpf::limiter::format::default_burst;
    assert!(
        default_burst(u64::MAX) <= MAX_ENFORCABLE_BURST,
        "userspace burst clamp must never trip the enforcement bound"
    );
    assert_eq!(default_burst(u64::MAX), 100_000_000);
}

#[test]
fn test_enforce_math_total_for_corrupt_policy() {
    // Mirror of the ebpf-side security-3 sanitize: ANY stored
    // burst value must leave the refill math overflow-free after
    // the trust-boundary clamp. This simulates the exact sequence
    // ebpf enforce() runs — including the u64::MAX adversary —
    // where the pre-fix math would wrap on the fill-detect
    // multiply and produce garbage enforcement.
    const NS_PER_SEC: u64 = 1_000_000_000;

    for corrupt_burst in [u64::MAX, u64::MAX - 1, MAX_ENFORCABLE_BURST + 1] {
        // The trust-boundary clamp (try_enforce side).
        let burst = corrupt_burst.min(MAX_ENFORCABLE_BURST);
        // Corrupt bucket seed: garbage tokens above the burst.
        let stored_tokens = u64::MAX;

        // The tokens clamp (enforce side).
        let tokens = stored_tokens.min(burst);

        // Refill math with elapsed capped at 1s, rate arbitrary.
        for rate_bps in [1u64, 1_000, 1_000_000_000, u64::MAX] {
            let elapsed = NS_PER_SEC; // worst case after the cap
            let fill_ns = 2 * burst * NS_PER_SEC / rate_bps; // must not overflow
            let refill_whole = if elapsed >= fill_ns {
                burst
            } else {
                // Only reachable when product < 2 * burst * NS_PER_SEC.
                let product = elapsed
                    .checked_mul(rate_bps)
                    .expect("product must be representable inside the fill-detect bound");
                product / NS_PER_SEC
            };
            let new_tokens = tokens
                .checked_add(refill_whole)
                .expect("tokens + refill must be representable after both clamps");
            let capped = new_tokens.min(burst);
            assert_eq!(
                capped, burst,
                "a clamped adversary lands at burst, not garbage"
            );
        }
    }
}

// ── charger-core-3b: the flags field's layout contract pins ────────

/// The offset-20 padding became the flags field at v15; the v24
/// guarantee pair (NIGHT-improve-40) slots between burst_bytes and
/// the tail word pair, moving group_id/flags to 32/36 and growing
/// the struct 24 -> 40 — the numbers the v24 layout contract
/// rides, pinned so no future field can silently shift the layout
/// the pinned maps carry (the first VALUE-SIZE change a schema
/// bump ever carried: a pinned v23 map holds 24-byte rows this
/// object must never be asked to read).
#[test]
fn policy_raw_flags_layout_is_pinned() {
    use crate::ebpf::limiter::types::{PolicyRaw, POLICY_FLAG_PER_SOCKET};

    assert_eq!(core::mem::size_of::<PolicyRaw>(), 40);
    assert_eq!(core::mem::offset_of!(PolicyRaw, floor_bps), 16);
    assert_eq!(core::mem::offset_of!(PolicyRaw, ceil_bps), 24);
    assert_eq!(core::mem::offset_of!(PolicyRaw, group_id), 32);
    assert_eq!(
        core::mem::offset_of!(PolicyRaw, flags),
        36,
        "flags rides the tail word pair, after the v24 guarantee slots"
    );
    assert_eq!(POLICY_FLAG_PER_SOCKET, 1);
    // The default write is the legacy cgroup lane: flags 0, and the
    // bracket's zero sentinel is UNSET on both sides (the v23
    // arithmetic, exactly — the fail-open posture).
    assert_eq!(PolicyRaw::default().flags, 0);
    assert_eq!(PolicyRaw::default().floor_bps, 0);
    assert_eq!(PolicyRaw::default().ceil_bps, 0);
}
