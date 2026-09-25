// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-depthbore-1: precision pins for the eBPF token-bucket math
//! (ebpf/src/math.rs — the same file the BPF object builds). Before
//! this harness the refill arithmetic was provable only through
//! root-run integration; these pins make the sharpest knife in the
//! repo testable rootlessly. Every pin maps to a documented contract:
//!
//!  * fill-detect equivalence and threshold — the branch is the
//!    overflow guard, not a behavior change;
//!  * fractional-carry exactness — long-run admitted bytes equal
//!    rate x elapsed exactly, no 0.5-1% truncation drift (the
//!    frac_rem reason to exist);
//!  * conservation — the math never creates or destroys tokens;
//!  * the hostile-state clamp triple (burst, tokens, frac) — schema
//!    v6 completed the family;
//!  * steady-state exactness — one second at 1 MB/s admits exactly
//!    1,000,000 bytes, to the byte.

// The production arithmetic itself, compiled into this test module:
// the SAME file the BPF object builds (ebpf/src/bin/limiter.rs wires
// it with its own #[path]). Only the test tree reaches across
// trees — src/ wirings stay under test/ (the gate-tree discipline).
// NIGHT-boost-38: pub(super) so the sibling math_smp_tests reuses
// THIS copy — one inclusion of math.rs per test binary (the
// duplicate-mod lint clippy -D warnings rightly rejects two).
#[path = "../../../ebpf/src/math.rs"]
pub(super) mod ebpf_math;

use self::ebpf_math::{enforce, Bucket, LimiterStats, Policy, MAX_ENFORCABLE_BURST, NS_PER_SEC};

fn pol(rate: u64, burst: u64) -> Policy {
    Policy {
        rate_bps: rate,
        burst_bytes: burst,
        group_id: 0,
    }
}

fn bkt(tokens: u64, frac: u64, last: u64) -> Bucket {
    Bucket {
        tokens,
        last_refill_ns: last,
        frac_rem: frac,
    }
}

fn fresh_stats() -> LimiterStats {
    LimiterStats {
        packets_allowed: 0,
        packets_dropped: 0,
        bytes_allowed: 0,
        bytes_dropped: 0,
    }
}

// ── fill-detect: the overflow guard, behaviorally invisible ─────────────

#[test]
fn fill_detect_matches_exact_branch_at_the_threshold() {
    // rate 1 TB/s, burst 100 MB: fill_ns = 2 * burst * NS / rate
    // = 200,000 ns. One tick below the threshold takes the exact
    // branch (product ~2 x burst, well inside u64); at and above it
    // the fill-detect branch skips the multiply. Both must land on
    // the same state: full bucket, empty fraction.
    let rate = 1_000_000_000_000u64;
    let burst = 100_000_000u64;
    let fill_ns = 2 * burst * NS_PER_SEC / rate;

    let mut below = bkt(0, 0, 0);
    enforce(&pol(rate, burst), &mut below, 0, fill_ns - 1, None);
    assert_eq!(
        below.tokens, burst,
        "exact branch below fill_ns must cap at burst"
    );
    assert_eq!(below.frac_rem, 0, "cap branch resets the fraction");

    let mut at = bkt(0, 0, 0);
    enforce(&pol(rate, burst), &mut at, 0, fill_ns, None);
    assert_eq!(at.tokens, burst, "fill-detect at fill_ns must credit burst");
    assert_eq!(at.frac_rem, 0);

    let mut above = bkt(0, 0, 0);
    enforce(&pol(rate, burst), &mut above, 0, 10 * fill_ns, None);
    assert_eq!(above.tokens, burst);
    assert_eq!(above.frac_rem, 0);
}

#[test]
fn exact_branch_survives_the_largest_legal_product() {
    // The stress corner the fill-detect exists for: burst at the
    // MAX_ENFORCABLE_BURST bound, rate high enough that one elapsed
    // second would overflow if the multiply ever ran unguarded. The
    // elapsed cap keeps elapsed <= 1s and the threshold keeps the
    // exact branch below 2 * burst * NS_PER_SEC == u64::MAX at the
    // bound — this pin runs the corner and asserts no overflow
    // (test builds have overflow checks ON, so a wrap here panics).
    let burst = MAX_ENFORCABLE_BURST;
    let rate = 1_000_000_000_000u64;
    let fill_ns = 2 * burst * NS_PER_SEC / rate;

    let mut b = bkt(0, 0, 0);
    // elapsed just under the threshold: the largest product the
    // exact branch can ever form.
    enforce(&pol(rate, burst), &mut b, 0, fill_ns - 1, None);
    assert_eq!(b.tokens, burst, "the largest legal refill caps at burst");

    // elapsed above the threshold AND above the 1s cap: fill-detect,
    // no multiply at all.
    let mut b2 = bkt(0, 0, 0);
    enforce(&pol(rate, burst), &mut b2, 0, NS_PER_SEC * 10, None);
    assert_eq!(b2.tokens, burst);
}

// ── fractional carry: the precision frac_rem exists for ────────────────

#[test]
fn steady_state_one_second_at_1mbps_is_exact_to_the_byte() {
    // The headline: 1000 ticks of 1ms at rate 1 MB/s refill exactly
    // 1000 bytes per tick (product 1e12, no remainder), and a
    // 1000-byte packet per tick is admitted every time. Zero drops,
    // zero drift, tokens back where they started.
    let rate = 1_000_000u64;
    let burst = 1_000_000u64;
    let mut b = bkt(0, 0, 0);
    let mut st = fresh_stats();

    for tick in 1..=1000u64 {
        let now = tick * 1_000_000; // 1ms steps
        let verdict = enforce(&pol(rate, burst), &mut b, 1000, now, Some(&mut st));
        assert_eq!(
            verdict, 1,
            "every 1000B packet must pass at 1MB/s steady state"
        );
    }
    assert_eq!(st.packets_allowed, 1000);
    assert_eq!(
        st.bytes_allowed, 1_000_000,
        "exactly rate x one second, to the byte"
    );
    assert_eq!(st.packets_dropped, 0);
    assert_eq!(b.tokens, 0);
    assert_eq!(b.frac_rem, 0);
}

#[test]
fn frac_carry_recovers_every_truncated_byte() {
    // rate 1,500,003 B/s in 1ms ticks: each tick's product
    // (1.500003e12) truncates to 1500 whole bytes and banks 3000 ns
    // of remainder. After 1000 ticks the banked remainder has
    // carried exactly the 3 missing bytes: conservation holds to the
    // byte — no 0.5-1% drift, which is the documented reason
    // frac_rem exists.
    let rate = 1_500_003u64;
    let burst = 1_000_000_000u64; // no cap interaction in this pin
    let mut b = bkt(0, 0, 0);
    let mut st = fresh_stats();

    for tick in 1..=1000u64 {
        let now = tick * 1_000_000;
        enforce(&pol(rate, burst), &mut b, 1, now, Some(&mut st));
    }
    // Conservation: every refilled byte is either spent on a packet
    // or still in the bucket — tokens + consumed == refilled.
    let refilled = b.tokens + st.bytes_allowed;
    assert_eq!(
        refilled, 1_500_003,
        "long-run refill equals rate x elapsed exactly"
    );
    assert_eq!(b.frac_rem, 0, "the fraction bank ends the second at zero");
}

#[test]
fn frac_carry_odd_rate_long_run() {
    // rate 7 B/s, 1ms ticks: per-tick product 7e6 truncates to 0
    // bytes for 142 straight ticks until the remainder crosses one
    // second. 1e6 ticks (= 1000 s) must admit exactly 7000 bytes.
    // Burst stays high enough that the cap never interferes with
    // the accounting.
    let rate = 7u64;
    let burst = 1_000_000u64;
    let mut b = bkt(0, 0, 0);

    for tick in 1..=1_000_000u64 {
        let now = tick * 1_000_000;
        enforce(&pol(rate, burst), &mut b, 0, now, None);
    }
    assert_eq!(
        b.tokens, 7000,
        "1000 seconds at 7 B/s is exactly 7000 bytes"
    );
    assert_eq!(b.frac_rem, 0);
}

// ── idle and the elapsed cap ───────────────────────────────────────────

#[test]
fn elapsed_is_capped_at_one_second() {
    // 10s of idle and exactly 1s of idle must refill identically:
    // the cap bounds burst-after-idle, and at default burst
    // (1s of rate) both land on a full bucket with a reset fraction.
    let rate = 1_000_000u64;
    let burst = 1_000_000u64;

    let mut ten = bkt(0, 0, 0);
    enforce(&pol(rate, burst), &mut ten, 0, 10 * NS_PER_SEC, None);
    let mut one = bkt(0, 0, 0);
    enforce(&pol(rate, burst), &mut one, 0, NS_PER_SEC, None);

    assert_eq!(ten.tokens, burst);
    assert_eq!(one.tokens, burst);
    assert_eq!(ten.frac_rem, one.frac_rem);
    assert_eq!(ten.last_refill_ns, 10 * NS_PER_SEC);
}

#[test]
fn zero_elapsed_does_not_refill() {
    // Back-to-back packets in one timestamp: no free tokens.
    let mut b = bkt(500, 0, 1_000);
    enforce(&pol(1_000_000, 100_000), &mut b, 100, 1_000, None);
    assert_eq!(b.tokens, 400);
    // Time running backwards is elapsed zero, never a negative.
    enforce(&pol(1_000_000, 100_000), &mut b, 100, 500, None);
    assert_eq!(b.tokens, 300);
}

// ── verdicts, remainders, stats booking ────────────────────────────────

#[test]
fn drop_keeps_the_refilled_remainder() {
    // The silent-killer precision: a dropped packet leaves its
    // refilled tokens in place, not zeroed — the next smaller packet
    // passes on the saved-up remainder.
    let rate = 100_000u64;
    let burst = 10_000u64;
    let mut b = bkt(50, 0, 0);
    let mut st = fresh_stats();

    // 1ms refills 100 tokens -> 150 total: a 1000B packet drops,
    // tokens stay 150.
    let v = enforce(&pol(rate, burst), &mut b, 1000, 1_000_000, Some(&mut st));
    assert_eq!(v, 0);
    assert_eq!(b.tokens, 150);
    assert_eq!(st.packets_dropped, 1);
    assert_eq!(st.bytes_dropped, 1000);

    // Another 1ms: 250 total, a 200B packet passes, 50 remain.
    let v = enforce(&pol(rate, burst), &mut b, 200, 2_000_000, Some(&mut st));
    assert_eq!(v, 1);
    assert_eq!(b.tokens, 50);
    assert_eq!(st.packets_allowed, 1);
    assert_eq!(st.bytes_allowed, 200);
}

// ── conservation under churn (deterministic adversarial load) ──────────

#[test]
fn conservation_bound_holds_under_churn() {
    // Deterministic LCG churn: 20k events of random gaps (0..2ms)
    // and packet sizes (800..2000B, averaging ABOVE the 1000B/ms
    // refill so the bucket actually drains and enforcement engages)
    // at 1 MB/s / 1 MB burst, starting from a drained bucket. The
    // invariant the bucket promises: admitted bytes never exceed
    // seed + refill, and refill never exceeds rate x capped-elapsed
    // (+1 byte per event for the carry's floor edge).
    let rate = 1_000_000u64;
    let burst = 1_000_000u64;
    let mut b = bkt(0, 0, 0);
    let mut st = fresh_stats();
    let mut lcg: u64 = 0x9E3779B97F4A7C15;
    let mut capped_elapsed = 0u64;
    let mut now = 0u64;

    for _ in 0..20_000 {
        lcg = lcg
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let dt = lcg % 2_000_000; // 0..2ms
        let pkt = 800 + (lcg >> 32) % 1201; // 800..2000
        now += dt;
        capped_elapsed += dt.min(NS_PER_SEC);
        enforce(&pol(rate, burst), &mut b, pkt as u32, now, Some(&mut st));
    }
    let bound = rate * capped_elapsed / NS_PER_SEC + 20_000;
    assert!(
        st.bytes_allowed <= bound,
        "admitted {} exceeds the conservation bound {}",
        st.bytes_allowed,
        bound
    );
    assert!(st.packets_dropped > 0, "churn must engage enforcement");
}

// ── the hostile-state clamp triple (schema v6 completes it) ────────────

#[test]
fn hostile_tokens_and_frac_are_sanitized_not_wrapped() {
    // The security-3/v6 trust boundary: a bucket written by a
    // hostile root process carries tokens = u64::MAX and
    // frac_rem = u64::MAX. Pre-v6 the frac addition wrapped (silent
    // garbage in the release BPF build, a panic under these test
    // overflow checks). The clamp triple treats the anomalous bucket
    // as full with an empty fraction — and enforcement proceeds.
    let rate = 1_000_000u64;
    let burst = 5_000u64;
    let mut b = bkt(u64::MAX, u64::MAX, 0);
    let mut st = fresh_stats();

    // 1ms refills 1000 tokens; the clamp caps everything at burst.
    let v = enforce(&pol(rate, burst), &mut b, 1500, 1_000_000, Some(&mut st));
    assert_eq!(v, 1, "a full sanitized bucket admits the packet");
    assert_eq!(b.tokens, burst - 1500);
    assert_eq!(
        b.frac_rem, 0,
        "hostile fraction is zeroed once, then stays healthy"
    );
    assert_eq!(b.last_refill_ns, 1_000_000);

    // The stored garbage never comes back: the next refill works on
    // the sanitized state.
    enforce(&pol(rate, burst), &mut b, 0, 2_000_000, None);
    assert_eq!(b.tokens, burst - 500);
    assert!(b.frac_rem < NS_PER_SEC);
}

#[test]
fn hostile_frac_just_above_one_second_is_zeroed() {
    // The smallest hostile value: exactly NS_PER_SEC. A healthy
    // remainder is always < NS_PER_SEC (the math's own invariant),
    // so this is drift by definition — v6 zeroes it instead of
    // letting frac + refill_frac wrap. This tick (1ms at 1000 B/s)
    // refills exactly 1 byte with zero remainder.
    let mut b = bkt(0, NS_PER_SEC, 0);
    enforce(&pol(1_000, 4096), &mut b, 0, 1_000_000, None);
    assert_eq!(
        b.frac_rem, 0,
        "sanitized seed; this tick's remainder is zero"
    );
    assert_eq!(
        b.tokens, 1,
        "product 1e9 at rate 1000 refills exactly 1 byte"
    );
}
