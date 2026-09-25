// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-boost-38: SMP invariant pins for the eBPF token-bucket math
//! (ebpf/src/math.rs — the same file the BPF object builds). The
//! v6-and-earlier enforce lost updates whenever two CPUs enforced the
//! same bucket concurrently (the E2E strict-multi / curl-burst
//! over-delivery, 130-146% of budget under 2-6 flows); the v7 rewrite
//! is lock-free atomics. These pins hold the v7 invariants under real
//! thread contention — the properties that make the race impossible:
//!
//!  * consume conservation — the sum of allowed bytes plus the final
//!    token stock equals the seed exactly; a resurrected deduction
//!    (the over-allow shape) breaks this to the byte;
//!  * window exclusivity — the allowed bytes never exceed the seed
//!    plus the union-span credit at rate (a double-credited window
//!    breaks it), pinned with a rate whose per-window credit is
//!    integer (1e9 % rate == 0) so the bound is exact, not
//!    epsilon-tolerant;
//!  * counter atomicity — the stats ledger matches the thread-local
//!    tallies exactly, no lost increments;
//!  * single-thread window ownership — the CAS that replaces the v6
//!    unconditional store is behaviorally identical: it advances on
//!    forward time, moves back on the anomalous backward clock, and
//!    credits only owned windows.
//!
//! The concurrency model matches production: the BPF program runs on
//! many CPUs against ONE map value, and aya hands each CPU its own
//! `&mut` to that same value (get_bucket_ptr's `&mut *ptr` — the
//! pattern limiter.rs has used since the port). The sharing harness
//! below reproduces exactly that reality through raw pointers; every
//! access inside enforce is a raw-pointer projection (addr_of_mut!)
//! or an atomic, never a reference read/write.

// The production arithmetic, via the sibling math_tests' inclusion
// (one copy of ebpf/src/math.rs per test binary — the duplicate-mod
// lint clippy -D warnings rejects two inclusions of the same file).
use super::math_tests::ebpf_math;

use self::ebpf_math::{enforce, refill_credits, Bucket, LimiterStats, Policy, NS_PER_SEC};
use std::ptr;
use std::thread;

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

/// One bucket + one stats entry shared across threads — the map-value
/// reality. The raw pointers are to boxed values owned by the
/// spawning thread and outlive every scope join.
#[derive(Clone, Copy)]
struct SharedHandle {
    bucket: *mut Bucket,
    stats: *mut LimiterStats,
}

// SAFETY: the handle crosses threads only to reproduce the BPF
// runtime's many-CPUs-one-map-value reality; enforce touches the
// structs solely through raw-pointer projections and atomics (see
// the module docs), the same pattern the production program's
// get_ptr_mut + `&mut *ptr` established.
unsafe impl Send for SharedHandle {}

impl SharedHandle {
    // SAFETY: same disclosure as the Send impl.
    unsafe fn hit(&self, pol: &Policy, pkt_len: u32, now: u64) -> i32 {
        unsafe { enforce(pol, &mut *self.bucket, pkt_len, now, Some(&mut *self.stats)) }
    }
}

fn handle_of(shared: &mut Shared) -> SharedHandle {
    SharedHandle {
        bucket: ptr::addr_of_mut!(*shared.bucket),
        stats: ptr::addr_of_mut!(*shared.stats),
    }
}

struct Shared {
    bucket: Box<Bucket>,
    stats: Box<LimiterStats>,
}

// ── consume conservation under contention ─────────────────────────────────

/// Constant `now` (zero elapsed, no refill, no window CAS): a pure
/// concurrent-consume hammer. Conservation is EXACT — the allowed
/// bytes plus the final stock equal the seed to the byte, and the
/// ledger matches the thread-local tallies to the packet. The v6
/// plain read-modify-write breaks both (a resurrected deduction
/// pushes the allowed sum past the seed).
#[test]
fn smp_consume_conserves_tokens_exactly() {
    const THREADS: usize = 8;
    const HITS: usize = 25_000;
    const PKT: u32 = 7;
    let seed: u64 = 100_000;
    let policy = pol(1_000_000, 100_000);
    let mut shared = Shared {
        bucket: Box::new(bkt(seed, 0, 1_000)),
        stats: Box::new(fresh_stats()),
    };
    let handle = handle_of(&mut shared);
    let results: Vec<u64> = thread::scope(|s| {
        let joins: Vec<_> = (0..THREADS)
            .map(|_| {
                s.spawn(move || {
                    let mut allowed: u64 = 0;
                    for _ in 0..HITS {
                        // SAFETY: see the SharedHandle disclosure.
                        if unsafe { handle.hit(&policy, PKT, 1_000) } == 1 {
                            allowed += 1;
                        }
                    }
                    allowed
                })
            })
            .collect();
        joins
            .into_iter()
            .map(|j| j.join().expect("worker"))
            .collect()
    });
    let allowed_packets: u64 = results.iter().sum();
    let dropped_packets: u64 = (THREADS * HITS) as u64 - allowed_packets;
    let allowed_bytes = allowed_packets * u64::from(PKT);
    let b = &*shared.bucket;
    let st = &*shared.stats;
    // Consume conservation, exact: every allowed byte was deducted
    // from the stock once and only once.
    assert_eq!(
        b.tokens + allowed_bytes,
        seed,
        "resurrected deduction: stock {} + allowed {allowed_bytes} must equal the seed {seed}",
        b.tokens
    );
    // The stock never wrapped negative (a fetch_sub-and-revert shape
    // would transiently wrap to a huge u64; the CAS consume cannot).
    assert!(b.tokens <= seed);
    // Ledger atomicity, exact: every verdict counted once.
    assert_eq!(st.packets_allowed, allowed_packets);
    assert_eq!(st.packets_dropped, dropped_packets);
    assert_eq!(st.bytes_allowed, allowed_bytes);
    assert_eq!(st.bytes_dropped, dropped_packets * u64::from(PKT));
    // Every allowed packet cost PKT against the seed stock; the seed
    // admits exactly floor(seed/PKT) of them under any interleaving.
    assert_eq!(allowed_packets, seed / u64::from(PKT));
}

// ── the NIGHT-lts-8 budget-covers contract (the consume retry) ────────────

/// The retry's hard contract, re-pinned after the first CI catch
/// (2026-09-25, gnu-dynamic on ubuntu-24.04: 511 of 512 allowed):
/// four attempts make a false drop a TAIL, not an impossibility —
/// a thread can lose the read-then-CAS race four times in a row,
/// and the 200-run design probe never saw the tail that thousands
/// of CI runs eventually hit. Two contracts now: EXACT, every
/// round — conservation and ledger atomicity (the race-impossible
/// invariants); BOUNDED TAIL — a zero-drop round inside a 64-round
/// budget. The single-attempt shape dropped 1.425 per round here
/// (~24% clean rounds): 64 dirty rounds is ~1e-7 — a retry removal
/// cannot slip through, and the tail can never fail the budget.
#[test]
fn smp_budget_covers_lets_every_packet_through() {
    const THREADS: usize = 2;
    const HITS: usize = 256;
    const PKT: u32 = 1;
    const ROUNDS: usize = 64;
    let demand: u64 = (THREADS * HITS) as u64;
    let mut clean_rounds = 0usize;
    for _round in 0..ROUNDS {
        // rate 0 keeps the refill inert; burst = seed so the clamp
        // never fires. A FRESH bucket and ledger per round — each
        // round is the original single-run scenario verbatim.
        let policy = pol(0, demand);
        let mut shared = Shared {
            bucket: Box::new(bkt(demand, 0, 1_000)),
            stats: Box::new(fresh_stats()),
        };
        let handle = handle_of(&mut shared);
        let allowed: u64 = thread::scope(|s| {
            let joins: Vec<_> = (0..THREADS)
                .map(|_| {
                    s.spawn(move || {
                        let mut allowed = 0;
                        for _ in 0..HITS {
                            // SAFETY: see the SharedHandle disclosure.
                            if unsafe { handle.hit(&policy, PKT, 1_000) } == 1 {
                                allowed += 1;
                            }
                        }
                        allowed
                    })
                })
                .collect();
            joins.into_iter().map(|j| j.join().expect("worker")).sum()
        });
        let dropped = demand - allowed;
        let st = &*shared.stats;
        // Conservation and ledger atomicity, exact, every round.
        assert_eq!(
            shared.bucket.tokens + st.bytes_allowed,
            demand,
            "conservation broke — a lost update or a resurrected deduction"
        );
        assert_eq!(st.packets_allowed, allowed);
        assert_eq!(st.packets_dropped, dropped);
        assert_eq!(st.bytes_allowed, allowed);
        assert_eq!(st.bytes_dropped, dropped);
        // Each packet had only its own four attempts — a clean round
        // is the retry doing its job.
        if dropped == 0 {
            clean_rounds += 1;
        }
    }
    assert!(
        clean_rounds > 0,
        "no zero-drop round in {ROUNDS} rounds — the consume retry \
         regressed (the single-attempt shape drops ~1.4 per round here)"
    );
}

/// The retry's soft contract under heavy oversubscription: eight
/// threads on one bucket (the many-CPU burst shape the lts-8 audit
/// named), seed exactly covering demand. The single-attempt shape
/// measured 27.55 false drops per 2048-packet run here (1.35%); the
/// four-attempt retry measured 0.975 (0.048%). The pin bounds the
/// drop rate at 1% — 20x above the measured retry residual, 1.4x
/// below the single-attempt rate — so a retry removal fails it with
/// near-certainty while no healthy host class can flake it. Exact
/// conservation holds regardless (the hard invariant).
#[test]
fn smp_retry_reduces_false_drops_under_oversubscription() {
    const THREADS: usize = 8;
    const HITS: usize = 256;
    const PKT: u32 = 1;
    let demand: u64 = (THREADS * HITS) as u64;
    let policy = pol(0, demand);
    let mut shared = Shared {
        bucket: Box::new(bkt(demand, 0, 1_000)),
        stats: Box::new(fresh_stats()),
    };
    let handle = handle_of(&mut shared);
    let allowed: u64 = thread::scope(|s| {
        let joins: Vec<_> = (0..THREADS)
            .map(|_| {
                s.spawn(move || {
                    let mut allowed = 0;
                    for _ in 0..HITS {
                        // SAFETY: see the SharedHandle disclosure.
                        if unsafe { handle.hit(&policy, PKT, 1_000) } == 1 {
                            allowed += 1;
                        }
                    }
                    allowed
                })
            })
            .collect();
        joins.into_iter().map(|j| j.join().expect("worker")).sum()
    });
    let dropped = demand - allowed;
    let st = &*shared.stats;
    // Conservation, exact (the never-over-allow / never-resurrect
    // invariants — absolute under any contention).
    assert_eq!(shared.bucket.tokens + st.bytes_allowed, demand);
    assert_eq!(st.packets_allowed, allowed);
    assert_eq!(st.packets_dropped, dropped);
    // The retry's quantitative contract: under 1% false drops. The
    // single-attempt shape measured 1.35% — this bound is what a
    // retry removal breaks.
    assert!(
        (dropped * 100) < demand,
        "{dropped} of {demand} affordable packets dropped ({}%) — the consume retry regressed",
        dropped * 100 / demand
    );
}

// ── refill window exclusivity under contention ─────────────────────────────

/// Eight threads hammer the bucket through a SHARED fetch_add clock —
/// the kernel's own timestamp reality (every CPU samples the same
/// global monotonic clock at packet-processing time; the fetch order
/// IS the processing order). Each hit draws the next 1 ms tick, so
/// every window credits exactly 1 byte at rate 1000 B/s (integer,
/// no fraction anywhere) and the union of all owned windows is a
/// sub-interval of the tick span. The ceiling is exact: allowed
/// bytes cannot exceed the seed plus the tick-span credit — a
/// double-credited window (two CPUs owning one interval) or a
/// backward re-credit (the stall fountain the v6 unconditional
/// stamp-store left open) breaks it. Threads stall and race freely
/// between their tick fetch and their ownership CAS; the invariant
/// must hold for every interleaving.
#[test]
fn smp_refill_never_double_credits() {
    const THREADS: u64 = 8;
    const STEPS: u64 = 20_000;
    const TICK_NS: u64 = 1_000_000; // 1 ms per tick
    const RATE: u64 = 1_000; // TICK * RATE == 1e9: exactly 1 B/tick
    const BURST: u64 = 50;
    const T0: u64 = 1_000_000_000;
    let total_ticks = THREADS * STEPS;
    let span_credit = total_ticks; // 1 byte per tick, exact
                                   // +2: the shared fraction bank may hold at most one carried
                                   // byte at quiesce (stalled windows credit floor() and bank the
                                   // remainder; the bank is part of the true total, paid late).
    let ceiling = BURST + span_credit + 2;
    let policy = pol(RATE, BURST);
    let mut shared = Shared {
        bucket: Box::new(bkt(BURST, 0, T0)),
        stats: Box::new(fresh_stats()),
    };
    let handle = handle_of(&mut shared);
    let clock = &std::sync::atomic::AtomicU64::new(T0);
    let results: Vec<u64> = thread::scope(|s| {
        let joins: Vec<_> = (0..THREADS)
            .map(|_| {
                s.spawn(move || {
                    let mut allowed: u64 = 0;
                    for _ in 0..STEPS {
                        let now = clock.fetch_add(TICK_NS, std::sync::atomic::Ordering::Relaxed);
                        // SAFETY: see the SharedHandle disclosure.
                        if unsafe { handle.hit(&policy, 1, now) } == 1 {
                            allowed += 1;
                        }
                    }
                    allowed
                })
            })
            .collect();
        joins
            .into_iter()
            .map(|j| j.join().expect("worker"))
            .collect()
    });
    let allowed_packets: u64 = results.iter().sum();
    // Window exclusivity, exact: pkt_len 1 makes allowed bytes equal
    // allowed packets, so no rounding slack exists anywhere.
    assert!(
        allowed_packets <= ceiling,
        "double-credited window or backward re-credit: allowed {allowed_packets} exceeds seed {BURST} + tick credit {span_credit}"
    );
    // The final stock is capped at burst plus at most one refill
    // quantum (a one-shot cap CAS that lost its race and saw no
    // later packet to retry it; the elapsed cap bounds the quantum
    // at 1 s of rate).
    let b = &*shared.bucket;
    assert!(
        b.tokens <= BURST + RATE,
        "stock {} beyond burst + one capped quantum",
        b.tokens
    );
    // The stats ledger counted every verdict (atomic fetch_add).
    let st = &*shared.stats;
    assert_eq!(st.packets_allowed, allowed_packets);
    assert_eq!(st.bytes_allowed, allowed_packets);
    assert_eq!(st.packets_allowed + st.packets_dropped, total_ticks);
}

// ── single-thread window ownership pins (v6 parity) ───────────────────────

/// The ownership CAS replaces v6's unconditional store; single-
/// threaded it must behave identically: forward time advances the
/// stamp, the owned window credits exactly what refill_credits
/// computes, and the fraction carries across windows.
#[test]
fn single_thread_window_ownership_matches_v6() {
    // rate 333_333 leaves a fractional remainder every step — the
    // carry arithmetic is exercised on each owned window.
    let policy = pol(333_333, 10_000);
    let mut b = bkt(0, 0, 1_000);
    let mut st = fresh_stats();
    // 3 ms window: product = 3_000 * 333_333 = 999_999_000 rate-ns
    // -> 0 whole bytes, remainder 999_999_000 banked. No tokens yet,
    // the 1-byte packet drops — but the window was owned.
    assert_eq!(enforce(&policy, &mut b, 1, 4_000, Some(&mut st)), 0);
    assert_eq!(b.last_refill_ns, 4_000);
    assert_eq!(b.frac_rem, 999_999_000);
    assert_eq!(b.tokens, 0);
    assert_eq!(st.packets_dropped, 1);
    // Second 3 ms window: the stored remainder 999_999_000 plus the
    // fresh 999_999_000 crosses 1e9 -> carry 1 whole byte, credited
    // and immediately spent on the packet.
    assert_eq!(enforce(&policy, &mut b, 1, 7_000, Some(&mut st)), 1);
    assert_eq!(b.last_refill_ns, 7_000);
    assert_eq!(b.frac_rem, 999_998_000);
    assert_eq!(b.tokens, 0);
    assert_eq!(st.packets_allowed, 1);
    assert_eq!(st.bytes_allowed, 1);
}

/// The stale-sampler rule replaces v6's unconditional stamp store;
/// single-threaded with a monotonic clock the forward case is
/// identical, and the two anomalous shapes get the v7 treatment:
/// a small backward excursion (cross-CPU skew in the kernel — never
/// reachable single-threaded with a real monotonic clock) stays
/// skipped, and an absurd future stamp heals with no credit (the
/// v6 hostile-state guard, preserved).
#[test]
fn single_thread_window_stamp_rule_matches_v7() {
    let policy = pol(1_000, 10_000);
    let mut b = bkt(500, 0, 10_000);
    let mut st = fresh_stats();
    // now == last: the degenerate case — v6 wrote the same value
    // back; v7 skips the CAS because nothing would change.
    assert_eq!(enforce(&policy, &mut b, 100, 10_000, Some(&mut st)), 1);
    assert_eq!(b.last_refill_ns, 10_000);
    assert_eq!(b.tokens, 400);
    // now < last, small excursion: skipped — the stamp stays put
    // (moving it back would re-credit an interval another owner
    // already paid; see the math.rs window-rule comment).
    assert_eq!(enforce(&policy, &mut b, 100, 9_000, Some(&mut st)), 1);
    assert_eq!(b.last_refill_ns, 10_000);
    assert_eq!(b.tokens, 300);
    assert_eq!(st.packets_allowed, 2);
    assert_eq!(st.bytes_allowed, 200);
}

/// The hostile future stamp heals: an absurd backward excursion
/// (beyond any legitimate scheduling skew) resets the stamp to now
/// with zero credit — the v6 sanitization family's answer to a
/// corrupted last_refill_ns, preserved in v7.
#[test]
fn single_thread_hostile_future_stamp_heals() {
    let policy = pol(1_000, 10_000);
    // last_refill_ns 10 s into the future: drifted or hostile.
    let mut b = bkt(0, 0, 20_000_000_000);
    let mut st = fresh_stats();
    assert_eq!(
        enforce(&policy, &mut b, 100, 10_000_000_000, Some(&mut st)),
        0
    );
    assert_eq!(b.last_refill_ns, 10_000_000_000);
    assert_eq!(b.tokens, 0);
    assert_eq!(st.packets_dropped, 1);
}

/// The seed clamp keeps its v6 in-place rewrite: a hostile token
/// stock above burst collapses to burst before any consume.
#[test]
fn single_thread_hostile_stock_clamps_in_place() {
    let policy = pol(1_000, 10_000);
    let mut b = bkt(u64::MAX / 2, 0, 5_000);
    let mut st = fresh_stats();
    assert_eq!(enforce(&policy, &mut b, 4_000, 5_000, Some(&mut st)), 1);
    assert_eq!(b.tokens, 10_000 - 4_000);
    assert_eq!(st.bytes_allowed, 4_000);
}

// ── refill_credits pure pins ───────────────────────────────────────────────

#[test]
fn refill_credits_zero_elapsed_keeps_healthy_frac() {
    assert_eq!(refill_credits(1_000, 10, 0, 123), (0, 123));
    // The v6 sanitize: an anomalous remainder reads as empty.
    assert_eq!(refill_credits(1_000, 10, 0, NS_PER_SEC), (0, 0));
    assert_eq!(refill_credits(1_000, 10, 0, NS_PER_SEC + 1), (0, 0));
    // Zero rate: no credit, the healthy fraction survives untouched.
    assert_eq!(refill_credits(0, 10, 1_000, 456), (0, 456));
}

#[test]
fn refill_credits_idle_cap_bounds_the_window() {
    // 2 seconds of idle credits at most 1 second of rate.
    assert_eq!(refill_credits(1_000, 10_000, 2_000_000_000, 0), (1_000, 0));
}

#[test]
fn refill_credits_carry_is_exact() {
    // 1e9 % 333_333 != 0: a 3_000 ns window banks remainder
    // 999_999_000; a stored healthy frac of 2_000 tips the sum past
    // 1e9 (1_000_001_000) -> carry 1 whole byte, bank 1_000.
    let (whole, frac) = refill_credits(333_333, 10_000, 3_000, 2_000);
    assert_eq!(whole, 1);
    assert_eq!(frac, 1_000);
    // The doubled remainder carries the same way.
    let (whole, frac) = refill_credits(333_333, 10_000, 3_000, 999_999_000);
    assert_eq!(whole, 1);
    assert_eq!(frac, 999_998_000);
}
