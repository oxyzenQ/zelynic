// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! private-research-4: rootless pins for the ECN-first debt core
//! (ebpf/src/ecn.rs, the same file the BPF object builds, wired below
//! with #[path]). Every pin maps to a documented contract in that
//! module and in the schema v19 entry (src/ebpf/limiter/schema.rs):
//!
//!  * the cap law — ECN_DEBT_CAP rides the GSO admit floor (the
//!    drr.rs law, one constant across both lanes' starvation heals);
//!  * charge semantics — accumulation under the cap, the exact fit,
//!    the oversize refusal, the cap-saturated refusal;
//!  * pay semantics — the conservation move (tokens buy debt, never
//!    the reverse), the partial pay, the empty-word no-ops, and the
//!    never-overpay invariant on the token side;
//!  * the ledger correction — book_rescue moves a booked drop to the
//!    allowed column exactly (math.rs, the wrapping-add form);
//!  * THE BUDGET LAW — the CE-ignoring hammer simulation: a sender
//!    that sets ECT, never reacts, and sends at 4x the policy still
//!    delivers inside rate*t + burst + one 64 KiB super-packet (the
//!    ecn.rs proof's closed form — the 2R hole a time-decayed debt
//!    would open is pinned ABSENT);
//!  * THE CONVERGENCE FINGERPRINT — the A/B twin: the same
//!    demand-feedback sender under the ECN-first policer and under
//!    the legacy drop policer; the ECN lane delivers more goodput
//!    with zero losses once the window settles, which is the entire
//!    point of mark-instead-of-drop, reproduced rootlessly.

// The production debt core, compiled into this test module: the SAME
// file the BPF object builds. Only the test tree reaches across
// trees (the gate-tree discipline, the math_tests precedent).
#[path = "../../../ebpf/src/ecn.rs"]
mod ebpf_ecn;

use self::ebpf_ecn::{debt_charge, debt_pay, ECN_DEBT_CAP};
use super::drr_tests::ebpf_drr::GSO_ADMIT_FLOOR;
use super::math_tests::ebpf_math::{book, book_rescue, LimiterStats};

/// One arbitration pair: a token word and a debt word, the two words
/// the pure core arbitrates (the raw-pointer contract the wiring
/// hands map values by).
struct Lane {
    tokens: u64,
    debt: u64,
}

impl Lane {
    fn new(tokens: u64, debt: u64) -> Self {
        Lane { tokens, debt }
    }

    fn pay(&mut self) {
        let tokens_ptr = core::ptr::addr_of_mut!(self.tokens);
        let debt_ptr = core::ptr::addr_of_mut!(self.debt);
        debt_pay(tokens_ptr, debt_ptr);
    }

    fn charge(&mut self, pkt_len: u32) -> bool {
        let debt_ptr = core::ptr::addr_of_mut!(self.debt);
        debt_charge(debt_ptr, pkt_len)
    }
}

#[test]
fn debt_cap_rides_the_gso_admit_floor() {
    // One constant, two lanes' starvation heals: the DRR quantum's
    // GSO admit floor and the ECN debt ceiling are the same law — a
    // single super-packet of slack. A drift here is a policy drift.
    assert_eq!(ECN_DEBT_CAP, GSO_ADMIT_FLOOR);
    assert_eq!(ECN_DEBT_CAP, 65_536);
}

#[test]
fn charge_accumulates_under_the_cap() {
    let mut lane = Lane::new(0, 0);
    // Ten 1500-byte packets fit with room to spare.
    for _ in 0..10 {
        assert!(lane.charge(1500));
    }
    assert_eq!(lane.debt, 15_000);
}

#[test]
fn charge_takes_the_exact_fit_then_refuses() {
    let mut lane = Lane::new(0, 0);
    // Fill the word to exactly the cap, then every further charge —
    // even one byte — is refused: the cap is a hard ceiling, not a
    // soft target.
    let big = u32::try_from(ECN_DEBT_CAP).unwrap();
    assert!(lane.charge(big));
    assert_eq!(lane.debt, ECN_DEBT_CAP);
    assert!(!lane.charge(1));
    assert_eq!(lane.debt, ECN_DEBT_CAP);
}

#[test]
fn charge_refuses_the_oversize_packet() {
    let mut lane = Lane::new(0, 0);
    // A packet bigger than the remaining room finds no room at all:
    // the word never crosses the cap, and the oversize packet drops
    // (the safe verdict) instead of borrowing headroom.
    assert!(lane.charge(1000));
    let oversize = u32::try_from(ECN_DEBT_CAP - 1000 + 1).unwrap();
    assert!(!lane.charge(oversize));
    assert_eq!(lane.debt, 1000);
    // The room that WAS there is still there for a fitting packet.
    assert!(lane.charge(u32::try_from(ECN_DEBT_CAP - 1000).unwrap()));
    assert_eq!(lane.debt, ECN_DEBT_CAP);
}

#[test]
fn pay_clears_debt_with_abundant_tokens() {
    let mut lane = Lane::new(10_000, 4_000);
    lane.pay();
    // The stream bought every outstanding marked byte.
    assert_eq!((lane.tokens, lane.debt), (6_000, 0));
}

#[test]
fn pay_partial_when_tokens_run_short() {
    let mut lane = Lane::new(1_000, 4_000);
    lane.pay();
    // What the stream holds, the debt takes; the rest of the debt
    // waits for the next refill (the LRU ages it out if the lane
    // goes quiet — the documented safe-direction loss).
    assert_eq!((lane.tokens, lane.debt), (0, 3_000));
}

#[test]
fn pay_is_a_noop_on_empty_words() {
    let mut lane = Lane::new(5_000, 0);
    lane.pay();
    assert_eq!((lane.tokens, lane.debt), (5_000, 0));
    lane = Lane::new(0, 4_000);
    lane.pay();
    assert_eq!((lane.tokens, lane.debt), (0, 4_000));
}

#[test]
fn pay_moves_value_between_the_words_exactly() {
    // The conservation move's bookkeeping, single-threaded form:
    // whatever the pay takes off the debt word comes off the token
    // word 1:1 — the pay never forgives debt the stream did not
    // buy, and never buys more debt than was outstanding.
    let mut lane = Lane::new(7_777, 3_333);
    let (tokens_before, debt_before) = (lane.tokens, lane.debt);
    lane.pay();
    let paid = tokens_before - lane.tokens;
    assert_eq!(debt_before - lane.debt, paid);
    assert_eq!(lane.tokens, tokens_before - paid);
    // The partial pay's shape: the stream held less than the debt.
    assert_eq!(paid, tokens_before.min(debt_before));
    // And nothing moves when either word is empty (the no-op pins
    // cover the exact zero sides).
    assert!(lane.debt <= debt_before);
    assert!(lane.tokens <= tokens_before);
}

#[test]
fn book_rescue_moves_the_booking_exactly() {
    // The lane booked a drop; the rescue delivered the packet
    // CE-marked. The ledger must show one allowed packet and zero
    // dropped — the correction pair, exact.
    let mut stats = LimiterStats {
        packets_allowed: 41,
        packets_dropped: 7,
        bytes_allowed: 41_000,
        bytes_dropped: 7_000,
    };
    book(&mut stats, false, 1500);
    assert_eq!((stats.packets_dropped, stats.bytes_dropped), (8, 8_500));
    book_rescue(&mut stats, 1500);
    assert_eq!((stats.packets_allowed, stats.bytes_allowed), (42, 42_500));
    assert_eq!((stats.packets_dropped, stats.bytes_dropped), (7, 7_000));
}

#[test]
fn ce_ignoring_hammer_stays_inside_the_budget_law() {
    // THE BUDGET LAW, closed form. The hammer sets ECT on everything,
    // never reacts to a single CE mark, and offers 4x the policy
    // rate. The drop lane is gone for it — every over-budget packet
    // would be marked and delivered — yet the delivered total stays
    // inside rate*t + burst + ECN_DEBT_CAP: every marked byte is
    // bought back out of the hammer's own token stream (the pay
    // rides the allow path, from the leftover the deliveries left
    // behind). The 2R hole a time-decayed debt would open (a second
    // independent rate stream) is pinned ABSENT by the bound's
    // shape: the slack is a one-time 64 KiB, not a per-second
    // allowance. The starvation bug the rootless sim caught BEFORE
    // any kernel saw this code — a pay on every packet draining the
    // stock toward the debt — is pinned absent by the LOWER bound:
    // the hammer still captures the full policy stream, exactly the
    // drop lane's delivery, never less.
    const RATE: u64 = 1_000_000; // 1 MB/s
    const BURST: u64 = 8_000;
    const TICKS: u64 = 2_000;
    const CREDIT_PER_TICK: u64 = RATE / TICKS;
    const OFFER: u64 = CREDIT_PER_TICK * 4; // the 4x hammer

    let mut lane = Lane::new(BURST, 0);
    let mut delivered: u64 = 0;
    for _ in 0..TICKS {
        // The per-packet wiring order: refill, the lane verdict
        // (consume first, mark on refusal), then the pay on the
        // allow path only — the call-site law.
        lane.tokens = (lane.tokens + CREDIT_PER_TICK).min(BURST);
        let pkt = u32::try_from(OFFER).unwrap();
        if lane.tokens >= u64::from(pkt) {
            lane.tokens -= u64::from(pkt);
            delivered += u64::from(pkt);
            lane.pay();
        } else if lane.charge(pkt) {
            delivered += u64::from(pkt);
        }
        // A refused charge is a DROP: delivered does not move.
    }
    let bound = RATE + BURST + ECN_DEBT_CAP;
    assert!(
        delivered <= bound,
        "delivered {delivered} must stay inside the budget-law bound {bound}"
    );
    // Drop-lane parity, the starvation pin: the hammer's own token
    // deliveries alone must carry the full policy stream.
    assert!(
        delivered >= RATE,
        "delivered {delivered} must reach at least the policy rate {RATE}"
    );
}

#[test]
fn ecn_first_beats_the_drop_policer_on_goodput() {
    // THE CONVERGENCE FINGERPRINT, the A/B twin. One sender model,
    // two policers: the legacy drop lane (an over-budget packet is
    // lost — the window collapses and the bytes retransmit) vs the
    // ECN-first lane (the over-budget packet is delivered CE-marked —
    // the window halves but the bytes ARRIVE). Same demand feedback
    // (halve on pain, grow by an additive step on a clean deliver),
    // same credit stream, same burst. The ECN lane's goodput must
    // beat the drop lane's — that is the measurable shape of "the
    // limiter that doesn't hurt" — and its loss count must be zero
    // once the window settles under the cap.
    const RATE: u64 = 1_000_000;
    const BURST: u64 = 8_000;
    const TICKS: u64 = 4_000;
    const CREDIT: u64 = RATE / TICKS;
    const MIN_WINDOW: u64 = CREDIT / 4;
    const MAX_WINDOW: u64 = CREDIT * 4;

    struct Sender {
        window: u64,
        pending: u64,
    }
    impl Sender {
        fn new() -> Self {
            Sender {
                window: MAX_WINDOW,
                pending: 0,
            }
        }
        fn offer(&self) -> u32 {
            // The demand this tick: the window plus any retransmit
            // debt (the drop lane's lost bytes). The debt is bounded
            // by one flight — a real sender never holds more than
            // its window of unacknowledged bytes.
            u32::try_from((self.window + self.pending).min(2 * MAX_WINDOW)).unwrap()
        }
        fn on_clean_deliver(&mut self) {
            self.pending = 0;
            self.window = (self.window + CREDIT / 16).min(MAX_WINDOW);
        }
        fn on_pain(&mut self, pkt_len: u32) {
            self.window = (self.window / 2).max(MIN_WINDOW);
            self.pending = 0;
            // Only the DROP lane retransmits: the marked packet's
            // bytes arrived, so the ECN sender's `pending` stays 0
            // (set here, overridden below by the drop twin).
            let _ = pkt_len;
        }
        fn on_drop(&mut self, pkt_len: u32) {
            self.window = (self.window / 2).max(MIN_WINDOW);
            self.pending = (self.pending + u64::from(pkt_len)).min(MAX_WINDOW);
        }
    }

    // The ECN-first lane: refill, consume-or-mark, pay on allow.
    let mut lane = Lane::new(BURST, 0);
    let mut ecn_sender = Sender::new();
    let mut ecn_delivered: u64 = 0;
    let mut ecn_marks: u64 = 0;
    let mut ecn_last_resort_drops: u64 = 0;
    for _ in 0..TICKS {
        lane.tokens = (lane.tokens + CREDIT).min(BURST);
        let pkt = ecn_sender.offer();
        if lane.tokens >= u64::from(pkt) {
            lane.tokens -= u64::from(pkt);
            ecn_delivered += u64::from(pkt);
            ecn_sender.on_clean_deliver();
            lane.pay();
        } else if lane.charge(pkt) {
            ecn_delivered += u64::from(pkt);
            ecn_marks += 1;
            ecn_sender.on_pain(pkt);
        } else {
            // Debt saturated: the last-resort drop, same as the
            // legacy lane (the CE-ignoring corner of the model).
            ecn_last_resort_drops += 1;
            ecn_sender.on_drop(pkt);
        }
    }

    // The legacy drop lane: refill, consume-or-drop, retransmit.
    let mut tokens = BURST;
    let mut drop_sender = Sender::new();
    let mut drop_delivered: u64 = 0;
    let mut drops: u64 = 0;
    for _ in 0..TICKS {
        tokens = (tokens + CREDIT).min(BURST);
        let pkt = drop_sender.offer();
        if tokens >= u64::from(pkt) {
            tokens -= u64::from(pkt);
            drop_delivered += u64::from(pkt);
            drop_sender.on_clean_deliver();
        } else {
            drops += 1;
            drop_sender.on_drop(pkt);
        }
    }

    // The fingerprint: strictly better goodput under the same
    // policy, and the mark lane's loss count (the last-resort
    // branch) is zero — every over-budget packet rode a CE mark,
    // because the converged periods' leftover kept the debt bought
    // down and the marking budget re-armed.
    assert!(
        ecn_delivered > drop_delivered,
        "ECN-first goodput {ecn_delivered} must beat the drop lane's {drop_delivered}"
    );
    assert!(
        drop_delivered > 0,
        "the drop lane must deliver something for the comparison to be honest"
    );
    assert_eq!(
        ecn_last_resort_drops, 0,
        "a reactive sender must never hit the last-resort drop"
    );
    assert!(ecn_marks > 0, "the convergence transients must have marked");
    let _ = drops;
}
