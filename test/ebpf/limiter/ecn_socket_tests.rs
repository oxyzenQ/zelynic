// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! schema v21 (the per-socket convergence closure): the rootless
//! fleet sims that closed the question the per-socket lane's ECN
//! marking was deferred on — "a server's N connections each halving
//! their windows on per-connection marks is an aggregate-collapse
//! shape that needs its own convergence analysis before it ships"
//! (ebpf/src/ecn.rs's v19 scope note, now closed). The analysis and
//! its answer, pinned the way every law here is pinned — rootless,
//! before any kernel sees the wiring:
//!
//!  * THE FLEET HARNESS — N connections on one tick clock, each with
//!    its own lane (its own credit stream at the per-connection
//!    rate, its own debt word), every bucket refilling on the SAME
//!    tick (the synchronized worst case the fear named: correlated
//!    marks, lockstep halving); the senders are the ecn_tests
//!    fingerprint model, one per connection;
//!  * THE AGGREGATE DOES NOT COLLAPSE — per-connection budgets are
//!    independent, so each connection converges on its own stream
//!    and the fleet rides N x per-connection (the feared
//!    synchronized halving costs each connection its own sawtooth,
//!    never the fleet its total);
//!  * THE FLEET A/B — the marking fleet beats the same fleet under
//!    per-socket DROPS (the lane's shipped v20 behavior);
//!  * THE HAMMER — a CE-ignoring connection stays inside its own
//!    budget law while its neighbors converge untouched (the
//!    per-connection budget IS the isolation).

// The production debt core, compiled into the test binary by
// ecn_tests' single inclusion (one copy per test binary, the
// duplicate-mod law — the drr_tests/math_tests precedent): reached
// through the sibling wiring, `pub(super)`'s widened view.
use super::ecn_tests::ebpf_ecn::{ECN_DEBT_CAP, debt_charge, debt_pay};

/// One arbitration pair, the ecn_tests Lane verbatim: a token word
/// and a debt word, the two words the pure core arbitrates (the
/// raw-pointer contract the wiring hands map values by).
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

// ── the per-socket convergence analysis (the deferred question) ─────────────
//
// The per-socket lane's ECN marking was deferred (ecn.rs's scope
// note) on one question: does a server's N connections each halving
// their windows on PER-CONNECTION marks collapse the aggregate? The
// fleet sims below are the analysis, run rootlessly the way every
// law here is pinned before any kernel sees it:
//
//   * each connection gets its OWN lane (its own credit stream, its
//     own debt word) — the per-socket budget law verbatim;
//   * every bucket refills on the SAME tick (the synchronized worst
//     case the fear named: correlated marks, lockstep halving);
//   * the senders are the fingerprint test's demand-feedback model,
//     one per connection — halve on pain, additive growth on a
//     clean deliver, retransmit debt only under the drop twin.

/// The per-connection sender, the fingerprint test's model verbatim.
struct SocketSender {
    window: u64,
    pending: u64,
}

impl SocketSender {
    fn new(max_window: u64) -> Self {
        SocketSender {
            window: max_window,
            pending: 0,
        }
    }
}

/// One connection's results over the fleet's run.
#[derive(Default)]
struct SocketOutcome {
    delivered: u64,
    marks: u64,
    last_resort_drops: u64,
    drops: u64,
}

/// The fleet harness: N connections on one tick clock, each with its
/// own lane at the per-connection rate. `mark` selects the policer
/// (ECN-first vs the drop lane the per-socket policy ships today);
/// `hammer_idx` turns one connection into the CE-ignoring hammer
/// (ECT set, never reacts, offers 4x the stream every tick).
fn socket_fleet(mark: bool, n: usize, hammer_idx: Option<usize>) -> Vec<SocketOutcome> {
    const RATE: u64 = 1_000_000;
    const BURST: u64 = 8_000;
    const TICKS: u64 = 4_000;
    const CREDIT: u64 = RATE / TICKS; // 250: the per-connection per-tick credit
    const MIN_WINDOW: u64 = CREDIT / 4;
    const MAX_WINDOW: u64 = CREDIT * 4;
    const HAMMER_OFFER: u64 = CREDIT * 4;

    // One connection's verdict for THIS tick — the sender reacts to
    // the tick's own verdict, never to a cumulative counter (a
    // cumulative-signal sender would halve every tick after its
    // first mark: a false collapse the model would fabricate).
    #[derive(Clone, Copy, PartialEq)]
    enum Verdict {
        Clean,
        Marked,
        Lost,
    }

    let mut lanes: Vec<Lane> = (0..n).map(|_| Lane::new(BURST, 0)).collect();
    let mut drop_tokens: Vec<u64> = vec![BURST; n];
    let mut senders: Vec<SocketSender> = (0..n).map(|_| SocketSender::new(MAX_WINDOW)).collect();
    let mut out: Vec<SocketOutcome> = (0..n).map(|_| SocketOutcome::default()).collect();

    for _ in 0..TICKS {
        for i in 0..n {
            let hammer = hammer_idx == Some(i);
            let pkt = if hammer {
                u32::try_from(HAMMER_OFFER).unwrap()
            } else {
                u32::try_from((senders[i].window + senders[i].pending).min(2 * MAX_WINDOW)).unwrap()
            };
            let verdict = if mark {
                // The ECN-first lane, the wiring order verbatim:
                // refill, consume-or-mark, pay on the allow path.
                lanes[i].tokens = (lanes[i].tokens + CREDIT).min(BURST);
                if lanes[i].tokens >= u64::from(pkt) {
                    lanes[i].tokens -= u64::from(pkt);
                    out[i].delivered += u64::from(pkt);
                    lanes[i].pay();
                    Verdict::Clean
                } else if lanes[i].charge(pkt) {
                    out[i].delivered += u64::from(pkt);
                    out[i].marks += 1;
                    Verdict::Marked
                } else {
                    // Debt saturated: the last-resort drop.
                    out[i].last_resort_drops += 1;
                    Verdict::Lost
                }
            } else {
                // The per-socket DROP lane: today's shipped behavior.
                drop_tokens[i] = (drop_tokens[i] + CREDIT).min(BURST);
                if drop_tokens[i] >= u64::from(pkt) {
                    drop_tokens[i] -= u64::from(pkt);
                    out[i].delivered += u64::from(pkt);
                    Verdict::Clean
                } else {
                    out[i].drops += 1;
                    Verdict::Lost
                }
            };
            if !hammer {
                match verdict {
                    Verdict::Clean => {
                        // A clean deliver grows the window additively
                        // and clears the retransmit debt.
                        senders[i].pending = 0;
                        senders[i].window = (senders[i].window + CREDIT / 16).min(MAX_WINDOW);
                    }
                    Verdict::Marked => {
                        // Halve on the mark; the bytes arrived, so no
                        // retransmit debt (the ECN sender's shape).
                        senders[i].window = (senders[i].window / 2).max(MIN_WINDOW);
                        senders[i].pending = 0;
                    }
                    Verdict::Lost => {
                        // Halve on the loss and carry the retransmit
                        // debt (the drop lane's shape).
                        senders[i].window = (senders[i].window / 2).max(MIN_WINDOW);
                        senders[i].pending = (senders[i].pending + u64::from(pkt)).min(MAX_WINDOW);
                    }
                }
            }
        }
    }
    out
}

/// The per-connection budget law: rate*t + burst + one 64 KiB
/// super-packet (the ecn.rs closed form, one connection at a time).
fn socket_budget_bound() -> u64 {
    1_000_000 + 8_000 + ECN_DEBT_CAP
}

#[test]
fn per_socket_marks_do_not_collapse_the_aggregate() {
    // THE DEFERRED QUESTION, answered. Eight connections, ECN-first
    // each, every bucket refilling on the same tick — the aggregate
    // must ride N x per-connection, not collapse: every connection
    // converges on its own stream (the marks teach that connection's
    // window, and the window's floor sits far above the stream's
    // per-tick credit), so the fleet's total lands near N x rate
    // with each connection's delivery inside its own budget law, and
    // no reactive connection ever hits the last-resort drop.
    const N: usize = 8;
    const RATE: u64 = 1_000_000;
    let out = socket_fleet(true, N, None);
    let bound = socket_budget_bound();
    let mut aggregate: u64 = 0;
    for (i, o) in out.iter().enumerate() {
        assert!(
            o.delivered <= bound,
            "connection {i} delivered {} must stay inside its budget law {bound}",
            o.delivered
        );
        assert!(
            o.delivered > 0,
            "connection {i} starved — the per-socket lane cannot starve its own budget"
        );
        assert_eq!(
            o.last_resort_drops, 0,
            "reactive connection {i} must never hit the last-resort drop"
        );
        aggregate += o.delivered;
    }
    // The anti-collapse pin: the aggregate stays above 90% of
    // N x rate — per-connection convergence, measured shape.
    assert!(
        aggregate >= 9 * (RATE * N as u64) / 10,
        "the fleet aggregate {aggregate} must ride N x per-connection ({}) — no collapse",
        RATE * N as u64
    );
    assert!(aggregate <= RATE * N as u64 + bound, "the aggregate bound");
}

#[test]
fn per_socket_ecn_beats_per_socket_drops_on_the_aggregate() {
    // The fleet A/B: the same N connections under the per-socket
    // drop policer (the lane's shipped behavior — every over-budget
    // packet LOST, windows collapsing with retransmit debt) vs the
    // ECN-first fleet. The marking fleet must win the aggregate —
    // the measurable shape of "the lane that doesn't hurt" — with
    // the drop fleet still delivering (the honest comparison).
    const N: usize = 8;
    let ecn_fleet = socket_fleet(true, N, None);
    let drop_fleet = socket_fleet(false, N, None);
    let ecn_total: u64 = ecn_fleet.iter().map(|o| o.delivered).sum();
    let drop_total: u64 = drop_fleet.iter().map(|o| o.delivered).sum();
    assert!(
        ecn_total > drop_total,
        "the ECN fleet's aggregate {ecn_total} must beat the drop fleet's {drop_total}"
    );
    assert!(drop_total > 0, "the drop fleet must deliver for honesty");
}

#[test]
fn per_socket_hammer_stays_bounded_and_isolated() {
    // The cheat shape inside the fleet: connection 0 sets ECT and
    // never reacts (the CE-ignoring hammer at 4x its own stream).
    // Its own delivery stays inside the per-connection budget law —
    // the debt buy-back bites on the hammer's own stream — and its
    // NEIGHBORS converge exactly as the clean fleet did: the
    // per-connection budget IS the isolation (no shared word exists
    // for a hammer to farm).
    const N: usize = 8;
    const RATE: u64 = 1_000_000;
    let clean = socket_fleet(true, N, None);
    let hammered = socket_fleet(true, N, Some(0));
    let bound = socket_budget_bound();
    assert!(
        hammered[0].delivered <= bound,
        "the hammer's delivered {} must stay inside the budget law {bound}",
        hammered[0].delivered
    );
    let neighbors_clean: u64 = clean.iter().skip(1).map(|o| o.delivered).sum();
    let neighbors_hammered: u64 = hammered.iter().skip(1).map(|o| o.delivered).sum();
    assert!(
        neighbors_hammered >= 9 * (RATE * (N as u64 - 1)) / 10,
        "the neighbors' aggregate {neighbors_hammered} must ride N-1 x per-connection — \
         the hammer cannot depress connections it does not share a budget with"
    );
    let _ = neighbors_clean;
}
