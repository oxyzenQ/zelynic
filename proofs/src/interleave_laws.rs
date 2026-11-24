// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z17: the property tier over the interleaving
//! model — the sampled instruments that stand beside the kani
//! theorems:
//!
//!  * THE FIDELITY HAMMERS: the refill, consume, and debt actors,
//!    run with nothing interleaved, must reproduce the kernel
//!    functions' final state and verdict on every sampled case —
//!    thousands of shrinkable cases per run, the anti-gimmick
//!    instrument under the for-all pins.
//!  * THE BELT WITNESS PINS: the finding, reproduced
//!    deterministically. The shipped (ungated) belt's stamp write
//!    certifies a dead remnant a racing spend left (the failed
//!    zero-CAS class) and a dead credit a racing draw landed (the
//!    in-flight class); the ledger holds throughout — the
//!    violation is the certification, never the conservation. The
//!    gated form refuses both certifications and converges by
//!    re-fire — the fix's sampled certificate beside the kani one.
//!  * THE SCHEDULE SAMPLER: two actors, random verbs, an
//!    adversarial bit stream — the full invariant asserted after
//!    every micro-step of every sampled schedule (the gated belt's
//!    family), and the ungated family's violation-class reach
//!    counted (the falsification's statistical pin).

use proptest::prelude::*;

use crate::interleave_actors::{Actor, Verb};
use crate::interleave_model::{Target, World};
use crate::math_core::{Bucket, Policy, refill_window, try_consume};

// The reachable-ish sampled domains (the kani tier carries the
// hostile domain; the sampler's job is breadth at the shapes real
// traffic produces, plus the edges).
const SAMPLED_MAX_RATE: u64 = 1_000_000_000_000;
const SAMPLED_MAX_BURST: u64 = 100_000_000;
const SAMPLED_MAX_STOCK: u64 = 1 << 40;
const SAMPLED_MAX_CLOCK: u64 = 1 << 32;
const ECN_DEBT_CAP: u64 = 65_536;

fn cases() -> ProptestConfig {
    ProptestConfig::with_cases(4096)
}

fn sampled_policy(rate: u64, burst: u64) -> Policy {
    Policy {
        rate_bps: rate,
        burst_bytes: burst,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    }
}

fn bucket_of(tokens: u64, last: u64, frac: u64) -> Bucket {
    Bucket {
        tokens,
        last_refill_ns: last,
        frac_rem: frac,
    }
}

// ── The fidelity hammers ───────────────────────────────────────────

proptest! {
    #![proptest_config(cases())]

    /// The refill actor reproduces refill_window's final state on
    /// every sampled (policy, hostile bucket, clock) triple.
    #[test]
    fn refill_actor_matches_kernel_refill_window_for_sampled_inputs(
        rate in 0u64..SAMPLED_MAX_RATE,
        burst in 0u64..SAMPLED_MAX_BURST,
        tokens in 0u64..SAMPLED_MAX_STOCK,
        last in 0u64..SAMPLED_MAX_CLOCK,
        frac in 0u64..1_000_000_000u64,
        now in 0u64..SAMPLED_MAX_CLOCK,
    ) {
        let pol = sampled_policy(rate, burst);
        let bkt = bucket_of(tokens, last, frac);
        let mut kernel = bkt;
        refill_window(&pol, &mut kernel, now);
        let mut w = World::genesis(bkt, bucket_of(0, 0, 0), 0, 0, false);
        let mut actor = Actor::new(Verb::Refill { pol, now });
        actor.run(&mut w);
        prop_assert_eq!(w.pool.tokens, kernel.tokens);
        prop_assert_eq!(w.pool.last_refill_ns, kernel.last_refill_ns);
        prop_assert_eq!(w.pool.frac_rem, kernel.frac_rem);
        prop_assert!(w.ledger_ok());
    }

    /// The refill actor agrees with the direct sequential driver —
    /// the chain pin: kernel == driver (the kani fidelity lemmas,
    /// for all inputs) and driver == actor (this law, sampled) close
    /// the actor to the kernel's bytes through the shared segments.
    #[test]
    fn refill_actor_agrees_with_the_direct_driver_for_sampled_inputs(
        rate in 0u64..SAMPLED_MAX_RATE,
        burst in 0u64..SAMPLED_MAX_BURST,
        tokens in 0u64..SAMPLED_MAX_STOCK,
        last in 0u64..SAMPLED_MAX_CLOCK,
        frac in 0u64..1_000_000_000u64,
        now in 0u64..SAMPLED_MAX_CLOCK,
    ) {
        let pol = sampled_policy(rate, burst);
        let bkt = bucket_of(tokens, last, frac);
        let mut w_a = World::genesis(bkt, bucket_of(0, 0, 0), 0, 0, false);
        let mut actor = Actor::new(Verb::Refill { pol, now });
        actor.run(&mut w_a);
        let mut w_d = World::genesis(bkt, bucket_of(0, 0, 0), 0, 0, false);
        crate::interleave_segments::run_refill_direct(&mut w_d, &pol, now);
        prop_assert_eq!(w_a.pool.tokens, w_d.pool.tokens);
        prop_assert_eq!(w_a.pool.last_refill_ns, w_d.pool.last_refill_ns);
        prop_assert_eq!(w_a.pool.frac_rem, w_d.pool.frac_rem);
    }

    /// The consume actor reproduces try_consume's verdict and final
    /// state on every sampled (stock, packet) pair.
    #[test]
    fn consume_actor_matches_kernel_try_consume_for_sampled_inputs(
        tokens in 0u64..SAMPLED_MAX_STOCK,
        pkt in proptest::num::u32::ANY,
    ) {
        let bkt = bucket_of(tokens, 0, 0);
        let mut kernel = bkt;
        let kernel_allowed = try_consume(&mut kernel, pkt);
        let mut w = World::genesis(bkt, bucket_of(0, 0, 0), 0, 0, true);
        let mut actor = Actor::new(Verb::Consume { target: Target::Pool, want: pkt });
        actor.run(&mut w);
        prop_assert_eq!(w.pool.tokens, kernel.tokens);
        prop_assert_eq!(actor.verdict, kernel_allowed);
        prop_assert!(w.ledger_ok());
    }

    /// The debt pair's actors reproduce debt_charge's verdict and
    /// debt_pay's final pair on every sampled (stock, debt,
    /// packet) triple.
    #[test]
    fn debt_actors_match_kernel_debt_pair_for_sampled_inputs(
        stock in 0u64..SAMPLED_MAX_STOCK,
        debt in 0u64..(2 * ECN_DEBT_CAP),
        pkt in proptest::num::u32::ANY,
    ) {
        let mut k_tokens = stock;
        let mut k_debt = debt;
        let k_ptr_t = &mut k_tokens as *mut u64;
        let k_ptr_d = &mut k_debt as *mut u64;
        let charged = crate::ecn_core::debt_charge(k_ptr_d, pkt);
        crate::ecn_core::debt_pay(k_ptr_t, k_ptr_d);
        let mut w = World::genesis(
            bucket_of(stock, 0, 0),
            bucket_of(0, 0, 0),
            debt,
            0,
            true,
        );
        let mut charger = Actor::new(Verb::DebtCharge { pkt_len: pkt });
        charger.run(&mut w);
        let mut payer = Actor::new(Verb::DebtPay { target: Target::Pool });
        payer.run(&mut w);
        prop_assert_eq!(w.pool.tokens, k_tokens);
        prop_assert_eq!(w.debt.tokens, k_debt);
        prop_assert_eq!(charger.verdict, charged);
        prop_assert!(w.ledger_ok());
    }
}

// ── The belt witness pins (the finding, deterministic) ─────────────

/// THE FINDING, class one: the shipped belt's stamp write
/// certifies a racing spend's dead remnant. The interleaving:
/// the belt reads the stale stock, a consume verb runs whole
/// between the read and the zeroing CAS, the CAS loses against
/// the moved stock, and the unconditional stamp write lands a
/// current stamp over the surviving remnant. The LEDGER holds
/// throughout (the remnant is real budget, never minted) — the
/// violation is the certification, exactly the class the gated
/// form refuses.
#[test]
fn shipped_belt_certifies_a_racing_spend_dead_remnant() {
    let mut w = World::genesis(bucket_of(1 << 20, 123, 0), bucket_of(100, 0, 5), 0, 7, true);
    // Genesis coherence: stamp 5 against live generation 7 — the
    // whole stock is dead by the conservative split.
    assert_eq!(w.dead, 100);
    assert!(w.belt_dead_ok());
    let mut belt = Actor::new(Verb::Belt { gated: false });
    assert!(!belt.advance(&mut w)); // pc0: the generation read
    assert!(!belt.advance(&mut w)); // pc1: the stamp mismatches, fire
    assert!(!belt.advance(&mut w)); // pc2: the stale stock read (100)
    // The racing spend: a whole consume verb between the belt's
    // observation and its zeroing CAS.
    let mut consumer = Actor::new(Verb::Consume {
        target: Target::Leaf,
        want: 30,
    });
    consumer.run(&mut w);
    assert_eq!(w.leaf.tokens, 70);
    assert_eq!(w.dead, 70);
    assert!(w.laws_ok());
    // The belt's zeroing CAS loses against the moved stock.
    assert!(!belt.advance(&mut w));
    // The unconditional stamp write certifies the remnant.
    assert!(belt.advance(&mut w));
    assert_eq!(crate::math_core::gen_stamp_read(&w.leaf), 7);
    assert!(!w.belt_dead_ok());
    assert_eq!(w.dead, 70);
    // The conservation ledger holds through the violation.
    assert!(w.ledger_ok());
}

/// THE FINDING, class two: the shipped belt's stamp write
/// certifies a racing draw's dead credit. The interleaving: a
/// draw arms its take (the pool CAS landed, the leaf credit
/// pending), the belt runs against the stale-stamped empty leaf,
/// the draw's credit lands between the belt's stale read and the
/// stamp write, and the write certifies the freshly-landed dead
/// credit. Again the ledger holds — the take is real budget.
#[test]
fn shipped_belt_certifies_a_racing_draw_dead_credit() {
    let mut w = World::genesis(bucket_of(1 << 20, 123, 0), bucket_of(0, 0, 5), 0, 7, true);
    assert_eq!(w.dead, 0);
    let mut draw = Actor::new(Verb::Draw {
        quantum: 4096,
        learned: 0,
        allowance: u64::MAX,
        room: u64::MAX,
        now: 1000,
    });
    // The draw arms: stamp lock, pool observation, pool take.
    assert!(!draw.advance(&mut w)); // pc0: the stamp observation
    assert!(!draw.advance(&mut w)); // pc1: the stamp lock CAS
    assert!(!draw.advance(&mut w)); // pc2: the pool observation
    assert!(!draw.advance(&mut w)); // pc3: the pool take CAS (d armed)
    assert_eq!(w.inflight, 4096);
    // The belt against the stale-stamped empty leaf, interleaved.
    let mut belt = Actor::new(Verb::Belt { gated: false });
    assert!(!belt.advance(&mut w)); // pc0: the generation read (7)
    assert!(!belt.advance(&mut w)); // pc1: stamp 5 mismatches, fire
    assert!(!belt.advance(&mut w)); // pc2: the stale stock read (0)
    // The draw's leaf credit lands on the stale-stamped leaf —
    // dead taint, exactly the class the belt exists to zero.
    assert!(draw.advance(&mut w)); // pc6: the leaf credit (+4096)
    assert_eq!(w.dead, 4096);
    assert_eq!(w.leaf.tokens, 4096);
    // The belt's zeroing is skipped (the stock read was 0) and the
    // unconditional stamp write certifies the landed credit.
    assert!(!belt.advance(&mut w)); // pc3: the zero attempt (no-op)
    assert!(belt.advance(&mut w)); // pc4: the stamp write
    assert_eq!(crate::math_core::gen_stamp_read(&w.leaf), 7);
    assert!(!w.belt_dead_ok());
    assert_eq!(w.dead, 4096);
    assert!(w.ledger_ok());
}

/// THE CLOSE, both classes: the gated belt refuses the
/// certification and converges by re-fire — the same two
/// interleavings, the gated stamp segment, and the dead stock
/// ends at exactly zero through the belt's own convergence.
#[test]
fn gated_belt_refuses_and_converges_on_both_witness_classes() {
    // Class one, gated: the failed zeroing keeps the stamp stale.
    let mut w = World::genesis(bucket_of(1 << 20, 123, 0), bucket_of(100, 0, 5), 0, 7, true);
    let mut belt = Actor::new(Verb::Belt { gated: true });
    assert!(!belt.advance(&mut w));
    assert!(!belt.advance(&mut w));
    assert!(!belt.advance(&mut w));
    let mut consumer = Actor::new(Verb::Consume {
        target: Target::Leaf,
        want: 30,
    });
    consumer.run(&mut w);
    assert!(!belt.advance(&mut w)); // the zeroing CAS loses
    assert!(belt.advance(&mut w)); // the gated write refuses
    assert_eq!(crate::math_core::gen_stamp_read(&w.leaf), 5);
    assert!(w.belt_dead_ok());
    // The convergence: the next packet's belt re-fires (the stamp
    // still mismatches), the zeroing now runs uncontended, and the
    // gated write lands.
    let mut second = Actor::new(Verb::Belt { gated: true });
    second.run(&mut w);
    assert_eq!(crate::math_core::gen_stamp_read(&w.leaf), 7);
    assert_eq!(w.dead, 0);
    assert_eq!(w.leaf.tokens, 0);
    assert!(w.laws_ok());

    // Class two, gated: the re-observation refuses the racing
    // credit's certification; the next belt zeroes it.
    let mut w2 = World::genesis(bucket_of(1 << 20, 123, 0), bucket_of(0, 0, 5), 0, 7, true);
    let mut draw = Actor::new(Verb::Draw {
        quantum: 4096,
        learned: 0,
        allowance: u64::MAX,
        room: u64::MAX,
        now: 1000,
    });
    assert!(!draw.advance(&mut w2));
    assert!(!draw.advance(&mut w2));
    assert!(!draw.advance(&mut w2));
    assert!(!draw.advance(&mut w2));
    let mut belt2 = Actor::new(Verb::Belt { gated: true });
    assert!(!belt2.advance(&mut w2));
    assert!(!belt2.advance(&mut w2));
    assert!(!belt2.advance(&mut w2));
    assert!(draw.advance(&mut w2)); // the leaf credit lands (dead)
    assert_eq!(w2.dead, 4096);
    assert!(!belt2.advance(&mut w2)); // the zero attempt (no-op)
    assert!(belt2.advance(&mut w2)); // the gated re-observation refuses
    assert_eq!(crate::math_core::gen_stamp_read(&w2.leaf), 5);
    assert!(w2.belt_dead_ok());
    let mut second2 = Actor::new(Verb::Belt { gated: true });
    second2.run(&mut w2);
    assert_eq!(crate::math_core::gen_stamp_read(&w2.leaf), 7);
    assert_eq!(w2.dead, 0);
    assert!(w2.laws_ok());
}

// ── The schedule sampler ───────────────────────────────────────────

/// A small deterministic RNG (xorshift64*), seeded per schedule:
/// the sampler's reproducibility is the fail-loud culture's own
/// requirement — a red reruns identically, a witness replays.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

fn random_verb(rng: &mut Rng, gated: bool) -> Verb {
    match rng.below(8) {
        0 => Verb::Refill {
            pol: sampled_policy(
                rng.below(SAMPLED_MAX_RATE / 1000 + 1),
                rng.below(SAMPLED_MAX_BURST / 100 + 1),
            ),
            now: rng.below(SAMPLED_MAX_CLOCK),
        },
        1 | 2 => Verb::Consume {
            target: if rng.below(2) == 0 {
                Target::Pool
            } else {
                Target::Leaf
            },
            want: rng.below(65536) as u32,
        },
        3 => Verb::Draw {
            quantum: rng.below(1 << 20),
            learned: rng.below(24) as u16,
            allowance: if rng.below(2) == 0 {
                u64::MAX
            } else {
                rng.below(1 << 24)
            },
            room: if rng.below(2) == 0 {
                u64::MAX
            } else {
                rng.below(1 << 24)
            },
            now: rng.below(SAMPLED_MAX_CLOCK),
        },
        4 => Verb::DebtCharge {
            pkt_len: rng.below(65536) as u32,
        },
        5 => Verb::DebtPay {
            target: if rng.below(2) == 0 {
                Target::Pool
            } else {
                Target::Leaf
            },
        },
        6 => Verb::Belt { gated },
        _ => Verb::Mutate {
            bump: 1 + rng.below(3),
        },
    }
}

/// Run one random two-actor schedule: two verb slots, an
/// adversarial bit stream advancing one actor one micro-step at a
/// time, a fresh verb spawned on completion. Returns the number
/// of invariant violations seen (P4's dead law is the only
/// candidate under the gated belt; the conservative family is
/// asserted hard — any hit is a red, never a statistic).
fn run_schedule(seed: u64, gated: bool) -> (usize, usize) {
    let mut rng = Rng(seed | 1);
    let pool = bucket_of(
        rng.below(SAMPLED_MAX_STOCK),
        rng.below(SAMPLED_MAX_CLOCK),
        rng.below(1_000_000_000),
    );
    let g_live = rng.below(1 << 16);
    let leaf_stamp = if rng.below(2) == 0 {
        g_live
    } else {
        rng.below(1 << 16)
    };
    let mut w = World::genesis(
        pool,
        bucket_of(rng.below(1 << 20), rng.below(1 << 16), leaf_stamp),
        rng.below(2 * ECN_DEBT_CAP),
        g_live,
        rng.below(8) != 0,
    );
    let mut slots: [Option<Actor>; 2] = [None, None];
    let mut violations = 0;
    let mut steps = 0;
    while steps < 48 {
        // Fill an empty slot (or run Init first when unborn).
        let pick = rng.below(2) as usize;
        if slots[pick].is_none() {
            if !w.born && rng.below(4) == 0 {
                slots[pick] = Some(Actor::new(Verb::Init));
            } else {
                slots[pick] = Some(Actor::new(random_verb(&mut rng, gated)));
            }
        }
        let who = rng.below(2) as usize;
        if let Some(actor) = slots[who].as_mut() {
            actor.advance(&mut w);
            steps += 1;
            if actor.is_done() {
                slots[who] = None;
            }
        }
        // The conservative family is hard-asserted on every step.
        assert!(
            w.laws_ok_except_dead(),
            "conservative invariant broken at step {} (seed {}): \
             ledger={} debt_capped={} taint={} stamp_bounded={} frac_ok={}",
            steps,
            seed,
            w.ledger_ok(),
            w.debt_capped(),
            w.taint_coherent(),
            w.stamp_bounded(),
            w.frac_ok(),
        );
        if !w.belt_dead_ok() {
            violations += 1;
        }
    }
    (violations, steps)
}

/// THE SCHEDULE SAMPLER, the gated belt family: for every sampled
/// schedule the FULL invariant holds after every micro-step —
/// the ledger, the debt cap, the taint, the dead law, the stamp
/// bound, the fraction domain, all six, all the way down.
#[test]
fn sampled_two_actor_schedules_preserve_the_full_laws() {
    for seed in 1..=512u64 {
        let (violations, _) = run_schedule(seed, true);
        assert_eq!(
            violations, 0,
            "a gated-belt schedule reached a dead-law violation (seed {})",
            seed
        );
    }
}

/// THE FALSIFICATION STATISTIC, the shipped belt family: the
/// ungated belt's violation class is REACHABLE under sampled
/// schedules — the mechanical pin that the finding is real and
/// not a hand-built story. The count is reported, not asserted
/// zero; the deterministic witness pins above carry the shape.
#[test]
fn sampled_ungated_schedules_reach_the_dead_stamp_violation() {
    let mut schedules_with_violation = 0;
    for seed in 1..=512u64 {
        let (violations, _) = run_schedule(seed, false);
        if violations > 0 {
            schedules_with_violation += 1;
        }
    }
    // The class must be reachable (the finding is real under the
    // sampler's own breadth); a zero here means the model or the
    // belt changed — re-read the witness pins before touching
    // this bound.
    assert!(
        schedules_with_violation > 0,
        "the ungated violation class vanished from the sampler"
    );
}
