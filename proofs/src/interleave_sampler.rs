// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z17: the schedule sampler — the property tier's
//! interleaving instrument, split from interleave_laws.rs at the
//! 600-line cap (the split is mechanical; the instruments are
//! unchanged). Two families run over the two-CPU micro-step model:
//!
//!  * THE SHIPPED (gated) BELT FAMILY: 512 seeds x 48 micro-steps,
//!    two actors, an adversarial bit stream — the CONSERVATIVE
//!    invariant hard-asserted after every micro-step, the dead law
//!    P4's hits counted and reported (the shipped form's named
//!    quantum-bounded residual; the deterministic witness pin in
//!    interleave_laws.rs carries the shape).
//!  * THE PRE-PATCH (ungated) BELT FAMILY: the same schedules with
//!    the ungated belt — the violation class counted and pinned
//!    REACHABLE, the statistical record that the finding is real
//!    and not a hand-built story.

use crate::interleave_actors::{Actor, Verb};
use crate::interleave_laws::{
    ECN_DEBT_CAP, SAMPLED_MAX_BURST, SAMPLED_MAX_CLOCK, SAMPLED_MAX_RATE, SAMPLED_MAX_STOCK,
    bucket_of, sampled_policy,
};
use crate::interleave_model::{Target, World};

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
/// of dead-law hits seen (the conservative family is asserted
/// hard — any hit there is a red; the dead law rides the
/// conservative tier for the shipped form's named residual, so
/// its hits are the reported statistic, the deterministic witness
/// pin carrying the shape).
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

/// THE SCHEDULE SAMPLER, the shipped (gated) belt family: for
/// every sampled schedule the CONSERVATIVE invariant holds after
/// every micro-step — the ledger, the debt cap, the taint, the
/// stamp bound, the fraction domain — hard-asserted. The dead law
/// P4 rides the conservative tier for the shipped form (the named
/// quantum-bounded residual), so its hits are counted and
/// reported, the deterministic witness pin carrying the shape.
#[test]
fn sampled_two_actor_schedules_preserve_the_conservative_laws() {
    let mut schedules_with_hit = 0;
    for seed in 1..=512u64 {
        let (violations, _) = run_schedule(seed, true);
        if violations > 0 {
            schedules_with_hit += 1;
        }
    }
    // The named residual's statistical shape: reported, not
    // asserted zero — the in-flight window needs the exact
    // interleaving the deterministic witness pins; the
    // conservative family above is the hard-asserted part.
    println!("sampled gated-belt schedules with a dead-law hit: {schedules_with_hit}/512");
}

/// THE FALSIFICATION STATISTIC, the pre-patch (ungated) belt
/// family: the ungated belt's violation class is REACHABLE under
/// sampled schedules — the mechanical pin that the finding is real
/// and not a hand-built story, and the record of what the gated
/// landing removed from the shipped bytes. The count is reported,
/// not asserted zero; the deterministic witness pins in
/// interleave_laws.rs carry the shape.
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
