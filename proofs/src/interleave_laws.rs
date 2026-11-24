// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z17: the property tier over the interleaving
//! model — the sampled instruments that stand beside the kani
//! theorems (the schedule sampler lives in its sibling
//! interleave_sampler.rs, split here at the 600-line cap):
//!
//!  * THE FIDELITY HAMMERS: the refill, consume, and debt actors,
//!    run with nothing interleaved, must reproduce the kernel
//!    functions' final state and verdict on every sampled case —
//!    thousands of shrinkable cases per run, the anti-gimmick
//!    instrument under the for-all pins.
//!  * THE BELT WITNESS PINS: the finding, reproduced
//!    deterministically against the PRE-PATCH (ungated) belt the
//!    kernel shipped until night-frontier-Z17's gated landing —
//!    the falsification record the patch's own rationale rides.
//!    The ungated stamp write certified a dead remnant a racing
//!    spend left (the failed zero-CAS class) and a dead credit a
//!    racing draw landed (the in-flight class); the ledger held
//!    throughout — the violation was the certification, never the
//!    conservation. The SHIPPED form since rung 8 (the
//!    zeroed-verdict gate) refuses the spend class and converges,
//!    and carries the in-flight class as its NAMED residual
//!    (quantum-bounded — the two-word write window itself); the
//!    QUIET form (rung 4's re-observing landing, the live lane's
//!    falsification) refuses both classes — the unshippable
//!    certificate beside the kani one.
//!  * THE SCHEDULE SAMPLER: two actors, random verbs, an
//!    adversarial bit stream — the conservative invariant asserted
//!    after every micro-step of every sampled schedule (the
//!    shipped belt's family, the dead law counted and reported),
//!    and the ungated family's violation-class reach
//!    counted (the falsification's statistical pin) — the sibling
//!    interleave_sampler.rs carries the instrument itself.

use proptest::prelude::*;

use crate::interleave_actors::{Actor, Verb};
use crate::interleave_model::{Target, World};
use crate::interleave_segments::{belt_stamp_quiet_seg, belt_zero_seg};
use crate::math_core::{Bucket, Policy, refill_window, try_consume};

// The reachable-ish sampled domains (the kani tier carries the
// hostile domain; the sampler's job is breadth at the shapes real
// traffic produces, plus the edges). Shared with the sampler
// sibling through the pub(crate) surface below.
pub(crate) const SAMPLED_MAX_RATE: u64 = 1_000_000_000_000;
pub(crate) const SAMPLED_MAX_BURST: u64 = 100_000_000;
pub(crate) const SAMPLED_MAX_STOCK: u64 = 1 << 40;
pub(crate) const SAMPLED_MAX_CLOCK: u64 = 1 << 32;
pub(crate) const ECN_DEBT_CAP: u64 = 65_536;

fn cases() -> ProptestConfig {
    ProptestConfig::with_cases(4096)
}

pub(crate) fn sampled_policy(rate: u64, burst: u64) -> Policy {
    Policy {
        rate_bps: rate,
        burst_bytes: burst,
        floor_bps: 0,
        ceil_bps: 0,
        group_id: 0,
        flags: 0,
    }
}

pub(crate) fn bucket_of(tokens: u64, last: u64, frac: u64) -> Bucket {
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

/// THE FINDING, class one — the pre-patch record: the ungated
/// belt's stamp write certified a racing spend's dead remnant.
/// The interleaving: the belt reads the stale stock, a consume
/// verb runs whole between the read and the zeroing CAS, the CAS
/// loses against the moved stock, and the unconditional stamp
/// write lands a current stamp over the surviving remnant. The
/// LEDGER holds throughout (the remnant is real budget, never
/// minted) — the violation is the certification, exactly the
/// class the gated form (the shipped bytes since the landing)
/// refuses.
#[test]
fn legacy_belt_certifies_a_racing_spend_dead_remnant() {
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

/// THE FINDING, class two — the pre-patch record: the ungated
/// belt's stamp write certified a racing draw's dead credit. The
/// interleaving: a draw arms its take (the pool CAS landed, the
/// leaf credit pending), the belt runs against the stale-stamped
/// empty leaf, the draw's credit lands between the belt's stale
/// read and the stamp write, and the write certifies the
/// freshly-landed dead credit. Again the ledger holds — the take
/// is real budget.
#[test]
fn legacy_belt_certifies_a_racing_draw_dead_credit() {
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

/// THE CLOSE, class one, shipped: the gated belt — the SHIPPED
/// bytes (the zeroed-verdict gate since Z17 rung 8) — refuses the
/// racing spend's certification and converges by re-fire: the
/// failed zeroing keeps the stamp stale, the next packet's belt
/// re-fires, the zeroing now runs uncontended, and the dead stock
/// ends at exactly zero. The stockpile-bounded class the finding
/// filed is closed in the shipped bytes.
#[test]
fn shipped_belt_refuses_the_racing_spend_class_and_converges() {
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
}

/// THE NAMED RESIDUAL, class two, shipped: the gated belt's
/// verdict gate closes the stockpile-bounded class but prices the
/// quantum-bounded one — a racing draw's in-flight credit that
/// lands inside the belt's own read-to-write window is stamped
/// current. The LEDGER holds throughout (the take is real budget,
/// drawn under the live policy); the violation is the
/// certification, bounded by exactly one armed take (the quantum
/// here), the two-word atomicity floor the census names. The
/// re-observing QUIET form refuses this class — and the live e2e
/// lane priced that refusal (the census's rung-4 record).
#[test]
fn shipped_belt_certifies_the_racing_draw_class_the_named_residual() {
    // Class two, gated: the verdict gate cannot see the in-flight
    // credit that lands between the belt's read and its write.
    let mut w = World::genesis(bucket_of(1 << 20, 123, 0), bucket_of(0, 0, 5), 0, 7, true);
    let mut draw = Actor::new(Verb::Draw {
        quantum: 4096,
        learned: 0,
        allowance: u64::MAX,
        room: u64::MAX,
        now: 1000,
    });
    assert!(!draw.advance(&mut w));
    assert!(!draw.advance(&mut w));
    assert!(!draw.advance(&mut w));
    assert!(!draw.advance(&mut w));
    let mut belt = Actor::new(Verb::Belt { gated: true });
    assert!(!belt.advance(&mut w));
    assert!(!belt.advance(&mut w));
    assert!(!belt.advance(&mut w));
    assert!(draw.advance(&mut w)); // the leaf credit lands (dead)
    assert_eq!(w.dead, 4096);
    assert!(!belt.advance(&mut w)); // the zero attempt (no-op read)
    assert!(belt.advance(&mut w)); // the verdict gate stamps: the read
    // was zero, the credit raced the write window — the residual.
    assert_eq!(crate::math_core::gen_stamp_read(&w.leaf), 7);
    assert!(!w.belt_dead_ok());
    // The residual's own bound: exactly the armed take, not the
    // stockpile — the pre-patch class certified any surviving
    // remnant; this certifies one quantum.
    assert_eq!(w.dead, 4096);
    assert!(w.ledger_ok());
    assert!(w.laws_ok_except_dead());
}

/// THE QUIET CERTIFICATE, both classes: the re-observing belt —
/// rung 4's first landing, now the model-side form the live e2e
/// lane priced — refuses BOTH certification classes and converges
/// by re-fire: the re-observation re-reads the stock inside the
/// stamp segment and refuses to certify a stock it did not watch
/// empty. Unshippable under sustained delivery (the census's
/// numbers), certified here: the full law the shipped bytes
/// cannot carry.
#[test]
fn quiet_belt_refuses_and_converges_on_both_witness_classes() {
    // Class one, quiet: the failed zeroing keeps the stamp stale,
    // and the next belt converges the same way.
    let mut w = World::genesis(bucket_of(1 << 20, 123, 0), bucket_of(100, 0, 5), 0, 7, true);
    let gen_obs = w.g_live;
    // pc0-pc2 by hand: the generation read, the stamp mismatch,
    // the stale stock read (100).
    let stale_obs = crate::math_core::tokens_read(&w.leaf);
    assert_eq!(stale_obs, 100);
    let mut consumer = Actor::new(Verb::Consume {
        target: Target::Leaf,
        want: 30,
    });
    consumer.run(&mut w);
    // pc3: the zeroing CAS loses against the moved stock.
    let zeroed = belt_zero_seg(&mut w, stale_obs);
    assert!(!zeroed);
    belt_stamp_quiet_seg(&mut w, gen_obs, zeroed);
    assert_eq!(crate::math_core::gen_stamp_read(&w.leaf), 5);
    assert!(w.belt_dead_ok());
    // The convergence: the next episode runs uncontended.
    let stale2 = crate::math_core::tokens_read(&w.leaf);
    let zeroed2 = belt_zero_seg(&mut w, stale2);
    belt_stamp_quiet_seg(&mut w, gen_obs, zeroed2);
    assert_eq!(crate::math_core::gen_stamp_read(&w.leaf), 7);
    assert_eq!(w.dead, 0);
    assert!(w.laws_ok());

    // Class two, quiet: the re-observation refuses the racing
    // credit's certification; the next belt zeroes it.
    let mut w2 = World::genesis(bucket_of(1 << 20, 123, 0), bucket_of(0, 0, 5), 0, 7, true);
    let gen_obs2 = w2.g_live;
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
    // pc0-pc2: the empty stock read (0).
    let stale_obs2 = crate::math_core::tokens_read(&w2.leaf);
    assert_eq!(stale_obs2, 0);
    assert!(draw.advance(&mut w2)); // the leaf credit lands (dead)
    assert_eq!(w2.dead, 4096);
    // pc3: the zero attempt (no-op — the read was zero).
    let zeroed2 = belt_zero_seg(&mut w2, stale_obs2);
    assert!(!zeroed2);
    // pc4: the re-observation catches the raced credit and refuses.
    belt_stamp_quiet_seg(&mut w2, gen_obs2, zeroed2 || stale_obs2 == 0);
    assert_eq!(crate::math_core::gen_stamp_read(&w2.leaf), 5);
    assert!(w2.belt_dead_ok());
    // The convergence: the next belt zeroes the refused credit.
    let stale3 = crate::math_core::tokens_read(&w2.leaf);
    let zeroed3 = belt_zero_seg(&mut w2, stale3);
    belt_stamp_quiet_seg(&mut w2, gen_obs2, zeroed3);
    assert_eq!(crate::math_core::gen_stamp_read(&w2.leaf), 7);
    assert_eq!(w2.dead, 0);
    assert!(w2.laws_ok());
}
