// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z17: the micro-step coroutine controllers — the
//! honest scheduler's execution shape. Each verb instance is an
//! Actor whose program counter walks its kernel-mirrored program
//! order ONE MICRO-STEP AT A TIME: every observation (a volatile
//! read that feeds a later CAS) is its own step, and every action
//! (one RMW or write through interleave_segments.rs's segment
//! machines) is its own step. The scheduler — the property-tier
//! sampler, or the fixed no-interleaving driver the fidelity runs
//! use — advances one actor one micro-step at a time, so the
//! stale-observation windows materialize exactly as they do on
//! real CPUs: an actor reads, the other actor runs, the first
//! actor's CAS meets a moved world.
//!
//! The controllers ARE the verbs: `Actor::run` (advance until
//! done, nothing interleaved) is the sequential driver the
//! fidelity theorems hold against the kernel's own functions, and
//! the same controllers under the sampler's alternating bit
//! stream are the two-CPU interleaving the theorem tier is about —
//! one implementation, both instruments (the Z6 law).

use crate::interleave_model::{Target, World};
use crate::interleave_segments::{
    belt_stamp_gated_seg, belt_stamp_ungated_seg, belt_zero_seg, consume_seg, debt_charge_seg,
    debt_pay_forgive_seg, debt_pay_tokens_seg, draw_leaf_credit_seg, draw_pool_take_seg,
    draw_rollback_seg, draw_stamp_seg, init_seg, mutate_seg, refill_cap_clamp, refill_credit,
    refill_frac_write, refill_seed_clamp, refill_window_take,
};
use crate::math_core::{Policy, gen_stamp_read, tokens_read};

/// The DRR fair-share epoch (drr.rs's window) — the failed draw's
/// rollback target, computed the kernel's own way.
pub const SHARE_EPOCH_NS: u64 = 100_000_000;

/// One verb instance. The parameters are the actor's own
/// resolution-time inputs (the policy the packet met, the packet
/// length, the draw's shaping constants); everything the verb
/// OBSERVES from the shared words is read through micro-steps, so
/// the staleness is scheduled, never assumed.
#[derive(Clone, Copy)]
pub enum Verb {
    /// The refill (refill_window over the pool).
    Refill { pol: Policy, now: u64 },
    /// The consume (try_consume over one bucket).
    Consume { target: Target, want: u32 },
    /// The draw's pure protocol core (try_draw without the
    /// map-shaped calls — the shaping words ride their documented
    /// slack class, never the token conservation).
    Draw {
        quantum: u64,
        learned: u16,
        allowance: u64,
        room: u64,
        now: u64,
    },
    /// The ECN debt charge (debt_charge over the debt word).
    DebtCharge { pkt_len: u32 },
    /// The ECN debt pay (debt_pay over the budget bucket and the
    /// debt word).
    DebtPay { target: Target },
    /// The generation belt (drr_flow.rs's leaf belt and its
    /// cake_flow.rs flow twin); `gated` selects the stamp form —
    /// the gated form is the SHIPPED bytes since night-frontier-Z17's
    /// landing, the ungated form the pre-patch bytes the finding
    /// falsified (the record the property tier keeps).
    Belt { gated: bool },
    /// The policy mutation (the live generation bump).
    Mutate { bump: u64 },
    /// The NOEXIST init (the map layer's atomic insert).
    Init,
}

/// One actor's per-instance state: the verb, the program counter,
/// the verb's final verdict (the boolean the kernel functions
/// return — the consume's allow, the draw's success, the charge's
/// landed), and the observation locals the micro-steps shuttle
/// between the observation phase and the action phase.
#[derive(Clone)]
pub struct Actor {
    pub verb: Verb,
    pc: u8,
    done: bool,
    /// The verb's returned verdict (consume: allowed; draw: drew;
    /// charge: the charge landed).
    pub verdict: bool,
    // observation locals (shared across verbs by phase role)
    seeded: u64,
    last_obs: u64,
    frac_obs: u64,
    elapsed: u64,
    won: bool,
    cap_branch: bool,
    new_frac: u64,
    over_obs: u64,
    observed: u64,
    stale_obs: u64,
    zeroed: bool,
    gen_obs: u64,
    outstanding: u64,
    pay: u64,
    fresh_obs: u64,
    draw_d: u64,
}

impl Actor {
    /// A fresh actor for one verb instance.
    pub fn new(verb: Verb) -> Actor {
        Actor {
            verb,
            pc: 0,
            done: false,
            verdict: false,
            seeded: 0,
            last_obs: 0,
            frac_obs: 0,
            elapsed: 0,
            won: false,
            cap_branch: false,
            new_frac: 0,
            over_obs: 0,
            observed: 0,
            stale_obs: 0,
            zeroed: false,
            gen_obs: 0,
            outstanding: 0,
            pay: 0,
            fresh_obs: 0,
            draw_d: 0,
        }
    }

    /// Whether the verb instance has completed.
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Run to completion with NOTHING interleaved — the sequential
    /// driver (the fidelity runs' shape: every observation is
    /// fresh, immediately followed by its action).
    pub fn run(&mut self, w: &mut World) {
        while !self.advance(w) {}
    }

    /// The UNROLLED sequential driver — twelve explicit micro-steps,
    /// no loop: the kani economics (a symbolic program counter
    /// matched inside a loop back-edge explodes the solver's path
    /// count; the explicit sequence keeps the counter chain
    /// concrete while running the SAME advance steps the loop
    /// would). Every verb completes inside twelve steps by
    /// construction (refill 9, consume 8, draw 8, charge 4, pay 10,
    /// belt 5, mutate 1, init 1) — the trailing assert is the
    /// driver's own bound check, fail-loud if a verb ever grows.
    pub fn run_unrolled(&mut self, w: &mut World) {
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        if !self.done {
            self.advance(w);
        }
        assert!(self.done, "the unrolled driver ran out of steps");
    }

    /// Advance exactly one micro-step. Returns true when the verb
    /// is complete after this step.
    pub fn advance(&mut self, w: &mut World) -> bool {
        match self.verb {
            Verb::Refill { pol, now } => self.advance_refill(w, &pol, now),
            Verb::Consume { target, want } => self.advance_consume(w, target, want),
            Verb::Draw {
                quantum,
                learned,
                allowance,
                room,
                now,
            } => self.advance_draw(w, quantum, learned, allowance, room, now),
            Verb::DebtCharge { pkt_len } => self.advance_charge(w, pkt_len),
            Verb::DebtPay { target } => self.advance_pay(w, target),
            Verb::Belt { gated } => self.advance_belt(w, gated),
            Verb::Mutate { bump } => {
                mutate_seg(w, bump);
                self.done = true;
                true
            }
            Verb::Init => {
                init_seg(w);
                self.done = true;
                true
            }
        }
    }

    // ── refill_window's program order ───────────────────────────
    fn advance_refill(&mut self, w: &mut World, pol: &Policy, now: u64) -> bool {
        match self.pc {
            0 => {
                self.seeded = tokens_read(&w.pool);
                self.pc = 1;
            }
            1 => {
                refill_seed_clamp(w, pol.burst_bytes, self.seeded);
                self.pc = 2;
            }
            2 => {
                let ptr = &w.pool.last_refill_ns;
                // SAFETY: the model's own live field (READ_ONCE's
                // bytes — the volatile read the kernel's window
                // step rides).
                self.last_obs = unsafe { (ptr as *const u64).read_volatile() };
                self.pc = 3;
            }
            3 => {
                let win = refill_window_take(w, now, self.last_obs);
                self.won = win.won;
                self.elapsed = win.elapsed;
                self.pc = if win.won && win.elapsed > 0 && pol.rate_bps > 0 {
                    4
                } else {
                    // No credit armed: the kernel writes no
                    // fraction (the whole credit block is gated on
                    // the owned forward window).
                    9
                };
            }
            4 => {
                let ptr = &w.pool.frac_rem;
                // SAFETY: the same one-field volatile read.
                self.frac_obs = unsafe { (ptr as *const u64).read_volatile() };
                self.pc = 5;
            }
            5 => {
                let credit = refill_credit(w, pol, self.elapsed, self.frac_obs);
                self.cap_branch = credit.cap_branch;
                self.new_frac = credit.new_frac;
                self.pc = if credit.cap_branch { 6 } else { 8 };
            }
            6 => {
                self.over_obs = tokens_read(&w.pool);
                self.pc = 7;
            }
            7 => {
                refill_cap_clamp(w, pol.burst_bytes, self.over_obs);
                self.pc = 8;
            }
            8 => {
                let v = if self.cap_branch { 0 } else { self.new_frac };
                refill_frac_write(w, v);
                self.done = true;
            }
            9 => {
                // The un-owned window's terminal: nothing written.
                self.done = true;
            }
            _ => {
                self.done = true;
            }
        }
        self.done
    }

    // ── try_consume's program order (four written-out attempts) ──
    fn advance_consume(&mut self, w: &mut World, target: Target, want: u32) -> bool {
        let stock = match target {
            crate::interleave_model::Target::Pool => tokens_read(&w.pool),
            crate::interleave_model::Target::Leaf => {
                if w.born {
                    tokens_read(&w.leaf)
                } else {
                    // The absent slot's miss: the verb completes
                    // fail-open without touching anything.
                    self.verdict = false;
                    self.done = true;
                    return true;
                }
            }
        };
        match self.pc {
            0 => {
                self.observed = stock;
                self.pc = 1;
            }
            1 => {
                if consume_seg(w, target, want, self.observed) {
                    self.verdict = true;
                    self.done = true;
                    return true;
                }
                self.pc = 2;
            }
            2 => {
                self.observed = stock;
                self.pc = 3;
            }
            3 => {
                if consume_seg(w, target, want, self.observed) {
                    self.verdict = true;
                    self.done = true;
                    return true;
                }
                self.pc = 4;
            }
            4 => {
                self.observed = stock;
                self.pc = 5;
            }
            5 => {
                if consume_seg(w, target, want, self.observed) {
                    self.verdict = true;
                    self.done = true;
                    return true;
                }
                self.pc = 6;
            }
            6 => {
                self.observed = stock;
                self.pc = 7;
            }
            7 => {
                consume_seg(w, target, want, self.observed);
                self.verdict = false;
                self.done = true;
            }
            _ => {
                self.verdict = false;
                self.done = true;
            }
        }
        self.done
    }

    // ── try_draw's pure protocol core (draw_attempt!'s order) ────
    fn advance_draw(
        &mut self,
        w: &mut World,
        quantum: u64,
        learned: u16,
        allowance: u64,
        room: u64,
        now: u64,
    ) -> bool {
        match self.pc {
            0 => {
                let ptr = &w.leaf.last_refill_ns;
                // SAFETY: the leaf's draw stamp, the READ_ONCE
                // bytes the kernel's draw step rides.
                self.observed = unsafe { (ptr as *const u64).read_volatile() };
                self.pc = 1;
            }
            1 => {
                if !draw_stamp_seg(w, now, self.observed) {
                    // The stamp lock was lost: another CPU's draw
                    // for this leaf is in flight (the kernel's
                    // skip — its credit lands within nanoseconds).
                    self.verdict = false;
                    self.done = true;
                    return true;
                }
                self.pc = 2;
            }
            2 => {
                self.observed = tokens_read(&w.pool);
                self.pc = 3;
            }
            3 => match draw_pool_take_seg(w, quantum, learned, allowance, room, self.observed) {
                Some(d) => {
                    self.draw_d = d;
                    self.pc = 6;
                }
                None => self.pc = 4,
            },
            4 => {
                self.observed = tokens_read(&w.pool);
                self.pc = 5;
            }
            5 => match draw_pool_take_seg(w, quantum, learned, allowance, room, self.observed) {
                Some(d) => {
                    self.draw_d = d;
                    self.pc = 6;
                }
                None => self.pc = 7,
            },
            6 => {
                draw_leaf_credit_seg(w, self.draw_d);
                self.verdict = true;
                self.done = true;
            }
            7 => {
                // The failed draw's rollback: the stamp rolls to
                // the CURRENT epoch's start (the kernel's own
                // arithmetic — the u32 epoch and its product,
                // mirrored exactly).
                let now_epoch = (now / SHARE_EPOCH_NS) as u32;
                let epoch_start = u64::from(now_epoch) * SHARE_EPOCH_NS;
                draw_rollback_seg(w, now, epoch_start);
                self.verdict = false;
                self.done = true;
            }
            _ => {
                self.verdict = false;
                self.done = true;
            }
        }
        self.done
    }

    // ── debt_charge's program order (two written-out attempts) ───
    fn advance_charge(&mut self, w: &mut World, pkt_len: u32) -> bool {
        match self.pc {
            0 => {
                self.observed = w.debt.tokens;
                self.pc = 1;
            }
            1 => {
                if debt_charge_seg(w, pkt_len, self.observed) {
                    self.verdict = true;
                    self.done = true;
                    return true;
                }
                self.pc = 2;
            }
            2 => {
                self.observed = w.debt.tokens;
                self.pc = 3;
            }
            3 => {
                debt_charge_seg(w, pkt_len, self.observed);
                self.verdict = false;
                self.done = true;
            }
            _ => {
                self.verdict = false;
                self.done = true;
            }
        }
        self.done
    }

    // ── debt_pay's program order (the over-pay window exposed) ───
    fn advance_pay(&mut self, w: &mut World, target: Target) -> bool {
        match self.pc {
            0 => {
                self.outstanding = w.debt.tokens;
                self.pc = if self.outstanding == 0 { 9 } else { 1 };
            }
            1 => {
                self.observed = match target {
                    crate::interleave_model::Target::Pool => tokens_read(&w.pool),
                    crate::interleave_model::Target::Leaf => {
                        if w.born {
                            tokens_read(&w.leaf)
                        } else {
                            self.pc = 9;
                            return self.done;
                        }
                    }
                };
                self.pc = 2;
            }
            2 => match debt_pay_tokens_seg(w, target, self.outstanding, self.observed) {
                Some(p) => {
                    self.pay = p;
                    self.pc = 4;
                }
                None => self.pc = 5,
            },
            4 => {
                self.fresh_obs = w.debt.tokens;
                self.pc = 3;
            }
            3 => {
                debt_pay_forgive_seg(w, self.pay, self.fresh_obs);
                self.pc = 9;
            }
            5 => {
                self.observed = match target {
                    crate::interleave_model::Target::Pool => tokens_read(&w.pool),
                    crate::interleave_model::Target::Leaf => {
                        if w.born {
                            tokens_read(&w.leaf)
                        } else {
                            self.pc = 9;
                            return self.done;
                        }
                    }
                };
                self.pc = 6;
            }
            6 => match debt_pay_tokens_seg(w, target, self.outstanding, self.observed) {
                Some(p) => {
                    self.pay = p;
                    self.pc = 7;
                }
                None => self.pc = 9,
            },
            7 => {
                self.fresh_obs = w.debt.tokens;
                self.pc = 8;
            }
            8 => {
                debt_pay_forgive_seg(w, self.pay, self.fresh_obs);
                self.pc = 9;
            }
            9 => {
                self.done = true;
            }
            _ => {
                self.done = true;
            }
        }
        self.done
    }

    // ── the leaf belt's program order (the gated kernel shape) ──
    fn advance_belt(&mut self, w: &mut World, gated: bool) -> bool {
        match self.pc {
            0 => {
                // current_generation()'s read, its own observation
                // step: a policy mutation landing between this read
                // and the stamp write is exactly the staleness the
                // real belt runs with.
                self.gen_obs = w.g_live;
                self.pc = 1;
            }
            1 => {
                let stamp = gen_stamp_read(&w.leaf);
                if stamp == self.gen_obs {
                    // The belt does not fire: the stamp matches.
                    self.done = true;
                    return true;
                }
                self.pc = 2;
            }
            2 => {
                self.stale_obs = tokens_read(&w.leaf);
                self.pc = 3;
            }
            3 => {
                self.zeroed = belt_zero_seg(w, self.stale_obs);
                self.pc = 4;
            }
            4 => {
                // The gated arm is the shipped bytes (the gated
                // landing); the ungated arm is the pre-patch record
                // the property tier falsifies against.
                if gated {
                    let zeroed_or_empty = self.zeroed || self.stale_obs == 0;
                    belt_stamp_gated_seg(w, self.gen_obs, zeroed_or_empty);
                } else {
                    belt_stamp_ungated_seg(w, self.gen_obs);
                }
                self.done = true;
            }
            _ => {
                self.done = true;
            }
        }
        self.done
    }
}
