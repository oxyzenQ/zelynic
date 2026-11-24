// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! night-frontier-Z17: the five verbs' SEGMENT machines — the
//! atomicity units the scheduler interleaves. Each segment is one
//! observation phase (its observed parameters, possibly stale —
//! the exact window the kernel's read-to-CAS gap leaves open)
//! plus at most one RMW or write, and every segment calls the
//! ACTUAL dual-compiled primitives — the same bytes the kernel
//! object builds. The program orders mirror the kernel's own:
//! math.rs's refill_window and try_consume, ecn.rs's debt pair,
//! drr_flow_draw.rs's draw_attempt! shape, drr_flow.rs's six-line
//! leaf belt, the map layer's NOEXIST insert. The fidelity
//! theorems (kani_interleave.rs) hold the refill, consume, and
//! debt machines against the includeable kernel functions for ALL
//! inputs; the draw and belt machines' sequencing is pinned by the
//! segment bytes plus the sampler (the aya-touching halves are
//! not includeable by this package's core-only law — the honest
//! boundary, stated in interleave_model.rs's header).

use crate::drr_core;
use crate::ecn_core::ECN_DEBT_CAP;
use crate::interleave_model::{Target, World, leaf_or_fail};
use crate::math_core::{
    Bucket, Policy, draw_stamp_take, gen_stamp_read, gen_stamp_write, refill_credits, tokens_cas,
    tokens_fetch_add, tokens_read,
};

// ── The sequential fidelity driver ──────────────────────────────────

/// The refill's DIRECT sequential driver — the kernel's own program
/// order over the segments, fresh observations, no actor machinery:
/// the kani economics (the actor's program-counter match unwound
/// twelve times multiplies the heavyweight arm bodies past every
/// solver ceiling; the direct sequence carries each body exactly
/// once). The actor's program order is pinned to this driver by the
/// property tier (the sampled equivalence), and this driver is
/// pinned to the kernel's bytes by the kani fidelity lemmas — the
/// chain closes: actor == driver == kernel.
pub fn run_refill_direct(w: &mut World, pol: &Policy, now: u64) {
    let seeded_obs = tokens_read(&w.pool);
    refill_seed_clamp(w, pol.burst_bytes, seeded_obs);
    let last_ptr = &w.pool.last_refill_ns;
    // SAFETY: the model's own live field (READ_ONCE's bytes — the
    // volatile read the kernel's window step rides).
    let last_obs = unsafe { (last_ptr as *const u64).read_volatile() };
    let win = refill_window_take(w, now, last_obs);
    if win.won && win.elapsed > 0 && pol.rate_bps > 0 {
        let frac_ptr = &w.pool.frac_rem;
        // SAFETY: the same one-field volatile read.
        let frac_obs = unsafe { (frac_ptr as *const u64).read_volatile() };
        let credit = refill_credit(w, pol, win.elapsed, frac_obs);
        if credit.cap_branch {
            let over_obs = tokens_read(&w.pool);
            refill_cap_clamp(w, pol.burst_bytes, over_obs);
            refill_frac_write(w, 0);
        } else {
            refill_frac_write(w, credit.new_frac);
        }
    }
}

// ── The refill verb's segments (math.rs refill_window) ────────────

/// Segment R1: the security-3 seed clamp. `seeded_obs` is the
/// actor's own earlier read — a stale observation loses the CAS to
/// whatever moved the stock, and the clamp converges on a later
/// packet (the kernel's one-shot-CAS posture, no loop body for
/// the verifier to bound).
pub fn refill_seed_clamp(w: &mut World, burst: u64, seeded_obs: u64) {
    if seeded_obs > burst && tokens_cas(&mut w.pool, seeded_obs, burst) {
        w.burned += u128::from(seeded_obs - burst);
    }
}

/// Segment R2: the window-ownership CAS (the heal branch included)
/// plus the elapsed the winner arms. Pure stamp arithmetic — the
/// ledger is untouched; the credit the window arms lands in its
/// own segment, so a mid-verb observation still sees a consistent
/// ledger (P1 holds at every point of every schedule).
pub fn refill_window_take(
    w: &mut World,
    now: u64,
    last_obs: u64,
) -> crate::interleave_model::WindowOutcome {
    if now > last_obs {
        if draw_stamp_take(&mut w.pool, last_obs, now) {
            // The elapsed, computed the kernel's own expression
            // shape (saturating sub, then the branch cap) so the
            // credit lemma's multiply circuits merge with the
            // kernel's — the value is the same either way; the
            // SHAPE is the solver economics.
            let mut elapsed = now.saturating_sub(last_obs);
            if elapsed > crate::math_core::NS_PER_SEC {
                elapsed = crate::math_core::NS_PER_SEC;
            }
            return crate::interleave_model::WindowOutcome { won: true, elapsed };
        }
        return crate::interleave_model::WindowOutcome {
            won: false,
            elapsed: 0,
        };
    }
    if last_obs.saturating_sub(now) > crate::math_core::NS_PER_SEC {
        // The absurd-excursion heal: hostile or drifted future
        // stamp, no credit (the kernel's own v7 sanitization
        // branch, the stall-fountain close).
        let _ = draw_stamp_take(&mut w.pool, last_obs, now);
    }
    crate::interleave_model::WindowOutcome {
        won: false,
        elapsed: 0,
    }
}

/// Segment R3: the owned window's credit — the fetch_add plus the
/// ledger entry, one transition. `frac_obs` is the actor's own
/// earlier read of the fraction (the documented stale-fraction
/// window, sub-byte, safe direction — exposed as a parameter so
/// the theorem tier sees it instead of hiding it inside a call).
pub fn refill_credit(
    w: &mut World,
    pol: &Policy,
    elapsed: u64,
    frac_obs: u64,
) -> crate::interleave_model::CreditOutcome {
    let (whole, new_frac) = refill_credits(pol.rate_bps, pol.burst_bytes, elapsed, frac_obs);
    let before = tokens_fetch_add(&mut w.pool, whole);
    w.entered += u128::from(whole);
    crate::interleave_model::CreditOutcome {
        cap_branch: before.saturating_add(whole) > pol.burst_bytes,
        new_frac,
    }
}

/// Segment R4: the post-credit cap clamp (the cap branch's CAS,
/// its own scheduling point — the kernel's one-shot convergence;
/// a lost clamp leaves the documented one-refill transient).
pub fn refill_cap_clamp(w: &mut World, burst: u64, over_obs: u64) {
    if over_obs > burst && tokens_cas(&mut w.pool, over_obs, burst) {
        w.burned += u128::from(over_obs - burst);
    }
}

/// Segment R5: the fraction write — 0 in the cap branch, the new
/// fraction otherwise (the kernel writes unconditionally inside
/// the taken branch; the write is the WRITE_ONCE twin).
pub fn refill_frac_write(w: &mut World, v: u64) {
    let frac_ptr = &mut w.pool.frac_rem;
    crate::interleave_model::word_write(frac_ptr, v);
}

// ── The consume verb's segments (math.rs try_consume) ─────────────

/// Segment C: one consume attempt — the sufficiency-verified CAS.
/// The spent shadow lands with the deduction, one transition; the
/// leaf's taint spends live first (the worst case for the belt's
/// dead law — the conservative split the law deserves). An absent
/// leaf slot is the kernel's fail-open miss: no state change.
pub fn consume_seg(w: &mut World, target: Target, want: u32, observed_obs: u64) -> bool {
    let want = u64::from(want);
    let bkt = match target {
        Target::Pool => &mut w.pool,
        Target::Leaf => match leaf_or_fail(w) {
            Some(b) => b,
            None => return false,
        },
    };
    if observed_obs >= want && tokens_cas(bkt, observed_obs, observed_obs - want) {
        w.spent += u128::from(want);
        if matches!(target, Target::Leaf) {
            if w.live >= want {
                w.live -= want;
            } else {
                w.dead -= want - w.live;
                w.live = 0;
            }
        }
        return true;
    }
    false
}

// ── The draw verb's segments (drr_flow_draw.rs try_draw) ───────────

/// Segment D1: the draw admission and stamp lock — the
/// window-ownership trick on the leaf's draw stamp. Pure stamp
/// arithmetic; the ledger is untouched. An absent leaf slot is
/// the kernel's fail-open miss (get_leaf_ptr returned nothing —
/// the draw never runs): the verb completes as a no-op.
pub fn draw_stamp_seg(w: &mut World, now: u64, stamp_obs: u64) -> bool {
    if !w.born {
        return false;
    }
    now >= stamp_obs && draw_stamp_take(&mut w.leaf, stamp_obs, now)
}

/// Segment D2: the pool take — the sufficiency-verified CAS that
/// moves the take out of the pool. The take is computed by the
/// pure law (drr::take_size, the two-lane form) over the actor's
/// own observed pool stock; the debit arms the in-flight shadow —
/// the credit lands in its own segment, the real window between
/// the pool CAS and the leaf fetch_add the kernel's own "the pair
/// can only under-deliver" comment owns.
pub fn draw_pool_take_seg(
    w: &mut World,
    quantum: u64,
    learned: u16,
    allowance: u64,
    room: u64,
    observed_obs: u64,
) -> Option<u64> {
    let d = drr_core::take_size(quantum, observed_obs, learned, allowance, room);
    if d > 0 && tokens_cas(&mut w.pool, observed_obs, observed_obs - d) {
        w.inflight += u128::from(d);
        Some(d)
    } else {
        None
    }
}

/// Segment D3: the leaf credit — the draw's atomic add landing the
/// take, plus the taint rule: a credit landing while the leaf is
/// stamped with the live generation is live, everything else is
/// dead (a stale-budget take — exactly the class the belt exists
/// to zero). The born gate mirrors the kernel's own miss posture
/// (the credit only ever follows the stamp lock, which already
/// required a live leaf).
pub fn draw_leaf_credit_seg(w: &mut World, d: u64) {
    if !w.born {
        return;
    }
    tokens_fetch_add(&mut w.leaf, d);
    w.inflight -= u128::from(d);
    if gen_stamp_read(&w.leaf) == w.g_live {
        w.live += d;
    } else {
        w.dead += d;
    }
}

/// Segment D4: the failed draw's stamp rollback (to the current
/// epoch's start — the retry-every-packet admission the kernel
/// rolls to). Pure stamp arithmetic, born-gated with the verb's
/// own miss posture.
pub fn draw_rollback_seg(w: &mut World, now: u64, epoch_start: u64) {
    if !w.born {
        return;
    }
    let _ = draw_stamp_take(&mut w.leaf, now, epoch_start);
}

// ── The debt verb's segments (ecn.rs debt_charge / debt_pay) ───────

/// Segment X: one charge attempt — the cap-guarded CAS onto the
/// debt word (the note_share discipline's two-attempt shape, one
/// attempt per segment; the guard rides the same observation the
/// CAS compares, so a lost race cannot slip past the cap).
pub fn debt_charge_seg(w: &mut World, pkt_len: u32, observed_obs: u64) -> bool {
    let want = u64::from(pkt_len);
    observed_obs.saturating_add(want) <= ECN_DEBT_CAP
        && tokens_cas(&mut w.debt, observed_obs, observed_obs + want)
}

/// Segment P1: the pay's token deduction — `pay` is computed by
/// the pure law from the actor's own two observations (the
/// outstanding it read, the stock it read), and the deduction
/// lands through the sufficiency-verified CAS. The paid shadow
/// lands with it, one transition.
pub fn debt_pay_tokens_seg(
    w: &mut World,
    target: Target,
    outstanding_obs: u64,
    available_obs: u64,
) -> Option<u64> {
    let pay = available_obs.min(outstanding_obs);
    if pay == 0 {
        return None;
    }
    let bkt = match target {
        Target::Pool => &mut w.pool,
        Target::Leaf => leaf_or_fail(w)?,
    };
    if tokens_cas(bkt, available_obs, available_obs - pay) {
        w.paid += u128::from(pay);
        if matches!(target, Target::Leaf) {
            if w.live >= pay {
                w.live -= pay;
            } else {
                w.dead -= pay - w.live;
                w.live = 0;
            }
        }
        return Some(pay);
    }
    None
}

/// Segment P2: the pay's debt forgiveness — against a fresh read
/// (a concurrent payer may have forgiven part of it already),
/// never below zero. The token CAS and this forgiveness are
/// SEPARATE segments on purpose: the gap between them is the
/// documented over-pay window (safe direction, one pay wide) the
/// theorem tier now sees instead of assumes.
pub fn debt_pay_forgive_seg(w: &mut World, pay: u64, fresh_obs: u64) {
    let forgive = fresh_obs.min(pay);
    let _ = tokens_cas(&mut w.debt, fresh_obs, fresh_obs - forgive);
}

// ── The belt verb's segments (drr_flow.rs's leaf belt) ─────────────

/// Segment B1: the stale-quantum zeroing — the belt's CAS. The
/// burn lands with the zeroed stock (stale quanta leave without a
/// delivery); the taint zeroes with the tokens it zeroed. A lost
/// CAS (a racing spend or credit moved the stock between the
/// actor's read and the CAS) leaves the stock untouched — the
/// kernel's own discard, the exact shape the finding documents.
pub fn belt_zero_seg(w: &mut World, stale_obs: u64) -> bool {
    if !w.born {
        return false;
    }
    if stale_obs != 0 && tokens_cas(&mut w.leaf, stale_obs, 0) {
        w.burned += u128::from(stale_obs);
        w.live = 0;
        w.dead = 0;
        return true;
    }
    false
}

/// Segment B2 (the SHIPPED form): the stamp write. The kernel
/// writes its observed generation unconditionally after the zero
/// attempt — win or lose — which is the byte shape this segment
/// mirrors (the fidelity to drr_flow.rs's six lines is stated,
/// sampler-pinned; the machine cannot satisfy P4 in this form —
/// the falsification is the finding, and the gated twin below is
/// the proposed close's certificate).
pub fn belt_stamp_seg(w: &mut World, gen_obs: u64) {
    if w.born && gen_stamp_read(&w.leaf) != gen_obs {
        gen_stamp_write(&mut w.leaf, gen_obs);
    }
}

/// Segment B2 (the GATED form — the proposed close, model-side):
/// the stamp write lands only when the zeroing actually succeeded
/// or the stock read zero — a failed zero keeps the stamp stale,
/// so the next packet's belt re-fires and the zeroing converges
/// (the leaf belt re-fires on every packet while the stamp
/// mismatches, exactly the convergence the clamp family owns).
/// The re-observation (`tokens_read == 0`) is inside the segment,
/// the model's atomicity; the real re-read-to-write gap is the
/// two-word atomicity floor the finding names honestly.
pub fn belt_stamp_gated_seg(w: &mut World, gen_obs: u64, zeroed: bool) {
    if w.born && gen_stamp_read(&w.leaf) != gen_obs && zeroed && tokens_read(&w.leaf) == 0 {
        gen_stamp_write(&mut w.leaf, gen_obs);
    }
}

// ── The mutation and init verbs ────────────────────────────────────

/// Segment M: the policy mutation — the live generation bump,
/// forward only (the MMSPA memo's monotone design; the belt exists
/// for exactly this move). No stock arithmetic: P1 untouched, the
/// taint laws only gain room (a stale stamp gets staler).
pub fn mutate_seg(w: &mut World, bump: u64) {
    w.g_live += bump;
}

/// Segment I: the NOEXIST init — the map layer's atomic insert.
/// Two racing initializers converge on one zero bucket (the loser
/// re-looks-up and rides the winner's entry — the insert itself
/// is the kernel's own atomicity, which is the whole theorem); a
/// born slot no-ops (BPF_NOEXIST refuses the clobber). The genesis
/// ledger counts a born leaf only, and the absent slot was the
/// zero bucket all along, so the birth changes no equation.
pub fn init_seg(w: &mut World) {
    if !w.born {
        w.leaf = Bucket {
            tokens: 0,
            last_refill_ns: 0,
            frac_rem: 0,
        };
        w.born = true;
    }
}
