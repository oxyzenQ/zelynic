// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the guarantee law (schema v24,
// NIGHT-improve-40 — the min/max brackets) moved out of drr.rs
// at the 600-line cap — nested #[path], re-exported through drr.
//
// ── The guarantee law (schema v24, NIGHT-improve-40: the min/max ──
//    brackets, floor/ceiling + hierarchical borrowing) ─────────────
//
// THE PROBLEM (the owner's lane list, the DRR arc's close): the
// v13/v16/v17/v20 laws made the leaves EQUAL — the epoch allowance
// is the pool's refill split across the drawee peak, nothing more.
// But equal is not always the intent: the policy owner may want
// every subprocess GUARANTEED a floor (the maintenance-window
// shape: "no leaf under 100kb, ever, however greedy its siblings")
// or CAPPED at a ceiling ("no leaf above 300kb even when its
// siblings are idle and the pool is rich"). The HTB rate/ceil
// idiom, carried into a policer that cannot queue — HFSC-lite, the
// strongest guarantee shape the verifier's straight-line budget
// admits.
//
// THE LAW: the epoch allowance's fair split is BRACKETED — clamped
// between the floor's per-epoch share and the ceiling's. The zero
// sentinel is UNSET on both sides (a 0/0 row is the exact v23
// arithmetic by construction — the fail-open posture), and both
// sides clamp against the row's own rate at every consumer, so a
// drifted or hostile value above the rate can never bind (the pool
// refills at the rate; a bracket above it is arithmetic noise) and
// the ledger's plain-multiply bound stays inside the band the
// ELAPSED_CEILING proof states.
//
// THE FLOOR IS A PRIORITY, NOT A RESERVATION: a floored leaf's
// allowance EARN RATE rises to the floor's share — no tokens are
// ever held back for it in the pool. This is deliberate, the LRU
// posture's own reasoning one lane over: a reservation would strand
// capacity when a leaf dies silently (transient systemd scopes,
// churned container cgroups — exactly the leaves the LRU exists to
// forget), and the release would lag the death. An absent leaf
// costs nothing instead: its floor earns nothing, draws nothing.
// The guarantee is enforced by the SIBLINGS' bounds, not by the
// floored leaf's own arithmetic — a greedy sibling's per-epoch
// total is bounded by ITS allowance, so the refill a floored leaf
// accrues is there when it asks.
//
// THE HIERARCHICAL BORROWING IS THE POOL ITSELF: unspent allowance
// stays in the pool (nothing else touches it), and any leaf under
// its ceiling may draw it through the unchanged residue/learned
// laws — the pool's natural accumulation IS the lender. No
// carve-out, no daemon, no borrowing ledger: the hierarchy is
// root-refill -> leaf-brackets, and the spare flows down to
// whichever leaf is under its ceiling and asking. A leaf whose
// ceiling is unset may borrow up to the whole budget (the legacy
// shape); a leaf whose ceiling is set may borrow only up to it.
//
// THE CEILING BINDS THE LONE DRAWER: the ledger-off lane (drawees
// < 2 -> the whole budget) stands for floor-only rows, but a set
// ceiling forces the ledger ON even for a lone leaf — a cap that
// folds the moment siblings appear is not a cap (the single active
// subprocess is exactly the case the owner caps). The stockpile
// tightens with it: quantum(ceil) instead of quantum(rate), so a
// capped leaf's banking bound is its OWN ceiling's quantum (the
// GSO admit floor still holds — quantum floors at 64 KiB for every
// rate) and the one-epoch overshoot stays one CEILING quantum, not
// one POLICY quantum. The floor never tightens the stockpile: a
// floored leaf banking several epochs toward one fat GSO admit is
// the v17 design itself (its TCP heals on the admit).
//
// THE OVER-SUBSCRIPTION HONESTY: when the floors' sum exceeds the
// pool's refill (K leaves each floored above refill/K — the config
// the per-leaf validation cannot see coming, leaves being dynamic),
// the floors degrade to the pool law: the pool never hands out
// what it does not have, so the late-epoch draws fail exactly the
// way an unfloored pool's do and the distribution settles between
// the fair split and the floor. The same documented honesty as the
// trickle tradeoff: coarse guarantees beat starved ones, and the
// bound is stated so the degradation is a decision, not drift. The
// sim pins hold both sides of it.
//
// THE CONTRADICTION: a floor above a ceiling is a config the
// userspace validation rejects outright — but the datapath law must
// be total, and on a contradiction the CEILING WINS (the cap is
// the safety law; a guarantee above a cap is unkeepable in any
// arithmetic that respects the cap).

/// The guarantee bracket's law (v24, pure): the epoch allowance —
/// the fair split, clamped between the floor's and the ceiling's
/// per-epoch shares. Both bracket sides clamp against the row's own
/// rate at this consumer (a bracket above the rate can never bind;
/// the clamp keeps the ledger's multiply bound in its proven band),
/// the zero sentinel is unset (the v23 arithmetic exactly), and on
/// the lone-drawer lane a set ceiling engages the ledger while a
/// floor-only bracket keeps the whole-budget row.
use super::epoch_allowance;
use super::epoch_refill;
use super::quantum;
#[inline(always)]
pub const fn guaranteed_allowance(
    rate_bps: u64,
    floor_bps: u64,
    ceil_bps: u64,
    drawees: u16,
) -> u64 {
    // The law-side clamp: the bracket never exceeds the row's own
    // rate (security-3's posture for the pair — the userspace write
    // ladder is the first guard, this is the second, and a drifted
    // map row is the case between them).
    let bounded_floor = if floor_bps > rate_bps {
        rate_bps
    } else {
        floor_bps
    };
    let bounded_ceiling = if ceil_bps > rate_bps {
        rate_bps
    } else {
        ceil_bps
    };
    if drawees < 2 {
        // The lone-drawer close: the OFF lane keeps the whole
        // budget for a floor-only bracket, but a set ceiling forces
        // the ledger ON — a cap that folds when siblings appear is
        // not a cap.
        if bounded_ceiling == 0 {
            return u64::MAX;
        }
        return epoch_refill(bounded_ceiling);
    }
    let fair_split = epoch_allowance(rate_bps, drawees);
    let floor_epoch = epoch_refill(bounded_floor);
    let ceiling_epoch_share = epoch_refill(bounded_ceiling);
    // The floor raises, the ceiling lowers, and the zero sentinel
    // SKIPS its side (an unset ceiling clamping at 0 would zero
    // every split — the battery's own catch, before any kernel saw
    // the law); on the contradiction the ceiling wins (the cap is
    // the safety law). The long local names are the fair_draw_size
    // lesson's own discipline: this tail if-else pair must never
    // collapse under the ebpf nightly's single-line cap while
    // stable expands it — the named forms run past the cap on both
    // toolchains.
    let floored_split = if floor_epoch > fair_split {
        floor_epoch
    } else {
        fair_split
    };
    if bounded_ceiling != 0 && ceiling_epoch_share < floored_split {
        ceiling_epoch_share
    } else {
        floored_split
    }
}

/// The stockpile cap under the guarantee law (v24, pure): the
/// banking bound a starved leaf may accumulate toward one fat GSO
/// admit. A set ceiling tightens it to the CEILING's quantum — a
/// leaf banked at the policy-rate quantum could spend
/// rate-quantum in one epoch, a multiple of its ceiling for every
/// quantum above it; the ceiling's own quantum keeps the GSO admit
/// floor (quantum floors at 64 KiB for every rate) while the
/// one-epoch overshoot stays one CEILING quantum. No ceiling: the
/// v13 stockpile, unchanged. The floor never tightens it — the
/// banking is the starved leaf's own right, and a floored leaf
/// banks the same way an unfloored one does.
#[inline(always)]
pub const fn guaranteed_stockpile(rate_bps: u64, ceil_bps: u64) -> u64 {
    // The law-side clamp: a ceiling above the rate can never bind
    // (the pool refills at the rate), so the stockpile stays at the
    // legacy quantum rather than growing past it on drifted state.
    let bounded_ceil = if ceil_bps > rate_bps {
        rate_bps
    } else {
        ceil_bps
    };
    if bounded_ceil == 0 {
        quantum(rate_bps)
    } else {
        quantum(bounded_ceil)
    }
}
