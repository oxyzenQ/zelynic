// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// NIGHT-improve-44: the epoch ledger (repair-3/4, v17) moved out
// of drr.rs at the 600-line cap — a nested #[path] module whose
// items re-export through drr, so every consumer (the bin root,
// the rootless test tree) keeps resolving drr::ledger_*.
//
// ── The epoch ledger (repair-3/4, v17) ────────────────────────────────
//
// THE FIND, live on every CI leg (the improve-1b battery's red era):
// the learned-share cap above bounds each DRAW's take — but a leaf's
// draw frequency is its packet rate, and that rate is TCP feedback.
// The flow that admits grows its window and offers more packets
// (every one a draw); the starved flows back off to retransmit
// timers. The battery's measured shape at 6 leaves / 1mb / 4s: the
// worst leaf read 4.7x its fair share while the quietest measured
// ONE admit (65536 + 78 B over the whole window) — the pool's credit
// stream went to the only drawer still fast enough to ask. Three
// compounding defects, each reproduced by the feedback simulation
// in drr_ledger_tests.rs before the law that closed it was written:
//
//  1. the share-state NOTE raced: a plain read plus a BPF_ANY insert
//     means concurrent notes clobber each other's increments, the
//     learned count converged to 1-3, and the cap weakened back to
//     the v13 residue shape (the sim with a racy count reproduces the
//     quietest leaf's single admit exactly);
//  2. even with a PERFECT count, a per-take cap cannot bound a
//     per-EPOCH share: one drawer drawing on every packet drains the
//     pool through (K+2)-sized bites — the geometric decay the residue
//     law owned at take granularity, back at stream granularity;
//  3. an allowance split across the ASKERS inflates for the
//     survivors the moment the starved go quiet (the asker count IS
//     the silence): the many24 leg read worst 4.7x fair with the
//     count at ~6 of 24 — the peak field above is this close.
//
// THE LAW (the epoch ledger, the carry form): each leaf banks an
// ALLOWANCE of the pool's per-epoch refill split across the drawee
// peak — earned at `epoch_refill / drawees` per 100ms epoch, held as
// a CARRY in one packed u64 per leaf (the drr_leaf_state maps, the
// leaf_bucket posture), spent only by draws, and capped at one
// QUANTUM of unspent credit:
//
//   bits 32..63 : epoch  — the epoch the carry was last credited at
//   bits  0..31 : carry  — the banked, unspent allowance (bytes)
//
// The quantum cap is the v13 doc's own stockpile sentence made real
// ("a leaf may hold at most one quantum at a time"): a starved leaf
// banks several epochs' allowance for ONE fat admit — the 64 KiB GSO
// admit floor demands it, its TCP heals on the admit, its cadence
// recovers, and the aggregate floor (the battery's 65% band, which
// the blocking form of this ledger sagged under) comes back with
// it. The worst leaf's windowed total stays inside the battery's
// 1.75x-fair-plus-one-quantum bound by construction: the earn rate
// IS the fair split, and the stockpile IS the quantum. The lone
// drawer keeps the whole budget (drawees < 2 leaves the ledger OFF
// — the single-active row's own lo bound); a state-map miss or a
// cold pool fails open onto the v16 law exactly as dinner-28 did.

/// The pool's refill over one fair-share epoch (pure): the rate's
/// 100ms share — the budget the epoch ledger splits. The quantum's
/// share term before the GSO floor applies (quantum floors at the
/// admit packet size; the refill never does).
use super::DRR_WINDOW_MS;
#[inline(always)]
pub const fn epoch_refill(rate_bps: u64) -> u64 {
    rate_bps / (1000 / DRR_WINDOW_MS)
}

/// The epoch ledger's earn rate (the v17 law, pure): the pool's
/// per-epoch refill split across the drawee count — the PEAK (the
/// decaying high-water), never the momentary asker count, so the
/// allowance does not inflate when starved siblings go quiet. A
/// drawee count of 0 or 1 keeps the ledger OFF — a cold pool or a
/// missed state lookup fails open onto the v16 law (never throttles
/// a packet the laws below permit), and a lone leaf must see the
/// whole budget: the battery's single-active row measures >= 80% of
/// policy, and an allowance of refill/1 never binds a leaf whose
/// takes are already pool-fraction bounded.
#[inline(always)]
pub const fn epoch_allowance(rate_bps: u64, drawees: u16) -> u64 {
    if drawees < 2 {
        return u64::MAX;
    }
    epoch_refill(rate_bps) / drawees as u64
}

/// Pack the leaf-ledger word (epoch high, carry low).
#[inline(always)]
pub const fn ledger_pack(epoch: u32, carry: u32) -> u64 {
    ((epoch as u64) << 32) | carry as u64
}

/// Unpack the ledger word's epoch (bits 32..63): the epoch the
/// carry was last credited at.
#[inline(always)]
pub const fn ledger_epoch(word: u64) -> u32 {
    (word >> 32) as u32
}

/// Unpack the ledger word's banked carry (bits 0..31): the leaf's
/// unspent allowance, already capped at the quantum by the credit.
#[inline(always)]
pub const fn ledger_carry(word: u64) -> u32 {
    (word & 0xFFFF_FFFF) as u32
}

/// The elapsed-epoch ceiling for the carry's earning step: beyond it
/// the product below could only come from the u32 epoch wrap (13.7
/// years of 100ms epochs), and the credit saturates at the full
/// stockpile cap instead — one epoch's worth of coarseness per
/// decade, in the safe direction. The value keeps the plain multiply
/// overflow-free by construction (see ledger_room).
pub const ELAPSED_CEILING: u32 = 1 << 24;

/// The carry's earning step (pure): credit the epochs elapsed since
/// the word's epoch at the allowance, capped at the stockpile cap
/// (the quantum — the v13 stockpile bound). The multiply is PLAIN,
/// overflow-safe by construction the math.rs fill_ns way: bounds,
/// not libcall checks — saturating_mul lowers to the 128-bit
/// __multi3 libcall, which the BPF ISA does not carry and the aya
/// loader refuses to relocate (the repair-4 CI find: "function
/// 0x2190 not found while relocating enforce_dl", ten dead sites
/// from one inlined call). The bound: the allowance is at most half
/// the 1tb ladder's refill (5e10), 2^24 epochs of it stays two
/// orders under u64's ceiling, and the carry is at most one quantum
/// (1e8) — the sum cannot wrap. The stockpile naming is the
/// fair_draw_size lesson: a short if-else here collapses under the
/// ebpf nightly's single-line cap and expands under stable — these
/// names run past it, both greens.
#[inline(always)]
pub const fn ledger_room(word: u64, now_epoch: u32, allowance: u64, stockpile_cap: u64) -> u64 {
    let elapsed_epochs = now_epoch.wrapping_sub(ledger_epoch(word));
    let earned_stockpile = if elapsed_epochs > ELAPSED_CEILING {
        stockpile_cap
    } else {
        allowance * elapsed_epochs as u64 + ledger_carry(word) as u64
    };
    if earned_stockpile > stockpile_cap {
        stockpile_cap
    } else {
        earned_stockpile
    }
}

/// The carry's credit-then-spend step (pure): the room above minus
/// the take (never below zero — a take larger than the room is a
/// caller bug the saturating form forgives once), re-anchored at
/// the now-epoch. The datapath computes the room, sizes the take
/// inside it, and writes this word through one CAS — the credit and
/// the spend land together or not at all.
#[inline(always)]
pub const fn ledger_note(
    word: u64,
    now_epoch: u32,
    allowance: u64,
    stockpile_cap: u64,
    take: u64,
) -> u64 {
    let room = ledger_room(word, now_epoch, allowance, stockpile_cap);
    let spent = if take > room { room } else { take };
    ledger_pack(now_epoch, (room - spent) as u32)
}
