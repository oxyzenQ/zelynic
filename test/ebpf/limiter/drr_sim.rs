// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The DRR simulation machinery — the kernel-shaped TCP-feedback
//! engine the ledger/guarantee batteries drive, split from
//! drr_ledger_tests.rs when the improve-40 guarantee bracket
//! (schema v24) needed the same engine and the file rode the
//! 500-LOC owner cap at exactly 500 (the policy_write discipline,
//! one family over: the machinery moves, the pins stay home, and
//! every battery that follows reaches it through the sibling path).
//!
//! THE MODEL, stated honestly (the drr_share_tests precedent, one
//! order deeper — the fixed-cadence sim embedded the fairness it
//! claimed to produce, so the kernel's reality stayed unpinned):
//! each leaf's offer cadence is TCP feedback (an admit grows the
//! window toward the 200us base; a starved flow backs off its
//! retransmit timer exponentially, capped at 400ms), the pool is
//! credited per packet (this packet owns [last, now] — the
//! micro-credit stream the kernel produces), the 64 KiB admit floor
//! stands, and the note rides the attempt once per leaf per epoch.
//!
//! improve-40 (schema v24): the engine's allowance step is the
//! GUARANTEE LAW's — `guaranteed_allowance` with the config's
//! bracket, `guaranteed_stockpile` for the banking bound — so a
//! 0/0-bracketed run is the exact pre-v24 engine by construction
//! (the fail-open composition, pinned by the existing ledger
//! battery standing unchanged), and the ceiling's engage-even-lone
//! lane replaces the old `drawees >= 2` gate with the law's own
//! `allowance != u64::MAX` (identical semantics at the 0/0 bracket).

use super::ebpf_drr::{
    draw_size, fair_draw_size, guaranteed_allowance, guaranteed_stockpile, ledger_note,
    ledger_room, pool_share_last, pool_share_note, pool_share_peak, quantum, share_epoch_ns,
};
// The math copy rides drr_tests' parent inclusion (the duplicate-mod
// law), reached through the limiter mod where math_tests lives.
use super::super::math_tests::ebpf_math::{Bucket, draw_stamp_take, tokens_fetch_add, tokens_read};

/// The sim's GRO super-packet (the hook's view — the admit floor).
pub(super) const PKT: u64 = 65_536;
/// The hot-leaf offer cadence (a fully-grown window's spacing).
pub(super) const BASE_NS: u64 = 200_000;
/// The window ceiling the feedback grows toward.
pub(super) const MAX_CWND: u64 = 64;
/// The retransmit-timer backoff ceiling: 32x the cadence, capped at
/// 400ms (the calibration that reproduced the CI fingerprint).
pub(super) const RTO_STEPS: u32 = 5;
pub(super) const RTO_CAP_NS: u64 = 400_000_000;

/// One simulated leaf: bucket, epoch evidence, TCP feedback state,
/// and its packed epoch-ledger word (the pure core's packing).
pub(super) struct SimLeaf {
    pub(super) bkt: Bucket,
    pub(super) noted_epoch: u32,
    pub(super) got: u64,
    pub(super) cwnd: u64,
    pub(super) streak: u64,
    pub(super) rto: u32,
    pub(super) next_offer: u64,
    pub(super) ledger: u64,
}

impl SimLeaf {
    fn new(first_offer: u64) -> Self {
        SimLeaf {
            bkt: Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            },
            noted_epoch: 0,
            got: 0,
            cwnd: 1,
            streak: 0,
            rto: 0,
            next_offer: first_offer,
            ledger: 0,
        }
    }

    /// The offer cadence: the window feedback, stretched by backoff.
    fn gap(&self) -> u64 {
        let base = BASE_NS * MAX_CWND / self.cwnd;
        let stretched = base << self.rto.min(RTO_STEPS);
        if stretched < RTO_CAP_NS {
            stretched
        } else {
            RTO_CAP_NS
        }
    }

    /// A starved offer: streak grows; every fourth drop halves the
    /// window and steps the backoff.
    fn drop_tick(&mut self) {
        self.streak += 1;
        if self.streak.is_multiple_of(4) {
            self.cwnd /= 2;
            if self.cwnd == 0 {
                self.cwnd = 1;
            }
            self.rto += 1;
        }
    }

    /// An admitted packet: the window grows, the timers heal.
    fn admit_tick(&mut self) {
        if self.cwnd < MAX_CWND {
            self.cwnd += 1;
        }
        self.streak = 0;
        self.rto = 0;
    }
}

/// The configuration under test: the take law, the note's honesty
/// (the racy cap), whether the epoch ledger caps the room, whether
/// it carries (repair-4) or blocks (the ablation), and — improve-40,
/// schema v24 — the guarantee bracket the allowance step clamps
/// between (the zero sentinel unset: the exact pre-v24 engine).
pub(super) struct SimConfig {
    pub(super) law: fn(u64, u64, u16) -> u64,
    pub(super) racy_note_cap: Option<u16>,
    pub(super) ledger: bool,
    pub(super) carry: bool,
    /// The per-leaf guaranteed minimum (v24). 0 = unset.
    pub(super) floor_bps: u64,
    /// The per-leaf maximum (v24). 0 = unset.
    pub(super) ceil_bps: u64,
}

/// The v16-law config (ledger off; the racy cap optional).
pub(super) fn v16_cfg(racy: Option<u16>) -> SimConfig {
    SimConfig {
        law: v16_law,
        racy_note_cap: racy,
        ledger: false,
        carry: true,
        floor_bps: 0,
        ceil_bps: 0,
    }
}

/// The v17-law config (the ledger on; the carry or the ablation).
pub(super) fn v17_cfg(carry: bool) -> SimConfig {
    SimConfig {
        law: v17_law,
        racy_note_cap: None,
        ledger: true,
        carry,
        floor_bps: 0,
        ceil_bps: 0,
    }
}

/// The v24 guarantee config (improve-40): the carried ledger under
/// the bracket — the shape the datapath runs for a bracketed row.
pub(super) fn v24_cfg(floor_bps: u64, ceil_bps: u64) -> SimConfig {
    SimConfig {
        law: v17_law,
        racy_note_cap: None,
        ledger: true,
        carry: true,
        floor_bps,
        ceil_bps,
    }
}

/// The v16 law as a take law — also the OFF lane's law under
/// repair-7 (a lone drawer, a cold pool, a miss: the fraction, verbatim).
fn v16_law(q: u64, pool: u64, learned: u16) -> u64 {
    fair_draw_size(q, pool, learned)
}

/// The v17 law under repair-7: the ENGAGED lane's residue law —
/// the sim's room machinery caps it, the datapath's take_size posture
/// (the room owns the epoch split; a catch-up drawer banks its
/// admit floor instead of a starving fraction).
fn v17_law(q: u64, pool: u64, _learned: u16) -> u64 {
    draw_size(q, pool)
}

/// The kernel-shaped run: K leaves, one pool at `rate`, `secs` of
/// feedback-driven offers (the later half staggered in at
/// `stagger_ns`), starting from `initial_share` (the carried-over
/// pool-share word) and returning the per-leaf admits plus the final
/// word.
pub(super) fn run_kernel_shape(
    cfg: &SimConfig,
    rate: u64,
    k: usize,
    secs: u64,
    stagger_ns: u64,
    initial_share: u64,
) -> (Vec<u64>, u64) {
    use std::collections::BinaryHeap;
    let q = quantum(rate);
    let burst = rate.clamp(65_536, 4_194_304).max(65_536);
    let mut pool = Bucket {
        tokens: 0,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let mut pool_stamp: u64 = 0;
    let mut share: u64 = initial_share;
    let half = k / 2;
    let mut leaves: Vec<SimLeaf> = (0..k)
        .map(|i| {
            let stagger = if i >= half { stagger_ns } else { 0 };
            SimLeaf::new((i as u64 + 1) * BASE_NS + stagger)
        })
        .collect();
    let mut heap: BinaryHeap<std::cmp::Reverse<(u64, usize)>> = leaves
        .iter()
        .enumerate()
        .map(|(i, l)| std::cmp::Reverse((l.next_offer, i)))
        .collect();
    let total = secs * 1_000_000_000;
    while let Some(std::cmp::Reverse((now, i))) = heap.pop() {
        if now > total {
            break;
        }
        let leaf = &mut leaves[i];
        // The pool credit: this packet owns [stamp, now].
        let dt = now - pool_stamp;
        pool_stamp = now;
        let credit = rate.saturating_mul(dt) / 1_000_000_000;
        pool.tokens = (tokens_read(&pool) + credit).min(burst);
        // The spend.
        if tokens_read(&leaf.bkt) >= PKT {
            let observed = tokens_read(&leaf.bkt);
            leaf.bkt.tokens = observed - PKT;
            leaf.got += PKT;
            leaf.admit_tick();
        } else {
            // The draw attempt: the note rides it, once per epoch.
            let now_epoch = (now / share_epoch_ns()) as u32;
            let drew_this_epoch = leaf.noted_epoch == now_epoch;
            leaf.noted_epoch = now_epoch;
            share = pool_share_note(share, now_epoch, drew_this_epoch);
            let mut learned = pool_share_last(share);
            if let Some(cap) = cfg.racy_note_cap {
                learned = learned.min(cap);
            }
            let drawees = pool_share_peak(share);
            // The take under the law under test.
            let mut take = (cfg.law)(q, tokens_read(&pool), learned);
            // The ledger's room: the carry form, or the ablation's
            // blocking form — improve-40 (v24): the allowance is the
            // GUARANTEE LAW's (the fair split clamped between the
            // config's floor and ceiling), the stockpile the
            // ceiling's own quantum when one is set, and the
            // engage gate is the law's own `!= u64::MAX` (a set
            // ceiling engages the ledger even on the lone-drawer
            // lane — at the 0/0 bracket this is the exact pre-v24
            // engine, the fail-open composition).
            let mut ledgery = false;
            let mut allowance = 0u64;
            let mut stockpile = q;
            if cfg.ledger {
                allowance = guaranteed_allowance(rate, cfg.floor_bps, cfg.ceil_bps, drawees);
                if allowance != u64::MAX {
                    stockpile = guaranteed_stockpile(rate, cfg.ceil_bps);
                    let room = if cfg.carry {
                        ledger_room(leaf.ledger, now_epoch, allowance, stockpile)
                    } else {
                        allowance
                    };
                    take = take.min(room);
                    ledgery = true;
                }
            }
            if take > 0 && tokens_read(&pool) >= take {
                pool.tokens = tokens_read(&pool) - take;
                let _ = tokens_fetch_add(&mut leaf.bkt, take);
                if ledgery {
                    leaf.ledger = ledger_note(leaf.ledger, now_epoch, allowance, stockpile, take);
                }
                if tokens_read(&leaf.bkt) >= PKT {
                    let observed = tokens_read(&leaf.bkt);
                    leaf.bkt.tokens = observed - PKT;
                    leaf.got += PKT;
                    leaf.admit_tick();
                } else {
                    leaf.drop_tick();
                }
            } else {
                // The failed draw rolls the stamp to the epoch start.
                let last_draw = leaf.bkt.last_refill_ns;
                let _ = draw_stamp_take(&mut leaf.bkt, last_draw, now);
                let epoch_start = now_epoch as u64 * share_epoch_ns();
                let _ = draw_stamp_take(&mut leaf.bkt, now, epoch_start);
                leaf.drop_tick();
            }
        }
        leaf.next_offer = now + leaf.gap();
        heap.push(std::cmp::Reverse((leaf.next_offer, i)));
    }
    (leaves.into_iter().map(|l| l.got).collect(), share)
}

/// The bounds the live battery judges, as one verdict over the admits.
pub(super) struct Verdict {
    pub(super) fair: u64,
    pub(super) worst: u64,
    pub(super) quietest: u64,
    pub(super) total: u64,
}

pub(super) fn verdict_for(gots: &[u64]) -> Verdict {
    let total: u64 = gots.iter().sum();
    Verdict {
        fair: total / gots.len() as u64,
        worst: *gots.iter().max().unwrap(),
        quietest: *gots.iter().min().unwrap(),
        total,
    }
}
