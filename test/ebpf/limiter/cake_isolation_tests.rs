// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! schema v20, CAKE-shaped flow isolation: the kernel-shaped
//! isolation battery — the feedback simulation that reproduces the
//! intra-leaf find rootlessly (the shared leaf bucket starves the
//! quiet flow THROUGH the very epoch ledger that protects the leaf),
//! then the flow lane that closes it.
//!
//! THE MODEL, stated honestly (the drr_ledger_tests posture, one
//! level deeper): the leaf-level machinery runs VERBATIM — the pool
//! micro-credits per packet, the leaf draws under the real v17 laws
//! (the learned count, the drawee peak, the carry-formed epoch
//! ledger) — and the flows under it are offer-driven TCP feedback
//! (an admit grows the window toward the 200us base; a starved flow
//! backs off exponentially, capped at 400ms). The sparse flow is the
//! honest exception: a DNS-shaped query offers one 200-byte packet
//! per 100ms at a fixed cadence — its starve shape is drops, not
//! backoff, so the sim counts offers and admits directly.
//!
//! THE FIND the sim reproduces (the honest verdict the sim itself
//! delivered first): the sketched starvation of the quiet flow does
//! NOT reproduce — the leaf's GRO-granularity banking always strands
//! leftovers, and a 200-byte query rides them in BOTH lanes. The
//! race's real victims are the weaker DEMANDERS: under the shared
//! leaf a second download measured 524 KB of its 1.5 MB fair share
//! (2.9:1 against the first), and the three-flow shape breaks the
//! battery's own anti-monopoly bound — the monopoly the pool arc
//! closed at the leaf, alive inside it. The quiet flow's protection
//! rides the same law that closes it: its admits never regress under
//! the lane, and its demand-sized takes strand nothing (taken ==
//! got, measured).
//!
//! THE CLOSE: the flow lane splits the leaf's budget by flow — the
//! bulk flow's draws cap at its own allowance, the leaf's room
//! outlasts the epoch, and the quiet flow's demand-sized takes admit
//! on the first offer. The honest tradeoff, pinned: the leaf's
//! under-demanded share stays RESERVED (the sibling leaf cannot farm
//! it without breaking the anti-monopoly bound), so the aggregate
//! rides the same 65%-130% band the leaf ledger's battery set —
//! protection bought at the cost of the monopoly's false
//! efficiency, the coarse-fairness-beats-starvation tradeoff one
//! level deeper.

use super::ebpf_drr::{
    draw_admitted, epoch_allowance, flow_allowance, flow_is_sparse, flow_leaf_budget, flow_take,
    ledger_note, ledger_room, pool_share_last, pool_share_note, pool_share_peak, quantum,
    share_epoch_ns, take_size,
};
// The math copy rides drr_tests' parent inclusion (the duplicate-mod
// law), reached through the limiter mod where math_tests lives.
use super::super::math_tests::ebpf_math::{Bucket, draw_stamp_take, tokens_fetch_add, tokens_read};

/// The sim's GRO super-packet (the hook's view — the admit floor).
const PKT: u64 = 65_536;
/// The interactive flow's packet (the DNS-ish shape the find starves).
const SPARSE_PKT: u64 = 200;
/// The hot-flow offer cadence (a fully-grown window's spacing).
const BASE_NS: u64 = 200_000;
/// The window ceiling the feedback grows toward.
const MAX_CWND: u64 = 64;
/// The retransmit-timer backoff ceiling (the ledger battery's own
/// calibration — the shape that reproduced the CI fingerprint).
const RTO_STEPS: u32 = 5;
const RTO_CAP_NS: u64 = 400_000_000;
/// The quiet flow's cadence: one query per fair-share epoch.
const SPARSE_GAP_NS: u64 = 100_000_000;
/// The sim's boot offset: the real hook's ktime is past boot (the
/// get_socket_ptr note's own posture), so no packet ever sees epoch
/// 0 — a sim born at t=0 misreads every cold stamp as drew-this-
/// epoch (the epoch-0 artifact the trace exposed) and the count
/// never learns. One second of boot, ten clean epochs.
const BOOT_NS: u64 = 1_000_000_000;

/// One simulated flow: its bucket, its epoch-ledger word, its TCP
/// feedback state, and its admit ledger. The sparse flow rides a
/// fixed cadence (`fixed_gap`) — its packet is not windowed.
struct SimFlow {
    bkt: Bucket,
    got: u64,
    taken: u64,
    offers: u64,
    admits: u64,
    cwnd: u64,
    streak: u64,
    rto: u32,
    next_offer: u64,
    pkt: u64,
    fixed_gap: Option<u64>,
    ledger: u64,
}

impl SimFlow {
    fn bulk(first_offer: u64) -> Self {
        SimFlow {
            bkt: Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            },
            got: 0,
            taken: 0,
            offers: 0,
            admits: 0,
            cwnd: 1,
            streak: 0,
            rto: 0,
            next_offer: first_offer,
            pkt: PKT,
            fixed_gap: None,
            ledger: 0,
        }
    }

    fn sparse(first_offer: u64) -> Self {
        SimFlow {
            bkt: Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            },
            got: 0,
            taken: 0,
            offers: 0,
            admits: 0,
            cwnd: 1,
            streak: 0,
            rto: 0,
            next_offer: first_offer,
            pkt: SPARSE_PKT,
            fixed_gap: Some(SPARSE_GAP_NS),
            ledger: 0,
        }
    }

    /// The offer cadence: the window feedback stretched by backoff,
    /// or the sparse flow's fixed timer.
    fn gap(&self) -> u64 {
        match self.fixed_gap {
            Some(g) => g,
            None => {
                let base = BASE_NS * MAX_CWND / self.cwnd;
                let stretched = base << self.rto.min(RTO_STEPS);
                if stretched < RTO_CAP_NS {
                    stretched
                } else {
                    RTO_CAP_NS
                }
            }
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

/// One simulated leaf: its bucket and its epoch-ledger word.
#[derive(Clone)]
struct SimLeaf {
    bkt: Bucket,
    ledger: u64,
}

/// The shape under test.
pub(super) struct Shape {
    /// false = the v19 shared-bucket lane (the find); true = the
    /// v20 flow lane (the close).
    pub(super) flow_lane: bool,
    pub(super) rate: u64,
    pub(super) secs: u64,
    /// Bulk (GRO + TCP feedback) flows in leaf 0.
    pub(super) bulks: usize,
    /// Whether leaf 0 carries the quiet flow.
    pub(super) sparse: bool,
    /// Single-bulk sibling leaves (engages the leaf-level ledger).
    pub(super) siblings: usize,
}

/// The verdict surface: per-flow admits (leaf 0's flows, then each
/// sibling's), the quiet flow's offer/admit counts, the total.
pub(super) struct Report {
    pub(super) got: Vec<u64>,
    pub(super) offers: u64,
    pub(super) admits: u64,
    pub(super) total: u64,
    pub(super) taken: Vec<u64>,
    #[allow(dead_code)]
    pub(super) flow_share: u64,
    #[allow(dead_code)]
    pub(super) pool_share: u64,
}

/// The kernel-shaped run: one pool at `rate`, leaf 0 carrying the
/// configured flows, `siblings` single-bulk leaves beside it, the
/// leaf-level laws running verbatim under whichever flow path the
/// shape selects.
pub(super) fn run_flow_shape(s: &Shape) -> Report {
    use std::collections::BinaryHeap;
    let q = quantum(s.rate);
    let burst = s.rate.clamp(65_536, 4_194_304).max(65_536);
    let mut pool = Bucket {
        tokens: 0,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let mut pool_stamp: u64 = BOOT_NS;
    let mut pool_share: u64 = 0;
    let mut leaves: Vec<SimLeaf> = vec![
        SimLeaf {
            bkt: Bucket {
                tokens: 0,
                last_refill_ns: 0,
                frac_rem: 0,
            },
            ledger: 0,
        };
        1 + s.siblings
    ];
    let mut flow_shares: Vec<u64> = vec![0; 1 + s.siblings];
    // Leaf 0's flows: the bulks staggered on the base cadence, the
    // quiet flow at the first mid-epoch mark.
    let mut flows: Vec<Vec<SimFlow>> = Vec::with_capacity(1 + s.siblings);
    let mut leaf0: Vec<SimFlow> = (0..s.bulks)
        .map(|i| SimFlow::bulk(BOOT_NS + (i as u64 + 1) * BASE_NS))
        .collect();
    if s.sparse {
        leaf0.push(SimFlow::sparse(BOOT_NS + 50_000_000));
    }
    flows.push(leaf0);
    for i in 0..s.siblings {
        flows.push(vec![SimFlow::bulk(
            BOOT_NS + (i as u64 + 2) * BASE_NS + BASE_NS / 2,
        )]);
    }
    let mut heap: BinaryHeap<std::cmp::Reverse<(u64, usize, usize)>> = flows
        .iter()
        .enumerate()
        .flat_map(|(li, fs)| fs.iter().enumerate().map(move |(fi, f)| (li, fi, f)))
        .map(|(li, fi, f)| std::cmp::Reverse((f.next_offer, li, fi)))
        .collect();
    let total_ns = BOOT_NS + s.secs * 1_000_000_000;
    while let Some(std::cmp::Reverse((now, li, fi))) = heap.pop() {
        if now > total_ns {
            break;
        }
        // The pool credit: this packet owns [stamp, now].
        let dt = now - pool_stamp;
        pool_stamp = now;
        let credit = s.rate.saturating_mul(dt) / 1_000_000_000;
        pool.tokens = (tokens_read(&pool) + credit).min(burst);
        let pkt = flows[li][fi].pkt;
        flows[li][fi].offers += 1;
        let mut admitted = false;
        if !s.flow_lane {
            // THE v19 PATH: the flow spends from the shared leaf
            // bucket directly — the shape the find starves.
            if tokens_read(&leaves[li].bkt) >= pkt {
                let observed = tokens_read(&leaves[li].bkt);
                leaves[li].bkt.tokens = observed - pkt;
                admitted = true;
            } else {
                leaf_draw(&mut pool, &mut pool_share, &mut leaves[li], s.rate, q, now);
                if tokens_read(&leaves[li].bkt) >= pkt {
                    let observed = tokens_read(&leaves[li].bkt);
                    leaves[li].bkt.tokens = observed - pkt;
                    admitted = true;
                }
            }
        } else {
            // THE v20 PATH: the flow spends from its OWN bucket,
            // drawing from the leaf when it empties (the leaf draw
            // cascading ahead of it when the leaf cannot cover the
            // packet).
            if tokens_read(&flows[li][fi].bkt) >= pkt {
                let observed = tokens_read(&flows[li][fi].bkt);
                flows[li][fi].bkt.tokens = observed - pkt;
                admitted = true;
            } else {
                if tokens_read(&leaves[li].bkt) < pkt {
                    leaf_draw(&mut pool, &mut pool_share, &mut leaves[li], s.rate, q, now);
                }
                let leaf = &mut leaves[li];
                if flow_draw(
                    &mut leaf.bkt,
                    &mut leaf.ledger,
                    &mut flow_shares[li],
                    pool_share,
                    &mut flows[li][fi],
                    s.rate,
                    q,
                    now,
                ) && tokens_read(&flows[li][fi].bkt) >= pkt
                {
                    let observed = tokens_read(&flows[li][fi].bkt);
                    flows[li][fi].bkt.tokens = observed - pkt;
                    admitted = true;
                }
            }
        }
        // Booking + feedback.
        let flow = &mut flows[li][fi];
        if admitted {
            flow.got += pkt;
            flow.admits += 1;
            if flow.fixed_gap.is_none() {
                flow.admit_tick();
            }
        } else if flow.fixed_gap.is_none() {
            flow.drop_tick();
        }
        let gap = flow.gap();
        flow.next_offer = now + gap;
        heap.push(std::cmp::Reverse((flow.next_offer, li, fi)));
    }
    let mut got: Vec<u64> = flows
        .iter()
        .flat_map(|fs| fs.iter().map(|f| f.got))
        .collect();
    let taken: Vec<u64> = flows
        .iter()
        .flat_map(|fs| fs.iter().map(|f| f.taken))
        .collect();
    let (offers, admits) = match flows.first().and_then(|fs| fs.last()) {
        Some(f) if f.fixed_gap.is_some() => (f.offers, f.admits),
        _ => (0, 0),
    };
    let total: u64 = got.iter().sum();
    let _ = &mut got; // (kept a mutable binding for future battery rows)
    Report {
        got,
        taken,
        offers,
        admits,
        total,
        flow_share: flow_shares[0],
        pool_share,
    }
}

/// The leaf draw, VERBATIM from the ledger battery's runner (the
/// real v17 laws: the note with the pre-CAS epoch evidence, the
/// drawee-peak allowance, the carry-formed room, the take under
/// take_size, the failed-draw rollback).
fn leaf_draw(
    pool: &mut Bucket,
    pool_share: &mut u64,
    leaf: &mut SimLeaf,
    rate: u64,
    q: u64,
    now: u64,
) {
    let stamp = leaf.bkt.last_refill_ns;
    if !draw_admitted(now, stamp) {
        return;
    }
    if !draw_stamp_take(&mut leaf.bkt, stamp, now) {
        return;
    }
    let now_epoch = (now / share_epoch_ns()) as u32;
    let leaf_prev_epoch = (stamp / share_epoch_ns()) as u32;
    *pool_share = pool_share_note(*pool_share, now_epoch, leaf_prev_epoch == now_epoch);
    let learned = pool_share_last(*pool_share);
    let drawees = pool_share_peak(*pool_share);
    let allowance = epoch_allowance(rate, drawees);
    // The ledger-off lane (a lone drawer, a cold pool): the room is
    // unlimited and the word is never touched — the datapath
    // wrapper's own short-circuit, mirrored (the pure core's MAX
    // precondition).
    let room = if allowance == u64::MAX {
        u64::MAX
    } else {
        ledger_room(leaf.ledger, now_epoch, allowance, q)
    };
    let take = take_size(q, tokens_read(pool), learned, allowance, room);
    if take > 0 && tokens_read(pool) >= take {
        pool.tokens = tokens_read(pool) - take;
        let _ = tokens_fetch_add(&mut leaf.bkt, take);
        if allowance != u64::MAX {
            leaf.ledger = ledger_note(leaf.ledger, now_epoch, allowance, q, take);
        }
    } else {
        let epoch_start = now_epoch as u64 * share_epoch_ns();
        let _ = draw_stamp_take(&mut leaf.bkt, now, epoch_start);
    }
}

/// The flow draw (the v20 lane): stamp admission with the sparse
/// test on the PRE-CAS stamp, the flow-share note, the allowance
/// cascade (the leaf's drawee peak from the pool word, the flow peak
/// from the leaf's word), the carry-formed room, the demand-or-
/// quantum take, and the move leaf -> flow.
#[allow(clippy::too_many_arguments)]
fn flow_draw(
    leaf_bkt: &mut Bucket,
    leaf_ledger: &mut u64,
    flow_share: &mut u64,
    pool_share: u64,
    flow: &mut SimFlow,
    rate: u64,
    q: u64,
    now: u64,
) -> bool {
    let _ = leaf_ledger; // (the leaf's word is spent inside leaf_draw only)
    let stamp = flow.bkt.last_refill_ns;
    if !draw_admitted(now, stamp) {
        return false;
    }
    let sparse = flow_is_sparse(stamp, now);
    if !draw_stamp_take(&mut flow.bkt, stamp, now) {
        return false;
    }
    let now_epoch = (now / share_epoch_ns()) as u32;
    let noted = pool_share_note(*flow_share, now_epoch, !sparse);
    *flow_share = noted;
    let learned = pool_share_last(noted);
    let flow_peak = pool_share_peak(noted);
    let leaf_peak = pool_share_peak(pool_share);
    let leaf_budget = flow_leaf_budget(rate, leaf_peak);
    let allowance = flow_allowance(leaf_budget, flow_peak);
    // The same MAX short-circuit one level down: a lone flow's room
    // is unlimited and its ledger word is never touched.
    let room = if allowance == u64::MAX {
        u64::MAX
    } else {
        ledger_room(flow.ledger, now_epoch, allowance, q)
    };
    let leaf_tokens = tokens_read(leaf_bkt);
    let take = flow_take(
        sparse,
        flow.pkt as u32,
        q,
        learned,
        allowance,
        room,
        leaf_tokens,
    );
    if take > 0 && leaf_tokens >= take {
        leaf_bkt.tokens = leaf_tokens - take;
        flow.taken += take;
        let _ = tokens_fetch_add(&mut flow.bkt, take);
        if allowance != u64::MAX {
            flow.ledger = ledger_note(flow.ledger, now_epoch, allowance, q, take);
        }
        true
    } else {
        let epoch_start = now_epoch as u64 * share_epoch_ns();
        let _ = draw_stamp_take(&mut flow.bkt, now, epoch_start);
        false
    }
}

// The battery's pin set, split from this file at the LOC cap (the
// drr_tests child-wiring precedent): the runner above stays with
// the machinery it exercises, the pins ride the same single core
// copy through this module's parent.
#[path = "cake_battery_tests.rs"]
mod cake_battery_tests;
