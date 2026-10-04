// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! schema v20, CAKE-shaped flow isolation: the law pins for the
//! flow-level take (the same file the BPF object builds — ebpf/src/
//! drr.rs's v20 section — pinned rootlessly before any kernel saw
//! the wiring). Every pin maps to a documented contract:
//!
//!  * the flow BUDGET cascade — the leaf's own pool share is what
//!    its flows split (a lone leaf earns the whole refill; an
//!    engaged leaf earns the refill across its drawee peak);
//!  * the flow ALLOWANCE — the epoch_allowance law one level down,
//!    MAX lanes and composition (the cascade divides honestly:
//!    refill / leaf-peak / flow-peak);
//!  * the SPARSE TEST — the ledger word's epoch anchor IS the
//!    evidence, zero extra state (a cold flow's boot-window edge
//!    documented, not hidden);
//!  * the FLOW TAKE — sparse draws its packet's own bytes (the
//!    reserved small quantum), dense draws the quantum, both cap
//!    by room and by what the leaf holds, and the take admits the
//!    packet that triggered it whenever room and leaf allow.

// The production quantum core itself (drr_tests' single inclusion
// of ebpf/src/drr.rs, the duplicate-mod law — one copy per test
// binary serves these pins too).
use super::ebpf_drr::{
    epoch_refill, flow_allowance, flow_is_sparse, flow_leaf_budget, flow_take, quantum,
    share_epoch_ns, GSO_ADMIT_FLOOR,
};

/// The interactive flow's packet (the DNS-ish shape the find starves).
const SPARSE_PKT: u32 = 200;
/// A rate whose quantum sits at the GSO floor (the trickle regime,
/// where every take law is tightest): 640 KB/s -> share 64 KiB.
const TRICKLE_RATE: u64 = 640_000;
/// A rate whose quantum rides the window share (the ordinary
/// regime): 1 MB/s -> quantum 100 KiB.
const ORDINARY_RATE: u64 = 1_000_000;

#[test]
fn the_flow_budget_cascade_divides_the_leafs_own_share() {
    // The lone leaf (pool drawees < 2): the WHOLE refill — its
    // whole-budget row, one level down. The flows of a lone leaf
    // are splitting the entire policy stream.
    assert_eq!(
        flow_leaf_budget(ORDINARY_RATE, 0),
        epoch_refill(ORDINARY_RATE)
    );
    assert_eq!(
        flow_leaf_budget(ORDINARY_RATE, 1),
        epoch_refill(ORDINARY_RATE)
    );
    // The engaged leaf: the refill split across its drawee peak —
    // the SAME divisor the leaf's own allowance uses (the flow lane
    // must never invent a second budget the pool never credited).
    assert_eq!(
        flow_leaf_budget(ORDINARY_RATE, 2),
        epoch_refill(ORDINARY_RATE) / 2
    );
    assert_eq!(
        flow_leaf_budget(ORDINARY_RATE, 5),
        epoch_refill(ORDINARY_RATE) / 5
    );
}

#[test]
fn the_flow_allowance_mirrors_the_epoch_allowance_law() {
    // The OFF lanes: a cold leaf's first flows (count 0) and a lone
    // flow (count 1) keep the ledger off — fail-open, and the lone
    // flow must see the leaf's whole content (the single-active
    // row's own lo bound, mirrored one level down).
    let budget = flow_leaf_budget(ORDINARY_RATE, 2);
    assert_eq!(flow_allowance(budget, 0), u64::MAX);
    assert_eq!(flow_allowance(budget, 1), u64::MAX);
    assert_eq!(flow_allowance(u64::MAX, 0), u64::MAX);
    // The engaged lane: the budget split across the flow peak.
    assert_eq!(flow_allowance(budget, 2), budget / 2);
    assert_eq!(flow_allowance(budget, 7), budget / 7);
    // The COMPOSITION, stated as one law: a leaf at peak L under a
    // policy at rate R, with F flows drawing, banks each flow
    // exactly the refill split twice — R/10/L/F — never a budget
    // either level did not earn.
    for (leaves, flows) in [(2u16, 2u16), (4, 2), (2, 5), (24, 3)] {
        let composed = flow_allowance(flow_leaf_budget(ORDINARY_RATE, leaves), flows);
        let expected = epoch_refill(ORDINARY_RATE) / leaves as u64 / flows as u64;
        assert_eq!(
            composed, expected,
            "cascade at leaves={leaves} flows={flows}"
        );
    }
}

#[test]
fn the_sparse_test_reads_the_draw_stamp_epoch() {
    // Two draws inside one epoch: the second reads DENSE — the
    // flow's own frequency classifies it, whatever its ledger state
    // (the stamp is the evidence BECAUSE every draw CASes it,
    // whether the ledger is on or off — a lone ledger-off bulk flow
    // still amortizes its draws on the quantum).
    assert!(!flow_is_sparse(5_000_000, 50_000_000));
    assert!(!flow_is_sparse(0, 99_999_999));
    // A draw in a past epoch: SPARSE — the quiet flow's next draw
    // takes its packet's own bytes.
    assert!(flow_is_sparse(0, 100_000_000));
    assert!(flow_is_sparse(90_000_000, 150_000_000));
    // The boundary itself: the epoch rollover flips the reading
    // at exactly the window the DRR laws already keep time by.
    assert_eq!(share_epoch_ns(), 100_000_000);
    assert!(!flow_is_sparse(99_999_999, 100_000_000 - 1));
    assert!(flow_is_sparse(99_999_999, 100_000_000));
    // The starved-recovery shape: a failed draw rolled the stamp to
    // the epoch start (the retry-every-packet admission), so the
    // retry reads DENSE and rides the fat take its banked carry
    // affords — the repair-4 heal, one level down, by design.
    let epoch_start = 3 * share_epoch_ns();
    assert!(!flow_is_sparse(epoch_start, epoch_start + 50_000_000));
}

#[test]
fn the_sparse_take_is_demand_sized() {
    let q = 1_000_000u64; // an arbitrary rich quantum
    let rich_leaf = 10 * q;
    let allowance = 250_000u64; // an engaged lane
                                // The reserved small quantum: the interactive flow's 200-byte
                                // query draws exactly 200 — never a stockpile it would strand
                                // in a bucket the LRU may age out before it spends.
    assert_eq!(
        flow_take(true, SPARSE_PKT, q, 2, allowance, u64::MAX, rich_leaf),
        200
    );
    // The GSO super-packet as a sparse demand: still demand-sized —
    // the admit floor that sizes the quantum sizes the packet too.
    assert_eq!(
        flow_take(
            true,
            GSO_ADMIT_FLOOR as u32,
            q,
            2,
            allowance,
            u64::MAX,
            rich_leaf
        ),
        GSO_ADMIT_FLOOR
    );
    // Room caps it: a spent-down sparse flow draws within its bank.
    assert_eq!(
        flow_take(true, SPARSE_PKT, q, 2, allowance, 120, rich_leaf),
        120
    );
    // Availability caps it: the conservation edge — the flow lane
    // moves what the leaf holds, never more.
    assert_eq!(
        flow_take(true, SPARSE_PKT, q, 2, allowance, u64::MAX, 50),
        50
    );
    // The OFF lane's lone sparse flow: the fraction never binds a
    // demand smaller than it (leaf/3 of a rich leaf dwarfs 200).
    assert_eq!(
        flow_take(true, SPARSE_PKT, q, 1, u64::MAX, u64::MAX, rich_leaf),
        200
    );
}

#[test]
fn the_dense_take_is_quantum_sized() {
    let rich_leaf = 10_000_000u64;
    let allowance = 250_000u64; // an engaged lane
                                // The bulk cadence amortizes the draw: a dense flow's take is
                                // the quantum, never the packet (a draw per packet would CAS
                                // the share word per packet).
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 2, allowance, u64::MAX, rich_leaf),
        7_000
    );
    // Room caps it: the dense flow's remaining allowance this epoch.
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 2, allowance, 2_500, rich_leaf),
        2_500
    );
    // Availability caps it: the leaf's own content bounds the take.
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 2, allowance, u64::MAX, 900),
        900
    );
}

#[test]
fn the_off_lane_bounds_the_transient_to_a_fraction() {
    // THE SIM'S SECOND CATCH, as a law: the share word's PEAK decays
    // a step every eight quiet epochs, and for the epochs between
    // the decay and the re-ratchet the allowance reads MAX — the
    // OFF lane's take must still be the learned-share FRACTION of
    // the leaf, never the whole leaf. Without this bound a bulk
    // flow rides the transient to one full leaf-drain per decay
    // epoch (the isolation leaking its own divisor's decay).
    let leaf = 90_000u64;
    let q = 1_000_000u64;
    // learned 2 (the word's last completed epoch counted both
    // flows): the transient take is leaf/4 — bounded.
    assert_eq!(
        flow_take(false, SPARSE_PKT, q, 2, u64::MAX, u64::MAX, leaf),
        90_000 / 4
    );
    // The sparse transient rides its OWN demand as the tighter
    // bound: 200 bytes is smaller than the fraction, the
    // demand-sized take even more conservative than the law needs.
    assert_eq!(
        flow_take(true, SPARSE_PKT, q, 2, u64::MAX, u64::MAX, leaf),
        200
    );
    // The LONE flow keeps its throughput: the fraction paces its
    // draws (leaf/3 steps, one latency apart) but never throttles —
    // the v13/v16 lone-drawer row, verbatim one level down. The
    // quantum binds when it is the smaller of the two; the fraction
    // binds when the leaf is the poorer (a cold word's leaf/2).
    let small_leaf = 30_000u64;
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 1, u64::MAX, u64::MAX, small_leaf),
        7_000
    );
    let poorer_leaf = 10_000u64;
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 0, u64::MAX, u64::MAX, poorer_leaf),
        poorer_leaf / 2
    );
}

#[test]
fn the_take_admits_its_packet_whenever_room_and_leaf_allow() {
    // The ENGAGED lane's reachability contract: whenever the room
    // covers the packet and the leaf holds it, the take covers the
    // packet — the GSO admit floor keeps the quantum at or above
    // every packet the hook ever sees, so the dense lane admits by
    // construction and the sparse lane IS the packet. (The OFF lane
    // paces the lone drawer in fraction steps instead — the v13
    // residue law's own posture, re-drawn leaf -> flow.)
    for rate in [TRICKLE_RATE, ORDINARY_RATE, 50_000_000] {
        let q = quantum(rate);
        let pkt = GSO_ADMIT_FLOOR as u32;
        let room = pkt as u64 + 1;
        let leaf = pkt as u64 + 1;
        assert!(
            flow_take(true, pkt, q, 2, 250_000, room, leaf) >= pkt as u64,
            "sparse admit reachability at rate {rate}"
        );
        assert!(
            flow_take(false, pkt, q, 2, 250_000, room, leaf) >= pkt as u64,
            "dense admit reachability at rate {rate}"
        );
    }
    // The trickle regime's floor: at 640 KB/s the quantum IS the
    // GSO admit floor — the smallest quantum the law ever produces
    // still admits the largest packet the hook ever hands.
    assert_eq!(quantum(TRICKLE_RATE), GSO_ADMIT_FLOOR);
    assert_eq!(
        flow_take(
            false,
            GSO_ADMIT_FLOOR as u32,
            quantum(TRICKLE_RATE),
            2,
            250_000,
            u64::MAX,
            GSO_ADMIT_FLOOR
        ),
        GSO_ADMIT_FLOOR
    );
}
