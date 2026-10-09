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
    GSO_ADMIT_FLOOR, epoch_refill, flow_allowance, flow_is_sparse, flow_leaf_budget, flow_take,
    quantum, share_epoch_ns,
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
}

#[test]
fn the_dense_take_never_drains_the_leaf_whole() {
    // THE SOURCE BUFFER LAW (the live battery's catch, pinned as a
    // law): a dense take's availability cap is HALF the leaf — the
    // leaf bucket was designed to ride high (packet-sized spends,
    // quantum-sized draws), and a whole-leaf take broke exactly
    // that: the live battery measured 1411 packets dropped under a
    // NON-BINDING 12 GB/s policy (zero before the lane) and the
    // 100kb trickle row sagged to 64.8%, both under the whole-leaf
    // form. The half-split keeps the pool's micro-credit oscillation
    // away from every admit decision.
    let allowance = 250_000u64; // an engaged lane
    let rich_leaf = 10_000_000u64;
    // A rich leaf: the room/quantum binds long before the buffer.
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 2, allowance, u64::MAX, rich_leaf),
        7_000
    );
    // Above two packets' worth: the take is HALF its content — the
    // leaf keeps an admit buffer of at least one packet.
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 2, allowance, u64::MAX, 900),
        450
    );
    // Below two packets' worth the buffer law stands down — the
    // take is whole and the admit deterministic (the old lane's own
    // property: the take covers the packet whenever the leaf does).
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 2, allowance, u64::MAX, 64),
        64
    );
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 2, allowance, u64::MAX, 399),
        399
    );
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 2, allowance, u64::MAX, 400),
        200
    );
    // The OFF lane's fraction sits at or under the half for
    // learned >= 1, and its packet floor (below) lifts it above
    // under-sizing: the fraction is the binding bound on this
    // shape (learned 0, leaf/2 vs leaf/2 — the floor lifts the
    // 200-byte case to itself, the fraction stays the take).
    assert_eq!(
        flow_take(false, SPARSE_PKT, 7_000, 0, u64::MAX, u64::MAX, 900),
        450
    );
    // THE PACKET FLOOR (the lane's fourth lesson), carrying the
    // LONE/COLD shape only (learned < 2): the lone bulk flow's
    // fraction under-sized takes at low binding rates and the
    // drop-with-bank cycle collapsed TCP to 37% of a policy it
    // should have ridden (the third battery run's measurement, at
    // 2 MB/s where leaf/3 sits at the packet's own order). A
    // decayed-peak TRANSIENT (learned >= 2) keeps the fraction —
    // the trickle regime measured the unconditional floor lifting
    // transient takes to the full quantum, four epochs of allowance
    // per draw.
    assert_eq!(
        flow_take(false, 65_536, 200_000, 1, u64::MAX, u64::MAX, 90_000),
        65_536
    );
    assert_eq!(
        flow_take(false, 65_536, 200_000, 0, u64::MAX, u64::MAX, 90_000),
        65_536
    );
    // The transient (learned 2, peak decayed): the fraction binds.
    assert_eq!(
        flow_take(false, 65_536, 200_000, 2, u64::MAX, u64::MAX, 90_000),
        90_000 / 4
    );
    // The floor is bounded by the leaf: a leaf below the packet
    // gives what it holds (the cascade's own shape).
    assert_eq!(
        flow_take(false, 65_536, 200_000, 1, u64::MAX, u64::MAX, 40_000),
        40_000
    );
    // The floor never exceeds the lane law: a sparse demand is its
    // own floor (200 bytes), and the fraction still binds whenever
    // it sits above the packet.
    assert_eq!(
        flow_take(true, 200, 200_000, 2, u64::MAX, u64::MAX, 90_000),
        200
    );
    assert_eq!(
        flow_take(false, 65_536, 200_000, 1, u64::MAX, u64::MAX, 300_000),
        100_000
    );
    // A sparse take keeps the whole-leaf right: 200 bytes may take
    // the leaf's last 200 (the demand IS the packet; the bulk
    // sibling's cascade refills behind it).
    assert_eq!(
        flow_take(true, SPARSE_PKT, 7_000, 2, allowance, u64::MAX, 200),
        200
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
    // The ENGAGED lane's reachability contract, in the buffer law's
    // honest form: the SPARSE take always covers its packet (it IS
    // the packet); the DENSE take covers it whenever the leaf holds
    // TWICE the packet — the buffer law's price, stated — and banks
    // toward it across draws below that (the flow bucket accumulates
    // halves exactly the way the leaf itself always banked toward
    // the GSO floor at trickle rates). The GSO admit floor keeps the
    // quantum at or above every packet the hook ever sees, so the
    // dense lane's lane-law never binds below the packet it serves.
    for rate in [TRICKLE_RATE, ORDINARY_RATE, 50_000_000] {
        let q = quantum(rate);
        let pkt = GSO_ADMIT_FLOOR as u32;
        let room = pkt as u64 + 1;
        // The sparse lane: the packet itself, from a leaf that
        // barely covers it.
        assert!(
            flow_take(true, pkt, q, 2, 250_000, room, pkt as u64 + 1) >= pkt as u64,
            "sparse admit reachability at rate {rate}"
        );
        // The dense lane: twice the packet covers it in one take.
        assert!(
            flow_take(false, pkt, q, 2, 250_000, room, pkt as u64 * 2) >= pkt as u64,
            "dense admit reachability at rate {rate}"
        );
        // Below twice: the take is WHOLE and the admit deterministic —
        // the old single-bucket lane's own property (a take at
        // pkt + 2 covers the packet it serves).
        let whole = flow_take(false, pkt, q, 2, 250_000, u64::MAX, pkt as u64 + 2);
        assert!(
            whole >= pkt as u64,
            "the deterministic admit below the buffer threshold at rate {rate}: {whole}"
        );
    }
    // The trickle regime's floor: at 640 KB/s the quantum IS the
    // GSO admit floor — the smallest quantum the law ever produces
    // still admits the largest packet the hook ever hands, from a
    // leaf holding twice it.
    assert_eq!(quantum(TRICKLE_RATE), GSO_ADMIT_FLOOR);
    assert_eq!(
        flow_take(
            false,
            GSO_ADMIT_FLOOR as u32,
            quantum(TRICKLE_RATE),
            2,
            250_000,
            u64::MAX,
            GSO_ADMIT_FLOOR * 2
        ),
        GSO_ADMIT_FLOOR
    );
}
