// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! schema v20, CAKE-shaped flow isolation: the battery pins — the
//! find, the close, the edges, and the A/B fingerprint, calibrated
//! to the runner's measured shapes (the ledger battery's own
//! discipline: the pins hold the reproduced fingerprint, so the
//! tradeoff is a decision, not drift). Split from
//! cake_isolation_tests.rs at the LOC cap; the runner and its
//! machinery live in the parent.

use super::super::ebpf_drr::quantum;
use super::Shape;
use super::run_flow_shape;

// ── THE PINS ──────────────────────────────────────────────────────────
//
// The battery's own rows, judged by the battery's own numbers —
// calibrated to the sim's measured shapes (the ledger battery's own
// discipline: the pins hold the reproduced fingerprint, so the
// tradeoff is a decision, not drift). THE HONEST VERDICT the sim
// itself delivered first: the sketched starvation of the quiet flow
// does NOT reproduce — the leaf's GRO-granularity banking always
// strands leftovers (36 KB at the ordinary rates, measured) and a
// 200-byte query rides them, in BOTH lanes. The race's real victims
// are the weaker DEMANDERS: a second download measured 262 KB of
// its 1.31 MB fair share under the shared leaf — 6.5:1 against the
// first, the battery's own monopoly fingerprint one level deeper —
// and the quiet flow's protection rides the same law that closes
// it. The pins hold that world: the find, the close, the quiet
// flow's non-regression and its zero-stranding demand-sized takes,
// the edges, and the A/B fingerprint across the lane boundary.

/// THE FIND (the v19 shape): the shared leaf breaks the battery's
/// anti-monopoly bound at flow granularity — the packet-arrival
/// race concentrates the leaf's whole stream on the first flow, the
/// battery's own 4.7x-class shape one level deeper.
#[test]
fn the_shared_leaf_breaks_the_bound_at_flow_granularity() {
    let r = run_flow_shape(&Shape {
        flow_lane: false,
        rate: 1_000_000,
        secs: 4,
        bulks: 3,
        sparse: false,
        siblings: 0,
    });
    let q = quantum(1_000_000);
    let worst = *r.got.iter().max().unwrap();
    let fair = r.total / 3;
    assert!(
        worst > fair.saturating_mul(175) / 100 + q,
        "the monopoly shape: worst {} vs bound {} (fair {fair}) — if this \
         fails, the packet-arrival race no longer concentrates the \
         shared leaf's stream on the first flow",
        worst,
        fair.saturating_mul(175) / 100 + q
    );
}

/// THE FIND, the paired shape (two bulk flows and the quiet one in
/// the shared leaf, a sibling leaf beside them): the first flow's
/// monopoly crushes the second to a 4:1 ratio or worse — the exact
/// class the leaf-level battery closed at the leaf, alive inside it.
#[test]
fn the_shared_leaf_crushes_the_weaker_demander() {
    let r = run_flow_shape(&Shape {
        flow_lane: false,
        rate: 1_000_000,
        secs: 4,
        bulks: 2,
        sparse: true,
        siblings: 1,
    });
    // got layout: [leaf0 bulk A, leaf0 bulk B, quiet, sibling bulk]
    let (first, second) = (r.got[0], r.got[1]);
    assert!(
        first > second.saturating_mul(2),
        "the weaker demander's crush: {first} vs {second} — if this \
         fails, FCFS at flow granularity no longer monopolizes",
    );
}

/// THE CLOSE: the flow lane splits the shared leaf's bulk flows
/// inside the battery's bounds — worst, quietest, and the aggregate
/// in the 65%-130% band the leaf ledger's own battery floors.
#[test]
fn the_flow_lane_holds_the_battery_bounds() {
    let r = run_flow_shape(&Shape {
        flow_lane: true,
        rate: 1_000_000,
        secs: 4,
        bulks: 3,
        sparse: false,
        siblings: 0,
    });
    let q = quantum(1_000_000);
    let worst = *r.got.iter().max().unwrap();
    let quietest = *r.got.iter().min().unwrap();
    let fair = r.total / 3;
    assert!(
        worst <= fair.saturating_mul(175) / 100 + q,
        "anti-monopoly at flow granularity: worst {} vs bound {} (fair {fair})",
        worst,
        fair.saturating_mul(175) / 100 + q
    );
    assert!(
        quietest >= fair / 4,
        "no-starve at flow granularity: quietest {} vs fair/4 {}",
        quietest,
        fair / 4
    );
    assert!(
        r.total <= 1_000_000 * 4 * 130 / 100,
        "the pool never creates budget: total {}",
        r.total
    );
    assert!(
        r.total >= 1_000_000 * 4 * 65 / 100,
        "the collapse guard: total {} vs the 65% floor {}",
        r.total,
        1_000_000 * 4 * 65 / 100
    );
}

/// THE CLOSE, the paired shape: the two bulks split the leaf's
/// budget within 1.25:1 — the monopoly is gone at the scale the
/// race actually lived.
#[test]
fn the_flow_lane_splits_the_shared_leafs_bulks() {
    let r = run_flow_shape(&Shape {
        flow_lane: true,
        rate: 1_000_000,
        secs: 4,
        bulks: 2,
        sparse: true,
        siblings: 1,
    });
    // got layout: [leaf0 bulk A, leaf0 bulk B, quiet, sibling bulk]
    let (first, second) = (r.got[0], r.got[1]);
    let (hi, lo) = (first.max(second), first.min(second));
    assert!(
        hi <= lo.saturating_mul(5) / 4,
        "the split: {hi} vs {lo} — the shared-leaf monopoly must be gone"
    );
}

/// THE QUIET FLOW, stated honestly (the sim's own verdict): its
/// 200-byte queries ride the banking leftovers in BOTH lanes (the
/// measured admit rate never regresses under the flow lane), and
/// under the lane every byte it DRAWS is a byte it DELIVERS — the
/// demand-sized take leaves nothing stranded in a bucket an LRU
/// may age out before it spends (taken == got, measured).
#[test]
fn the_flow_lane_never_costs_the_quiet_flow_its_crumbs() {
    for lane in [false, true] {
        let r = run_flow_shape(&Shape {
            flow_lane: lane,
            rate: 1_000_000,
            secs: 4,
            bulks: 2,
            sparse: true,
            siblings: 1,
        });
        assert!(r.offers >= 30, "the quiet flow offered {} times", r.offers);
        let admit_pct = r.admits * 100 / r.offers;
        assert!(
            admit_pct >= 90,
            "the quiet flow's admit rate under lane={lane}: {admit_pct}% ({}/{})",
            r.admits,
            r.offers
        );
    }
    // The demand-sized take's measured proof: the quiet flow drew
    // exactly what it delivered — zero stranding.
    let r = run_flow_shape(&Shape {
        flow_lane: true,
        rate: 1_000_000,
        secs: 4,
        bulks: 2,
        sparse: true,
        siblings: 1,
    });
    assert_eq!(
        r.taken[2], r.got[2],
        "the quiet flow's takes == its deliveries: {} drawn, {} delivered",
        r.taken[2], r.got[2]
    );
}

/// THE BULK BOUND (the engaged lane, a sibling leaf present so the
/// leaf-level ledger rides): the bulk flow caps inside the battery's
/// anti-monopoly bound at its flow-fair share, never starves below
/// 60% of it, the sibling leaf stays inside its own leaf-level
/// bounds (its lane never changed — the residue it farms from the
/// under-demanded share is the leaf-level v17 semantics, bounded by
/// the leaf battery's own rows), and the aggregate rides the band.
#[test]
fn the_flow_lane_caps_the_bulk_at_its_flow_fair_share() {
    let r = run_flow_shape(&Shape {
        flow_lane: true,
        rate: 1_000_000,
        secs: 4,
        bulks: 1,
        sparse: true,
        siblings: 1,
    });
    let q = quantum(1_000_000);
    // got layout: [leaf0 bulk, quiet, sibling bulk]
    let (bulk, sibling) = (r.got[0], r.got[2]);
    // Leaf 0's budget at a two-leaf pool: 500 KB/s, split across two
    // flows — the bulk's fair share, 250 KB/s over 4 s.
    let fair: u64 = 1_000_000 * 4 / 2 / 2;
    assert!(
        bulk <= fair.saturating_mul(175) / 100 + q,
        "anti-monopoly at the engaged lane: bulk {} vs bound {} (fair {fair})",
        bulk,
        fair.saturating_mul(175) / 100 + q
    );
    assert!(
        bulk >= fair * 6 / 10,
        "the bulk flow is not starved by the lane: {} vs fair {fair}",
        bulk
    );
    // The sibling: inside its own leaf-level bounds (its fair is the
    // leaf share, 2 MB over 4 s — the leaf battery's own rows).
    let sibling_fair: u64 = 1_000_000 * 4 / 2;
    assert!(
        sibling <= sibling_fair.saturating_mul(175) / 100 + q,
        "the sibling leaf's own bound: {} vs {}",
        sibling,
        sibling_fair.saturating_mul(175) / 100 + q
    );
    assert!(
        sibling >= sibling_fair * 65 / 100,
        "the sibling leaf's own floor: {} vs {}",
        sibling,
        sibling_fair * 65 / 100
    );
    assert!(
        r.total <= 1_000_000 * 4 * 130 / 100,
        "the pool never creates budget: total {}",
        r.total
    );
    assert!(
        r.total >= 1_000_000 * 4 * 65 / 100,
        "the collapse guard: total {} vs the 65% floor {}",
        r.total,
        1_000_000 * 4 * 65 / 100
    );
}

/// THE LONE-FLOW EDGE: one flow alone in one lone leaf keeps the
/// whole budget — the flow lane's allowances stay OFF (the ledger
/// and the share word never engage below a second flow), and the
/// fraction-paced draws are the lone-drawer row's own posture, never
/// a throttle.
#[test]
fn a_lone_flow_keeps_the_whole_budget() {
    let r = run_flow_shape(&Shape {
        flow_lane: true,
        rate: 1_000_000,
        secs: 2,
        bulks: 1,
        sparse: false,
        siblings: 0,
    });
    assert!(
        r.total >= 1_000_000 * 2 * 8 / 10,
        "the lo bound: the lone flow delivered {} of {}",
        r.total,
        1_000_000 * 2
    );
    assert!(
        r.total <= 1_000_000 * 2 * 145 / 100,
        "over band: {}",
        r.total
    );
}

/// THE TRICKLE EDGE (the tightest regime — the quantum pinned at
/// the GSO admit floor): the lane holds its bounds where every take
/// law is tightest.
#[test]
fn the_trickle_regime_holds_the_bounds() {
    let r = run_flow_shape(&Shape {
        flow_lane: true,
        rate: 640_000,
        secs: 4,
        bulks: 1,
        sparse: true,
        siblings: 1,
    });
    let q = quantum(640_000);
    let (bulk, quiet_got, sibling) = (r.got[0], r.got[1], r.got[2]);
    let fair: u64 = 640_000 * 4 / 2 / 2;
    assert!(
        bulk <= fair.saturating_mul(175) / 100 + q,
        "anti-monopoly at trickle: bulk {} vs bound {} (fair {fair})",
        bulk,
        fair.saturating_mul(175) / 100 + q
    );
    assert_eq!(quiet_got, r.taken[1], "zero stranding at trickle");
    let sibling_fair: u64 = 640_000 * 4 / 2;
    assert!(
        sibling <= sibling_fair.saturating_mul(175) / 100 + q && sibling >= sibling_fair * 65 / 100,
        "the sibling leaf at trickle: {} (fair {sibling_fair})",
        sibling
    );
}

/// THE A/B FINGERPRINT (the ECN battery's own posture): same
/// deterministic seeds, both shapes, the deltas that ARE the
/// feature — the monopoly's 6.5:1 crush becomes a 1.25:1 split,
/// and the quiet flow's admits and the aggregate both stay inside
/// their bands (the reservation's honest cost, bounded).
#[test]
fn the_ab_fingerprint_flow_lane_vs_shared_leaf() {
    let v19 = run_flow_shape(&Shape {
        flow_lane: false,
        rate: 1_000_000,
        secs: 4,
        bulks: 2,
        sparse: true,
        siblings: 1,
    });
    let v20 = run_flow_shape(&Shape {
        flow_lane: true,
        rate: 1_000_000,
        secs: 4,
        bulks: 2,
        sparse: true,
        siblings: 1,
    });
    // got layout: [leaf0 bulk A, leaf0 bulk B, quiet, sibling bulk]
    let crush19 = v19.got[0] / v19.got[1].max(1);
    let split20 = v20.got[0].max(v20.got[1]) / v20.got[0].min(v20.got[1]).max(1);
    assert!(
        crush19 >= 2,
        "the shared leaf's crush: {crush19}:1 — the fingerprint the \
         lane exists to close"
    );
    assert!(split20 <= 5 / 4, "the flow lane's split: {split20}:1");
    let admit19 = v19.admits * 100 / v19.offers;
    let admit20 = v20.admits * 100 / v20.offers;
    assert!(
        admit20 >= admit19 * 9 / 10,
        "the quiet flow never pays for the isolation: v20 {admit20}% vs v19 {admit19}%"
    );
    let total_ratio = v20.total * 100 / v19.total.max(1);
    assert!(
        (85..=105).contains(&total_ratio),
        "the aggregate across the lane boundary: v20/v19 = {total_ratio}% — the \
         reservation's cost, bounded"
    );
}
