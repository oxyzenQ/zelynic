// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! NIGHT-upgrade-charger-core-1c: precision pins for the DRR
//! fair-share core (ebpf/src/drr.rs — the same file the BPF object
//! builds) and the atomic primitive set it draws through
//! (math.rs, the math_tests copy). Before this harness the fairness
//! shape was provable only on a root machine; these pins make the
//! starvation close testable rootlessly.
//!
//! Every pin maps to a documented contract:
//!
//!  * the quantum bounds — the window's share, floored at the GSO
//!    admit floor (a quantum below it could never admit a
//!    super-packet: the trickle tradeoff, decided not drifted);
//!  * the draw size — never more than the quantum, never more than
//!    the pool holds (the pool never hands out what it does not
//!    have: DRR redistributes the budget, it cannot create one);
//!  * the draw-stamp ownership — one drawer per leaf per timestamp;
//!  * the fairness simulation — alternating leaves split the pool's
//!    quanta where the FCFS shape starved the sibling to zero;
//!  * the stale-quantum belt — a mismatching generation stamp zeroes
//!    a leaf's dead-budget tokens before the packet may spend them.

// The production quantum core itself, compiled into this test
// module: the SAME file the BPF object builds (ebpf/src/bin/limiter.rs
// wires it with its own #[path]). Only the test tree reaches across
// trees — the gate-tree discipline. The math copy rides math_tests'
// single inclusion (one per test binary, the duplicate-mod law).
#[path = "../../../ebpf/src/drr.rs"]
pub(super) mod ebpf_drr;

use super::math_tests::ebpf_math::{
    draw_stamp_take, gen_stamp_read, gen_stamp_write, tokens_cas, tokens_fetch_add, tokens_read,
    Bucket,
};

use ebpf_drr::{
    draw_admitted, draw_size, leaf_inflight_bound, quantum, DRR_WINDOW_MS, DRR_WINDOW_NS,
};

/// A zeroed leaf bucket (the datapath's init shape).
fn fresh_leaf() -> Bucket {
    Bucket {
        tokens: 0,
        last_refill_ns: 0,
        frac_rem: 0,
    }
}

/// The window constant is the owner's specced 100ms horizon.
#[test]
fn the_window_is_the_spec_horizon() {
    assert_eq!(DRR_WINDOW_MS, 100);
}

/// The quantum bounds: the window's share of the rate, floored at the
/// 64 KiB GSO admit floor. At 1mb and above the share dominates; at
/// the canonical 100kb and below the floor does — the documented
/// trickle tradeoff (coarse fairness at trickle rates beats the
/// starvation the FCFS shape owned).
#[test]
fn the_quantum_is_the_share_floored_at_the_gso_law() {
    // The floor dominates through the canonical desktop rates.
    assert_eq!(quantum(1_000), 65_536, "1kb: the GSO floor, not 100 bytes");
    assert_eq!(quantum(100_000), 65_536, "100kb: the GSO floor, not 10 KB");
    assert_eq!(quantum(500_000), 65_536, "500kb: the GSO floor, not 50 KB");
    // The share dominates from ~656 KB/s up.
    assert_eq!(quantum(1_000_000), 100_000, "1mb: one window's share");
    assert_eq!(quantum(10_000_000), 1_000_000, "10mb: one window's share");
    assert_eq!(quantum(1_000_000_000_000), 100_000_000_000, "1 TB policy");
    // The in-flight bound rides the quantum plus one packet.
    assert_eq!(leaf_inflight_bound(1_000_000), 100_000 + 65_536);
}

/// The draw never moves more than the quantum, and never more than
/// HALF the pool — the residue law (the starved regime's fairness:
/// every draw leaves half for whoever asks next) plus the
/// conservation law the whole design rests on.
#[test]
fn the_draw_is_bounded_by_quantum_and_half_the_pool() {
    // The quantum binds when the pool is rich.
    assert_eq!(draw_size(100_000, 1_000_000), 100_000, "quantum wins");
    assert_eq!(
        draw_size(100_000, 300_000),
        100_000,
        "quantum wins under 2x"
    );
    // The half binds when the pool is starved: never drain it whole.
    assert_eq!(
        draw_size(1_000_000, 100_000),
        50_000,
        "half the starved pool"
    );
    assert_eq!(draw_size(1_000_000, 10_000), 5_000, "half of a trickle");
    assert_eq!(draw_size(100_000, 0), 0, "an empty pool draws nothing");
    assert_eq!(draw_size(0, 100_000), 0, "a zero quantum draws nothing");
}

/// The draw-stamp ownership: the CAS race the stamp closes — two
/// CPUs observed the same stamp and both attempt ownership, exactly
/// one wins; the next timestamp admits again.
#[test]
fn the_draw_stamp_admits_one_drawer_per_timestamp() {
    let mut leaf = fresh_leaf();
    assert!(
        draw_stamp_take(&mut leaf, 0, 1_000),
        "the first drawer wins"
    );
    assert!(
        !draw_stamp_take(&mut leaf, 0, 1_000),
        "the second drawer loses (the stamp moved)"
    );
    assert!(
        !draw_stamp_take(&mut leaf, 0, 1_500),
        "any stale observation loses"
    );
    assert!(
        draw_stamp_take(&mut leaf, 1_000, 2_000),
        "the next stamp wins"
    );
}

/// THE FAIRNESS PIN: two leaves, one pool, packets arriving in a
/// GREEDY-FIRST ALTERNATION (A's packet, then B's, every step — A
/// always first, the worst case the FCFS shape owned) — the
/// starvation shape becomes a split. The simulation drives the exact
/// primitive sequence the datapath runs per packet: the stamp guard
/// (`now <= last` skips the draw), the draw, the spend, and a
/// time-consistent refill (1000-byte packets at a 1 MB/s rate means
/// one packet per millisecond, so the pool refills 1000 bytes per
/// packet step — the same credit the kernel's windows produce).
#[test]
fn alternating_leaves_split_the_pool_where_fcfs_starved() {
    let rate = 1_000_000_u64; // 1mb: quantum = 100 KB, burst = 1 MB.
    let q = quantum(rate);
    assert_eq!(q, 100_000);
    let burst = 1_000_000_u64;
    let packet = 1_000_u64; // one packet per ms at the 1 MB/s rate

    let mut pool = Bucket {
        tokens: burst,
        last_refill_ns: 0,
        frac_rem: 0,
    };
    let mut leaf_a = fresh_leaf();
    let mut leaf_b = fresh_leaf();
    let mut got_a: u64 = 0;
    let mut got_b: u64 = 0;

    // One leaf's packet through the DRR primitive sequence (the
    // datapath's own order: the admission guard, the stamp lock, the
    // residue-law draw, the spend). The clock is ns at a past-boot
    // base; one packet per ms at the 1 MB/s rate. No pacing — the CI
    // daemon row proved paced draws TCP-hostile; the stamp is the
    // draw lock and the fairness rides the residue law alone.
    let step = |leaf: &mut Bucket, pool: &mut Bucket, now: u64, got: &mut u64| {
        let stamp = leaf.last_refill_ns;
        if tokens_read(leaf) < packet && now >= stamp && draw_stamp_take(leaf, stamp, now) {
            let d = draw_size(q, tokens_read(pool));
            let observed = tokens_read(pool);
            if d > 0 && observed >= d && tokens_cas(pool, observed, observed - d) {
                let _ = tokens_fetch_add(leaf, d);
            } else {
                // The rollback: an empty pool must not advance the
                // leaf's stamp (the starved leaf retries every packet).
                let _ = draw_stamp_take(leaf, now, stamp);
            }
        }
        let observed = tokens_read(leaf);
        if observed >= packet && tokens_cas(leaf, observed, observed - packet) {
            *got += packet;
        }
    };

    // 20 seconds of traffic (20,000 packet steps), A first every
    // step — under FCFS, A's first-come packets drain every token the
    // instant it exists and B measures zero; under DRR each leaf
    // holds at most one quantum at a time, so the pool's refills flow
    // to whichever leaf is empty and asking.
    let steps = 20_000_u64;
    // The clock: ns units at a past-boot base (ktime is ~1e15 on any
    // real machine — a fresh leaf's stamp 0 admits immediately).
    const BOOT_NS: u64 = 1_000_000_000_000_000;
    for i in 0..steps {
        let now = BOOT_NS + (i + 1) * 1_000_000;
        step(&mut leaf_a, &mut pool, now, &mut got_a);
        step(&mut leaf_b, &mut pool, now, &mut got_b);
        // The refill: one packet-time of credit (1 ms at 1 MB/s).
        let _ = tokens_fetch_add(&mut pool, packet);
    }

    let total = got_a + got_b;
    let issued = burst + steps * packet;
    assert!(total > 0, "traffic moved");
    assert!(
        total <= issued,
        "conservation: the pair moved {total} through a {issued} budget"
    );
    // The fairness band: each leaf holds at least a quarter of what
    // moved (the FCFS shape measured B at zero — the exact
    // starvation this design closes).
    let share_b = got_b * 100 / total;
    let share_a = got_a * 100 / total;
    assert!(
        share_b >= 25 && share_a >= 25,
        "the split is fair within the band: A {share_a}% B {share_b}% of {total} bytes"
    );
}

/// The draw lock's admission arithmetic: the stamp holds the LAST
/// DRAW time — a reached-or-later clock admits (the CAS below the
/// guard is the actual lock; this is its gate). NOT pacing: the CI
/// daemon row proved paced draws TCP-hostile (46% of configured —
/// the silent windows read as congestion), so the fairness rides the
/// residue law and the holding cap alone.
#[test]
fn the_draw_lock_admits_on_a_later_clock() {
    assert!(
        draw_admitted(1_000, 0),
        "a fresh leaf (stamp 0) draws immediately"
    );
    assert!(
        draw_admitted(1_000, 1_000),
        "the clock reached the stamp: draw"
    );
    assert!(!draw_admitted(1_000, 1_001), "a future stamp waits");
    // The window constant itself, in both units.
    assert_eq!(DRR_WINDOW_MS, 100);
    assert_eq!(DRR_WINDOW_NS, 100_000_000);
}

/// The stale-quantum belt: a leaf holding tokens drawn under a dead
/// generation is zeroed before the packet may spend them — the
/// generation-stamp trick applied to buckets.
#[test]
fn the_stale_quantum_belt_zeroes_dead_budget_tokens() {
    let mut leaf = fresh_leaf();
    // Quanta drawn under generation 0 (pre-mutation).
    let _ = tokens_fetch_add(&mut leaf, 65_536);
    gen_stamp_write(&mut leaf, 0);
    assert_eq!(tokens_read(&leaf), 65_536);

    // A mutation happened: the live generation is 1. The belt's exact
    // sequence (drr_flow): mismatch -> CAS the stale tokens to zero.
    let live_generation = 1_u64;
    assert_ne!(gen_stamp_read(&leaf), live_generation);
    let stale = tokens_read(&leaf);
    assert!(tokens_cas(&mut leaf, stale, 0));
    gen_stamp_write(&mut leaf, live_generation);

    assert_eq!(tokens_read(&leaf), 0, "the dead budget's tokens are gone");
    assert_eq!(
        gen_stamp_read(&leaf),
        live_generation,
        "re-stamped for the draw"
    );
}

/// The belt's concurrent-consumer safety: a consumer whose CAS raced
/// the zeroing re-observes the zero and fails its spend (the safe
/// verdict), never spends phantom tokens.
#[test]
fn the_belt_zeroing_is_safe_against_a_racing_consumer() {
    let mut leaf = fresh_leaf();
    let _ = tokens_fetch_add(&mut leaf, 50_000);
    // The consumer read 50_000 and is about to spend 1_000 — but the
    // belt zeroed the leaf first: the consumer's CAS loses.
    let observed = tokens_read(&leaf);
    assert!(tokens_cas(&mut leaf, observed, 0), "the belt's zero wins");
    assert!(
        !tokens_cas(&mut leaf, observed, observed - 1_000),
        "the racing consumer's spend fails against the fresh state"
    );
    assert_eq!(tokens_read(&leaf), 0);
}

// dinner-28: the learned-share simulation battery — the K-leaf decay
// the live fair-share battery caught, and the law that closes it.
// Wired as a child of this module so the ONE copy of the quantum
// core (ebpf_drr above) serves both pin sets — the duplicate-mod law.
#[path = "drr_share_tests.rs"]
mod drr_share_tests;

// repair-3: the epoch-ledger battery — the kernel-shaped feedback
// sim (TCP-window cadence + per-packet credits) that reproduces the
// live battery's CI finds rootlessly, and the per-epoch allowance
// that closes them. Same child-module wiring, same single core copy.
#[path = "drr_ledger_tests.rs"]
mod drr_ledger_tests;

// repair-7: the two-lane take law — the engaged lane's catch-up
// close (the fraction cap retires where the ledger room already
// owns the split), the off lane verbatim. Same child wiring.
#[path = "drr_take_tests.rs"]
mod drr_take_tests;
