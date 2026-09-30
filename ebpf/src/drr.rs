// Copyright (C) 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
// The DRR (Deficit Round Robin) fair-share core,
// NIGHT-upgrade-charger-core-1-c: the pure arithmetic of the
// fair-shared bucket — the quantum sizing and the invariants the
// datapath (drr_flow.rs) and the userspace pins share. Extracted
// core-only (the math.rs / ammsp.rs discipline): zero aya/eBPF
// dependencies, so the SAME file compiles into the kernel object
// (ebpf/src/bin/limiter.rs wires it with #[path]) AND into the
// userspace test tree, where test/ebpf/limiter/drr_tests.rs pins it
// rootlessly.
//
// THE PROBLEM (the owner's starvation find): AMMSP gives a policy's
// whole subtree ONE shared budget — and a shared bucket is
// first-come-first-served at token granularity. One greedy leaf
// (a subprocess of the limited app) whose packets keep arriving can
// consume every token the instant it refills, starving its siblings
// indefinitely: cgroup /A at 100kb with subprocess #1 greedy means
// subprocesses #2..#100 get ~nothing, forever. No configuration,
// daemon, or enumeration can fix FCFS inside the hot path — the fix
// has to live in the datapath itself.
//
// THE DESIGN (quantum-fair sharing, DRR-shaped): the shared bucket
// becomes a POOL (refills at the policy rate, exactly as before),
// and every LEAF cgroup under the root gets its own small bucket
// that spends only tokens it DREW from the pool, in quanta:
//
//   * a packet is admitted from the LEAF's bucket, never the pool;
//   * an empty leaf draws min(quantum, HALF the pool) — the residue
//     law below — under a one-drawer-per-timestamp lock (the
//     window-ownership trick, applied to draws);
//   * the draw is a bounded CAS sequence — a lost race retries
//     against a fresh read, and a lost pool draw DROPS (the safe
//     verdict), never over-allows;
//   * the stamp is a DRAW LOCK, not pacing — paced draws (a quantum
//     per window) proved TCP-hostile on the CI daemon row (the
//     silent windows read as congestion and collapse the flow to
//     46% of configured), so the anti-hog cap is the holding bound
//     alone and a leaf re-draws the moment it empties;
//   * the pool never hands out what it does not have, so the
//     subtree's aggregate stays exactly the policy it had — DRR
//     redistributes the budget, it cannot create one.
//
// WHY THIS IS FAIR: a leaf holding a quantum stops touching the pool
// (its packets spend its own tokens), so the pool's next refills go
// to whichever leaf is empty and asking. Over any window, a greedy
// leaf's consumption is bounded by roughly one quantum plus its
// share of the refill — the starvation shape (one leaf at ~100%,
// the rest at ~0%) becomes a bounded-share shape. It is
// statistical, not a formal DRR guarantee: the formal version needs
// iteration over leaves (impossible in a cgroup_skb hot path), and
// the quantized version is the strongest fairness that fits the
// verifier's straight-line budget. The bound is honest and
// documented: any leaf can hold at most one quantum at a time (the
// draw-ownership stamp enforces it), so K equal-demand leaves share
// the refill within one quantum of slop.
//
// THE TRICKLE TRADEOFF (the GSO admit floor, on purpose): the
// quantum is floored at the 64 KiB super-packet floor
// (BURST_FLOOR_BYTES, NIGHT-lts-8's law) because a quantum below it
// could never admit the GSO/GRO super-packets the kernel hands the
// hooks — a leaf waiting to accumulate 64 KiB in 64-byte quanta
// would bar its own packets forever, the exact class the burst floor
// closed. At rates below ~640 KB/s the floor dominates the window's
// share (a 100kb policy's 100ms share is 10 KB, but the quantum
// stays 64 KiB), so fairness at trickle rates is coarse — leaves
// alternate on quantum boundaries (~0.64s at 100kb) instead of
// never at all. Coarse fairness beats starvation; the numbers are
// pinned so the tradeoff is a decision, not drift.
//
// This module must stay `core`-only: no std, no alloc, no aya — any
// dependency added here reaches both trees at once.

/// The GSO admit floor (the math.rs BURST_FLOOR_BYTES value, named
/// locally so this core stays standalone): the largest super-packet
/// the kernel hands a cgroup_skb hook by default.
pub const GSO_ADMIT_FLOOR: u64 = 65_536;

/// The fair-share window, in milliseconds: one quantum equals the
/// policy's rate over this window — the share a single leaf may draw
/// from the pool per draw. 100 ms is the owner's specced shape
/// ("sisa token leaf balik ke pool root setelah 1 window (misal
/// 100ms)"), reinterpreted as the quantum horizon: a leaf may hold
/// at most one window's share in flight, which bounds the greedy
/// advantage to one window plus whatever the starved siblings leave.
pub const DRR_WINDOW_MS: u64 = 100;

/// The fair-share window, in nanoseconds — the unit the pins hold
/// the window constant in (the datapath itself never converts: the
/// pacing that consumed it was removed, the CI ebpf-clippy lane
/// caught the orphan, and the const stays test-facing — the
/// walk_queries precedent).
#[cfg(test)]
pub const DRR_WINDOW_NS: u64 = DRR_WINDOW_MS * 1_000_000;

/// The draw admission (pure): the leaf's stamp holds its last draw
/// time — a reached-or-later clock admits. The stamp is the DRAW LOCK
/// (one drawer per leaf per timestamp, the window-ownership trick),
/// not a pacing mechanism: the CI daemon row proved paced draws hurt
/// TCP (a quantum staircase with silent windows reads as congestion
/// and collapses the flow — 46% of configured on the leg that
/// caught it), so the fairness work belongs to the residue law and
/// the holding cap alone, and a leaf re-draws the moment it empties
/// (the single-flow shape stays the legacy trickle).
#[inline(always)]
pub const fn draw_admitted(now: u64, last_draw: u64) -> bool {
    now >= last_draw
}

/// The per-draw quantum for a policy: the window's share of the
/// rate, floored at the GSO admit floor. Pure — the datapath calls
/// it per draw, the pins hold it to its bounds.
///
/// The floor is the correctness half (see the module header): a
/// quantum below the largest super-packet the hook ever sees could
/// never admit that packet class, barring a leaf's own data forever.
/// The `rate / 10` shape is `rate x WINDOW / 1000` in integer math.
#[inline(always)]
pub const fn quantum(rate_bps: u64) -> u64 {
    let share = rate_bps / (1000 / DRR_WINDOW_MS);
    if share > GSO_ADMIT_FLOOR {
        share
    } else {
        GSO_ADMIT_FLOOR
    }
}

/// The residue law (the starved regime's fairness): a draw takes at
/// most HALF the visible pool — never all of it. Without the half,
/// the first asker at each instant captures everything that
/// accumulated and the second starves (the simulation pinned the
/// shape at 95/4 before this law); with it, an interleaved asker
/// pair splits the continuous refill stream ~evenly, because every
/// draw leaves the other half for whoever asks next. The quantum cap
/// still binds (the stockpile bound), and a single active leaf is
/// untouched in throughput: its half-draws pace at the refill rate,
/// one step of latency apart.
#[inline(always)]
pub const fn draw_size(quantum: u64, pool_tokens: u64) -> u64 {
    let pool_half = pool_tokens / 2;
    if quantum < pool_half {
        quantum
    } else {
        pool_half
    }
}

/// The worst in-flight over-allow one leaf can hold: one quantum
/// (the draw-ownership stamp makes a second concurrent draw for the
/// same leaf wait for the clock) plus the packet that triggered it —
/// the bound the fairness guarantee is phrased against, and the
/// number a stale-quantum zeroing is bounded by on the other side.
/// Test-facing by design (the walk_queries precedent): the datapath
/// needs no bound, the documentation and the pins do — cfg(test)
/// keeps the ebpf release build free of the dead symbol a clippy
/// -D warnings run rejects.
#[cfg(test)]
#[inline(always)]
pub const fn leaf_inflight_bound(rate_bps: u64) -> u64 {
    quantum(rate_bps).saturating_add(GSO_ADMIT_FLOOR)
}

// ── The learned-share draw (dinner-28) ────────────────────────────────
//
// THE FIND the live battery filed (supermassive fair-share, all four
// CI legs): the residue law splits a TWO-asker pool evenly — every
// draw leaves half for whoever asks next — but across K > 2
// successive drawers the takes decay geometrically: the first asker
// of each epoch takes half the pool, the second half of the rest
// (25%), the third 12.5% ... the K-th (1/2)^K of the pool. The
// measured CI shape at 6 leaves / 1mb: the worst leaf read 2.13 MB
// over 4s (the first-drawer's 500 KB/s share, 3.35x the fair share)
// while the quietest accumulated ~60 KB in 40 epochs — one GRO admit
// short of 64 KiB — and never admitted a single packet (78 B). The
// pool law held exactly (0.95x of policy — the aggregate was always
// right); only the DISTRIBUTION was broken. The v13 pins simulated
// K=2 only (the alternating pair), so the decay class was never
// covered: the pins' own precedent — the 95/4 FCFS shape was found
// by simulation, and this class is one order deeper.
//
// THE LAW: the draw take is the residue law's bound FURTHER capped
// by the quantum's fair split across a LEARNED drawee count — the
// number of distinct leaves that drew in the last completed 100ms
// epoch, kept per (pool, direction) in a packed state word:
//
//   bits  0..15 : last     — the distinct-drawee count of the last
//                           COMPLETED epoch (the divisor source)
//   bits 16..31 : running  — the distinct-drawee count of the
//                           CURRENT epoch
//   bits 32..63 : epoch    — now / DRR_WINDOW_MS (the 100ms epoch)
//
// A learned count of 0 (a cold pool, the first 100ms) keeps the
// exact v13 shape — fair_draw_size(q, pool, 0) is draw_size by
// construction — and from the first rollover on, the first asker of
// an epoch is capped at quantum/(K+1) like every other drawer: the
// monopoly position itself stops paying. The count is an ESTIMATE
// (concurrent notes may lose one increment, a failed-draw epoch
// under-counts its starved askers): the divisor's slack absorbs it —
// the bounds the battery judges (1.75x fair + one quantum, and
// fair/4 for the quietest) are met with margin in the simulation
// pin, which reproduces the CI decay first and the close second.

/// The epoch length in ns for the share state (the DRR window).
#[inline(always)]
pub const fn share_epoch_ns() -> u64 {
    DRR_WINDOW_MS * 1_000_000
}

/// Unpack the state word's epoch (bits 32..63).
#[inline(always)]
pub const fn pool_share_epoch(word: u64) -> u32 {
    (word >> 32) as u32
}

/// Unpack the running distinct-drawee count (bits 16..31).
#[inline(always)]
pub const fn pool_share_running(word: u64) -> u16 {
    ((word >> 16) & 0xFFFF) as u16
}

/// Unpack the learned divisor source: the last completed epoch's
/// distinct-drawee count (bits 0..15).
#[inline(always)]
pub const fn pool_share_last(word: u64) -> u16 {
    (word & 0xFFFF) as u16
}

/// Pack the state word.
#[inline(always)]
pub const fn pool_share_pack(epoch: u32, running: u16, last: u16) -> u64 {
    ((epoch as u64) << 32) | ((running as u64) << 16) | last as u64
}

/// The rollover + count step (pure, the same math the datapath's
/// atomics and the simulation's plain stores run): given the current
/// word, the now-epoch, and whether THIS leaf already drew in the
/// current epoch, return the updated word. A rollover at an epoch
/// boundary retires the epoch's running count into `last` — the
/// divisor the next epoch's draws read.
#[inline(always)]
pub const fn pool_share_note(word: u64, now_epoch: u32, leaf_drew_this_epoch: bool) -> u64 {
    let mut epoch = pool_share_epoch(word);
    let mut running = pool_share_running(word);
    let mut last = pool_share_last(word);
    if epoch != now_epoch {
        last = running;
        running = 0;
        epoch = now_epoch;
    }
    if !leaf_drew_this_epoch {
        running = running.saturating_add(1);
    }
    pool_share_pack(epoch, running, last)
}

/// The learned-share draw (the new law, dinner-28): the residue
/// law's bound further capped by the POOL's fair split across the
/// learned drawee count — pool/(learned+2), not quantum/(learned+1):
/// the cap must bind at the micro scale, where the pool holds only
/// the refill since the last drain (hundreds of bytes at a 200us
/// offer cadence — a quantum-scaled cap sits forty times above the
/// binding constraint there and never engages; the simulation pin
/// caught that too). At learned+2 the arithmetic keeps every case
/// honest: learned 0 (a cold pool, a missed state lookup) is
/// pool/2 — the EXACT v13 residue law by construction, the fail-open
/// lane; learned 1 (a single active leaf) is pool/3 — smaller takes,
/// the same throughput (the lone leaf re-draws freely); learned K is
/// pool/(K+2) — a flat split whose position ratio is
/// (1-1/(K+2))^(K-1), 1.34 at K=6 and 1.18 at K=24, both far inside
/// the battery's 1.75x bound. The order-dependence the residue law
/// owned at K>2 (geometric decay across positions) is gone by
/// construction: every drawer takes the same fraction of a pool the
/// previous drawers barely dented.
#[inline(always)]
pub const fn fair_draw_size(quantum: u64, pool_tokens: u64, learned: u16) -> u64 {
    // The naming is load-bearing, not decoration: the file is
    // formatted by BOTH trees' rustfmt (the root reaches it through
    // the test tree's #[path] includes, the ebpf crate formats it
    // natively), and the two toolchains disagree on collapsing a
    // short if-else into one line — the nightly collapses under its
    // single-line width cap, the stable expands. draw_size stayed
    // stable through the whole DRR era because its statement runs
    // past the cap; these names put this statement past it too (the
    // compact one-liner and the trait method — Ord::min is not const
    // on the ebpf toolchain, E0658 — each fail a gate on one side).
    let residue_law_take = draw_size(quantum, pool_tokens);
    let learned_share_take = pool_tokens / (learned as u64 + 2);
    if residue_law_take < learned_share_take {
        residue_law_take
    } else {
        learned_share_take
    }
}
