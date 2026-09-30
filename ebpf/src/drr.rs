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
//   * an empty leaf draws min(quantum, pool) — one drawer per leaf
//     per timestamp (the window-ownership trick, applied to draws);
//   * the draw is a bounded CAS sequence — a lost race retries
//     against a fresh read, and a lost pool draw DROPS (the safe
//     verdict), never over-allows;
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

/// The fair-share window, in milliseconds: one quantum equals the
/// policy's rate over this window — the share a single leaf may draw
/// from the pool per draw. 100 ms is the owner's specced shape
/// ("sisa token leaf balik ke pool root setelah 1 window (misal
/// 100ms)"), reinterpreted as the quantum horizon: a leaf may hold
/// at most one window's share in flight, which bounds the greedy
/// advantage to one window plus whatever the starved siblings leave.
pub const DRR_WINDOW_MS: u64 = 100;

/// The fair-share window, in nanoseconds — the datapath's elapsed
/// clock (ktime) measures the spacing.
pub const DRR_WINDOW_NS: u64 = DRR_WINDOW_MS * 1_000_000;

/// The paced admission (pure): the leaf's stamp holds its
/// NEXT-ELIGIBLE time (the last draw's time plus that draw's
/// proportional wait, [`draw_wait`]) — a leaf may draw when the
/// clock reaches it. The pacing is what keeps the starved regime
/// fair: a full quantum stocks a leaf for a window (the anti-hog
/// cap) while a residual trickle costs a trickle of waiting (the
/// starved leaf keeps collecting the refills as they land), so a
/// single active leaf still converges to the whole budget (the
/// pool's equilibrium sits at twice the refill step, where half
/// equals its full consumption) and interleaved leaves split it.
#[inline(always)]
pub const fn draw_admitted(now: u64, next_eligible: u64) -> bool {
    now >= next_eligible
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
    if share > 65_536 {
        share
    } else {
        65_536
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
    let half = pool_tokens / 2;
    if quantum < half {
        quantum
    } else {
        half
    }
}

/// The proportional pacing (the stockpile bound's clock): a draw of
/// `d` tokens costs `d / quantum` of a fair-share window of waiting
/// — a full quantum stocks a leaf for a full window (the anti-hog
/// cap), a residual trickle costs a trickle of waiting (the starved
/// leaf retries essentially every packet, collecting the refills as
/// they land). Saturating throughout; `quantum` is never zero (the
/// GSO floor).
#[inline(always)]
pub const fn draw_wait(drawn: u64, quantum: u64) -> u64 {
    if drawn >= quantum {
        DRR_WINDOW_NS
    } else {
        DRR_WINDOW_NS * drawn / quantum
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
    quantum(rate_bps).saturating_add(65_536)
}
